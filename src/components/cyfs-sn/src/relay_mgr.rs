use crate::{
    sn_err, SnAuthDBRef, SnDeviceInfoDBRef, SnDeviceState, SnError, SnErrorCode, SnResult,
};
use serde::{Deserialize, Serialize};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteRow};
use sqlx::{Row, SqlitePool};
use std::collections::HashSet;
use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

pub type SnRelayManagerRef = Arc<dyn SnRelayManager>;

const DEFAULT_CAPACITY_SCORE: i64 = 100;
const DEFAULT_ADMISSION_TTL_SECS: u64 = 60;
const DEFAULT_MIGRATION_WINDOW_SECS: u64 = 300;

macro_rules! relay_string_enum {
    ($name:ident { $($variant:ident => $value:literal),+ $(,)? }) => {
        impl $name {
            pub fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $value,)+
                }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str((*self).as_str())
            }
        }

        impl FromStr for $name {
            type Err = String;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                match value {
                    $($value => Ok(Self::$variant),)+
                    _ => Err(format!("invalid {}: {}", stringify!($name), value)),
                }
            }
        }
    };
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayNodeStatus {
    Active,
    Draining,
    Disabled,
    Unhealthy,
    Deleted,
}

relay_string_enum!(RelayNodeStatus {
    Active => "active",
    Draining => "draining",
    Disabled => "disabled",
    Unhealthy => "unhealthy",
    Deleted => "deleted",
});

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayAssignmentState {
    Active,
    Migrating,
    Draining,
    Suspended,
}

relay_string_enum!(RelayAssignmentState {
    Active => "active",
    Migrating => "migrating",
    Draining => "draining",
    Suspended => "suspended",
});

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayAssignmentSource {
    Auto,
    Admin,
    Recovery,
    Migration,
}

relay_string_enum!(RelayAssignmentSource {
    Auto => "auto",
    Admin => "admin",
    Recovery => "recovery",
    Migration => "migration",
});

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayAdmissionDecisionKind {
    Allow,
    Reject,
    Redirect,
}

relay_string_enum!(RelayAdmissionDecisionKind {
    Allow => "allow",
    Reject => "reject",
    Redirect => "redirect",
});

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayAdmissionReason {
    Ok,
    WrongRelay,
    DeviceNotFound,
    ZoneSuspended,
    TokenInvalid,
    AssignmentMissing,
    AssignmentMigrating,
    RelayDraining,
    RelayUnavailable,
    StaleGeneration,
}

relay_string_enum!(RelayAdmissionReason {
    Ok => "ok",
    WrongRelay => "wrong_relay",
    DeviceNotFound => "device_not_found",
    ZoneSuspended => "zone_suspended",
    TokenInvalid => "token_invalid",
    AssignmentMissing => "assignment_missing",
    AssignmentMigrating => "assignment_migrating",
    RelayDraining => "relay_draining",
    RelayUnavailable => "relay_unavailable",
    StaleGeneration => "stale_generation",
});

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct RelayNode {
    pub relay_id: String,
    pub relay_sn: String,
    pub public_host: String,
    pub http_endpoint: Option<String>,
    pub rtcp_endpoint: Option<String>,
    pub region: Option<String>,
    pub isp: Option<String>,
    pub tags: Vec<String>,
    pub capabilities: Vec<String>,
    pub status: RelayNodeStatus,
    pub capacity_score: i64,
    pub current_load: i64,
    pub last_heartbeat_at: Option<u64>,
    pub drain_until: Option<u64>,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct RelayNodeRegistration {
    pub relay_id: String,
    pub relay_sn: String,
    pub public_host: String,
    pub http_endpoint: Option<String>,
    pub rtcp_endpoint: Option<String>,
    pub region: Option<String>,
    pub isp: Option<String>,
    pub tags: Vec<String>,
    pub capabilities: Vec<String>,
    pub status: Option<RelayNodeStatus>,
    pub capacity_score: Option<i64>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct RelayHeartbeat {
    pub relay_id: String,
    pub status: Option<RelayNodeStatus>,
    pub current_load: Option<i64>,
    pub capacity_score: Option<i64>,
    pub drain_until: Option<u64>,
    pub http_endpoint: Option<String>,
    pub rtcp_endpoint: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct RelayNodeHealth {
    pub relay_id: String,
    pub status: RelayNodeStatus,
    pub capacity_score: i64,
    pub current_load: i64,
    pub last_heartbeat_at: u64,
    pub drain_until: Option<u64>,
    pub updated_at: u64,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct RelayAssignment {
    pub zone: String,
    pub relay_id: String,
    pub relay_sn: String,
    pub state: RelayAssignmentState,
    pub source: RelayAssignmentSource,
    pub reason: Option<String>,
    pub generation: u64,
    pub backup_relay_id: Option<String>,
    pub sticky_until: Option<u64>,
    pub lease_expires_at: Option<u64>,
    pub migrated_from: Option<String>,
    pub migration_deadline: Option<u64>,
    pub source_version: Option<String>,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct AssignZoneRelayReq {
    pub zone: String,
    pub relay_id: Option<String>,
    pub relay_sn: Option<String>,
    pub from_ip: Option<String>,
    pub region: Option<String>,
    pub source: RelayAssignmentSource,
    pub reason: Option<String>,
    pub sticky_until: Option<u64>,
    pub lease_expires_at: Option<u64>,
    pub backup_relay_id: Option<String>,
    pub source_version: Option<String>,
}

impl AssignZoneRelayReq {
    pub fn auto(zone: impl Into<String>) -> Self {
        Self {
            zone: zone.into(),
            relay_id: None,
            relay_sn: None,
            from_ip: None,
            region: None,
            source: RelayAssignmentSource::Auto,
            reason: Some("auto_assign".to_string()),
            sticky_until: None,
            lease_expires_at: None,
            backup_relay_id: None,
            source_version: None,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct RelayMigrationReq {
    pub zone: String,
    pub target_relay_id: Option<String>,
    pub target_relay_sn: Option<String>,
    pub operator: Option<String>,
    pub reason: Option<String>,
    pub migration_deadline: Option<u64>,
    pub source_version: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct RelayAdmissionReq {
    pub request_id: Option<String>,
    pub relay_id: String,
    pub zone: String,
    pub device_name: Option<String>,
    pub did: Option<String>,
    pub auth_context: Option<String>,
    pub assignment_generation: Option<u64>,
    pub observed_ip: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct RelayAdmissionDecision {
    pub request_id: Option<String>,
    pub relay_id: String,
    pub zone: String,
    pub device_name: Option<String>,
    pub did: Option<String>,
    pub auth_context: Option<String>,
    pub decision: RelayAdmissionDecisionKind,
    pub reason: RelayAdmissionReason,
    pub expected_relay_sn: Option<String>,
    pub assignment_generation: Option<u64>,
    pub admission_expires_at: Option<u64>,
    pub observed_ip: Option<String>,
    pub created_at: u64,
}

#[async_trait::async_trait]
pub trait SnRelayManager: Send + Sync + 'static {
    async fn register_relay_node(&self, node: RelayNodeRegistration) -> SnResult<RelayNode>;
    async fn heartbeat_relay_node(&self, heartbeat: RelayHeartbeat) -> SnResult<RelayNodeHealth>;
    async fn assign_zone_relay(&self, req: AssignZoneRelayReq) -> SnResult<RelayAssignment>;
    async fn get_zone_relay(&self, zone: &str) -> SnResult<Option<RelayAssignment>>;
    async fn check_relay_admission(
        &self,
        req: RelayAdmissionReq,
    ) -> SnResult<RelayAdmissionDecision>;
    async fn start_relay_migration(&self, req: RelayMigrationReq) -> SnResult<RelayAssignment>;
    async fn complete_relay_migration(&self, zone: &str, generation: u64) -> SnResult<()>;
}

pub struct SqliteSnRelayManager {
    pool: SqlitePool,
    auth_db: Option<SnAuthDBRef>,
    device_info_db: Option<SnDeviceInfoDBRef>,
    admission_ttl_secs: u64,
}

impl SqliteSnRelayManager {
    pub async fn new() -> SnResult<Self> {
        let base_dir = PathBuf::from(std::env::current_exe().unwrap().parent().unwrap());
        let db_path = base_dir.join("sn_relay_mgr.sqlite3");

        Self::new_by_path(db_path.to_string_lossy().as_ref()).await
    }

    pub async fn new_by_path(path: &str) -> SnResult<Self> {
        let db_url = if path.starts_with("sqlite:") {
            path.to_string()
        } else {
            format!("sqlite://{}", path)
        };
        let options = SqliteConnectOptions::from_str(db_url.as_str())
            .map_err(|e| Self::db_err("parse sqlite url failed", e))?
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal);
        let pool = SqlitePoolOptions::new()
            .max_connections(300)
            .connect_with(options)
            .await
            .map_err(|e| Self::db_err(format!("open file: {:?}", path), e))?;

        Ok(Self {
            pool,
            auth_db: None,
            device_info_db: None,
            admission_ttl_secs: DEFAULT_ADMISSION_TTL_SECS,
        })
    }

    pub async fn open_local(path: &str) -> SnResult<SnRelayManagerRef> {
        let db = Self::new_by_path(path).await?;
        db.initialize_database().await?;
        Ok(Arc::new(db))
    }

    pub fn with_auth_db(mut self, auth_db: SnAuthDBRef) -> Self {
        self.auth_db = Some(auth_db);
        self
    }

    pub fn with_device_info_db(mut self, device_info_db: SnDeviceInfoDBRef) -> Self {
        self.device_info_db = Some(device_info_db);
        self
    }

    pub fn with_admission_ttl_secs(mut self, admission_ttl_secs: u64) -> Self {
        self.admission_ttl_secs = admission_ttl_secs;
        self
    }

    pub async fn initialize_database(&self) -> SnResult<()> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS relay_nodes (
                relay_id TEXT PRIMARY KEY,
                relay_sn TEXT NOT NULL UNIQUE,
                public_host TEXT NOT NULL,
                http_endpoint TEXT NULL,
                rtcp_endpoint TEXT NULL,
                region TEXT NULL,
                isp TEXT NULL,
                tags TEXT NULL,
                capabilities TEXT NOT NULL,
                status TEXT NOT NULL,
                capacity_score INTEGER NOT NULL DEFAULT 100,
                current_load INTEGER NOT NULL DEFAULT 0,
                last_heartbeat_at INTEGER NULL,
                drain_until INTEGER NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            )",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| Self::db_err("create relay_nodes table failed", e))?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS relay_assignments (
                zone TEXT PRIMARY KEY,
                relay_id TEXT NOT NULL,
                relay_sn TEXT NOT NULL,
                state TEXT NOT NULL,
                source TEXT NOT NULL,
                reason TEXT NULL,
                generation INTEGER NOT NULL,
                backup_relay_id TEXT NULL,
                sticky_until INTEGER NULL,
                lease_expires_at INTEGER NULL,
                migrated_from TEXT NULL,
                migration_deadline INTEGER NULL,
                source_version TEXT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            )",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| Self::db_err("create relay_assignments table failed", e))?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_relay_assignments_relay
                ON relay_assignments(relay_id, state)",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| Self::db_err("create relay assignment relay index failed", e))?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS relay_admission_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id TEXT NULL,
                relay_id TEXT NOT NULL,
                zone TEXT NOT NULL,
                device_name TEXT NULL,
                did TEXT NULL,
                decision TEXT NOT NULL,
                reason TEXT NOT NULL,
                expected_relay_sn TEXT NULL,
                assignment_generation INTEGER NULL,
                observed_ip TEXT NULL,
                created_at INTEGER NOT NULL
            )",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| Self::db_err("create relay_admission_events table failed", e))?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_relay_admission_events_zone_time
                ON relay_admission_events(zone, created_at)",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| Self::db_err("create relay admission zone index failed", e))?;

        Ok(())
    }

    pub async fn get_relay_node(&self, relay_id: &str) -> SnResult<Option<RelayNode>> {
        Self::check_non_empty(relay_id, "relay_id")?;
        let row = sqlx::query(Self::relay_node_select_sql("WHERE relay_id = ?1").as_str())
            .bind(relay_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| Self::db_err("query relay node failed", e))?;

        row.map(Self::relay_node_from_row).transpose()
    }

    pub async fn list_relay_nodes(&self) -> SnResult<Vec<RelayNode>> {
        let rows = sqlx::query(Self::relay_node_select_sql("ORDER BY relay_id ASC").as_str())
            .fetch_all(&self.pool)
            .await
            .map_err(|e| Self::db_err("list relay nodes failed", e))?;

        rows.into_iter()
            .map(Self::relay_node_from_row)
            .collect::<SnResult<Vec<_>>>()
    }

    pub async fn list_zone_relays_by_node(&self, relay_id: &str) -> SnResult<Vec<RelayAssignment>> {
        Self::check_non_empty(relay_id, "relay_id")?;
        let rows = sqlx::query(
            Self::relay_assignment_select_sql(
                "WHERE relay_id = ?1 AND state IN ('active', 'migrating', 'draining')
                 ORDER BY zone ASC",
            )
            .as_str(),
        )
        .bind(relay_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| Self::db_err("list relay assignments failed", e))?;

        rows.into_iter()
            .map(Self::relay_assignment_from_row)
            .collect::<SnResult<Vec<_>>>()
    }

    pub async fn zone_belongs_to_relay(&self, zone: &str, relay_id: &str) -> SnResult<bool> {
        let Some(assignment) = self.get_zone_relay(zone).await? else {
            return Ok(false);
        };
        Ok(assignment.relay_id == relay_id
            && matches!(
                assignment.state,
                RelayAssignmentState::Active | RelayAssignmentState::Migrating
            ))
    }

    async fn choose_relay_node(&self, req: &AssignZoneRelayReq) -> SnResult<RelayNode> {
        if let Some(relay_id) = req.relay_id.as_deref() {
            let node = self
                .get_relay_node(relay_id)
                .await?
                .ok_or_else(|| sn_err!(SnErrorCode::NotFound, "relay node not found"))?;
            Self::check_assignable_node(&node)?;
            if let Some(relay_sn) = req.relay_sn.as_deref() {
                if node.relay_sn != relay_sn {
                    return Err(sn_err!(
                        SnErrorCode::Conflict,
                        "relay_id {} does not match relay_sn {}",
                        relay_id,
                        relay_sn
                    ));
                }
            }
            return Ok(node);
        }

        if let Some(relay_sn) = req.relay_sn.as_deref() {
            let node = self
                .get_relay_node_by_sn(relay_sn)
                .await?
                .ok_or_else(|| sn_err!(SnErrorCode::NotFound, "relay node not found"))?;
            Self::check_assignable_node(&node)?;
            return Ok(node);
        }

        if let Some(existing) = self.get_zone_relay(req.zone.as_str()).await? {
            if req.source == RelayAssignmentSource::Auto
                && matches!(existing.state, RelayAssignmentState::Active)
                && existing
                    .sticky_until
                    .map(|sticky_until| sticky_until > Self::now_secs())
                    .unwrap_or(false)
            {
                if let Some(node) = self.get_relay_node(existing.relay_id.as_str()).await? {
                    if Self::is_assignable_node(&node) {
                        return Ok(node);
                    }
                }
            }
        }

        let row = sqlx::query(
            Self::relay_node_select_sql(
                "WHERE status = 'active'
                 ORDER BY
                    CASE WHEN ?1 IS NOT NULL AND region = ?1 THEN 0 ELSE 1 END,
                    (current_load * 1000 / CASE WHEN capacity_score > 0 THEN capacity_score ELSE 1 END) ASC,
                    capacity_score DESC,
                    relay_id ASC
                 LIMIT 1",
            )
            .as_str(),
        )
        .bind(req.region.as_deref())
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| Self::db_err("choose relay node failed", e))?;

        row.map(Self::relay_node_from_row)
            .transpose()?
            .ok_or_else(|| sn_err!(SnErrorCode::NotFound, "no active relay node is available"))
    }

    async fn get_relay_node_by_sn(&self, relay_sn: &str) -> SnResult<Option<RelayNode>> {
        Self::check_non_empty(relay_sn, "relay_sn")?;
        let row = sqlx::query(Self::relay_node_select_sql("WHERE relay_sn = ?1").as_str())
            .bind(relay_sn)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| Self::db_err("query relay node by sn failed", e))?;

        row.map(Self::relay_node_from_row).transpose()
    }

    async fn ensure_relay_sn_unique(&self, relay_id: &str, relay_sn: &str) -> SnResult<()> {
        let row = sqlx::query("SELECT relay_id FROM relay_nodes WHERE relay_sn = ?1 LIMIT 1")
            .bind(relay_sn)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| Self::db_err("query relay_sn uniqueness failed", e))?;

        if let Some(row) = row {
            let existing_relay_id: String = row.get(0);
            if existing_relay_id != relay_id {
                return Err(sn_err!(
                    SnErrorCode::Conflict,
                    "relay_sn {} already belongs to {}",
                    relay_sn,
                    existing_relay_id
                ));
            }
        }

        Ok(())
    }

    async fn fetch_assignment_for_update(&self, zone: &str) -> SnResult<Option<RelayAssignment>> {
        let row = sqlx::query(Self::relay_assignment_select_sql("WHERE zone = ?1").as_str())
            .bind(zone)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| Self::db_err("query relay assignment failed", e))?;

        row.map(Self::relay_assignment_from_row).transpose()
    }

    async fn upsert_assignment(&self, assignment: &RelayAssignment) -> SnResult<()> {
        sqlx::query(
            "INSERT INTO relay_assignments
                (zone, relay_id, relay_sn, state, source, reason, generation,
                 backup_relay_id, sticky_until, lease_expires_at, migrated_from,
                 migration_deadline, source_version, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)
             ON CONFLICT(zone) DO UPDATE SET
                relay_id = excluded.relay_id,
                relay_sn = excluded.relay_sn,
                state = excluded.state,
                source = excluded.source,
                reason = excluded.reason,
                generation = excluded.generation,
                backup_relay_id = excluded.backup_relay_id,
                sticky_until = excluded.sticky_until,
                lease_expires_at = excluded.lease_expires_at,
                migrated_from = excluded.migrated_from,
                migration_deadline = excluded.migration_deadline,
                source_version = excluded.source_version,
                updated_at = excluded.updated_at",
        )
        .bind(assignment.zone.as_str())
        .bind(assignment.relay_id.as_str())
        .bind(assignment.relay_sn.as_str())
        .bind(assignment.state.as_str())
        .bind(assignment.source.as_str())
        .bind(assignment.reason.as_deref())
        .bind(Self::to_db_time(assignment.generation, "generation")?)
        .bind(assignment.backup_relay_id.as_deref())
        .bind(Self::to_db_time_opt(
            assignment.sticky_until,
            "sticky_until",
        )?)
        .bind(Self::to_db_time_opt(
            assignment.lease_expires_at,
            "lease_expires_at",
        )?)
        .bind(assignment.migrated_from.as_deref())
        .bind(Self::to_db_time_opt(
            assignment.migration_deadline,
            "migration_deadline",
        )?)
        .bind(assignment.source_version.as_deref())
        .bind(Self::to_db_time(assignment.created_at, "created_at")?)
        .bind(Self::to_db_time(assignment.updated_at, "updated_at")?)
        .execute(&self.pool)
        .await
        .map_err(|e| Self::db_err("upsert relay assignment failed", e))?;

        Ok(())
    }

    async fn sync_zone_relay_cache(&self, assignment: &RelayAssignment) -> SnResult<()> {
        if let Some(auth_db) = self.auth_db.as_ref() {
            auth_db
                .update_zone_relay_sn(
                    assignment.zone.as_str(),
                    assignment.relay_sn.as_str(),
                    assignment.source_version.as_deref(),
                )
                .await?;
        }

        Ok(())
    }

    async fn verify_device_binding(&self, req: &RelayAdmissionReq) -> SnResult<bool> {
        let Some(device_info_db) = self.device_info_db.as_ref() else {
            return Ok(true);
        };

        match (req.did.as_deref(), req.device_name.as_deref()) {
            (Some(did), Some(device_name)) => {
                let Some(device) = device_info_db.get_device_state(did).await? else {
                    return Ok(false);
                };
                Ok(device.zone == req.zone
                    && device.device_name == device_name
                    && !matches!(device.state, SnDeviceState::Blocked))
            }
            (Some(did), None) => {
                let Some(device) = device_info_db.get_device_state(did).await? else {
                    return Ok(false);
                };
                Ok(device.zone == req.zone && !matches!(device.state, SnDeviceState::Blocked))
            }
            (None, Some(device_name)) => {
                let Some(device) = device_info_db
                    .get_device_state_by_name(req.zone.as_str(), device_name)
                    .await?
                else {
                    return Ok(false);
                };
                Ok(!matches!(device.state, SnDeviceState::Blocked))
            }
            (None, None) => Ok(true),
        }
    }

    async fn resolve_assignment_for_admission(
        &self,
        req: &RelayAdmissionReq,
    ) -> SnResult<Option<RelayAssignment>> {
        if let Some(assignment) = self.get_zone_relay(req.zone.as_str()).await? {
            return Ok(Some(assignment));
        }

        let auto_req = AssignZoneRelayReq {
            zone: req.zone.clone(),
            relay_id: None,
            relay_sn: None,
            from_ip: req.observed_ip.clone(),
            region: None,
            source: RelayAssignmentSource::Auto,
            reason: Some("first_keep_tunnel".to_string()),
            sticky_until: None,
            lease_expires_at: None,
            backup_relay_id: None,
            source_version: None,
        };

        match self.assign_zone_relay(auto_req).await {
            Ok(assignment) => Ok(Some(assignment)),
            Err(err) if err.code() == SnErrorCode::NotFound => Ok(None),
            Err(err) => Err(err),
        }
    }

    async fn build_admission_decision(
        &self,
        req: &RelayAdmissionReq,
        decision: RelayAdmissionDecisionKind,
        reason: RelayAdmissionReason,
        expected_relay_sn: Option<String>,
        assignment_generation: Option<u64>,
    ) -> SnResult<RelayAdmissionDecision> {
        let now = Self::now_secs();
        let admission_expires_at = if decision == RelayAdmissionDecisionKind::Allow {
            Some(now.saturating_add(self.admission_ttl_secs))
        } else {
            None
        };

        let result = RelayAdmissionDecision {
            request_id: req.request_id.clone(),
            relay_id: req.relay_id.clone(),
            zone: req.zone.clone(),
            device_name: req.device_name.clone(),
            did: req.did.clone(),
            auth_context: req.auth_context.clone(),
            decision,
            reason,
            expected_relay_sn,
            assignment_generation,
            admission_expires_at,
            observed_ip: req.observed_ip.clone(),
            created_at: now,
        };

        self.record_admission_event(&result).await?;
        Ok(result)
    }

    async fn record_admission_event(&self, event: &RelayAdmissionDecision) -> SnResult<()> {
        sqlx::query(
            "INSERT INTO relay_admission_events
                (request_id, relay_id, zone, device_name, did, decision, reason,
                 expected_relay_sn, assignment_generation, observed_ip, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        )
        .bind(event.request_id.as_deref())
        .bind(event.relay_id.as_str())
        .bind(event.zone.as_str())
        .bind(event.device_name.as_deref())
        .bind(event.did.as_deref())
        .bind(event.decision.as_str())
        .bind(event.reason.as_str())
        .bind(event.expected_relay_sn.as_deref())
        .bind(Self::to_db_time_opt(
            event.assignment_generation,
            "assignment_generation",
        )?)
        .bind(event.observed_ip.as_deref())
        .bind(Self::to_db_time(event.created_at, "created_at")?)
        .execute(&self.pool)
        .await
        .map_err(|e| Self::db_err("insert relay admission event failed", e))?;

        Ok(())
    }

    async fn complete_assignment_migration(&self, zone: &str, generation: u64) -> SnResult<()> {
        let now = Self::now_secs();
        let result = sqlx::query(
            "UPDATE relay_assignments
             SET state = 'active',
                 migrated_from = NULL,
                 migration_deadline = NULL,
                 updated_at = ?1
             WHERE zone = ?2 AND generation = ?3 AND state = 'migrating'",
        )
        .bind(Self::to_db_time(now, "updated_at")?)
        .bind(zone)
        .bind(Self::to_db_time(generation, "generation")?)
        .execute(&self.pool)
        .await
        .map_err(|e| Self::db_err("complete relay migration failed", e))?;

        if result.rows_affected() == 0 {
            return Err(sn_err!(
                SnErrorCode::Conflict,
                "relay assignment migration generation does not match"
            ));
        }

        Ok(())
    }

    fn relay_node_select_sql(tail: &str) -> String {
        format!(
            "SELECT relay_id, relay_sn, public_host, http_endpoint, rtcp_endpoint,
                    region, isp, tags, capabilities, status, capacity_score,
                    current_load, last_heartbeat_at, drain_until, created_at, updated_at
             FROM relay_nodes {}",
            tail
        )
    }

    fn relay_assignment_select_sql(tail: &str) -> String {
        format!(
            "SELECT zone, relay_id, relay_sn, state, source, reason, generation,
                    backup_relay_id, sticky_until, lease_expires_at, migrated_from,
                    migration_deadline, source_version, created_at, updated_at
             FROM relay_assignments {}",
            tail
        )
    }

    fn relay_node_from_row(row: SqliteRow) -> SnResult<RelayNode> {
        Ok(RelayNode {
            relay_id: row.get(0),
            relay_sn: row.get(1),
            public_host: row.get(2),
            http_endpoint: row.get(3),
            rtcp_endpoint: row.get(4),
            region: row.get(5),
            isp: row.get(6),
            tags: Self::parse_json_string_vec(row.get(7), "relay tags")?,
            capabilities: Self::parse_json_string_vec(row.get(8), "relay capabilities")?,
            status: Self::parse_db_enum(row.get(9), "relay status")?,
            capacity_score: row.get(10),
            current_load: row.get(11),
            last_heartbeat_at: Self::opt_to_u64(row.get(12)),
            drain_until: Self::opt_to_u64(row.get(13)),
            created_at: Self::i64_to_u64(row.get(14)),
            updated_at: Self::i64_to_u64(row.get(15)),
        })
    }

    fn relay_assignment_from_row(row: SqliteRow) -> SnResult<RelayAssignment> {
        Ok(RelayAssignment {
            zone: row.get(0),
            relay_id: row.get(1),
            relay_sn: row.get(2),
            state: Self::parse_db_enum(row.get(3), "relay assignment state")?,
            source: Self::parse_db_enum(row.get(4), "relay assignment source")?,
            reason: row.get(5),
            generation: Self::i64_to_u64(row.get(6)),
            backup_relay_id: row.get(7),
            sticky_until: Self::opt_to_u64(row.get(8)),
            lease_expires_at: Self::opt_to_u64(row.get(9)),
            migrated_from: row.get(10),
            migration_deadline: Self::opt_to_u64(row.get(11)),
            source_version: row.get(12),
            created_at: Self::i64_to_u64(row.get(13)),
            updated_at: Self::i64_to_u64(row.get(14)),
        })
    }

    fn check_assignable_node(node: &RelayNode) -> SnResult<()> {
        if Self::is_assignable_node(node) {
            Ok(())
        } else {
            Err(sn_err!(
                SnErrorCode::Conflict,
                "relay node {} is not assignable: {}",
                node.relay_id,
                node.status
            ))
        }
    }

    fn is_assignable_node(node: &RelayNode) -> bool {
        matches!(node.status, RelayNodeStatus::Active)
    }

    fn check_non_empty(value: &str, field: &str) -> SnResult<()> {
        if value.trim().is_empty() {
            return Err(sn_err!(SnErrorCode::InvalidInput, "{} is empty", field));
        }

        Ok(())
    }

    fn normalize_optional_text(value: Option<String>) -> Option<String> {
        value
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    }

    fn normalize_label_vec(values: Vec<String>) -> Vec<String> {
        let mut seen = HashSet::new();
        let mut result = Vec::new();
        for value in values {
            let value = value.trim().to_string();
            if !value.is_empty() && seen.insert(value.clone()) {
                result.push(value);
            }
        }
        result
    }

    fn normalize_capability_vec(values: Vec<String>) -> Vec<String> {
        Self::normalize_label_vec(
            values
                .into_iter()
                .map(|value| value.to_ascii_lowercase())
                .collect(),
        )
    }

    fn validate_registration(node: &RelayNodeRegistration) -> SnResult<()> {
        Self::check_non_empty(node.relay_id.as_str(), "relay_id")?;
        Self::check_non_empty(node.relay_sn.as_str(), "relay_sn")?;
        Self::check_non_empty(node.public_host.as_str(), "public_host")?;
        if node.status == Some(RelayNodeStatus::Deleted) {
            return Err(sn_err!(
                SnErrorCode::InvalidInput,
                "deleted relay node cannot be registered"
            ));
        }
        if let Some(capacity_score) = node.capacity_score {
            if capacity_score <= 0 {
                return Err(sn_err!(
                    SnErrorCode::InvalidInput,
                    "capacity_score must be positive"
                ));
            }
        }

        Ok(())
    }

    fn validate_assignment_req(req: &AssignZoneRelayReq) -> SnResult<()> {
        Self::check_non_empty(req.zone.as_str(), "zone")?;
        if let Some(relay_id) = req.relay_id.as_deref() {
            Self::check_non_empty(relay_id, "relay_id")?;
        }
        if let Some(relay_sn) = req.relay_sn.as_deref() {
            Self::check_non_empty(relay_sn, "relay_sn")?;
        }
        Ok(())
    }

    fn validate_admission_req(req: &RelayAdmissionReq) -> SnResult<()> {
        Self::check_non_empty(req.relay_id.as_str(), "relay_id")?;
        Self::check_non_empty(req.zone.as_str(), "zone")?;
        if let Some(device_name) = req.device_name.as_deref() {
            Self::check_non_empty(device_name, "device_name")?;
        }
        if let Some(did) = req.did.as_deref() {
            Self::check_non_empty(did, "did")?;
        }
        Ok(())
    }

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn db_err(context: impl AsRef<str>, err: impl std::fmt::Display) -> SnError {
        sn_err!(SnErrorCode::DBError, "{}: {}", context.as_ref(), err)
    }

    fn parse_db_enum<T>(value: String, field: &str) -> SnResult<T>
    where
        T: FromStr<Err = String>,
    {
        value
            .parse()
            .map_err(|e| sn_err!(SnErrorCode::DBError, "invalid {} in db: {}", field, e))
    }

    fn parse_json_string_vec(value: Option<String>, field: &str) -> SnResult<Vec<String>> {
        match value {
            Some(value) if !value.trim().is_empty() => serde_json::from_str(&value)
                .map_err(|e| sn_err!(SnErrorCode::DBError, "invalid {} json: {}", field, e)),
            _ => Ok(Vec::new()),
        }
    }

    fn to_json_string(values: &[String], field: &str) -> SnResult<String> {
        serde_json::to_string(values)
            .map_err(|e| sn_err!(SnErrorCode::InvalidInput, "invalid {} json: {}", field, e))
    }

    fn i64_to_u64(value: i64) -> u64 {
        u64::try_from(value).unwrap_or_default()
    }

    fn opt_to_u64(value: Option<i64>) -> Option<u64> {
        value.and_then(|v| u64::try_from(v).ok())
    }

    fn to_db_time(value: u64, field: &str) -> SnResult<i64> {
        i64::try_from(value).map_err(|_| {
            sn_err!(
                SnErrorCode::InvalidInput,
                "{} is too large for sqlite integer",
                field
            )
        })
    }

    fn to_db_time_opt(value: Option<u64>, field: &str) -> SnResult<Option<i64>> {
        value
            .map(|value| Self::to_db_time(value, field))
            .transpose()
    }
}

#[async_trait::async_trait]
impl SnRelayManager for SqliteSnRelayManager {
    async fn register_relay_node(&self, node: RelayNodeRegistration) -> SnResult<RelayNode> {
        Self::validate_registration(&node)?;
        self.ensure_relay_sn_unique(node.relay_id.as_str(), node.relay_sn.as_str())
            .await?;

        let now = Self::now_secs();
        let existing = self.get_relay_node(node.relay_id.as_str()).await?;
        if existing
            .as_ref()
            .map(|node| node.status == RelayNodeStatus::Deleted)
            .unwrap_or(false)
        {
            return Err(sn_err!(
                SnErrorCode::Conflict,
                "deleted relay node cannot be registered"
            ));
        }
        let tags = Self::normalize_label_vec(node.tags);
        let capabilities = Self::normalize_capability_vec(node.capabilities);
        let status = node.status.unwrap_or_else(|| {
            existing
                .as_ref()
                .map(|node| node.status)
                .filter(|status| {
                    matches!(
                        status,
                        RelayNodeStatus::Draining | RelayNodeStatus::Disabled
                    )
                })
                .unwrap_or(RelayNodeStatus::Active)
        });
        let capacity_score = node.capacity_score.unwrap_or(DEFAULT_CAPACITY_SCORE);

        sqlx::query(
            "INSERT INTO relay_nodes
                (relay_id, relay_sn, public_host, http_endpoint, rtcp_endpoint, region, isp,
                 tags, capabilities, status, capacity_score, current_load, last_heartbeat_at,
                 drain_until, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 0, NULL, NULL, ?12, ?13)
             ON CONFLICT(relay_id) DO UPDATE SET
                relay_sn = excluded.relay_sn,
                public_host = excluded.public_host,
                http_endpoint = excluded.http_endpoint,
                rtcp_endpoint = excluded.rtcp_endpoint,
                region = excluded.region,
                isp = excluded.isp,
                tags = excluded.tags,
                capabilities = excluded.capabilities,
                status = excluded.status,
                capacity_score = excluded.capacity_score,
                updated_at = excluded.updated_at",
        )
        .bind(node.relay_id.as_str())
        .bind(node.relay_sn.as_str())
        .bind(node.public_host.as_str())
        .bind(Self::normalize_optional_text(node.http_endpoint).as_deref())
        .bind(Self::normalize_optional_text(node.rtcp_endpoint).as_deref())
        .bind(Self::normalize_optional_text(node.region).as_deref())
        .bind(Self::normalize_optional_text(node.isp).as_deref())
        .bind(Self::to_json_string(&tags, "tags")?)
        .bind(Self::to_json_string(&capabilities, "capabilities")?)
        .bind(status.as_str())
        .bind(capacity_score)
        .bind(Self::to_db_time(now, "created_at")?)
        .bind(Self::to_db_time(now, "updated_at")?)
        .execute(&self.pool)
        .await
        .map_err(|e| Self::db_err("upsert relay node failed", e))?;

        self.get_relay_node(node.relay_id.as_str())
            .await?
            .ok_or_else(|| sn_err!(SnErrorCode::NotFound, "relay node not found after upsert"))
    }

    async fn heartbeat_relay_node(&self, heartbeat: RelayHeartbeat) -> SnResult<RelayNodeHealth> {
        Self::check_non_empty(heartbeat.relay_id.as_str(), "relay_id")?;
        let existing = self
            .get_relay_node(heartbeat.relay_id.as_str())
            .await?
            .ok_or_else(|| sn_err!(SnErrorCode::NotFound, "relay node not found"))?;
        if existing.status == RelayNodeStatus::Deleted {
            return Err(sn_err!(
                SnErrorCode::Conflict,
                "deleted relay node cannot heartbeat"
            ));
        }

        let now = Self::now_secs();
        let status = heartbeat.status.unwrap_or(match existing.status {
            RelayNodeStatus::Unhealthy => RelayNodeStatus::Active,
            status => status,
        });
        let current_load = heartbeat.current_load.unwrap_or(existing.current_load);
        let capacity_score = heartbeat.capacity_score.unwrap_or(existing.capacity_score);
        if capacity_score <= 0 || current_load < 0 {
            return Err(sn_err!(
                SnErrorCode::InvalidInput,
                "capacity_score must be positive and current_load must be non-negative"
            ));
        }
        let drain_until = if status == RelayNodeStatus::Draining {
            heartbeat.drain_until.or(existing.drain_until)
        } else {
            heartbeat.drain_until
        };

        sqlx::query(
            "UPDATE relay_nodes
             SET status = ?1,
                 current_load = ?2,
                 capacity_score = ?3,
                 http_endpoint = COALESCE(?4, http_endpoint),
                 rtcp_endpoint = COALESCE(?5, rtcp_endpoint),
                 last_heartbeat_at = ?6,
                 drain_until = ?7,
                 updated_at = ?8
             WHERE relay_id = ?9",
        )
        .bind(status.as_str())
        .bind(current_load)
        .bind(capacity_score)
        .bind(Self::normalize_optional_text(heartbeat.http_endpoint).as_deref())
        .bind(Self::normalize_optional_text(heartbeat.rtcp_endpoint).as_deref())
        .bind(Self::to_db_time(now, "last_heartbeat_at")?)
        .bind(Self::to_db_time_opt(drain_until, "drain_until")?)
        .bind(Self::to_db_time(now, "updated_at")?)
        .bind(heartbeat.relay_id.as_str())
        .execute(&self.pool)
        .await
        .map_err(|e| Self::db_err("update relay heartbeat failed", e))?;

        Ok(RelayNodeHealth {
            relay_id: heartbeat.relay_id,
            status,
            capacity_score,
            current_load,
            last_heartbeat_at: now,
            drain_until,
            updated_at: now,
        })
    }

    async fn assign_zone_relay(&self, req: AssignZoneRelayReq) -> SnResult<RelayAssignment> {
        Self::validate_assignment_req(&req)?;
        let target = self.choose_relay_node(&req).await?;
        let now = Self::now_secs();
        let existing = self.fetch_assignment_for_update(req.zone.as_str()).await?;

        let assignment = if let Some(existing) = existing {
            let relay_changed = existing.relay_id != target.relay_id
                || existing.relay_sn != target.relay_sn
                || existing.state != RelayAssignmentState::Active;
            RelayAssignment {
                zone: existing.zone,
                relay_id: target.relay_id,
                relay_sn: target.relay_sn,
                state: RelayAssignmentState::Active,
                source: req.source,
                reason: req.reason.or_else(|| Some("assign_zone_relay".to_string())),
                generation: if relay_changed {
                    existing.generation.saturating_add(1)
                } else {
                    existing.generation
                },
                backup_relay_id: req.backup_relay_id.or(existing.backup_relay_id),
                sticky_until: req.sticky_until.or(existing.sticky_until),
                lease_expires_at: req.lease_expires_at.or(existing.lease_expires_at),
                migrated_from: if relay_changed {
                    Some(existing.relay_id)
                } else {
                    existing.migrated_from
                },
                migration_deadline: None,
                source_version: req.source_version.or(existing.source_version),
                created_at: existing.created_at,
                updated_at: now,
            }
        } else {
            RelayAssignment {
                zone: req.zone,
                relay_id: target.relay_id,
                relay_sn: target.relay_sn,
                state: RelayAssignmentState::Active,
                source: req.source,
                reason: req.reason.or_else(|| Some("first_assignment".to_string())),
                generation: 1,
                backup_relay_id: req.backup_relay_id,
                sticky_until: req.sticky_until,
                lease_expires_at: req.lease_expires_at,
                migrated_from: None,
                migration_deadline: None,
                source_version: req.source_version,
                created_at: now,
                updated_at: now,
            }
        };

        self.upsert_assignment(&assignment).await?;
        self.sync_zone_relay_cache(&assignment).await?;
        Ok(assignment)
    }

    async fn get_zone_relay(&self, zone: &str) -> SnResult<Option<RelayAssignment>> {
        Self::check_non_empty(zone, "zone")?;
        let row = sqlx::query(Self::relay_assignment_select_sql("WHERE zone = ?1").as_str())
            .bind(zone)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| Self::db_err("query relay assignment failed", e))?;

        row.map(Self::relay_assignment_from_row).transpose()
    }

    async fn check_relay_admission(
        &self,
        req: RelayAdmissionReq,
    ) -> SnResult<RelayAdmissionDecision> {
        Self::validate_admission_req(&req)?;
        let assignment = self.resolve_assignment_for_admission(&req).await?;
        let Some(assignment) = assignment else {
            return self
                .build_admission_decision(
                    &req,
                    RelayAdmissionDecisionKind::Reject,
                    RelayAdmissionReason::AssignmentMissing,
                    None,
                    None,
                )
                .await;
        };

        if assignment.state == RelayAssignmentState::Suspended {
            return self
                .build_admission_decision(
                    &req,
                    RelayAdmissionDecisionKind::Reject,
                    RelayAdmissionReason::ZoneSuspended,
                    Some(assignment.relay_sn),
                    Some(assignment.generation),
                )
                .await;
        }
        if assignment.state == RelayAssignmentState::Draining {
            return self
                .build_admission_decision(
                    &req,
                    RelayAdmissionDecisionKind::Reject,
                    RelayAdmissionReason::RelayDraining,
                    Some(assignment.relay_sn),
                    Some(assignment.generation),
                )
                .await;
        }

        if req
            .assignment_generation
            .map(|generation| generation != assignment.generation)
            .unwrap_or(false)
        {
            return self
                .build_admission_decision(
                    &req,
                    RelayAdmissionDecisionKind::Redirect,
                    RelayAdmissionReason::StaleGeneration,
                    Some(assignment.relay_sn),
                    Some(assignment.generation),
                )
                .await;
        }

        if !self.verify_device_binding(&req).await? {
            return self
                .build_admission_decision(
                    &req,
                    RelayAdmissionDecisionKind::Reject,
                    RelayAdmissionReason::DeviceNotFound,
                    Some(assignment.relay_sn),
                    Some(assignment.generation),
                )
                .await;
        }

        if req.relay_id != assignment.relay_id {
            let reason = if assignment.state == RelayAssignmentState::Migrating {
                RelayAdmissionReason::AssignmentMigrating
            } else {
                RelayAdmissionReason::WrongRelay
            };
            return self
                .build_admission_decision(
                    &req,
                    RelayAdmissionDecisionKind::Redirect,
                    reason,
                    Some(assignment.relay_sn),
                    Some(assignment.generation),
                )
                .await;
        }

        let node = self.get_relay_node(req.relay_id.as_str()).await?;
        let Some(node) = node else {
            return self
                .build_admission_decision(
                    &req,
                    RelayAdmissionDecisionKind::Reject,
                    RelayAdmissionReason::RelayUnavailable,
                    Some(assignment.relay_sn),
                    Some(assignment.generation),
                )
                .await;
        };

        match node.status {
            RelayNodeStatus::Active => {}
            RelayNodeStatus::Draining => {
                return self
                    .build_admission_decision(
                        &req,
                        RelayAdmissionDecisionKind::Reject,
                        RelayAdmissionReason::RelayDraining,
                        Some(assignment.relay_sn),
                        Some(assignment.generation),
                    )
                    .await;
            }
            RelayNodeStatus::Disabled | RelayNodeStatus::Unhealthy | RelayNodeStatus::Deleted => {
                return self
                    .build_admission_decision(
                        &req,
                        RelayAdmissionDecisionKind::Reject,
                        RelayAdmissionReason::RelayUnavailable,
                        Some(assignment.relay_sn),
                        Some(assignment.generation),
                    )
                    .await;
            }
        }

        self.build_admission_decision(
            &req,
            RelayAdmissionDecisionKind::Allow,
            RelayAdmissionReason::Ok,
            None,
            Some(assignment.generation),
        )
        .await
    }

    async fn start_relay_migration(&self, req: RelayMigrationReq) -> SnResult<RelayAssignment> {
        Self::check_non_empty(req.zone.as_str(), "zone")?;
        let target_req = AssignZoneRelayReq {
            zone: req.zone.clone(),
            relay_id: req.target_relay_id,
            relay_sn: req.target_relay_sn,
            from_ip: None,
            region: None,
            source: RelayAssignmentSource::Migration,
            reason: req.reason.clone().or_else(|| Some("migration".to_string())),
            sticky_until: None,
            lease_expires_at: None,
            backup_relay_id: None,
            source_version: req.source_version.clone(),
        };
        let target = self.choose_relay_node(&target_req).await?;
        let existing = self
            .get_zone_relay(req.zone.as_str())
            .await?
            .ok_or_else(|| sn_err!(SnErrorCode::NotFound, "relay assignment not found"))?;
        if existing.relay_id == target.relay_id {
            return Err(sn_err!(
                SnErrorCode::Conflict,
                "target relay is already assigned"
            ));
        }

        let now = Self::now_secs();
        let assignment = RelayAssignment {
            zone: existing.zone,
            relay_id: target.relay_id,
            relay_sn: target.relay_sn,
            state: RelayAssignmentState::Migrating,
            source: RelayAssignmentSource::Migration,
            reason: req.reason.or_else(|| Some("migration".to_string())),
            generation: existing.generation.saturating_add(1),
            backup_relay_id: Some(existing.relay_id.clone()),
            sticky_until: existing.sticky_until,
            lease_expires_at: existing.lease_expires_at,
            migrated_from: Some(existing.relay_id),
            migration_deadline: Some(
                req.migration_deadline
                    .unwrap_or_else(|| now.saturating_add(DEFAULT_MIGRATION_WINDOW_SECS)),
            ),
            source_version: req.source_version.or(existing.source_version),
            created_at: existing.created_at,
            updated_at: now,
        };

        self.upsert_assignment(&assignment).await?;
        self.sync_zone_relay_cache(&assignment).await?;
        Ok(assignment)
    }

    async fn complete_relay_migration(&self, zone: &str, generation: u64) -> SnResult<()> {
        Self::check_non_empty(zone, "zone")?;
        self.complete_assignment_migration(zone, generation).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SnAuthDB, SqliteSnAuthDB, ZoneInfoPatch};

    async fn temp_mgr() -> SnResult<(tempfile::TempDir, SqliteSnRelayManager)> {
        let tmp_dir = tempfile::tempdir()
            .map_err(|e| sn_err!(SnErrorCode::DBError, "create temp dir failed: {}", e))?;
        let db_path = tmp_dir.path().join("sn_relay_mgr.sqlite3");
        let mgr = SqliteSnRelayManager::new_by_path(db_path.to_string_lossy().as_ref()).await?;
        mgr.initialize_database().await?;
        Ok((tmp_dir, mgr))
    }

    fn node(relay_id: &str, relay_sn: &str, region: &str) -> RelayNodeRegistration {
        RelayNodeRegistration {
            relay_id: relay_id.to_string(),
            relay_sn: relay_sn.to_string(),
            public_host: relay_sn.to_string(),
            http_endpoint: Some(format!("https://{}", relay_sn)),
            rtcp_endpoint: Some(format!("rtcp://{}:443", relay_sn)),
            region: Some(region.to_string()),
            isp: None,
            tags: vec!["edge".to_string()],
            capabilities: vec!["http_relay".to_string(), "rtcp_relay".to_string()],
            status: None,
            capacity_score: Some(100),
        }
    }

    #[tokio::test]
    async fn test_register_assign_and_get() -> SnResult<()> {
        let (_tmp_dir, mgr) = temp_mgr().await?;
        let relay = mgr
            .register_relay_node(node("relay-a", "relay-a.example", "us"))
            .await?;
        assert_eq!(relay.status, RelayNodeStatus::Active);

        let assignment = mgr
            .assign_zone_relay(AssignZoneRelayReq {
                zone: "alice".to_string(),
                relay_id: Some("relay-a".to_string()),
                relay_sn: None,
                from_ip: None,
                region: None,
                source: RelayAssignmentSource::Admin,
                reason: Some("test".to_string()),
                sticky_until: None,
                lease_expires_at: None,
                backup_relay_id: None,
                source_version: Some("v1".to_string()),
            })
            .await?;

        assert_eq!(assignment.generation, 1);
        assert_eq!(assignment.relay_sn, "relay-a.example");
        assert_eq!(
            mgr.get_zone_relay("alice").await?.unwrap().relay_id,
            "relay-a"
        );
        assert!(mgr.zone_belongs_to_relay("alice", "relay-a").await?);

        Ok(())
    }

    #[tokio::test]
    async fn test_admission_redirect_and_allow() -> SnResult<()> {
        let (_tmp_dir, mgr) = temp_mgr().await?;
        mgr.register_relay_node(node("relay-a", "relay-a.example", "us"))
            .await?;
        mgr.register_relay_node(node("relay-b", "relay-b.example", "us"))
            .await?;
        let assignment = mgr
            .assign_zone_relay(AssignZoneRelayReq {
                zone: "alice".to_string(),
                relay_id: Some("relay-a".to_string()),
                relay_sn: None,
                from_ip: None,
                region: None,
                source: RelayAssignmentSource::Admin,
                reason: Some("test".to_string()),
                sticky_until: None,
                lease_expires_at: None,
                backup_relay_id: None,
                source_version: None,
            })
            .await?;

        let redirect = mgr
            .check_relay_admission(RelayAdmissionReq {
                request_id: Some("req-1".to_string()),
                relay_id: "relay-b".to_string(),
                zone: "alice".to_string(),
                device_name: Some("ood1".to_string()),
                did: Some("did:dev:alice-ood1".to_string()),
                auth_context: Some("Device(alice, ood1, did:dev:alice-ood1)".to_string()),
                assignment_generation: Some(assignment.generation),
                observed_ip: Some("1.2.3.4".to_string()),
            })
            .await?;
        assert_eq!(redirect.decision, RelayAdmissionDecisionKind::Redirect);
        assert_eq!(redirect.reason, RelayAdmissionReason::WrongRelay);
        assert_eq!(
            redirect.expected_relay_sn.as_deref(),
            Some("relay-a.example")
        );

        let allowed = mgr
            .check_relay_admission(RelayAdmissionReq {
                request_id: Some("req-2".to_string()),
                relay_id: "relay-a".to_string(),
                zone: "alice".to_string(),
                device_name: Some("ood1".to_string()),
                did: Some("did:dev:alice-ood1".to_string()),
                auth_context: Some("Device(alice, ood1, did:dev:alice-ood1)".to_string()),
                assignment_generation: Some(assignment.generation),
                observed_ip: Some("1.2.3.4".to_string()),
            })
            .await?;
        assert_eq!(allowed.decision, RelayAdmissionDecisionKind::Allow);
        assert!(allowed.admission_expires_at.is_some());

        Ok(())
    }

    #[tokio::test]
    async fn test_draining_relay_rejects_admission_and_auto_assignment_skips_it() -> SnResult<()> {
        let (_tmp_dir, mgr) = temp_mgr().await?;
        mgr.register_relay_node(node("relay-a", "relay-a.example", "us"))
            .await?;
        mgr.register_relay_node(node("relay-b", "relay-b.example", "us"))
            .await?;
        let assignment = mgr
            .assign_zone_relay(AssignZoneRelayReq {
                zone: "alice".to_string(),
                relay_id: Some("relay-a".to_string()),
                relay_sn: None,
                from_ip: None,
                region: None,
                source: RelayAssignmentSource::Admin,
                reason: Some("test".to_string()),
                sticky_until: None,
                lease_expires_at: None,
                backup_relay_id: None,
                source_version: None,
            })
            .await?;

        mgr.heartbeat_relay_node(RelayHeartbeat {
            relay_id: "relay-a".to_string(),
            status: Some(RelayNodeStatus::Draining),
            current_load: Some(1),
            capacity_score: None,
            drain_until: Some(SqliteSnRelayManager::now_secs() + 60),
            http_endpoint: None,
            rtcp_endpoint: None,
        })
        .await?;

        let rejected = mgr
            .check_relay_admission(RelayAdmissionReq {
                request_id: Some("req-drain".to_string()),
                relay_id: "relay-a".to_string(),
                zone: "alice".to_string(),
                device_name: None,
                did: None,
                auth_context: None,
                assignment_generation: Some(assignment.generation),
                observed_ip: None,
            })
            .await?;
        assert_eq!(rejected.decision, RelayAdmissionDecisionKind::Reject);
        assert_eq!(rejected.reason, RelayAdmissionReason::RelayDraining);

        let auto_assigned = mgr
            .assign_zone_relay(AssignZoneRelayReq::auto("bob"))
            .await?;
        assert_eq!(auto_assigned.relay_id, "relay-b");

        Ok(())
    }

    #[tokio::test]
    async fn test_migration_generation_and_complete() -> SnResult<()> {
        let (_tmp_dir, mgr) = temp_mgr().await?;
        mgr.register_relay_node(node("relay-a", "relay-a.example", "us"))
            .await?;
        mgr.register_relay_node(node("relay-b", "relay-b.example", "us"))
            .await?;
        let initial = mgr
            .assign_zone_relay(AssignZoneRelayReq {
                zone: "alice".to_string(),
                relay_id: Some("relay-a".to_string()),
                relay_sn: None,
                from_ip: None,
                region: None,
                source: RelayAssignmentSource::Admin,
                reason: Some("test".to_string()),
                sticky_until: None,
                lease_expires_at: None,
                backup_relay_id: None,
                source_version: None,
            })
            .await?;

        let migrating = mgr
            .start_relay_migration(RelayMigrationReq {
                zone: "alice".to_string(),
                target_relay_id: Some("relay-b".to_string()),
                target_relay_sn: None,
                operator: Some("admin".to_string()),
                reason: Some("rebalance".to_string()),
                migration_deadline: None,
                source_version: Some("v2".to_string()),
            })
            .await?;
        assert_eq!(migrating.state, RelayAssignmentState::Migrating);
        assert_eq!(migrating.generation, initial.generation + 1);
        assert_eq!(migrating.migrated_from.as_deref(), Some("relay-a"));
        assert_eq!(migrating.relay_id, "relay-b");

        mgr.complete_relay_migration("alice", migrating.generation)
            .await?;
        let active = mgr.get_zone_relay("alice").await?.unwrap();
        assert_eq!(active.state, RelayAssignmentState::Active);
        assert!(active.migrated_from.is_none());

        Ok(())
    }

    #[tokio::test]
    async fn test_assignment_syncs_zone_info_relay_sn() -> SnResult<()> {
        let tmp_dir = tempfile::tempdir()
            .map_err(|e| sn_err!(SnErrorCode::DBError, "create temp dir failed: {}", e))?;
        let relay_path = tmp_dir.path().join("sn_relay_mgr.sqlite3");
        let auth_path = tmp_dir.path().join("sn_auth.sqlite3");
        let auth_db = SqliteSnAuthDB::new_by_path(auth_path.to_string_lossy().as_ref()).await?;
        auth_db.initialize_database().await?;
        auth_db.insert_activation_code("alice-code").await?;
        assert!(
            auth_db
                .register_user_v2("alice-code", "alice", "hash", "salt", "pbkdf2")
                .await?
        );
        auth_db
            .update_zone_info(
                "alice",
                ZoneInfoPatch {
                    zone: Some("alice.zone".to_string()),
                    ..Default::default()
                },
            )
            .await?;

        let mgr = SqliteSnRelayManager::new_by_path(relay_path.to_string_lossy().as_ref())
            .await?
            .with_auth_db(Arc::new(auth_db));
        mgr.initialize_database().await?;
        mgr.register_relay_node(node("relay-a", "relay-a.example", "us"))
            .await?;
        mgr.assign_zone_relay(AssignZoneRelayReq {
            zone: "alice.zone".to_string(),
            relay_id: Some("relay-a".to_string()),
            relay_sn: None,
            from_ip: None,
            region: None,
            source: RelayAssignmentSource::Admin,
            reason: Some("test".to_string()),
            sticky_until: None,
            lease_expires_at: None,
            backup_relay_id: None,
            source_version: Some("relay-v1".to_string()),
        })
        .await?;

        let zone_info = mgr
            .auth_db
            .as_ref()
            .unwrap()
            .get_zone_info("alice")
            .await?
            .unwrap();
        assert_eq!(zone_info.relay_sn.as_deref(), Some("relay-a.example"));
        assert_eq!(zone_info.source_version.as_deref(), Some("relay-v1"));

        Ok(())
    }
}
