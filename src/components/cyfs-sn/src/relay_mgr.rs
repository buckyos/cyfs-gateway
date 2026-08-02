use crate::{sn_err, SnDeviceInfoDBRef, SnDeviceState, SnError, SnErrorCode, SnResult};
use cyfs_gateway_api::normalize_sn_region_id_hint;
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use sfo_ip::{CachePolicy, Searcher};
use sqlx::sqlite::SqliteRow;
#[cfg(test)]
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::{Row, Sqlite, SqlitePool, Transaction};
use std::cmp::Ordering;
use std::collections::HashSet;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

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
    #[serde(with = "canonical_ip_pair")]
    pub ips: [IpAddr; 2],
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
    #[serde(with = "canonical_ip_pair")]
    pub ips: [IpAddr; 2],
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
pub struct RelayNodeAddressUpdate {
    pub relay_id: String,
    #[serde(with = "canonical_ip_pair")]
    pub ips: [IpAddr; 2],
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Default)]
pub struct RelayNodeIpMapReq {
    pub if_revision: Option<u64>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct RelayNodeIpEntry {
    pub relay_id: String,
    pub relay_sn: String,
    #[serde(with = "canonical_ip_pair")]
    pub ips: [IpAddr; 2],
    pub status: RelayNodeStatus,
    pub updated_at: u64,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct RelayNodeIpMapSnapshot {
    pub revision: u64,
    pub generated_at: u64,
    pub nodes: Vec<RelayNodeIpEntry>,
}

mod canonical_ip_pair {
    use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};
    use std::net::IpAddr;

    pub fn serialize<S>(ips: &[IpAddr; 2], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        [ips[0].to_string(), ips[1].to_string()].serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[IpAddr; 2], D::Error>
    where
        D: Deserializer<'de>,
    {
        let values = Vec::<String>::deserialize(deserializer)?;
        if values.len() != 2 {
            return Err(D::Error::custom(format!(
                "relay node must contain exactly two IP addresses, got {}",
                values.len()
            )));
        }
        let mut ips = [IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED); 2];
        for (slot, value) in values.into_iter().enumerate() {
            let ip = value.parse::<IpAddr>().map_err(|e| {
                D::Error::custom(format!("invalid relay IP address in slot {slot}: {e}"))
            })?;
            if ip.to_string() != value {
                return Err(D::Error::custom(format!(
                    "relay IP address in slot {slot} is not canonical: {value}"
                )));
            }
            ips[slot] = ip;
        }
        Ok(ips)
    }
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
pub struct AllocateZoneRelayReq {
    pub zone: String,
    pub preferred_region: Option<String>,
    pub source_ip: Option<IpAddr>,
    pub reason: String,
    pub source_version: Option<String>,
}

impl AllocateZoneRelayReq {
    pub fn new(zone: impl Into<String>) -> Self {
        Self {
            zone: zone.into(),
            preferred_region: None,
            source_ip: None,
            reason: "auto_assign".to_string(),
            source_version: None,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct GeoIpInfo {
    pub country_code: Option<String>,
    pub country: Option<String>,
    pub province: Option<String>,
    pub city: Option<String>,
    pub isp: Option<String>,
}

#[async_trait::async_trait]
pub trait GeoIpResolver: Send + Sync + 'static {
    async fn lookup(&self, ip: IpAddr) -> SnResult<Option<GeoIpInfo>>;
}

pub type GeoIpResolverRef = Arc<dyn GeoIpResolver>;

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct GeoIpResolverConfig {
    pub ipv4_xdb_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv6_xdb_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_policy: Option<String>,
}

/// 直接封装 ip2region XDB，不依赖 process-chain collection。
pub struct XdbGeoIpResolver {
    ipv4: RwLock<Searcher>,
    ipv6: Option<RwLock<Searcher>>,
}

impl XdbGeoIpResolver {
    pub fn new(config: &GeoIpResolverConfig) -> SnResult<Self> {
        let cache_policy = match config
            .cache_policy
            .as_deref()
            .unwrap_or("vector_index")
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "no_cache" => CachePolicy::NoCache,
            "vector_index" => CachePolicy::VectorIndex,
            "full_memory" => CachePolicy::FullMemory,
            value => {
                return Err(sn_err!(
                    SnErrorCode::InvalidInput,
                    "invalid geoip cache_policy: {}",
                    value
                ));
            }
        };
        let ipv4 = Searcher::new(config.ipv4_xdb_path.clone(), cache_policy).map_err(|error| {
            sn_err!(
                SnErrorCode::InvalidInput,
                "open GeoIP ipv4 XDB failed: {}",
                error
            )
        })?;
        let ipv6 = config
            .ipv6_xdb_path
            .as_ref()
            .map(|path| {
                Searcher::new(path.clone(), cache_policy)
                    .map(RwLock::new)
                    .map_err(|error| {
                        sn_err!(
                            SnErrorCode::InvalidInput,
                            "open GeoIP ipv6 XDB failed: {}",
                            error
                        )
                    })
            })
            .transpose()?;
        Ok(Self {
            ipv4: RwLock::new(ipv4),
            ipv6,
        })
    }

    fn clean_part(value: Option<&&str>) -> Option<String> {
        value
            .map(|value| value.trim())
            .filter(|value| !value.is_empty() && *value != "0")
            .map(ToString::to_string)
    }

    fn parse_record(record: &str) -> Option<GeoIpInfo> {
        if record.trim().is_empty() {
            return None;
        }
        let parts: Vec<&str> = record.split('|').collect();
        Some(GeoIpInfo {
            country: Self::clean_part(parts.first()),
            province: Self::clean_part(parts.get(1)),
            city: Self::clean_part(parts.get(2)),
            isp: Self::clean_part(parts.get(3)),
            country_code: Self::clean_part(parts.get(4)),
        })
    }
}

#[async_trait::async_trait]
impl GeoIpResolver for XdbGeoIpResolver {
    async fn lookup(&self, ip: IpAddr) -> SnResult<Option<GeoIpInfo>> {
        let searcher = match ip {
            IpAddr::V4(_) => &self.ipv4,
            IpAddr::V6(_) => match self.ipv6.as_ref() {
                Some(searcher) => searcher,
                None => return Ok(None),
            },
        };
        let searcher = searcher
            .read()
            .map_err(|_| sn_err!(SnErrorCode::Failed, "GeoIP XDB lock is poisoned"))?;
        let value = searcher
            .search(ip.to_string().as_str())
            .map_err(|error| sn_err!(SnErrorCode::Failed, "GeoIP XDB lookup failed: {}", error))?;
        Ok(Self::parse_record(value.as_str()))
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayMatchRule {
    PreferredRegion,
    GeoCountryCode,
    GeoProvince,
    GeoCity,
    GeoIsp,
}

impl RelayMatchRule {
    fn as_str(self) -> &'static str {
        match self {
            Self::PreferredRegion => "preferred_region",
            Self::GeoCountryCode => "geo_country_code",
            Self::GeoProvince => "geo_province",
            Self::GeoCity => "geo_city",
            Self::GeoIsp => "geo_isp",
        }
    }
}

fn default_match_rules() -> Vec<RelayMatchRule> {
    vec![
        RelayMatchRule::PreferredRegion,
        RelayMatchRule::GeoCountryCode,
        RelayMatchRule::GeoProvince,
        RelayMatchRule::GeoCity,
        RelayMatchRule::GeoIsp,
    ]
}

fn default_fallback_relays() -> Vec<String> {
    vec!["*".to_string()]
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct RelayAllocationConfig {
    /// 有序匹配规则，首个产生健康候选集的规则获胜。
    #[serde(default = "default_match_rules")]
    pub match_rules: Vec<RelayMatchRule>,
    /// relay_id 或 relay_sn；`*` 表示所有健康节点。空数组表示禁用 fallback。
    #[serde(default = "default_fallback_relays")]
    pub fallback_relays: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub geoip: Option<GeoIpResolverConfig>,
}

impl Default for RelayAllocationConfig {
    fn default() -> Self {
        Self {
            match_rules: default_match_rules(),
            fallback_relays: default_fallback_relays(),
            geoip: None,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RelayAllocationPending {
    pub zone: String,
    pub preferred_region: Option<String>,
    pub reason: String,
    pub source_version: Option<String>,
    pub attempts: u64,
    pub last_error: String,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct RelayAllocationMetricsSnapshot {
    pub attempts: u64,
    pub successes: u64,
    pub fallbacks: u64,
    pub failures: u64,
    pub geoip_failures: u64,
}

#[derive(Default)]
struct RelayAllocationMetrics {
    attempts: AtomicU64,
    successes: AtomicU64,
    fallbacks: AtomicU64,
    failures: AtomicU64,
    geoip_failures: AtomicU64,
}

pub(crate) struct RelaySelection {
    pub(crate) node: RelayNode,
    pub(crate) rule: &'static str,
    pub(crate) fallback: bool,
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
    fn allocation_metrics(&self) -> RelayAllocationMetricsSnapshot;
    async fn register_relay_node(&self, node: RelayNodeRegistration) -> SnResult<RelayNode>;
    async fn heartbeat_relay_node(&self, heartbeat: RelayHeartbeat) -> SnResult<RelayNodeHealth>;
    async fn update_relay_node_addresses(
        &self,
        update: RelayNodeAddressUpdate,
    ) -> SnResult<RelayNode>;
    async fn get_relay_node(&self, relay_id: &str) -> SnResult<Option<RelayNode>>;
    async fn list_relay_nodes(&self) -> SnResult<Vec<RelayNode>>;
    async fn get_relay_nodes_ip_map(
        &self,
        req: RelayNodeIpMapReq,
    ) -> SnResult<Option<RelayNodeIpMapSnapshot>>;
    async fn assign_zone_relay(&self, req: AssignZoneRelayReq) -> SnResult<RelayAssignment>;
    async fn allocate_zone_relay(&self, req: AllocateZoneRelayReq) -> SnResult<RelayAssignment>;
    async fn get_zone_relay(&self, zone: &str) -> SnResult<Option<RelayAssignment>>;
    async fn check_relay_admission(
        &self,
        req: RelayAdmissionReq,
    ) -> SnResult<RelayAdmissionDecision>;
    async fn start_relay_migration(&self, req: RelayMigrationReq) -> SnResult<RelayAssignment>;
    async fn complete_relay_migration(&self, zone: &str, generation: u64) -> SnResult<()>;
}

pub(crate) struct SqliteSnRelayManager {
    pool: SqlitePool,
    device_info_db: Option<SnDeviceInfoDBRef>,
    admission_ttl_secs: u64,
    allocation_config: RelayAllocationConfig,
    geo_ip_resolver: Option<GeoIpResolverRef>,
    allocation_metrics: RelayAllocationMetrics,
}

impl SqliteSnRelayManager {
    #[cfg(test)]
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

        Ok(Self::from_pool(pool))
    }

    pub(crate) fn from_pool(pool: SqlitePool) -> Self {
        Self {
            pool,
            device_info_db: None,
            admission_ttl_secs: DEFAULT_ADMISSION_TTL_SECS,
            allocation_config: RelayAllocationConfig::default(),
            geo_ip_resolver: None,
            allocation_metrics: RelayAllocationMetrics::default(),
        }
    }

    #[allow(dead_code)]
    pub fn with_device_info_db(mut self, device_info_db: SnDeviceInfoDBRef) -> Self {
        self.device_info_db = Some(device_info_db);
        self
    }

    #[allow(dead_code)]
    pub fn with_admission_ttl_secs(mut self, admission_ttl_secs: u64) -> Self {
        self.admission_ttl_secs = admission_ttl_secs;
        self
    }

    pub fn with_allocation_config(mut self, allocation_config: RelayAllocationConfig) -> Self {
        self.allocation_config = allocation_config;
        self
    }

    pub fn with_geo_ip_resolver(mut self, geo_ip_resolver: GeoIpResolverRef) -> Self {
        self.geo_ip_resolver = Some(geo_ip_resolver);
        self
    }

    pub fn allocation_metrics(&self) -> RelayAllocationMetricsSnapshot {
        RelayAllocationMetricsSnapshot {
            attempts: self
                .allocation_metrics
                .attempts
                .load(AtomicOrdering::Relaxed),
            successes: self
                .allocation_metrics
                .successes
                .load(AtomicOrdering::Relaxed),
            fallbacks: self
                .allocation_metrics
                .fallbacks
                .load(AtomicOrdering::Relaxed),
            failures: self
                .allocation_metrics
                .failures
                .load(AtomicOrdering::Relaxed),
            geoip_failures: self
                .allocation_metrics
                .geoip_failures
                .load(AtomicOrdering::Relaxed),
        }
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
            "CREATE TABLE IF NOT EXISTS relay_node_addresses (
                relay_id TEXT NOT NULL,
                slot INTEGER NOT NULL CHECK(slot IN (0, 1)),
                ip TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                PRIMARY KEY (relay_id, slot),
                FOREIGN KEY (relay_id) REFERENCES relay_nodes(relay_id) ON DELETE CASCADE
            )",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| Self::db_err("create relay_node_addresses table failed", e))?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS relay_metadata (
                key TEXT PRIMARY KEY,
                value INTEGER NOT NULL
            )",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| Self::db_err("create relay_metadata table failed", e))?;
        sqlx::query(
            "INSERT OR IGNORE INTO relay_metadata (key, value)
             VALUES ('node_map_revision', 0)",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| Self::db_err("initialize relay node-map revision failed", e))?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS relay_assignments (
                zone TEXT PRIMARY KEY,
                relay_id TEXT NOT NULL,
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
        self.migrate_relay_assignments_schema().await?;

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

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS relay_allocation_pending (
                zone TEXT PRIMARY KEY,
                preferred_region TEXT NULL,
                reason TEXT NOT NULL,
                source_version TEXT NULL,
                attempts INTEGER NOT NULL DEFAULT 1,
                last_error TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            )",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| Self::db_err("create relay allocation pending table failed", e))?;

        Ok(())
    }

    async fn migrate_relay_assignments_schema(&self) -> SnResult<()> {
        let columns = sqlx::query("PRAGMA table_info(relay_assignments)")
            .fetch_all(&self.pool)
            .await
            .map_err(|e| Self::db_err("inspect relay_assignments schema failed", e))?;
        if !columns.iter().any(|row| {
            row.try_get::<String, _>("name")
                .map(|name| name == "relay_sn")
                .unwrap_or(false)
        }) {
            return Ok(());
        }

        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| Self::db_err("begin relay assignment migration failed", e))?;
        sqlx::query("ALTER TABLE relay_assignments RENAME TO relay_assignments_legacy")
            .execute(&mut *tx)
            .await
            .map_err(|e| Self::db_err("rename legacy relay_assignments failed", e))?;
        sqlx::query(
            "CREATE TABLE relay_assignments (
                zone TEXT PRIMARY KEY,
                relay_id TEXT NOT NULL,
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
                updated_at INTEGER NOT NULL,
                FOREIGN KEY (relay_id) REFERENCES relay_nodes(relay_id)
            )",
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| Self::db_err("create normalized relay_assignments failed", e))?;
        sqlx::query(
            "INSERT INTO relay_assignments
                (zone, relay_id, state, source, reason, generation, backup_relay_id,
                 sticky_until, lease_expires_at, migrated_from, migration_deadline,
                 source_version, created_at, updated_at)
             SELECT zone, relay_id, state, source, reason, generation, backup_relay_id,
                    sticky_until, lease_expires_at, migrated_from, migration_deadline,
                    source_version, created_at, updated_at
             FROM relay_assignments_legacy",
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| Self::db_err("copy legacy relay assignments failed", e))?;
        sqlx::query("DROP TABLE relay_assignments_legacy")
            .execute(&mut *tx)
            .await
            .map_err(|e| Self::db_err("drop legacy relay_assignments failed", e))?;
        tx.commit()
            .await
            .map_err(|e| Self::db_err("commit relay assignment migration failed", e))?;
        Ok(())
    }

    pub async fn get_relay_node(&self, relay_id: &str) -> SnResult<Option<RelayNode>> {
        Self::check_non_empty(relay_id, "relay_id")?;
        let row = sqlx::query(Self::relay_node_select_sql("WHERE n.relay_id = ?1").as_str())
            .bind(relay_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| Self::db_err("query relay node failed", e))?;

        row.map(Self::relay_node_from_row).transpose()
    }

    pub async fn list_relay_nodes(&self) -> SnResult<Vec<RelayNode>> {
        let rows = sqlx::query(Self::relay_node_select_sql("ORDER BY n.relay_id ASC").as_str())
            .fetch_all(&self.pool)
            .await
            .map_err(|e| Self::db_err("list relay nodes failed", e))?;

        rows.into_iter()
            .map(Self::relay_node_from_row)
            .collect::<SnResult<Vec<_>>>()
    }

    pub async fn get_relay_nodes_ip_map_snapshot(
        &self,
        if_revision: Option<u64>,
    ) -> SnResult<Option<RelayNodeIpMapSnapshot>> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| Self::db_err("begin relay node-map snapshot failed", e))?;
        let revision: i64 =
            sqlx::query_scalar("SELECT value FROM relay_metadata WHERE key = 'node_map_revision'")
                .fetch_one(&mut *tx)
                .await
                .map_err(|e| Self::db_err("read relay node-map revision failed", e))?;
        let revision = Self::i64_to_u64(revision);
        if if_revision == Some(revision) {
            tx.commit()
                .await
                .map_err(|e| Self::db_err("commit relay node-map revision read failed", e))?;
            return Ok(None);
        }

        let rows = sqlx::query(
            "SELECT relay_id, relay_sn, status, updated_at
             FROM relay_nodes
             WHERE status <> 'deleted'
             ORDER BY relay_id ASC",
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| Self::db_err("list relay node-map nodes failed", e))?;
        let mut nodes = Vec::with_capacity(rows.len());
        for row in rows {
            let relay_id: String = row
                .try_get(0)
                .map_err(|e| Self::db_err("read relay node-map relay_id failed", e))?;
            let address_rows = sqlx::query(
                "SELECT slot, ip FROM relay_node_addresses
                 WHERE relay_id = ?1 ORDER BY slot ASC",
            )
            .bind(relay_id.as_str())
            .fetch_all(&mut *tx)
            .await
            .map_err(|e| Self::db_err("read relay node-map addresses failed", e))?;
            if address_rows.len() != 2 {
                return Err(sn_err!(
                    SnErrorCode::DBError,
                    "relay node {} has {} addresses; expected exactly 2",
                    relay_id,
                    address_rows.len()
                ));
            }
            let mut ips = [IpAddr::V4(Ipv4Addr::UNSPECIFIED); 2];
            for (expected_slot, address_row) in address_rows.into_iter().enumerate() {
                let slot: i64 = address_row
                    .try_get(0)
                    .map_err(|e| Self::db_err("read relay address slot failed", e))?;
                if slot != expected_slot as i64 {
                    return Err(sn_err!(
                        SnErrorCode::DBError,
                        "relay node {} is missing address slot {}",
                        relay_id,
                        expected_slot
                    ));
                }
                let value: Option<String> = address_row
                    .try_get(1)
                    .map_err(|e| Self::db_err("read relay address failed", e))?;
                ips[expected_slot] = Self::parse_stored_ip(value, expected_slot)?;
            }
            nodes.push(RelayNodeIpEntry {
                relay_id,
                relay_sn: row
                    .try_get(1)
                    .map_err(|e| Self::db_err("read relay node-map relay_sn failed", e))?,
                ips,
                status: Self::parse_db_enum(
                    row.try_get(2)
                        .map_err(|e| Self::db_err("read relay node-map status failed", e))?,
                    "relay status",
                )?,
                updated_at: Self::i64_to_u64(
                    row.try_get(3)
                        .map_err(|e| Self::db_err("read relay node-map updated_at failed", e))?,
                ),
            });
        }
        tx.commit()
            .await
            .map_err(|e| Self::db_err("commit relay node-map snapshot failed", e))?;
        Ok(Some(RelayNodeIpMapSnapshot {
            revision,
            generated_at: Self::now_secs(),
            nodes,
        }))
    }

    async fn bump_node_map_revision(tx: &mut Transaction<'_, Sqlite>) -> SnResult<()> {
        sqlx::query("UPDATE relay_metadata SET value = value + 1 WHERE key = 'node_map_revision'")
            .execute(&mut **tx)
            .await
            .map_err(|e| Self::db_err("advance relay node-map revision failed", e))?;
        Ok(())
    }

    #[allow(dead_code)]
    pub async fn list_zone_relays_by_node(&self, relay_id: &str) -> SnResult<Vec<RelayAssignment>> {
        Self::check_non_empty(relay_id, "relay_id")?;
        let rows = sqlx::query(
            Self::relay_assignment_select_sql(
                "WHERE a.relay_id = ?1 AND a.state IN ('active', 'migrating', 'draining')
                 ORDER BY a.zone ASC",
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

    #[allow(dead_code)]
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

    #[allow(dead_code)]
    pub async fn get_pending_allocation(
        &self,
        zone: &str,
    ) -> SnResult<Option<RelayAllocationPending>> {
        Self::check_non_empty(zone, "zone")?;
        let row = sqlx::query(
            "SELECT zone, preferred_region, reason, source_version, attempts, last_error,
                    created_at, updated_at
             FROM relay_allocation_pending WHERE zone = ?1",
        )
        .bind(zone)
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| Self::db_err("query pending relay allocation failed", error))?;
        Ok(row.map(|row| RelayAllocationPending {
            zone: row.get(0),
            preferred_region: row.get(1),
            reason: row.get(2),
            source_version: row.get(3),
            attempts: Self::i64_to_u64(row.get(4)),
            last_error: row.get(5),
            created_at: Self::i64_to_u64(row.get(6)),
            updated_at: Self::i64_to_u64(row.get(7)),
        }))
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
                "WHERE n.status = 'active'
                 ORDER BY
                    CASE WHEN ?1 IS NOT NULL AND n.region = ?1 THEN 0 ELSE 1 END,
                    (n.current_load * 1000 / CASE WHEN n.capacity_score > 0 THEN n.capacity_score ELSE 1 END) ASC,
                    n.capacity_score DESC,
                    n.relay_id ASC
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

    fn normalize_match_label(value: &str) -> Option<String> {
        let value = value.trim();
        if value.is_empty() || value.len() > 128 {
            return None;
        }

        let mut normalized = String::with_capacity(value.len());
        let mut separator_pending = false;
        for character in value.chars() {
            if character.is_alphanumeric() {
                if separator_pending && !normalized.is_empty() {
                    normalized.push('-');
                }
                separator_pending = false;
                normalized.extend(character.to_lowercase());
            } else if matches!(character, '-' | '_' | '/' | '.') || character.is_whitespace() {
                separator_pending = !normalized.is_empty();
            } else {
                return None;
            }
        }
        if normalized.is_empty() {
            None
        } else {
            Some(normalized)
        }
    }

    fn is_public_source_ip(ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(ip) => Self::is_public_ipv4(ip),
            IpAddr::V6(ip) => {
                if let Some(ipv4) = ip.to_ipv4() {
                    return Self::is_public_ipv4(ipv4);
                }
                Self::is_public_ipv6(ip)
            }
        }
    }

    fn is_public_ipv4(ip: Ipv4Addr) -> bool {
        let [a, b, c, _] = ip.octets();
        !(a == 0
            || a == 10
            || a == 127
            || (a == 100 && (64..=127).contains(&b))
            || (a == 169 && b == 254)
            || (a == 172 && (16..=31).contains(&b))
            || (a == 192 && b == 0 && c == 0)
            || (a == 192 && b == 0 && c == 2)
            || (a == 192 && b == 88 && c == 99)
            || (a == 192 && b == 168)
            || (a == 198 && (b == 18 || b == 19))
            || (a == 198 && b == 51 && c == 100)
            || (a == 203 && b == 0 && c == 113)
            || a >= 224)
    }

    fn is_public_ipv6(ip: Ipv6Addr) -> bool {
        let segments = ip.segments();
        !(ip.is_unspecified()
            || ip.is_loopback()
            || ip.is_multicast()
            || (segments[0] & 0xfe00) == 0xfc00
            || (segments[0] & 0xffc0) == 0xfe80
            || (segments[0] == 0x2001 && segments[1] == 0x0db8))
    }

    fn normalized_tag_matches(node: &RelayNode, namespace: &str, value: &str) -> bool {
        node.tags.iter().any(|tag| {
            if let Some((tag_namespace, tag_value)) = tag.split_once(':') {
                Self::normalize_match_label(tag_namespace).as_deref() == Some(namespace)
                    && Self::normalize_match_label(tag_value).as_deref() == Some(value)
            } else {
                Self::normalize_match_label(tag).as_deref() == Some(value)
            }
        })
    }

    fn region_contains_label(region: &str, value: &str) -> bool {
        region == value
            || region.starts_with(format!("{}-", value).as_str())
            || region.ends_with(format!("-{}", value).as_str())
            || region.contains(format!("-{}-", value).as_str())
    }

    fn node_matches_rule(node: &RelayNode, rule: RelayMatchRule, value: &str) -> bool {
        let region = node.region.as_deref().and_then(Self::normalize_match_label);
        match rule {
            RelayMatchRule::PreferredRegion => {
                region.as_deref() == Some(value)
                    || Self::normalized_tag_matches(node, "region", value)
            }
            RelayMatchRule::GeoCountryCode => {
                region.as_deref().is_some_and(|region| {
                    region == value || region.starts_with(format!("{}-", value).as_str())
                }) || Self::normalized_tag_matches(node, "country", value)
            }
            RelayMatchRule::GeoProvince => {
                region
                    .as_deref()
                    .is_some_and(|region| Self::region_contains_label(region, value))
                    || Self::normalized_tag_matches(node, "province", value)
            }
            RelayMatchRule::GeoCity => {
                region
                    .as_deref()
                    .is_some_and(|region| Self::region_contains_label(region, value))
                    || Self::normalized_tag_matches(node, "city", value)
            }
            RelayMatchRule::GeoIsp => {
                node.isp
                    .as_deref()
                    .and_then(Self::normalize_match_label)
                    .as_deref()
                    == Some(value)
                    || Self::normalized_tag_matches(node, "isp", value)
            }
        }
    }

    fn compare_relay_load(left: &RelayNode, right: &RelayNode) -> Ordering {
        let left_ratio = i128::from(left.current_load) * i128::from(right.capacity_score.max(1));
        let right_ratio = i128::from(right.current_load) * i128::from(left.capacity_score.max(1));
        left_ratio
            .cmp(&right_ratio)
            .then_with(|| right.capacity_score.cmp(&left.capacity_score))
            .then_with(|| left.relay_id.cmp(&right.relay_id))
    }

    fn rule_value(
        rule: RelayMatchRule,
        preferred_region: Option<&String>,
        geo: Option<&GeoIpInfo>,
    ) -> Option<String> {
        let value = match rule {
            RelayMatchRule::PreferredRegion => preferred_region.map(String::as_str),
            RelayMatchRule::GeoCountryCode => geo.and_then(|info| info.country_code.as_deref()),
            RelayMatchRule::GeoProvince => geo.and_then(|info| info.province.as_deref()),
            RelayMatchRule::GeoCity => geo.and_then(|info| info.city.as_deref()),
            RelayMatchRule::GeoIsp => geo.and_then(|info| info.isp.as_deref()),
        }?;
        Self::normalize_match_label(value)
    }

    async fn lookup_geo_for_allocation(&self, source_ip: Option<IpAddr>) -> Option<GeoIpInfo> {
        let Some(source_ip) = source_ip.filter(|ip| Self::is_public_source_ip(*ip)) else {
            return None;
        };
        let Some(resolver) = self.geo_ip_resolver.as_ref() else {
            return None;
        };
        match resolver.lookup(source_ip).await {
            Ok(info) => info,
            Err(error) => {
                self.allocation_metrics
                    .geoip_failures
                    .fetch_add(1, AtomicOrdering::Relaxed);
                // 不记录 IP；源地址可能属于敏感运行信息。
                warn!(
                    "relay allocation GeoIP lookup degraded: error_code={:?}",
                    error.code()
                );
                None
            }
        }
    }

    async fn choose_automatic_relay(
        &self,
        preferred_region: Option<&String>,
        geo: Option<&GeoIpInfo>,
    ) -> SnResult<RelaySelection> {
        let mut active_nodes = Vec::new();
        for node in self.list_relay_nodes().await? {
            if Self::is_assignable_node(&node) {
                active_nodes.push(node);
            } else {
                debug!(
                    "relay allocation candidate excluded: relay_id={} reason=status status={}",
                    node.relay_id, node.status
                );
            }
        }
        active_nodes.sort_by(Self::compare_relay_load);

        for rule in self.allocation_config.match_rules.iter().copied() {
            let Some(value) = Self::rule_value(rule, preferred_region, geo) else {
                continue;
            };
            for node in &active_nodes {
                if Self::node_matches_rule(node, rule, value.as_str()) {
                    return Ok(RelaySelection {
                        node: node.clone(),
                        rule: rule.as_str(),
                        fallback: false,
                    });
                }
                debug!(
                    "relay allocation candidate excluded: relay_id={} rule={} reason=label_mismatch",
                    node.relay_id,
                    rule.as_str()
                );
            }
            debug!(
                "relay allocation rule produced no candidate: rule={} value={}",
                rule.as_str(),
                value
            );
        }

        let fallback_all = self
            .allocation_config
            .fallback_relays
            .iter()
            .any(|relay| relay.trim() == "*");
        let fallback = active_nodes.into_iter().find(|node| {
            let included = fallback_all
                || self.allocation_config.fallback_relays.iter().any(|relay| {
                    let relay = relay.trim();
                    relay == node.relay_id || relay == node.relay_sn
                });
            if !included {
                debug!(
                    "relay allocation candidate excluded: relay_id={} rule=fallback reason=not_configured",
                    node.relay_id
                );
            }
            included
        });
        fallback
            .map(|node| RelaySelection {
                node,
                rule: "fallback",
                fallback: true,
            })
            .ok_or_else(|| {
                sn_err!(
                    SnErrorCode::NotFound,
                    "no_relay_available: no matching or fallback relay is healthy"
                )
            })
    }

    pub(crate) async fn plan_registration_allocation(
        &self,
        req: &AllocateZoneRelayReq,
    ) -> SnResult<RelaySelection> {
        Self::check_non_empty(req.zone.as_str(), "zone")?;
        Self::check_non_empty(req.reason.as_str(), "reason")?;
        self.allocation_metrics
            .attempts
            .fetch_add(1, AtomicOrdering::Relaxed);

        let preferred_region = req
            .preferred_region
            .as_deref()
            .and_then(normalize_sn_region_id_hint);
        if req.preferred_region.is_some() && preferred_region.is_none() {
            debug!(
                "relay allocation ignored invalid preferred region: zone={}",
                req.zone
            );
        }
        let geo = self.lookup_geo_for_allocation(req.source_ip).await;
        self.choose_automatic_relay(preferred_region.as_ref(), geo.as_ref())
            .await
    }

    pub(crate) async fn commit_registration_allocation(
        &self,
        tx: &mut Transaction<'_, Sqlite>,
        req: &AllocateZoneRelayReq,
        plan: SnResult<RelaySelection>,
    ) -> SnResult<Result<RelayAssignment, SnError>> {
        let allocation = match plan {
            Ok(plan) => {
                let row =
                    sqlx::query(Self::relay_node_select_sql("WHERE n.relay_id = ?1").as_str())
                        .bind(plan.node.relay_id.as_str())
                        .fetch_optional(&mut **tx)
                        .await
                        .map_err(|e| {
                            Self::db_err("revalidate registration relay node failed", e)
                        })?;
                match row.map(Self::relay_node_from_row).transpose()? {
                    Some(node) if Self::is_assignable_node(&node) => {
                        let now = Self::now_secs();
                        let assignment = RelayAssignment {
                            zone: req.zone.trim().to_string(),
                            relay_id: node.relay_id,
                            relay_sn: node.relay_sn,
                            state: RelayAssignmentState::Active,
                            source: RelayAssignmentSource::Auto,
                            reason: Some(format!("{};rule={}", req.reason.trim(), plan.rule)),
                            generation: 1,
                            backup_relay_id: None,
                            sticky_until: None,
                            lease_expires_at: None,
                            migrated_from: None,
                            migration_deadline: None,
                            source_version: req.source_version.clone(),
                            created_at: now,
                            updated_at: now,
                        };
                        Self::insert_registration_assignment_tx(tx, &assignment).await?;
                        sqlx::query("DELETE FROM relay_allocation_pending WHERE zone = ?1")
                            .bind(assignment.zone.as_str())
                            .execute(&mut **tx)
                            .await
                            .map_err(|e| {
                                Self::db_err("clear registration relay pending failed", e)
                            })?;
                        self.allocation_metrics
                            .successes
                            .fetch_add(1, AtomicOrdering::Relaxed);
                        if plan.fallback {
                            self.allocation_metrics
                                .fallbacks
                                .fetch_add(1, AtomicOrdering::Relaxed);
                        }
                        info!(
                            "relay allocation selected: zone={} relay_id={} generation={} rule={} fallback={}",
                            assignment.zone,
                            assignment.relay_id,
                            assignment.generation,
                            plan.rule,
                            plan.fallback
                        );
                        Ok(assignment)
                    }
                    Some(node) => Err(sn_err!(
                        SnErrorCode::Conflict,
                        "planned relay node {} became unavailable: {}",
                        node.relay_id,
                        node.status
                    )),
                    None => Err(sn_err!(
                        SnErrorCode::NotFound,
                        "planned relay node {} no longer exists",
                        plan.node.relay_id
                    )),
                }
            }
            Err(error) => Err(error),
        };

        match allocation {
            Ok(assignment) => Ok(Ok(assignment)),
            Err(error) => {
                Self::record_registration_pending_tx(tx, req, &error).await?;
                self.allocation_metrics
                    .failures
                    .fetch_add(1, AtomicOrdering::Relaxed);
                warn!(
                    "relay allocation pending: zone={} error_code={:?} error={}",
                    req.zone,
                    error.code(),
                    error.msg()
                );
                Ok(Err(error))
            }
        }
    }

    async fn insert_registration_assignment_tx(
        tx: &mut Transaction<'_, Sqlite>,
        assignment: &RelayAssignment,
    ) -> SnResult<()> {
        sqlx::query(
            "INSERT INTO relay_assignments
                (zone, relay_id, state, source, reason, generation,
                 backup_relay_id, sticky_until, lease_expires_at, migrated_from,
                 migration_deadline, source_version, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, NULL, NULL, NULL, NULL, ?7, ?8, ?9)",
        )
        .bind(assignment.zone.as_str())
        .bind(assignment.relay_id.as_str())
        .bind(assignment.state.as_str())
        .bind(assignment.source.as_str())
        .bind(assignment.reason.as_deref())
        .bind(Self::to_db_time(assignment.generation, "generation")?)
        .bind(assignment.source_version.as_deref())
        .bind(Self::to_db_time(assignment.created_at, "created_at")?)
        .bind(Self::to_db_time(assignment.updated_at, "updated_at")?)
        .execute(&mut **tx)
        .await
        .map_err(|e| Self::db_err("insert registration relay assignment failed", e))?;
        Ok(())
    }

    async fn record_registration_pending_tx(
        tx: &mut Transaction<'_, Sqlite>,
        req: &AllocateZoneRelayReq,
        error: &SnError,
    ) -> SnResult<()> {
        let now = Self::now_secs();
        let preferred_region = req
            .preferred_region
            .as_deref()
            .and_then(normalize_sn_region_id_hint);
        sqlx::query(
            "INSERT INTO relay_allocation_pending
                (zone, preferred_region, reason, source_version, attempts, last_error,
                 created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, 1, ?5, ?6, ?7)
             ON CONFLICT(zone) DO UPDATE SET
                preferred_region = excluded.preferred_region,
                reason = excluded.reason,
                source_version = excluded.source_version,
                attempts = relay_allocation_pending.attempts + 1,
                last_error = excluded.last_error,
                updated_at = excluded.updated_at",
        )
        .bind(req.zone.trim())
        .bind(preferred_region.as_deref())
        .bind(req.reason.trim())
        .bind(req.source_version.as_deref())
        .bind(format!("{:?}: {}", error.code(), error.msg()))
        .bind(Self::to_db_time(now, "created_at")?)
        .bind(Self::to_db_time(now, "updated_at")?)
        .execute(&mut **tx)
        .await
        .map_err(|e| Self::db_err("record registration relay pending failed", e))?;
        Ok(())
    }

    async fn record_pending_allocation(
        &self,
        req: &AllocateZoneRelayReq,
        error: &SnError,
    ) -> SnResult<()> {
        let now = Self::now_secs();
        let preferred_region = req
            .preferred_region
            .as_deref()
            .and_then(normalize_sn_region_id_hint);
        sqlx::query(
            "INSERT INTO relay_allocation_pending
                (zone, preferred_region, reason, source_version, attempts, last_error,
                 created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, 1, ?5, ?6, ?7)
             ON CONFLICT(zone) DO UPDATE SET
                preferred_region = excluded.preferred_region,
                reason = excluded.reason,
                source_version = excluded.source_version,
                attempts = relay_allocation_pending.attempts + 1,
                last_error = excluded.last_error,
                updated_at = excluded.updated_at",
        )
        .bind(req.zone.trim())
        .bind(preferred_region.as_deref())
        .bind(req.reason.trim())
        .bind(req.source_version.as_deref())
        .bind(format!("{:?}: {}", error.code(), error.msg()))
        .bind(Self::to_db_time(now, "created_at")?)
        .bind(Self::to_db_time(now, "updated_at")?)
        .execute(&self.pool)
        .await
        .map_err(|db_error| Self::db_err("record pending relay allocation failed", db_error))?;
        Ok(())
    }

    async fn clear_pending_allocation(&self, zone: &str) -> SnResult<()> {
        sqlx::query("DELETE FROM relay_allocation_pending WHERE zone = ?1")
            .bind(zone)
            .execute(&self.pool)
            .await
            .map_err(|error| Self::db_err("clear pending relay allocation failed", error))?;
        Ok(())
    }

    async fn retry_pending_allocations(&self) -> SnResult<()> {
        let rows = sqlx::query(
            "SELECT zone, preferred_region, reason, source_version
             FROM relay_allocation_pending ORDER BY created_at ASC, zone ASC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|error| Self::db_err("list pending relay allocations failed", error))?;
        for row in rows {
            let req = AllocateZoneRelayReq {
                zone: row
                    .try_get(0)
                    .map_err(|e| Self::db_err("read pending relay zone failed", e))?,
                preferred_region: row
                    .try_get(1)
                    .map_err(|e| Self::db_err("read pending relay region failed", e))?,
                source_ip: None,
                reason: row
                    .try_get(2)
                    .map_err(|e| Self::db_err("read pending relay reason failed", e))?,
                source_version: row
                    .try_get(3)
                    .map_err(|e| Self::db_err("read pending relay source_version failed", e))?,
            };
            if let Err(error) = self.allocate_zone_relay(req.clone()).await {
                warn!(
                    "retry pending relay allocation failed: zone={} error_code={:?} error={}",
                    req.zone,
                    error.code(),
                    error.msg()
                );
            }
        }
        Ok(())
    }

    async fn allocate_zone_relay_inner(
        &self,
        req: &AllocateZoneRelayReq,
    ) -> SnResult<(RelayAssignment, bool)> {
        Self::check_non_empty(req.zone.as_str(), "zone")?;
        Self::check_non_empty(req.reason.as_str(), "reason")?;

        // 自动分配以 zone 为幂等键。只要已有 assignment 的节点仍允许服务，
        // 地区提示、GeoIP 或负载变化都不能令重试无故漂移。
        if let Some(existing) = self.get_zone_relay(req.zone.as_str()).await? {
            if existing.state == RelayAssignmentState::Active {
                if let Some(node) = self.get_relay_node(existing.relay_id.as_str()).await? {
                    if Self::is_assignable_node(&node) {
                        info!(
                            "relay allocation reused sticky assignment: zone={} relay_id={} generation={} rule=sticky",
                            req.zone, existing.relay_id, existing.generation
                        );
                        return Ok((existing, false));
                    }
                }
            }
        }

        let preferred_region = req
            .preferred_region
            .as_deref()
            .and_then(normalize_sn_region_id_hint);
        if req.preferred_region.is_some() && preferred_region.is_none() {
            debug!(
                "relay allocation ignored invalid preferred region: zone={}",
                req.zone
            );
        }
        let geo = self.lookup_geo_for_allocation(req.source_ip).await;
        let selection = self
            .choose_automatic_relay(preferred_region.as_ref(), geo.as_ref())
            .await?;
        let reason = format!("{};rule={}", req.reason.trim(), selection.rule);
        let assignment = self
            .assign_zone_relay(AssignZoneRelayReq {
                zone: req.zone.trim().to_string(),
                relay_id: Some(selection.node.relay_id.clone()),
                relay_sn: None,
                from_ip: None,
                region: None,
                source: RelayAssignmentSource::Auto,
                reason: Some(reason),
                sticky_until: None,
                lease_expires_at: None,
                backup_relay_id: None,
                source_version: req.source_version.clone(),
            })
            .await?;
        info!(
            "relay allocation selected: zone={} relay_id={} generation={} rule={} fallback={}",
            assignment.zone,
            assignment.relay_id,
            assignment.generation,
            selection.rule,
            selection.fallback
        );
        Ok((assignment, selection.fallback))
    }

    async fn get_relay_node_by_sn(&self, relay_sn: &str) -> SnResult<Option<RelayNode>> {
        Self::check_non_empty(relay_sn, "relay_sn")?;
        let row = sqlx::query(Self::relay_node_select_sql("WHERE n.relay_sn = ?1").as_str())
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
        let row = sqlx::query(Self::relay_assignment_select_sql("WHERE a.zone = ?1").as_str())
            .bind(zone)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| Self::db_err("query relay assignment failed", e))?;

        row.map(Self::relay_assignment_from_row).transpose()
    }

    async fn upsert_assignment(&self, assignment: &RelayAssignment) -> SnResult<()> {
        sqlx::query(
            "INSERT INTO relay_assignments
                (zone, relay_id, state, source, reason, generation,
                 backup_relay_id, sticky_until, lease_expires_at, migrated_from,
                 migration_deadline, source_version, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
             ON CONFLICT(zone) DO UPDATE SET
                relay_id = excluded.relay_id,
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

        let auto_req = AllocateZoneRelayReq {
            zone: req.zone.clone(),
            preferred_region: None,
            source_ip: req
                .observed_ip
                .as_deref()
                .and_then(|value| value.parse::<IpAddr>().ok()),
            reason: "first_keep_tunnel".to_string(),
            source_version: None,
        };

        match self.allocate_zone_relay(auto_req).await {
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
            "SELECT n.relay_id, n.relay_sn,
                    (SELECT a0.ip FROM relay_node_addresses a0
                     WHERE a0.relay_id = n.relay_id AND a0.slot = 0),
                    (SELECT a1.ip FROM relay_node_addresses a1
                     WHERE a1.relay_id = n.relay_id AND a1.slot = 1),
                    n.public_host, n.http_endpoint, n.rtcp_endpoint,
                    n.region, n.isp, n.tags, n.capabilities, n.status, n.capacity_score,
                    n.current_load, n.last_heartbeat_at, n.drain_until, n.created_at, n.updated_at
             FROM relay_nodes n {}",
            tail
        )
    }

    fn relay_assignment_select_sql(tail: &str) -> String {
        format!(
            "SELECT a.zone, a.relay_id, n.relay_sn, a.state, a.source, a.reason, a.generation,
                    a.backup_relay_id, a.sticky_until, a.lease_expires_at, a.migrated_from,
                    a.migration_deadline, a.source_version, a.created_at, a.updated_at
             FROM relay_assignments a
             JOIN relay_nodes n ON n.relay_id = a.relay_id {}",
            tail
        )
    }

    fn relay_node_from_row(row: SqliteRow) -> SnResult<RelayNode> {
        let ip0 = Self::parse_stored_ip(
            row.try_get::<Option<String>, _>(2)
                .map_err(|e| Self::db_err("read relay address slot 0 failed", e))?,
            0,
        )?;
        let ip1 = Self::parse_stored_ip(
            row.try_get::<Option<String>, _>(3)
                .map_err(|e| Self::db_err("read relay address slot 1 failed", e))?,
            1,
        )?;
        Ok(RelayNode {
            relay_id: row.get(0),
            relay_sn: row.get(1),
            ips: [ip0, ip1],
            public_host: row.get(4),
            http_endpoint: row.get(5),
            rtcp_endpoint: row.get(6),
            region: row.get(7),
            isp: row.get(8),
            tags: Self::parse_json_string_vec(row.get(9), "relay tags")?,
            capabilities: Self::parse_json_string_vec(row.get(10), "relay capabilities")?,
            status: Self::parse_db_enum(row.get(11), "relay status")?,
            capacity_score: row.get(12),
            current_load: row.get(13),
            last_heartbeat_at: Self::opt_to_u64(row.get(14)),
            drain_until: Self::opt_to_u64(row.get(15)),
            created_at: Self::i64_to_u64(row.get(16)),
            updated_at: Self::i64_to_u64(row.get(17)),
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

    fn parse_stored_ip(value: Option<String>, slot: usize) -> SnResult<IpAddr> {
        let value = value.ok_or_else(|| {
            sn_err!(
                SnErrorCode::DBError,
                "relay node address slot {} is missing",
                slot
            )
        })?;
        let ip = value.parse::<IpAddr>().map_err(|e| {
            sn_err!(
                SnErrorCode::DBError,
                "relay node address slot {} is corrupt: {}",
                slot,
                e
            )
        })?;
        if ip.to_string() != value {
            return Err(sn_err!(
                SnErrorCode::DBError,
                "relay node address slot {} is not canonical: {}",
                slot,
                value
            ));
        }
        Ok(ip)
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
    fn allocation_metrics(&self) -> RelayAllocationMetricsSnapshot {
        SqliteSnRelayManager::allocation_metrics(self)
    }

    async fn register_relay_node(&self, node: RelayNodeRegistration) -> SnResult<RelayNode> {
        Self::validate_registration(&node)?;
        self.ensure_relay_sn_unique(node.relay_id.as_str(), node.relay_sn.as_str())
            .await?;

        let now = Self::now_secs();
        let existing_status =
            sqlx::query_scalar::<_, String>("SELECT status FROM relay_nodes WHERE relay_id = ?1")
                .bind(node.relay_id.as_str())
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| Self::db_err("query existing relay node status failed", e))?
                .map(|status| Self::parse_db_enum(status, "relay status"))
                .transpose()?;
        if existing_status == Some(RelayNodeStatus::Deleted) {
            return Err(sn_err!(
                SnErrorCode::Conflict,
                "deleted relay node cannot be registered"
            ));
        }
        let tags = Self::normalize_label_vec(node.tags);
        let capabilities = Self::normalize_capability_vec(node.capabilities);
        let status = node.status.unwrap_or_else(|| {
            existing_status
                .filter(|status| {
                    matches!(
                        status,
                        RelayNodeStatus::Draining | RelayNodeStatus::Disabled
                    )
                })
                .unwrap_or(RelayNodeStatus::Active)
        });
        let capacity_score = node.capacity_score.unwrap_or(DEFAULT_CAPACITY_SCORE);
        let ips = node.ips;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| Self::db_err("begin relay node registration failed", e))?;

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
        .execute(&mut *tx)
        .await
        .map_err(|e| Self::db_err("upsert relay node failed", e))?;
        for (slot, ip) in ips.into_iter().enumerate() {
            sqlx::query(
                "INSERT INTO relay_node_addresses
                    (relay_id, slot, ip, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(relay_id, slot) DO UPDATE SET
                    ip = excluded.ip,
                    updated_at = excluded.updated_at",
            )
            .bind(node.relay_id.as_str())
            .bind(slot as i64)
            .bind(ip.to_string())
            .bind(Self::to_db_time(now, "created_at")?)
            .bind(Self::to_db_time(now, "updated_at")?)
            .execute(&mut *tx)
            .await
            .map_err(|e| Self::db_err("upsert relay node address failed", e))?;
        }
        Self::bump_node_map_revision(&mut tx).await?;
        tx.commit()
            .await
            .map_err(|e| Self::db_err("commit relay node registration failed", e))?;

        let stored = self
            .get_relay_node(node.relay_id.as_str())
            .await?
            .ok_or_else(|| sn_err!(SnErrorCode::NotFound, "relay node not found after upsert"))?;
        if status == RelayNodeStatus::Active {
            self.retry_pending_allocations().await?;
        }
        Ok(stored)
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
        let status_changed = status != existing.status;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| Self::db_err("begin relay heartbeat update failed", e))?;

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
        .execute(&mut *tx)
        .await
        .map_err(|e| Self::db_err("update relay heartbeat failed", e))?;
        if status_changed {
            Self::bump_node_map_revision(&mut tx).await?;
        }
        tx.commit()
            .await
            .map_err(|e| Self::db_err("commit relay heartbeat update failed", e))?;
        if status == RelayNodeStatus::Active && existing.status != RelayNodeStatus::Active {
            self.retry_pending_allocations().await?;
        }

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

    async fn update_relay_node_addresses(
        &self,
        update: RelayNodeAddressUpdate,
    ) -> SnResult<RelayNode> {
        Self::check_non_empty(update.relay_id.as_str(), "relay_id")?;
        let existing = self
            .get_relay_node(update.relay_id.as_str())
            .await?
            .ok_or_else(|| sn_err!(SnErrorCode::NotFound, "relay node not found"))?;
        if existing.status == RelayNodeStatus::Deleted {
            return Err(sn_err!(
                SnErrorCode::Conflict,
                "deleted relay node addresses cannot be updated"
            ));
        }
        if existing.ips == update.ips {
            return Ok(existing);
        }

        let now = Self::now_secs();
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| Self::db_err("begin relay address update failed", e))?;
        for (slot, ip) in update.ips.into_iter().enumerate() {
            sqlx::query(
                "UPDATE relay_node_addresses
                 SET ip = ?1, updated_at = ?2
                 WHERE relay_id = ?3 AND slot = ?4",
            )
            .bind(ip.to_string())
            .bind(Self::to_db_time(now, "updated_at")?)
            .bind(update.relay_id.as_str())
            .bind(slot as i64)
            .execute(&mut *tx)
            .await
            .map_err(|e| Self::db_err("update relay node address failed", e))?;
        }
        sqlx::query("UPDATE relay_nodes SET updated_at = ?1 WHERE relay_id = ?2")
            .bind(Self::to_db_time(now, "updated_at")?)
            .bind(update.relay_id.as_str())
            .execute(&mut *tx)
            .await
            .map_err(|e| Self::db_err("touch relay node after address update failed", e))?;
        Self::bump_node_map_revision(&mut tx).await?;
        tx.commit()
            .await
            .map_err(|e| Self::db_err("commit relay address update failed", e))?;
        self.get_relay_node(update.relay_id.as_str())
            .await?
            .ok_or_else(|| sn_err!(SnErrorCode::NotFound, "relay node not found after update"))
    }

    async fn get_relay_node(&self, relay_id: &str) -> SnResult<Option<RelayNode>> {
        SqliteSnRelayManager::get_relay_node(self, relay_id).await
    }

    async fn list_relay_nodes(&self) -> SnResult<Vec<RelayNode>> {
        SqliteSnRelayManager::list_relay_nodes(self).await
    }

    async fn get_relay_nodes_ip_map(
        &self,
        req: RelayNodeIpMapReq,
    ) -> SnResult<Option<RelayNodeIpMapSnapshot>> {
        self.get_relay_nodes_ip_map_snapshot(req.if_revision).await
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
        Ok(assignment)
    }

    async fn allocate_zone_relay(&self, req: AllocateZoneRelayReq) -> SnResult<RelayAssignment> {
        Self::check_non_empty(req.zone.as_str(), "zone")?;
        Self::check_non_empty(req.reason.as_str(), "reason")?;
        self.allocation_metrics
            .attempts
            .fetch_add(1, AtomicOrdering::Relaxed);
        // 进程内并发注册/补偿按 zone 串行化；DB 的 zone 主键继续作为最终幂等约束。
        let _zone_locker = async_named_locker::Locker::get_locker(format!(
            "sn_relay_allocate_zone_{}",
            req.zone.trim()
        ))
        .await;

        match self.allocate_zone_relay_inner(&req).await {
            Ok((assignment, fallback)) => {
                self.allocation_metrics
                    .successes
                    .fetch_add(1, AtomicOrdering::Relaxed);
                if fallback {
                    self.allocation_metrics
                        .fallbacks
                        .fetch_add(1, AtomicOrdering::Relaxed);
                }
                if let Err(error) = self
                    .clear_pending_allocation(assignment.zone.as_str())
                    .await
                {
                    warn!(
                        "relay allocation could not clear stale pending row: zone={} error={}",
                        assignment.zone,
                        error.msg()
                    );
                }
                Ok(assignment)
            }
            Err(error) => {
                self.allocation_metrics
                    .failures
                    .fetch_add(1, AtomicOrdering::Relaxed);
                if let Err(pending_error) = self.record_pending_allocation(&req, &error).await {
                    warn!(
                        "relay allocation failed and pending row could not be recorded: zone={} error_code={:?} pending_error={}",
                        req.zone,
                        error.code(),
                        pending_error.msg()
                    );
                }
                warn!(
                    "relay allocation pending: zone={} error_code={:?} error={}",
                    req.zone,
                    error.code(),
                    error.msg()
                );
                Err(error)
            }
        }
    }

    async fn get_zone_relay(&self, zone: &str) -> SnResult<Option<RelayAssignment>> {
        Self::check_non_empty(zone, "zone")?;
        let row = sqlx::query(Self::relay_assignment_select_sql("WHERE a.zone = ?1").as_str())
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
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicUsizeOrdering};

    struct TestGeoIpResolver {
        info: Option<GeoIpInfo>,
        fail: bool,
        calls: AtomicUsize,
    }

    impl TestGeoIpResolver {
        fn new(info: Option<GeoIpInfo>) -> Self {
            Self {
                info,
                fail: false,
                calls: AtomicUsize::new(0),
            }
        }

        fn failing() -> Self {
            Self {
                info: None,
                fail: true,
                calls: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait::async_trait]
    impl GeoIpResolver for TestGeoIpResolver {
        async fn lookup(&self, _ip: IpAddr) -> SnResult<Option<GeoIpInfo>> {
            self.calls.fetch_add(1, AtomicUsizeOrdering::Relaxed);
            if self.fail {
                Err(sn_err!(SnErrorCode::Failed, "test GeoIP failure"))
            } else {
                Ok(self.info.clone())
            }
        }
    }

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
            ips: [
                "192.0.2.10".parse().unwrap(),
                "2001:db8::10".parse().unwrap(),
            ],
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

    fn allocation_req(
        zone: &str,
        preferred_region: Option<&str>,
        source_ip: Option<IpAddr>,
    ) -> AllocateZoneRelayReq {
        AllocateZoneRelayReq {
            zone: zone.to_string(),
            preferred_region: preferred_region.map(ToString::to_string),
            source_ip,
            reason: "register".to_string(),
            source_version: Some("test-v1".to_string()),
        }
    }

    fn geo(country_code: &str, province: &str, city: &str, isp: &str) -> GeoIpInfo {
        GeoIpInfo {
            country_code: Some(country_code.to_string()),
            country: None,
            province: Some(province.to_string()),
            city: Some(city.to_string()),
            isp: Some(isp.to_string()),
        }
    }

    #[tokio::test]
    async fn test_node_ip_map_roundtrips_all_address_families_and_revision() -> SnResult<()> {
        let (_tmp_dir, mgr) = temp_mgr().await?;
        let cases = [
            (
                "relay-v4",
                [
                    "192.0.2.10".parse::<IpAddr>().unwrap(),
                    "198.51.100.10".parse::<IpAddr>().unwrap(),
                ],
            ),
            (
                "relay-dual",
                [
                    "192.0.2.11".parse::<IpAddr>().unwrap(),
                    "2001:db8::11".parse::<IpAddr>().unwrap(),
                ],
            ),
            (
                "relay-v6",
                [
                    "2001:db8::12".parse::<IpAddr>().unwrap(),
                    "2001:db8::13".parse::<IpAddr>().unwrap(),
                ],
            ),
        ];
        for (relay_id, ips) in cases {
            let mut registration = node(relay_id, &format!("{relay_id}.example"), "test");
            registration.ips = ips;
            let stored = mgr.register_relay_node(registration).await?;
            assert_eq!(stored.ips, ips);
        }

        let snapshot = mgr
            .get_relay_nodes_ip_map(RelayNodeIpMapReq::default())
            .await?
            .unwrap();
        assert_eq!(snapshot.revision, 3);
        assert_eq!(
            snapshot
                .nodes
                .iter()
                .map(|node| node.relay_id.as_str())
                .collect::<Vec<_>>(),
            vec!["relay-dual", "relay-v4", "relay-v6"]
        );
        assert!(mgr
            .get_relay_nodes_ip_map(RelayNodeIpMapReq {
                if_revision: Some(snapshot.revision),
            })
            .await?
            .is_none());

        let updated_ips = [
            "203.0.113.20".parse().unwrap(),
            "2001:db8::20".parse().unwrap(),
        ];
        mgr.update_relay_node_addresses(RelayNodeAddressUpdate {
            relay_id: "relay-dual".to_string(),
            ips: updated_ips,
        })
        .await?;
        let updated = mgr
            .get_relay_nodes_ip_map(RelayNodeIpMapReq {
                if_revision: Some(snapshot.revision),
            })
            .await?
            .unwrap();
        assert_eq!(updated.revision, 4);
        assert_eq!(updated.nodes.len(), 3);
        assert_eq!(
            updated
                .nodes
                .iter()
                .find(|node| node.relay_id == "relay-dual")
                .unwrap()
                .ips,
            updated_ips
        );

        mgr.heartbeat_relay_node(RelayHeartbeat {
            relay_id: "relay-dual".to_string(),
            status: None,
            current_load: Some(5),
            capacity_score: None,
            drain_until: None,
            http_endpoint: None,
            rtcp_endpoint: None,
        })
        .await?;
        assert!(mgr
            .get_relay_nodes_ip_map(RelayNodeIpMapReq {
                if_revision: Some(updated.revision),
            })
            .await?
            .is_none());
        mgr.heartbeat_relay_node(RelayHeartbeat {
            relay_id: "relay-dual".to_string(),
            status: Some(RelayNodeStatus::Draining),
            current_load: None,
            capacity_score: None,
            drain_until: Some(100),
            http_endpoint: None,
            rtcp_endpoint: None,
        })
        .await?;
        assert_eq!(
            mgr.get_relay_nodes_ip_map(RelayNodeIpMapReq {
                if_revision: Some(updated.revision),
            })
            .await?
            .unwrap()
            .revision,
            5
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_node_ip_map_rejects_incomplete_or_noncanonical_storage() -> SnResult<()> {
        let (_tmp_dir, mgr) = temp_mgr().await?;
        mgr.register_relay_node(node("relay-a", "relay-a.example", "test"))
            .await?;
        sqlx::query(
            "UPDATE relay_node_addresses SET ip = '2001:0db8::10'
             WHERE relay_id = 'relay-a' AND slot = 1",
        )
        .execute(&mgr.pool)
        .await
        .map_err(|e| SqliteSnRelayManager::db_err("corrupt test relay address failed", e))?;
        assert_eq!(
            mgr.get_relay_nodes_ip_map(RelayNodeIpMapReq::default())
                .await
                .unwrap_err()
                .code(),
            SnErrorCode::DBError
        );

        sqlx::query(
            "DELETE FROM relay_node_addresses
             WHERE relay_id = 'relay-a' AND slot = 1",
        )
        .execute(&mgr.pool)
        .await
        .map_err(|e| SqliteSnRelayManager::db_err("delete test relay address failed", e))?;
        assert_eq!(
            mgr.get_relay_nodes_ip_map(RelayNodeIpMapReq::default())
                .await
                .unwrap_err()
                .code(),
            SnErrorCode::DBError
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_allocate_prefers_normalized_region_over_geoip() -> SnResult<()> {
        let (_tmp_dir, base_mgr) = temp_mgr().await?;
        let resolver = Arc::new(TestGeoIpResolver::new(Some(geo(
            "DE",
            "Berlin",
            "Berlin",
            "Example ISP",
        ))));
        let mgr = base_mgr.with_geo_ip_resolver(resolver.clone());
        mgr.register_relay_node(node("relay-us", "relay-us.example", "us-west"))
            .await?;
        mgr.register_relay_node(node("relay-de", "relay-de.example", "de"))
            .await?;

        let assignment = mgr
            .allocate_zone_relay(allocation_req(
                "alice",
                Some(" US_WEST "),
                Some("8.8.8.8".parse().unwrap()),
            ))
            .await?;
        assert_eq!(assignment.relay_id, "relay-us");
        assert_eq!(assignment.source, RelayAssignmentSource::Auto);
        assert_eq!(
            assignment.reason.as_deref(),
            Some("register;rule=preferred_region")
        );
        assert_eq!(resolver.calls.load(AtomicUsizeOrdering::Relaxed), 1);
        Ok(())
    }

    #[tokio::test]
    async fn test_allocate_uses_geoip_when_region_is_missing_or_unknown() -> SnResult<()> {
        let (_tmp_dir, base_mgr) = temp_mgr().await?;
        let resolver = Arc::new(TestGeoIpResolver::new(Some(geo(
            "DE",
            "Berlin",
            "Berlin",
            "Example ISP",
        ))));
        let mgr = base_mgr.with_geo_ip_resolver(resolver);
        mgr.register_relay_node(node("relay-us", "relay-us.example", "us"))
            .await?;
        mgr.register_relay_node(node("relay-de", "relay-de.example", "de"))
            .await?;

        let missing = mgr
            .allocate_zone_relay(allocation_req(
                "alice",
                None,
                Some("8.8.8.8".parse().unwrap()),
            ))
            .await?;
        let unknown = mgr
            .allocate_zone_relay(allocation_req(
                "bob",
                Some("moon-1"),
                Some("8.8.4.4".parse().unwrap()),
            ))
            .await?;
        assert_eq!(missing.relay_id, "relay-de");
        assert_eq!(unknown.relay_id, "relay-de");
        assert_eq!(
            unknown.reason.as_deref(),
            Some("register;rule=geo_country_code")
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_private_ip_skips_geoip_and_uses_configured_fallback() -> SnResult<()> {
        let (_tmp_dir, base_mgr) = temp_mgr().await?;
        let resolver = Arc::new(TestGeoIpResolver::new(Some(geo(
            "US",
            "California",
            "San Francisco",
            "Example ISP",
        ))));
        let mgr = base_mgr
            .with_allocation_config(RelayAllocationConfig {
                fallback_relays: vec!["relay-b".to_string()],
                ..Default::default()
            })
            .with_geo_ip_resolver(resolver.clone());
        mgr.register_relay_node(node("relay-a", "relay-a.example", "us"))
            .await?;
        mgr.register_relay_node(node("relay-b", "relay-b.example", "eu"))
            .await?;

        let assignment = mgr
            .allocate_zone_relay(allocation_req(
                "alice",
                None,
                Some("192.168.1.8".parse().unwrap()),
            ))
            .await?;
        assert_eq!(assignment.relay_id, "relay-b");
        assert_eq!(assignment.reason.as_deref(), Some("register;rule=fallback"));
        assert_eq!(resolver.calls.load(AtomicUsizeOrdering::Relaxed), 0);
        assert_eq!(mgr.allocation_metrics().fallbacks, 1);
        Ok(())
    }

    #[tokio::test]
    async fn test_geoip_failure_degrades_to_fallback() -> SnResult<()> {
        let (_tmp_dir, base_mgr) = temp_mgr().await?;
        let mgr = base_mgr.with_geo_ip_resolver(Arc::new(TestGeoIpResolver::failing()));
        mgr.register_relay_node(node("relay-a", "relay-a.example", "us"))
            .await?;
        let assignment = mgr
            .allocate_zone_relay(allocation_req(
                "alice",
                None,
                Some("8.8.8.8".parse().unwrap()),
            ))
            .await?;
        assert_eq!(assignment.relay_id, "relay-a");
        assert_eq!(mgr.allocation_metrics().geoip_failures, 1);
        Ok(())
    }

    #[tokio::test]
    async fn test_unavailable_fallback_records_retryable_pending_state() -> SnResult<()> {
        let (_tmp_dir, base_mgr) = temp_mgr().await?;
        let mgr = base_mgr.with_allocation_config(RelayAllocationConfig {
            fallback_relays: vec!["relay-b".to_string()],
            ..Default::default()
        });
        mgr.register_relay_node(node("relay-a", "relay-a.example", "us"))
            .await?;
        mgr.register_relay_node(node("relay-b", "relay-b.example", "eu"))
            .await?;
        mgr.heartbeat_relay_node(RelayHeartbeat {
            relay_id: "relay-b".to_string(),
            status: Some(RelayNodeStatus::Disabled),
            current_load: None,
            capacity_score: None,
            drain_until: None,
            http_endpoint: None,
            rtcp_endpoint: None,
        })
        .await?;

        let error = mgr
            .allocate_zone_relay(allocation_req("alice", Some("unknown"), None))
            .await
            .unwrap_err();
        assert_eq!(error.code(), SnErrorCode::NotFound);
        assert!(error.msg().contains("no_relay_available"));
        let pending = mgr.get_pending_allocation("alice").await?.unwrap();
        assert_eq!(pending.attempts, 1);
        assert_eq!(pending.preferred_region.as_deref(), Some("unknown"));
        assert!(pending.last_error.contains("no_relay_available"));
        assert_eq!(mgr.allocation_metrics().failures, 1);
        mgr.heartbeat_relay_node(RelayHeartbeat {
            relay_id: "relay-b".to_string(),
            status: Some(RelayNodeStatus::Active),
            current_load: None,
            capacity_score: None,
            drain_until: None,
            http_endpoint: None,
            rtcp_endpoint: None,
        })
        .await?;
        assert!(mgr.get_pending_allocation("alice").await?.is_none());
        assert_eq!(
            mgr.get_zone_relay("alice").await?.unwrap().relay_id,
            "relay-b"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_allocate_is_idempotent_and_concurrent_per_zone() -> SnResult<()> {
        let (_tmp_dir, mgr) = temp_mgr().await?;
        mgr.register_relay_node(node("relay-us", "relay-us.example", "us"))
            .await?;
        mgr.register_relay_node(node("relay-eu", "relay-eu.example", "eu"))
            .await?;
        let mgr = Arc::new(mgr);

        let first_mgr = mgr.clone();
        let first = tokio::spawn(async move {
            first_mgr
                .allocate_zone_relay(allocation_req("alice", Some("us"), None))
                .await
        });
        let second_mgr = mgr.clone();
        let second = tokio::spawn(async move {
            second_mgr
                .allocate_zone_relay(allocation_req("alice", Some("eu"), None))
                .await
        });
        let first = first.await.unwrap()?;
        let second = second.await.unwrap()?;
        assert_eq!(first.relay_id, second.relay_id);
        assert_eq!(first.generation, 1);
        assert_eq!(second.generation, 1);

        let retry = mgr
            .allocate_zone_relay(allocation_req("alice", Some("unknown"), None))
            .await?;
        assert_eq!(retry.relay_id, first.relay_id);
        assert_eq!(retry.generation, 1);
        assert!(mgr.get_pending_allocation("alice").await?.is_none());
        Ok(())
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
    async fn test_auth_db_projects_assignment_into_zone_info() -> SnResult<()> {
        let tmp_dir = tempfile::tempdir()
            .map_err(|e| sn_err!(SnErrorCode::DBError, "create temp dir failed: {}", e))?;
        let auth_path = tmp_dir.path().join("sn_auth.sqlite3");
        let auth_db = SqliteSnAuthDB::new_by_path(auth_path.to_string_lossy().as_ref()).await?;
        auth_db.initialize_database().await?;
        auth_db.insert_activation_code("alice-code").await?;
        assert!(
            auth_db
                .register_user(
                    "alice-code",
                    "alice",
                    "alice@example.com",
                    "hash",
                    "salt",
                    "pbkdf2",
                )
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

        auth_db
            .register_relay_node(node("relay-a", "relay-a.example", "us"))
            .await?;
        auth_db
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
                source_version: Some("relay-v1".to_string()),
            })
            .await?;

        let zone_info = auth_db.get_zone_info("alice").await?.unwrap();
        assert_eq!(zone_info.relay_sn.as_deref(), Some("relay-a.example"));
        assert_eq!(
            zone_info
                .relay
                .as_ref()
                .map(|relay| relay.relay_id.as_str()),
            Some("relay-a")
        );

        Ok(())
    }
}
