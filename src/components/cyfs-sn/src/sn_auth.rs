use crate::{sn_err, SnError, SnErrorCode, SnResult};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::{Row, Sqlite, SqlitePool, Transaction};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

const ACTIVATION_CODE_LEN: usize = 32;
const ACTIVATION_CODE_CHARS: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const DOMAIN_BINDING_PENDING_PKX: &str = "pending_pkx";
const DOMAIN_BINDING_ACTIVE: &str = "active";
const DOMAIN_BINDING_REVOKED: &str = "revoked";
const SESSION_ACTIVE: &str = "active";
const SESSION_REVOKED: &str = "revoked";

pub type SnAuthDBRef = Arc<dyn SnAuthDB>;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserState {
    Active,
    Suspended,
    Deleted,
    Banned,
}

impl ToString for UserState {
    fn to_string(&self) -> String {
        match self {
            UserState::Active => "active".to_string(),
            UserState::Suspended => "suspended".to_string(),
            UserState::Deleted => "deleted".to_string(),
            UserState::Banned => "banned".to_string(),
        }
    }
}

impl UserState {
    pub fn from_str(s: Option<&str>) -> Self {
        match s {
            Some("suspended") => UserState::Suspended,
            Some("deleted") => UserState::Deleted,
            Some("banned") => UserState::Banned,
            _ => UserState::Active,
        }
    }

    fn is_active(&self) -> bool {
        matches!(self, UserState::Active)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SNUserInfo {
    pub username: Option<String>,
    pub state: UserState,
    pub public_key: String,
    pub activation_code: Option<String>,
    pub zone_config: String,
    pub self_cert: bool,
    pub user_domain: Option<String>,
    pub sn_ips: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnClearStateResult {
    pub deleted_users: u64,
    pub deleted_devices: u64,
    pub deleted_domain_records: u64,
    pub deleted_did_documents: u64,
    pub activation_code_reset: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnV2AuthInfo {
    pub username: String,
    pub password_hash: String,
    pub password_salt: String,
    pub password_algo: String,
    pub created_at: u64,
    pub updated_at: u64,
    pub last_login_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PkxBindingChallenge {
    pub username: String,
    pub domain: String,
    pub pkx: String,
    pub pkx_record_name: String,
    pub state: String,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainBinding {
    pub username: String,
    pub domain: String,
    pub pkx: String,
    pub pkx_record_name: String,
    pub verified_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneInfo {
    pub username: String,
    pub bns_name: String,
    pub zone: Option<String>,
    pub relay_sn: Option<String>,
    pub self_cert: bool,
    pub cert_checked_at: Option<u64>,
    pub cert_expires_at: Option<u64>,
    pub sn_ips: Option<String>,
    pub source_version: Option<String>,
    pub updated_at: u64,
}

impl ZoneInfo {
    pub fn default_for(username: &str) -> Self {
        Self {
            username: username.to_string(),
            bns_name: username.to_string(),
            zone: None,
            relay_sn: None,
            self_cert: false,
            cert_checked_at: None,
            cert_expires_at: None,
            sn_ips: None,
            source_version: None,
            updated_at: 0,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ZoneInfoPatch {
    pub bns_name: Option<String>,
    pub zone: Option<String>,
    pub relay_sn: Option<String>,
    pub self_cert: Option<bool>,
    pub cert_checked_at: Option<u64>,
    pub cert_expires_at: Option<u64>,
    pub sn_ips: Option<String>,
    pub source_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountSession {
    pub session_id: String,
    pub username: String,
    pub token_aud: String,
    pub state: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub revoked_at: Option<u64>,
}

#[async_trait::async_trait]
pub trait SnAuthDB: Send + Sync + 'static {
    async fn get_activation_codes(&self) -> SnResult<Vec<String>>;
    async fn insert_activation_code(&self, code: &str) -> SnResult<()>;
    async fn generate_activation_codes(&self, count: usize) -> SnResult<Vec<String>>;
    async fn check_active_code(&self, active_code: &str) -> SnResult<bool>;
    async fn clear_state_by_active_code(&self, active_code: &str) -> SnResult<SnClearStateResult>;
    async fn register_user_v2(
        &self,
        active_code: &str,
        username: &str,
        password_hash: &str,
        password_salt: &str,
        password_algo: &str,
    ) -> SnResult<bool>;
    async fn create_v2_auth(
        &self,
        username: &str,
        password_hash: &str,
        password_salt: &str,
        password_algo: &str,
    ) -> SnResult<bool>;
    async fn is_user_exist(&self, username: &str) -> SnResult<bool>;
    async fn register_user_with_owner_key(
        &self,
        active_code: &str,
        username: &str,
        public_key: &str,
        zone_config: &str,
        user_domain: Option<String>,
        sn_ips: Option<String>,
    ) -> SnResult<bool>;
    async fn get_user_by_public_key(
        &self,
        public_key: &str,
    ) -> SnResult<Option<(String, String, Option<String>)>>;
    async fn get_user_info(&self, username: &str) -> SnResult<Option<SNUserInfo>>;
    async fn get_user_by_domain(&self, domain: &str) -> SnResult<Option<SNUserInfo>>;
    async fn set_user_state(&self, username: &str, state: UserState) -> SnResult<()>;
    async fn update_user_public_key(&self, username: &str, public_key: &str) -> SnResult<()>;
    async fn update_user_zone_config(&self, username: &str, zone_config: &str) -> SnResult<()>;
    async fn update_user_self_cert(&self, username: &str, self_cert: bool) -> SnResult<()>;
    async fn update_user_domain(&self, username: &str, user_domain: Option<String>)
        -> SnResult<()>;
    async fn get_user_sn_ips(&self, username: &str) -> SnResult<Option<String>>;
    async fn get_user_sn_ips_as_vec(&self, username: &str) -> SnResult<Option<Vec<String>>> {
        let Some(sn_ips) = self.get_user_sn_ips(username).await? else {
            return Ok(None);
        };
        if sn_ips.trim().is_empty() {
            return Ok(Some(Vec::new()));
        }
        match serde_json::from_str::<Vec<String>>(sn_ips.as_str()) {
            Ok(ips) => Ok(Some(ips)),
            Err(_) => Ok(Some(
                sn_ips
                    .split(',')
                    .map(str::trim)
                    .filter(|ip| !ip.is_empty())
                    .map(ToString::to_string)
                    .collect(),
            )),
        }
    }
    async fn get_v2_auth(&self, username: &str) -> SnResult<Option<SnV2AuthInfo>>;
    async fn update_v2_last_login(&self, username: &str, last_login_at: u64) -> SnResult<()>;

    async fn create_pkx_binding(
        &self,
        username: &str,
        domain: &str,
    ) -> SnResult<PkxBindingChallenge>;
    async fn verify_pkx_binding(
        &self,
        username: &str,
        domain: &str,
        txt_records: &[String],
    ) -> SnResult<DomainBinding>;
    async fn unbind_user_domain(&self, username: &str, domain: &str) -> SnResult<()>;

    async fn get_zone_info(&self, username: &str) -> SnResult<Option<ZoneInfo>>;
    async fn update_zone_info(&self, username: &str, patch: ZoneInfoPatch) -> SnResult<()>;
    async fn update_zone_relay_sn(
        &self,
        zone: &str,
        relay_sn: &str,
        source_version: Option<&str>,
    ) -> SnResult<bool> {
        let _ = (zone, relay_sn, source_version);
        Ok(false)
    }

    async fn create_account_session(
        &self,
        session_id: &str,
        username: &str,
        token_aud: &str,
        issued_at: u64,
        expires_at: u64,
    ) -> SnResult<()>;
    async fn revoke_account_session(&self, session_id: &str, revoked_at: u64) -> SnResult<()>;
    async fn revoke_user_sessions(&self, username: &str, revoked_at: u64) -> SnResult<u64>;
    async fn get_account_session(&self, session_id: &str) -> SnResult<Option<AccountSession>>;
}

/// Remote SnAuthDB backed by the sn_auth_db S2S KRPC API.
#[derive(Clone)]
pub struct RemoteSnAuthDB {
    client: crate::s2s_api::SnAuthDbClient,
}

impl RemoteSnAuthDB {
    pub fn new(client: crate::s2s_api::SnAuthDbClient) -> Self {
        Self { client }
    }

    pub fn new_krpc(client: std::sync::Arc<::kRPC::kRPC>) -> Self {
        Self::new(crate::s2s_api::SnAuthDbClient::new_krpc(client))
    }

    pub fn new_krpc_url(auth_db_url: &str, session_token: Option<String>) -> Self {
        Self::new(crate::s2s_api::SnAuthDbClient::new_krpc_url(
            auth_db_url,
            session_token,
        ))
    }

    pub fn client(&self) -> &crate::s2s_api::SnAuthDbClient {
        &self.client
    }
}

#[async_trait::async_trait]
impl SnAuthDB for RemoteSnAuthDB {
    async fn get_activation_codes(&self) -> SnResult<Vec<String>> {
        self.client.get_activation_codes().await
    }

    async fn insert_activation_code(&self, code: &str) -> SnResult<()> {
        self.client.insert_activation_code(code).await
    }

    async fn generate_activation_codes(&self, count: usize) -> SnResult<Vec<String>> {
        self.client.generate_activation_codes(count).await
    }

    async fn check_active_code(&self, active_code: &str) -> SnResult<bool> {
        self.client.check_active_code(active_code).await
    }

    async fn clear_state_by_active_code(&self, active_code: &str) -> SnResult<SnClearStateResult> {
        self.client.clear_state_by_active_code(active_code).await
    }

    async fn register_user_v2(
        &self,
        active_code: &str,
        username: &str,
        password_hash: &str,
        password_salt: &str,
        password_algo: &str,
    ) -> SnResult<bool> {
        self.client
            .register_user_v2(
                active_code,
                username,
                password_hash,
                password_salt,
                password_algo,
            )
            .await
    }

    async fn create_v2_auth(
        &self,
        username: &str,
        password_hash: &str,
        password_salt: &str,
        password_algo: &str,
    ) -> SnResult<bool> {
        self.client
            .create_v2_auth(username, password_hash, password_salt, password_algo)
            .await
    }

    async fn is_user_exist(&self, username: &str) -> SnResult<bool> {
        self.client.is_user_exist(username).await
    }

    async fn register_user_with_owner_key(
        &self,
        active_code: &str,
        username: &str,
        public_key: &str,
        zone_config: &str,
        user_domain: Option<String>,
        sn_ips: Option<String>,
    ) -> SnResult<bool> {
        self.client
            .register_user_with_owner_key(
                active_code,
                username,
                public_key,
                zone_config,
                user_domain,
                sn_ips,
            )
            .await
    }

    async fn get_user_by_public_key(
        &self,
        public_key: &str,
    ) -> SnResult<Option<(String, String, Option<String>)>> {
        self.client.get_user_by_public_key(public_key).await
    }

    async fn get_user_info(&self, username: &str) -> SnResult<Option<SNUserInfo>> {
        self.client.get_user_info(username).await
    }

    async fn get_user_by_domain(&self, domain: &str) -> SnResult<Option<SNUserInfo>> {
        self.client.get_user_by_domain(domain).await
    }

    async fn set_user_state(&self, username: &str, state: UserState) -> SnResult<()> {
        self.client.set_user_state(username, state).await
    }

    async fn update_user_public_key(&self, username: &str, public_key: &str) -> SnResult<()> {
        self.client
            .update_user_public_key(username, public_key)
            .await
    }

    async fn update_user_zone_config(&self, username: &str, zone_config: &str) -> SnResult<()> {
        self.client
            .update_user_zone_config(username, zone_config)
            .await
    }

    async fn update_user_self_cert(&self, username: &str, self_cert: bool) -> SnResult<()> {
        self.client.update_user_self_cert(username, self_cert).await
    }

    async fn update_user_domain(
        &self,
        username: &str,
        user_domain: Option<String>,
    ) -> SnResult<()> {
        self.client.update_user_domain(username, user_domain).await
    }

    async fn get_user_sn_ips(&self, username: &str) -> SnResult<Option<String>> {
        self.client.get_user_sn_ips(username).await
    }

    async fn get_v2_auth(&self, username: &str) -> SnResult<Option<SnV2AuthInfo>> {
        self.client.get_v2_auth(username).await
    }

    async fn update_v2_last_login(&self, username: &str, last_login_at: u64) -> SnResult<()> {
        self.client
            .update_v2_last_login(username, last_login_at)
            .await
    }

    async fn create_pkx_binding(
        &self,
        username: &str,
        domain: &str,
    ) -> SnResult<PkxBindingChallenge> {
        self.client.create_pkx_binding(username, domain).await
    }

    async fn verify_pkx_binding(
        &self,
        username: &str,
        domain: &str,
        txt_records: &[String],
    ) -> SnResult<DomainBinding> {
        self.client
            .verify_pkx_binding(username, domain, txt_records)
            .await
    }

    async fn unbind_user_domain(&self, username: &str, domain: &str) -> SnResult<()> {
        self.client.unbind_user_domain(username, domain).await
    }

    async fn get_zone_info(&self, username: &str) -> SnResult<Option<ZoneInfo>> {
        self.client.get_zone_info(username).await
    }

    async fn update_zone_info(&self, username: &str, patch: ZoneInfoPatch) -> SnResult<()> {
        self.client.update_zone_info(username, patch).await
    }

    async fn update_zone_relay_sn(
        &self,
        zone: &str,
        relay_sn: &str,
        source_version: Option<&str>,
    ) -> SnResult<bool> {
        self.client
            .update_zone_relay_sn(zone, relay_sn, source_version)
            .await
    }

    async fn create_account_session(
        &self,
        session_id: &str,
        username: &str,
        token_aud: &str,
        issued_at: u64,
        expires_at: u64,
    ) -> SnResult<()> {
        self.client
            .create_account_session(session_id, username, token_aud, issued_at, expires_at)
            .await
    }

    async fn revoke_account_session(&self, session_id: &str, revoked_at: u64) -> SnResult<()> {
        self.client
            .revoke_account_session(session_id, revoked_at)
            .await
    }

    async fn revoke_user_sessions(&self, username: &str, revoked_at: u64) -> SnResult<u64> {
        self.client.revoke_user_sessions(username, revoked_at).await
    }

    async fn get_account_session(&self, session_id: &str) -> SnResult<Option<AccountSession>> {
        self.client.get_account_session(session_id).await
    }
}

pub struct SqliteSnAuthDB {
    pool: SqlitePool,
}

impl SqliteSnAuthDB {
    const USER_DOMAIN_BINDING_LOCK: &'static str = "sn_user_domain_binding";

    pub async fn new() -> SnResult<Self> {
        let base_dir = PathBuf::from(std::env::current_exe().unwrap().parent().unwrap());
        let db_path = base_dir.join("sn_auth.sqlite3");

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

        Ok(Self { pool })
    }

    pub async fn initialize_database(&self) -> SnResult<()> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS activation_codes (
                code TEXT PRIMARY KEY,
                used INTEGER NOT NULL DEFAULT 0
            )",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| Self::db_err("create activation_codes table failed", e))?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                state TEXT NOT NULL DEFAULT 'active',
                bns_name TEXT,
                public_key TEXT NOT NULL DEFAULT '',
                activation_code TEXT,
                owner_key_ref TEXT,
                zone_config TEXT NOT NULL DEFAULT '',
                self_cert INTEGER NOT NULL DEFAULT 0,
                user_domain TEXT,
                sn_ips TEXT,
                created_at INTEGER NOT NULL DEFAULT 0,
                updated_at INTEGER NOT NULL DEFAULT 0,
                last_login_at INTEGER NULL
            )",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| Self::db_err("create users table failed", e))?;
        self.ensure_user_columns().await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS user_auth_v2 (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                password_algo TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                last_login_at INTEGER NULL
            )",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| Self::db_err("create user_auth_v2 table failed", e))?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS user_domain_history (
                domain TEXT PRIMARY KEY,
                owner TEXT NOT NULL,
                created_at INTEGER NOT NULL
            )",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| Self::db_err("create user_domain_history table failed", e))?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS user_domain_bindings (
                domain TEXT PRIMARY KEY,
                owner TEXT NOT NULL,
                state TEXT NOT NULL,
                pkx TEXT NOT NULL,
                pkx_record_name TEXT NOT NULL,
                verified_at INTEGER NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            )",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| Self::db_err("create user_domain_bindings table failed", e))?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_user_domain_bindings_owner_state
             ON user_domain_bindings (owner, state)",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| Self::db_err("create user_domain_bindings index failed", e))?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS zone_info (
                username TEXT PRIMARY KEY,
                bns_name TEXT NOT NULL,
                zone TEXT NULL,
                relay_sn TEXT NULL,
                self_cert INTEGER NOT NULL DEFAULT 0,
                cert_checked_at INTEGER NULL,
                cert_expires_at INTEGER NULL,
                sn_ips TEXT NULL,
                source_version TEXT NULL,
                updated_at INTEGER NOT NULL
            )",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| Self::db_err("create zone_info table failed", e))?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS account_sessions (
                session_id TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                token_aud TEXT NOT NULL,
                state TEXT NOT NULL,
                issued_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                revoked_at INTEGER NULL
            )",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| Self::db_err("create account_sessions table failed", e))?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_account_sessions_username_state
             ON account_sessions (username, state)",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| Self::db_err("create account_sessions index failed", e))?;

        self.backfill_user_domain_history().await?;
        self.backfill_zone_info().await?;

        Ok(())
    }

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn generate_activation_code() -> String {
        let mut rng = rand::rng();
        (0..ACTIVATION_CODE_LEN)
            .map(|_| {
                let index = rng.random_range(0..ACTIVATION_CODE_CHARS.len());
                ACTIVATION_CODE_CHARS[index] as char
            })
            .collect()
    }

    fn db_err(context: impl AsRef<str>, err: impl std::fmt::Display) -> SnError {
        sn_err!(SnErrorCode::DBError, "{}: {}", context.as_ref(), err)
    }

    fn invalid_input(context: impl AsRef<str>) -> SnError {
        sn_err!(SnErrorCode::InvalidInput, "{}", context.as_ref())
    }

    fn check_non_empty(value: &str, field: &str) -> SnResult<()> {
        if value.trim().is_empty() {
            return Err(Self::invalid_input(format!("{} is empty", field)));
        }

        Ok(())
    }

    fn canonical_user_domain(domain: &str) -> Option<String> {
        let normalized = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        if normalized.is_empty() {
            return None;
        }

        Some(
            normalized
                .strip_prefix("*.")
                .unwrap_or(normalized.as_str())
                .to_string(),
        )
    }

    fn pkx_record_name(canonical_domain: &str) -> String {
        format!("_pkx.{}", canonical_domain)
    }

    fn pkx_value(pkx_source: &str) -> SnResult<String> {
        let pkx_source = pkx_source.trim();
        if pkx_source.is_empty() {
            return Err(Self::invalid_input(
                "owner key ref or public key is required before creating PKX binding",
            ));
        }
        Ok(format!("PKX({})", pkx_source))
    }

    fn txt_matches_pkx(txt: &str, expected_pkx: &str) -> bool {
        txt.trim().trim_matches('"') == expected_pkx
    }

    fn i64_to_u64(value: i64) -> u64 {
        value.max(0) as u64
    }

    fn opt_i64_to_u64(value: Option<i64>) -> Option<u64> {
        value.map(Self::i64_to_u64)
    }

    async fn ensure_user_columns(&self) -> SnResult<()> {
        self.ensure_column("users", "bns_name", "TEXT").await?;
        self.ensure_column("users", "owner_key_ref", "TEXT").await?;
        self.ensure_column("users", "created_at", "INTEGER NOT NULL DEFAULT 0")
            .await?;
        self.ensure_column("users", "updated_at", "INTEGER NOT NULL DEFAULT 0")
            .await?;
        self.ensure_column("users", "last_login_at", "INTEGER NULL")
            .await?;
        Ok(())
    }

    async fn ensure_column(&self, table: &str, column: &str, definition: &str) -> SnResult<()> {
        let pragma = format!("PRAGMA table_info({})", table);
        let rows = sqlx::query(pragma.as_str())
            .fetch_all(&self.pool)
            .await
            .map_err(|e| Self::db_err(format!("query {} columns failed", table), e))?;
        let exists = rows.iter().any(|row| {
            row.try_get::<String, _>("name")
                .map(|name| name == column)
                .unwrap_or(false)
        });
        if !exists {
            let alter = format!("ALTER TABLE {} ADD COLUMN {} {}", table, column, definition);
            sqlx::query(alter.as_str())
                .execute(&self.pool)
                .await
                .map_err(|e| Self::db_err(format!("add {}.{} failed", table, column), e))?;
        }
        Ok(())
    }

    async fn backfill_user_domain_history(&self) -> SnResult<()> {
        let rows = sqlx::query(
            "SELECT username, user_domain FROM users
             WHERE user_domain IS NOT NULL AND user_domain != ''",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| Self::db_err("query existing user_domain history failed", e))?;
        let now = Self::now_secs() as i64;
        for row in rows {
            let username: String = row
                .try_get("username")
                .map_err(|e| Self::db_err("read username failed", e))?;
            let user_domain: String = row
                .try_get("user_domain")
                .map_err(|e| Self::db_err("read user_domain failed", e))?;
            if let Some(canonical_domain) = Self::canonical_user_domain(user_domain.as_str()) {
                sqlx::query(
                    "INSERT OR IGNORE INTO user_domain_history (domain, owner, created_at)
                     VALUES (?1, ?2, ?3)",
                )
                .bind(canonical_domain)
                .bind(username)
                .bind(now)
                .execute(&self.pool)
                .await
                .map_err(|e| Self::db_err("backfill user_domain_history failed", e))?;
            }
        }
        Ok(())
    }

    async fn backfill_zone_info(&self) -> SnResult<()> {
        let rows = sqlx::query(
            "SELECT username, bns_name, zone_config, self_cert, sn_ips, updated_at FROM users",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| Self::db_err("query users for zone_info backfill failed", e))?;

        let now = Self::now_secs() as i64;
        for row in rows {
            let username: String = row
                .try_get("username")
                .map_err(|e| Self::db_err("read username failed", e))?;
            let bns_name: Option<String> = row
                .try_get("bns_name")
                .map_err(|e| Self::db_err("read bns_name failed", e))?;
            let zone_config: Option<String> = row
                .try_get("zone_config")
                .map_err(|e| Self::db_err("read zone_config failed", e))?;
            let self_cert: Option<i64> = row
                .try_get("self_cert")
                .map_err(|e| Self::db_err("read self_cert failed", e))?;
            let sn_ips: Option<String> = row
                .try_get("sn_ips")
                .map_err(|e| Self::db_err("read sn_ips failed", e))?;
            let updated_at: Option<i64> = row
                .try_get("updated_at")
                .map_err(|e| Self::db_err("read updated_at failed", e))?;
            let zone = zone_config.and_then(|value| {
                if value.trim().is_empty() {
                    None
                } else {
                    Some(value)
                }
            });
            sqlx::query(
                "INSERT OR IGNORE INTO zone_info
                    (username, bns_name, zone, relay_sn, self_cert, cert_checked_at,
                     cert_expires_at, sn_ips, source_version, updated_at)
                 VALUES (?1, ?2, ?3, NULL, ?4, NULL, NULL, ?5, NULL, ?6)",
            )
            .bind(username.as_str())
            .bind(bns_name.unwrap_or_else(|| username.clone()))
            .bind(zone)
            .bind(self_cert.unwrap_or(0))
            .bind(sn_ips)
            .bind(updated_at.filter(|v| *v > 0).unwrap_or(now))
            .execute(&self.pool)
            .await
            .map_err(|e| Self::db_err("backfill zone_info failed", e))?;
        }
        Ok(())
    }

    async fn table_exists_tx(tx: &mut Transaction<'_, Sqlite>, table_name: &str) -> SnResult<bool> {
        let row = sqlx::query("SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?1")
            .bind(table_name)
            .fetch_optional(&mut **tx)
            .await
            .map_err(|e| Self::db_err("query sqlite_master failed", e))?;
        Ok(row.is_some())
    }

    async fn count_optional_related_rows(
        tx: &mut Transaction<'_, Sqlite>,
        table_name: &str,
        active_code: &str,
    ) -> SnResult<i64> {
        if !Self::table_exists_tx(tx, table_name).await? {
            return Ok(0);
        }

        let sql = match table_name {
            "devices" => {
                "SELECT COUNT(*) FROM devices
                 WHERE owner IN (
                    SELECT username FROM users WHERE activation_code = ?1
                 )"
            }
            "user_dns_records" => {
                "SELECT COUNT(*) FROM user_dns_records
                 WHERE owner IN (
                    SELECT username FROM users WHERE activation_code = ?1
                 )"
            }
            "did_documents" => {
                "SELECT COUNT(*) FROM did_documents
                 WHERE owner_user IN (
                    SELECT username FROM users WHERE activation_code = ?1
                 )"
            }
            _ => return Ok(0),
        };

        sqlx::query_scalar::<_, i64>(sql)
            .bind(active_code)
            .fetch_one(&mut **tx)
            .await
            .map_err(|e| Self::db_err(format!("count {} failed", table_name), e))
    }

    async fn delete_optional_related_rows(
        tx: &mut Transaction<'_, Sqlite>,
        active_code: &str,
    ) -> SnResult<()> {
        if Self::table_exists_tx(tx, "devices").await? {
            sqlx::query(
                "DELETE FROM devices
                 WHERE owner IN (
                    SELECT username FROM users WHERE activation_code = ?1
                 )",
            )
            .bind(active_code)
            .execute(&mut **tx)
            .await
            .map_err(|e| Self::db_err("delete devices failed", e))?;
        }

        if Self::table_exists_tx(tx, "user_dns_records").await? {
            sqlx::query(
                "DELETE FROM user_dns_records
                 WHERE owner IN (
                    SELECT username FROM users WHERE activation_code = ?1
                 )",
            )
            .bind(active_code)
            .execute(&mut **tx)
            .await
            .map_err(|e| Self::db_err("delete user dns records failed", e))?;
        }

        if Self::table_exists_tx(tx, "did_documents").await? {
            sqlx::query(
                "DELETE FROM did_documents
                 WHERE owner_user IN (
                    SELECT username FROM users WHERE activation_code = ?1
                 )",
            )
            .bind(active_code)
            .execute(&mut **tx)
            .await
            .map_err(|e| Self::db_err("delete did documents failed", e))?;
        }

        Ok(())
    }

    async fn check_domain_conflicts_tx(
        tx: &mut Transaction<'_, Sqlite>,
        username: &str,
        canonical_domain: &str,
    ) -> SnResult<()> {
        let descendant_pattern = format!("%.{}", canonical_domain);
        let history_conflicts = sqlx::query(
            "SELECT domain, owner FROM user_domain_history
             WHERE owner != ?1
               AND (domain = ?2 OR domain LIKE ?3 OR ?2 LIKE '%.' || domain)",
        )
        .bind(username)
        .bind(canonical_domain)
        .bind(descendant_pattern.as_str())
        .fetch_all(&mut **tx)
        .await
        .map_err(|e| Self::db_err("query user_domain history failed", e))?;
        if let Some(conflict) = history_conflicts.first() {
            let conflict_domain: String = conflict
                .try_get("domain")
                .map_err(|e| Self::db_err("read conflict domain failed", e))?;
            let conflict_owner: String = conflict
                .try_get("owner")
                .map_err(|e| Self::db_err("read conflict owner failed", e))?;
            return Err(sn_err!(
                SnErrorCode::Conflict,
                "user_domain {} conflicts with historical domain {} owned by {}",
                canonical_domain,
                conflict_domain,
                conflict_owner
            ));
        }

        let active_conflicts = sqlx::query(
            "SELECT domain, owner FROM user_domain_bindings
             WHERE owner != ?1
               AND state IN ('pending_pkx', 'active')
               AND (domain = ?2 OR domain LIKE ?3 OR ?2 LIKE '%.' || domain)",
        )
        .bind(username)
        .bind(canonical_domain)
        .bind(descendant_pattern.as_str())
        .fetch_all(&mut **tx)
        .await
        .map_err(|e| Self::db_err("query user_domain bindings failed", e))?;
        if let Some(conflict) = active_conflicts.first() {
            let conflict_domain: String = conflict
                .try_get("domain")
                .map_err(|e| Self::db_err("read conflict domain failed", e))?;
            let conflict_owner: String = conflict
                .try_get("owner")
                .map_err(|e| Self::db_err("read conflict owner failed", e))?;
            return Err(sn_err!(
                SnErrorCode::Conflict,
                "user_domain {} conflicts with pending/active domain {} owned by {}",
                canonical_domain,
                conflict_domain,
                conflict_owner
            ));
        }

        Ok(())
    }

    fn user_from_row(row: &sqlx::sqlite::SqliteRow) -> SnResult<SNUserInfo> {
        let state_str: Option<String> = row
            .try_get("state")
            .map_err(|e| Self::db_err("read state failed", e))?;
        let self_cert: Option<i64> = row
            .try_get("self_cert")
            .map_err(|e| Self::db_err("read self_cert failed", e))?;
        Ok(SNUserInfo {
            username: Some(
                row.try_get("username")
                    .map_err(|e| Self::db_err("read username failed", e))?,
            ),
            state: UserState::from_str(state_str.as_deref()),
            public_key: row
                .try_get::<Option<String>, _>("public_key")
                .map_err(|e| Self::db_err("read public_key failed", e))?
                .unwrap_or_default(),
            activation_code: row
                .try_get("activation_code")
                .map_err(|e| Self::db_err("read activation_code failed", e))?,
            zone_config: row
                .try_get::<Option<String>, _>("zone_config")
                .map_err(|e| Self::db_err("read zone_config failed", e))?
                .unwrap_or_default(),
            self_cert: self_cert.unwrap_or(0) != 0,
            user_domain: row
                .try_get("user_domain")
                .map_err(|e| Self::db_err("read user_domain failed", e))?,
            sn_ips: row
                .try_get("sn_ips")
                .map_err(|e| Self::db_err("read sn_ips failed", e))?,
        })
    }

    fn zone_info_from_row(row: &sqlx::sqlite::SqliteRow) -> SnResult<ZoneInfo> {
        let self_cert: i64 = row
            .try_get("self_cert")
            .map_err(|e| Self::db_err("read self_cert failed", e))?;
        let updated_at: i64 = row
            .try_get("updated_at")
            .map_err(|e| Self::db_err("read updated_at failed", e))?;
        Ok(ZoneInfo {
            username: row
                .try_get("username")
                .map_err(|e| Self::db_err("read username failed", e))?,
            bns_name: row
                .try_get("bns_name")
                .map_err(|e| Self::db_err("read bns_name failed", e))?,
            zone: row
                .try_get("zone")
                .map_err(|e| Self::db_err("read zone failed", e))?,
            relay_sn: row
                .try_get("relay_sn")
                .map_err(|e| Self::db_err("read relay_sn failed", e))?,
            self_cert: self_cert != 0,
            cert_checked_at: Self::opt_i64_to_u64(
                row.try_get("cert_checked_at")
                    .map_err(|e| Self::db_err("read cert_checked_at failed", e))?,
            ),
            cert_expires_at: Self::opt_i64_to_u64(
                row.try_get("cert_expires_at")
                    .map_err(|e| Self::db_err("read cert_expires_at failed", e))?,
            ),
            sn_ips: row
                .try_get("sn_ips")
                .map_err(|e| Self::db_err("read sn_ips failed", e))?,
            source_version: row
                .try_get("source_version")
                .map_err(|e| Self::db_err("read source_version failed", e))?,
            updated_at: Self::i64_to_u64(updated_at),
        })
    }
}

#[async_trait::async_trait]
impl SnAuthDB for SqliteSnAuthDB {
    async fn get_activation_codes(&self) -> SnResult<Vec<String>> {
        let rows = sqlx::query("SELECT code FROM activation_codes WHERE used = 0")
            .fetch_all(&self.pool)
            .await
            .map_err(|e| Self::db_err("query activation_codes failed", e))?;
        rows.into_iter()
            .map(|row| {
                row.try_get(0)
                    .map_err(|e| Self::db_err("read activation code failed", e))
            })
            .collect()
    }

    async fn insert_activation_code(&self, code: &str) -> SnResult<()> {
        sqlx::query("INSERT INTO activation_codes (code, used) VALUES (?1, 0)")
            .bind(code)
            .execute(&self.pool)
            .await
            .map_err(|e| Self::db_err("insert activation_codes failed", e))?;
        Ok(())
    }

    async fn generate_activation_codes(&self, count: usize) -> SnResult<Vec<String>> {
        let mut codes = Vec::with_capacity(count);
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| Self::db_err("begin transaction failed", e))?;

        while codes.len() < count {
            let code = Self::generate_activation_code();
            let result =
                sqlx::query("INSERT OR IGNORE INTO activation_codes (code, used) VALUES (?1, 0)")
                    .bind(code.as_str())
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| Self::db_err("insert activation_codes failed", e))?;

            if result.rows_affected() > 0 {
                codes.push(code);
            }
        }

        tx.commit()
            .await
            .map_err(|e| Self::db_err("commit transaction failed", e))?;
        Ok(codes)
    }

    async fn check_active_code(&self, active_code: &str) -> SnResult<bool> {
        let used =
            sqlx::query_scalar::<_, i64>("SELECT used FROM activation_codes WHERE code = ?1")
                .bind(active_code)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| Self::db_err("query activation code failed", e))?;
        Ok(used == Some(0))
    }

    async fn clear_state_by_active_code(&self, active_code: &str) -> SnResult<SnClearStateResult> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| Self::db_err("begin transaction failed", e))?;

        let user_count =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users WHERE activation_code = ?1")
                .bind(active_code)
                .fetch_one(&mut *tx)
                .await
                .map_err(|e| Self::db_err("count users failed", e))?;
        let device_count =
            Self::count_optional_related_rows(&mut tx, "devices", active_code).await?;
        let domain_record_count =
            Self::count_optional_related_rows(&mut tx, "user_dns_records", active_code).await?;
        let did_doc_count =
            Self::count_optional_related_rows(&mut tx, "did_documents", active_code).await?;

        Self::delete_optional_related_rows(&mut tx, active_code).await?;

        sqlx::query(
            "DELETE FROM account_sessions
             WHERE username IN (
                SELECT username FROM users WHERE activation_code = ?1
             )",
        )
        .bind(active_code)
        .execute(&mut *tx)
        .await
        .map_err(|e| Self::db_err("delete account sessions failed", e))?;

        sqlx::query(
            "DELETE FROM user_domain_bindings
             WHERE owner IN (
                SELECT username FROM users WHERE activation_code = ?1
             )",
        )
        .bind(active_code)
        .execute(&mut *tx)
        .await
        .map_err(|e| Self::db_err("delete user domain bindings failed", e))?;

        sqlx::query(
            "DELETE FROM zone_info
             WHERE username IN (
                SELECT username FROM users WHERE activation_code = ?1
             )",
        )
        .bind(active_code)
        .execute(&mut *tx)
        .await
        .map_err(|e| Self::db_err("delete zone info failed", e))?;

        sqlx::query(
            "DELETE FROM user_auth_v2
             WHERE username IN (
                SELECT username FROM users WHERE activation_code = ?1
             )",
        )
        .bind(active_code)
        .execute(&mut *tx)
        .await
        .map_err(|e| Self::db_err("delete user auth v2 failed", e))?;

        sqlx::query("DELETE FROM users WHERE activation_code = ?1")
            .bind(active_code)
            .execute(&mut *tx)
            .await
            .map_err(|e| Self::db_err("delete users failed", e))?;

        sqlx::query(
            "INSERT INTO activation_codes (code, used) VALUES (?1, 0)
             ON CONFLICT(code) DO UPDATE SET used = 0",
        )
        .bind(active_code)
        .execute(&mut *tx)
        .await
        .map_err(|e| Self::db_err("reset activation code failed", e))?;

        tx.commit()
            .await
            .map_err(|e| Self::db_err("commit transaction failed", e))?;

        Ok(SnClearStateResult {
            deleted_users: user_count.max(0) as u64,
            deleted_devices: device_count.max(0) as u64,
            deleted_domain_records: domain_record_count.max(0) as u64,
            deleted_did_documents: did_doc_count.max(0) as u64,
            activation_code_reset: true,
        })
    }

    async fn register_user_v2(
        &self,
        active_code: &str,
        username: &str,
        password_hash: &str,
        password_salt: &str,
        password_algo: &str,
    ) -> SnResult<bool> {
        let _locker =
            async_named_locker::Locker::get_locker(format!("active_code_{}", active_code)).await;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| Self::db_err("begin transaction failed", e))?;

        let code_unused =
            sqlx::query_scalar::<_, i64>("SELECT used FROM activation_codes WHERE code = ?1")
                .bind(active_code)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|e| Self::db_err("query activation code failed", e))?
                == Some(0);
        if !code_unused {
            return Ok(false);
        }

        let user_count =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users WHERE username = ?1")
                .bind(username)
                .fetch_one(&mut *tx)
                .await
                .map_err(|e| Self::db_err("query user count failed", e))?;
        if user_count > 0 {
            return Ok(false);
        }

        let auth_count =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM user_auth_v2 WHERE username = ?1")
                .bind(username)
                .fetch_one(&mut *tx)
                .await
                .map_err(|e| Self::db_err("query user auth count failed", e))?;
        if auth_count > 0 {
            return Ok(false);
        }

        let now = Self::now_secs() as i64;
        sqlx::query(
            "INSERT INTO users
                (username, state, bns_name, public_key, activation_code, owner_key_ref,
                 zone_config, user_domain, self_cert, sn_ips, created_at, updated_at, last_login_at)
             VALUES (?1, ?2, ?3, '', ?4, NULL, '', NULL, 0, NULL, ?5, ?5, NULL)",
        )
        .bind(username)
        .bind(UserState::Active.to_string())
        .bind(username)
        .bind(active_code)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|e| Self::db_err("insert v2 user failed", e))?;

        sqlx::query(
            "INSERT INTO user_auth_v2
                (username, password_hash, password_salt, password_algo,
                 created_at, updated_at, last_login_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?5, NULL)",
        )
        .bind(username)
        .bind(password_hash)
        .bind(password_salt)
        .bind(password_algo)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|e| Self::db_err("insert v2 auth failed", e))?;

        sqlx::query("UPDATE activation_codes SET used = 1 WHERE code = ?1")
            .bind(active_code)
            .execute(&mut *tx)
            .await
            .map_err(|e| Self::db_err("update activation code failed", e))?;

        tx.commit()
            .await
            .map_err(|e| Self::db_err("commit transaction failed", e))?;

        Ok(true)
    }

    async fn create_v2_auth(
        &self,
        username: &str,
        password_hash: &str,
        password_salt: &str,
        password_algo: &str,
    ) -> SnResult<bool> {
        let _locker =
            async_named_locker::Locker::get_locker(format!("username_{}", username)).await;
        let user_count =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users WHERE username = ?1")
                .bind(username)
                .fetch_one(&self.pool)
                .await
                .map_err(|e| Self::db_err("query user count failed", e))?;
        if user_count > 0 {
            return Ok(false);
        }

        let auth_count =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM user_auth_v2 WHERE username = ?1")
                .bind(username)
                .fetch_one(&self.pool)
                .await
                .map_err(|e| Self::db_err("query user auth count failed", e))?;
        if auth_count > 0 {
            return Ok(false);
        }

        let now = Self::now_secs() as i64;
        sqlx::query(
            "INSERT INTO user_auth_v2
                (username, password_hash, password_salt, password_algo,
                 created_at, updated_at, last_login_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?5, NULL)",
        )
        .bind(username)
        .bind(password_hash)
        .bind(password_salt)
        .bind(password_algo)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| Self::db_err("insert v2 auth failed", e))?;

        Ok(true)
    }

    async fn is_user_exist(&self, username: &str) -> SnResult<bool> {
        let count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users WHERE username = ?1")
            .bind(username)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| Self::db_err("query user failed", e))?;
        Ok(count > 0)
    }

    async fn register_user_with_owner_key(
        &self,
        active_code: &str,
        username: &str,
        public_key: &str,
        zone_config: &str,
        user_domain: Option<String>,
        sn_ips: Option<String>,
    ) -> SnResult<bool> {
        let _locker =
            async_named_locker::Locker::get_locker(format!("active_code_{}", active_code)).await;
        let _domain_locker = if user_domain.is_some() {
            Some(
                async_named_locker::Locker::get_locker(Self::USER_DOMAIN_BINDING_LOCK.to_string())
                    .await,
            )
        } else {
            None
        };
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| Self::db_err("begin transaction failed", e))?;

        let code_unused =
            sqlx::query_scalar::<_, i64>("SELECT used FROM activation_codes WHERE code = ?1")
                .bind(active_code)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|e| Self::db_err("query activation code failed", e))?
                == Some(0);
        if !code_unused {
            return Ok(false);
        }

        let user_count =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users WHERE username = ?1")
                .bind(username)
                .fetch_one(&mut *tx)
                .await
                .map_err(|e| Self::db_err("query user count failed", e))?;
        if user_count > 0 {
            return Ok(false);
        }

        let canonical_domain = user_domain.as_deref().and_then(Self::canonical_user_domain);
        if let Some(domain) = canonical_domain.as_deref() {
            Self::check_domain_conflicts_tx(&mut tx, username, domain).await?;
        }

        let now = Self::now_secs() as i64;
        sqlx::query(
            "INSERT INTO users
                (username, state, bns_name, public_key, activation_code, owner_key_ref,
                 zone_config, user_domain, self_cert, sn_ips, created_at, updated_at, last_login_at)
             VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6, ?7, 0, ?8, ?9, ?9, NULL)",
        )
        .bind(username)
        .bind(UserState::Active.to_string())
        .bind(username)
        .bind(public_key)
        .bind(active_code)
        .bind(zone_config)
        .bind(canonical_domain.as_deref())
        .bind(sn_ips.as_deref())
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|e| Self::db_err("insert user failed", e))?;

        sqlx::query(
            "INSERT INTO zone_info
                (username, bns_name, zone, relay_sn, self_cert, cert_checked_at,
                 cert_expires_at, sn_ips, source_version, updated_at)
             VALUES (?1, ?2, ?3, NULL, 0, NULL, NULL, ?4, NULL, ?5)",
        )
        .bind(username)
        .bind(username)
        .bind(if zone_config.trim().is_empty() {
            None
        } else {
            Some(zone_config)
        })
        .bind(sn_ips.as_deref())
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|e| Self::db_err("insert zone info failed", e))?;

        if let Some(domain) = canonical_domain.as_deref() {
            let pkx = Self::pkx_value(public_key)?;
            let pkx_record_name = Self::pkx_record_name(domain);
            sqlx::query(
                "INSERT INTO user_domain_bindings
                    (domain, owner, state, pkx, pkx_record_name, verified_at, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, ?6)
                 ON CONFLICT(domain) DO UPDATE SET
                    owner = excluded.owner,
                    state = excluded.state,
                    pkx = excluded.pkx,
                    pkx_record_name = excluded.pkx_record_name,
                    verified_at = excluded.verified_at,
                    updated_at = excluded.updated_at",
            )
            .bind(domain)
            .bind(username)
            .bind(DOMAIN_BINDING_ACTIVE)
            .bind(pkx.as_str())
            .bind(pkx_record_name.as_str())
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(|e| Self::db_err("upsert user_domain binding failed", e))?;
            sqlx::query(
                "INSERT OR IGNORE INTO user_domain_history (domain, owner, created_at)
                 VALUES (?1, ?2, ?3)",
            )
            .bind(domain)
            .bind(username)
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(|e| Self::db_err("insert user_domain history failed", e))?;
        }

        sqlx::query("UPDATE activation_codes SET used = 1 WHERE code = ?1")
            .bind(active_code)
            .execute(&mut *tx)
            .await
            .map_err(|e| Self::db_err("update activation code failed", e))?;

        tx.commit()
            .await
            .map_err(|e| Self::db_err("commit transaction failed", e))?;
        Ok(true)
    }

    async fn get_user_by_public_key(
        &self,
        public_key: &str,
    ) -> SnResult<Option<(String, String, Option<String>)>> {
        let row =
            sqlx::query("SELECT username, zone_config, sn_ips FROM users WHERE public_key = ?1")
                .bind(public_key)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| Self::db_err("query user by public_key failed", e))?;

        row.map(|row| {
            Ok((
                row.try_get("username")
                    .map_err(|e| Self::db_err("read username failed", e))?,
                row.try_get::<Option<String>, _>("zone_config")
                    .map_err(|e| Self::db_err("read zone_config failed", e))?
                    .unwrap_or_default(),
                row.try_get("sn_ips")
                    .map_err(|e| Self::db_err("read sn_ips failed", e))?,
            ))
        })
        .transpose()
    }

    async fn get_user_info(&self, username: &str) -> SnResult<Option<SNUserInfo>> {
        let row = sqlx::query(
            "SELECT username, state, public_key, activation_code, zone_config,
                    self_cert, user_domain, sn_ips
             FROM users WHERE username = ?1",
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| Self::db_err("query user failed", e))?;

        row.as_ref().map(Self::user_from_row).transpose()
    }

    async fn get_user_by_domain(&self, domain: &str) -> SnResult<Option<SNUserInfo>> {
        let canonical_domain = match Self::canonical_user_domain(domain) {
            Some(domain) => domain,
            None => return Ok(None),
        };
        let row = sqlx::query(
            "SELECT u.username, u.state, u.public_key, u.activation_code, u.zone_config,
                    u.self_cert, u.user_domain, u.sn_ips
             FROM user_domain_bindings b
             JOIN users u ON u.username = b.owner
             WHERE b.state = 'active'
               AND (?1 = b.domain OR ?1 LIKE '%.' || b.domain)
             ORDER BY length(b.domain) DESC
             LIMIT 1",
        )
        .bind(canonical_domain.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| Self::db_err("query user by domain failed", e))?;

        if row.is_some() {
            return row.as_ref().map(Self::user_from_row).transpose();
        }

        let row = sqlx::query(
            "SELECT username, state, public_key, activation_code, zone_config,
                    self_cert, user_domain, sn_ips
             FROM users
             WHERE user_domain IS NOT NULL
               AND user_domain != ''
               AND (?1 = user_domain OR ?1 LIKE '%.' || user_domain)
             ORDER BY length(user_domain) DESC
             LIMIT 1",
        )
        .bind(canonical_domain.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| Self::db_err("query legacy user_domain failed", e))?;

        row.as_ref().map(Self::user_from_row).transpose()
    }

    async fn set_user_state(&self, username: &str, state: UserState) -> SnResult<()> {
        let now = Self::now_secs() as i64;
        sqlx::query("UPDATE users SET state = ?1, updated_at = ?2 WHERE username = ?3")
            .bind(state.to_string())
            .bind(now)
            .bind(username)
            .execute(&self.pool)
            .await
            .map_err(|e| Self::db_err("update user state failed", e))?;
        if !state.is_active() {
            self.revoke_user_sessions(username, now as u64).await?;
        }
        Ok(())
    }

    async fn update_user_public_key(&self, username: &str, public_key: &str) -> SnResult<()> {
        let now = Self::now_secs() as i64;
        sqlx::query("UPDATE users SET public_key = ?1, updated_at = ?2 WHERE username = ?3")
            .bind(public_key)
            .bind(now)
            .bind(username)
            .execute(&self.pool)
            .await
            .map_err(|e| Self::db_err("update user public_key failed", e))?;
        Ok(())
    }

    async fn update_user_zone_config(&self, username: &str, zone_config: &str) -> SnResult<()> {
        self.update_zone_info(
            username,
            ZoneInfoPatch {
                zone: Some(zone_config.to_string()),
                ..ZoneInfoPatch::default()
            },
        )
        .await
    }

    async fn update_user_self_cert(&self, username: &str, self_cert: bool) -> SnResult<()> {
        self.update_zone_info(
            username,
            ZoneInfoPatch {
                self_cert: Some(self_cert),
                ..ZoneInfoPatch::default()
            },
        )
        .await
    }

    async fn update_user_domain(
        &self,
        username: &str,
        user_domain: Option<String>,
    ) -> SnResult<()> {
        let _locker =
            async_named_locker::Locker::get_locker(Self::USER_DOMAIN_BINDING_LOCK.to_string())
                .await;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| Self::db_err("begin transaction failed", e))?;
        let now = Self::now_secs() as i64;

        let canonical_domain = user_domain.as_deref().and_then(Self::canonical_user_domain);

        if let Some(domain) = canonical_domain.as_deref() {
            Self::check_domain_conflicts_tx(&mut tx, username, domain).await?;
            let user =
                sqlx::query("SELECT public_key, owner_key_ref FROM users WHERE username = ?1")
                    .bind(username)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(|e| Self::db_err("query user failed", e))?
                    .ok_or_else(|| {
                        sn_err!(SnErrorCode::NotFound, "user not found: {}", username)
                    })?;
            let owner_key_ref: Option<String> = user
                .try_get("owner_key_ref")
                .map_err(|e| Self::db_err("read owner_key_ref failed", e))?;
            let public_key: Option<String> = user
                .try_get("public_key")
                .map_err(|e| Self::db_err("read public_key failed", e))?;
            let pkx_source = owner_key_ref
                .filter(|value| !value.trim().is_empty())
                .or_else(|| public_key.filter(|value| !value.trim().is_empty()))
                .unwrap_or_default();
            let pkx = if pkx_source.trim().is_empty() {
                String::new()
            } else {
                Self::pkx_value(pkx_source.as_str())?
            };
            let pkx_record_name = Self::pkx_record_name(domain);
            sqlx::query(
                "INSERT INTO user_domain_bindings
                    (domain, owner, state, pkx, pkx_record_name, verified_at, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, ?6)
                 ON CONFLICT(domain) DO UPDATE SET
                    owner = excluded.owner,
                    state = excluded.state,
                    pkx = excluded.pkx,
                    pkx_record_name = excluded.pkx_record_name,
                    verified_at = excluded.verified_at,
                    updated_at = excluded.updated_at",
            )
            .bind(domain)
            .bind(username)
            .bind(DOMAIN_BINDING_ACTIVE)
            .bind(pkx.as_str())
            .bind(pkx_record_name.as_str())
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(|e| Self::db_err("upsert user_domain binding failed", e))?;
            sqlx::query(
                "INSERT OR IGNORE INTO user_domain_history (domain, owner, created_at)
                 VALUES (?1, ?2, ?3)",
            )
            .bind(domain)
            .bind(username)
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(|e| Self::db_err("insert user_domain history failed", e))?;
        } else {
            sqlx::query(
                "UPDATE user_domain_bindings
                 SET state = ?1, updated_at = ?2
                 WHERE owner = ?3 AND state = ?4",
            )
            .bind(DOMAIN_BINDING_REVOKED)
            .bind(now)
            .bind(username)
            .bind(DOMAIN_BINDING_ACTIVE)
            .execute(&mut *tx)
            .await
            .map_err(|e| Self::db_err("revoke user_domain bindings failed", e))?;
        }

        sqlx::query("UPDATE users SET user_domain = ?1, updated_at = ?2 WHERE username = ?3")
            .bind(canonical_domain.as_deref())
            .bind(now)
            .bind(username)
            .execute(&mut *tx)
            .await
            .map_err(|e| Self::db_err("update user_domain failed", e))?;

        tx.commit()
            .await
            .map_err(|e| Self::db_err("commit transaction failed", e))?;
        Ok(())
    }

    async fn get_user_sn_ips(&self, username: &str) -> SnResult<Option<String>> {
        if let Some(zone_info) = self.get_zone_info(username).await? {
            if zone_info.sn_ips.is_some() {
                return Ok(zone_info.sn_ips);
            }
        }

        let row = sqlx::query("SELECT sn_ips FROM users WHERE username = ?1")
            .bind(username)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| Self::db_err("query user sn_ips failed", e))?;
        row.map(|row| {
            row.try_get("sn_ips")
                .map_err(|e| Self::db_err("read sn_ips failed", e))
        })
        .transpose()
    }

    async fn get_v2_auth(&self, username: &str) -> SnResult<Option<SnV2AuthInfo>> {
        let row = sqlx::query(
            "SELECT username, password_hash, password_salt, password_algo,
                    created_at, updated_at, last_login_at
             FROM user_auth_v2 WHERE username = ?1",
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| Self::db_err("query v2 auth failed", e))?;

        row.map(|row| {
            let created_at: i64 = row
                .try_get("created_at")
                .map_err(|e| Self::db_err("read created_at failed", e))?;
            let updated_at: i64 = row
                .try_get("updated_at")
                .map_err(|e| Self::db_err("read updated_at failed", e))?;
            let last_login_at: Option<i64> = row
                .try_get("last_login_at")
                .map_err(|e| Self::db_err("read last_login_at failed", e))?;
            Ok(SnV2AuthInfo {
                username: row
                    .try_get("username")
                    .map_err(|e| Self::db_err("read username failed", e))?,
                password_hash: row
                    .try_get("password_hash")
                    .map_err(|e| Self::db_err("read password_hash failed", e))?,
                password_salt: row
                    .try_get("password_salt")
                    .map_err(|e| Self::db_err("read password_salt failed", e))?,
                password_algo: row
                    .try_get("password_algo")
                    .map_err(|e| Self::db_err("read password_algo failed", e))?,
                created_at: Self::i64_to_u64(created_at),
                updated_at: Self::i64_to_u64(updated_at),
                last_login_at: Self::opt_i64_to_u64(last_login_at),
            })
        })
        .transpose()
    }

    async fn update_v2_last_login(&self, username: &str, last_login_at: u64) -> SnResult<()> {
        let last_login_at = last_login_at as i64;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| Self::db_err("begin transaction failed", e))?;
        sqlx::query(
            "UPDATE user_auth_v2
             SET last_login_at = ?1, updated_at = ?1
             WHERE username = ?2",
        )
        .bind(last_login_at)
        .bind(username)
        .execute(&mut *tx)
        .await
        .map_err(|e| Self::db_err("update v2 last login failed", e))?;
        sqlx::query(
            "UPDATE users
             SET last_login_at = ?1, updated_at = ?1
             WHERE username = ?2",
        )
        .bind(last_login_at)
        .bind(username)
        .execute(&mut *tx)
        .await
        .map_err(|e| Self::db_err("update user last login failed", e))?;
        tx.commit()
            .await
            .map_err(|e| Self::db_err("commit transaction failed", e))?;
        Ok(())
    }

    async fn create_pkx_binding(
        &self,
        username: &str,
        domain: &str,
    ) -> SnResult<PkxBindingChallenge> {
        let canonical_domain = Self::canonical_user_domain(domain)
            .ok_or_else(|| Self::invalid_input("domain is empty"))?;
        let _locker =
            async_named_locker::Locker::get_locker(Self::USER_DOMAIN_BINDING_LOCK.to_string())
                .await;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| Self::db_err("begin transaction failed", e))?;

        let user =
            sqlx::query("SELECT state, public_key, owner_key_ref FROM users WHERE username = ?1")
                .bind(username)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|e| Self::db_err("query user failed", e))?
                .ok_or_else(|| sn_err!(SnErrorCode::NotFound, "user not found: {}", username))?;
        let state: Option<String> = user
            .try_get("state")
            .map_err(|e| Self::db_err("read state failed", e))?;
        if !UserState::from_str(state.as_deref()).is_active() {
            return Err(sn_err!(
                SnErrorCode::Blocked,
                "user is not active: {}",
                username
            ));
        }
        let owner_key_ref: Option<String> = user
            .try_get("owner_key_ref")
            .map_err(|e| Self::db_err("read owner_key_ref failed", e))?;
        let public_key: Option<String> = user
            .try_get("public_key")
            .map_err(|e| Self::db_err("read public_key failed", e))?;
        let pkx_source = owner_key_ref
            .filter(|value| !value.trim().is_empty())
            .or_else(|| public_key.filter(|value| !value.trim().is_empty()))
            .unwrap_or_else(|| format!("sn-user:{}", username));

        Self::check_domain_conflicts_tx(&mut tx, username, canonical_domain.as_str()).await?;

        if let Some(existing) =
            sqlx::query("SELECT owner FROM user_domain_bindings WHERE domain = ?1")
                .bind(canonical_domain.as_str())
                .fetch_optional(&mut *tx)
                .await
                .map_err(|e| Self::db_err("query user_domain binding failed", e))?
        {
            let owner: String = existing
                .try_get("owner")
                .map_err(|e| Self::db_err("read binding owner failed", e))?;
            if owner != username {
                return Err(sn_err!(
                    SnErrorCode::Conflict,
                    "user_domain {} is owned by {}",
                    canonical_domain,
                    owner
                ));
            }
        }

        let now = Self::now_secs() as i64;
        let pkx = Self::pkx_value(pkx_source.as_str())?;
        let pkx_record_name = Self::pkx_record_name(canonical_domain.as_str());
        sqlx::query(
            "INSERT INTO user_domain_bindings
                (domain, owner, state, pkx, pkx_record_name, verified_at, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6, ?6)
             ON CONFLICT(domain) DO UPDATE SET
                state = excluded.state,
                pkx = excluded.pkx,
                pkx_record_name = excluded.pkx_record_name,
                verified_at = NULL,
                updated_at = excluded.updated_at",
        )
        .bind(canonical_domain.as_str())
        .bind(username)
        .bind(DOMAIN_BINDING_PENDING_PKX)
        .bind(pkx.as_str())
        .bind(pkx_record_name.as_str())
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|e| Self::db_err("upsert user_domain binding failed", e))?;

        tx.commit()
            .await
            .map_err(|e| Self::db_err("commit transaction failed", e))?;

        Ok(PkxBindingChallenge {
            username: username.to_string(),
            domain: canonical_domain,
            pkx,
            pkx_record_name,
            state: DOMAIN_BINDING_PENDING_PKX.to_string(),
            created_at: now as u64,
            updated_at: now as u64,
        })
    }

    async fn verify_pkx_binding(
        &self,
        username: &str,
        domain: &str,
        txt_records: &[String],
    ) -> SnResult<DomainBinding> {
        let canonical_domain = Self::canonical_user_domain(domain)
            .ok_or_else(|| Self::invalid_input("domain is empty"))?;
        let _locker =
            async_named_locker::Locker::get_locker(Self::USER_DOMAIN_BINDING_LOCK.to_string())
                .await;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| Self::db_err("begin transaction failed", e))?;

        let binding = sqlx::query(
            "SELECT owner, state, pkx, pkx_record_name
             FROM user_domain_bindings WHERE domain = ?1",
        )
        .bind(canonical_domain.as_str())
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| Self::db_err("query user_domain binding failed", e))?
        .ok_or_else(|| {
            sn_err!(
                SnErrorCode::NotFound,
                "user_domain binding not found: {}",
                canonical_domain
            )
        })?;

        let owner: String = binding
            .try_get("owner")
            .map_err(|e| Self::db_err("read binding owner failed", e))?;
        if owner != username {
            return Err(sn_err!(
                SnErrorCode::Conflict,
                "user_domain {} is owned by {}",
                canonical_domain,
                owner
            ));
        }
        let state: String = binding
            .try_get("state")
            .map_err(|e| Self::db_err("read binding state failed", e))?;
        if state != DOMAIN_BINDING_PENDING_PKX && state != DOMAIN_BINDING_ACTIVE {
            return Err(sn_err!(
                SnErrorCode::Blocked,
                "user_domain {} is not pending PKX",
                canonical_domain
            ));
        }
        let pkx: String = binding
            .try_get("pkx")
            .map_err(|e| Self::db_err("read binding pkx failed", e))?;
        if !txt_records
            .iter()
            .any(|txt| Self::txt_matches_pkx(txt.as_str(), pkx.as_str()))
        {
            return Err(sn_err!(
                SnErrorCode::InvalidInput,
                "PKX TXT record does not match expected value for {}",
                canonical_domain
            ));
        }
        Self::check_domain_conflicts_tx(&mut tx, username, canonical_domain.as_str()).await?;

        let now = Self::now_secs() as i64;
        sqlx::query(
            "UPDATE user_domain_bindings
             SET state = ?1, verified_at = ?2, updated_at = ?2
             WHERE domain = ?3 AND owner = ?4",
        )
        .bind(DOMAIN_BINDING_ACTIVE)
        .bind(now)
        .bind(canonical_domain.as_str())
        .bind(username)
        .execute(&mut *tx)
        .await
        .map_err(|e| Self::db_err("activate user_domain binding failed", e))?;

        sqlx::query("UPDATE users SET user_domain = ?1, updated_at = ?2 WHERE username = ?3")
            .bind(canonical_domain.as_str())
            .bind(now)
            .bind(username)
            .execute(&mut *tx)
            .await
            .map_err(|e| Self::db_err("update user_domain failed", e))?;

        sqlx::query(
            "INSERT OR IGNORE INTO user_domain_history (domain, owner, created_at)
             VALUES (?1, ?2, ?3)",
        )
        .bind(canonical_domain.as_str())
        .bind(username)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|e| Self::db_err("insert user_domain history failed", e))?;

        tx.commit()
            .await
            .map_err(|e| Self::db_err("commit transaction failed", e))?;

        Ok(DomainBinding {
            username: username.to_string(),
            domain: canonical_domain,
            pkx,
            pkx_record_name: binding
                .try_get("pkx_record_name")
                .map_err(|e| Self::db_err("read binding pkx_record_name failed", e))?,
            verified_at: now as u64,
        })
    }

    async fn unbind_user_domain(&self, username: &str, domain: &str) -> SnResult<()> {
        let canonical_domain = Self::canonical_user_domain(domain)
            .ok_or_else(|| Self::invalid_input("domain is empty"))?;
        let _locker =
            async_named_locker::Locker::get_locker(Self::USER_DOMAIN_BINDING_LOCK.to_string())
                .await;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| Self::db_err("begin transaction failed", e))?;
        let now = Self::now_secs() as i64;
        sqlx::query(
            "UPDATE user_domain_bindings
             SET state = ?1, updated_at = ?2
             WHERE domain = ?3 AND owner = ?4",
        )
        .bind(DOMAIN_BINDING_REVOKED)
        .bind(now)
        .bind(canonical_domain.as_str())
        .bind(username)
        .execute(&mut *tx)
        .await
        .map_err(|e| Self::db_err("revoke user_domain binding failed", e))?;
        sqlx::query(
            "UPDATE users
             SET user_domain = NULL, updated_at = ?1
             WHERE username = ?2 AND user_domain = ?3",
        )
        .bind(now)
        .bind(username)
        .bind(canonical_domain.as_str())
        .execute(&mut *tx)
        .await
        .map_err(|e| Self::db_err("clear user_domain failed", e))?;
        tx.commit()
            .await
            .map_err(|e| Self::db_err("commit transaction failed", e))?;
        Ok(())
    }

    async fn get_zone_info(&self, username: &str) -> SnResult<Option<ZoneInfo>> {
        let row = sqlx::query(
            "SELECT username, bns_name, zone, relay_sn, self_cert, cert_checked_at,
                    cert_expires_at, sn_ips, source_version, updated_at
             FROM zone_info WHERE username = ?1",
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| Self::db_err("query zone_info failed", e))?;
        if let Some(row) = row.as_ref() {
            return Self::zone_info_from_row(row).map(Some);
        }

        let Some(user) = self.get_user_info(username).await? else {
            return Ok(Some(ZoneInfo::default_for(username)));
        };

        let mut zone_info = ZoneInfo::default_for(username);
        zone_info.zone = if user.zone_config.trim().is_empty() {
            None
        } else {
            Some(user.zone_config)
        };
        zone_info.self_cert = user.self_cert;
        zone_info.sn_ips = user.sn_ips;
        Ok(Some(zone_info))
    }

    async fn update_zone_info(&self, username: &str, patch: ZoneInfoPatch) -> SnResult<()> {
        let mut current = self
            .get_zone_info(username)
            .await?
            .unwrap_or_else(|| ZoneInfo::default_for(username));
        if let Some(value) = patch.bns_name {
            current.bns_name = value;
        }
        if let Some(value) = patch.zone {
            current.zone = Some(value);
        }
        if let Some(value) = patch.relay_sn {
            current.relay_sn = Some(value);
        }
        if let Some(value) = patch.self_cert {
            current.self_cert = value;
        }
        if let Some(value) = patch.cert_checked_at {
            current.cert_checked_at = Some(value);
        }
        if let Some(value) = patch.cert_expires_at {
            current.cert_expires_at = Some(value);
        }
        if let Some(value) = patch.sn_ips {
            current.sn_ips = Some(value);
        }
        if let Some(value) = patch.source_version {
            current.source_version = Some(value);
        }
        current.updated_at = Self::now_secs();

        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| Self::db_err("begin transaction failed", e))?;
        sqlx::query(
            "INSERT INTO zone_info
                (username, bns_name, zone, relay_sn, self_cert, cert_checked_at,
                 cert_expires_at, sn_ips, source_version, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(username) DO UPDATE SET
                bns_name = excluded.bns_name,
                zone = excluded.zone,
                relay_sn = excluded.relay_sn,
                self_cert = excluded.self_cert,
                cert_checked_at = excluded.cert_checked_at,
                cert_expires_at = excluded.cert_expires_at,
                sn_ips = excluded.sn_ips,
                source_version = excluded.source_version,
                updated_at = excluded.updated_at",
        )
        .bind(username)
        .bind(current.bns_name.as_str())
        .bind(current.zone.as_deref())
        .bind(current.relay_sn.as_deref())
        .bind(if current.self_cert { 1_i64 } else { 0_i64 })
        .bind(current.cert_checked_at.map(|v| v as i64))
        .bind(current.cert_expires_at.map(|v| v as i64))
        .bind(current.sn_ips.as_deref())
        .bind(current.source_version.as_deref())
        .bind(current.updated_at as i64)
        .execute(&mut *tx)
        .await
        .map_err(|e| Self::db_err("upsert zone_info failed", e))?;

        sqlx::query(
            "UPDATE users
             SET zone_config = COALESCE(?1, zone_config),
                 self_cert = ?2,
                 sn_ips = ?3,
                 updated_at = ?4
             WHERE username = ?5",
        )
        .bind(current.zone.as_deref())
        .bind(if current.self_cert { 1_i64 } else { 0_i64 })
        .bind(current.sn_ips.as_deref())
        .bind(current.updated_at as i64)
        .bind(username)
        .execute(&mut *tx)
        .await
        .map_err(|e| Self::db_err("update user zone cache failed", e))?;

        tx.commit()
            .await
            .map_err(|e| Self::db_err("commit transaction failed", e))?;
        Ok(())
    }

    async fn update_zone_relay_sn(
        &self,
        zone: &str,
        relay_sn: &str,
        source_version: Option<&str>,
    ) -> SnResult<bool> {
        Self::check_non_empty(zone, "zone")?;
        Self::check_non_empty(relay_sn, "relay_sn")?;
        let now = Self::now_secs();
        let result = sqlx::query(
            "UPDATE zone_info
             SET relay_sn = ?1,
                 source_version = COALESCE(?2, source_version),
                 updated_at = ?3
             WHERE zone = ?4 OR bns_name = ?4 OR username = ?4",
        )
        .bind(relay_sn)
        .bind(source_version)
        .bind(now as i64)
        .bind(zone)
        .execute(&self.pool)
        .await
        .map_err(|e| Self::db_err("update zone relay_sn failed", e))?;

        if result.rows_affected() > 0 {
            return Ok(true);
        }

        let result = sqlx::query(
            "INSERT INTO zone_info
                (username, bns_name, zone, relay_sn, self_cert, cert_checked_at,
                 cert_expires_at, sn_ips, source_version, updated_at)
             VALUES (?1, ?1, NULL, ?2, 0, NULL, NULL, NULL, ?3, ?4)
             ON CONFLICT(username) DO UPDATE SET
                relay_sn = excluded.relay_sn,
                source_version = COALESCE(excluded.source_version, zone_info.source_version),
                updated_at = excluded.updated_at",
        )
        .bind(zone)
        .bind(relay_sn)
        .bind(source_version)
        .bind(now as i64)
        .execute(&self.pool)
        .await
        .map_err(|e| Self::db_err("insert zone relay_sn cache failed", e))?;

        Ok(result.rows_affected() > 0)
    }

    async fn create_account_session(
        &self,
        session_id: &str,
        username: &str,
        token_aud: &str,
        issued_at: u64,
        expires_at: u64,
    ) -> SnResult<()> {
        sqlx::query(
            "INSERT INTO account_sessions
                (session_id, username, token_aud, state, issued_at, expires_at, revoked_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL)",
        )
        .bind(session_id)
        .bind(username)
        .bind(token_aud)
        .bind(SESSION_ACTIVE)
        .bind(issued_at as i64)
        .bind(expires_at as i64)
        .execute(&self.pool)
        .await
        .map_err(|e| Self::db_err("insert account session failed", e))?;
        Ok(())
    }

    async fn revoke_account_session(&self, session_id: &str, revoked_at: u64) -> SnResult<()> {
        sqlx::query(
            "UPDATE account_sessions
             SET state = ?1, revoked_at = ?2
             WHERE session_id = ?3",
        )
        .bind(SESSION_REVOKED)
        .bind(revoked_at as i64)
        .bind(session_id)
        .execute(&self.pool)
        .await
        .map_err(|e| Self::db_err("revoke account session failed", e))?;
        Ok(())
    }

    async fn revoke_user_sessions(&self, username: &str, revoked_at: u64) -> SnResult<u64> {
        let result = sqlx::query(
            "UPDATE account_sessions
             SET state = ?1, revoked_at = ?2
             WHERE username = ?3 AND state != ?1",
        )
        .bind(SESSION_REVOKED)
        .bind(revoked_at as i64)
        .bind(username)
        .execute(&self.pool)
        .await
        .map_err(|e| Self::db_err("revoke user sessions failed", e))?;
        Ok(result.rows_affected())
    }

    async fn get_account_session(&self, session_id: &str) -> SnResult<Option<AccountSession>> {
        let row = sqlx::query(
            "SELECT session_id, username, token_aud, state, issued_at, expires_at, revoked_at
             FROM account_sessions WHERE session_id = ?1",
        )
        .bind(session_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| Self::db_err("query account session failed", e))?;
        row.map(|row| {
            let issued_at: i64 = row
                .try_get("issued_at")
                .map_err(|e| Self::db_err("read issued_at failed", e))?;
            let expires_at: i64 = row
                .try_get("expires_at")
                .map_err(|e| Self::db_err("read expires_at failed", e))?;
            let revoked_at: Option<i64> = row
                .try_get("revoked_at")
                .map_err(|e| Self::db_err("read revoked_at failed", e))?;
            Ok(AccountSession {
                session_id: row
                    .try_get("session_id")
                    .map_err(|e| Self::db_err("read session_id failed", e))?,
                username: row
                    .try_get("username")
                    .map_err(|e| Self::db_err("read username failed", e))?,
                token_aud: row
                    .try_get("token_aud")
                    .map_err(|e| Self::db_err("read token_aud failed", e))?,
                state: row
                    .try_get("state")
                    .map_err(|e| Self::db_err("read state failed", e))?,
                issued_at: Self::i64_to_u64(issued_at),
                expires_at: Self::i64_to_u64(expires_at),
                revoked_at: Self::opt_i64_to_u64(revoked_at),
            })
        })
        .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn new_test_db() -> SnResult<(tempfile::TempDir, SqliteSnAuthDB)> {
        let tmp_dir = tempfile::tempdir()
            .map_err(|e| sn_err!(SnErrorCode::DBError, "create temp dir failed: {}", e))?;
        let db_path = tmp_dir.path().join("sn_auth.sqlite3");
        let db = SqliteSnAuthDB::new_by_path(db_path.to_string_lossy().as_ref()).await?;
        db.initialize_database().await?;
        Ok((tmp_dir, db))
    }

    #[tokio::test]
    async fn test_activation_code_and_v2_auth_flow() -> SnResult<()> {
        let (_tmp_dir, db) = new_test_db().await?;
        let codes = db.generate_activation_codes(3).await?;
        assert_eq!(codes.len(), 3);
        assert!(codes.iter().all(|code| code.len() == ACTIVATION_CODE_LEN));

        let active_code = codes[0].as_str();
        assert!(db.check_active_code(active_code).await?);
        assert!(
            db.register_user_v2(active_code, "alice", "hash", "salt", "pbkdf2")
                .await?
        );
        assert!(!db.check_active_code(active_code).await?);
        assert!(
            !db.register_user_v2(active_code, "bob", "hash2", "salt2", "pbkdf2")
                .await?
        );
        assert!(db.is_user_exist("alice").await?);

        let user = db.get_user_info("alice").await?.unwrap();
        assert_eq!(user.username.as_deref(), Some("alice"));
        assert_eq!(user.activation_code.as_deref(), Some(active_code));
        assert_eq!(user.public_key, "");
        assert!(!user.self_cert);

        let auth = db.get_v2_auth("alice").await?.unwrap();
        assert_eq!(auth.username, "alice");
        assert_eq!(auth.password_hash, "hash");
        assert_eq!(auth.password_salt, "salt");
        assert_eq!(auth.password_algo, "pbkdf2");
        assert!(auth.last_login_at.is_none());

        db.update_v2_last_login("alice", 12345).await?;
        let auth = db.get_v2_auth("alice").await?.unwrap();
        assert_eq!(auth.last_login_at, Some(12345));
        assert_eq!(auth.updated_at, 12345);

        let zone = db.get_zone_info("alice").await?.unwrap();
        assert_eq!(zone.username, "alice");
        assert_eq!(zone.bns_name, "alice");
        assert!(!zone.self_cert);

        Ok(())
    }

    #[tokio::test]
    async fn test_pkx_binding_flow_and_domain_conflicts() -> SnResult<()> {
        let (_tmp_dir, db) = new_test_db().await?;
        db.insert_activation_code("alice-code").await?;
        db.insert_activation_code("bob-code").await?;
        assert!(
            db.register_user_v2("alice-code", "alice", "hash", "salt", "pbkdf2")
                .await?
        );
        assert!(
            db.register_user_v2("bob-code", "bob", "hash", "salt", "pbkdf2")
                .await?
        );

        sqlx::query("UPDATE users SET public_key = ?1 WHERE username = 'alice'")
            .bind("alice-owner-key")
            .execute(&db.pool)
            .await
            .map_err(|e| SqliteSnAuthDB::db_err("bind test public key failed", e))?;
        sqlx::query("UPDATE users SET public_key = ?1 WHERE username = 'bob'")
            .bind("bob-owner-key")
            .execute(&db.pool)
            .await
            .map_err(|e| SqliteSnAuthDB::db_err("bind test public key failed", e))?;

        let challenge = db.create_pkx_binding("alice", "*.Example.COM.").await?;
        assert_eq!(challenge.domain, "example.com");
        assert_eq!(challenge.pkx_record_name, "_pkx.example.com");
        assert_eq!(challenge.pkx, "PKX(alice-owner-key)");

        assert!(db
            .verify_pkx_binding("alice", "example.com", &[String::from("wrong")])
            .await
            .is_err());
        let binding = db
            .verify_pkx_binding("alice", "example.com", &[challenge.pkx.clone()])
            .await?;
        assert_eq!(binding.domain, "example.com");
        assert_eq!(
            db.get_user_by_domain("api.example.com")
                .await?
                .unwrap()
                .username
                .as_deref(),
            Some("alice")
        );

        let err = db.create_pkx_binding("bob", "api.example.com").await;
        assert!(err.is_err());

        db.unbind_user_domain("alice", "example.com").await?;
        assert!(db.get_user_by_domain("api.example.com").await?.is_none());

        Ok(())
    }

    #[tokio::test]
    async fn test_zone_info_patch_and_session_revocation() -> SnResult<()> {
        let (_tmp_dir, db) = new_test_db().await?;
        db.insert_activation_code("zone-code").await?;
        assert!(
            db.register_user_v2("zone-code", "alice", "hash", "salt", "pbkdf2")
                .await?
        );

        db.update_zone_info(
            "alice",
            ZoneInfoPatch {
                zone: Some("did:zone:alice".to_string()),
                relay_sn: Some("relay-a".to_string()),
                self_cert: Some(true),
                cert_checked_at: Some(10),
                cert_expires_at: Some(20),
                sn_ips: Some("[\"1.2.3.4\"]".to_string()),
                source_version: Some("v1".to_string()),
                ..Default::default()
            },
        )
        .await?;
        let zone = db.get_zone_info("alice").await?.unwrap();
        assert_eq!(zone.zone.as_deref(), Some("did:zone:alice"));
        assert_eq!(zone.relay_sn.as_deref(), Some("relay-a"));
        assert!(zone.self_cert);
        assert_eq!(zone.sn_ips.as_deref(), Some("[\"1.2.3.4\"]"));
        assert_eq!(db.get_user_info("alice").await?.unwrap().self_cert, true);

        db.create_account_session("refresh-1", "alice", "sn-v2-refresh", 1, 100)
            .await?;
        let session = db.get_account_session("refresh-1").await?.unwrap();
        assert_eq!(session.state, SESSION_ACTIVE);
        db.revoke_account_session("refresh-1", 50).await?;
        let session = db.get_account_session("refresh-1").await?.unwrap();
        assert_eq!(session.state, SESSION_REVOKED);
        assert_eq!(session.revoked_at, Some(50));

        db.create_account_session("refresh-2", "alice", "sn-v2-refresh", 51, 100)
            .await?;
        assert_eq!(db.revoke_user_sessions("alice", 60).await?, 1);
        let session = db.get_account_session("refresh-2").await?.unwrap();
        assert_eq!(session.state, SESSION_REVOKED);

        Ok(())
    }

    #[tokio::test]
    async fn test_clear_state_by_active_code_resets_auth_and_legacy_related_rows() -> SnResult<()> {
        let (_tmp_dir, db) = new_test_db().await?;
        db.insert_activation_code("clear-me").await?;
        assert!(
            db.register_user_v2("clear-me", "alice", "hash", "salt", "pbkdf2")
                .await?
        );

        sqlx::query("CREATE TABLE devices (owner TEXT, device_name TEXT, did TEXT PRIMARY KEY, ip TEXT, description TEXT, mini_config_jwt TEXT, created_at INTEGER, updated_at INTEGER)")
            .execute(&db.pool)
            .await
            .map_err(|e| SqliteSnAuthDB::db_err("create devices failed", e))?;
        sqlx::query("CREATE TABLE user_dns_records (id INTEGER PRIMARY KEY AUTOINCREMENT, owner TEXT, domain TEXT, record_type TEXT, record TEXT, ttl INTEGER, created_at INTEGER, updated_at INTEGER)")
            .execute(&db.pool)
            .await
            .map_err(|e| SqliteSnAuthDB::db_err("create user_dns_records failed", e))?;
        sqlx::query("CREATE TABLE did_documents (id INTEGER PRIMARY KEY AUTOINCREMENT, obj_id TEXT, owner_user TEXT, obj_name TEXT, did_document TEXT, doc_type TEXT, update_time INTEGER)")
            .execute(&db.pool)
            .await
            .map_err(|e| SqliteSnAuthDB::db_err("create did_documents failed", e))?;
        sqlx::query("INSERT INTO devices (owner, device_name, did, ip, description, mini_config_jwt, created_at, updated_at) VALUES ('alice', 'ood1', 'did:dev:1', '', '', '', 1, 1)")
            .execute(&db.pool)
            .await
            .map_err(|e| SqliteSnAuthDB::db_err("insert device failed", e))?;
        sqlx::query("INSERT INTO user_dns_records (owner, domain, record_type, record, ttl, created_at, updated_at) VALUES ('alice', 'alice.example.com', 'A', '127.0.0.1', 60, 1, 1)")
            .execute(&db.pool)
            .await
            .map_err(|e| SqliteSnAuthDB::db_err("insert dns record failed", e))?;
        sqlx::query("INSERT INTO did_documents (obj_id, owner_user, obj_name, did_document, doc_type, update_time) VALUES ('obj1', 'alice', 'zone', '{}', 'zone', 1)")
            .execute(&db.pool)
            .await
            .map_err(|e| SqliteSnAuthDB::db_err("insert did document failed", e))?;

        let result = db.clear_state_by_active_code("clear-me").await?;
        assert_eq!(result.deleted_users, 1);
        assert_eq!(result.deleted_devices, 1);
        assert_eq!(result.deleted_domain_records, 1);
        assert_eq!(result.deleted_did_documents, 1);
        assert!(result.activation_code_reset);
        assert!(db.check_active_code("clear-me").await?);
        assert!(!db.is_user_exist("alice").await?);
        assert!(db.get_v2_auth("alice").await?.is_none());
        let zone = db.get_zone_info("alice").await?.unwrap();
        assert_eq!(zone.username, "alice");
        assert_eq!(zone.bns_name, "alice");
        assert!(!zone.self_cert);
        assert!(zone.zone.is_none());

        Ok(())
    }

    // ---- §3.1 账号与凭证（DB 层）----

    /// 激活码：生成 32 位、charset 受限、唯一；`check_active_code` 区分存在/已用/未知；
    /// 注册后事务内置 `used=1`，二次使用被拒。
    #[tokio::test]
    async fn test_activation_code_generation_and_single_use() -> SnResult<()> {
        let (_tmp_dir, db) = new_test_db().await?;

        let codes = db.generate_activation_codes(8).await?;
        assert_eq!(codes.len(), 8);
        for code in &codes {
            assert_eq!(code.len(), ACTIVATION_CODE_LEN);
            assert!(code.bytes().all(|b| ACTIVATION_CODE_CHARS.contains(&b)));
        }
        let unique: std::collections::HashSet<_> = codes.iter().cloned().collect();
        assert_eq!(unique.len(), codes.len(), "generated codes must be unique");

        // 未知激活码 → false（既非存在也非未用）。
        assert!(!db.check_active_code("does-not-exist").await?);

        let code = codes[0].as_str();
        assert!(db.check_active_code(code).await?);
        assert!(
            db.register_user_v2(code, "alice", "h", "s", "pbkdf2")
                .await?
        );

        // 注册后事务内 used=1。
        let used: i64 = sqlx::query_scalar("SELECT used FROM activation_codes WHERE code = ?1")
            .bind(code)
            .fetch_one(&db.pool)
            .await
            .map_err(|e| SqliteSnAuthDB::db_err("read used flag failed", e))?;
        assert_eq!(used, 1);
        assert!(!db.check_active_code(code).await?);

        // 二次使用被拒（既不创建用户，也不报错，按契约返回 false）。
        assert!(!db.register_user_v2(code, "bob", "h", "s", "pbkdf2").await?);
        assert!(!db.is_user_exist("bob").await?);

        Ok(())
    }

    /// `register_user_v2` 事务性：`users` + `user_auth_v2` + `zone_info` 一致写入，激活码标记 used。
    #[tokio::test]
    async fn test_register_user_v2_writes_consistent_rows() -> SnResult<()> {
        let (_tmp_dir, db) = new_test_db().await?;
        db.insert_activation_code("code-1").await?;
        assert!(
            db.register_user_v2("code-1", "alice", "hash", "salt", "pbkdf2")
                .await?
        );

        // users 行。
        let user = db.get_user_info("alice").await?.unwrap();
        assert_eq!(user.username.as_deref(), Some("alice"));
        assert_eq!(user.activation_code.as_deref(), Some("code-1"));
        assert!(matches!(user.state, UserState::Active));

        // user_auth_v2 行。
        let auth = db.get_v2_auth("alice").await?.unwrap();
        assert_eq!(auth.username, "alice");
        assert_eq!(auth.password_hash, "hash");
        assert_eq!(auth.password_salt, "salt");
        assert_eq!(auth.password_algo, "pbkdf2");

        // zone_info 行（bns_name 默认为 username）。
        let zone = db.get_zone_info("alice").await?.unwrap();
        assert_eq!(zone.username, "alice");
        assert_eq!(zone.bns_name, "alice");

        // 同名二次注册（换激活码）被拒，且不破坏已有行。
        db.insert_activation_code("code-2").await?;
        assert!(
            !db.register_user_v2("code-2", "alice", "h2", "s2", "pbkdf2")
                .await?
        );
        // code-2 未被消费。
        assert!(db.check_active_code("code-2").await?);
        let auth = db.get_v2_auth("alice").await?.unwrap();
        assert_eq!(
            auth.password_hash, "hash",
            "existing auth must be untouched"
        );

        Ok(())
    }

    /// 命名锁下并发注册：N 个任务用同一激活码注册不同用户名，只允许一个成功。
    #[tokio::test]
    async fn test_register_user_v2_concurrent_single_success() -> SnResult<()> {
        let (_tmp_dir, db) = new_test_db().await?;
        db.insert_activation_code("shared-code").await?;
        let db = Arc::new(db);

        let mut handles = Vec::new();
        for i in 0..8 {
            let db = db.clone();
            handles.push(tokio::spawn(async move {
                db.register_user_v2(
                    "shared-code",
                    &format!("user-{i}"),
                    "hash",
                    "salt",
                    "pbkdf2",
                )
                .await
            }));
        }

        let mut success = 0;
        for handle in handles {
            if handle.await.expect("task panicked")? {
                success += 1;
            }
        }
        assert_eq!(success, 1, "exactly one concurrent registration may win");

        // 激活码已消费，且只创建了一个用户。
        assert!(!db.check_active_code("shared-code").await?);
        let user_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
            .fetch_one(&db.pool)
            .await
            .map_err(|e| SqliteSnAuthDB::db_err("count users failed", e))?;
        assert_eq!(user_count, 1);

        Ok(())
    }

    /// 密码：PBKDF2-sha256-100000、16B salt(hex)、32B hash(hex)；`verify_password` 正确/错误；
    /// 服务端不存明文；不支持的算法被拒。
    #[tokio::test]
    async fn test_password_pbkdf2_hash_and_verify() -> SnResult<()> {
        use crate::sn_v2_auth::{hash_password, verify_password, PASSWORD_ALGO};

        let (hash, salt) = hash_password("hunter2")
            .map_err(|e| sn_err!(SnErrorCode::Failed, "hash failed: {:?}", e))?;
        // 16 字节 salt → 32 hex 字符；32 字节 hash → 64 hex 字符。
        assert_eq!(salt.len(), 32);
        assert_eq!(hash.len(), 64);
        assert_eq!(hex::decode(&salt).unwrap().len(), 16);
        assert_eq!(hex::decode(&hash).unwrap().len(), 32);
        // 不存明文。
        assert_ne!(hash, "hunter2");

        // 同一密码 + 不同随机 salt → 不同 hash。
        let (hash2, salt2) = hash_password("hunter2")
            .map_err(|e| sn_err!(SnErrorCode::Failed, "hash failed: {:?}", e))?;
        assert_ne!(salt, salt2);
        assert_ne!(hash, hash2);

        let auth = SnV2AuthInfo {
            username: "alice".to_string(),
            password_hash: hash,
            password_salt: salt,
            password_algo: PASSWORD_ALGO.to_string(),
            created_at: 0,
            updated_at: 0,
            last_login_at: None,
        };
        assert!(verify_password("hunter2", &auth).map_err(|e| sn_err!(
            SnErrorCode::Failed,
            "verify failed: {:?}",
            e
        ))?);
        assert!(!verify_password("wrong-pass", &auth).map_err(|e| sn_err!(
            SnErrorCode::Failed,
            "verify failed: {:?}",
            e
        ))?);

        // 不支持的算法 → 错误，而非 false。
        let mut bad = auth.clone();
        bad.password_algo = "plaintext".to_string();
        assert!(verify_password("hunter2", &bad).is_err());

        Ok(())
    }

    /// 用户状态机：`set_user_state` 写入 active/suspended/deleted/banned；
    /// 置非 active 时自动撤销该用户 session；active 不撤销。
    #[tokio::test]
    async fn test_set_user_state_revokes_sessions() -> SnResult<()> {
        let (_tmp_dir, db) = new_test_db().await?;
        db.insert_activation_code("state-code").await?;
        assert!(
            db.register_user_v2("state-code", "alice", "h", "s", "pbkdf2")
                .await?
        );

        // active → active：session 保留。
        db.create_account_session("sess-keep", "alice", "sn-v2-refresh", 1, 100)
            .await?;
        db.set_user_state("alice", UserState::Active).await?;
        assert_eq!(
            db.get_account_session("sess-keep").await?.unwrap().state,
            SESSION_ACTIVE
        );

        // 逐个非 active 状态：写库 + 撤销 session。
        for (state, label) in [
            (UserState::Suspended, "suspended"),
            (UserState::Deleted, "deleted"),
            (UserState::Banned, "banned"),
        ] {
            // 重新发一个活跃 session。
            let sid = format!("sess-{label}");
            db.create_account_session(&sid, "alice", "sn-v2-refresh", 1, 100)
                .await?;
            db.set_user_state("alice", state).await?;

            let stored: String =
                sqlx::query_scalar("SELECT state FROM users WHERE username = 'alice'")
                    .fetch_one(&db.pool)
                    .await
                    .map_err(|e| SqliteSnAuthDB::db_err("read user state failed", e))?;
            assert_eq!(stored, label);

            let session = db.get_account_session(&sid).await?.unwrap();
            assert_eq!(
                session.state, SESSION_REVOKED,
                "{label} must revoke session"
            );
            assert!(session.revoked_at.is_some());
        }

        Ok(())
    }

    // ---- §3.2 session（account_sessions）----

    /// session 生命周期：create/get/revoke/revoke_user_sessions 语义与计数。
    #[tokio::test]
    async fn test_account_session_lifecycle_and_counts() -> SnResult<()> {
        let (_tmp_dir, db) = new_test_db().await?;

        // 未知 session → None。
        assert!(db.get_account_session("missing").await?.is_none());

        db.create_account_session("a1", "alice", "sn-v2-refresh", 1, 100)
            .await?;
        db.create_account_session("a2", "alice", "sn-v2-refresh", 2, 100)
            .await?;
        db.create_account_session("b1", "bob", "sn-v2-refresh", 3, 100)
            .await?;

        let s = db.get_account_session("a1").await?.unwrap();
        assert_eq!(s.username, "alice");
        assert_eq!(s.token_aud, "sn-v2-refresh");
        assert_eq!(s.state, SESSION_ACTIVE);
        assert_eq!(s.issued_at, 1);
        assert_eq!(s.expires_at, 100);
        assert!(s.revoked_at.is_none());

        // 单条撤销。
        db.revoke_account_session("a1", 50).await?;
        let s = db.get_account_session("a1").await?.unwrap();
        assert_eq!(s.state, SESSION_REVOKED);
        assert_eq!(s.revoked_at, Some(50));

        // 批量撤销只命中 alice 的活跃 session（a1 已撤销，仅 a2 计入）。
        assert_eq!(db.revoke_user_sessions("alice", 60).await?, 1);
        assert_eq!(
            db.get_account_session("a2").await?.unwrap().state,
            SESSION_REVOKED
        );
        // bob 不受影响。
        assert_eq!(
            db.get_account_session("b1").await?.unwrap().state,
            SESSION_ACTIVE
        );

        // 再次批量撤销 alice：已无活跃 session → 0。
        assert_eq!(db.revoke_user_sessions("alice", 70).await?, 0);

        Ok(())
    }

    // ---- §3.3 user_domain + PKX proof ----

    /// `canonical_user_domain` / `pkx_record_name` / `pkx_value` / `txt_matches_pkx` helper 稳定性。
    #[test]
    fn test_user_domain_helpers_are_stable() {
        // 去 `*.` 前缀、小写、去尾点。
        assert_eq!(
            SqliteSnAuthDB::canonical_user_domain("*.Example.COM."),
            Some("example.com".to_string())
        );
        assert_eq!(
            SqliteSnAuthDB::canonical_user_domain("  API.Example.com  "),
            Some("api.example.com".to_string())
        );
        assert_eq!(
            SqliteSnAuthDB::canonical_user_domain("example.com"),
            Some("example.com".to_string())
        );
        // 空 / 仅点 / 仅通配 → None。
        assert_eq!(SqliteSnAuthDB::canonical_user_domain("   "), None);
        assert_eq!(SqliteSnAuthDB::canonical_user_domain("."), None);

        // 派生 helper 同输入恒等（无 nonce / exp）。
        assert_eq!(
            SqliteSnAuthDB::pkx_record_name("example.com"),
            "_pkx.example.com"
        );
        assert_eq!(
            SqliteSnAuthDB::pkx_value("owner-key").unwrap(),
            SqliteSnAuthDB::pkx_value("owner-key").unwrap()
        );
        assert_eq!(
            SqliteSnAuthDB::pkx_value("  owner-key  ").unwrap(),
            "PKX(owner-key)"
        );
        assert!(SqliteSnAuthDB::pkx_value("   ").is_err());

        // TXT 比较容忍包裹引号与首尾空白。
        assert!(SqliteSnAuthDB::txt_matches_pkx(
            "  \"PKX(owner-key)\"  ",
            "PKX(owner-key)"
        ));
        assert!(!SqliteSnAuthDB::txt_matches_pkx(
            "PKX(other)",
            "PKX(owner-key)"
        ));
    }

    /// PKX 状态机：create → pending、verify → active、unbind → revoked，history 保留。
    #[tokio::test]
    async fn test_pkx_binding_state_transitions_and_history() -> SnResult<()> {
        let (_tmp_dir, db) = new_test_db().await?;
        db.insert_activation_code("alice-code").await?;
        assert!(
            db.register_user_v2("alice-code", "alice", "h", "s", "pbkdf2")
                .await?
        );
        db.update_user_public_key("alice", "alice-owner-key")
            .await?;

        // create → pending_pkx，返回固定的 record name / pkx。
        let challenge = db.create_pkx_binding("alice", "Example.com.").await?;
        assert_eq!(challenge.domain, "example.com");
        assert_eq!(challenge.pkx_record_name, "_pkx.example.com");
        assert_eq!(challenge.pkx, "PKX(alice-owner-key)");
        assert_eq!(
            binding_state(&db, "example.com").await?,
            DOMAIN_BINDING_PENDING_PKX
        );
        // pending 未被 get_user_by_domain 命中。
        assert!(db.get_user_by_domain("example.com").await?.is_none());

        // 重新 create 幂等：record name / pkx 不变。
        let challenge2 = db.create_pkx_binding("alice", "example.com").await?;
        assert_eq!(challenge2.pkx, challenge.pkx);
        assert_eq!(challenge2.pkx_record_name, challenge.pkx_record_name);

        // verify TXT 匹配 → active。
        let binding = db
            .verify_pkx_binding("alice", "example.com", &[challenge.pkx.clone()])
            .await?;
        assert_eq!(binding.domain, "example.com");
        assert_eq!(
            binding_state(&db, "example.com").await?,
            DOMAIN_BINDING_ACTIVE
        );
        assert_eq!(
            db.get_user_by_domain("api.example.com")
                .await?
                .unwrap()
                .username
                .as_deref(),
            Some("alice")
        );

        // unbind → revoked，但 history 仍保留。
        db.unbind_user_domain("alice", "example.com").await?;
        assert_eq!(
            binding_state(&db, "example.com").await?,
            DOMAIN_BINDING_REVOKED
        );
        assert!(db.get_user_by_domain("api.example.com").await?.is_none());
        let history: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM user_domain_history WHERE domain = 'example.com' AND owner = 'alice'",
        )
        .fetch_one(&db.pool)
        .await
        .map_err(|e| SqliteSnAuthDB::db_err("count history failed", e))?;
        assert_eq!(history, 1, "history must be retained after unbind");

        Ok(())
    }

    /// 域名冲突：相同 / 祖先 / 子域名被他人历史绑定 → Conflict；本人则允许。
    #[tokio::test]
    async fn test_domain_conflict_rules() -> SnResult<()> {
        let (_tmp_dir, db) = new_test_db().await?;
        for (code, user) in [("a-code", "alice"), ("b-code", "bob")] {
            db.insert_activation_code(code).await?;
            assert!(db.register_user_v2(code, user, "h", "s", "pbkdf2").await?);
        }
        db.update_user_public_key("alice", "alice-key").await?;
        db.update_user_public_key("bob", "bob-key").await?;

        // alice 激活 example.com。
        db.create_pkx_binding("alice", "example.com").await?;
        db.verify_pkx_binding("alice", "example.com", &[String::from("PKX(alice-key)")])
            .await?;

        // bob：相同域名冲突。
        let err = db
            .create_pkx_binding("bob", "example.com")
            .await
            .unwrap_err();
        assert_eq!(err.code(), SnErrorCode::Conflict);
        // bob：子域名（descendant）冲突。
        let err = db
            .create_pkx_binding("bob", "api.example.com")
            .await
            .unwrap_err();
        assert_eq!(err.code(), SnErrorCode::Conflict);
        // bob：祖先域名（ancestor）冲突。
        let err = db.create_pkx_binding("bob", "com").await.unwrap_err();
        assert_eq!(err.code(), SnErrorCode::Conflict);

        // alice 本人的子域名允许（owner 相同被排除）。
        let challenge = db.create_pkx_binding("alice", "sub.example.com").await?;
        assert_eq!(challenge.domain, "sub.example.com");

        Ok(())
    }

    /// `get_user_by_domain`：active binding 最长匹配 + legacy `users.user_domain` 回退。
    #[tokio::test]
    async fn test_get_user_by_domain_longest_match_and_legacy_fallback() -> SnResult<()> {
        let (_tmp_dir, db) = new_test_db().await?;
        db.insert_activation_code("alice-code").await?;
        assert!(
            db.register_user_v2("alice-code", "alice", "h", "s", "pbkdf2")
                .await?
        );
        db.update_user_public_key("alice", "alice-key").await?;

        // alice 同时激活 example.com 与更具体的 sub.example.com。
        db.create_pkx_binding("alice", "example.com").await?;
        db.verify_pkx_binding("alice", "example.com", &[String::from("PKX(alice-key)")])
            .await?;
        db.create_pkx_binding("alice", "sub.example.com").await?;
        db.verify_pkx_binding(
            "alice",
            "sub.example.com",
            &[String::from("PKX(alice-key)")],
        )
        .await?;

        // host.sub.example.com → 命中最长的 sub.example.com binding（同样属 alice）。
        assert_eq!(
            db.get_user_by_domain("host.sub.example.com")
                .await?
                .unwrap()
                .username
                .as_deref(),
            Some("alice")
        );
        assert!(db.get_user_by_domain("unrelated.org").await?.is_none());

        // legacy 回退：bob 仅在 users.user_domain 留有遗留域名、无 binding 行。
        db.insert_activation_code("bob-code").await?;
        assert!(
            db.register_user_v2("bob-code", "bob", "h", "s", "pbkdf2")
                .await?
        );
        sqlx::query("UPDATE users SET user_domain = 'legacy.test' WHERE username = 'bob'")
            .execute(&db.pool)
            .await
            .map_err(|e| SqliteSnAuthDB::db_err("set legacy domain failed", e))?;
        assert_eq!(
            db.get_user_by_domain("host.legacy.test")
                .await?
                .unwrap()
                .username
                .as_deref(),
            Some("bob")
        );

        Ok(())
    }

    // ---- §3.4 zone_info ----

    /// `update_zone_info` patch 语义：只改传入字段，其余保留；users 缓存同步。
    #[tokio::test]
    async fn test_zone_info_patch_only_changes_given_fields() -> SnResult<()> {
        let (_tmp_dir, db) = new_test_db().await?;
        db.insert_activation_code("zone-code").await?;
        assert!(
            db.register_user_v2("zone-code", "alice", "h", "s", "pbkdf2")
                .await?
        );

        // 初始整体写入。
        db.update_zone_info(
            "alice",
            ZoneInfoPatch {
                zone: Some("did:zone:alice".to_string()),
                self_cert: Some(true),
                sn_ips: Some("[\"1.2.3.4\"]".to_string()),
                ..Default::default()
            },
        )
        .await?;

        // 仅 patch relay_sn，其余字段保留。
        db.update_zone_info(
            "alice",
            ZoneInfoPatch {
                relay_sn: Some("relay-a".to_string()),
                ..Default::default()
            },
        )
        .await?;
        let zone = db.get_zone_info("alice").await?.unwrap();
        assert_eq!(zone.relay_sn.as_deref(), Some("relay-a"));
        assert_eq!(zone.zone.as_deref(), Some("did:zone:alice"));
        assert!(zone.self_cert);
        assert_eq!(zone.sn_ips.as_deref(), Some("[\"1.2.3.4\"]"));
        // users 缓存同步。
        assert!(db.get_user_info("alice").await?.unwrap().self_cert);

        Ok(())
    }

    /// `get_zone_info` 在缺 zone_info 行时从 `users` 回退派生（backfill 分支）。
    #[tokio::test]
    async fn test_get_zone_info_backfills_from_users() -> SnResult<()> {
        let (_tmp_dir, db) = new_test_db().await?;
        db.insert_activation_code("zone-code").await?;
        assert!(
            db.register_user_v2("zone-code", "alice", "h", "s", "pbkdf2")
                .await?
        );

        // 删 zone_info 行，并在 users 上留下 zone_config / self_cert。
        sqlx::query("DELETE FROM zone_info WHERE username = 'alice'")
            .execute(&db.pool)
            .await
            .map_err(|e| SqliteSnAuthDB::db_err("delete zone_info failed", e))?;
        sqlx::query(
            "UPDATE users SET zone_config = 'did:zone:legacy', self_cert = 1 WHERE username = 'alice'",
        )
        .execute(&db.pool)
        .await
        .map_err(|e| SqliteSnAuthDB::db_err("update user cache failed", e))?;

        let zone = db.get_zone_info("alice").await?.unwrap();
        assert_eq!(zone.username, "alice");
        assert_eq!(zone.bns_name, "alice");
        assert_eq!(zone.zone.as_deref(), Some("did:zone:legacy"));
        assert!(zone.self_cert);

        // 完全未知用户 → 默认值（不报错）。
        let zone = db.get_zone_info("ghost").await?.unwrap();
        assert_eq!(zone.username, "ghost");
        assert!(zone.zone.is_none());
        assert!(!zone.self_cert);

        Ok(())
    }

    /// `update_zone_relay_sn`：按 zone/bns_name/username 命中写 relay_sn；缺行则插入；空参数被拒。
    #[tokio::test]
    async fn test_update_zone_relay_sn_paths() -> SnResult<()> {
        let (_tmp_dir, db) = new_test_db().await?;
        db.insert_activation_code("zone-code").await?;
        assert!(
            db.register_user_v2("zone-code", "alice", "h", "s", "pbkdf2")
                .await?
        );

        // 按 username/bns_name 命中既有行。
        assert!(
            db.update_zone_relay_sn("alice", "relay-a", Some("v2"))
                .await?
        );
        let zone = db.get_zone_info("alice").await?.unwrap();
        assert_eq!(zone.relay_sn.as_deref(), Some("relay-a"));
        assert_eq!(zone.source_version.as_deref(), Some("v2"));

        // 空 zone / 空 relay_sn → InvalidInput。
        assert_eq!(
            db.update_zone_relay_sn("", "relay-a", None)
                .await
                .unwrap_err()
                .code(),
            SnErrorCode::InvalidInput
        );
        assert_eq!(
            db.update_zone_relay_sn("alice", "  ", None)
                .await
                .unwrap_err()
                .code(),
            SnErrorCode::InvalidInput
        );

        // 缺行 → 插入新 zone_info 行。
        assert!(
            db.update_zone_relay_sn("ghost-zone", "relay-b", None)
                .await?
        );
        let zone = db.get_zone_info("ghost-zone").await?.unwrap();
        assert_eq!(zone.relay_sn.as_deref(), Some("relay-b"));

        Ok(())
    }

    async fn binding_state(db: &SqliteSnAuthDB, domain: &str) -> SnResult<String> {
        sqlx::query_scalar("SELECT state FROM user_domain_bindings WHERE domain = ?1")
            .bind(domain)
            .fetch_one(&db.pool)
            .await
            .map_err(|e| SqliteSnAuthDB::db_err("read binding state failed", e))
    }
}
