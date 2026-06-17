use crate::{into_sn_err, SnErrorCode, SnResult};
use rand::Rng;
use sfo_sql::mysql::sql_query;
use sfo_sql::sqlite::{SqlConnection, SqlPool, SqliteJournalMode};
use sfo_sql::Row;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

const ACTIVATION_CODE_LEN: usize = 32;
const ACTIVATION_CODE_CHARS: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

pub type SnAuthDBRef = Arc<dyn SnAuthDB>;

#[derive(Debug, Clone)]
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
}

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
pub struct SnClearStateResult {
    pub deleted_users: u64,
    pub deleted_devices: u64,
    pub deleted_domain_records: u64,
    pub deleted_did_documents: u64,
    pub activation_code_reset: bool,
}

#[derive(Debug, Clone)]
pub struct SnV2AuthInfo {
    pub username: String,
    pub password_hash: String,
    pub password_salt: String,
    pub password_algo: String,
    pub created_at: u64,
    pub updated_at: u64,
    pub last_login_at: Option<u64>,
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
    async fn get_user_info(&self, username: &str) -> SnResult<Option<SNUserInfo>>;
    async fn get_v2_auth(&self, username: &str) -> SnResult<Option<SnV2AuthInfo>>;
    async fn update_v2_last_login(&self, username: &str, last_login_at: u64) -> SnResult<()>;
}

pub struct SqliteSnAuthDB {
    pool: SqlPool,
}

impl SqliteSnAuthDB {
    pub async fn new() -> SnResult<Self> {
        let base_dir = PathBuf::from(std::env::current_exe().unwrap().parent().unwrap());
        let db_path = base_dir.join("sn_auth.sqlite3");

        Self::new_by_path(db_path.to_string_lossy().as_ref()).await
    }

    pub async fn new_by_path(path: &str) -> SnResult<Self> {
        let pool = SqlPool::open(
            format!("sqlite://{}", path).as_str(),
            300,
            Some(SqliteJournalMode::Wal),
        )
        .await
        .map_err(into_sn_err!(SnErrorCode::DBError, "open file: {:?}", path))?;

        Ok(Self { pool })
    }

    pub async fn initialize_database(&self) -> SnResult<()> {
        let mut conn = self
            .pool
            .get_conn()
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "get conn"))?;

        conn.execute_sql(sql_query(
            "CREATE TABLE IF NOT EXISTS activation_codes (
                code TEXT PRIMARY KEY,
                used INTEGER NOT NULL
            )",
        ))
        .await
        .map_err(into_sn_err!(
            SnErrorCode::DBError,
            "create activation_codes table failed"
        ))?;

        conn.execute_sql(sql_query(
            "CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                state TEXT,
                public_key TEXT,
                activation_code TEXT,
                zone_config TEXT,
                self_cert boolean,
                user_domain TEXT,
                sn_ips TEXT
            )",
        ))
        .await
        .map_err(into_sn_err!(
            SnErrorCode::DBError,
            "create users table failed"
        ))?;

        conn.execute_sql(sql_query(
            "CREATE TABLE IF NOT EXISTS user_auth_v2 (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                password_algo TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                last_login_at INTEGER NULL
            )",
        ))
        .await
        .map_err(into_sn_err!(
            SnErrorCode::DBError,
            "create user_auth_v2 table failed"
        ))?;

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

    async fn rollback_transaction(conn: &mut SqlConnection, context: &str) -> SnResult<()> {
        conn.rollback_transaction()
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "{}", context))
    }

    async fn table_exists(conn: &mut SqlConnection, table_name: &str) -> SnResult<bool> {
        Ok(conn
            .query_one(
                sql_query("SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?1")
                    .bind(table_name),
            )
            .await
            .is_ok())
    }

    async fn count_devices_by_active_code(
        conn: &mut SqlConnection,
        active_code: &str,
    ) -> SnResult<i64> {
        if !Self::table_exists(conn, "devices").await? {
            return Ok(0);
        }

        Ok(conn
            .query_one(
                sql_query(
                    "SELECT COUNT(*) FROM devices
                     WHERE owner IN (
                        SELECT username FROM users WHERE activation_code = ?1
                     )",
                )
                .bind(active_code),
            )
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "count devices failed"))?
            .get(0))
    }

    async fn count_domain_records_by_active_code(
        conn: &mut SqlConnection,
        active_code: &str,
    ) -> SnResult<i64> {
        if !Self::table_exists(conn, "user_dns_records").await? {
            return Ok(0);
        }

        Ok(conn
            .query_one(
                sql_query(
                    "SELECT COUNT(*) FROM user_dns_records
                     WHERE owner IN (
                        SELECT username FROM users WHERE activation_code = ?1
                     )",
                )
                .bind(active_code),
            )
            .await
            .map_err(into_sn_err!(
                SnErrorCode::DBError,
                "count user_dns_records failed"
            ))?
            .get(0))
    }

    async fn count_did_documents_by_active_code(
        conn: &mut SqlConnection,
        active_code: &str,
    ) -> SnResult<i64> {
        if !Self::table_exists(conn, "did_documents").await? {
            return Ok(0);
        }

        Ok(conn
            .query_one(
                sql_query(
                    "SELECT COUNT(*) FROM did_documents
                     WHERE owner_user IN (
                        SELECT username FROM users WHERE activation_code = ?1
                     )",
                )
                .bind(active_code),
            )
            .await
            .map_err(into_sn_err!(
                SnErrorCode::DBError,
                "count did_documents failed"
            ))?
            .get(0))
    }

    async fn delete_optional_related_rows(
        conn: &mut SqlConnection,
        active_code: &str,
    ) -> SnResult<()> {
        if Self::table_exists(conn, "devices").await? {
            conn.execute_sql(
                sql_query(
                    "DELETE FROM devices
                     WHERE owner IN (
                        SELECT username FROM users WHERE activation_code = ?1
                     )",
                )
                .bind(active_code),
            )
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "delete devices failed"))?;
        }

        if Self::table_exists(conn, "user_dns_records").await? {
            conn.execute_sql(
                sql_query(
                    "DELETE FROM user_dns_records
                     WHERE owner IN (
                        SELECT username FROM users WHERE activation_code = ?1
                     )",
                )
                .bind(active_code),
            )
            .await
            .map_err(into_sn_err!(
                SnErrorCode::DBError,
                "delete user dns records failed"
            ))?;
        }

        if Self::table_exists(conn, "did_documents").await? {
            conn.execute_sql(
                sql_query(
                    "DELETE FROM did_documents
                     WHERE owner_user IN (
                        SELECT username FROM users WHERE activation_code = ?1
                     )",
                )
                .bind(active_code),
            )
            .await
            .map_err(into_sn_err!(
                SnErrorCode::DBError,
                "delete did documents failed"
            ))?;
        }

        Ok(())
    }
}

#[async_trait::async_trait]
impl SnAuthDB for SqliteSnAuthDB {
    async fn get_activation_codes(&self) -> SnResult<Vec<String>> {
        let mut conn = self
            .pool
            .get_conn()
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "get conn"))?;
        let rows = conn
            .query_all(sql_query(
                "SELECT code FROM activation_codes WHERE used = 0",
            ))
            .await
            .map_err(into_sn_err!(
                SnErrorCode::DBError,
                "query activation_codes failed"
            ))?;

        Ok(rows.into_iter().map(|row| row.get(0)).collect())
    }

    async fn insert_activation_code(&self, code: &str) -> SnResult<()> {
        let mut conn = self
            .pool
            .get_conn()
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "get conn"))?;
        conn.execute_sql(
            sql_query("INSERT INTO activation_codes (code, used) VALUES (?1, 0)").bind(code),
        )
        .await
        .map_err(into_sn_err!(
            SnErrorCode::DBError,
            "insert activation_codes failed"
        ))?;

        Ok(())
    }

    async fn generate_activation_codes(&self, count: usize) -> SnResult<Vec<String>> {
        let mut codes = Vec::with_capacity(count);
        let mut conn = self
            .pool
            .get_conn()
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "get conn"))?;

        while codes.len() < count {
            let code = Self::generate_activation_code();
            let result = conn
                .execute_sql(
                    sql_query("INSERT OR IGNORE INTO activation_codes (code, used) VALUES (?1, 0)")
                        .bind(code.as_str()),
                )
                .await
                .map_err(into_sn_err!(
                    SnErrorCode::DBError,
                    "insert activation_codes failed"
                ))?;

            if result.rows_affected() > 0 {
                codes.push(code);
            }
        }

        Ok(codes)
    }

    async fn check_active_code(&self, active_code: &str) -> SnResult<bool> {
        let mut conn = self
            .pool
            .get_conn()
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "get conn"))?;

        match conn
            .query_one(
                sql_query("SELECT used FROM activation_codes WHERE code = ?1").bind(active_code),
            )
            .await
        {
            Ok(row) => {
                let used: i32 = row.get(0);
                Ok(used == 0)
            }
            Err(_) => Ok(false),
        }
    }

    async fn clear_state_by_active_code(&self, active_code: &str) -> SnResult<SnClearStateResult> {
        let mut conn = self
            .pool
            .get_conn()
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "get conn"))?;

        conn.begin_transaction().await.map_err(into_sn_err!(
            SnErrorCode::DBError,
            "begin transaction failed"
        ))?;

        let user_count: i64 = conn
            .query_one(
                sql_query("SELECT COUNT(*) FROM users WHERE activation_code = ?1")
                    .bind(active_code),
            )
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "count users failed"))?
            .get(0);
        let device_count = Self::count_devices_by_active_code(&mut conn, active_code).await?;
        let domain_record_count =
            Self::count_domain_records_by_active_code(&mut conn, active_code).await?;
        let did_doc_count =
            Self::count_did_documents_by_active_code(&mut conn, active_code).await?;

        Self::delete_optional_related_rows(&mut conn, active_code).await?;

        conn.execute_sql(
            sql_query(
                "DELETE FROM user_auth_v2
                 WHERE username IN (
                    SELECT username FROM users WHERE activation_code = ?1
                 )",
            )
            .bind(active_code),
        )
        .await
        .map_err(into_sn_err!(
            SnErrorCode::DBError,
            "delete user auth v2 failed"
        ))?;

        conn.execute_sql(
            sql_query("DELETE FROM users WHERE activation_code = ?1").bind(active_code),
        )
        .await
        .map_err(into_sn_err!(SnErrorCode::DBError, "delete users failed"))?;

        conn.execute_sql(
            sql_query(
                "INSERT INTO activation_codes (code, used) VALUES (?1, 0)
                 ON CONFLICT(code) DO UPDATE SET used = 0",
            )
            .bind(active_code),
        )
        .await
        .map_err(into_sn_err!(
            SnErrorCode::DBError,
            "reset activation code failed"
        ))?;

        conn.commit_transaction().await.map_err(into_sn_err!(
            SnErrorCode::DBError,
            "commit transaction failed"
        ))?;

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
        let mut conn = self
            .pool
            .get_conn()
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "get conn"))?;

        conn.begin_transaction().await.map_err(into_sn_err!(
            SnErrorCode::DBError,
            "begin transaction failed"
        ))?;

        let code_unused = match conn
            .query_one(
                sql_query("SELECT used FROM activation_codes WHERE code = ?1").bind(active_code),
            )
            .await
        {
            Ok(row) => row.get::<i32, _>(0) == 0,
            Err(_) => false,
        };
        if !code_unused {
            Self::rollback_transaction(&mut conn, "rollback invalid activation code failed")
                .await?;
            return Ok(false);
        }

        let user_count: i64 = conn
            .query_one(sql_query("SELECT COUNT(*) FROM users WHERE username = ?1").bind(username))
            .await
            .map_err(into_sn_err!(
                SnErrorCode::DBError,
                "query user count failed"
            ))?
            .get(0);
        if user_count > 0 {
            Self::rollback_transaction(&mut conn, "rollback existing user failed").await?;
            return Ok(false);
        }

        let auth_count: i64 = conn
            .query_one(
                sql_query("SELECT COUNT(*) FROM user_auth_v2 WHERE username = ?1").bind(username),
            )
            .await
            .map_err(into_sn_err!(
                SnErrorCode::DBError,
                "query user auth count failed"
            ))?
            .get(0);
        if auth_count > 0 {
            Self::rollback_transaction(&mut conn, "rollback existing user auth failed").await?;
            return Ok(false);
        }

        let now = Self::now_secs() as i64;
        conn.execute_sql(sql_query("INSERT INTO users (username, state, public_key, activation_code, zone_config, user_domain, self_cert, sn_ips) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)")
            .bind(username)
            .bind(UserState::Active.to_string())
            .bind("")
            .bind(active_code)
            .bind("")
            .bind(Option::<String>::None)
            .bind(false)
            .bind(Option::<String>::None))
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "insert v2 user failed"))?;

        conn.execute_sql(sql_query("INSERT INTO user_auth_v2 (username, password_hash, password_salt, password_algo, created_at, updated_at, last_login_at) VALUES (?1, ?2, ?3, ?4, ?5, ?5, NULL)")
            .bind(username)
            .bind(password_hash)
            .bind(password_salt)
            .bind(password_algo)
            .bind(now))
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "insert v2 auth failed"))?;

        conn.execute_sql(
            sql_query("UPDATE activation_codes SET used = 1 WHERE code = ?1").bind(active_code),
        )
        .await
        .map_err(into_sn_err!(
            SnErrorCode::DBError,
            "update activation code failed"
        ))?;

        conn.commit_transaction().await.map_err(into_sn_err!(
            SnErrorCode::DBError,
            "commit transaction failed"
        ))?;

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
        let mut conn = self
            .pool
            .get_conn()
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "get conn"))?;

        let user_count: i64 = conn
            .query_one(sql_query("SELECT COUNT(*) FROM users WHERE username = ?1").bind(username))
            .await
            .map_err(into_sn_err!(
                SnErrorCode::DBError,
                "query user count failed"
            ))?
            .get(0);
        if user_count > 0 {
            return Ok(false);
        }

        let auth_count: i64 = conn
            .query_one(
                sql_query("SELECT COUNT(*) FROM user_auth_v2 WHERE username = ?1").bind(username),
            )
            .await
            .map_err(into_sn_err!(
                SnErrorCode::DBError,
                "query user auth count failed"
            ))?
            .get(0);
        if auth_count > 0 {
            return Ok(false);
        }

        let now = Self::now_secs() as i64;
        conn.execute_sql(sql_query("INSERT INTO user_auth_v2 (username, password_hash, password_salt, password_algo, created_at, updated_at, last_login_at) VALUES (?1, ?2, ?3, ?4, ?5, ?5, NULL)")
            .bind(username)
            .bind(password_hash)
            .bind(password_salt)
            .bind(password_algo)
            .bind(now))
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "insert v2 auth failed"))?;

        Ok(true)
    }

    async fn is_user_exist(&self, username: &str) -> SnResult<bool> {
        let mut conn = self
            .pool
            .get_conn()
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "get conn"))?;
        let row = conn
            .query_one(sql_query("SELECT COUNT(*) FROM users WHERE username = ?1").bind(username))
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "query user failed"))?;
        let count: i64 = row.get(0);

        Ok(count > 0)
    }

    async fn get_user_info(&self, username: &str) -> SnResult<Option<SNUserInfo>> {
        let mut conn = self
            .pool
            .get_conn()
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "get conn"))?;

        match conn
            .query_one(sql_query("SELECT state, public_key, activation_code, zone_config, self_cert, user_domain, sn_ips FROM users WHERE username = ?1").bind(username))
            .await
        {
            Ok(row) => {
                let state_str: Option<String> = row.get(0);
                Ok(Some(SNUserInfo {
                    username: None,
                    state: UserState::from_str(state_str.as_deref()),
                    public_key: row.get(1),
                    activation_code: row.get(2),
                    zone_config: row.get(3),
                    self_cert: row.get::<Option<bool>, _>(4).unwrap_or(false),
                    user_domain: row.get(5),
                    sn_ips: row.get(6),
                }))
            }
            Err(_) => Ok(None),
        }
    }

    async fn get_v2_auth(&self, username: &str) -> SnResult<Option<SnV2AuthInfo>> {
        let mut conn = self
            .pool
            .get_conn()
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "get conn"))?;

        match conn
            .query_one(
                sql_query("SELECT username, password_hash, password_salt, password_algo, created_at, updated_at, last_login_at FROM user_auth_v2 WHERE username = ?1")
                    .bind(username),
            )
            .await
        {
            Ok(row) => Ok(Some(SnV2AuthInfo {
                username: row.get(0),
                password_hash: row.get(1),
                password_salt: row.get(2),
                password_algo: row.get(3),
                created_at: row.get::<i64, _>(4) as u64,
                updated_at: row.get::<i64, _>(5) as u64,
                last_login_at: row.get::<Option<i64>, _>(6).map(|v| v as u64),
            })),
            Err(_) => Ok(None),
        }
    }

    async fn update_v2_last_login(&self, username: &str, last_login_at: u64) -> SnResult<()> {
        let mut conn = self
            .pool
            .get_conn()
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "get conn"))?;
        conn.execute_sql(
            sql_query(
                "UPDATE user_auth_v2 SET last_login_at = ?1, updated_at = ?1 WHERE username = ?2",
            )
            .bind(last_login_at as i64)
            .bind(username),
        )
        .await
        .map_err(into_sn_err!(
            SnErrorCode::DBError,
            "update v2 last login failed"
        ))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sn_err;

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

        let mut conn = db
            .pool
            .get_conn()
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "get conn"))?;
        conn.execute_sql(sql_query("CREATE TABLE devices (owner TEXT, device_name TEXT, did TEXT PRIMARY KEY, ip TEXT, description TEXT, mini_config_jwt TEXT, created_at INTEGER, updated_at INTEGER)"))
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "create devices failed"))?;
        conn.execute_sql(sql_query("CREATE TABLE user_dns_records (id INTEGER PRIMARY KEY AUTOINCREMENT, owner TEXT, domain TEXT, record_type TEXT, record TEXT, ttl INTEGER, created_at INTEGER, updated_at INTEGER)"))
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "create user_dns_records failed"))?;
        conn.execute_sql(sql_query("CREATE TABLE did_documents (id INTEGER PRIMARY KEY AUTOINCREMENT, obj_id TEXT, owner_user TEXT, obj_name TEXT, did_document TEXT, doc_type TEXT, update_time INTEGER)"))
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "create did_documents failed"))?;
        conn.execute_sql(sql_query("INSERT INTO devices (owner, device_name, did, ip, description, mini_config_jwt, created_at, updated_at) VALUES ('alice', 'ood1', 'did:dev:1', '', '', '', 1, 1)"))
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "insert device failed"))?;
        conn.execute_sql(sql_query("INSERT INTO user_dns_records (owner, domain, record_type, record, ttl, created_at, updated_at) VALUES ('alice', 'alice.example.com', 'A', '127.0.0.1', 60, 1, 1)"))
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "insert dns record failed"))?;
        conn.execute_sql(sql_query("INSERT INTO did_documents (obj_id, owner_user, obj_name, did_document, doc_type, update_time) VALUES ('obj1', 'alice', 'zone', '{}', 'zone', 1)"))
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "insert did document failed"))?;
        drop(conn);

        let result = db.clear_state_by_active_code("clear-me").await?;
        assert_eq!(result.deleted_users, 1);
        assert_eq!(result.deleted_devices, 1);
        assert_eq!(result.deleted_domain_records, 1);
        assert_eq!(result.deleted_did_documents, 1);
        assert!(result.activation_code_reset);
        assert!(db.check_active_code("clear-me").await?);
        assert!(!db.is_user_exist("alice").await?);
        assert!(db.get_v2_auth("alice").await?.is_none());

        Ok(())
    }
}
