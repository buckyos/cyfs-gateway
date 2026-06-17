use crate::{into_sn_err, sn_err, SnErrorCode, SnResult};
use sfo_sql::mysql::sql_query;
use sfo_sql::sqlite::{SqlPool, SqliteJournalMode};
use sfo_sql::Row;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

pub type SnDeviceInfoDBRef = Arc<dyn SnDeviceInfoDB>;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SnDidInfo {
    pub did: String,
    pub did_info: String,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SnDeviceEndpoint {
    pub did: String,
    pub endpoint: String,
    pub created_at: u64,
    pub updated_at: u64,
}

#[async_trait::async_trait]
pub trait SnDeviceInfoDB: Send + Sync + 'static {
    async fn update_did_info(&self, did: &str, did_info: &str) -> SnResult<()>;
    async fn get_did_info(&self, did: &str) -> SnResult<Option<SnDidInfo>>;
    async fn update_device_endpoint(&self, did: &str, endpoint: &str) -> SnResult<()>;
    async fn get_device_endpoint(&self, did: &str) -> SnResult<Option<SnDeviceEndpoint>>;
}

pub struct SqliteSnDeviceInfoDB {
    pool: SqlPool,
}

impl SqliteSnDeviceInfoDB {
    pub async fn new() -> SnResult<Self> {
        let base_dir = PathBuf::from(std::env::current_exe().unwrap().parent().unwrap());
        let db_path = base_dir.join("sn_device_info.sqlite3");

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
            "CREATE TABLE IF NOT EXISTS did_infos (
                did TEXT PRIMARY KEY,
                did_info TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            )",
        ))
        .await
        .map_err(into_sn_err!(
            SnErrorCode::DBError,
            "create did_infos table failed"
        ))?;

        conn.execute_sql(sql_query(
            "CREATE TABLE IF NOT EXISTS device_endpoints (
                did TEXT PRIMARY KEY,
                endpoint TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            )",
        ))
        .await
        .map_err(into_sn_err!(
            SnErrorCode::DBError,
            "create device_endpoints table failed"
        ))?;

        Ok(())
    }

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn check_did(did: &str) -> SnResult<()> {
        if did.trim().is_empty() {
            return Err(sn_err!(SnErrorCode::Failed, "device did is empty"));
        }

        Ok(())
    }
}

#[async_trait::async_trait]
impl SnDeviceInfoDB for SqliteSnDeviceInfoDB {
    async fn update_did_info(&self, did: &str, did_info: &str) -> SnResult<()> {
        Self::check_did(did)?;
        let now = Self::now_secs();
        let mut conn = self
            .pool
            .get_conn()
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "get conn"))?;

        conn.execute_sql(
            sql_query(
                "INSERT INTO did_infos (did, did_info, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?3)
                 ON CONFLICT(did) DO UPDATE SET did_info = ?2, updated_at = ?3",
            )
            .bind(did)
            .bind(did_info)
            .bind(now as i64),
        )
        .await
        .map_err(into_sn_err!(SnErrorCode::DBError, "update did info failed"))?;

        Ok(())
    }

    async fn get_did_info(&self, did: &str) -> SnResult<Option<SnDidInfo>> {
        Self::check_did(did)?;
        let mut conn = self
            .pool
            .get_conn()
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "get conn"))?;

        match conn
            .query_one(
                sql_query(
                    "SELECT did, did_info, created_at, updated_at FROM did_infos WHERE did = ?1",
                )
                .bind(did),
            )
            .await
        {
            Ok(row) => Ok(Some(SnDidInfo {
                did: row.get(0),
                did_info: row.get(1),
                created_at: row.get::<i64, _>(2) as u64,
                updated_at: row.get::<i64, _>(3) as u64,
            })),
            Err(_) => Ok(None),
        }
    }

    async fn update_device_endpoint(&self, did: &str, endpoint: &str) -> SnResult<()> {
        Self::check_did(did)?;
        let now = Self::now_secs();
        let mut conn = self
            .pool
            .get_conn()
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "get conn"))?;

        conn.execute_sql(
            sql_query(
                "INSERT INTO device_endpoints (did, endpoint, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?3)
                 ON CONFLICT(did) DO UPDATE SET endpoint = ?2, updated_at = ?3",
            )
            .bind(did)
            .bind(endpoint)
            .bind(now as i64),
        )
        .await
        .map_err(into_sn_err!(
            SnErrorCode::DBError,
            "update device endpoint failed"
        ))?;

        Ok(())
    }

    async fn get_device_endpoint(&self, did: &str) -> SnResult<Option<SnDeviceEndpoint>> {
        Self::check_did(did)?;
        let mut conn = self
            .pool
            .get_conn()
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "get conn"))?;

        match conn
            .query_one(
                sql_query(
                    "SELECT did, endpoint, created_at, updated_at
                     FROM device_endpoints WHERE did = ?1",
                )
                .bind(did),
            )
            .await
        {
            Ok(row) => Ok(Some(SnDeviceEndpoint {
                did: row.get(0),
                endpoint: row.get(1),
                created_at: row.get::<i64, _>(2) as u64,
                updated_at: row.get::<i64, _>(3) as u64,
            })),
            Err(_) => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_update_and_get_device_dynamic_info() -> SnResult<()> {
        let tmp_dir = tempfile::tempdir()
            .map_err(|e| sn_err!(SnErrorCode::DBError, "create temp dir failed: {}", e))?;
        let db_path = tmp_dir.path().join("sn_device_info.sqlite3");
        let db = SqliteSnDeviceInfoDB::new_by_path(db_path.to_string_lossy().as_ref()).await?;
        db.initialize_database().await?;

        let did = "did:dev:test-device-id";
        assert!(db.get_did_info(did).await?.is_none());
        assert!(db.get_device_endpoint(did).await?.is_none());

        db.update_did_info(did, r#"{"online":true}"#).await?;
        db.update_device_endpoint(did, "tcp://127.0.0.1:8080")
            .await?;

        let did_info = db.get_did_info(did).await?.unwrap();
        assert_eq!(did_info.did, did);
        assert_eq!(did_info.did_info, r#"{"online":true}"#);
        assert!(did_info.created_at <= did_info.updated_at);

        let endpoint = db.get_device_endpoint(did).await?.unwrap();
        assert_eq!(endpoint.did, did);
        assert_eq!(endpoint.endpoint, "tcp://127.0.0.1:8080");
        assert!(endpoint.created_at <= endpoint.updated_at);

        db.update_did_info(did, r#"{"online":false}"#).await?;
        db.update_device_endpoint(did, "tcp://127.0.0.1:8081")
            .await?;

        let did_info = db.get_did_info(did).await?.unwrap();
        assert_eq!(did_info.did_info, r#"{"online":false}"#);
        let endpoint = db.get_device_endpoint(did).await?.unwrap();
        assert_eq!(endpoint.endpoint, "tcp://127.0.0.1:8081");

        Ok(())
    }
}
