use sfo_sql::Row;
use sfo_sql::sqlite::sql_query;
use cyfs_process_chain::{SetCollection, SetCollectionTraverseCallBackRef};

pub struct SqliteSet {
    pub table_name: String,
    pub column_name: String,
    pub pool: sfo_sql::sqlite::SqlPool,
}

impl SqliteSet {
    pub async fn open(path: impl Into<String>, table_name: Option<String>, column_name: Option<String>) -> Result<Self, String> {
        let pool = sfo_sql::sqlite::SqlPool::open(path.into().as_str(), 5, None)
            .await.map_err(|e| e.to_string())?;
        let table_name = if table_name.is_some() {
            table_name.unwrap()
        } else {
            let mut conn = pool.get_conn().await.map_err(|e| e.to_string())?;
            // 从数据库中获取表名
            match conn.query_one(sql_query("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;")).await {
                Ok(row) => {
                    row.get("name")
                }
                Err(e) => {
                    if e.code() == sfo_sql::errors::SqlErrorCode::NotFound {
                        // 创建表
                        conn.execute_sql(sql_query("CREATE TABLE datas (data TEXT PRIMARY KEY);")).await.map_err(|e| e.to_string())?;
                        "datas".to_string()
                    } else {
                        return Err(e.to_string());
                    }
                }
            }
        };

        let column_name = if column_name.is_some() {
            column_name.unwrap()
        } else {
            let mut conn = pool.get_conn().await.map_err(|e| e.to_string())?;
            // 从数据库中获取列名
            match conn.query_one(sql_query(format!("PRAGMA table_info({});", table_name).as_str())).await {
                Ok(row) => {
                    row.get("name")
                }
                Err(e) => {
                    if e.code() == sfo_sql::errors::SqlErrorCode::NotFound {
                        // 创建列
                        conn.execute_sql(sql_query(format!("ALTER TABLE {} ADD COLUMN data TEXT;", table_name).as_str())).await.map_err(|e| e.to_string())?;
                        "data".to_string()
                    } else {
                        return Err(e.to_string());
                    }
                }
            }
        };

        Ok(SqliteSet {
            table_name,
            column_name,
            pool,
        })
    }
}

#[async_trait::async_trait]
impl SetCollection for SqliteSet {
    async fn len(&self) -> Result<usize, String> {
        let mut conn = self.pool.get_conn().await.map_err(|e| e.to_string())?;
        let row = conn.query_one(sql_query(format!("SELECT COUNT(*) AS count FROM {};", self.table_name).as_str())).await.map_err(|e| e.to_string())?;
        Ok(row.get::<i64, _>("count") as usize)
    }

    async fn insert(&self, value: &str) -> Result<bool, String> {
        let mut conn = self.pool.get_conn().await.map_err(|e| e.to_string())?;
        let row = conn.execute_sql(sql_query(format!("INSERT OR IGNORE INTO {} ({}) VALUES (?);", self.table_name, self.column_name).as_str()).bind(value)).await.map_err(|e| e.to_string())?;
        Ok(row.rows_affected() > 0)
    }

    async fn contains(&self, key: &str) -> Result<bool, String> {
        let mut conn = self.pool.get_conn().await.map_err(|e| e.to_string())?;
        match conn.query_one(sql_query(format!("SELECT * FROM {} WHERE {} = ?;", self.table_name, self.column_name).as_str()).bind(key)).await {
            Ok(_) => {
                Ok(true)
            }
            Err(e) => {
                if e.code() == sfo_sql::errors::SqlErrorCode::NotFound {
                    Ok(false)
                } else {
                    Err(e.to_string())
                }
            }
        }
    }

    async fn remove(&self, key: &str) -> Result<bool, String> {
        let mut conn = self.pool.get_conn().await.map_err(|e| e.to_string())?;
        let row = conn.execute_sql(sql_query(format!("DELETE FROM {} WHERE {} = ?;", self.table_name, self.column_name).as_str()).bind(key)).await.map_err(|e| e.to_string())?;
        Ok(row.rows_affected() > 0)
    }

    async fn get_all(&self) -> Result<Vec<String>, String> {
        let mut conn = self.pool.get_conn().await.map_err(|e| e.to_string())?;
        let rows = conn.query_all(sql_query(format!("SELECT * FROM {};", self.table_name).as_str())).await.map_err(|e| e.to_string())?;
        let mut result = Vec::new();
        for row in rows {
            result.push(row.get(self.column_name.as_str()));
        }
        Ok(result)
    }

    async fn traverse(&self, callback: SetCollectionTraverseCallBackRef) -> Result<(), String> {
        let mut conn = self.pool.get_conn().await.map_err(|e| e.to_string())?;
        let rows = conn.query_all(sql_query(format!("SELECT * FROM {}", self.table_name).as_str())).await.map_err(|e| e.to_string())?;
        for row in rows {
            callback.call(row.get(self.column_name.as_str())).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use sfo_sql::sqlite::sql_query;
    use crate::SqliteSet;
    use cyfs_process_chain::SetCollection;

    #[tokio::test]
    async fn test_new_sqlite_set() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let path = file.path().to_string_lossy().to_string();
        let set = SqliteSet::open(format!("sqlite://{}", path), None, None).await.unwrap();
        assert_eq!(set.len().await.unwrap(), 0);
        assert_eq!(set.insert("test").await.unwrap(), true);
        assert_eq!(set.len().await.unwrap(), 1);
        assert_eq!(set.contains("test").await.unwrap(), true);
        assert_eq!(set.remove("test").await.unwrap(), true);
    }

    #[tokio::test]
    async fn test_reopen_sqlite_set() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let path = file.path().to_string_lossy().to_string();
        {
            let set = SqliteSet::open(format!("sqlite://{}", path.as_str()), None, None).await.unwrap();
            assert_eq!(set.len().await.unwrap(), 0);
            assert_eq!(set.insert("test").await.unwrap(), true);
            assert_eq!(set.len().await.unwrap(), 1);
            assert_eq!(set.contains("test").await.unwrap(), true);
        }
        {
            let set = SqliteSet::open(format!("sqlite://{}", path), None, None).await.unwrap();
            assert_eq!(set.len().await.unwrap(), 1);
            assert_eq!(set.contains("test").await.unwrap(), true);
            assert_eq!(set.remove("test").await.unwrap(), true);
        }
    }

    #[tokio::test]
    async fn test_open_sqlite_set() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let path = file.path().to_string_lossy().to_string();

        {
            let pool = sfo_sql::sqlite::SqlPool::open(format!("sqlite://{}", path).as_str(), 5, None)
                .await.unwrap();
            let mut conn = pool.get_conn().await.unwrap();
            conn.execute_sql(sql_query("CREATE TABLE test_datas (item TEXT PRIMARY KEY);")).await.unwrap();
            conn.execute_sql(sql_query("INSERT INTO test_datas (item) VALUES ('test');")).await.unwrap();
            conn.execute_sql(sql_query("INSERT INTO test_datas (item) VALUES ('test1');")).await.unwrap();
        }

        let set = SqliteSet::open(format!("sqlite://{}", path), Some("test_datas".to_string()), Some("item".to_string())).await.unwrap();
        assert_eq!(set.len().await.unwrap(), 2);
        assert_eq!(set.contains("test").await.unwrap(), true);
        assert_eq!(set.contains("test1").await.unwrap(), true);
        assert_eq!(set.remove("test").await.unwrap(), true);
        assert_eq!(set.contains("test").await.unwrap(), false);
        assert_eq!(set.contains("test1").await.unwrap(), true);
        assert_eq!(set.get_all().await.unwrap(), vec!["test1"]);
    }

    #[tokio::test]
    async fn test_open_sqlite_set1() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let path = file.path().to_string_lossy().to_string();

        {
            let pool = sfo_sql::sqlite::SqlPool::open(format!("sqlite://{}", path).as_str(), 5, None)
                .await.unwrap();
            let mut conn = pool.get_conn().await.unwrap();
            conn.execute_sql(sql_query("CREATE TABLE test_datas (item TEXT PRIMARY KEY);")).await.unwrap();
            conn.execute_sql(sql_query("INSERT INTO test_datas (item) VALUES ('test');")).await.unwrap();
            conn.execute_sql(sql_query("INSERT INTO test_datas (item) VALUES ('test1');")).await.unwrap();
        }

        let set = SqliteSet::open(format!("sqlite://{}", path), None, None).await.unwrap();
        assert_eq!(set.len().await.unwrap(), 2);
        assert_eq!(set.contains("test").await.unwrap(), true);
        assert_eq!(set.contains("test1").await.unwrap(), true);
        assert_eq!(set.remove("test").await.unwrap(), true);
        assert_eq!(set.contains("test").await.unwrap(), false);
        assert_eq!(set.contains("test1").await.unwrap(), true);
        assert_eq!(set.get_all().await.unwrap(), vec!["test1"]);
    }

    #[tokio::test]
    async fn test_open_sqlite_set2() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let path = file.path().to_string_lossy().to_string();

        {
            let pool = sfo_sql::sqlite::SqlPool::open(format!("sqlite://{}", path).as_str(), 5, None)
                .await.unwrap();
            let mut conn = pool.get_conn().await.unwrap();
            conn.execute_sql(sql_query("CREATE TABLE test_datas (item TEXT PRIMARY KEY);")).await.unwrap();
            conn.execute_sql(sql_query("INSERT INTO test_datas (item) VALUES ('test');")).await.unwrap();
            conn.execute_sql(sql_query("INSERT INTO test_datas (item) VALUES ('test1');")).await.unwrap();
        }

        let set = SqliteSet::open(format!("sqlite://{}", path), Some("test_datas".to_string()), None).await.unwrap();
        assert_eq!(set.len().await.unwrap(), 2);
        assert_eq!(set.contains("test").await.unwrap(), true);
        assert_eq!(set.contains("test1").await.unwrap(), true);
        assert_eq!(set.remove("test").await.unwrap(), true);
        assert_eq!(set.contains("test").await.unwrap(), false);
        assert_eq!(set.contains("test1").await.unwrap(), true);
        assert_eq!(set.get_all().await.unwrap(), vec!["test1"]);
    }
}