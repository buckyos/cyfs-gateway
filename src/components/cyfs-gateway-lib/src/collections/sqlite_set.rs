use super::sqlite_pool::open_sqlite_pool;
use cyfs_process_chain::{SetCollection, SetCollectionTraverseCallBackRef};
use sqlx::Row;
use sqlx::sqlite::SqlitePool;

pub struct SqliteSet {
    pub table_name: String,
    pub column_name: String,
    pool: SqlitePool,
}

impl SqliteSet {
    pub async fn open(
        path: impl Into<String>,
        table_name: Option<String>,
        column_name: Option<String>,
    ) -> Result<Self, String> {
        let pool = open_sqlite_pool(path.into().as_str())
            .await
            .map_err(|e| e.to_string())?;
        let table_name = if table_name.is_some() {
            table_name.unwrap()
        } else {
            // 从数据库中获取表名
            match sqlx::query("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;")
                .fetch_optional(&pool)
                .await
                .map_err(|e| e.to_string())?
            {
                Some(row) => row.get("name"),
                None => {
                    // 创建表
                    sqlx::query("CREATE TABLE datas (data TEXT PRIMARY KEY);")
                        .execute(&pool)
                        .await
                        .map_err(|e| e.to_string())?;
                    "datas".to_string()
                }
            }
        };

        let column_name = if column_name.is_some() {
            column_name.unwrap()
        } else {
            // 从数据库中获取列名
            match sqlx::query(format!("PRAGMA table_info({});", table_name).as_str())
                .fetch_optional(&pool)
                .await
                .map_err(|e| e.to_string())?
            {
                Some(row) => row.get("name"),
                None => {
                    // 创建列
                    sqlx::query(
                        format!("ALTER TABLE {} ADD COLUMN data TEXT;", table_name).as_str(),
                    )
                    .execute(&pool)
                    .await
                    .map_err(|e| e.to_string())?;
                    "data".to_string()
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
        let row = sqlx::query(
            format!("SELECT COUNT(*) AS count FROM {};", self.table_name).as_str(),
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| e.to_string())?;
        Ok(row.get::<i64, _>("count") as usize)
    }

    async fn insert(&self, value: &str) -> Result<bool, String> {
        let row = sqlx::query(
            format!(
                "INSERT OR IGNORE INTO {} ({}) VALUES (?);",
                self.table_name, self.column_name
            )
            .as_str(),
        )
        .bind(value)
        .execute(&self.pool)
        .await
        .map_err(|e| e.to_string())?;
        Ok(row.rows_affected() > 0)
    }

    async fn contains(&self, key: &str) -> Result<bool, String> {
        let row = sqlx::query(
            format!(
                "SELECT * FROM {} WHERE {} = ?;",
                self.table_name, self.column_name
            )
            .as_str(),
        )
        .bind(key)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| e.to_string())?;
        Ok(row.is_some())
    }

    async fn remove(&self, key: &str) -> Result<bool, String> {
        let row = sqlx::query(
            format!(
                "DELETE FROM {} WHERE {} = ?;",
                self.table_name, self.column_name
            )
            .as_str(),
        )
        .bind(key)
        .execute(&self.pool)
        .await
        .map_err(|e| e.to_string())?;
        Ok(row.rows_affected() > 0)
    }

    async fn get_all(&self) -> Result<Vec<String>, String> {
        let rows = sqlx::query(format!("SELECT * FROM {};", self.table_name).as_str())
            .fetch_all(&self.pool)
            .await
            .map_err(|e| e.to_string())?;
        let mut result = Vec::new();
        for row in rows {
            result.push(row.get(self.column_name.as_str()));
        }
        Ok(result)
    }

    async fn traverse(&self, callback: SetCollectionTraverseCallBackRef) -> Result<(), String> {
        let rows = sqlx::query(format!("SELECT * FROM {}", self.table_name).as_str())
            .fetch_all(&self.pool)
            .await
            .map_err(|e| e.to_string())?;
        for row in rows {
            callback.call(row.get(self.column_name.as_str())).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::SqliteSet;
    use super::open_sqlite_pool;
    use cyfs_process_chain::SetCollection;

    #[tokio::test]
    async fn test_new_sqlite_set() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let path = file.path().to_string_lossy().to_string();
        let set = SqliteSet::open(format!("sqlite://{}", path), None, None)
            .await
            .unwrap();
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
            let set = SqliteSet::open(format!("sqlite://{}", path.as_str()), None, None)
                .await
                .unwrap();
            assert_eq!(set.len().await.unwrap(), 0);
            assert_eq!(set.insert("test").await.unwrap(), true);
            assert_eq!(set.len().await.unwrap(), 1);
            assert_eq!(set.contains("test").await.unwrap(), true);
        }
        {
            let set = SqliteSet::open(format!("sqlite://{}", path), None, None)
                .await
                .unwrap();
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
            let pool = open_sqlite_pool(format!("sqlite://{}", path).as_str())
                .await
                .unwrap();
            sqlx::query("CREATE TABLE test_datas (item TEXT PRIMARY KEY);")
                .execute(&pool)
                .await
                .unwrap();
            sqlx::query("INSERT INTO test_datas (item) VALUES ('test');")
                .execute(&pool)
                .await
                .unwrap();
            sqlx::query("INSERT INTO test_datas (item) VALUES ('test1');")
                .execute(&pool)
                .await
                .unwrap();
        }

        let set = SqliteSet::open(
            format!("sqlite://{}", path),
            Some("test_datas".to_string()),
            Some("item".to_string()),
        )
        .await
        .unwrap();
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
            let pool = open_sqlite_pool(format!("sqlite://{}", path).as_str())
                .await
                .unwrap();
            sqlx::query("CREATE TABLE test_datas (item TEXT PRIMARY KEY);")
                .execute(&pool)
                .await
                .unwrap();
            sqlx::query("INSERT INTO test_datas (item) VALUES ('test');")
                .execute(&pool)
                .await
                .unwrap();
            sqlx::query("INSERT INTO test_datas (item) VALUES ('test1');")
                .execute(&pool)
                .await
                .unwrap();
        }

        let set = SqliteSet::open(format!("sqlite://{}", path), None, None)
            .await
            .unwrap();
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
            let pool = open_sqlite_pool(format!("sqlite://{}", path).as_str())
                .await
                .unwrap();
            sqlx::query("CREATE TABLE test_datas (item TEXT PRIMARY KEY);")
                .execute(&pool)
                .await
                .unwrap();
            sqlx::query("INSERT INTO test_datas (item) VALUES ('test');")
                .execute(&pool)
                .await
                .unwrap();
            sqlx::query("INSERT INTO test_datas (item) VALUES ('test1');")
                .execute(&pool)
                .await
                .unwrap();
        }

        let set = SqliteSet::open(
            format!("sqlite://{}", path),
            Some("test_datas".to_string()),
            None,
        )
        .await
        .unwrap();
        assert_eq!(set.len().await.unwrap(), 2);
        assert_eq!(set.contains("test").await.unwrap(), true);
        assert_eq!(set.contains("test1").await.unwrap(), true);
        assert_eq!(set.remove("test").await.unwrap(), true);
        assert_eq!(set.contains("test").await.unwrap(), false);
        assert_eq!(set.contains("test1").await.unwrap(), true);
        assert_eq!(set.get_all().await.unwrap(), vec!["test1"]);
    }
}
