use sfo_sql::Row;
use sfo_sql::sqlite::sql_query;
use cyfs_process_chain::{CollectionValue, MapCollection, MapCollectionTraverseCallBackRef};
use std::collections::HashMap;
use crate::{collection_value_to_json_value, json_value_to_collection_value};

pub struct SqliteMap {
    pub table_name: String,
    pub key_column: String,
    pub value_column: String,
    pub pool: sfo_sql::sqlite::SqlPool,
}

impl SqliteMap {
    pub async fn open(
        path: impl Into<String>,
        table_name: Option<String>,
        key_column: Option<String>,
        value_column: Option<String>,
    ) -> Result<Self, String> {
        let pool = sfo_sql::sqlite::SqlPool::open(path.into().as_str(), 5, None)
            .await
            .map_err(|e| e.to_string())?;

        let table_name = if let Some(name) = table_name {
            name
        } else {
            let mut conn = pool
                .get_conn()
                .await
                .map_err(|e| e.to_string())?;
            // 从数据库中获取表名
            match conn
                .query_one(sql_query(
                    "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;",
                ))
                .await
            {
                Ok(row) => row.get("name"),
                Err(e) => {
                    if e.code() == sfo_sql::errors::SqlErrorCode::NotFound {
                        // 创建表
                        conn.execute_sql(sql_query(
                            "CREATE TABLE map_datas (key_item TEXT PRIMARY KEY, value_item TEXT);",
                        ))
                            .await
                            .map_err(|e| e.to_string())?;
                        "map_datas".to_string()
                    } else {
                        return Err(e.to_string());
                    }
                }
            }
        };

        let (key_column, value_column) = if key_column.is_none() || value_column.is_none() {
            // 确保表中有需要的列
            let mut conn = pool.get_conn().await.map_err(|e| e.to_string())?;
            let columns: Vec<String> = conn
                .query_all(sql_query(&format!("PRAGMA table_info({});", table_name)))
                .await
                .map_err(|e| e.to_string())?
                .into_iter()
                .map(|row| row.get("name"))
                .collect();

            if columns.len() == 2 {
                (columns[0].clone(), columns[1].clone())
            } else if columns.len() == 0 {
                let key_column = "key_item".to_string();
                let value_column = "value_item".to_string();
                conn.execute_sql(sql_query(&format!(
                    "ALTER TABLE {} ADD COLUMN {} TEXT;",
                    table_name, key_column
                )))
                    .await
                    .map_err(|e| e.to_string())?;
                conn.execute_sql(sql_query(&format!(
                    "ALTER TABLE {} ADD COLUMN {} TEXT;",
                    table_name, value_column
                )))
                    .await
                    .map_err(|e| e.to_string())?;
                (key_column, value_column)
            } else {
                return Err("Invalid table structure".to_string());
            }
        } else {
            (key_column.unwrap(), value_column.unwrap())
        };

        Ok(SqliteMap {
            table_name,
            key_column,
            value_column,
            pool,
        })
    }
}

#[async_trait::async_trait]
impl MapCollection for SqliteMap {
    async fn len(&self) -> Result<usize, String> {
        let mut conn = self
            .pool
            .get_conn()
            .await
            .map_err(|e| e.to_string())?;
        let row = conn
            .query_one(sql_query(&format!(
                "SELECT COUNT(*) AS count FROM {};",
                self.table_name
            )))
            .await
            .map_err(|e| e.to_string())?;
        Ok(row.get::<i64, _>("count") as usize)
    }

    async fn insert_new(&self, key: &str, value: CollectionValue) -> Result<bool, String> {
        let mut conn = self
            .pool
            .get_conn()
            .await
            .map_err(|e| e.to_string())?;
        let result = conn
            .execute_sql(
                sql_query(&format!(
                    "INSERT OR IGNORE INTO {} ({}, {}) VALUES (?, ?);",
                    self.table_name, self.key_column, self.value_column
                ))
                    .bind(key)
                    .bind(collection_value_to_json_value(&value).to_string()),
            )
            .await
            .map_err(|e| e.to_string())?;
        Ok(result.rows_affected() > 0)
    }

    async fn insert(
        &self,
        key: &str,
        value: CollectionValue,
    ) -> Result<Option<CollectionValue>, String> {
        // 先检查是否存在旧值
        let old_value = self.get(key).await?;

        let mut conn = self
            .pool
            .get_conn()
            .await
            .map_err(|e| e.to_string())?;
        conn.execute_sql(
            sql_query(&format!(
                "INSERT OR REPLACE INTO {} ({}, {}) VALUES (?, ?);",
                self.table_name, self.key_column, self.value_column
            ))
                .bind(key)
                .bind(collection_value_to_json_value(&value).to_string()),
        )
            .await
            .map_err(|e| e.to_string())?;

        Ok(old_value)
    }

    async fn get(&self, key: &str) -> Result<Option<CollectionValue>, String> {
        let mut conn = self
            .pool
            .get_conn()
            .await
            .map_err(|e| e.to_string())?;
        match conn
            .query_one(
                sql_query(&format!(
                    "SELECT {} FROM {} WHERE {} = ?;",
                    self.value_column, self.table_name, self.key_column
                ))
                    .bind(key),
            )
            .await
        {
            Ok(row) => {
                let value: String = row.get(self.value_column.as_str());
                let value: serde_json::Value = serde_json::from_str(value.as_str()).map_err(|e| e.to_string())?;
                Ok(Some(json_value_to_collection_value(&value)))
            }
            Err(e) => {
                if e.code() == sfo_sql::errors::SqlErrorCode::NotFound {
                    Ok(None)
                } else {
                    Err(e.to_string())
                }
            }
        }
    }

    async fn contains_key(&self, key: &str) -> Result<bool, String> {
        let mut conn = self
            .pool
            .get_conn()
            .await
            .map_err(|e| e.to_string())?;
        match conn
            .query_one(
                sql_query(&format!(
                    "SELECT 1 FROM {} WHERE {} = ?;",
                    self.table_name, self.key_column
                ))
                    .bind(key),
            )
            .await
        {
            Ok(_) => Ok(true),
            Err(e) => {
                if e.code() == sfo_sql::errors::SqlErrorCode::NotFound {
                    Ok(false)
                } else {
                    Err(e.to_string())
                }
            }
        }
    }

    async fn remove(&self, key: &str) -> Result<Option<CollectionValue>, String> {
        // 先获取旧值
        let old_value = self.get(key).await?;

        let mut conn = self
            .pool
            .get_conn()
            .await
            .map_err(|e| e.to_string())?;
        conn.execute_sql(
            sql_query(&format!(
                "DELETE FROM {} WHERE {} = ?;",
                self.table_name, self.key_column
            ))
                .bind(key),
        )
            .await
            .map_err(|e| e.to_string())?;

        Ok(old_value)
    }

    async fn traverse(&self, callback: MapCollectionTraverseCallBackRef) -> Result<(), String> {
        let mut conn = self
            .pool
            .get_conn()
            .await
            .map_err(|e| e.to_string())?;
        let rows = conn
            .query_all(sql_query(&format!(
                "SELECT {}, {} FROM {}",
                self.key_column, self.value_column, self.table_name
            )))
            .await
            .map_err(|e| e.to_string())?;

        for row in rows {
            let key: String = row.get(self.key_column.as_str());
            let value: String = row.get(self.value_column.as_str());
            let value: serde_json::Value = serde_json::from_str(value.as_str()).map_err(|e| e.to_string())?;
            let value = json_value_to_collection_value(&value);
            callback
                .call(&key, &value)
                .await?;
        }
        Ok(())
    }

    async fn dump(&self) -> Result<Vec<(String, CollectionValue)>, String> {
        let mut conn = self
            .pool
            .get_conn()
            .await
            .map_err(|e| e.to_string())?;
        let rows = conn
            .query_all(sql_query(&format!(
                "SELECT {}, {} FROM {}",
                self.key_column, self.value_column, self.table_name
            )))
            .await
            .map_err(|e| e.to_string())?;

        let mut result = Vec::new();
        for row in rows {
            let key: String = row.get(self.key_column.as_str());
            let value: String = row.get(self.value_column.as_str());
            let value: serde_json::Value = serde_json::from_str(value.as_str()).map_err(|e| e.to_string())?;
            let value = json_value_to_collection_value(&value);
            result.push((key, value));
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cyfs_process_chain::MapCollection;

    #[tokio::test]
    async fn test_new_sqlite_map() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let path = file.path().to_string_lossy().to_string();
        let map = SqliteMap::open(format!("sqlite://{}", path), None, None, None)
            .await
            .unwrap();

        assert_eq!(map.len().await.unwrap(), 0);

        let value = CollectionValue::String("value1".to_string());
        assert!(map.insert("key1", value).await.unwrap().is_none());
        assert_eq!(map.len().await.unwrap(), 1);
        assert!(map.contains_key("key1").await.unwrap());

        let retrieved = map.get("key1").await.unwrap().unwrap();
        assert_eq!(retrieved.to_string(), "value1");

        let value = CollectionValue::String("value2".to_string());
        assert!(map.insert("key1", value).await.unwrap().is_some());

        let old_value = map.remove("key1").await.unwrap();
        assert!(old_value.is_some());
        assert_eq!(old_value.unwrap().to_string(), "value2");
        assert_eq!(map.len().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn test_insert_new_sqlite_map() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let path = file.path().to_string_lossy().to_string();
        let map = SqliteMap::open(format!("sqlite://{}", path), None, None, None)
            .await
            .unwrap();

        assert_eq!(map.len().await.unwrap(), 0);

        let value = CollectionValue::String("value1".to_string());
        assert!(map.insert_new("key1", value).await.unwrap());
        assert_eq!(map.len().await.unwrap(), 1);
        assert!(map.contains_key("key1").await.unwrap());
        let retrieved = map.get("key1").await.unwrap().unwrap();
        assert_eq!(retrieved.to_string(), "value1");


        let value = CollectionValue::String("value2".to_string());
        assert!(!map.insert_new("key1", value).await.unwrap());

        let retrieved = map.get("key1").await.unwrap().unwrap();
        assert_eq!(retrieved.to_string(), "value1");

        let old_value = map.remove("key1").await.unwrap();
        assert!(old_value.is_some());
        assert_eq!(old_value.unwrap().to_string(), "value1");
        assert_eq!(map.len().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn test_reopen_sqlite_map() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let path = file.path().to_string_lossy().to_string();

        {
            let map = SqliteMap::open(format!("sqlite://{}", path), None, None, None)
                .await
                .unwrap();
            assert_eq!(map.len().await.unwrap(), 0);

            let value = CollectionValue::String("persistent_value".to_string());
            map.insert("persistent_key", value).await.unwrap();
            assert_eq!(map.len().await.unwrap(), 1);
            assert!(map.contains_key("persistent_key").await.unwrap());
        }

        {
            let map = SqliteMap::open(format!("sqlite://{}", path), None, None, None)
                .await
                .unwrap();
            assert_eq!(map.len().await.unwrap(), 1);
            assert!(map.contains_key("persistent_key").await.unwrap());

            let retrieved = map.get("persistent_key").await.unwrap().unwrap();
            assert_eq!(retrieved.to_string(), "persistent_value");

            let old_value = map.remove("persistent_key").await.unwrap();
            assert!(old_value.is_some());
            assert_eq!(old_value.unwrap().to_string(), "persistent_value");
        }
    }

    #[tokio::test]
    async fn test_sqlite_map_operations() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let path = file.path().to_string_lossy().to_string();
        let map = SqliteMap::open(format!("sqlite://{}", path), None, None, None)
            .await
            .unwrap();

        // 插入多个键值对
        let value1 = CollectionValue::String("first".to_string());
        assert!(map.insert("key1", value1).await.unwrap().is_none());

        let value2 = CollectionValue::String("second".to_string());
        assert!(map.insert("key2", value2).await.unwrap().is_none());

        // 验证长度
        assert_eq!(map.len().await.unwrap(), 2);

        // 更新已存在的键
        let new_value = CollectionValue::String("updated".to_string());
        let old_value = map.insert("key1", new_value).await.unwrap();
        assert!(old_value.is_some());
        assert_eq!(old_value.unwrap().to_string(), "first");

        // 验证更新后的值
        let value = map.get("key1").await.unwrap().unwrap();
        assert_eq!(value.to_string(), "updated");

        // 验证dump功能
        let all_entries = map.dump().await.unwrap();
        assert_eq!(all_entries.len(), 2);
        let mut entries_map = HashMap::new();
        for (key, value) in all_entries {
            entries_map.insert(key, value.to_string());
        }
        assert_eq!(entries_map.get("key1"), Some(&"updated".to_string()));
        assert_eq!(entries_map.get("key2"), Some(&"second".to_string()));
    }
}