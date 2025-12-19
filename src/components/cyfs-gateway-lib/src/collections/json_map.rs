use std::collections::{HashMap};
use std::ops::Deref;
use std::path::Path;
use std::sync::RwLock;
use cyfs_process_chain::{CollectionValue, MapCollection, MapCollectionRef, MapCollectionTraverseCallBackRef, MemoryMapCollection};

/// JSON 到 MapCollection 的转换错误
#[derive(Debug)]
pub enum JsonCollectionError {
    NotObject,
    InsertFailed(String),
    DumpFailed(String),
}

impl std::fmt::Display for JsonCollectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JsonCollectionError::NotObject => write!(f, "JSON value is not an object"),
            JsonCollectionError::InsertFailed(e) => write!(f, "Failed to insert into map: {}", e),
            JsonCollectionError::DumpFailed(e) => write!(f, "Failed to dump map: {}", e),
        }
    }
}

impl std::error::Error for JsonCollectionError {}

/// 为 MapCollectionRef 提供 JSON 转换功能的 trait
#[async_trait::async_trait]
pub trait JsonMapCollection {
    /// 从 JSON Value 创建 MapCollection
    ///
    /// # Arguments
    /// * `json` - JSON 对象值
    ///
    /// # Returns
    /// * `Ok(MapCollectionRef)` - 成功时返回新的 map collection
    /// * `Err(JsonCollectionError)` - 失败时返回错误
    async fn from_json(json: &serde_json::Value) -> Result<MapCollectionRef, JsonCollectionError>;

    /// 将 MapCollection 转换为 JSON Value
    ///
    /// # Returns
    /// * `Ok(serde_json::Value)` - 成功时返回 JSON 对象
    /// * `Err(JsonCollectionError)` - 失败时返回错误
    async fn to_json(&self) -> Result<serde_json::Value, JsonCollectionError>;
}

/// 为任意 MapCollectionRef 实现 JSON 转换
#[async_trait::async_trait]
impl JsonMapCollection for MapCollectionRef {
    async fn from_json(json: &serde_json::Value) -> Result<MapCollectionRef, JsonCollectionError> {
        let obj = json.as_object()
            .ok_or(JsonCollectionError::NotObject)?;

        let map = MemoryMapCollection::new_ref();

        for (key, value) in obj {
            let coll_value = json_value_to_collection_value(value);
            map.insert(key, coll_value).await
                .map_err(|e| JsonCollectionError::InsertFailed(e))?;
        }

        Ok(map)
    }

    async fn to_json(&self) -> Result<serde_json::Value, JsonCollectionError> {
        let map_dump = self.dump().await
            .map_err(|e| JsonCollectionError::DumpFailed(e))?;

        let mut json_obj = serde_json::Map::new();
        for (key, value) in map_dump {
            let json_value = collection_value_to_json_value(&value);
            json_obj.insert(key, json_value);
        }

        Ok(serde_json::Value::Object(json_obj))
    }
}

/// 将 JSON Value 转换为 CollectionValue
///
/// 转换规则：
/// - String -> CollectionValue::String
/// - Number -> CollectionValue::String (保留精度)
/// - Bool -> CollectionValue::String
/// - Null -> CollectionValue::String ("null")
/// - Object/Array -> CollectionValue::String (JSON 字符串表示)
pub fn json_value_to_collection_value(value: &serde_json::Value) -> CollectionValue {
    match value {
        serde_json::Value::String(s) => CollectionValue::String(s.clone()),
        serde_json::Value::Number(n) => CollectionValue::String(n.to_string()),
        serde_json::Value::Bool(b) => CollectionValue::String(b.to_string()),
        serde_json::Value::Null => CollectionValue::String("null".to_string()),
        _ => CollectionValue::String(value.to_string()),
    }
}

/// 将 CollectionValue 转换为 JSON Value
///
/// 转换规则：
/// - 尝试解析字符串为数字（i64, f64）
/// - 尝试解析字符串为布尔值
/// - 尝试解析字符串为 JSON（如果是对象或数组）
/// - 其他情况保持为字符串
pub fn collection_value_to_json_value(value: &CollectionValue) -> serde_json::Value {
    match value {
        CollectionValue::String(s) => {
            // 尝试解析为数字
            if let Ok(n) = s.parse::<i64>() {
                return serde_json::Value::Number(serde_json::Number::from(n));
            }

            // 尝试解析为浮点数
            if let Ok(f) = s.parse::<f64>() {
                if let Some(n) = serde_json::Number::from_f64(f) {
                    return serde_json::Value::Number(n);
                }
            }

            // 尝试解析为布尔值
            if let Ok(b) = s.parse::<bool>() {
                return serde_json::Value::Bool(b);
            }

            // 尝试解析为 JSON（支持嵌套对象/数组）
            if s.starts_with('{') || s.starts_with('[') {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(s) {
                    return json;
                }
            }

            // 默认返回字符串
            serde_json::Value::String(s.clone())
        }
        _ => serde_json::Value::String(value.to_string()),
    }
}

/// 简化版本：只将 JSON 转为 MapCollection，不尝试智能类型转换
pub async fn json_to_map_simple(json: &serde_json::Value) -> Result<MapCollectionRef, JsonCollectionError> {
    let obj = json.as_object()
        .ok_or(JsonCollectionError::NotObject)?;

    let map = MemoryMapCollection::new_ref();

    for (key, value) in obj {
        let coll_value = CollectionValue::String(value.to_string());
        map.insert(key, coll_value).await
            .map_err(|e| JsonCollectionError::InsertFailed(e))?;
    }

    Ok(map)
}

/// 简化版本：只将 MapCollection 转为 JSON，不尝试智能类型转换
pub async fn map_to_json_simple(map: &MapCollectionRef) -> Result<serde_json::Value, JsonCollectionError> {
    let map_dump = map.dump().await
        .map_err(|e| JsonCollectionError::DumpFailed(e))?;

    let mut json_obj = serde_json::Map::new();
    for (key, value) in map_dump {
        if let CollectionValue::String(s) = value {
            json_obj.insert(key, serde_json::Value::String(s));
        } else {
            json_obj.insert(key, serde_json::Value::String(value.to_string()));
        }
    }

    Ok(serde_json::Value::Object(json_obj))
}

pub struct JsonMap {
    file_path: String,
    map: RwLock<HashMap<String, serde_json::Value>>,
}

impl JsonMap {
    pub async fn load_from(file_path: impl Into<String>) -> Result<Self, String> {
        let file_path = file_path.into();
        let map = if Path::new(file_path.as_str()).exists() {
            let content = tokio::fs::read_to_string(file_path.as_str()).await.map_err(|e| e.to_string())?;
            if content.is_empty() {
                HashMap::new()
            } else {
                let map = serde_json::from_str::<HashMap<String, serde_json::Value>>(&content).map_err(|e| e.to_string())?;
                map
            }
        } else {
            HashMap::new()
        };
        Ok(JsonMap {
            file_path,
            map: RwLock::new(map),
        })
    }

    pub async fn save(&self) -> Result<(), String> {
        let content = {
            let map = self.map.read().unwrap();
            serde_json::to_string(map.deref()).map_err(|e| e.to_string())?
        };
        tokio::fs::write(self.file_path.as_str(), content).await.map_err(|e| e.to_string())?;
        Ok(())
    }
}
#[async_trait::async_trait]
impl MapCollection for JsonMap {
    async fn len(&self) -> Result<usize, String> {
        Ok(self.map.read().unwrap().len())
    }

    async fn insert_new(&self, key: &str, value: CollectionValue) -> Result<bool, String> {
        {
            let mut map = self.map.write().unwrap();
            if map.contains_key(key) {
                return Ok(false);
            }
            map.insert(key.to_string(), collection_value_to_json_value(&value));
        }
        self.save().await?;
        Ok(true)
    }

    async fn insert(&self, key: &str, value: CollectionValue) -> Result<Option<CollectionValue>, String> {
        let old = {
            let mut map = self.map.write().unwrap();
            map.insert(key.to_string(), collection_value_to_json_value(&value))
        };
        self.save().await?;
        Ok(old.map(|v| json_value_to_collection_value(&v)))
    }

    async fn get(&self, key: &str) -> Result<Option<CollectionValue>, String> {
        let map = self.map.read().unwrap();
        Ok(map.get(key).map(|v| json_value_to_collection_value(v)))
    }

    async fn contains_key(&self, key: &str) -> Result<bool, String> {
        Ok(self.map.read().unwrap().contains_key(key))
    }

    async fn remove(&self, key: &str) -> Result<Option<CollectionValue>, String> {
        let value = {
            let mut map = self.map.write().unwrap();
            if !map.contains_key(key) {
                return Ok(None);
            }
            map.remove(key)
        };
        self.save().await?;
        Ok(value.map(|v| json_value_to_collection_value(&v)))
    }

    async fn traverse(&self, callback: MapCollectionTraverseCallBackRef) -> Result<(), String> {
        let map = {
            let map = self.map.read().unwrap();
            map.clone()
        };
        for (key, value) in map {
            let value = json_value_to_collection_value(&value);
            callback.call(key.as_str(), &value).await?;
        }
        Ok(())
    }

    async fn dump(&self) -> Result<Vec<(String, CollectionValue)>, String> {
        let map = {
            let map = self.map.read().unwrap();
            map.clone()
        };

        Ok(map.into_iter().map(|(key, value)| (key, json_value_to_collection_value(&value))).collect())
    }
}


#[cfg(test)]
mod tests {
    use std::io::Write;
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn test_json_to_map() {
        let json = json!({
            "name": "test",
            "count": 42,
            "enabled": true,
            "score": 3.14
        });

        let map = MapCollectionRef::from_json(&json).await.unwrap();

        let name = map.get("name").await.unwrap().unwrap();
        assert_eq!(name.to_string(), "test");

        let count = map.get("count").await.unwrap().unwrap();
        assert_eq!(count.to_string(), "42");

        let enabled = map.get("enabled").await.unwrap().unwrap();
        assert_eq!(enabled.to_string(), "true");
    }

    #[tokio::test]
    async fn test_map_to_json() {
        let map = MemoryMapCollection::new_ref();
        map.insert("name", CollectionValue::String("test".to_string())).await.unwrap();
        map.insert("count", CollectionValue::String("42".to_string())).await.unwrap();
        map.insert("enabled", CollectionValue::String("true".to_string())).await.unwrap();

        let json = map.to_json().await.unwrap();

        assert_eq!(json["name"], "test");
        assert_eq!(json["count"], 42); // 应该被解析为数字
        assert_eq!(json["enabled"], true); // 应该被解析为布尔值
    }

    #[tokio::test]
    async fn test_nested_json() {
        let json = json!({
            "user": {
                "name": "Alice",
                "age": 30
            },
            "tags": ["rust", "programming"]
        });

        let map = MapCollectionRef::from_json(&json).await.unwrap();

        let user = map.get("user").await.unwrap().unwrap();
        assert!(user.to_string().contains("Alice"));
    }

    #[tokio::test]
    async fn test_round_trip() {
        let original_json = json!({
            "name": "test",
            "count": 42,
            "enabled": true
        });

        let map = MapCollectionRef::from_json(&original_json).await.unwrap();
        let result_json = map.to_json().await.unwrap();

        assert_eq!(result_json["name"], "test");
        assert_eq!(result_json["count"], 42);
        assert_eq!(result_json["enabled"], true);
    }

    #[tokio::test]
    async fn test_new_json_map() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let path = file.path().to_string_lossy().to_string();
        let map = JsonMap::load_from(path).await.unwrap();

        assert_eq!(map.len().await.unwrap(), 0);
        assert!(!map.contains_key("test").await.unwrap());

        let value = CollectionValue::String("value".to_string());
        assert!(map.insert("test", value).await.unwrap().is_none());
        assert_eq!(map.len().await.unwrap(), 1);
        assert!(map.contains_key("test").await.unwrap());

        let old_value = map.remove("test").await.unwrap();
        assert!(old_value.is_some());
        assert_eq!(old_value.unwrap().to_string(), "value");
        assert_eq!(map.len().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn test_reopen_json_map() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let path = file.path().to_string_lossy().to_string();
        {
            let map = JsonMap::load_from(path.as_str()).await.unwrap();

            assert_eq!(map.len().await.unwrap(), 0);
            assert!(!map.contains_key("test").await.unwrap());

            let value = CollectionValue::String("value".to_string());
            assert!(map.insert("test", value).await.unwrap().is_none());
            assert_eq!(map.len().await.unwrap(), 1);
            assert!(map.contains_key("test").await.unwrap());
        }
        {
            let map = JsonMap::load_from(path).await.unwrap();

            assert_eq!(map.len().await.unwrap(), 1);
            assert!(map.contains_key("test").await.unwrap());

            let old_value = map.remove("test").await.unwrap();
            assert!(old_value.is_some());
            assert_eq!(old_value.unwrap().to_string(), "value");
            assert_eq!(map.len().await.unwrap(), 0);
        }
    }

    #[tokio::test]
    async fn test_open_json_map() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(br#"{"test": "value"}"#).unwrap();
        let path = file.path().to_string_lossy().to_string();

        let map = JsonMap::load_from(path).await.unwrap();
        assert_eq!(map.len().await.unwrap(), 1);

        let value = map.get("test").await.unwrap().unwrap();
        assert_eq!(value.to_string(), "value");
        assert!(map.contains_key("test").await.unwrap());

        let old_value = map.remove("test").await.unwrap();
        assert!(old_value.is_some());
        assert_eq!(old_value.unwrap().to_string(), "value");
        assert_eq!(map.len().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn test_json_map_operations() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let path = file.path().to_string_lossy().to_string();
        let map = JsonMap::load_from(&path).await.unwrap();

        // 插入键值对
        let value1 = CollectionValue::String("first".to_string());
        assert!(map.insert("key1", value1).await.unwrap().is_none());

        // 插入另一个键值对
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
        let mut entries_map = std::collections::HashMap::new();
        for (key, value) in all_entries {
            entries_map.insert(key, value.to_string());
        }
        assert_eq!(entries_map.get("key1"), Some(&"updated".to_string()));
        assert_eq!(entries_map.get("key2"), Some(&"second".to_string()));
    }
}

