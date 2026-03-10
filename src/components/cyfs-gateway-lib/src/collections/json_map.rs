use buckyos_kit::get_by_json_path;
use cyfs_process_chain::{
    CollectionValue, MapCollection, MapCollectionRef, MapCollectionTraverseCallBackRef,
    MemoryListCollection, MemoryMapCollection,
};
use std::collections::HashMap;
use std::future::Future;
use std::ops::Deref;
use std::path::Path;
use std::pin::Pin;
use std::sync::RwLock;

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
        let obj = json.as_object().ok_or(JsonCollectionError::NotObject)?;

        let map = MemoryMapCollection::new_ref();

        for (key, value) in obj {
            let coll_value = json_value_to_collection_value(value).await;
            map.insert(key, coll_value)
                .await
                .map_err(|e| JsonCollectionError::InsertFailed(e))?;
        }

        Ok(map)
    }

    async fn to_json(&self) -> Result<serde_json::Value, JsonCollectionError> {
        let map_dump = self
            .dump()
            .await
            .map_err(|e| JsonCollectionError::DumpFailed(e))?;

        let mut json_obj = serde_json::Map::new();
        for (key, value) in map_dump {
            let json_value = collection_value_to_json_value(&value).await;
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
/// - Object -> CollectionValue::Map
/// - Array -> CollectionValue::List
pub fn json_value_to_collection_value<'a>(
    value: &'a serde_json::Value,
) -> Pin<Box<dyn Future<Output = CollectionValue> + Send + 'a>> {
    Box::pin(async move {
        match value {
            serde_json::Value::String(s) => CollectionValue::String(s.clone()),
            serde_json::Value::Number(n) => CollectionValue::String(n.to_string()),
            serde_json::Value::Bool(b) => CollectionValue::String(b.to_string()),
            serde_json::Value::Null => CollectionValue::String("null".to_string()),
            serde_json::Value::Array(items) => {
                let list = MemoryListCollection::new_ref();
                for item in items {
                    let value = json_value_to_collection_value(item).await;
                    list.push(value).await.expect(
                        "MemoryListCollection::push should not fail during json conversion",
                    );
                }
                CollectionValue::List(list)
            }
            serde_json::Value::Object(entries) => {
                let map = MemoryMapCollection::new_ref();
                for (key, item) in entries {
                    let value = json_value_to_collection_value(item).await;
                    map.insert(key, value).await.expect(
                        "MemoryMapCollection::insert should not fail during json conversion",
                    );
                }
                CollectionValue::Map(map)
            }
        }
    })
}

/// 将 CollectionValue 转换为 JSON Value
///
/// 转换规则：
/// - 尝试解析字符串为数字（i64, f64）
/// - 尝试解析字符串为布尔值
/// - 尝试解析字符串为 JSON（如果是对象或数组）
/// - 其他情况保持为字符串
pub fn collection_value_to_json_value<'a>(
    value: &'a CollectionValue,
) -> Pin<Box<dyn Future<Output = serde_json::Value> + Send + 'a>> {
    Box::pin(async move {
        match value {
            CollectionValue::Null => serde_json::Value::Null,
            CollectionValue::Bool(v) => serde_json::Value::Bool(*v),
            CollectionValue::Number(v) => {
                if let Ok(n) = v.to_string().parse::<i64>() {
                    serde_json::Value::Number(serde_json::Number::from(n))
                } else if let Ok(f) = v.to_string().parse::<f64>() {
                    match serde_json::Number::from_f64(f) {
                        Some(n) => serde_json::Value::Number(n),
                        None => serde_json::Value::String(v.to_string()),
                    }
                } else {
                    serde_json::Value::String(v.to_string())
                }
            }
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
            CollectionValue::Set(set) => match set.dump().await {
                Ok(values) => serde_json::Value::Array(
                    values.into_iter().map(serde_json::Value::String).collect(),
                ),
                Err(e) => {
                    warn!("Failed to dump set for json conversion: {}", e);
                    serde_json::Value::String("[Set]".to_string())
                }
            },
            CollectionValue::List(list) => match list.dump().await {
                Ok(values) => {
                    let mut arr = Vec::with_capacity(values.len());
                    for item in values {
                        arr.push(collection_value_to_json_value(&item).await);
                    }
                    serde_json::Value::Array(arr)
                }
                Err(e) => {
                    warn!("Failed to dump list for json conversion: {}", e);
                    serde_json::Value::String("[List]".to_string())
                }
            },
            CollectionValue::Map(map) => match map.dump().await {
                Ok(entries) => {
                    let mut obj = serde_json::Map::new();
                    for (key, item) in entries {
                        obj.insert(key, collection_value_to_json_value(&item).await);
                    }
                    serde_json::Value::Object(obj)
                }
                Err(e) => {
                    warn!("Failed to dump map for json conversion: {}", e);
                    serde_json::Value::String("[Map]".to_string())
                }
            },
            CollectionValue::MultiMap(multi_map) => match multi_map.dump().await {
                Ok(entries) => {
                    let mut obj = serde_json::Map::new();
                    for (key, values) in entries {
                        obj.insert(
                            key,
                            serde_json::Value::Array(
                                values.into_iter().map(serde_json::Value::String).collect(),
                            ),
                        );
                    }
                    serde_json::Value::Object(obj)
                }
                Err(e) => {
                    warn!("Failed to dump multi map for json conversion: {}", e);
                    serde_json::Value::String("[MultiMap]".to_string())
                }
            },
            CollectionValue::Visitor(_) => serde_json::Value::String("[Visitor]".to_string()),
            CollectionValue::Any(_) => serde_json::Value::String("[Any]".to_string()),
        }
    })
}

/// 简化版本：只将 JSON 转为 MapCollection，不尝试智能类型转换
pub async fn json_to_map_simple(
    json: &serde_json::Value,
) -> Result<MapCollectionRef, JsonCollectionError> {
    let obj = json.as_object().ok_or(JsonCollectionError::NotObject)?;

    let map = MemoryMapCollection::new_ref();

    for (key, value) in obj {
        let coll_value = CollectionValue::String(value.to_string());
        map.insert(key, coll_value)
            .await
            .map_err(|e| JsonCollectionError::InsertFailed(e))?;
    }

    Ok(map)
}

/// 简化版本：只将 MapCollection 转为 JSON，不尝试智能类型转换
pub async fn map_to_json_simple(
    map: &MapCollectionRef,
) -> Result<serde_json::Value, JsonCollectionError> {
    let map_dump = map
        .dump()
        .await
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
    source_file_path: String,
    json_path: Option<String>,
    only_read_file: bool,
    map: RwLock<HashMap<String, serde_json::Value>>,
}

impl JsonMap {
    pub async fn load_from(file_path: impl Into<String>) -> Result<Self, String> {
        Self::open(file_path, false).await
    }

    pub async fn open(file_path: impl Into<String>, only_read_file: bool) -> Result<Self, String> {
        let file_path = file_path.into();
        let (source_file_path, json_path) = Self::parse_file_spec(file_path.as_str());
        if json_path.is_some() && !only_read_file {
            return Err(format!(
                "json_map {} with #json_path requires only_read_file=true",
                file_path
            ));
        }
        let map = Self::load_map_from_path(source_file_path.as_str(), json_path.as_deref()).await?;
        Ok(JsonMap {
            file_path,
            source_file_path,
            json_path,
            only_read_file,
            map: RwLock::new(map),
        })
    }

    async fn load_map_from_path(
        file_path: &str,
        json_path: Option<&str>,
    ) -> Result<HashMap<String, serde_json::Value>, String> {
        if Path::new(file_path).exists() {
            let content = tokio::fs::read_to_string(file_path)
                .await
                .map_err(|e| e.to_string())?;
            if content.is_empty() {
                Ok(HashMap::new())
            } else {
                let root = serde_json::from_str::<serde_json::Value>(&content)
                    .map_err(|e| e.to_string())?;
                let target = if let Some(json_path) = json_path {
                    get_by_json_path(&root, json_path).ok_or_else(|| {
                        format!("json_map {} cannot find json_path {}", file_path, json_path)
                    })?
                } else {
                    root
                };

                match target {
                    serde_json::Value::Object(map) => Ok(map.into_iter().collect()),
                    _ => Err(format!(
                        "json_map {} target is not a JSON object",
                        if let Some(json_path) = json_path {
                            format!("{}#{}", file_path, json_path)
                        } else {
                            file_path.to_string()
                        }
                    )),
                }
            }
        } else {
            Ok(HashMap::new())
        }
    }

    fn parse_file_spec(file_path: &str) -> (String, Option<String>) {
        if let Some((source_file_path, json_path)) = file_path.split_once('#') {
            let json_path = json_path.trim();
            if json_path.is_empty() {
                (source_file_path.to_string(), None)
            } else {
                (source_file_path.to_string(), Some(json_path.to_string()))
            }
        } else {
            (file_path.to_string(), None)
        }
    }

    async fn read_snapshot(&self) -> Result<HashMap<String, serde_json::Value>, String> {
        if self.only_read_file {
            Self::load_map_from_path(self.source_file_path.as_str(), self.json_path.as_deref())
                .await
        } else {
            Ok(self.map.read().unwrap().clone())
        }
    }

    fn read_only_err(&self) -> String {
        format!(
            "json_map {} is read-only because only_read_file is enabled",
            self.file_path
        )
    }

    pub async fn save(&self) -> Result<(), String> {
        if self.only_read_file {
            return Err(self.read_only_err());
        }
        let content = {
            let map = self.map.read().unwrap();
            serde_json::to_string(map.deref()).map_err(|e| e.to_string())?
        };
        tokio::fs::write(self.source_file_path.as_str(), content)
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}
#[async_trait::async_trait]
impl MapCollection for JsonMap {
    async fn len(&self) -> Result<usize, String> {
        Ok(self.read_snapshot().await?.len())
    }

    async fn insert_new(&self, key: &str, value: CollectionValue) -> Result<bool, String> {
        if self.only_read_file {
            return Err(self.read_only_err());
        }
        let json_value = collection_value_to_json_value(&value).await;
        {
            let mut map = self.map.write().unwrap();
            if map.contains_key(key) {
                return Ok(false);
            }
            map.insert(key.to_string(), json_value);
        }
        self.save().await?;
        Ok(true)
    }

    async fn insert(
        &self,
        key: &str,
        value: CollectionValue,
    ) -> Result<Option<CollectionValue>, String> {
        if self.only_read_file {
            return Err(self.read_only_err());
        }
        let json_value = collection_value_to_json_value(&value).await;
        let old = {
            let mut map = self.map.write().unwrap();
            map.insert(key.to_string(), json_value)
        };
        self.save().await?;
        Ok(match old {
            Some(v) => Some(json_value_to_collection_value(&v).await),
            None => None,
        })
    }

    async fn get(&self, key: &str) -> Result<Option<CollectionValue>, String> {
        let map = self.read_snapshot().await?;
        if let Some(value) = map.get(key) {
            Ok(Some(json_value_to_collection_value(value).await))
        } else {
            Ok(None)
        }
    }

    async fn contains_key(&self, key: &str) -> Result<bool, String> {
        Ok(self.read_snapshot().await?.contains_key(key))
    }

    async fn remove(&self, key: &str) -> Result<Option<CollectionValue>, String> {
        if self.only_read_file {
            return Err(self.read_only_err());
        }
        let value = {
            let mut map = self.map.write().unwrap();
            if !map.contains_key(key) {
                return Ok(None);
            }
            map.remove(key)
        };
        self.save().await?;
        Ok(match value {
            Some(v) => Some(json_value_to_collection_value(&v).await),
            None => None,
        })
    }

    async fn traverse(&self, callback: MapCollectionTraverseCallBackRef) -> Result<(), String> {
        let map = self.read_snapshot().await?;
        for (key, value) in map {
            let value = json_value_to_collection_value(&value).await;
            callback.call(key.as_str(), &value).await?;
        }
        Ok(())
    }

    async fn dump(&self) -> Result<Vec<(String, CollectionValue)>, String> {
        let map = self.read_snapshot().await?;
        let mut result = Vec::with_capacity(map.len());
        for (key, value) in map {
            result.push((key, json_value_to_collection_value(&value).await));
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cyfs_process_chain::MemorySetCollection;
    use serde_json::json;
    use std::io::Write;

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
        map.insert("name", CollectionValue::String("test".to_string()))
            .await
            .unwrap();
        map.insert("count", CollectionValue::String("42".to_string()))
            .await
            .unwrap();
        map.insert("enabled", CollectionValue::String("true".to_string()))
            .await
            .unwrap();

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
        let user = match user {
            CollectionValue::Map(user) => user,
            other => panic!("expected map, got {}", other.get_type()),
        };
        assert_eq!(
            user.get("name").await.unwrap().unwrap().to_string(),
            "Alice"
        );
        assert_eq!(user.get("age").await.unwrap().unwrap().to_string(), "30");

        let tags = map.get("tags").await.unwrap().unwrap();
        let tags = match tags {
            CollectionValue::List(tags) => tags,
            other => panic!("expected list, got {}", other.get_type()),
        };
        assert_eq!(tags.get(0).await.unwrap().unwrap().to_string(), "rust");
        assert_eq!(
            tags.get(1).await.unwrap().unwrap().to_string(),
            "programming"
        );
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
    async fn test_collection_value_to_json_value_all_types() {
        let set = MemorySetCollection::new_ref();
        set.insert("a").await.unwrap();
        set.insert("b").await.unwrap();

        let nested_map = MemoryMapCollection::new_ref();
        nested_map
            .insert("k", CollectionValue::String("1".to_string()))
            .await
            .unwrap();

        let set_json = collection_value_to_json_value(&CollectionValue::Set(set)).await;
        assert!(set_json.as_array().is_some());

        let map_json = collection_value_to_json_value(&CollectionValue::Map(nested_map)).await;
        assert_eq!(map_json["k"], 1);
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

    #[tokio::test]
    async fn test_json_map_only_read_file_reload_on_every_read() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(br#"{"test": "value1"}"#).unwrap();
        file.flush().unwrap();
        let path = file.path().to_string_lossy().to_string();

        let map = JsonMap::open(path.as_str(), true).await.unwrap();
        let value = map.get("test").await.unwrap().unwrap();
        assert_eq!(value.to_string(), "value1");

        std::fs::write(path.as_str(), br#"{"test": "value2", "new_key": 1}"#).unwrap();

        let value = map.get("test").await.unwrap().unwrap();
        assert_eq!(value.to_string(), "value2");
        assert!(map.contains_key("new_key").await.unwrap());
        assert_eq!(map.len().await.unwrap(), 2);
    }

    #[tokio::test]
    async fn test_json_map_only_read_file_rejects_write_operations() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(br#"{"test": "value"}"#).unwrap();
        file.flush().unwrap();
        let path = file.path().to_string_lossy().to_string();

        let map = JsonMap::open(path.as_str(), true).await.unwrap();

        let err = map
            .insert("test", CollectionValue::String("changed".to_string()))
            .await
            .unwrap_err();
        assert!(err.contains("only_read_file"));

        let err = map
            .insert_new("new_key", CollectionValue::String("value".to_string()))
            .await
            .unwrap_err();
        assert!(err.contains("only_read_file"));

        let err = map.remove("test").await.unwrap_err();
        assert!(err.contains("only_read_file"));

        let content = std::fs::read_to_string(path).unwrap();
        assert_eq!(content, r#"{"test": "value"}"#);
    }

    #[tokio::test]
    async fn test_json_map_reads_object_as_map() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(br#"{"app":{"appid":"filebrowser","url":"http://127.0.0.1:10160"}}"#)
            .unwrap();
        file.flush().unwrap();
        let path = file.path().to_string_lossy().to_string();

        let map = JsonMap::open(path.as_str(), true).await.unwrap();
        let app = map.get("app").await.unwrap().unwrap();
        assert_eq!(app.get_type(), "Map");

        let app = match app {
            CollectionValue::Map(app) => app,
            other => panic!("expected map, got {}", other.get_type()),
        };

        let appid = app.get("appid").await.unwrap().unwrap();
        assert_eq!(appid.to_string(), "filebrowser");
        let url = app.get("url").await.unwrap().unwrap();
        assert_eq!(url.to_string(), "http://127.0.0.1:10160");
    }

    #[tokio::test]
    async fn test_json_map_reads_object_from_json_path() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(
            br#"{"app_info":{"appid":"filebrowser","url":"http://127.0.0.1:10160"},"other":{"k":"v"}}"#,
        )
        .unwrap();
        file.flush().unwrap();
        let path = format!("{}#app_info", file.path().to_string_lossy());

        let map = JsonMap::open(path.as_str(), true).await.unwrap();
        let appid = map.get("appid").await.unwrap().unwrap();
        assert_eq!(appid.to_string(), "filebrowser");
        let url = map.get("url").await.unwrap().unwrap();
        assert_eq!(url.to_string(), "http://127.0.0.1:10160");
        assert!(!map.contains_key("other").await.unwrap());
    }

    #[tokio::test]
    async fn test_json_map_json_path_requires_only_read_file() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let path = format!("{}#app_info", file.path().to_string_lossy());

        let err = JsonMap::open(path.as_str(), false).await.err().unwrap();
        assert!(err.contains("only_read_file=true"));
    }
}
