use cyfs_process_chain::{CollectionValue, MapCollectionRef, MemoryMapCollection};

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

#[cfg(test)]
mod tests {
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
}

