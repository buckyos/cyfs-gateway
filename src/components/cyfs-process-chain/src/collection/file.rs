use super::coll::*;
use super::mem::*;
use serde::de::{self, Visitor};
use serde::{Deserialize, Serialize};
use serde::{Deserializer, Serializer};
use std::collections::{HashMap, HashSet};
use std::marker::PhantomData;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

pub struct JsonFileCollection<T: Send + Sync + for<'a> Deserialize<'a> + Serialize + Default> {
    file: PathBuf,
    is_dirty: AtomicBool,
    data: PhantomData<T>,
}

impl<T: Send + Sync + for<'a> Deserialize<'a> + Serialize + Default> JsonFileCollection<T> {
    pub fn new(file: PathBuf) -> Self {
        Self {
            file,
            is_dirty: AtomicBool::new(false),
            data: PhantomData,
        }
    }

    fn load(&self) -> Result<T, String> {
        if self.file.exists() {
            let content = std::fs::read_to_string(&self.file).map_err(|e| {
                let msg = format!("Failed to read file {}: {}", self.file.display(), e);
                msg
            })?;

            let ret: T = serde_json::from_str(&content).map_err(|e| {
                let msg = format!(
                    "Failed to parse JSON from file {}: {}",
                    self.file.display(),
                    e
                );
                msg
            })?;

            Ok(ret)
        } else {
            Ok(T::default())
        }
    }

    fn save(&self, data: &T) -> Result<(), String> {
        let content = {
            serde_json::to_string_pretty(data).map_err(|e| {
                let msg = format!("Failed to serialize data to JSON: {}", e);
                msg
            })?
        };

        std::fs::write(&self.file, content).map_err(|e| {
            let msg = format!("Failed to write to file {}: {}", self.file.display(), e);
            msg
        })?;

        Ok(())
    }

    fn mark_dirty(&self) {
        self.is_dirty.store(true, Ordering::SeqCst);
    }

    fn clear_dirty(&self) {
        self.is_dirty.store(false, Ordering::SeqCst);
    }

    pub fn is_dirty(&self) -> bool {
        self.is_dirty.load(Ordering::SeqCst)
    }
}

#[derive(Clone)]
pub struct JsonSetCollection {
    data: Arc<MemorySetCollection>,
    file: Arc<JsonFileCollection<HashSet<String>>>,
}

impl JsonSetCollection {
    pub fn new(file: PathBuf) -> Result<Self, String> {
        let file = JsonFileCollection::new(file);
        let set = file.load()?;
        let data = MemorySetCollection::from_set(set);
        Ok(Self {
            data: Arc::new(data),
            file: Arc::new(file),
        })
    }

    pub fn flush(&self) -> Result<(), String> {
        if self.file.is_dirty() {
            self.file.save(&self.data.data().read().unwrap())?;
            self.file.clear_dirty();
        }

        Ok(())
    }
}

#[async_trait::async_trait]
impl SetCollection for JsonSetCollection {
    async fn len(&self) -> Result<usize, String> {
        self.data.len().await
    }

    async fn insert(&self, value: &str) -> Result<bool, String> {
        let ret = self.data.insert(value).await?;
        if ret {
            self.file.mark_dirty();
        }

        Ok(ret)
    }

    async fn contains(&self, key: &str) -> Result<bool, String> {
        self.data.contains(key).await
    }

    async fn remove(&self, key: &str) -> Result<bool, String> {
        let ret = self.data.remove(key).await?;
        if ret {
            self.file.mark_dirty();
        }

        Ok(ret)
    }

    async fn get_all(&self) -> Result<Vec<String>, String> {
        self.data.get_all().await
    }

    fn is_flushable(&self) -> bool {
        self.file.is_dirty()
    }
    
    async fn flush(&self) -> Result<(), String> {
        self.flush()
    }
}

impl Serialize for CollectionValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            CollectionValue::String(s) => serializer.serialize_str(s),
            _ => serializer.serialize_str(""),
        }
    }
}

impl<'de> Deserialize<'de> for CollectionValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StringVisitor;

        impl<'de> Visitor<'de> for StringVisitor {
            type Value = CollectionValue;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("string")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(CollectionValue::String(v.to_string()))
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(CollectionValue::String(v))
            }
        }

        deserializer.deserialize_string(StringVisitor)
    }
}

#[derive(Clone)]
pub struct JsonMapCollection {
    data: Arc<MemoryMapCollection>,
    file: Arc<JsonFileCollection<HashMap<String, CollectionValue>>>,
}

impl JsonMapCollection {
    pub fn new(file: PathBuf) -> Result<Self, String> {
        let file = JsonFileCollection::new(file);
        let map = file.load()?;
        let data = MemoryMapCollection::from_map(map);
        Ok(Self {
            data: Arc::new(data),
            file: Arc::new(file),
        })
    }

    pub fn flush(&self) -> Result<(), String> {
        if self.file.is_dirty() {
            self.file.save(&self.data.data().read().unwrap())?;
            self.file.clear_dirty();
        }

        Ok(())
    }
}

#[async_trait::async_trait]
impl MapCollection for JsonMapCollection {
    async fn len(&self) -> Result<usize, String> {
        self.data.len().await
    }

    async fn insert_new(&self, key: &str, value: CollectionValue) -> Result<bool, String> {
        let ret = self.data.insert_new(key, value).await?;
        if ret {
            self.file.mark_dirty();
        }

        Ok(ret)
    }

    async fn insert(
        &self,
        key: &str,
        value: CollectionValue,
    ) -> Result<Option<CollectionValue>, String> {
        let new_value = value.clone();
        let ret = self.data.insert(key, value).await?;
        if let Some(prev) = &ret {
            if let Some(false) = prev.compare_string(&new_value) {
                self.file.mark_dirty();
            }
        }

        Ok(ret)
    }

    async fn get(&self, key: &str) -> Result<Option<CollectionValue>, String> {
        self.data.get(key).await
    }

    async fn contains_key(&self, key: &str) -> Result<bool, String> {
        self.data.contains_key(key).await
    }

    async fn remove(&self, key: &str) -> Result<Option<CollectionValue>, String> {
        let ret = self.data.remove(key).await?;
        if ret.is_some() {
            self.file.mark_dirty();
        }

        Ok(ret)
    }

    fn is_flushable(&self) -> bool {
        self.file.is_dirty()
    }

    async fn flush(&self) -> Result<(), String> {
        self.flush()
    }

    async fn dump(&self) -> Result<Vec<(String, CollectionValue)>, String> {
        self.data.dump().await
    }
}

#[derive(Clone)]
pub struct JsonMultiMapCollection {
    data: Arc<MemoryMultiMapCollection>,
    file: Arc<JsonFileCollection<HashMap<String, HashSet<String>>>>,
}

impl JsonMultiMapCollection {
    pub fn new(file: PathBuf) -> Result<Self, String> {
        let file = JsonFileCollection::new(file);
        let map = file.load()?;
        let data = MemoryMultiMapCollection::from_map(map);
        Ok(Self {
            data: Arc::new(data),
            file: Arc::new(file),
        })
    }

    pub fn flush(&self) -> Result<(), String> {
        if self.file.is_dirty() {
            self.file.save(&self.data.data().read().unwrap())?;
            self.file.clear_dirty();
        }

        Ok(())
    }
}

#[async_trait::async_trait]
impl MultiMapCollection for JsonMultiMapCollection {
    async fn len(&self) -> Result<usize, String> {
        self.data.len().await
    }

    async fn insert(&self, key: &str, value: &str) -> Result<bool, String> {
        let ret = self.data.insert(key, value).await?;
        if ret {
            self.file.mark_dirty();
        }

        Ok(ret)
    }

    async fn insert_many(&self, key: &str, values: &[&str]) -> Result<bool, String> {
        let ret = self.data.insert_many(key, values).await?;
        if ret {
            self.file.mark_dirty();
        }

        Ok(ret)
    }

    async fn get(&self, key: &str) -> Result<Option<String>, String> {
        self.data.get(key).await
    }

    async fn get_many(&self, keys: &str) -> Result<Option<SetCollectionRef>, String> {
        self.data.get_many(keys).await
    }

    async fn contains_key(&self, key: &str) -> Result<bool, String> {
        self.data.contains_key(key).await
    }

    async fn remove(&self, key: &str, value: &str) -> Result<bool, String> {
        let ret = self.data.remove(key, value).await?;
        if ret {
            self.file.mark_dirty();
        }

        Ok(ret)
    }

    async fn remove_many(&self, key: &str, values: &[&str]) -> Result<Option<SetCollectionRef>, String> {
        let ret = self.data.remove_many(key, values).await?;
        if ret.is_some() && ret.as_ref().unwrap().len().await? > 0 {
            self.file.mark_dirty();
        }

        Ok(ret)
    }

    async fn remove_all(&self, key: &str) -> Result<Option<SetCollectionRef>, String> {
        let ret = self.data.remove_all(key).await?;
        if ret.is_some() {
            self.file.mark_dirty();
        }

        Ok(ret)
    }

    fn is_flushable(&self) -> bool {
        self.file.is_dirty()
    }

    async fn flush(&self) -> Result<(), String> {
        self.flush()
    }

    async fn dump(&self) -> Result<Vec<(String, HashSet<String>)>, String> {
        self.data.dump().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[tokio::test]
    async fn test_json_set_collection() {
        let temp_dir = std::env::temp_dir().join("test_json_collection");
        fs::create_dir_all(&temp_dir).unwrap();
        let file_path = temp_dir.join("test_set.json");
        println!("Using file: {:?}", file_path);
        std::fs::remove_file(&file_path).ok(); // Clean up before test
        let collection = JsonSetCollection::new(file_path.clone()).unwrap();
        assert!(collection.insert("value1").await.unwrap());
        assert!(collection.contains("value1").await.unwrap());
        assert!(collection.remove("value1").await.unwrap());
        assert!(!collection.contains("value1").await.unwrap());

        for i in 0..10 {
            collection.insert(&format!("value{}", i)).await.unwrap();
        }

        collection.flush().unwrap();

        // Test loading from file
        let loaded_collection = JsonSetCollection::new(file_path).unwrap();
        assert!(loaded_collection.contains("value5").await.unwrap());
        assert!(!loaded_collection.contains("non_existent").await.unwrap());
    }

    #[tokio::test]
    async fn test_json_map_collection() {
        let temp_dir = std::env::temp_dir().join("test_json_collection");
        fs::create_dir_all(&temp_dir).unwrap();
        let file_path = temp_dir.join("test_map.json");
        println!("Using file: {:?}", file_path);
        std::fs::remove_file(&file_path).ok(); // Clean up before test
        let collection = JsonMapCollection::new(file_path.clone()).unwrap();
        assert_eq!(
            collection
                .insert("key1", CollectionValue::String("value1".to_string()))
                .await
                .unwrap(),
            None
        );

        assert_eq!(
            collection
                .insert("key1", CollectionValue::String("value1".to_string()))
                .await
                .unwrap(),
            Some(CollectionValue::String("value1".to_string()))
        );
        assert_eq!(
            collection.get("key1").await.unwrap(),
            Some(CollectionValue::String("value1".to_string()))
        );
        assert_eq!(
            collection.remove("key1").await.unwrap(),
            Some(CollectionValue::String("value1".to_string()))
        );
        assert_eq!(collection.get("key1").await.unwrap(), None);

        for i in 0..10 {
            collection
                .insert(
                    &format!("key{}", i),
                    CollectionValue::String(format!("value{}", i)),
                )
                .await
                .unwrap();
        }

        collection.flush().unwrap();

        // Test loading from file
        let loaded_collection = JsonMapCollection::new(file_path).unwrap();
        assert_eq!(
            loaded_collection.get("key5").await.unwrap(),
            Some(CollectionValue::String("value5".to_string()))
        );
        assert_eq!(loaded_collection.get("non_existent").await.unwrap(), None);
    }

    #[tokio::test]
    async fn test_json_multi_map_collection() {
        let temp_dir = std::env::temp_dir().join("test_json_collection");
        fs::create_dir_all(&temp_dir).unwrap();
        let file_path = temp_dir.join("test_multi_map.json");
        println!("Using file: {:?}", file_path);
        std::fs::remove_file(&file_path).ok(); // Clean up before test
        let collection = JsonMultiMapCollection::new(file_path.clone()).unwrap();

        assert!(collection.insert("key1", "value1").await.unwrap());
        assert!(collection.insert("key1", "value2").await.unwrap());
        assert!(collection.get("key1").await.unwrap().is_some());

        let changed = collection
            .insert_many("key1", &["value1", "value2"])
            .await
            .unwrap();
        assert!(!changed); // No change since values already exist

        let ret = collection.get_many("key1").await.unwrap();
        assert!(ret.is_some());
        let ret = ret.unwrap();
        assert!(ret.contains("value1").await.unwrap());
        assert!(ret.contains("value2").await.unwrap());

        let values = collection.get_many("key1").await.unwrap().unwrap();
        assert!(values.contains("value1").await.unwrap());
        assert!(values.contains("value2").await.unwrap());

        assert!(collection.remove("key1", "value1").await.unwrap());
        assert_eq!(
            collection.get("key1").await.unwrap(),
            Some("value2".to_string())
        );

        let ret = collection.get_many("key1").await.unwrap();
        assert!(ret.is_some());
        let ret = ret.unwrap();
        assert!(ret.contains("value2").await.unwrap());
        assert!(!ret.contains("value1").await.unwrap());

        // Insert multiple values
        for i in 1..10 {
            let value_list: Vec<String> = (0..i + 2).map(|j| format!("value{}", j)).collect();
            let value_list: Vec<&str> = value_list.iter().map(|s| s.as_str()).collect();
            collection
                .insert_many(&format!("key{}", i), &value_list)
                .await
                .unwrap();
        }

        collection.flush().unwrap();

        // Test loading from file
        let loaded_collection = JsonMultiMapCollection::new(file_path).unwrap();
        assert!(loaded_collection.get("key1").await.unwrap().is_some());

        for i in 1..10 {
            let key = format!("key{}", i);
            let value = format!("value{}", i);
            assert!(loaded_collection.get(&key).await.unwrap().is_some());
            assert!(loaded_collection.contains_key(&key).await.unwrap());
            assert!(loaded_collection.remove(&key, &value).await.unwrap());
            assert!(loaded_collection.contains_key(&key).await.unwrap());

            let values = loaded_collection.get_many(&key).await.unwrap();
            assert!(values.is_some());

            // remove all values for the key
            assert!(loaded_collection.remove_all(&key).await.unwrap().is_some());
            assert!(!loaded_collection.contains_key(&key).await.unwrap());
        }
    }
}
