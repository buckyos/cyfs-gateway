use super::coll::*;
use std::collections::{HashMap, HashSet};
use std::sync::RwLock;

pub struct MemorySetCollection {
    data: RwLock<HashSet<String>>,
}

impl MemorySetCollection {
    pub fn new() -> Self {
        Self {
            data: RwLock::new(HashSet::new()),
        }
    }
}

#[async_trait::async_trait]
impl SetCollection for MemorySetCollection {
    async fn insert(&self, value: &str) -> Result<bool, String> {
        let mut data = self.data.write().unwrap();
        Ok(data.insert(value.to_string()))
    }

    async fn contains(&self, key: &str) -> Result<bool, String> {
        let data = self.data.read().unwrap();
        Ok(data.contains(key))
    }

    async fn remove(&self, key: &str) -> Result<bool, String> {
        let mut data = self.data.write().unwrap();
        Ok(data.remove(key))
    }
}

pub struct MemoryMapCollection {
    data: RwLock<HashMap<String, String>>,
}

impl MemoryMapCollection {
    pub fn new() -> Self {
        Self {
            data: RwLock::new(HashMap::new()),
        }
    }
}

#[async_trait::async_trait]
impl MapCollection for MemoryMapCollection {
    async fn insert(&self, key: &str, value: &str) -> Result<Option<String>, String> {
        let mut data = self.data.write().unwrap();
        let prev = data.insert(key.to_string(), value.to_string());
        Ok(prev)
    }

    async fn get(&self, key: &str) -> Result<Option<String>, String> {
        let data = self.data.read().unwrap();
        Ok(data.get(key).cloned())
    }

    async fn contains_key(&self, key: &str) -> Result<bool, String> {
        let data = self.data.read().unwrap();
        Ok(data.contains_key(key))
    }

    async fn remove(&self, key: &str) -> Result<Option<String>, String> {
        let mut data = self.data.write().unwrap();
        Ok(data.remove(key))
    }
}
