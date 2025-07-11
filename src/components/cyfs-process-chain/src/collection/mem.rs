use super::coll::*;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

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

pub struct MemoryMultiMapCollection {
    data: RwLock<HashMap<String, HashSet<String>>>,
}

impl MemoryMultiMapCollection {
    pub fn new() -> Self {
        Self {
            data: RwLock::new(HashMap::new()),
        }
    }
}

#[async_trait::async_trait]
impl MultiMapCollection for MemoryMultiMapCollection {
    async fn insert(&self, key: &str, value: &str) -> Result<bool, String> {
        let mut data = self.data.write().unwrap();
        let entry = data.entry(key.to_string()).or_insert_with(HashSet::new);
        Ok(entry.insert(value.to_string()))
    }

    async fn insert_many(&self, key: &str, values: &[&str]) -> Result<bool, String> {
        let mut data = self.data.write().unwrap();
        let entry = data.entry(key.to_string()).or_insert_with(HashSet::new);
        let initial_len = entry.len();
        for value in values {
            entry.insert(value.to_string());
        }
        Ok(entry.len() > initial_len)
    }

    async fn get(&self, key: &str) -> Result<Option<String>, String> {
        let data = self.data.read().unwrap();
        if let Some(set) = data.get(key) {
            if let Some(first_value) = set.iter().next() {
                return Ok(Some(first_value.clone()));
            }
        }

        Ok(None)
    }

    async fn get_many(&self, keys: &str) -> Result<Option<SetCollectionRef>, String> {
        let data = self.data.read().unwrap();
        if let Some(set) = data.get(keys) {
            let collection = Arc::new(Box::new(MemorySetCollection {
                data: RwLock::new(set.clone()),
            }) as Box<dyn SetCollection>);
            return Ok(Some(collection));
        }

        Ok(None)
    }

    async fn contains_key(&self, key: &str) -> Result<bool, String> {
        let data = self.data.read().unwrap();
        Ok(data.contains_key(key))
    }

    async fn remove(&self, key: &str, value: &str) -> Result<bool, String> {
        let mut data = self.data.write().unwrap();
        if let Some(set) = data.get_mut(key) {
            let ret = set.remove(value);

            if set.is_empty() {
                data.remove(key);
            }

            return Ok(ret);
        }

        Ok(false)
    }

    async fn remove_all(&self, key: &str) -> Result<bool, String> {
        let mut data = self.data.write().unwrap();
        Ok(data.remove(key).is_some())
    }
}
