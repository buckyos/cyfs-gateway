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

    pub(crate) fn from_set(set: HashSet<String>) -> Self {
        Self {
            data: RwLock::new(set),
        }
    }

    pub fn data(&self) -> &RwLock<HashSet<String>> {
        &self.data
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

    async fn get_all(&self) -> Result<Vec<String>, String> {
        let data = self.data.read().unwrap();
        Ok(data.iter().cloned().collect())
    }
}

pub struct MemoryMapCollection {
    data: RwLock<HashMap<String, CollectionValue>>,
}

impl MemoryMapCollection {
    pub fn new() -> Self {
        Self {
            data: RwLock::new(HashMap::new()),
        }
    }

    pub(crate) fn from_map(map: HashMap<String, CollectionValue>) -> Self {
        Self {
            data: RwLock::new(map),
        }
    }

    pub fn data(&self) -> &RwLock<HashMap<String, CollectionValue>> {
        &self.data
    }
}

#[async_trait::async_trait]
impl MapCollection for MemoryMapCollection {
    async fn insert_new(&self, key: &str, value: CollectionValue) -> Result<bool, String> {
        let mut data = self.data.write().unwrap();
        match data.entry(key.to_string()) {
            std::collections::hash_map::Entry::Occupied(_) => {
                let msg = format!("Key '{}' already exists in the collection", key);
                warn!("{}", msg);
                Ok(false)
            }
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(value);
                Ok(true)
            }
        }
    }

    async fn insert(
        &self,
        key: &str,
        value: CollectionValue,
    ) -> Result<Option<CollectionValue>, String> {
        let visitor;
        {
            let mut data = self.data.write().unwrap();
            match data.entry(key.to_string()) {
                std::collections::hash_map::Entry::Occupied(mut entry) => match entry.get() {
                    CollectionValue::Visitor(v) => {
                        visitor = Some(v.clone());
                    }
                    _ => {
                        let prev = entry.insert(value);
                        return Ok(Some(prev));
                    }
                },
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(value);
                    return Ok(None);
                }
            }
        };

        let visitor = visitor.unwrap();
        visitor.set(key, value).await
    }

    async fn get(&self, key: &str) -> Result<Option<CollectionValue>, String> {
        let mut visitor;
        {
            let data = self.data.read().unwrap();
            if let Some(value) = data.get(key) {
                if let CollectionValue::Visitor(v) = value {
                    visitor = Some(v.clone());
                } else {
                    return Ok(Some(value.clone()));
                }
            } else {
                return Ok(None);
            }
        }

        loop {
            let current = visitor.unwrap();
            let ret = current.get(key).await?;

            match ret {
                CollectionValue::Visitor(v) => {
                    // If the value is a visitor, we need to call get again
                    visitor = Some(v);
                }
                _ => {
                    // If it's not a visitor, we can return the value
                    return Ok(Some(ret));
                }
            }
        }
    }

    async fn contains_key(&self, key: &str) -> Result<bool, String> {
        let data = self.data.read().unwrap();
        Ok(data.contains_key(key))
    }

    async fn remove(&self, key: &str) -> Result<Option<CollectionValue>, String> {
        let mut data = self.data.write().unwrap();
        Ok(data.remove(key))
    }

    async fn flush(&self) -> Result<(), String> {
        let list = {
            let data = self.data.read().unwrap();
            // Get all collections that are flushable
            data.iter()
                .filter_map(|(_key, item)| match item {
                    CollectionValue::Set(set) => {
                        if set.is_flushable() {
                            Some(CollectionValue::Set(set.clone()))
                        } else {
                            None
                        }
                    }
                    CollectionValue::Map(map) => {
                        if map.is_flushable() {
                            Some(CollectionValue::Map(map.clone()))
                        } else {
                            None
                        }
                    }
                    CollectionValue::MultiMap(multi_map) => {
                        if multi_map.is_flushable() {
                            Some(CollectionValue::MultiMap(multi_map.clone()))
                        } else {
                            None
                        }
                    }
                    _ => None,
                })
                .collect::<Vec<CollectionValue>>()
        };

        for item in list {
            match item {
                CollectionValue::Set(set) => {
                    set.flush().await?;
                }
                CollectionValue::Map(map) => {
                    map.flush().await?;
                }
                CollectionValue::MultiMap(multi_map) => {
                    multi_map.flush().await?;
                }
                _ => unreachable!("Unexpected collection type in flush"),
            }
        }

        Ok(())
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

    pub(crate) fn from_map(map: HashMap<String, HashSet<String>>) -> Self {
        Self {
            data: RwLock::new(map),
        }
    }

    pub fn data(&self) -> &RwLock<HashMap<String, HashSet<String>>> {
        &self.data
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

    async fn remove_many(&self, key: &str, values: &[&str]) -> Result<bool, String> {
        let mut data = self.data.write().unwrap();
        if let Some(set) = data.get_mut(key) {
            let initial_len = set.len();
            for value in values {
                set.remove(*value);
            }

            let changed = set.len() < initial_len;
            if set.is_empty() {
                data.remove(key);
            }

            return Ok(changed);
        }

        Ok(false)
    }
    async fn remove_all(&self, key: &str) -> Result<bool, String> {
        let mut data = self.data.write().unwrap();
        Ok(data.remove(key).is_some())
    }
}
