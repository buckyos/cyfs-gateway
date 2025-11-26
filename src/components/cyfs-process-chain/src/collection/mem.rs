use super::coll::*;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use tokio::sync::RwLock as AsyncRwLock;

pub struct TraverseGuard<'a> {
    counter: &'a AtomicU32,
}

impl<'a> TraverseGuard<'a> {
    pub fn new(counter: &'a AtomicU32) -> Self {
        counter.fetch_add(1, Ordering::SeqCst); // Increment when entering
        TraverseGuard { counter }
    }
}

impl<'a> Drop for TraverseGuard<'a> {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::SeqCst); // Decrement when leaving
    }
}

pub struct MemorySetCollection {
    data: AsyncRwLock<HashSet<String>>,
    transverse_counter: AtomicU32, // Indicates if a traversal is currently happening
}

impl MemorySetCollection {
    pub fn new() -> Self {
        Self {
            data: AsyncRwLock::new(HashSet::new()),
            transverse_counter: AtomicU32::new(0),
        }
    }

    pub fn new_ref() -> SetCollectionRef {
        Arc::new(Box::new(Self::new()) as Box<dyn SetCollection>)
    }
    
    pub(crate) fn from_set(set: HashSet<String>) -> Self {
        Self {
            data: AsyncRwLock::new(set),
            transverse_counter: AtomicU32::new(0),
        }
    }

    pub(crate) fn data(&self) -> &AsyncRwLock<HashSet<String>> {
        &self.data
    }

    pub fn is_during_traversal(&self) -> bool {
        self.transverse_counter.load(Ordering::SeqCst) > 0
    }
}

#[async_trait::async_trait]
impl SetCollection for MemorySetCollection {
    async fn len(&self) -> Result<usize, String> {
        let data = self.data.read().await;
        Ok(data.len())
    }

    async fn insert(&self, value: &str) -> Result<bool, String> {
        let mut data = self.data.write().await;
        Ok(data.insert(value.to_string()))
    }

    async fn contains(&self, key: &str) -> Result<bool, String> {
        let data = self.data.read().await;
        Ok(data.contains(key))
    }

    async fn remove(&self, key: &str) -> Result<bool, String> {
        if self.is_during_traversal() {
            let msg = format!("Cannot remove key '{}' during traversal", key);
            warn!("{}", msg);
            return Err(msg);
        }

        let mut data = self.data.write().await;
        Ok(data.remove(key))
    }

    async fn get_all(&self) -> Result<Vec<String>, String> {
        let data = self.data.read().await;
        Ok(data.iter().cloned().collect())
    }

    async fn traverse(&self, callback: SetCollectionTraverseCallBackRef) -> Result<(), String> {
        let _guard = TraverseGuard::new(&self.transverse_counter);

        let data = self.data.read().await;
        for item in data.iter() {
            if !callback.call(item).await? {
                break;
            }
        }

        Ok(())
    }
}

pub struct MemoryMapCollection {
    data: AsyncRwLock<HashMap<String, CollectionValue>>,
    transverse_counter: AtomicU32, // Indicates if a traversal is currently happening
}

impl MemoryMapCollection {
    pub fn new() -> Self {
        Self {
            data: AsyncRwLock::new(HashMap::new()),
            transverse_counter: AtomicU32::new(0),
        }
    }

    pub fn new_ref() -> MapCollectionRef {
        Arc::new(Box::new(Self::new()) as Box<dyn MapCollection>)
    }

    pub(crate) fn from_map(map: HashMap<String, CollectionValue>) -> Self {
        Self {
            data: AsyncRwLock::new(map),
            transverse_counter: AtomicU32::new(0),
        }
    }

    pub(crate) fn data(&self) -> &AsyncRwLock<HashMap<String, CollectionValue>> {
        &self.data
    }

    pub fn is_during_traversal(&self) -> bool {
        self.transverse_counter.load(Ordering::SeqCst) > 0
    }
}

#[async_trait::async_trait]
impl MapCollection for MemoryMapCollection {
    async fn len(&self) -> Result<usize, String> {
        let data = self.data.read().await;
        Ok(data.len())
    }

    async fn insert_new(&self, key: &str, value: CollectionValue) -> Result<bool, String> {
        if self.is_during_traversal() {
            let msg = format!("Cannot insert new key '{}' during traversal", key);
            warn!("{}", msg);
            return Err(msg);
        }

        let mut data = self.data.write().await;
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
        if self.is_during_traversal() {
            let msg = format!("Cannot insert key '{}' during traversal", key);
            warn!("{}", msg);
            return Err(msg);
        }

        let visitor;
        {
            let mut data = self.data.write().await;
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
            let data = self.data.read().await;
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
        let data = self.data.read().await;
        Ok(data.contains_key(key))
    }

    async fn remove(&self, key: &str) -> Result<Option<CollectionValue>, String> {
        let mut data = self.data.write().await;
        Ok(data.remove(key))
    }

    async fn traverse(&self, callback: MapCollectionTraverseCallBackRef) -> Result<(), String> {
        let _guard = TraverseGuard::new(&self.transverse_counter);

        let data = self.data.read().await;
        for (key, value) in data.iter() {
            if !callback.call(key, value).await? {
                break;
            }
        }

        Ok(())
    }

    async fn flush(&self) -> Result<(), String> {
        let list = {
            let data = self.data.read().await;
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

    async fn dump(&self) -> Result<Vec<(String, CollectionValue)>, String> {
        let data = self.data.read().await;
        Ok(data.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
    }
}

pub struct MemoryMultiMapCollection {
    data: AsyncRwLock<HashMap<String, HashSet<String>>>,
    transverse_counter: AtomicU32, // Indicates if a traversal is currently happening
}

impl MemoryMultiMapCollection {
    pub fn new() -> Self {
        Self {
            data: AsyncRwLock::new(HashMap::new()),
            transverse_counter: AtomicU32::new(0),
        }
    }

    pub(crate) fn from_map(map: HashMap<String, HashSet<String>>) -> Self {
        Self {
            data: AsyncRwLock::new(map),
            transverse_counter: AtomicU32::new(0),
        }
    }

    pub(crate) fn data(&self) -> &AsyncRwLock<HashMap<String, HashSet<String>>> {
        &self.data
    }

    pub fn is_during_traversal(&self) -> bool {
        self.transverse_counter.load(Ordering::SeqCst) > 0
    }
}

#[async_trait::async_trait]
impl MultiMapCollection for MemoryMultiMapCollection {
    async fn len(&self) -> Result<usize, String> {
        let data = self.data.read().await;
        Ok(data.len())
    }

    async fn insert(&self, key: &str, value: &str) -> Result<bool, String> {
        if self.is_during_traversal() {
            let msg = format!("Cannot insert key '{}' during traversal", key);
            warn!("{}", msg);
            return Err(msg);
        }

        let mut data = self.data.write().await;
        let entry = data.entry(key.to_string()).or_insert_with(HashSet::new);
        Ok(entry.insert(value.to_string()))
    }

    async fn insert_many(&self, key: &str, values: &[&str]) -> Result<bool, String> {
        if self.is_during_traversal() {
            let msg = format!("Cannot insert key '{}' during traversal", key);
            warn!("{}", msg);
            return Err(msg);
        }

        let mut data = self.data.write().await;
        let entry = data.entry(key.to_string()).or_insert_with(HashSet::new);
        let initial_len = entry.len();
        for value in values {
            entry.insert(value.to_string());
        }
        Ok(entry.len() > initial_len)
    }

    async fn get(&self, key: &str) -> Result<Option<String>, String> {
        let data = self.data.read().await;
        if let Some(set) = data.get(key) {
            if let Some(first_value) = set.iter().next() {
                return Ok(Some(first_value.clone()));
            }
        }

        Ok(None)
    }

    async fn get_many(&self, keys: &str) -> Result<Option<SetCollectionRef>, String> {
        let data = self.data.read().await;
        if let Some(set) = data.get(keys) {
            let collection = Arc::new(
                Box::new(MemorySetCollection::from_set(set.clone())) as Box<dyn SetCollection>
            );
            return Ok(Some(collection));
        }

        Ok(None)
    }

    async fn contains_key(&self, key: &str) -> Result<bool, String> {
        let data = self.data.read().await;
        Ok(data.contains_key(key))
    }

    async fn contains_value(&self, key: &str, value: &[&str]) -> Result<bool, String> {
        let data = self.data.read().await;
        if let Some(set) = data.get(key) {
            let mut exists = false;
            for v in value {
                if !set.contains(*v) {
                    exists = false;
                    break;
                } else {
                    exists = true;
                }
            }

            Ok(exists)
        } else {
            Ok(false)
        }
    }

    async fn remove(&self, key: &str, value: &str) -> Result<bool, String> {
        if self.is_during_traversal() {
            let msg = format!("Cannot remove key '{}' during traversal", key);
            warn!("{}", msg);
            return Err(msg);
        }

        let mut data = self.data.write().await;
        if let Some(set) = data.get_mut(key) {
            let ret = set.remove(value);

            if set.is_empty() {
                data.remove(key);
            }

            return Ok(ret);
        }

        Ok(false)
    }

    async fn remove_many(
        &self,
        key: &str,
        values: &[&str],
    ) -> Result<Option<SetCollectionRef>, String> {
        if self.is_during_traversal() {
            let msg = format!("Cannot remove key '{}' during traversal", key);
            warn!("{}", msg);
            return Err(msg);
        }

        let mut data = self.data.write().await;
        if let Some(set) = data.get_mut(key) {
            let mut removed_set = HashSet::new();
            for value in values {
                if set.remove(*value) {
                    removed_set.insert(value.to_string());
                }
            }

            if set.is_empty() {
                data.remove(key);
            }

            let coll = MemorySetCollection::from_set(removed_set);
            let coll = Arc::new(Box::new(coll) as Box<dyn SetCollection>);
            return Ok(Some(coll));
        }

        Ok(None)
    }

    async fn remove_all(&self, key: &str) -> Result<Option<SetCollectionRef>, String> {
        if self.is_during_traversal() {
            let msg = format!("Cannot remove all for key '{}' during traversal", key);
            warn!("{}", msg);
            return Err(msg);
        }

        let mut data = self.data.write().await;
        if let Some(set) = data.remove(key) {
            let coll = MemorySetCollection::from_set(set);
            let coll = Arc::new(Box::new(coll) as Box<dyn SetCollection>);
            Ok(Some(coll))
        } else {
            Ok(None)
        }
    }

    async fn traverse(
        &self,
        callback: MultiMapCollectionTraverseCallBackRef,
    ) -> Result<(), String> {
        let _guard = TraverseGuard::new(&self.transverse_counter);

        let data = self.data.read().await;
        for (key, set) in data.iter() {
            for value in set.iter() {
                if !callback.call(key, value.as_str()).await? {
                    break;
                }
            }
        }

        Ok(())
    }

    async fn dump(&self) -> Result<Vec<(String, HashSet<String>)>, String> {
        let data = self.data.read().await;
        Ok(data
            .iter()
            .map(|(k, v)| (k.clone(), v.to_owned()))
            .collect())
    }
}
