use super::coll::*;
use indexmap::{IndexMap, IndexSet};
use std::collections::HashSet as StdHashSet;
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

pub struct MemoryListCollection {
    data: AsyncRwLock<Vec<CollectionValue>>,
    transverse_counter: AtomicU32, // Indicates if a traversal is currently happening
}

impl MemoryListCollection {
    pub fn new() -> Self {
        Self {
            data: AsyncRwLock::new(Vec::new()),
            transverse_counter: AtomicU32::new(0),
        }
    }

    pub fn new_ref() -> ListCollectionRef {
        Arc::new(Box::new(Self::new()) as Box<dyn ListCollection>)
    }

    pub(crate) fn from_list(list: Vec<CollectionValue>) -> Self {
        Self {
            data: AsyncRwLock::new(list),
            transverse_counter: AtomicU32::new(0),
        }
    }

    pub(crate) fn data(&self) -> &AsyncRwLock<Vec<CollectionValue>> {
        &self.data
    }

    pub fn is_during_traversal(&self) -> bool {
        self.transverse_counter.load(Ordering::SeqCst) > 0
    }
}

#[async_trait::async_trait]
impl ListCollection for MemoryListCollection {
    async fn len(&self) -> Result<usize, String> {
        let data = self.data.read().await;
        Ok(data.len())
    }

    async fn push(&self, value: CollectionValue) -> Result<(), String> {
        if self.is_during_traversal() {
            let msg = "Cannot push value during traversal".to_string();
            warn!("{}", msg);
            return Err(msg);
        }

        let mut data = self.data.write().await;
        data.push(value);
        Ok(())
    }

    async fn insert(&self, index: usize, value: CollectionValue) -> Result<(), String> {
        if self.is_during_traversal() {
            let msg = format!("Cannot insert at index {} during traversal", index);
            warn!("{}", msg);
            return Err(msg);
        }

        let mut data = self.data.write().await;
        if index > data.len() {
            let msg = format!(
                "List index out of bounds for insert: {} > {}",
                index,
                data.len()
            );
            warn!("{}", msg);
            return Err(msg);
        }

        data.insert(index, value);
        Ok(())
    }

    async fn set(
        &self,
        index: usize,
        value: CollectionValue,
    ) -> Result<Option<CollectionValue>, String> {
        if self.is_during_traversal() {
            let msg = format!("Cannot set index {} during traversal", index);
            warn!("{}", msg);
            return Err(msg);
        }

        let mut data = self.data.write().await;
        if index >= data.len() {
            let msg = format!(
                "List index out of bounds for set: {} >= {}",
                index,
                data.len()
            );
            warn!("{}", msg);
            return Err(msg);
        }

        let prev = std::mem::replace(&mut data[index], value);
        Ok(Some(prev))
    }

    async fn get(&self, index: usize) -> Result<Option<CollectionValue>, String> {
        let data = self.data.read().await;
        Ok(data.get(index).cloned())
    }

    async fn remove(&self, index: usize) -> Result<Option<CollectionValue>, String> {
        if self.is_during_traversal() {
            let msg = format!("Cannot remove index {} during traversal", index);
            warn!("{}", msg);
            return Err(msg);
        }

        let mut data = self.data.write().await;
        if index >= data.len() {
            return Ok(None);
        }

        Ok(Some(data.remove(index)))
    }

    async fn pop(&self) -> Result<Option<CollectionValue>, String> {
        if self.is_during_traversal() {
            let msg = "Cannot pop value during traversal".to_string();
            warn!("{}", msg);
            return Err(msg);
        }

        let mut data = self.data.write().await;
        Ok(data.pop())
    }

    async fn clear(&self) -> Result<(), String> {
        if self.is_during_traversal() {
            let msg = "Cannot clear list during traversal".to_string();
            warn!("{}", msg);
            return Err(msg);
        }

        let mut data = self.data.write().await;
        data.clear();
        Ok(())
    }

    async fn get_all(&self) -> Result<Vec<CollectionValue>, String> {
        let data = self.data.read().await;
        Ok(data.to_vec())
    }

    async fn traverse(&self, callback: ListCollectionTraverseCallBackRef) -> Result<(), String> {
        let _guard = TraverseGuard::new(&self.transverse_counter);

        let data = self.data.read().await;
        for (index, value) in data.iter().enumerate() {
            if !callback.call(index, value).await? {
                break;
            }
        }

        Ok(())
    }

    async fn contains_all_strings(&self, values: &[String]) -> Result<bool, String> {
        if values.is_empty() {
            return Ok(true);
        }

        let mut remaining: StdHashSet<&str> = values.iter().map(|v| v.as_str()).collect();

        let data = self.data.read().await;
        for value in data.iter() {
            if let CollectionValue::String(s) = value {
                remaining.remove(s.as_str());
                if remaining.is_empty() {
                    return Ok(true);
                }
            }
        }

        Ok(remaining.is_empty())
    }
}

pub struct MemorySetCollection {
    data: AsyncRwLock<OrderedStringSet>,
    transverse_counter: AtomicU32, // Indicates if a traversal is currently happening
}

impl MemorySetCollection {
    pub fn new() -> Self {
        Self {
            data: AsyncRwLock::new(IndexSet::new()),
            transverse_counter: AtomicU32::new(0),
        }
    }

    pub fn new_ref() -> SetCollectionRef {
        Arc::new(Box::new(Self::new()) as Box<dyn SetCollection>)
    }

    pub(crate) fn from_set(set: OrderedStringSet) -> Self {
        Self {
            data: AsyncRwLock::new(set),
            transverse_counter: AtomicU32::new(0),
        }
    }

    pub(crate) fn data(&self) -> &AsyncRwLock<OrderedStringSet> {
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
        if self.is_during_traversal() {
            let msg = format!("Cannot insert key '{}' during traversal", value);
            warn!("{}", msg);
            return Err(msg);
        }

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
        Ok(data.shift_remove(key))
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

#[derive(Clone)]
pub struct MemoryMapCollection {
    data: Arc<AsyncRwLock<OrderedStringMap<CollectionValue>>>,
    transverse_counter: Arc<AtomicU32>, // Indicates if a traversal is currently happening
}

impl MemoryMapCollection {
    pub fn new() -> Self {
        Self {
            data: Arc::new(AsyncRwLock::new(IndexMap::new())),
            transverse_counter: Arc::new(AtomicU32::new(0)),
        }
    }

    pub fn new_ref() -> MapCollectionRef {
        Arc::new(Box::new(Self::new()) as Box<dyn MapCollection>)
    }

    pub(crate) fn from_map(map: OrderedStringMap<CollectionValue>) -> Self {
        Self {
            data: Arc::new(AsyncRwLock::new(map)),
            transverse_counter: Arc::new(AtomicU32::new(0)),
        }
    }

    pub(crate) fn data(&self) -> &AsyncRwLock<OrderedStringMap<CollectionValue>> {
        &self.data
    }

    pub fn is_during_traversal(&self) -> bool {
        self.transverse_counter.load(Ordering::SeqCst) > 0
    }
}

struct MemoryMapCollectionCursor {
    map: MemoryMapCollection,
    keys: std::vec::IntoIter<String>,
}

#[async_trait::async_trait]
impl MapCollectionCursor for MemoryMapCollectionCursor {
    async fn next(&mut self) -> Result<Option<(String, TypedValue)>, String> {
        let Some(key) = self.keys.next() else {
            return Ok(None);
        };

        let value = {
            let data = self.map.data.read().await;
            data.get(&key).cloned().unwrap_or(TypedValue::Null)
        };

        Ok(Some((key, value)))
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
            indexmap::map::Entry::Occupied(_) => {
                let msg = format!("Key '{}' already exists in the collection", key);
                warn!("{}", msg);
                Ok(false)
            }
            indexmap::map::Entry::Vacant(entry) => {
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
                indexmap::map::Entry::Occupied(mut entry) => match entry.get() {
                    CollectionValue::Visitor(v) => {
                        visitor = Some(v.clone());
                    }
                    _ => {
                        let prev = entry.insert(value);
                        return Ok(Some(prev));
                    }
                },
                indexmap::map::Entry::Vacant(entry) => {
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
        if self.is_during_traversal() {
            let msg = format!("Cannot remove key '{}' during traversal", key);
            warn!("{}", msg);
            return Err(msg);
        }

        let mut data = self.data.write().await;
        Ok(data.shift_remove(key))
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

    async fn cursor_owned(&self) -> Result<Box<dyn MapCollectionCursor>, String> {
        let keys = self.keys_snapshot().await?;
        Ok(Box::new(MemoryMapCollectionCursor {
            map: self.clone(),
            keys: keys.into_iter(),
        }))
    }

    async fn traverse_owned(
        &self,
        callback: MapCollectionTraverseOwnedCallBackRef,
    ) -> Result<(), String> {
        let _guard = TraverseGuard::new(&self.transverse_counter);
        let data = self.data.read().await;
        for (key, value) in data.iter() {
            if callback.call(key.clone(), value.clone()).await? == TraverseControl::Break {
                break;
            }
        }
        Ok(())
    }

    async fn keys_snapshot(&self) -> Result<Vec<String>, String> {
        let data = self.data.read().await;
        Ok(data.keys().cloned().collect())
    }

    async fn flush(&self) -> Result<(), String> {
        let list = {
            let data = self.data.read().await;
            // Get all collections that are flushable
            data.iter()
                .filter_map(|(_key, item)| match item {
                    CollectionValue::List(list) => {
                        if list.is_flushable() {
                            Some(CollectionValue::List(list.clone()))
                        } else {
                            None
                        }
                    }
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
                CollectionValue::List(list) => {
                    list.flush().await?;
                }
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

#[derive(Clone)]
pub struct MemoryMultiMapCollection {
    data: Arc<AsyncRwLock<OrderedStringMap<OrderedStringSet>>>,
    transverse_counter: Arc<AtomicU32>, // Indicates if a traversal is currently happening
}

impl MemoryMultiMapCollection {
    pub fn new() -> Self {
        Self {
            data: Arc::new(AsyncRwLock::new(IndexMap::new())),
            transverse_counter: Arc::new(AtomicU32::new(0)),
        }
    }

    pub(crate) fn from_map(map: OrderedStringMap<OrderedStringSet>) -> Self {
        Self {
            data: Arc::new(AsyncRwLock::new(map)),
            transverse_counter: Arc::new(AtomicU32::new(0)),
        }
    }

    pub(crate) fn data(&self) -> &AsyncRwLock<OrderedStringMap<OrderedStringSet>> {
        &self.data
    }

    pub fn is_during_traversal(&self) -> bool {
        self.transverse_counter.load(Ordering::SeqCst) > 0
    }
}

struct MemoryMultiMapCollectionCursor {
    map: MemoryMultiMapCollection,
    keys: std::vec::IntoIter<String>,
}

#[async_trait::async_trait]
impl MultiMapCollectionCursor for MemoryMultiMapCollectionCursor {
    async fn next(&mut self) -> Result<Option<(String, OrderedStringSet)>, String> {
        let Some(key) = self.keys.next() else {
            return Ok(None);
        };

        let values = {
            let data = self.map.data.read().await;
            data.get(&key).cloned().unwrap_or_default()
        };

        Ok(Some((key, values)))
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
        let entry = data.entry(key.to_string()).or_insert_with(IndexSet::new);
        Ok(entry.insert(value.to_string()))
    }

    async fn insert_many(&self, key: &str, values: &[&str]) -> Result<bool, String> {
        if self.is_during_traversal() {
            let msg = format!("Cannot insert key '{}' during traversal", key);
            warn!("{}", msg);
            return Err(msg);
        }

        let mut data = self.data.write().await;
        let entry = data.entry(key.to_string()).or_insert_with(IndexSet::new);
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
            let ret = set.shift_remove(value);

            if set.is_empty() {
                data.shift_remove(key);
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
            let mut removed_set = IndexSet::new();
            for value in values {
                if set.shift_remove(*value) {
                    removed_set.insert(value.to_string());
                }
            }

            if set.is_empty() {
                data.shift_remove(key);
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
        if let Some(set) = data.shift_remove(key) {
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
        'outer: for (key, set) in data.iter() {
            for value in set.iter() {
                if !callback.call(key, value.as_str()).await? {
                    break 'outer;
                }
            }
        }

        Ok(())
    }

    async fn traverse_keys(
        &self,
        callback: MultiMapCollectionKeyTraverseCallBackRef,
    ) -> Result<(), String> {
        let _guard = TraverseGuard::new(&self.transverse_counter);

        let data = self.data.read().await;
        for key in data.keys() {
            if !callback.call(key.as_str()).await? {
                break;
            }
        }

        Ok(())
    }

    async fn cursor_owned(&self) -> Result<Box<dyn MultiMapCollectionCursor>, String> {
        let keys = self.keys_snapshot().await?;
        Ok(Box::new(MemoryMultiMapCollectionCursor {
            map: self.clone(),
            keys: keys.into_iter(),
        }))
    }

    async fn traverse_owned(
        &self,
        callback: MultiMapCollectionTraverseOwnedCallBackRef,
    ) -> Result<(), String> {
        let _guard = TraverseGuard::new(&self.transverse_counter);
        let data = self.data.read().await;
        for (key, values) in data.iter() {
            if callback.call(key.clone(), values.clone()).await? == TraverseControl::Break {
                break;
            }
        }
        Ok(())
    }

    async fn keys_snapshot(&self) -> Result<Vec<String>, String> {
        let data = self.data.read().await;
        Ok(data.keys().cloned().collect())
    }

    async fn dump(&self) -> Result<Vec<(String, OrderedStringSet)>, String> {
        let data = self.data.read().await;
        Ok(data
            .iter()
            .map(|(k, v)| (k.clone(), v.to_owned()))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;

    #[tokio::test]
    async fn test_memory_list_collection_basic_ops() {
        let list = MemoryListCollection::new();

        list.push(CollectionValue::String("a".to_string()))
            .await
            .unwrap();
        list.push(CollectionValue::String("b".to_string()))
            .await
            .unwrap();
        assert_eq!(list.len().await.unwrap(), 2);

        list.insert(1, CollectionValue::String("x".to_string()))
            .await
            .unwrap();
        assert_eq!(list.len().await.unwrap(), 3);
        assert_eq!(
            list.get(1).await.unwrap().unwrap().try_as_str().unwrap(),
            "x"
        );

        let prev = list
            .set(1, CollectionValue::String("y".to_string()))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(prev.try_as_str().unwrap(), "x");
        assert_eq!(
            list.get(1).await.unwrap().unwrap().try_as_str().unwrap(),
            "y"
        );

        let removed = list.remove(0).await.unwrap().unwrap();
        assert_eq!(removed.try_as_str().unwrap(), "a");

        let popped = list.pop().await.unwrap().unwrap();
        assert_eq!(popped.try_as_str().unwrap(), "b");
        assert_eq!(list.len().await.unwrap(), 1);

        list.clear().await.unwrap();
        assert_eq!(list.len().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn test_memory_list_collection_contains_all_strings() {
        let list = MemoryListCollection::new();

        list.push(CollectionValue::String("a".to_string()))
            .await
            .unwrap();
        list.push(CollectionValue::String("b".to_string()))
            .await
            .unwrap();
        list.push(CollectionValue::Map(MemoryMapCollection::new_ref()))
            .await
            .unwrap();
        list.push(CollectionValue::String("c".to_string()))
            .await
            .unwrap();

        assert!(
            list.contains_all_strings(&["a".to_string(), "c".to_string()])
                .await
                .unwrap()
        );
        assert!(
            !list
                .contains_all_strings(&["a".to_string(), "x".to_string()])
                .await
                .unwrap()
        );
        assert!(
            list.contains_all_strings(&["a".to_string(), "a".to_string()])
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_memory_set_preserves_insertion_order() {
        let set = MemorySetCollection::new();
        assert!(set.insert("b").await.unwrap());
        assert!(set.insert("a").await.unwrap());
        assert!(set.insert("c").await.unwrap());
        assert!(!set.insert("a").await.unwrap());

        assert_eq!(
            set.get_all().await.unwrap(),
            vec!["b".to_string(), "a".to_string(), "c".to_string()]
        );

        assert!(set.remove("a").await.unwrap());
        assert!(set.insert("d").await.unwrap());
        assert_eq!(
            set.get_all().await.unwrap(),
            vec!["b".to_string(), "c".to_string(), "d".to_string()]
        );
    }

    #[tokio::test]
    async fn test_memory_map_preserves_insertion_order() {
        let map = MemoryMapCollection::new();
        map.insert("k2", CollectionValue::String("v2".to_string()))
            .await
            .unwrap();
        map.insert("k1", CollectionValue::String("v1".to_string()))
            .await
            .unwrap();
        map.insert("k3", CollectionValue::String("v3".to_string()))
            .await
            .unwrap();

        assert_eq!(
            map.keys_snapshot().await.unwrap(),
            vec!["k2".to_string(), "k1".to_string(), "k3".to_string()]
        );

        map.insert("k1", CollectionValue::String("v1b".to_string()))
            .await
            .unwrap();
        assert_eq!(
            map.keys_snapshot().await.unwrap(),
            vec!["k2".to_string(), "k1".to_string(), "k3".to_string()]
        );

        map.remove("k2").await.unwrap();
        map.insert("k4", CollectionValue::String("v4".to_string()))
            .await
            .unwrap();
        assert_eq!(
            map.keys_snapshot().await.unwrap(),
            vec!["k1".to_string(), "k3".to_string(), "k4".to_string()]
        );
    }

    #[tokio::test]
    async fn test_memory_multimap_preserves_key_and_value_order() {
        let mm = MemoryMultiMapCollection::new();
        assert!(mm.insert("svc2", "b").await.unwrap());
        assert!(mm.insert("svc2", "a").await.unwrap());
        assert!(mm.insert("svc1", "x").await.unwrap());
        assert!(mm.insert("svc2", "c").await.unwrap());
        assert!(!mm.insert("svc2", "a").await.unwrap());

        assert_eq!(
            mm.keys_snapshot().await.unwrap(),
            vec!["svc2".to_string(), "svc1".to_string()]
        );
        assert_eq!(mm.get("svc2").await.unwrap(), Some("b".to_string()));

        let values = mm.get_many("svc2").await.unwrap().unwrap();
        assert_eq!(
            values.get_all().await.unwrap(),
            vec!["b".to_string(), "a".to_string(), "c".to_string()]
        );

        assert!(mm.remove("svc2", "a").await.unwrap());
        let values = mm.get_many("svc2").await.unwrap().unwrap();
        assert_eq!(
            values.get_all().await.unwrap(),
            vec!["b".to_string(), "c".to_string()]
        );
    }

    #[tokio::test]
    async fn test_memory_multimap_traverse_stops_globally_on_false() {
        struct StopAfterFirstCall {
            count: Arc<AtomicUsize>,
        }

        #[async_trait::async_trait]
        impl MultiMapCollectionTraverseCallBack for StopAfterFirstCall {
            async fn call(&self, _key: &str, _value: &str) -> Result<bool, String> {
                self.count.fetch_add(1, Ordering::SeqCst);
                Ok(false)
            }
        }

        let mm = MemoryMultiMapCollection::new();
        mm.insert_many("k1", &["a", "b"]).await.unwrap();
        mm.insert_many("k2", &["c"]).await.unwrap();

        let count = Arc::new(AtomicUsize::new(0));
        let callback = Arc::new(Box::new(StopAfterFirstCall {
            count: count.clone(),
        }) as Box<dyn MultiMapCollectionTraverseCallBack>);

        mm.traverse(callback).await.unwrap();
        assert_eq!(
            count.load(Ordering::SeqCst),
            1,
            "traverse should stop entirely after callback returns false"
        );
    }

    #[tokio::test]
    async fn test_memory_map_remove_during_traversal_returns_error() {
        struct RemoveDuringTraverse {
            map: Arc<MemoryMapCollection>,
            got_err: Arc<AtomicBool>,
        }

        #[async_trait::async_trait]
        impl MapCollectionTraverseCallBack for RemoveDuringTraverse {
            async fn call(&self, key: &str, _value: &CollectionValue) -> Result<bool, String> {
                match self.map.remove(key).await {
                    Ok(_) => Err("remove should fail during traversal".to_string()),
                    Err(_) => {
                        self.got_err.store(true, Ordering::SeqCst);
                        Ok(false)
                    }
                }
            }
        }

        let map = Arc::new(MemoryMapCollection::new());
        map.insert("k1", CollectionValue::String("v1".to_string()))
            .await
            .unwrap();

        let got_err = Arc::new(AtomicBool::new(false));
        let callback = Arc::new(Box::new(RemoveDuringTraverse {
            map: map.clone(),
            got_err: got_err.clone(),
        }) as Box<dyn MapCollectionTraverseCallBack>);

        let ret = tokio::time::timeout(Duration::from_secs(2), map.traverse(callback)).await;
        assert!(ret.is_ok(), "traverse should not deadlock");
        ret.unwrap().unwrap();
        assert!(
            got_err.load(Ordering::SeqCst),
            "callback should observe remove error during traversal"
        );
    }

    #[tokio::test]
    async fn test_memory_map_traverse_owned_breaks() {
        struct BreakOnFirst {
            count: Arc<AtomicUsize>,
        }

        #[async_trait::async_trait]
        impl MapCollectionTraverseOwnedCallBack for BreakOnFirst {
            async fn call(
                &self,
                _key: String,
                _value: CollectionValue,
            ) -> Result<TraverseControl, String> {
                self.count.fetch_add(1, Ordering::SeqCst);
                Ok(TraverseControl::Break)
            }
        }

        let map = MemoryMapCollection::new();
        map.insert("k1", CollectionValue::String("v1".to_owned()))
            .await
            .unwrap();
        map.insert("k2", CollectionValue::String("v2".to_owned()))
            .await
            .unwrap();

        let count = Arc::new(AtomicUsize::new(0));
        let callback = Arc::new(Box::new(BreakOnFirst {
            count: count.clone(),
        }) as Box<dyn MapCollectionTraverseOwnedCallBack>);

        map.traverse_owned(callback).await.unwrap();
        assert_eq!(
            count.load(Ordering::SeqCst),
            1,
            "traverse_owned should stop at first Break"
        );
    }

    #[tokio::test]
    async fn test_memory_multimap_traverse_owned_breaks() {
        struct BreakOnFirst {
            count: Arc<AtomicUsize>,
        }

        #[async_trait::async_trait]
        impl MultiMapCollectionTraverseOwnedCallBack for BreakOnFirst {
            async fn call(
                &self,
                _key: String,
                _values: OrderedStringSet,
            ) -> Result<TraverseControl, String> {
                self.count.fetch_add(1, Ordering::SeqCst);
                Ok(TraverseControl::Break)
            }
        }

        let mm = MemoryMultiMapCollection::new();
        mm.insert_many("k1", &["a", "b"]).await.unwrap();
        mm.insert_many("k2", &["c"]).await.unwrap();

        let count = Arc::new(AtomicUsize::new(0));
        let callback = Arc::new(Box::new(BreakOnFirst {
            count: count.clone(),
        })
            as Box<dyn MultiMapCollectionTraverseOwnedCallBack>);

        mm.traverse_owned(callback).await.unwrap();
        assert_eq!(
            count.load(Ordering::SeqCst),
            1,
            "traverse_owned should stop at first Break"
        );
    }
}
