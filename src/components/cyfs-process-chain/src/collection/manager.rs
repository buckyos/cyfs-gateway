use super::coll::*;
use super::mem::{MemoryMapCollection, MemorySetCollection};
use std::collections::HashMap;
use std::sync::{Arc};
use tokio::sync::RwLock;

struct Collections {
    set_collections: HashMap<String, SetCollectionRef>,
    map_collections: HashMap<String, MapCollectionRef>,
}

impl Collections {
    fn new() -> Self {
        Self {
            set_collections: HashMap::new(),
            map_collections: HashMap::new(),
        }
    }

    fn is_collection_exists(&self, id: &str) -> bool {
        self.set_collections.contains_key(id) || self.map_collections.contains_key(id)
    }

    async fn is_include_key(&self, id: &str, key: &str) -> Result<bool, String> {
        if let Some(collection) = self.set_collections.get(id) {
            return collection.contains(key).await;
        }
        if let Some(collection) = self.map_collections.get(id) {
            return collection.contains_key(key).await;
        }

        Ok(false)
    }
}

#[derive(Clone)]
pub struct CollectionManager {
    collections: Arc<RwLock<Collections>>,
}

impl CollectionManager {
    pub fn new() -> Self {
        Self {
            collections: Arc::new(RwLock::new(Collections::new())),
        }
    }

    /// Adds a set collection to the manager, if it already exists, it will return None.
    /// If the collection is added successfully, it will return the collection.
    pub async fn add_set_collection(&self, id: &str, collection: SetCollectionRef) -> Option<SetCollectionRef> {
        let mut collections = self.collections.write().await;
        if collections.is_collection_exists(id) {
            let msg = format!("Collection with id '{}' already exists", id);
            warn!("{}", msg);
            return None;
        }

        collections
            .set_collections
            .insert(id.to_string(), collection.clone());

        info!("Add set collection with id '{}' added successfully", id);

        Some(collection)
    }

    /// Creates a new set collection with the given id and adds it to the manager.
    /// If the collection already exists, it will return an error.
    pub async fn create_set_collection(&self, id: &str) -> Option<SetCollectionRef> {
        let collection = Arc::new(Box::new(MemorySetCollection::new()) as Box<dyn SetCollection>);
        self.add_set_collection(id, collection.clone()).await
    }

    pub async fn add_map_collection(&self, id: &str, collection: MapCollectionRef) -> Option<MapCollectionRef> {
        let mut collections = self.collections.write().await;
        if collections.is_collection_exists(id) {
            let msg = format!("Collection with id '{}' already exists", id);
            warn!("{}", msg);
            return None;
        }

        collections.map_collections.insert(id.to_string(), collection.clone());

        info!("Add map collection with id '{}' added successfully", id);

        Some(collection)
    }

    /// Creates a new map collection with the given id and adds it to the manager.
    /// If the collection already exists, it will return an error.
    pub async fn create_map_collection(&self, id: &str) -> Option<MapCollectionRef> {
        let collection = Arc::new(Box::new(MemoryMapCollection::new()) as Box<dyn MapCollection>);
        self.add_map_collection(id, collection.clone()).await
    }

    pub async fn get_set_collection(&self, id: &str) -> Option<SetCollectionRef> {
        let collections = self.collections.read().await;
        collections.set_collections.get(id).cloned()
    }

    pub async fn get_map_collection(&self, id: &str) -> Option<MapCollectionRef> {
        let collections = self.collections.read().await;
        collections.map_collections.get(id).cloned()
    }

    pub async fn is_include_key(&self, id: &str, key: &str) -> Result<bool, String> {
        let collections = self.collections.read().await;
        collections.is_include_key(id, key).await
    }
}
