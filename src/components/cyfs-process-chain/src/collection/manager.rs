use super::coll::*;
use super::mem::{MemoryMapCollection, MemoryMultiMapCollection, MemorySetCollection};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

pub enum CollectionResult {
    Set(SetCollectionRef),
    Map(MapCollectionRef),
    MultiMap(MultiMapCollectionRef),
}

pub enum MapCollectionResult {
    Map(MapCollectionRef),
    MultiMap(MultiMapCollectionRef),
}

struct CollectionsHolder {
    set_collections: HashMap<String, SetCollectionRef>,
    map_collections: HashMap<String, MapCollectionRef>,
    multi_map_collections: HashMap<String, MultiMapCollectionRef>,
}

impl CollectionsHolder {
    fn new() -> Self {
        Self {
            set_collections: HashMap::new(),
            map_collections: HashMap::new(),
            multi_map_collections: HashMap::new(),
        }
    }

    fn is_collection_exists(&self, id: &str) -> bool {
        self.set_collections.contains_key(id) || self.map_collections.contains_key(id)
    }

    fn get_set_collection(&self, id: &str) -> Option<SetCollectionRef> {
        self.set_collections.get(id).cloned()
    }

    fn get_map_collection(&self, id: &str) -> Option<MapCollectionResult> {
        if let Some(collection) = self.map_collections.get(id) {
            return Some(MapCollectionResult::Map(collection.clone()));
        }
        if let Some(collection) = self.multi_map_collections.get(id) {
            return Some(MapCollectionResult::MultiMap(collection.clone()));
        }

        None
    }

    fn get_collection(&self, id: &str) -> Option<CollectionResult> {
        if let Some(collection) = self.set_collections.get(id) {
            return Some(CollectionResult::Set(collection.clone()));
        }
        if let Some(collection) = self.map_collections.get(id) {
            return Some(CollectionResult::Map(collection.clone()));
        }
        if let Some(collection) = self.multi_map_collections.get(id) {
            return Some(CollectionResult::MultiMap(collection.clone()));
        }

        None
    }

    async fn is_include_key(&self, id: &str, key: &str) -> Result<bool, String> {
        if let Some(collection) = self.set_collections.get(id) {
            return collection.contains(key).await;
        }
        if let Some(collection) = self.map_collections.get(id) {
            return collection.contains_key(key).await;
        }
        if let Some(collection) = self.multi_map_collections.get(id) {
            return collection.contains_key(key).await;
        }

        Ok(false)
    }

    fn add_set_collection(
        &mut self,
        id: &str,
        collection: SetCollectionRef,
    ) -> Option<SetCollectionRef> {
        if self.is_collection_exists(id) {
            let msg = format!("Collection with id '{}' already exists", id);
            warn!("{}", msg);
            return None;
        }

        self.set_collections
            .insert(id.to_string(), collection.clone());

        info!("Add set collection with id '{}' added successfully", id);

        Some(collection)
    }

    fn add_map_collection(
        &mut self,
        id: &str,
        collection: MapCollectionRef,
    ) -> Option<MapCollectionRef> {
        if self.is_collection_exists(id) {
            let msg = format!("Collection with id '{}' already exists", id);
            warn!("{}", msg);
            return None;
        }

        self.map_collections
            .insert(id.to_string(), collection.clone());

        info!("Add map collection with id '{}' added successfully", id);

        Some(collection)
    }

    fn add_multi_map_collection(
        &mut self,
        id: &str,
        collection: MultiMapCollectionRef,
    ) -> Option<MultiMapCollectionRef> {
        if self.is_collection_exists(id) {
            let msg = format!("Collection with id '{}' already exists", id);
            warn!("{}", msg);
            return None;
        }

        self.multi_map_collections
            .insert(id.to_string(), collection.clone());

        info!(
            "Add multi map collection with id '{}' added successfully",
            id
        );

        Some(collection)
    }
}

#[derive(Clone)]
pub struct Collections {
    collections: Arc<RwLock<CollectionsHolder>>,
}

impl Collections {
    pub fn new() -> Self {
        Self {
            collections: Arc::new(RwLock::new(CollectionsHolder::new())),
        }
    }

    /// Adds a set collection to the manager, if it already exists, it will return None.
    /// If the collection is added successfully, it will return the collection.
    pub async fn add_set_collection(
        &self,
        id: &str,
        collection: SetCollectionRef,
    ) -> Option<SetCollectionRef> {
        let mut collections = self.collections.write().await;
        collections.add_set_collection(id, collection)
    }

    /// Creates a new set collection with the given id and adds it to the manager.
    /// If the collection already exists, it will return None.
    pub async fn create_set_collection(&self, id: &str) -> Option<SetCollectionRef> {
        let collection: Arc<Box<dyn SetCollection>> =
            Arc::new(Box::new(MemorySetCollection::new()) as Box<dyn SetCollection>);
        self.add_set_collection(id, collection.clone()).await
    }

    pub async fn add_map_collection(
        &self,
        id: &str,
        collection: MapCollectionRef,
    ) -> Option<MapCollectionRef> {
        let mut collections = self.collections.write().await;
        collections.add_map_collection(id, collection)
    }

    /// Creates a new map collection with the given id and adds it to the manager.
    /// If the collection already exists, it will return None.
    pub async fn create_map_collection(&self, id: &str) -> Option<MapCollectionRef> {
        let collection = Arc::new(Box::new(MemoryMapCollection::new()) as Box<dyn MapCollection>);
        self.add_map_collection(id, collection.clone()).await
    }

    pub async fn add_multi_map_collection(
        &self,
        id: &str,
        collection: MultiMapCollectionRef,
    ) -> Option<MultiMapCollectionRef> {
        let mut collections = self.collections.write().await;
        collections.add_multi_map_collection(id, collection)
    }

    /// Creates a new multi map collection with the given id and adds it to the manager.
    /// If the collection already exists, it will return None
    pub async fn create_multi_map_collection(&self, id: &str) -> Option<MultiMapCollectionRef> {
        let collection =
            Arc::new(Box::new(MemoryMultiMapCollection::new()) as Box<dyn MultiMapCollection>);
        self.add_multi_map_collection(id, collection.clone()).await
    }

    pub async fn get_set_collection(&self, id: &str) -> Option<SetCollectionRef> {
        let collections = self.collections.read().await;
        collections.set_collections.get(id).cloned()
    }

    pub async fn get_map_collection(&self, id: &str) -> Option<MapCollectionResult> {
        let collections = self.collections.read().await;
        collections.get_map_collection(id)
    }

    pub async fn get_multi_map_collection(&self, id: &str) -> Option<MultiMapCollectionRef> {
        let collections = self.collections.read().await;
        collections.multi_map_collections.get(id).cloned()
    }

    pub async fn get_collection(&self, id: &str) -> Option<CollectionResult> {
        let collections = self.collections.read().await;
        collections.get_collection(id)
    }

    pub async fn is_include_key(&self, id: &str, key: &str) -> Result<bool, String> {
        let collections = self.collections.read().await;
        collections.is_include_key(id, key).await
    }

    /// Flushes all collections to persistent storage if applicable.
    pub async fn flush(&self) -> Result<(), String> {
        let collections = self.collections.read().await;

        for collection in collections.set_collections.values() {
            collection.flush().await?;
        }
        for collection in collections.map_collections.values() {
            collection.flush().await?;
        }
        for collection in collections.multi_map_collections.values() {
            collection.flush().await?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollectionLevel {
    Global,
    Chain,
}

impl Default for CollectionLevel {
    fn default() -> Self {
        CollectionLevel::Chain
    }
}

#[derive(Clone)]
pub struct CollectionManager {
    global_collections: Collections,
    chain_collections: Collections,
}

impl CollectionManager {
    pub fn new(global_collections: Collections) -> Self {
        Self {
            global_collections,
            chain_collections: Collections::new(),
        }
    }

    pub fn get_global_collections(&self) -> &Collections {
        &self.global_collections
    }

    pub fn get_chain_collections(&self) -> &Collections {
        &self.chain_collections
    }

    pub async fn add_set_collection(
        &self,
        level: CollectionLevel,
        id: &str,
        collection: SetCollectionRef,
    ) -> Option<SetCollectionRef> {
        let mut global_collections = self.global_collections.collections.write().await;
        let mut chain_collections = self.chain_collections.collections.write().await;

        // Fisrt check if the collection already exists
        if global_collections.is_collection_exists(id) || chain_collections.is_collection_exists(id)
        {
            let msg = format!("Collection with id '{}' already exists", id);
            warn!("{}", msg);
            return None;
        }
        match level {
            CollectionLevel::Global => global_collections.add_set_collection(id, collection),
            CollectionLevel::Chain => chain_collections.add_set_collection(id, collection),
        }
    }

    pub async fn create_set_collection(
        &self,
        level: CollectionLevel,
        id: &str,
    ) -> Option<SetCollectionRef> {
        let mut global_collections = self.global_collections.collections.write().await;
        let mut chain_collections = self.chain_collections.collections.write().await;

        // First check if the collection already exists
        if global_collections.is_collection_exists(id) || chain_collections.is_collection_exists(id)
        {
            let msg = format!("Collection with id '{}' already exists", id);
            warn!("{}", msg);
            return None;
        }

        let collection: Arc<Box<dyn SetCollection>> =
            Arc::new(Box::new(MemorySetCollection::new()) as Box<dyn SetCollection>);
        match level {
            CollectionLevel::Global => global_collections.add_set_collection(id, collection),
            CollectionLevel::Chain => chain_collections.add_set_collection(id, collection),
        }
    }

    pub async fn add_map_collection(
        &self,
        level: CollectionLevel,
        id: &str,
        collection: MapCollectionRef,
    ) -> Option<MapCollectionRef> {
        let mut global_collections = self.global_collections.collections.write().await;
        let mut chain_collections = self.chain_collections.collections.write().await;

        // First check if the collection already exists
        if global_collections.is_collection_exists(id) || chain_collections.is_collection_exists(id)
        {
            let msg = format!("Collection with id '{}' already exists", id);
            warn!("{}", msg);
            return None;
        }

        match level {
            CollectionLevel::Global => global_collections.add_map_collection(id, collection),
            CollectionLevel::Chain => chain_collections.add_map_collection(id, collection),
        }
    }

    pub async fn create_map_collection(
        &self,
        level: CollectionLevel,
        id: &str,
    ) -> Option<MapCollectionRef> {
        let mut global_collections = self.global_collections.collections.write().await;
        let mut chain_collections = self.chain_collections.collections.write().await;

        // First check if the collection already exists
        if global_collections.is_collection_exists(id) || chain_collections.is_collection_exists(id)
        {
            let msg = format!("Collection with id '{}' already exists", id);
            warn!("{}", msg);
            return None;
        }

        let collection = Arc::new(Box::new(MemoryMapCollection::new()) as Box<dyn MapCollection>);
        match level {
            CollectionLevel::Global => global_collections.add_map_collection(id, collection),
            CollectionLevel::Chain => chain_collections.add_map_collection(id, collection),
        }
    }

    pub async fn add_multi_map_collection(
        &self,
        level: CollectionLevel,
        id: &str,
        collection: MultiMapCollectionRef,
    ) -> Option<MultiMapCollectionRef> {
        let mut global_collections = self.global_collections.collections.write().await;
        let mut chain_collections = self.chain_collections.collections.write().await;

        // First check if the collection already exists
        if global_collections.is_collection_exists(id) || chain_collections.is_collection_exists(id)
        {
            let msg = format!("Collection with id '{}' already exists", id);
            warn!("{}", msg);
            return None;
        }

        match level {
            CollectionLevel::Global => global_collections.add_multi_map_collection(id, collection),
            CollectionLevel::Chain => chain_collections.add_multi_map_collection(id, collection),
        }
    }

    pub async fn create_multi_map_collection(
        &self,
        level: CollectionLevel,
        id: &str,
    ) -> Option<MultiMapCollectionRef> {
        let mut global_collections = self.global_collections.collections.write().await;
        let mut chain_collections = self.chain_collections.collections.write().await;

        // First check if the collection already exists
        if global_collections.is_collection_exists(id) || chain_collections.is_collection_exists(id)
        {
            let msg = format!("Collection with id '{}' already exists", id);
            warn!("{}", msg);
            return None;
        }

        let collection =
            Arc::new(Box::new(MemoryMultiMapCollection::new()) as Box<dyn MultiMapCollection>);
        match level {
            CollectionLevel::Global => global_collections.add_multi_map_collection(id, collection),
            CollectionLevel::Chain => chain_collections.add_multi_map_collection(id, collection),
        }
    }

    pub async fn get_set_collection(&self, id: &str) -> Option<SetCollectionRef> {
        // First try to get from chain collections
        if let Some(collection) = self.chain_collections.get_set_collection(id).await {
            return Some(collection);
        }

        // If not found in chain collections, try global collections
        self.global_collections.get_set_collection(id).await
    }

    pub async fn get_map_collection(&self, id: &str) -> Option<MapCollectionResult> {
        // First try to get from chain collections
        if let Some(collection) = self.chain_collections.get_map_collection(id).await {
            return Some(collection);
        }

        // If not found in chain collections, try global collections
        self.global_collections.get_map_collection(id).await
    }

    pub async fn get_multi_map_collection(&self, id: &str) -> Option<MultiMapCollectionRef> {
        // First try to get from chain collections
        if let Some(collection) = self.chain_collections.get_multi_map_collection(id).await {
            return Some(collection);
        }

        // If not found in chain collections, try global collections
        self.global_collections.get_multi_map_collection(id).await
    }

    pub async fn get_collection(&self, id: &str) -> Option<CollectionResult> {
        // First try to get from chain collections
        if let Some(collection) = self.chain_collections.get_collection(id).await {
            return Some(collection);
        }

        // If not found in chain collections, try global collections
        self.global_collections.get_collection(id).await
    }

    pub async fn flush(&self) -> Result<(), String> {
        self.global_collections.flush().await?;
        self.chain_collections.flush().await?;
        Ok(())
    }
}
