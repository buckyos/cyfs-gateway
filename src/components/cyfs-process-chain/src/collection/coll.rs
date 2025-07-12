use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CollectionType {
    Set,
    Map,
    MultiMap,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CollectionFileFormat {
    Json,
    Sqlite,
}

#[async_trait::async_trait]
pub trait SetCollection: Send + Sync {
    /// Sets the collection with the given value.
    async fn insert(&self, value: &str) -> Result<bool, String>;

    /// Check if the collection contains the given value.
    async fn contains(&self, key: &str) -> Result<bool, String>;

    /// Removes the value from the collection.
    async fn remove(&self, key: &str) -> Result<bool, String>;

    /// Gets all values in the collection.
    async fn get_all(&self) -> Result<Vec<String>, String>;
}

pub type SetCollectionRef = Arc<Box<dyn SetCollection>>;

#[async_trait::async_trait]
pub trait MapCollection: Send + Sync {
    /// Sets the value for the given key in the collection.
    async fn insert(&self, key: &str, value: &str) -> Result<Option<String>, String>;

    /// Gets the value for the given key from the collection.
    async fn get(&self, key: &str) -> Result<Option<String>, String>;

    /// Checks if the collection contains the given key.
    async fn contains_key(&self, key: &str) -> Result<bool, String>;

    /// Removes the key from the collection.
    async fn remove(&self, key: &str) -> Result<Option<String>, String>;
}

pub type MapCollectionRef = Arc<Box<dyn MapCollection>>;

#[async_trait::async_trait]
pub trait MultiMapCollection: Send + Sync {
    /// Sets the value for the given key in the collection.
    async fn insert(&self, key: &str, value: &str) -> Result<bool, String>;

    /// Inserts multiple values for the given key in the collection.
    async fn insert_many(&self, key: &str, values: &[&str]) -> Result<bool, String>;

    /// Gets first value for the given key from the collection.
    async fn get(&self, key: &str) -> Result<Option<String>, String>;

    /// Gets all values for the given key from the collection.
    async fn get_many(&self, keys: &str) -> Result<Option<SetCollectionRef>, String>;

    /// Checks if the collection contains the given key.
    async fn contains_key(&self, key: &str) -> Result<bool, String>;

    /// Removes the value for the given key from the collection.
    /// If the key or value is not found, it returns false.
    async fn remove(&self, key: &str, value: &str) -> Result<bool, String>;

    /// Removes the values for the given key from the collection.
    /// if any value is removed, it returns true
    async fn remove_many(&self, key: &str, values: &[&str]) -> Result<bool, String>;

    /// Removes all values for the given key from the collection.
    /// If the key is not found, it returns false.
    async fn remove_all(&self, key: &str) -> Result<bool, String>;
}

pub type MultiMapCollectionRef = Arc<Box<dyn MultiMapCollection>>;
