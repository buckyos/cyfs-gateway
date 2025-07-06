use std::sync::Arc;

#[async_trait::async_trait]
pub trait SetCollection: Send + Sync {
    /// Sets the collection with the given value.
    async fn insert(&self, value: &str) -> Result<bool, String>;

    /// Check if the collection contains the given value.
    async fn contains(&self, key: &str) -> Result<bool, String>;

    /// Removes the value from the collection.
    async fn remove(&self, key: &str) -> Result<bool, String>;
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