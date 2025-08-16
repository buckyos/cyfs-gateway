use crate::collection::CollectionValue;
use std::any::Any;
use std::sync::Arc;
use tokio::sync::RwLock as AsyncRwLock;

#[async_trait::async_trait]
pub trait EnvExternal: Any + Send + Sync {
    /// Check if external env contains the given key.
    /// This is used to check if the variable exists in the environment.
    async fn contains(&self, key: &str) -> Result<bool, String>;

    /// Get the value of the given key from the environment.
    /// If the key does not exist, return None.
    async fn get(&self, key: &str) -> Result<Option<CollectionValue>, String>;

    /// Create a new variable in the environment.
    /// If the key already exists, it will be replaced.
    async fn set(
        &self,
        key: &str,
        value: CollectionValue,
    ) -> Result<Option<CollectionValue>, String>;

    /// Remove the variable with the given key from the environment.
    /// If the key does not exist, return None.
    async fn remove(&self, key: &str) -> Result<Option<CollectionValue>, String>;
}

pub type EnvExternalRef = Arc<Box<dyn EnvExternal>>;

struct EnvExternalItem {
    id: String,
    value: EnvExternalRef,
}

pub struct EnvExternalManager {
    external: AsyncRwLock<Vec<EnvExternalItem>>,
}

impl EnvExternalManager {
    pub fn new() -> Self {
        Self {
            external: AsyncRwLock::new(Vec::new()),
        }
    }

    pub async fn add_external(&self, id: &str, value: EnvExternalRef) -> Result<(), String> {
        let mut lock = self.external.write().await;
        if lock.iter().any(|item| item.id == id) {
            let msg = format!("External environment with id '{}' already exists", id);
            error!("{}", msg);
            return Err(msg);
        }

        lock.push(EnvExternalItem {
            id: id.to_owned(),
            value,
        });
        Ok(())
    }

    pub async fn remove_external(&self, id: &str) -> Result<Option<EnvExternalRef>, String> {
        let mut lock = self.external.write().await;
        if let Some(pos) = lock.iter().position(|item| item.id == id) {
            let item = lock.remove(pos);
            Ok(Some(item.value))
        } else {
            let msg = format!("External environment with id '{}' not found", id);
            warn!("{}", msg);
            Ok(None)
        }
    }

    pub async fn get_external(&self, id: &str) -> Result<Option<EnvExternalRef>, String> {
        let lock = self.external.read().await;
        for item in lock.iter() {
            if item.id == id {
                return Ok(Some(item.value.clone()));
            }
        }

        Ok(None)
    }

    pub async fn contains(&self, key: &str) -> Result<bool, String> {
        let lock = self.external.read().await;
        for item in lock.iter() {
            if item.value.contains(key).await? {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Returns the value of the key if it exists in any external environment.
    /// If the key exists, returns true and the value, otherwise returns false and None.
    pub async fn get(&self, key: &str) -> Result<(bool, Option<CollectionValue>), String> {
        let lock = self.external.read().await;
        for item in lock.iter() {
            if item.value.contains(key).await? {
                let value = item.value.get(key).await?;
                return Ok((true, value));
            }
        }

        Ok((false, None))
    }

    /// Returns true if the key was set in any external environment, false otherwise.
    /// If the key was set, returns the old value if it existed.
    pub async fn set(
        &self,
        key: &str,
        value: &CollectionValue,
    ) -> Result<(bool, Option<CollectionValue>), String> {
        let lock = self.external.read().await;
        for item in lock.iter() {
            if item.value.contains(key).await? {
                let old_value = item.value.set(key, value.clone()).await?;
                return Ok((true, old_value));
            }
        }

        // If not found in any external environment, return false
        Ok((false, None))
    }

    /// Removes the key from all external environments.
    /// Returns true if the key was removed from any environment, false otherwise.
    pub async fn remove(&self, key: &str) -> Result<(bool, Option<CollectionValue>), String> {
        let lock = self.external.read().await;
        for item in lock.iter() {
            if item.value.contains(key).await? {
                let old_value = item.value.remove(key).await?;
                return Ok((true, old_value));
            }
        }

        Ok((false, None))
    }
}
