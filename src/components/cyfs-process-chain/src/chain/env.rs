use crate::collection::*;
use std::sync::{Arc, RwLock};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum EnvLevel {
    Global, // Global level environment, used for global settings, used by: export name=value
    Chain,  // Chain level environment, used for chain-wide settings, which is default
    Block,  // Block level environment, used for block-specific settings, use by: local name=value
}

impl Default for EnvLevel {
    fn default() -> Self {
        EnvLevel::Chain // Default to chain level
    }
}

impl EnvLevel {
    pub fn as_str(&self) -> &str {
        match self {
            EnvLevel::Global => "global",
            EnvLevel::Chain => "chain",
            EnvLevel::Block => "block",
        }
    }
}

#[async_trait::async_trait]
pub trait EnvExternal: Send + Sync {
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

pub type EnvRef = Arc<Env>;

pub struct Env {
    level: EnvLevel,
    values: MapCollectionRef,
    parent: Option<EnvRef>,
    external: RwLock<Option<EnvExternalRef>>,
}

pub type EnvExternalRef = Arc<Box<dyn EnvExternal>>;

impl Env {
    pub fn new(level: EnvLevel, parent: Option<EnvRef>) -> Self {
        let values = MemoryMapCollection::new();
        let values: MapCollectionRef = Arc::new(Box::new(values) as Box<dyn MapCollection>);
        let external: RwLock<Option<EnvExternalRef>> = RwLock::new(None);

        Self {
            level,
            values,
            parent,
            external,
        }
    }

    pub fn set_external(&self, external: Option<EnvExternalRef>) -> Option<EnvExternalRef> {
        let mut lock = self.external.write().unwrap();
        let old_external = lock.take();
        *lock = external;

        old_external
    }

    pub fn external(&self) -> Option<EnvExternalRef> {
        let lock = self.external.read().unwrap();
        lock.clone()
    }

    pub fn level(&self) -> EnvLevel {
        self.level
    }

    pub fn parent(&self) -> Option<&EnvRef> {
        self.parent.as_ref()
    }

    /// Register the environment to the given variable visitor manager.
    /// The key must not already exist in the environment.
    pub async fn create(&self, key: &str, value: CollectionValue) -> Result<bool, String> {
        let ret = self.values.insert_new(key, value.clone()).await?;
        if ret {
            info!("Created variable '{}' with value: {}", key, value);
        } else {
            info!(
                "Replacing existing variable '{}' with value: {}",
                key, value
            );
        }

        Ok(ret)
    }

    pub async fn set(
        &self,
        key: &str,
        value: CollectionValue,
    ) -> Result<Option<CollectionValue>, String> {
        if self.values.contains_key(key).await? {
            return self.values.insert(key, value).await;
        } else if let Some(external) = self.external() {
            if external.contains(key).await? {
                // If the key exists in the external environment, set it there
                return external.set(key, value).await;
            }
        }

        // If the key does not exist in the local environment or external environment, set in the local environment
        self.values.insert(key, value).await
    }

    #[async_recursion::async_recursion]
    pub async fn get(&self, key: &str) -> Result<Option<CollectionValue>, String> {
        // First check local values
        if let Some(value) = self.values.get(key).await? {
            return Ok(Some(value));
        }

        // If external environment is set, check it
        if let Some(external) = self.external() {
            if let Some(value) = external.get(key).await? {
                return Ok(Some(value));
            }
        }

        // Then check parent environment if exists
        if let Some(parent) = &self.parent {
            return parent.get(key).await;
        }

        Ok(None)
    }

    pub async fn remove(&self, key: &str) -> Result<Option<CollectionValue>, String> {
        if let Some(value) = self.values.remove(key).await? {
            info!("Removed variable '{}' with value: {}", key, value);
            return Ok(Some(value));
        }

        // If the key does not exist in the local environment, check external environment
        if let Some(external) = self.external() {
            if let Some(value) = external.remove(key).await? {
                info!("Removed variable '{}' from external environment with value: {}", key, value);
                return Ok(Some(value));
            }
        }

        Ok(None)
    }

    pub async fn flush(&self) -> Result<(), String> {
        // Flush the current environment's values
        self.values.flush().await
    }
}
