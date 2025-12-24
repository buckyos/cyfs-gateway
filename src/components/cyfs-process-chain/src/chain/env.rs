use super::external::EnvExternalManager;
use crate::collection::*;
use std::{str::FromStr, sync::Arc};

use log::{log, Level};

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

impl FromStr for EnvLevel {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "global" => Ok(EnvLevel::Global),
            "chain" => Ok(EnvLevel::Chain),
            "block" => Ok(EnvLevel::Block),
            _ => Err(format!("Invalid environment level: {}", s)),
        }
    }
}

pub type EnvRef = Arc<Env>;

pub struct Env {
    level: EnvLevel,
    values: MapCollectionRef,
    parent: Option<EnvRef>,
    external: EnvExternalManager,
    debug_level: Level,
}

impl Env {
    pub fn new(level: EnvLevel, parent: Option<EnvRef>) -> Self {
        let values = MemoryMapCollection::new();
        let values = Arc::new(Box::new(values) as Box<dyn MapCollection>);
        let external = EnvExternalManager::new();
        Self {
            level,
            values,
            parent,
            external,
            debug_level: Level::Debug,
        }
    }

    pub fn env_external_manager(&self) -> &EnvExternalManager {
        &self.external
    }

    pub fn level(&self) -> EnvLevel {
        self.level
    }

    pub fn parent(&self) -> Option<&EnvRef> {
        self.parent.as_ref()
    }

    pub fn create_child_env(self: &Arc<Self>, level: EnvLevel) -> EnvRef {
        Arc::new(Env::new(level, Some(self.clone())))
    }

    /// Convert LevelFilter to Level for logging
    pub fn log_level(&self) -> Level {
        self.debug_level
    }
    
    /// Check if the environment contains the given key.
    /// This will first check the local environment, then the external environment if set, and will not check parent environment.
    /// If the key does not exist in the local environment or external environment, it will return false.
    pub async fn contains(&self, key: &str) -> Result<bool, String> {
        // First check local values
        if self.values.contains_key(key).await? {
            return Ok(true);
        }

        // If external environment is set, check it
        if self.external.contains(key).await? {
            return Ok(true);
        }

        // Should not check parent environment here, as this is a top-level check
        // If the key does not exist in the local environment or external environment, return false

        Ok(false)
    }

    /// Register the environment to the given variable visitor manager.
    /// The key must not already exist in the environment.
    pub async fn create(&self, key: &str, value: CollectionValue) -> Result<bool, String> {
        let ret = self.values.insert_new(key, value.clone()).await?;
        let log_level = self.log_level();
        if ret {
            log!(log_level, "Created variable '{}' with value: {}", key, value);
        } else {
            log!(
                log_level,
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
        } else {
            // Try to set in external environment if it exists
            let (handled, old_value) = self.external.set(key, &value).await?;
            if handled {
                log!(
                    self.log_level(),
                    "Set variable '{}' in external environment with value: {}",
                    key, value
                );
                return Ok(old_value);
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
        let (handled, value) = self.external.get(key).await?;
        if handled {
            return Ok(value);
        }

        // Then check parent environment if exists
        if let Some(parent) = &self.parent {
            return parent.get(key).await;
        }

        Ok(None)
    }

    pub async fn remove(&self, key: &str) -> Result<Option<CollectionValue>, String> {
        let log_level = self.log_level();
        if let Some(value) = self.values.remove(key).await? {
            log!(log_level, "Removed variable '{}' with value: {}", key, value);
            return Ok(Some(value));
        }

        // If the key does not exist in the local environment, check external environment
        let (handled, old_value) = self.external.remove(key).await?;
        if handled {
            log!(log_level, "Removed variable '{}' from external environment", key);
            return Ok(old_value);
        }

        Ok(None)
    }

    pub async fn flush(&self) -> Result<(), String> {
        // Flush the current environment's values
        self.values.flush().await
    }
}
