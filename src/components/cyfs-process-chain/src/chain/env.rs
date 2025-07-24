use crate::collection::{
    CollectionType, CollectionValue, MapCollection, MapCollectionRef, MemoryMapCollection,
    MemoryMultiMapCollection, MemorySetCollection, MultiMapCollection, SetCollection,
};
use std::collections::HashMap;
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

pub struct Env {
    level: EnvLevel,
    values: MapCollectionRef,
    parent: Option<EnvRef>,
}

pub type EnvRef = Arc<Env>;

impl Env {
    pub fn new(level: EnvLevel, parent: Option<EnvRef>) -> Self {
        let values = MemoryMapCollection::new();
        let values: MapCollectionRef = Arc::new(Box::new(values) as Box<dyn MapCollection>);

        Self {
            level,
            values,
            parent,
        }
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
        self.values.insert(key, value).await
    }

    #[async_recursion::async_recursion]
    pub async fn get(&self, key: &str) -> Result<Option<CollectionValue>, String> {
        // First check local values
        if let Some(value) = self.values.get(key).await? {
            return Ok(Some(value));
        }

        // Then check parent environment if exists
        if let Some(parent) = &self.parent {
            return parent.get(key).await;
        }

        Ok(None)
    }

    pub async fn remove(&self, key: &str) -> Result<Option<CollectionValue>, String> {
        self.values.remove(key).await
    }

    pub async fn flush(&self) -> Result<(), String> {
        // Flush the current environment's values
        self.values.flush().await
    }
}

enum PathCollection {
    Root(EnvRef),
    Map(MapCollectionRef),
}

impl PathCollection {
    pub async fn get(&self, key: &str) -> Result<Option<CollectionValue>, String> {
        match self {
            PathCollection::Root(env) => env.get(key).await,
            PathCollection::Map(map) => map.get(key).await,
        }
    }

    pub async fn insert_new(&self, key: &str, value: CollectionValue) -> Result<bool, String> {
        match self {
            PathCollection::Root(env) => env.create(key, value).await,
            PathCollection::Map(map) => map.insert_new(key, value).await,
        }
    }

    pub async fn insert(&self, key: &str, value: CollectionValue) -> Result<Option<CollectionValue>, String> {
        match self {
            PathCollection::Root(env) => env.set(key, value).await,
            PathCollection::Map(map) => map.insert(key, value).await,
        }
    }

    pub async fn remove(&self, key: &str) -> Result<Option<CollectionValue>, String> {
        match self {
            PathCollection::Root(env) => env.remove(key).await,
            PathCollection::Map(map) => map.remove(key).await,
        }
    }
}

#[derive(Clone)]
pub struct EnvManager {
    global: EnvRef,
    chain: EnvRef,
    block: EnvRef,

    // Tracking variables current level
    var_level_tracker: Arc<RwLock<HashMap<String, EnvLevel>>>,
}

impl EnvManager {
    pub fn new(global_env: EnvRef, chain_env: EnvRef) -> Self {
        assert!(
            global_env.level() == EnvLevel::Global,
            "Global environment must be at global level"
        );
        assert!(
            chain_env.level() == EnvLevel::Chain,
            "Chain environment must be at chain level"
        );

        let block = Arc::new(Env::new(EnvLevel::Block, Some(chain_env.clone())));
        let var_level_tracker = Arc::new(RwLock::new(HashMap::new()));

        Self {
            global: global_env,
            chain: chain_env,
            block,
            var_level_tracker,
        }
    }

    pub fn create_chain_env(&self) -> EnvRef {
        Arc::new(Env::new(EnvLevel::Chain, Some(self.global.clone())))
    }

    fn get_env(&self, level: EnvLevel) -> &EnvRef {
        match level {
            EnvLevel::Global => &self.global,
            EnvLevel::Chain => &self.chain,
            EnvLevel::Block => &self.block,
        }
    }

    fn parse_var(key: &str) -> Vec<&str> {
        key.split('.').collect()
    }

    pub fn get_var_level(&self, key: &str) -> EnvLevel {
        // Use the first part of the key to determine the level
        let key = Self::parse_var(key)[0];

        let tracker = self.var_level_tracker.read().unwrap();
        tracker.get(key).cloned().unwrap_or_default()
    }

    pub fn change_var_level(&self, key: &str, level: Option<EnvLevel>) {
        // Use the first part of the key to determine the level
        let key = Self::parse_var(key)[0];

        let level = level.unwrap_or_default();
        let mut tracker = self.var_level_tracker.write().unwrap();
        match tracker.entry(key.to_string()) {
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                if entry.get() != &level {
                    info!(
                        "Variable '{}' level changed from '{}' to '{}'",
                        key,
                        entry.get().as_str(),
                        level.as_str()
                    );
                    entry.insert(level);
                } else {
                    debug!("Variable '{}' already at level '{}'", key, level.as_str());
                }
            }
            std::collections::hash_map::Entry::Vacant(entry) => {
                if level != EnvLevel::default() {
                    entry.insert(level);
                    info!("Variable '{}' set to level '{}'", key, level.as_str());
                }
            }
        }
    }

    /*
    // FIXME: Should we allow moving variables between levels? or just track their level?
    fn move_var_level(&self, key: &str, from: EnvLevel, to: EnvLevel) {
        let from_env = self.get_env(from);
        let value = from_env.delete(key);
        if let Some(value) = value {
            let to_end = self.get_env(to);
            if let Some(prev) = to_end.set(key, &value) {
                info!(
                    "Moved variable '{}' from '{}' to '{}', replaced value: {}",
                    key, from.as_str(), to.as_str(), prev
                );
            } else {
                info!("Moved variable '{}' from '{}' to '{}'", key, from.as_str(), to.as_str());
            }
        } else {
            warn!(
                "Variable '{}' not found in '{}' environment, cannot move to '{}'",
                key, from.as_str(), to.as_str()
            );
        }
    }
    */

    pub fn get_global(&self) -> &EnvRef {
        &self.global
    }

    pub fn get_chain(&self) -> &EnvRef {
        &self.chain
    }

    pub fn get_block(&self) -> &EnvRef {
        &self.block
    }

    pub async fn create(
        &self,
        key: &str,
        value: CollectionValue,
        level: EnvLevel,
    ) -> Result<bool, String> {
        let key_list = Self::parse_var(key);

        // let level = level.unwrap_or_default();
        let ret = self.create_inner(level, &key_list, value).await?;

        if ret {
            // Track the variable's level
            self.change_var_level(key, Some(level));
        }

        Ok(ret)
    }

    // Get the parent collection by path, returns None if not found
    // The middle part of the key_list must be a map collection
    async fn get_parent_collection_by_path(
        &self,
        key_list: &[&str],
        level: EnvLevel,
    ) -> Result<Option<PathCollection>, String> {
        let env = match level {
            EnvLevel::Global => self.global.clone(),
            EnvLevel::Chain => self.chain.clone(),
            EnvLevel::Block => self.block.clone(),
        };

        let mut current = PathCollection::Root(env);
        for part in key_list[0..key_list.len() - 1].iter() {
            if let Some(value) = current.get(part).await? {
                if let CollectionValue::Map(map) = value {
                    current = PathCollection::Map(map);
                } else {
                    let msg = format!("Expected a map at '{}', found: {}", part, value);
                    warn!("{}", msg);
                    return Err(msg);
                }
            } else {
                return Ok(None); // Not found, return None
            }
        }

        Ok(Some(current))
    }

    async fn create_inner(
        &self,
        level: EnvLevel,
        key_list: &[&str],
        value: CollectionValue,
    ) -> Result<bool, String> {
        let parent = self.get_parent_collection_by_path(&key_list, level).await?;
        if parent.is_none() {
            // If parent is None, caller need to create the collection on the path
            let msg = format!(
                "Parent collection not found for key list '{:?}', please create the collection first",
                key_list
            );
            warn!("{}", msg);
            return Err(msg);
        }

        let coll = parent.unwrap();
        let key = key_list.last().unwrap();
        coll.insert_new(key, value).await
    }

    pub async fn create_collection(
        &self,
        key: &str,
        collection_type: CollectionType,
        level: EnvLevel,
    ) -> Result<Option<CollectionValue>, String> {
        let value = match collection_type {
            CollectionType::Set => {
                let collection =
                    Arc::new(Box::new(MemorySetCollection::new()) as Box<dyn SetCollection>);
                CollectionValue::Set(collection)
            }
            CollectionType::Map => {
                let collection =
                    Arc::new(Box::new(MemoryMapCollection::new()) as Box<dyn MapCollection>);
                CollectionValue::Map(collection)
            }

            CollectionType::MultiMap => {
                let collection = Arc::new(
                    Box::new(MemoryMultiMapCollection::new()) as Box<dyn MultiMapCollection>
                );
                CollectionValue::MultiMap(collection)
            }
        };

        match self.create(key, value.clone(), level).await? {
            true => Ok(Some(value)),
            false => Ok(None),
        }
    }

    // Set a value in the environment, level can be specified or depends on the variable's current level in the tracker
    pub async fn set(
        &self,
        key: &str,
        value: CollectionValue,
        level: Option<EnvLevel>,
    ) -> Result<Option<CollectionValue>, String> {
        info!("Setting variable '{}' to value: {:?}", key, value);
        let key_list = Self::parse_var(key);
        let level = match level {
            Some(l) => l,
            None => self.get_var_level(key_list[0]),
        };

        let ret = self.set_inner(level, &key_list, value).await?;
        self.change_var_level(key_list[0], Some(level));

        Ok(ret)
    }

    async fn set_inner(
        &self,
        level: EnvLevel,
        key_list: &[&str],
        value: CollectionValue,
    ) -> Result<Option<CollectionValue>, String> {
        let parent = self.get_parent_collection_by_path(key_list, level).await?;
        if parent.is_none() {
            let msg = format!(
                "Parent collection not found for key list '{:?}', please create the collection first",
                key_list
            );
            warn!("{}", msg);
            return Err(msg);
        }

        let coll = parent.unwrap();
        let key = key_list.last().unwrap();
        coll.insert(key, value).await
    }

    pub async fn get(
        &self,
        key: &str,
        level: Option<EnvLevel>,
    ) -> Result<Option<CollectionValue>, String> {
        let key_list = Self::parse_var(key);
        let level = match level {
            Some(l) => l,
            None => self.get_var_level(key_list[0]),
        };

        self.get_inner(level, &key_list).await
    }

    async fn get_inner(
        &self,
        level: EnvLevel,
        key_list: &[&str],
    ) -> Result<Option<CollectionValue>, String> {
        info!(
            "Getting variable '{}' at level '{}'",
            key_list.join("."),
            level.as_str()
        );
        let parent = self.get_parent_collection_by_path(key_list, level).await?;
        if parent.is_none() {
            let msg = format!(
                "Parent collection not found for key list '{:?}', please create the collection first",
                key_list
            );
            warn!("{}", msg);
            return Err(msg);
        }

        let coll = parent.unwrap();
        let key = key_list.last().unwrap();
        coll.get(key).await
    }

    pub async fn remove(
        &self,
        key: &str,
        level: Option<EnvLevel>,
    ) -> Result<Option<CollectionValue>, String> {
        let key_list = Self::parse_var(key);
        let level = match level {
            Some(l) => l,
            None => self.get_var_level(key_list[0]),
        };

        self.remove_inner(level, &key_list).await
    }

    async fn remove_inner(
        &self,
        level: EnvLevel,
        key_list: &[&str],
    ) -> Result<Option<CollectionValue>, String> {
        let parent = self.get_parent_collection_by_path(key_list, level).await?;
        if parent.is_none() {
            let msg = format!(
                "Parent collection not found for key list '{:?}', please create the collection first",
                key_list
            );
            warn!("{}", msg);
            return Err(msg);
        }

        let coll = parent.unwrap();
        let key = key_list.last().unwrap();
        coll.remove(key).await
    }
}
