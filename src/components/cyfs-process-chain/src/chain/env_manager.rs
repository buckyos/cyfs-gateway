use log::{log, Level};

use super::env::{Env, EnvLevel, EnvRef};
use super::external::EnvExternalRef;
use crate::collection::*;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

enum PathCollection {
    Root(EnvRef),
    Map(MapCollectionRef),
    Set(SetCollectionRef),           // Only for the last part of the path
    MultiMap(MultiMapCollectionRef), // Only for the last part of the path
}

impl PathCollection {
    pub async fn get(&self, key: &str) -> Result<Option<CollectionValue>, String> {
        match self {
            PathCollection::Root(env) => env.get(key).await,
            PathCollection::Map(map) => map.get(key).await,
            PathCollection::Set(set) => match set.contains(key).await? {
                true => Ok(Some(CollectionValue::String(key.to_string()))),
                false => Ok(None),
            },
            PathCollection::MultiMap(multi_map) => multi_map
                .get_many(key)
                .await
                .map(|value| value.map(|set| CollectionValue::Set(set))),
        }
    }

    pub async fn insert_new(&self, key: &str, value: CollectionValue) -> Result<bool, String> {
        match self {
            PathCollection::Root(env) => env.create(key, value).await,
            PathCollection::Map(map) => map.insert_new(key, value).await,
            PathCollection::Set(set) => {
                if let CollectionValue::String(s) = value {
                    set.insert(&s).await
                } else {
                    let msg = format!("Expected a string value for Set collection at '{}'", key);
                    warn!("{}", msg);
                    Err(msg)
                }
            }
            PathCollection::MultiMap(_multi_map) => {
                let msg = format!(
                    "Cannot insert new value into MultiMap collection at '{}'",
                    key
                );
                warn!("{}", msg);
                Err(msg)
            }
        }
    }

    pub async fn insert(
        &self,
        key: &str,
        value: CollectionValue,
    ) -> Result<Option<CollectionValue>, String> {
        match self {
            PathCollection::Root(env) => env.set(key, value).await,
            PathCollection::Map(map) => map.insert(key, value).await,
            PathCollection::Set(set) => {
                if let CollectionValue::String(s) = value {
                    match set.insert(&s).await? {
                        true => Ok(None),
                        false => Ok(Some(CollectionValue::String(s))),
                    }
                } else {
                    let msg = format!("Expected a string value for Set collection at '{}'", key);
                    warn!("{}", msg);
                    Err(msg)
                }
            }
            PathCollection::MultiMap(multi_map) => {
                if let CollectionValue::String(s) = value {
                    match multi_map.insert(key, &s).await? {
                        true => Ok(None),
                        false => Ok(Some(CollectionValue::String(s))),
                    }
                } else {
                    let msg = format!("Expected a Set value for MultiMap collection at '{}'", key);
                    warn!("{}", msg);
                    Err(msg)
                }
            }
        }
    }

    pub async fn remove(&self, key: &str) -> Result<Option<CollectionValue>, String> {
        match self {
            PathCollection::Root(env) => env.remove(key).await,
            PathCollection::Map(map) => map.remove(key).await,
            PathCollection::Set(set) => {
                if set.contains(key).await? {
                    set.remove(key).await?;
                    Ok(Some(CollectionValue::String(key.to_string())))
                } else {
                    Ok(None)
                }
            }
            PathCollection::MultiMap(multi_map) => {
                let ret = multi_map.remove_all(key).await?;
                if ret.is_some() {
                    Ok(Some(CollectionValue::Set(ret.unwrap())))
                } else {
                    Ok(None)
                }
            }
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
    pub fn get_log_level(&self) -> Level {
        let global_level = self.global.log_level();
        let chain_level = self.chain.log_level();
        let block_level = self.block.log_level();
        
        // Return the highest level among the three
        // Level ordering: Trace < Debug < Info < Warn < Error
        global_level.max(chain_level).max(block_level)
    }

    
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

    pub async fn add_env_external(
        &self,
        level: EnvLevel,
        id: &str,
        external: EnvExternalRef,
    ) -> Result<(), String> {
        let env = self.get_env(level);
        env.env_external_manager()
            .add_external(id, external)
            .await
    }

    pub async fn remove_env_external(
        &self,
        level: EnvLevel,
        id: &str,
    ) -> Result<Option<EnvExternalRef>, String> {
        let env = self.get_env(level);
        env.env_external_manager().remove_external(id).await
    }

    pub async fn get_env_external(
        &self,
        level: EnvLevel,
        id: &str,
    ) -> Result<Option<EnvExternalRef>, String> {
        let env = self.get_env(level);
        env.env_external_manager().get_external(id).await
    }

    fn get_env(&self, level: EnvLevel) -> &EnvRef {
        match level {
            EnvLevel::Global => &self.global,
            EnvLevel::Chain => &self.chain,
            EnvLevel::Block => &self.block,
        }
    }

    fn parse_var(key: &str) -> Vec<String> {
        let mut parts = Vec::new();
        let mut current = String::new();
        let mut escaped = false;

        for ch in key.chars() {
            if escaped {
                current.push(ch);
                escaped = false;
                continue;
            }

            if ch == '\\' {
                escaped = true;
                continue;
            }

            if ch == '.' {
                parts.push(current);
                current = String::new();
                continue;
            }

            current.push(ch);
        }

        if escaped {
            // Keep a trailing escape as a literal backslash.
            current.push('\\');
        }

        parts.push(current);

        parts
            .into_iter()
            .map(|part| {
                let part = part.trim();
                if part.len() >= 2 && part.starts_with('(') && part.ends_with(')') {
                    part[1..part.len() - 1].trim().to_string()
                } else {
                    part.to_string()
                }
            })
            .collect()
    }

    pub fn get_var_level(&self, key: &str) -> EnvLevel {
        // Use the first part of the key to determine the level
        let key_list = Self::parse_var(key);
        let key = key_list[0].as_str();

        let tracker = self.var_level_tracker.read().unwrap();
        tracker.get(key).cloned().unwrap_or_default()
    }

    pub fn change_var_level(&self, key: &str, level: Option<EnvLevel>) {
        // Use the first part of the key to determine the level
        let key_list = Self::parse_var(key);
        let key = key_list[0].as_str();

        let level = level.unwrap_or_default();
        let mut tracker = self.var_level_tracker.write().unwrap();
        match tracker.entry(key.to_string()) {
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                if entry.get() != &level {
                    log!(
                        self.get_log_level(),
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
                    log!(
                        self.get_log_level(),
                        "Variable '{}' set to level '{}'",
                        key,
                        level.as_str()
                    );
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
                log!(
                    self.get_log_level(),
                    "Moved variable '{}' from '{}' to '{}', replaced value: {}",
                    key,
                    from.as_str(),
                    to.as_str(),
                    prev
                );
            } else {
                log!(
                    self.get_log_level(),
                    "Moved variable '{}' from '{}' to '{}'",
                    key,
                    from.as_str(),
                    to.as_str()
                );
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
        let key_refs: Vec<&str> = key_list.iter().map(|s| s.as_str()).collect();

        // let level = level.unwrap_or_default();
        let ret = self.create_inner(level, &key_refs, value).await?;

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
        let sub_key_list = &key_list[0..key_list.len() - 1];
        for (i, part) in sub_key_list.iter().enumerate() {
            if let Some(value) = current.get(part).await? {
                if let CollectionValue::Map(map) = value {
                    current = PathCollection::Map(map);
                } else {
                    if let CollectionValue::MultiMap(multi_map) = &value {
                        if i == sub_key_list.len() - 1 {
                            // Last part can be a multi-map
                            return Ok(Some(PathCollection::MultiMap(multi_map.clone())));
                        }
                    } else if let CollectionValue::Set(set) = &value {
                        if i == sub_key_list.len() - 1 {
                            // Last part can be a set
                            return Ok(Some(PathCollection::Set(set.clone())));
                        }
                    }

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
        log!(
            self.get_log_level(),
            "Setting variable '{}' to value: {:?}",
            key,
            value
        );
        let key_list = Self::parse_var(key);
        let key_refs: Vec<&str> = key_list.iter().map(|s| s.as_str()).collect();
        let level = match level {
            Some(l) => l,
            None => self.get_var_level(key_refs[0]),
        };

        let ret = self.set_inner(level, &key_refs, value).await?;
        self.change_var_level(key_refs[0], Some(level));

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
        let key_refs: Vec<&str> = key_list.iter().map(|s| s.as_str()).collect();
        let level = match level {
            Some(l) => l,
            None => self.get_var_level(key_refs[0]),
        };

        self.get_inner(level, &key_refs).await
    }

    async fn get_inner(
        &self,
        level: EnvLevel,
        key_list: &[&str],
    ) -> Result<Option<CollectionValue>, String> {
        log!(
            self.get_log_level(),
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
        let key_refs: Vec<&str> = key_list.iter().map(|s| s.as_str()).collect();
        let level = match level {
            Some(l) => l,
            None => self.get_var_level(key_refs[0]),
        };

        self.remove_inner(level, &key_refs).await
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

#[cfg(test)]
mod tests {
    use super::EnvManager;

    #[test]
    fn test_parse_var_dynamic_segments() {
        assert_eq!(
            EnvManager::parse_var("test1.test2"),
            vec!["test1".to_string(), "test2".to_string()]
        );

        assert_eq!(
            EnvManager::parse_var("test1.(key2)"),
            vec!["test1".to_string(), "key2".to_string()]
        );

        assert_eq!(
            EnvManager::parse_var("a.(b).(c)"),
            vec!["a".to_string(), "b".to_string(), "c".to_string()]
        );

        assert_eq!(
            EnvManager::parse_var("geoByIp.1\\.2\\.3\\.4.country"),
            vec![
                "geoByIp".to_string(),
                "1.2.3.4".to_string(),
                "country".to_string()
            ]
        );
    }
}
