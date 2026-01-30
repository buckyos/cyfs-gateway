use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use serde::{Deserialize, Serialize};
use cyfs_process_chain::{CollectionValue, EnvRef, MapCollectionRef, MemoryMapCollection, MemorySetCollection, SetCollectionRef};
use crate::{config_err, ConfigErrorCode, ConfigResult, JsonMap, JsonSet, SqliteMap, SqliteSet, TextSet};

#[derive(Copy, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CollectionType {
    #[serde(rename = "memory_set")]
    MemorySet,
    #[serde(rename = "json_set")]
    JsonSet,
    #[serde(rename = "sqlite_set")]
    SqliteSet,
    #[serde(rename = "text_set")]
    TextSet,
    #[serde(rename = "memory_map")]
    MemoryMap,
    #[serde(rename = "json_map")]
    JsonMap,
    #[serde(rename = "sqlite_map")]
    SqliteMap,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CollectionConfig {
    pub name: String,
    #[serde(rename = "type")]
    pub collection_type: CollectionType,
    pub file_path: Option<String>,
    #[serde(flatten)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

pub struct GlobalCollectionManager {
    sets: HashMap<String, SetCollectionRef>,
    maps: HashMap<String, MapCollectionRef>,
}
pub type GlobalCollectionManagerRef = Arc<GlobalCollectionManager>;

impl GlobalCollectionManager {
    pub fn new() -> Arc<Self> {
        Arc::new(GlobalCollectionManager {
            sets: HashMap::new(),
            maps: HashMap::new(),
        })
    }

    pub async fn create(configs: Vec<CollectionConfig>) -> ConfigResult<GlobalCollectionManagerRef> {
        let mut sets: HashMap<String, SetCollectionRef> = HashMap::new();
        let mut maps: HashMap<String, MapCollectionRef> = HashMap::new();
        let mut collection_names = HashSet::new();

        for config in configs {
            if collection_names.contains(&config.name) {
                return Err(config_err!(ConfigErrorCode::InvalidConfig, "collection name {} is duplicated", config.name));
            }
            collection_names.insert(config.name.clone());
            match config.collection_type {
                CollectionType::JsonSet => {
                    if config.file_path.is_none() {
                        return Err(config_err!(ConfigErrorCode::InvalidConfig, "file_path is required for json_set"));
                    }
                    let set: SetCollectionRef = Arc::new(Box::new(JsonSet::load_from(config.file_path.as_ref().unwrap().as_str()).await
                        .map_err(|e| config_err!(ConfigErrorCode::InvalidConfig, "{}", e))?));
                    sets.insert(config.name, set);
                }
                CollectionType::SqliteSet => {
                    if config.file_path.is_none() {
                        return Err(config_err!(ConfigErrorCode::InvalidConfig, "file_path is required for json_set"));
                    }
                    let (table_name, column_name) = if let Some(data) = config.data {
                        let table_name = if let Some(table_name) = data.get("table_name") {
                            Some(table_name.to_string())
                        } else {
                            None
                        };
                        let column_name = if let Some(column_name) = data.get("column_name") {
                            Some(column_name.to_string())
                        } else {
                            None
                        };
                        (table_name, column_name)
                    } else {
                        (None, None)
                    };
                    let set: SetCollectionRef = Arc::new(Box::new(SqliteSet::open(config.file_path.as_ref().unwrap().as_str(), table_name, column_name).await
                        .map_err(|e| config_err!(ConfigErrorCode::InvalidConfig, "{}", e))?));
                    sets.insert(config.name, set);
                }
                CollectionType::TextSet => {
                    if config.file_path.is_none() {
                        return Err(config_err!(ConfigErrorCode::InvalidConfig, "file_path is required for text_set"));
                    }
                    let set: SetCollectionRef = Arc::new(Box::new(TextSet::load_from(config.file_path.as_ref().unwrap().as_str()).await
                        .map_err(|e| config_err!(ConfigErrorCode::InvalidConfig, "{}", e))?));
                    sets.insert(config.name, set);
                }
                CollectionType::JsonMap => {
                    if config.file_path.is_none() {
                        return Err(config_err!(ConfigErrorCode::InvalidConfig, "file_path is required for json_map"));
                    }
                    let map: MapCollectionRef = Arc::new(Box::new(JsonMap::load_from(config.file_path.as_ref().unwrap().as_str()).await
                        .map_err(|e| config_err!(ConfigErrorCode::InvalidConfig, "{}", e))?));
                    maps.insert(config.name, map);
                }
                CollectionType::SqliteMap => {
                    if config.file_path.is_none() {
                        return Err(config_err!(ConfigErrorCode::InvalidConfig, "file_path is required for sqlite_set"));
                    }
                    let (table_name, key_name, value_name) = if let Some(data) = config.data {
                        let table_name = if let Some(table_name) = data.get("table_name") {
                            Some(table_name.to_string())
                        } else {
                            None
                        };
                        let key_name = if let Some(column_name) = data.get("key_name") {
                            Some(column_name.to_string())
                        } else {
                            None
                        };
                        let value_name = if let Some(column_name) = data.get("value_name") {
                            Some(column_name.to_string())
                        } else {
                            None
                        };
                        (table_name, key_name, value_name)
                    } else {
                        (None, None, None)
                    };
                    let map: MapCollectionRef = Arc::new(Box::new(SqliteMap::open(config.file_path.as_ref().unwrap().as_str(), table_name, key_name, value_name).await
                        .map_err(|e| config_err!(ConfigErrorCode::InvalidConfig, "{}", e))?));
                    maps.insert(config.name, map);
                }
                CollectionType::MemorySet => {
                    let set: SetCollectionRef = Arc::new(Box::new(MemorySetCollection::new()));
                    sets.insert(config.name, set);
                }
                CollectionType::MemoryMap => {
                    let map: MapCollectionRef = Arc::new(Box::new(MemoryMapCollection::new()));
                    maps.insert(config.name, map);
                }
            }
        }

        Ok(Arc::new(GlobalCollectionManager {
            sets,
            maps,
        }))
    }

    pub async fn update(&mut self, configs: Vec<CollectionConfig>) -> ConfigResult<()> {
        let mut collection_names = HashSet::new();
        for config in configs {
            if collection_names.contains(&config.name) {
                return Err(config_err!(ConfigErrorCode::InvalidConfig, "collection name {} is duplicated", config.name));
            }
            collection_names.insert(config.name.clone());
            match config.collection_type {
                CollectionType::JsonSet => {
                    if config.file_path.is_none() {
                        return Err(config_err!(ConfigErrorCode::InvalidConfig, "file_path is required for json_set"));
                    }
                    let set: SetCollectionRef = Arc::new(Box::new(JsonSet::load_from(config.file_path.as_ref().unwrap().as_str()).await
                        .map_err(|e| config_err!(ConfigErrorCode::InvalidConfig, "{}", e))?));
                    self.add_set(config.name, set);
                }
                CollectionType::SqliteSet => {
                    if config.file_path.is_none() {
                        return Err(config_err!(ConfigErrorCode::InvalidConfig, "file_path is required for json_set"));
                    }
                    let (table_name, column_name) = if let Some(data) = config.data {
                        let table_name = if let Some(table_name) = data.get("table_name") {
                            Some(table_name.to_string())
                        } else {
                            None
                        };
                        let column_name = if let Some(column_name) = data.get("column_name") {
                            Some(column_name.to_string())
                        } else {
                            None
                        };
                        (table_name, column_name)
                    } else {
                        (None, None)
                    };
                    let set: SetCollectionRef = Arc::new(Box::new(SqliteSet::open(config.file_path.as_ref().unwrap().as_str(), table_name, column_name).await
                        .map_err(|e| config_err!(ConfigErrorCode::InvalidConfig, "{}", e))?));
                    self.add_set(config.name, set);
                }
                CollectionType::TextSet => {
                    if config.file_path.is_none() {
                        return Err(config_err!(ConfigErrorCode::InvalidConfig, "file_path is required for text_set"));
                    }
                    let set: SetCollectionRef = Arc::new(Box::new(TextSet::load_from(config.file_path.as_ref().unwrap().as_str()).await
                        .map_err(|e| config_err!(ConfigErrorCode::InvalidConfig, "{}", e))?));
                    self.add_set(config.name, set);
                }
                CollectionType::JsonMap => {
                    if config.file_path.is_none() {
                        return Err(config_err!(ConfigErrorCode::InvalidConfig, "file_path is required for json_map"));
                    }
                    let map: MapCollectionRef = Arc::new(Box::new(JsonMap::load_from(config.file_path.as_ref().unwrap().as_str()).await
                        .map_err(|e| config_err!(ConfigErrorCode::InvalidConfig, "{}", e))?));
                    self.add_map(config.name, map);
                }
                CollectionType::SqliteMap => {
                    if config.file_path.is_none() {
                        return Err(config_err!(ConfigErrorCode::InvalidConfig, "file_path is required for sqlite_set"));
                    }
                    let (table_name, key_name, value_name) = if let Some(data) = config.data {
                        let table_name = if let Some(table_name) = data.get("table_name") {
                            Some(table_name.to_string())
                        } else {
                            None
                        };
                        let key_name = if let Some(column_name) = data.get("key_name") {
                            Some(column_name.to_string())
                        } else {
                            None
                        };
                        let value_name = if let Some(column_name) = data.get("value_name") {
                            Some(column_name.to_string())
                        } else {
                            None
                        };
                        (table_name, key_name, value_name)
                    } else {
                        (None, None, None)
                    };
                    let map: MapCollectionRef = Arc::new(Box::new(SqliteMap::open(config.file_path.as_ref().unwrap().as_str(), table_name, key_name, value_name).await
                        .map_err(|e| config_err!(ConfigErrorCode::InvalidConfig, "{}", e))?));
                    self.add_map(config.name, map);
                }
                CollectionType::MemorySet => {
                    if !self.set_exists(config.name.as_str()) {
                        let set: SetCollectionRef = Arc::new(Box::new(MemorySetCollection::new()));
                        self.add_set(config.name, set);
                    }
                }
                CollectionType::MemoryMap => {
                    if !self.map_exists(config.name.as_str()) {
                        let map: MapCollectionRef = Arc::new(Box::new(MemoryMapCollection::new()));
                        self.add_map(config.name, map);
                    }
                }
            }
        }

        self.retain_sets(|name, _| {
            collection_names.contains(name)
        });

        self.retain_maps(|name, _| {
            collection_names.contains(name)
        });

        Ok(())
    }

    fn add_set(&mut self, name: String, set: SetCollectionRef) {
        self.sets.insert(name, set);
    }

    fn set_exists(&self, name: &str) -> bool {
        self.sets.contains_key(name)
    }

    fn retain_sets(&mut self, predicate: impl Fn(&String, &SetCollectionRef) -> bool) {
        self.sets.retain(|k, v| predicate(k, v));
    }

    fn retain_maps(&mut self, predicate: impl Fn(&String, &MapCollectionRef) -> bool) {
        self.maps.retain(|k, v| predicate(k, v));
    }
    fn add_map(&mut self, name: String, map: MapCollectionRef) {
        self.maps.insert(name, map);
    }

    fn map_exists(&self, name: &str) -> bool {
        self.maps.contains_key(name)
    }

    fn get_sets(&self) -> HashMap<String, SetCollectionRef> {
        self.sets.clone()
    }

    fn get_maps(&self) -> HashMap<String, MapCollectionRef> {
        self.maps.clone()
    }

    pub async fn register_collection(&self, env: &EnvRef) -> ConfigResult<()> {
        let sets = self.get_sets();
        for (name, set) in sets {
            env.create(name.as_str(), CollectionValue::Set(set)).await
                .map_err(|e| config_err!(ConfigErrorCode::ProcessChainError, "{}", e))?;
        }

        let maps = self.get_maps();
        for (name, map) in maps {
            env.create(name.as_str(), CollectionValue::Map(map)).await
                .map_err(|e| config_err!(ConfigErrorCode::ProcessChainError, "{}", e))?;
        }

        Ok(())
    }
}
