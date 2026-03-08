use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use serde::{Deserialize, Serialize};
use cyfs_process_chain::{CollectionValue, EnvRef, MapCollectionRef, MemoryMapCollection, MemorySetCollection, SetCollectionRef};
use crate::{config_err, ConfigErrorCode, ConfigResult, IpRegionMap, IpRegionMapConfig, JsonMap, JsonSet, SqliteMap, SqliteSet, TextSet};

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
    #[serde(rename = "ip_region_map")]
    IpRegionMap,
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

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CollectionKind {
    Set,
    Map,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct CollectionEntry {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: CollectionKind,
}

pub struct GlobalCollectionManager {
    sets: HashMap<String, SetCollectionRef>,
    maps: HashMap<String, MapCollectionRef>,
}
pub type GlobalCollectionManagerRef = Arc<GlobalCollectionManager>;

impl GlobalCollectionManager {
    fn parse_ip_region_data(data: Option<&serde_json::Value>) -> ConfigResult<(Option<String>, Option<String>, Option<u64>, Option<u64>, Option<String>, Option<String>, PathBuf)> {
        let Some(data) = data else {
            return Err(config_err!(ConfigErrorCode::InvalidConfig, "ip_region_map requires data.cache_path"));
        };

        let read_string = |key: &str| -> ConfigResult<Option<String>> {
            match data.get(key) {
                Some(value) if value.is_string() => Ok(value.as_str().map(|v| v.to_string())),
                Some(_) => Err(config_err!(
                    ConfigErrorCode::InvalidConfig,
                    "{} in ip_region_map.data must be string",
                    key
                )),
                None => Ok(None),
            }
        };

        let read_u64 = |key: &str| -> ConfigResult<Option<u64>> {
            match data.get(key) {
                Some(value) if value.is_u64() => Ok(value.as_u64()),
                Some(_) => Err(config_err!(
                    ConfigErrorCode::InvalidConfig,
                    "{} in ip_region_map.data must be unsigned integer",
                    key
                )),
                None => Ok(None),
            }
        };

        let cache_path = read_string("cache_path")?.ok_or(config_err!(
            ConfigErrorCode::InvalidConfig,
            "cache_path in ip_region_map.data is required"
        ))?;

        Ok((
            read_string("ipv6_file_path")?,
            read_string("cache_policy")?,
            read_u64("auto_update_interval_secs")?,
            read_u64("request_timeout_secs")?,
            read_string("ipv4_sha256")?,
            read_string("ipv6_sha256")?,
            PathBuf::from(cache_path),
        ))
    }

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
                CollectionType::IpRegionMap => {
                    if config.file_path.is_none() {
                        return Err(config_err!(ConfigErrorCode::InvalidConfig, "file_path is required for ip_region_map"));
                    }
                    let (ipv6_file_path, cache_policy, auto_update_interval_secs, request_timeout_secs, ipv4_sha256, ipv6_sha256, cache_path) =
                        Self::parse_ip_region_data(config.data.as_ref())?;

                    let map: MapCollectionRef = Arc::new(Box::new(
                        IpRegionMap::load_from(IpRegionMapConfig {
                            ipv4_file_path: config.file_path.unwrap(),
                            ipv6_file_path,
                            cache_policy,
                            auto_update_interval_secs,
                            request_timeout_secs,
                            ipv4_sha256,
                            ipv6_sha256,
                            cache_dir: cache_path,
                        })
                        .await
                        .map_err(|e| config_err!(ConfigErrorCode::InvalidConfig, "{}", e))?,
                    ));
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
                CollectionType::IpRegionMap => {
                    if config.file_path.is_none() {
                        return Err(config_err!(ConfigErrorCode::InvalidConfig, "file_path is required for ip_region_map"));
                    }
                    let (ipv6_file_path, cache_policy, auto_update_interval_secs, request_timeout_secs, ipv4_sha256, ipv6_sha256, cache_path) =
                        Self::parse_ip_region_data(config.data.as_ref())?;

                    let map: MapCollectionRef = Arc::new(Box::new(
                        IpRegionMap::load_from(IpRegionMapConfig {
                            ipv4_file_path: config.file_path.unwrap(),
                            ipv6_file_path,
                            cache_policy,
                            auto_update_interval_secs,
                            request_timeout_secs,
                            ipv4_sha256,
                            ipv6_sha256,
                            cache_dir: cache_path,
                        })
                        .await
                        .map_err(|e| config_err!(ConfigErrorCode::InvalidConfig, "{}", e))?,
                    ));
                    self.add_map(config.name, map);
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

    pub fn get_set(&self, name: &str) -> Option<SetCollectionRef> {
        self.sets.get(name).cloned()
    }

    pub fn get_map(&self, name: &str) -> Option<MapCollectionRef> {
        self.maps.get(name).cloned()
    }

    pub fn list(&self) -> Vec<CollectionEntry> {
        let mut collections = Vec::with_capacity(self.sets.len() + self.maps.len());
        for name in self.sets.keys() {
            collections.push(CollectionEntry {
                name: name.clone(),
                kind: CollectionKind::Set,
            });
        }
        for name in self.maps.keys() {
            collections.push(CollectionEntry {
                name: name.clone(),
                kind: CollectionKind::Map,
            });
        }
        collections.sort_by(|a, b| a.name.cmp(&b.name));
        collections
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
