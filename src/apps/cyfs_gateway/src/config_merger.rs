use anyhow::{anyhow, Result};
use async_recursion::async_recursion;
use json_value_merge::Merge;
use log::*;
use serde::Deserialize;
use serde_json::value::Value as JsonValue;
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use serde_json::json;

#[derive(Debug, Clone)]
struct ConfigItem {
    path: PathBuf,
    value: JsonValue,
}

#[derive(Debug, Deserialize)]
struct Include {
    path: String,
}

#[derive(Debug, Deserialize)]
struct RootConfig {
    includes: Option<Vec<Include>>,
}

pub struct ConfigMerger {}

impl ConfigMerger {
    pub async fn load_dir(
        dir: &Path,
        modified_since: Option<SystemTime>,
    ) -> Result<JsonValue> {
        info!("Loading config files from directory: {:?}", dir);

        let configs = load_dir_internal(dir, modified_since).await?;
        let merged = merge_configs(&configs)?;

        Ok(merged)
    }

    pub async fn load_dir_with_root(
        dir: &Path,
        root_file: &Path,
        modified_since: Option<SystemTime>,
    ) -> Result<JsonValue> {
        info!(
            "Loading config files from directory: {:?} with root file: {:?}",
            dir, root_file
        );

        let configs = load_dir_with_root_internal(dir, root_file, modified_since).await?;
        if configs.is_empty() {
            return Ok(json!({}));
        }
        
        let merged = merge_configs(&configs)?;

        Ok(merged)
    }

    pub async fn load_config<T>(
        dir: &Path,
        modified_since: Option<SystemTime>,
    ) -> Result<T>
    where
        T: serde::de::DeserializeOwned,
    {
        let value = Self::load_dir(dir, modified_since).await?;
        let config: T = serde_json::from_value(value).map_err(|e| {
            let msg = format!("Failed to parse config: {:?}", e);
            error!("{}", msg);
            anyhow!(msg)
        })?;
        Ok(config)
    }
}

fn merge_configs(configs: &[ConfigItem]) -> Result<JsonValue> {
    if configs.is_empty() {
        return Err(anyhow!("no config files loaded"));
    }

    info!("Loaded {} config files: {:?}", configs.len(), configs);

    let mut merged = configs[0].clone();
    for config in configs.iter().skip(1) {
        info!("Will merge config: {:?} -> {:?}", config.path, merged.path);
        merged.value.merge(&config.value);
    }

    Ok(merged.value)
}

fn get_root_file(dir: &Path) -> Option<PathBuf> {
    let root_file = dir.join("root");
    if root_file.exists() {
        return Some(root_file);
    }

    let root_file = dir.join("root.json");
    if root_file.exists() {
        return Some(root_file);
    }

    let root_file = dir.join("root.toml");
    if root_file.exists() {
        return Some(root_file);
    }
    None
}

fn toml_to_json(toml_value: toml::Value) -> Result<JsonValue> {
    let json_string = serde_json::to_string(&toml_value).map_err(|e| {
        let msg = format!("Failed to convert TOML to JSON: {:?}", e);
        error!("{}", msg);
        anyhow!(msg)
    })?;

    let json_value: JsonValue = serde_json::from_str(&json_string).map_err(|e| {
        let msg = format!("Failed to parse JSON: {:?}", e);
        error!("{}", msg);
        anyhow!(msg)
    })?;

    Ok(json_value)
}

fn yaml_to_json(yaml_value: serde_yaml_ng::Value) -> Result<JsonValue> {
    let json_value = serde_json::Value::deserialize(yaml_value).map_err(|e| {
        let msg = format!("Failed to convert YAML to JSON: {:?}", e);
        error!("{}", msg);
        anyhow!(msg)
    })?;
    Ok(json_value)
}

async fn load_file(file: &Path) -> Result<JsonValue> {
    debug!("Loading config file: {:?}", file);
    assert!(file.exists());

    let content = tokio::fs::read_to_string(file).await.map_err(|e| {
        let msg = format!("Failed to read file: {:?}, error: {:?}", file, e);
        error!("{}", msg);
        anyhow!(msg)
    })?;

    if let Some(ext) = file.extension().and_then(|s| s.to_str()) {
        match ext {
            "json" => {
                return serde_json::from_str(&content).map_err(|e| {
                    let msg = format!("Failed to parse JSON: {:?}", e);
                    error!("{}", msg);
                    anyhow!(msg)
                });
            }
            "toml" => {
                let toml_value: toml::Value = toml::from_str(&content).map_err(|e| {
                    let msg = format!("Failed to parse TOML: {:?}", e);
                    error!("{}", msg);
                    anyhow!(msg)
                })?;

                return toml_to_json(toml_value);
            }
            "yaml" | "yml" => {
                let yaml_value: serde_yaml_ng::Value = serde_yaml_ng::from_str(&content).map_err(|e| {
                    let msg = format!("Failed to parse YAML: {:?}", e);
                    error!("{}", msg);
                    anyhow!(msg)
                })?;

                return yaml_to_json(yaml_value);
            }
            _ => {}
        }
    }

    if content.trim_start().starts_with('{') {
        serde_json::from_str(&content).map_err(|e| {
            let msg = format!("Failed to parse JSON: {:?}", e);
            error!("{}", msg);
            anyhow!(msg)
        })
    } else {
        let toml_value: toml::Value = toml::from_str(&content).map_err(|e| {
            let msg = format!("Failed to parse TOML: {:?}", e);
            error!("{}", msg);
            anyhow!(msg)
        })?;
        toml_to_json(toml_value)
    }
}

fn should_load_file(file: &Path, modified_since: Option<SystemTime>) -> bool {
    let Some(modified_since) = modified_since else {
        return true;
    };

    match std::fs::metadata(file).and_then(|meta| meta.modified()) {
        Ok(modified) => modified > modified_since,
        Err(_) => true,
    }
}

fn resolve_include_path(base_dir: &Path, include_path: &str) -> PathBuf {
    let path = PathBuf::from(include_path);
    if path.is_absolute() {
        path
    } else {
        base_dir.join(path)
    }
}

#[async_recursion::async_recursion]
async fn load_config_file(
    file: &Path,
    modified_since: Option<SystemTime>,
) -> Result<Vec<ConfigItem>> {
    let value = load_file(file).await?;
    let root_config: RootConfig = serde_json::from_value(value.clone()).map_err(|e| {
        let msg = format!("Failed to parse config includes: {:?}", e);
        error!("{}", msg);
        anyhow!(msg)
    })?;

    let base_dir = file.parent().unwrap_or_else(|| Path::new("."));
    let mut configs = Vec::new();

    if let Some(includes) = root_config.includes {
        for include in includes {
            let include_path = resolve_include_path(base_dir, &include.path);

            if !include_path.exists() {
                let msg = format!("Include path not exists: {:?}", include_path);
                error!("{}", msg);
                return Err(anyhow!(msg));
            }

            if include_path.is_dir() {
                let items = load_dir_internal(&include_path, modified_since).await?;
                configs.extend(items);
            } else {
                let items = load_config_file(&include_path, modified_since).await?;
                configs.extend(items);
            }
        }
    }

    if should_load_file(file, modified_since) {
        configs.push(ConfigItem {
            path: file.to_path_buf(),
            value,
        });
    }

    Ok(configs)
}

async fn load_dir_with_root_internal(
    dir: &Path,
    root_file: &Path,
    modified_since: Option<SystemTime>,
) -> Result<Vec<ConfigItem>> {
    assert!(root_file.exists());

    let root_value = load_file(root_file).await?;
    let root_config: RootConfig = serde_json::from_value(root_value.clone()).map_err(|e| {
        let msg = format!("Failed to parse root config: {:?}", e);
        error!("{}", msg);
        anyhow!(msg)
    })?;

    let mut config = Vec::new();
    if let Some(includes) = root_config.includes {
        for include in includes {
            let include_path = resolve_include_path(dir, &include.path);

            if !include_path.exists() {
                let msg = format!("Include path not exists: {:?}", include_path);
                error!("{}", msg);
                return Err(anyhow!(msg));
            }

            if include_path.is_dir() {
                let items = load_dir_internal(&include_path, modified_since).await?;
                config.extend(items);
            } else {
                let items = load_config_file(&include_path, modified_since).await?;
                config.extend(items);
            }
        }
    }

    if should_load_file(root_file, modified_since) {
        config.push(ConfigItem {
            path: root_file.to_path_buf(),
            value: root_value,
        });
    }

    Ok(config)
}

#[derive(Debug)]
struct IndexedFile {
    index: u32,
    path: PathBuf,
}

async fn scan_files(dir: &Path) -> Result<Vec<IndexedFile>> {
    let mut indexed_files = Vec::new();

    let mut dir_entries = tokio::fs::read_dir(dir).await.map_err(|e| {
        let msg = format!("Failed to read dir: {:?}, error: {:?}", dir, e);
        error!("{}", msg);
        e
    })?;

    while let Some(entry) = dir_entries.next_entry().await? {
        let path = entry.path();

        let index = extract_index_from_filename(&path).unwrap_or(0);
        indexed_files.push(IndexedFile { index, path });
    }

    let mut index_set = std::collections::HashSet::new();
    for file in &indexed_files {
        if !index_set.insert(file.index) {
            let msg = format!("Duplicated index found: {} {:?}", file.index, file.path);
            error!("{}", msg);
            return Err(anyhow!(msg));
        }
    }

    indexed_files.sort_by_key(|file| file.index);

    Ok(indexed_files)
}

fn extract_index_from_filename(path: &Path) -> Option<u32> {
    let file_stem = path.file_name()?.to_str()?;
    let index_part = file_stem.rsplit('.').next()?;
    let index = index_part.parse::<u32>().ok();
    if index.is_none() {
        let index_part = file_stem.rsplit('.').nth(1)?;
        return index_part.parse::<u32>().ok();
    }
    index
}

async fn load_dir_without_root(
    dir: &Path,
    modified_since: Option<SystemTime>,
) -> Result<Vec<ConfigItem>> {
    let indexed_files = scan_files(dir).await?;

    debug!("Indexed files: {:?} in {:?}", indexed_files, dir);

    let mut config = Vec::new();
    for file in indexed_files {
        if file.path.is_file() {
            let items = load_config_file(&file.path, modified_since).await?;
            config.extend(items);
        } else {
            let items = load_dir_internal(&file.path, modified_since).await?;
            config.extend(items);
        }
    }

    Ok(config)
}

#[async_recursion::async_recursion]
async fn load_dir_internal(
    dir: &Path,
    modified_since: Option<SystemTime>,
) -> Result<Vec<ConfigItem>> {
    let root_file = get_root_file(dir);

    match root_file {
        Some(root_file) => load_dir_with_root_internal(dir, &root_file, modified_since).await,
        None => load_dir_without_root(dir, modified_since).await,
    }
}
