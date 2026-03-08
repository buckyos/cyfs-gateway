use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use cyfs_process_chain::{
    CollectionValue, MapCollection, MapCollectionRef, MapCollectionTraverseCallBackRef,
    MemoryMapCollection,
};
use sfo_ip::{CachePolicy, Searcher};
use reqwest::header::{ETAG, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED};
use sha2::{Digest, Sha256};
use tokio::task::JoinHandle;
use tokio::time::{Instant, interval_at};
use url::Url;

const DEFAULT_AUTO_UPDATE_INTERVAL_SECS: u64 = 24 * 60 * 60;
const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 15;
const KEEP_OLD_VERSIONED_XDB_FILES: usize = 2;

#[derive(Clone)]
pub struct IpRegionMapConfig {
    pub ipv4_file_path: String,
    pub ipv6_file_path: Option<String>,
    pub cache_policy: Option<String>,
    pub auto_update_interval_secs: Option<u64>,
    pub request_timeout_secs: Option<u64>,
    pub ipv4_sha256: Option<String>,
    pub ipv6_sha256: Option<String>,
    pub cache_dir: PathBuf,
}

#[derive(Clone)]
enum DbSource {
    Local {
        path: String,
    },
    Remote {
        url: Url,
        cache_file: PathBuf,
        current_file: PathBuf,
        etag_file: PathBuf,
        last_modified_file: PathBuf,
    },
}

#[derive(Clone)]
struct DbHandle {
    label: &'static str,
    source: DbSource,
    cache_policy: CachePolicy,
    request_timeout_secs: u64,
    expected_sha256: Option<String>,
    active_file: Arc<RwLock<PathBuf>>,
    searcher: Arc<RwLock<Option<Searcher>>>,
}

pub struct IpRegionMap {
    ipv4: DbHandle,
    ipv6: Option<DbHandle>,
    updater_tasks: Mutex<Vec<JoinHandle<()>>>,
}

impl IpRegionMap {
    pub async fn load_from(config: IpRegionMapConfig) -> Result<Self, String> {
        let IpRegionMapConfig {
            ipv4_file_path,
            ipv6_file_path,
            cache_policy,
            auto_update_interval_secs,
            request_timeout_secs,
            ipv4_sha256,
            ipv6_sha256,
            cache_dir,
        } = config;

        let cache_policy = parse_cache_policy(cache_policy.as_deref())?;
        let request_timeout_secs = request_timeout_secs.unwrap_or(DEFAULT_REQUEST_TIMEOUT_SECS);

        let ipv4 = DbHandle::new(
            "ipv4",
            ipv4_file_path,
            cache_policy,
            request_timeout_secs,
            ipv4_sha256,
            &cache_dir,
        )
            .await?;

        let ipv6 = if let Some(path) = ipv6_file_path {
            Some(
                DbHandle::new(
                    "ipv6",
                    path,
                    cache_policy,
                    request_timeout_secs,
                    ipv6_sha256,
                    &cache_dir,
                )
                    .await?,
            )
        } else {
            None
        };

        let mut map = Self {
            ipv4,
            ipv6,
            updater_tasks: Mutex::new(Vec::new()),
        };

        let interval_secs = auto_update_interval_secs.unwrap_or(DEFAULT_AUTO_UPDATE_INTERVAL_SECS);
        map.start_updater(interval_secs.max(1));

        Ok(map)
    }

    fn start_updater(&mut self, interval_secs: u64) {
        let mut tasks = self.updater_tasks.lock().unwrap();
        tasks.clear();

        if let Some(task) = spawn_refresh_task(self.ipv4.clone(), interval_secs) {
            tasks.push(task);
        }

        if let Some(ipv6) = &self.ipv6
            && let Some(task) = spawn_refresh_task(ipv6.clone(), interval_secs)
        {
            tasks.push(task);
        }
    }

    async fn build_result_map(
        key: &str,
        full: String,
        ip_version: &'static str,
    ) -> Result<MapCollectionRef, String> {
        let detail = MemoryMapCollection::new_ref();

        detail
            .insert("ip", CollectionValue::String(key.to_string()))
            .await?;
        detail
            .insert(
                "ip_version",
                CollectionValue::String(ip_version.to_string()),
            )
            .await?;
        detail
            .insert("full", CollectionValue::String(full.clone()))
            .await?;

        let matched = if full.is_empty() { "false" } else { "true" };
        detail
            .insert("matched", CollectionValue::String(matched.to_string()))
            .await?;

        let parts = if full.is_empty() {
            Vec::new()
        } else {
            full.split('|').map(|v| v.to_string()).collect::<Vec<_>>()
        };

        let parts_map = MemoryMapCollection::new_ref();
        for (idx, part) in parts.iter().enumerate() {
            let idx_key = idx.to_string();
            parts_map
                .insert(idx_key.as_str(), CollectionValue::String(part.clone()))
                .await?;
        }

        detail
            .insert("parts", CollectionValue::Map(parts_map))
            .await?;

        set_part_alias(&detail, "country", parts.first()).await?;
        set_part_alias(&detail, "province", parts.get(1)).await?;
        set_part_alias(&detail, "city", parts.get(2)).await?;
        set_part_alias(&detail, "isp", parts.get(3)).await?;
        set_part_alias(&detail, "country_code", parts.get(4)).await?;

        Ok(detail)
    }
}

#[async_trait::async_trait]
impl MapCollection for IpRegionMap {
    async fn len(&self) -> Result<usize, String> {
        Err("ip_region_map does not support len()".to_string())
    }

    async fn insert_new(&self, _key: &str, _value: CollectionValue) -> Result<bool, String> {
        Err("ip_region_map is read-only".to_string())
    }

    async fn insert(
        &self,
        _key: &str,
        _value: CollectionValue,
    ) -> Result<Option<CollectionValue>, String> {
        Err("ip_region_map is read-only".to_string())
    }

    async fn get(&self, key: &str) -> Result<Option<CollectionValue>, String> {
        let ip: IpAddr = match key.parse() {
            Ok(ip) => ip,
            Err(_) => return Ok(None),
        };

        let (db, ip_version) = match ip {
            IpAddr::V4(_) => (&self.ipv4, "ipv4"),
            IpAddr::V6(_) => {
                let Some(ipv6) = &self.ipv6 else {
                    return Err("ipv6_file_path is not configured for ip_region_map".to_string());
                };
                (ipv6, "ipv6")
            }
        };

        let Some(full) = db.search(key)? else {
            return Ok(None);
        };
        let result = Self::build_result_map(key, full, ip_version).await?;
        Ok(Some(CollectionValue::Map(result)))
    }

    async fn contains_key(&self, key: &str) -> Result<bool, String> {
        Ok(self.get(key).await?.is_some())
    }

    async fn remove(&self, _key: &str) -> Result<Option<CollectionValue>, String> {
        Err("ip_region_map is read-only".to_string())
    }

    async fn traverse(&self, _callback: MapCollectionTraverseCallBackRef) -> Result<(), String> {
        Err("ip_region_map does not support traverse()".to_string())
    }

    async fn dump(&self) -> Result<Vec<(String, CollectionValue)>, String> {
        Err("ip_region_map does not support dump()".to_string())
    }
}

impl Drop for IpRegionMap {
    fn drop(&mut self) {
        let mut tasks = self.updater_tasks.lock().unwrap();
        for task in tasks.drain(..) {
            task.abort();
        }
    }
}

impl DbHandle {
    async fn new(
        label: &'static str,
        path_or_url: String,
        cache_policy: CachePolicy,
        request_timeout_secs: u64,
        expected_sha256: Option<String>,
        cache_dir: &Path,
    ) -> Result<Self, String> {
        let source = build_source(label, path_or_url, cache_dir)?;

        match source.clone() {
            DbSource::Local { path } => {
                let searcher = Searcher::new(path.clone(), cache_policy).map_err(|e| e.to_string())?;
                Ok(Self {
                    label,
                    source,
                    cache_policy,
                    request_timeout_secs,
                    expected_sha256,
                    active_file: Arc::new(RwLock::new(PathBuf::from(&path))),
                    searcher: Arc::new(RwLock::new(Some(searcher))),
                })
            }
            DbSource::Remote {
                cache_file,
                current_file,
                ..
            } => {
                let active_file = resolve_active_cache_file(&cache_file, &current_file).await;

                if active_file.exists() {
                    match Searcher::new(active_file.to_string_lossy().to_string(), cache_policy) {
                        Ok(searcher) => {
                            if let Err(err) = write_current_cache_pointer(&current_file, &active_file).await {
                                warn!(
                                    "write {} xdb pointer file {} failed: {}",
                                    label,
                                    current_file.display(),
                                    err
                                );
                            }

                            return Ok(Self {
                                label,
                                source,
                                cache_policy,
                                request_timeout_secs,
                                expected_sha256,
                                active_file: Arc::new(RwLock::new(active_file)),
                                searcher: Arc::new(RwLock::new(Some(searcher))),
                            });
                        }
                        Err(err) => {
                            warn!(
                                "load {} cached xdb {} failed, use empty db and refresh in background: {}",
                                label,
                                active_file.display(),
                                err
                            );
                        }
                    }
                }

                info!(
                    "{} xdb cache is unavailable at startup, use empty db and refresh in background",
                    label
                );

                Ok(Self {
                    label,
                    source,
                    cache_policy,
                    request_timeout_secs,
                    expected_sha256,
                    active_file: Arc::new(RwLock::new(active_file)),
                    searcher: Arc::new(RwLock::new(None)),
                })
            }
        }
    }

    fn search(&self, key: &str) -> Result<Option<String>, String> {
        let searcher = self.searcher.read().unwrap();
        match searcher.as_ref() {
            Some(searcher) => searcher.search(key).map(Some).map_err(|e| e.to_string()),
            None => Ok(None),
        }
    }

    async fn refresh_remote(&self) -> Result<bool, String> {
        let DbSource::Remote {
            url,
            cache_file,
            current_file,
            etag_file,
            last_modified_file,
        } = &self.source
        else {
            return Ok(false);
        };

        let changed = download_remote_xdb(
            url,
            cache_file,
            current_file,
            etag_file,
            last_modified_file,
            self.request_timeout_secs,
            self.expected_sha256.as_deref(),
        )
            .await?;

        let Some(new_cache_file) = changed else {
            return Ok(false);
        };

        let searcher = Searcher::new(new_cache_file.to_string_lossy().to_string(), self.cache_policy)
            .map_err(|e| e.to_string())?;

        let previous_file = {
            let mut searcher_lock = self.searcher.write().unwrap();
            let mut active_lock = self.active_file.write().unwrap();
            let previous = active_lock.clone();
            *searcher_lock = Some(searcher);
            *active_lock = new_cache_file.clone();
            previous
        };

        if let Err(err) = write_current_cache_pointer(current_file, &new_cache_file).await {
            warn!(
                "ip_region_map {} write pointer {} failed: {}",
                self.label,
                current_file.display(),
                err
            );
        }

        cleanup_old_versioned_cache_files(cache_file, &new_cache_file, KEEP_OLD_VERSIONED_XDB_FILES)
            .await;

        if previous_file != *cache_file {
            let _ = tokio::fs::remove_file(&previous_file).await;
        }

        Ok(true)
    }
}

async fn set_part_alias(
    map: &MapCollectionRef,
    field: &str,
    value: Option<&String>,
) -> Result<(), String> {
    if let Some(value) = value
        && !value.is_empty()
    {
        map.insert(field, CollectionValue::String(value.clone()))
            .await?;
    }
    Ok(())
}

fn parse_cache_policy(input: Option<&str>) -> Result<CachePolicy, String> {
    let value = input.unwrap_or("vector_index").trim().to_ascii_lowercase();
    match value.as_str() {
        "no_cache" => Ok(CachePolicy::NoCache),
        "vector_index" => Ok(CachePolicy::VectorIndex),
        "full_memory" => Ok(CachePolicy::FullMemory),
        _ => Err(format!(
            "invalid cache_policy '{}', expected one of: no_cache, vector_index, full_memory",
            value
        )),
    }
}

fn is_remote_path(path: &str) -> bool {
    let path = path.trim_start();
    path.starts_with("http://") || path.starts_with("https://")
}

fn build_source(label: &'static str, path_or_url: String, cache_dir: &Path) -> Result<DbSource, String> {
    if !is_remote_path(path_or_url.as_str()) {
        return Ok(DbSource::Local { path: path_or_url });
    }

    let url = Url::parse(path_or_url.as_str())
        .map_err(|e| format!("invalid {} remote xdb url '{}': {}", label, path_or_url, e))?;

    match url.scheme() {
        "http" | "https" => {}
        _ => {
            return Err(format!(
                "invalid {} remote xdb url scheme '{}', only http/https is supported",
                label,
                url.scheme()
            ));
        }
    }

    let mut hasher = Sha256::new();
    hasher.update(url.as_str().as_bytes());
    let hash = hex::encode(hasher.finalize());

    let cache_file = cache_dir.join(format!("{}_{}.xdb", label, hash));
    let current_file = cache_dir.join(format!("{}_{}.current", label, hash));
    let etag_file = cache_dir.join(format!("{}_{}.etag", label, hash));
    let last_modified_file = cache_dir.join(format!("{}_{}.last_modified", label, hash));

    Ok(DbSource::Remote {
        url,
        cache_file,
        current_file,
        etag_file,
        last_modified_file,
    })
}

async fn resolve_active_cache_file(cache_file: &Path, current_file: &Path) -> PathBuf {
    if let Some(active_name) = read_optional_text(current_file).await {
        let candidate = match cache_file.parent() {
            Some(parent) => parent.join(active_name),
            None => PathBuf::from(active_name),
        };

        if candidate.exists() {
            return candidate;
        }

        warn!(
            "ip_region_map pointer file {} points to missing file {}, fallback to {}",
            current_file.display(),
            candidate.display(),
            cache_file.display()
        );
    }

    cache_file.to_path_buf()
}

async fn write_current_cache_pointer(current_file: &Path, active_file: &Path) -> Result<(), String> {
    let file_name = active_file
        .file_name()
        .ok_or_else(|| format!("invalid active xdb path '{}': missing file name", active_file.display()))?
        .to_string_lossy()
        .to_string();

    let tmp_file = current_file.with_extension("current.tmp");
    tokio::fs::write(&tmp_file, file_name)
        .await
        .map_err(|e| e.to_string())?;

    tokio::fs::rename(&tmp_file, current_file)
        .await
        .map_err(|e| e.to_string())
}

fn make_versioned_cache_file(cache_file: &Path) -> Result<PathBuf, String> {
    let stem = cache_file
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or_else(|| format!("invalid xdb cache file '{}': missing file stem", cache_file.display()))?;
    let ext = cache_file
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("xdb");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_nanos();
    let versioned_file_name = format!("{}_{}.{}", stem, now, ext);

    Ok(cache_file.with_file_name(versioned_file_name))
}

async fn cleanup_old_versioned_cache_files(cache_file: &Path, active_file: &Path, keep: usize) {
    let Some(parent) = cache_file.parent() else {
        return;
    };

    let stem = match cache_file.file_stem().and_then(|s| s.to_str()) {
        Some(stem) => stem,
        None => return,
    };
    let ext = cache_file
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("xdb");
    let prefix = format!("{}_", stem);

    let mut entries = match tokio::fs::read_dir(parent).await {
        Ok(entries) => entries,
        Err(_) => return,
    };

    let mut versioned_files = Vec::new();
    while let Ok(Some(entry)) = entries.next_entry().await {
        let path = entry.path();
        if path == active_file {
            continue;
        }

        let Some(file_name) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        let matches_name = file_name.starts_with(prefix.as_str())
            && path.extension().and_then(|s| s.to_str()) == Some(ext);
        if matches_name {
            versioned_files.push(path);
        }
    }

    versioned_files.sort_by(|a, b| b.cmp(a));
    for stale in versioned_files.into_iter().skip(keep) {
        if let Err(err) = tokio::fs::remove_file(&stale).await {
            debug!(
                "ip_region_map remove stale xdb {} failed: {}",
                stale.display(),
                err
            );
        }
    }
}

fn spawn_refresh_task(db: DbHandle, interval_secs: u64) -> Option<JoinHandle<()>> {
    match &db.source {
        DbSource::Remote { .. } => {
            let task = tokio::spawn(async move {
                match db.refresh_remote().await {
                    Ok(true) => info!("ip_region_map {} xdb updated", db.label),
                    Ok(false) => debug!("ip_region_map {} xdb not modified", db.label),
                    Err(err) => warn!("ip_region_map {} update failed: {}", db.label, err),
                }

                let mut ticker = interval_at(
                    Instant::now() + Duration::from_secs(interval_secs),
                    Duration::from_secs(interval_secs),
                );

                loop {
                    ticker.tick().await;
                    match db.refresh_remote().await {
                        Ok(true) => info!("ip_region_map {} xdb updated", db.label),
                        Ok(false) => debug!("ip_region_map {} xdb not modified", db.label),
                        Err(err) => warn!("ip_region_map {} update failed: {}", db.label, err),
                    }
                }
            });
            Some(task)
        }
        DbSource::Local { .. } => None,
    }
}

async fn read_optional_text(path: &Path) -> Option<String> {
    let content = tokio::fs::read_to_string(path).await.ok()?;
    let value = content.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

fn check_sha256(bytes: &[u8], expected_hex: &str) -> Result<(), String> {
    let expected = expected_hex.trim().to_ascii_lowercase();
    if expected.is_empty() {
        return Ok(());
    }

    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let actual = hex::encode(hasher.finalize());

    if actual == expected {
        Ok(())
    } else {
        Err(format!(
            "sha256 mismatch, expected {}, got {}",
            expected, actual
        ))
    }
}

async fn download_remote_xdb(
    url: &Url,
    cache_file: &Path,
    current_file: &Path,
    etag_file: &Path,
    last_modified_file: &Path,
    request_timeout_secs: u64,
    expected_sha256: Option<&str>,
) -> Result<Option<PathBuf>, String> {
    if let Some(parent) = cache_file.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| e.to_string())?;
    }

    let mut request = reqwest::Client::builder()
        .timeout(Duration::from_secs(request_timeout_secs))
        .build()
        .map_err(|e| e.to_string())?
        .get(url.clone());

    if let Some(etag) = read_optional_text(etag_file).await {
        request = request.header(IF_NONE_MATCH, etag);
    }
    if let Some(last_modified) = read_optional_text(last_modified_file).await {
        request = request.header(IF_MODIFIED_SINCE, last_modified);
    }

    let response = request.send().await.map_err(|e| e.to_string())?;

    if response.status() == reqwest::StatusCode::NOT_MODIFIED {
        return Ok(None);
    }

    if !response.status().is_success() {
        return Err(format!(
            "download xdb from '{}' failed with status {}",
            url,
            response.status()
        ));
    }

    let etag = response
        .headers()
        .get(ETAG)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_string());
    let last_modified = response
        .headers()
        .get(LAST_MODIFIED)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_string());

    let bytes = response.bytes().await.map_err(|e| e.to_string())?;

    if let Some(expected_sha256) = expected_sha256 {
        check_sha256(bytes.as_ref(), expected_sha256)?;
    }

    let versioned_file = make_versioned_cache_file(cache_file)?;
    let tmp_file = versioned_file.with_extension("tmp");
    tokio::fs::write(&tmp_file, &bytes)
        .await
        .map_err(|e| e.to_string())?;

    tokio::fs::rename(&tmp_file, &versioned_file)
        .await
        .map_err(|e| e.to_string())?;

    if !cache_file.exists() {
        let _ = tokio::fs::copy(&versioned_file, cache_file).await;
    }

    if !current_file.exists() {
        let _ = write_current_cache_pointer(current_file, &versioned_file).await;
    }

    if let Some(etag) = etag {
        tokio::fs::write(etag_file, etag)
            .await
            .map_err(|e| e.to_string())?;
    }
    if let Some(last_modified) = last_modified {
        tokio::fs::write(last_modified_file, last_modified)
            .await
            .map_err(|e| e.to_string())?;
    }

    Ok(Some(versioned_file))
}
