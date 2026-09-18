use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_util::{StreamExt, stream};
use http::{Request, Response, StatusCode};
use http_body_util::BodyExt;
use ndn_lib::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

use super::dispatch::*;
use crate::{
    HttpServer, Server, ServerConfig, ServerContextRef, ServerErrorCode, ServerFactory,
    ServerResult, StreamInfo, server_err,
};

fn default_timeout() -> String {
    "3s".into()
}
fn default_poll() -> String {
    "5s".into()
}
fn default_backoff() -> Vec<String> {
    ["5s", "30s", "2m", "10m"]
        .into_iter()
        .map(String::from)
        .collect()
}
fn default_object_bytes() -> u64 {
    65536
}
fn default_entries() -> usize {
    10000
}
fn default_bytes() -> u64 {
    268435456
}
fn default_concurrency() -> usize {
    1
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamedInboxPrincipalQuota {
    pub max_entries: usize,
    pub max_bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamedInboxCacheServerConfig {
    pub id: String,
    #[serde(rename = "type")]
    pub ty: String,
    pub target_zone: String,
    pub accepted_paths: Vec<String>,
    pub cache_path: PathBuf,
    #[serde(default)]
    pub upstream: Option<String>,
    #[serde(default = "default_timeout")]
    pub upstream_timeout: String,
    #[serde(default = "default_poll")]
    pub poll_interval: String,
    #[serde(default = "default_backoff")]
    pub retry_backoff: Vec<String>,
    #[serde(default = "default_concurrency")]
    pub concurrency: usize,
    #[serde(default)]
    pub drain_enabled: Option<bool>,
    #[serde(default = "default_object_bytes")]
    pub max_object_bytes: u64,
    #[serde(default = "default_entries")]
    pub max_entries: usize,
    #[serde(default = "default_bytes")]
    pub max_bytes: u64,
    #[serde(default)]
    pub per_principal_quota: Option<NamedInboxPrincipalQuota>,
    #[serde(default)]
    pub cache_ttl: Option<String>,
}

impl ServerConfig for NamedInboxCacheServerConfig {
    fn id(&self) -> String {
        self.id.clone()
    }
    fn server_type(&self) -> String {
        "named-inbox-cache".into()
    }
    fn get_config_json(&self) -> String {
        serde_json::to_string(self).unwrap()
    }
}

fn duration(raw: &str) -> Result<Duration, String> {
    let duration = crate::forward::parse_duration_str(raw)?;
    if duration.is_zero() {
        return Err("duration must be positive".into());
    }
    Ok(duration)
}

impl NamedInboxCacheServerConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.ty != "named-inbox-cache"
            || self.id.is_empty()
            || self.cache_path.as_os_str().is_empty()
            || self.accepted_paths.is_empty()
            || self.max_object_bytes == 0
            || self.max_object_bytes > usize::MAX as u64 / 8
            || self.max_entries == 0
            || self.max_bytes == 0
            || self.concurrency == 0
            || self.retry_backoff.is_empty()
        {
            return Err(
                "invalid named-inbox-cache identity, paths, capacity or scheduling limits".into(),
            );
        }
        for path in &self.accepted_paths {
            normalize_cyfs_dispatch_target(&self.target_zone, path).map_err(|e| e.to_string())?;
        }
        duration(&self.upstream_timeout)?;
        duration(&self.poll_interval)?;
        for value in &self.retry_backoff {
            duration(value)?;
        }
        if let Some(ttl) = &self.cache_ttl {
            duration(ttl)?;
        }
        if self
            .per_principal_quota
            .as_ref()
            .is_some_and(|q| q.max_entries == 0 || q.max_bytes == 0)
        {
            return Err("principal quotas must be positive".into());
        }
        if self.drain_enabled == Some(true) && self.upstream.is_none() {
            return Err("drain_enabled=true requires upstream".into());
        }
        if let Some(upstream) = &self.upstream {
            let url = url::Url::parse(upstream).map_err(|e| e.to_string())?;
            if !matches!(url.scheme(), "http" | "https")
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.path() != "/"
                || url.query().is_some()
                || url.fragment().is_some()
            {
                return Err(
                    "upstream must be an http(s) origin; the original semantic path is preserved"
                        .into(),
                );
            }
        }
        Ok(())
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[derive(Clone, Serialize, Deserialize)]
struct CacheEntry {
    instance: String,
    target: String,
    obj_id: ObjId,
    body: String,
    context: VerifiedDispatchContext,
    expires_at_ms: Option<u64>,
    attempts: u64,
    next_attempt_at: u64,
    last_error: Option<String>,
}

impl CacheEntry {
    fn key(&self) -> String {
        hex::encode(Sha256::digest(
            format!("{}\n{}", self.target, self.obj_id).as_bytes(),
        ))
    }
    fn expired(&self) -> bool {
        self.expires_at_ms.is_some_and(|v| v <= now_ms())
    }
    fn bytes(&self) -> u64 {
        self.body.len() as u64
    }
}

#[derive(Default)]
struct CacheState {
    entries: HashMap<String, CacheEntry>,
    bytes: u64,
    principals: HashMap<String, (usize, u64)>,
    initialized: bool,
}

impl CacheState {
    fn insert(&mut self, key: String, entry: CacheEntry) {
        self.remove(&key);
        self.bytes += entry.bytes();
        let quota = self
            .principals
            .entry(entry.context.principal.clone())
            .or_default();
        quota.0 += 1;
        quota.1 += entry.bytes();
        self.entries.insert(key, entry);
    }
    fn remove(&mut self, key: &str) {
        if let Some(entry) = self.entries.remove(key) {
            self.bytes -= entry.bytes();
            let quota = self.principals.get_mut(&entry.context.principal).unwrap();
            quota.0 -= 1;
            quota.1 -= entry.bytes();
            if quota.0 == 0 {
                self.principals.remove(&entry.context.principal);
            }
        }
    }
}

struct SharedStore {
    instance: String,
    zone: String,
    state: Mutex<CacheState>,
    drain: Mutex<()>,
}

// A reloaded server can overlap outstanding requests on the previous instance.
// Share both quota accounting and drain coordination for that cache directory.
static STORES: once_cell::sync::Lazy<StdMutex<HashMap<PathBuf, Weak<SharedStore>>>> =
    once_cell::sync::Lazy::new(|| StdMutex::new(HashMap::new()));

struct InboxInner {
    config: NamedInboxCacheServerConfig,
    targets: Vec<String>,
    store: Arc<SharedStore>,
    client: reqwest::Client,
    timeout: Duration,
    backoff: Vec<Duration>,
    ttl: Option<Duration>,
}

pub struct NamedInboxCacheServer {
    inner: Arc<InboxInner>,
    worker: Option<JoinHandle<()>>,
}

impl Drop for NamedInboxCacheServer {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.take() {
            worker.abort();
        }
    }
}

impl NamedInboxCacheServer {
    pub async fn new(mut config: NamedInboxCacheServerConfig) -> ServerResult<Self> {
        config
            .validate()
            .map_err(|e| server_err!(ServerErrorCode::InvalidConfig, "{}", e))?;
        config.cache_path = super::normalize_path(
            &std::path::absolute(&config.cache_path)
                .map_err(|e| server_err!(ServerErrorCode::InvalidConfig, "{}", e))?,
        );
        if let Ok(canonical) = std::fs::canonicalize(&config.cache_path) {
            config.cache_path = canonical;
        }
        let targets: Vec<_> = config
            .accepted_paths
            .iter()
            .map(|p| normalize_cyfs_dispatch_target(&config.target_zone, p).unwrap())
            .collect();
        let zone = targets[0].split('/').nth(2).unwrap().to_string();
        let store = {
            let mut stores = STORES.lock().unwrap();
            stores.retain(|_, v| v.strong_count() > 0);
            if let Some(store) = stores.get(&config.cache_path).and_then(Weak::upgrade) {
                if store.instance != config.id || store.zone != zone {
                    return Err(server_err!(
                        ServerErrorCode::InvalidConfig,
                        "cache_path belongs to a different logical receiver"
                    ));
                }
                store
            } else {
                let store = Arc::new(SharedStore {
                    instance: config.id.clone(),
                    zone,
                    state: Mutex::new(CacheState::default()),
                    drain: Mutex::new(()),
                });
                stores.insert(config.cache_path.clone(), Arc::downgrade(&store));
                store
            }
        };
        let inner = Arc::new(InboxInner {
            targets,
            store,
            client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .no_proxy()
                .build()
                .map_err(|e| server_err!(ServerErrorCode::InvalidConfig, "{}", e))?,
            timeout: duration(&config.upstream_timeout).unwrap(),
            backoff: config
                .retry_backoff
                .iter()
                .map(|v| duration(v).unwrap())
                .collect(),
            ttl: config.cache_ttl.as_deref().map(|v| duration(v).unwrap()),
            config,
        });
        inner.recover().await;
        let worker = if inner
            .config
            .drain_enabled
            .unwrap_or(inner.config.upstream.is_some())
        {
            let inner = inner.clone();
            Some(tokio::spawn(async move {
                let mut interval =
                    tokio::time::interval(duration(&inner.config.poll_interval).unwrap());
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    interval.tick().await;
                    inner.drain().await;
                }
            }))
        } else {
            None
        };
        Ok(Self { inner, worker })
    }
}

enum UpstreamResult {
    Confirmed(StatusCode, CyfsDispatchResult, Option<http::HeaderValue>),
    Transport { sent: bool, message: String },
    Invalid(String),
}

struct PendingRecord(PathBuf);

impl Drop for PendingRecord {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

impl InboxInner {
    fn path(&self, key: &str) -> PathBuf {
        self.config.cache_path.join(format!("{key}.json"))
    }

    async fn read_entry(&self, path: &Path) -> Result<CacheEntry, String> {
        let max = self
            .config
            .max_object_bytes
            .saturating_mul(6)
            .saturating_add(131072);
        let file = tokio::fs::File::open(path)
            .await
            .map_err(|e| e.to_string())?;
        let mut bytes = Vec::new();
        file.take(max + 1)
            .read_to_end(&mut bytes)
            .await
            .map_err(|e| e.to_string())?;
        if bytes.len() as u64 > max {
            return Err("cache record too large".into());
        }
        let entry: CacheEntry = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        let target = url::Url::parse(&entry.target).map_err(|e| e.to_string())?;
        if normalize_cyfs_dispatch_target(target.host_str().unwrap_or(""), target.path())
            .map_err(|e| e.to_string())?
            != entry.target
        {
            return Err("invalid cached target".into());
        }
        if entry.instance != self.config.id
            || entry.expired()
            || entry.bytes() > self.config.max_object_bytes
            || !entry.context.validate()
            || entry.context.target != entry.target
            || !entry
                .target
                .starts_with(&format!("cyfs://{}/", self.store.zone))
            || path != self.path(&entry.key())
        {
            return Err("incomplete, expired or foreign cache entry".into());
        }
        validate_cyfs_dispatch_object(entry.body.as_bytes(), Some(&entry.obj_id.to_string()))
            .map_err(|e| e.to_string())?;
        Ok(entry)
    }

    async fn recover(&self) {
        let mut state = self.store.state.lock().await;
        if state.initialized {
            return;
        }
        state.initialized = true;
        let mut files = match tokio::fs::read_dir(&self.config.cache_path).await {
            Ok(files) => files,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
            Err(e) => {
                log::warn!(
                    "inbox {}: cache recovery unavailable: {}",
                    self.config.id,
                    e
                );
                return;
            }
        };
        while let Ok(Some(file)) = files.next_entry().await {
            let path = file.path();
            if path.extension().is_some_and(|v| v == "tmp") {
                let _ = tokio::fs::remove_file(path).await;
                continue;
            }
            if path.extension().is_none_or(|v| v != "json") {
                continue;
            }
            match self.read_entry(&path).await {
                Ok(entry) if self.fits(&state, &entry) => state.insert(entry.key(), entry),
                Ok(_) | Err(_) => {
                    let _ = tokio::fs::remove_file(path).await;
                }
            }
        }
    }

    fn fits(&self, state: &CacheState, entry: &CacheEntry) -> bool {
        if state.entries.len() >= self.config.max_entries
            || state
                .bytes
                .checked_add(entry.bytes())
                .is_none_or(|n| n > self.config.max_bytes)
        {
            return false;
        }
        if let Some(quota) = &self.config.per_principal_quota {
            let (entries, bytes) = state
                .principals
                .get(&entry.context.principal)
                .copied()
                .unwrap_or_default();
            if entries >= quota.max_entries
                || bytes
                    .checked_add(entry.bytes())
                    .is_none_or(|n| n > quota.max_bytes)
            {
                return false;
            }
        }
        true
    }

    async fn persist(&self, key: &str, entry: &CacheEntry) -> Result<(), String> {
        tokio::fs::create_dir_all(&self.config.cache_path)
            .await
            .map_err(|e| e.to_string())?;
        let tmp = self
            .config
            .cache_path
            .join(format!("{key}.{}.tmp", rand::random::<u64>()));
        let _pending = PendingRecord(tmp.clone());
        let bytes = serde_json::to_vec(entry).map_err(|e| e.to_string())?;
        let result = async {
            let mut options = tokio::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            options.mode(0o600);
            let mut file = options.open(&tmp).await?;
            file.write_all(&bytes).await?;
            file.flush().await?;
            drop(file);
            tokio::fs::rename(&tmp, self.path(key)).await
        }
        .await;
        if let Err(e) = result {
            let _ = tokio::fs::remove_file(tmp).await;
            return Err(e.to_string());
        }
        Ok(())
    }

    async fn cleanup(&self, state: &mut CacheState) {
        let expired: Vec<_> = state
            .entries
            .iter()
            .filter(|(_, e)| e.expired())
            .map(|(k, _)| k.clone())
            .collect();
        for key in expired {
            let _ = tokio::fs::remove_file(self.path(&key)).await;
            state.remove(&key);
        }
    }

    async fn cache(self: &Arc<Self>, entry: CacheEntry) -> Result<CacheEntry, &'static str> {
        // Finish disk write and index accounting even if the HTTP caller goes
        // away during filesystem I/O. A live caller awaits the completed write.
        let inner = self.clone();
        tokio::spawn(async move { inner.cache_inner(entry).await })
            .await
            .map_err(|_| "cache-write-failed")?
    }

    async fn cache_inner(&self, entry: CacheEntry) -> Result<CacheEntry, &'static str> {
        let mut state = self.store.state.lock().await;
        self.cleanup(&mut state).await;
        let key = entry.key();
        if state.entries.contains_key(&key) {
            // Recheck the actual record: a missing/corrupt file cannot be cached.
            if let Ok(mut existing) = self.read_entry(&self.path(&key)).await {
                if existing.context.principal != entry.context.principal {
                    return Err("principal-conflict");
                }
                existing.context = entry.context;
                if let Err(e) = self.persist(&key, &existing).await {
                    log::warn!(
                        "inbox {}: updating replay context failed: {}",
                        self.config.id,
                        e
                    );
                    return Err("cache-write-failed");
                }
                state.entries.insert(key, existing.clone());
                return Ok(existing);
            }
            state.remove(&key);
        }
        if !self.fits(&state, &entry) {
            return Err("cache-full");
        }
        if let Err(e) = self.persist(&key, &entry).await {
            log::warn!("inbox {}: cache write failed: {}", self.config.id, e);
            return Err("cache-write-failed");
        }
        state.insert(key, entry.clone());
        Ok(entry)
    }

    async fn send(&self, entry: &CacheEntry) -> UpstreamResult {
        let upstream = self.config.upstream.as_ref().unwrap();
        let target = url::Url::parse(&entry.target).unwrap();
        let mut url = url::Url::parse(upstream).unwrap();
        url.set_path(target.path());
        let operation = async {
            let mut request = self
                .client
                .put(url)
                .header("host", target.host_str().unwrap())
                .header("content-type", CYFS_CONTENT_TYPE_NAMED_OBJECT_JSON)
                .header(CYFS_HEADER_OBJ_ID, entry.obj_id.to_string())
                .header(CYFS_HEADER_ORIGINAL_USER, &entry.context.principal)
                .body(entry.body.clone());
            for (key, value) in &entry.context.credentials {
                request = request.header(key, value);
            }
            let mut response = match request.send().await {
                Ok(r) => r,
                Err(e) => {
                    return UpstreamResult::Transport {
                        sent: !e.is_connect(),
                        message: e.to_string(),
                    };
                }
            };
            let status = response.status();
            let headers = response.headers().clone();
            let mut body = Vec::new();
            loop {
                match response.chunk().await {
                    Ok(Some(chunk)) if body.len() + chunk.len() <= 65536 => {
                        body.extend_from_slice(&chunk)
                    }
                    Ok(Some(_)) => {
                        return UpstreamResult::Invalid("upstream status body too large".into());
                    }
                    Ok(None) => break,
                    Err(e) => {
                        return UpstreamResult::Transport {
                            sent: true,
                            message: e.to_string(),
                        };
                    }
                }
            }
            match parse_cyfs_dispatch_result(
                status.as_u16(),
                &headers,
                &body,
                &entry.obj_id,
                &entry.target,
                false,
            ) {
                Ok(result) => {
                    UpstreamResult::Confirmed(status, result, headers.get("retry-after").cloned())
                }
                Err(e) => UpstreamResult::Invalid(e.to_string()),
            }
        };
        tokio::time::timeout(self.timeout, operation)
            .await
            .unwrap_or_else(|_| UpstreamResult::Transport {
                sent: true,
                message: "upstream timeout".into(),
            })
    }

    async fn drain(&self) {
        let _guard = self.store.drain.lock().await;
        let entries = {
            let mut state = self.store.state.lock().await;
            self.cleanup(&mut state).await;
            let mut entries: Vec<_> = state
                .entries
                .iter()
                .filter(|(_, e)| e.next_attempt_at <= now_ms())
                .map(|(key, e)| (key.clone(), e.next_attempt_at))
                .collect();
            entries.sort_by_key(|(_, next)| *next);
            entries
        };
        stream::iter(entries)
            .for_each_concurrent(self.config.concurrency, |(key, _)| async move {
                // Check the stored object immediately before replay, including TTL.
                let entry = match self.read_entry(&self.path(&key)).await {
                    Ok(entry) => entry,
                    Err(_) => {
                        self.store.state.lock().await.remove(&key);
                        return;
                    }
                };
                let result = self.send(&entry).await;
                let mut state = self.store.state.lock().await;
                let Some(current) = state.entries.get(&key) else {
                    return;
                };
                if current.context.received_at_ms != entry.context.received_at_ms {
                    return;
                }
                let error = match result {
                    UpstreamResult::Confirmed(_, result, _)
                        if result.status == CyfsDispatchStatus::Accepted
                            || (result.status == CyfsDispatchStatus::Rejected
                                && result.retryable == Some(false)) =>
                    {
                        if result.status == CyfsDispatchStatus::Rejected {
                            log::warn!(
                                "inbox {}: upstream permanently rejected {}: {:?}",
                                self.config.id,
                                key,
                                result.reason
                            );
                        }
                        if let Err(e) = tokio::fs::remove_file(self.path(&key)).await {
                            log::warn!(
                                "inbox {}: deleting completed entry failed: {}",
                                self.config.id,
                                e
                            );
                        }
                        state.remove(&key);
                        return;
                    }
                    UpstreamResult::Confirmed(_, result, _)
                        if result.status == CyfsDispatchStatus::Cached =>
                    {
                        log::warn!(
                            "inbox {}: upstream returned cached; check upstream configuration",
                            self.config.id
                        );
                        "upstream-returned-cached".to_string()
                    }
                    UpstreamResult::Confirmed(_, result, _) => {
                        result.reason.unwrap_or_else(|| "upstream-retryable".into())
                    }
                    UpstreamResult::Transport { message, .. }
                    | UpstreamResult::Invalid(message) => message,
                };
                let mut updated = current.clone();
                let delay = self.backoff[(updated.attempts as usize).min(self.backoff.len() - 1)];
                updated.attempts = updated.attempts.saturating_add(1);
                updated.next_attempt_at = now_ms().saturating_add(delay.as_millis() as u64);
                updated.last_error = Some(error.chars().take(1024).collect());
                if let Err(e) = self.persist(&key, &updated).await {
                    log::warn!(
                        "inbox {}: retry metadata write failed: {}",
                        self.config.id,
                        e
                    );
                }
                state.entries.insert(key, updated);
            })
            .await;
    }

    async fn handle(self: &Arc<Self>, mut req: Request<DispatchBody>) -> Response<DispatchBody> {
        let target = match dispatch_target(&req) {
            Ok(target) => target,
            Err(_) => return dispatch_rejected(StatusCode::BAD_REQUEST, "", "invalid-target"),
        };
        if !self.targets.contains(&target) {
            return dispatch_rejected(StatusCode::NOT_FOUND, &target, "no-handler");
        }
        if req.method() != http::Method::PUT {
            return dispatch_rejected(
                StatusCode::METHOD_NOT_ALLOWED,
                &target,
                "method-not-allowed",
            );
        }
        if req.uri().query().is_some() {
            return dispatch_rejected(StatusCode::BAD_REQUEST, &target, "invalid-query");
        }
        if !req
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .is_some_and(is_cyfs_named_object_content_type)
            || req.headers().contains_key("content-encoding")
        {
            return dispatch_rejected(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                &target,
                "unsupported-content-type",
            );
        }
        let context = match req.extensions().get::<VerifiedDispatchContext>() {
            Some(context) if context.validate() && context.target == target => context.clone(),
            _ => return dispatch_rejected(StatusCode::UNAUTHORIZED, &target, "unauthenticated"),
        };
        let max = self.config.max_object_bytes;
        if req.headers().get("content-length").is_some_and(|v| {
            v.to_str()
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .is_none_or(|v| v > max)
        }) {
            return dispatch_rejected(StatusCode::PAYLOAD_TOO_LARGE, &target, "object-too-large");
        }
        let claimed = match req.headers().get(CYFS_HEADER_OBJ_ID) {
            Some(value) => match value.to_str() {
                Ok(v) => Some(v.to_string()),
                Err(_) => {
                    return dispatch_rejected(
                        StatusCode::BAD_REQUEST,
                        &target,
                        "invalid-object-id",
                    );
                }
            },
            None => None,
        };
        let mut body = Vec::new();
        while let Some(frame) = req.body_mut().frame().await {
            match frame {
                Ok(frame) => {
                    if let Some(data) = frame.data_ref() {
                        if data.len() as u64 > max - body.len() as u64 {
                            return dispatch_rejected(
                                StatusCode::PAYLOAD_TOO_LARGE,
                                &target,
                                "object-too-large",
                            );
                        }
                        body.extend_from_slice(data);
                    }
                }
                Err(_) => {
                    return dispatch_rejected(StatusCode::BAD_REQUEST, &target, "body-read-failed");
                }
            }
        }
        let obj_id = match validate_cyfs_dispatch_object(&body, claimed.as_deref()) {
            Ok(id) => id,
            Err(_) => return dispatch_rejected(StatusCode::BAD_REQUEST, &target, "invalid-object"),
        };
        let entry = CacheEntry {
            instance: self.config.id.clone(),
            target: target.clone(),
            obj_id: obj_id.clone(),
            body: String::from_utf8(body).unwrap(),
            context,
            expires_at_ms: self
                .ttl
                .map(|ttl| now_ms().saturating_add(ttl.as_millis() as u64)),
            attempts: 0,
            next_attempt_at: now_ms().saturating_add(self.backoff[0].as_millis() as u64),
            last_error: None,
        };
        let mut sent = false;
        if self.config.upstream.is_some() {
            match self.send(&entry).await {
                UpstreamResult::Confirmed(status, result, retry_after)
                    if result.status != CyfsDispatchStatus::Cached =>
                {
                    let mut response = dispatch_response(status, &result);
                    if let Some(value) = retry_after {
                        response.headers_mut().insert("retry-after", value);
                    }
                    return response;
                }
                UpstreamResult::Transport {
                    sent: was_sent,
                    message,
                } => {
                    sent = was_sent;
                    log::debug!(
                        "inbox {}: synchronous delivery failed: {}",
                        self.config.id,
                        message
                    );
                }
                UpstreamResult::Invalid(message) => {
                    log::warn!(
                        "inbox {}: invalid upstream response: {}",
                        self.config.id,
                        message
                    );
                    return dispatch_error(
                        StatusCode::BAD_GATEWAY,
                        &target,
                        CYFS_DISPATCH_ERROR_OUTCOME_UNKNOWN,
                    );
                }
                UpstreamResult::Confirmed(_, _, _) => {
                    log::warn!(
                        "inbox {}: upstream returned cached; check upstream configuration",
                        self.config.id
                    );
                    return dispatch_error(
                        StatusCode::BAD_GATEWAY,
                        &target,
                        CYFS_DISPATCH_ERROR_OUTCOME_UNKNOWN,
                    );
                }
            }
        }
        match self.cache(entry).await {
            Ok(entry) => {
                let mut result =
                    CyfsDispatchResult::new(Some(obj_id), target, CyfsDispatchStatus::Cached);
                result.expires_at_ms = entry.expires_at_ms;
                dispatch_response(StatusCode::ACCEPTED, &result)
            }
            Err(_) if sent => dispatch_error(
                StatusCode::GATEWAY_TIMEOUT,
                &target,
                CYFS_DISPATCH_ERROR_OUTCOME_UNKNOWN,
            ),
            Err(reason) => {
                let status = if reason == "principal-conflict" {
                    StatusCode::FORBIDDEN
                } else {
                    StatusCode::SERVICE_UNAVAILABLE
                };
                let mut response = dispatch_response(
                    status,
                    &CyfsDispatchResult::rejected(
                        Some(obj_id),
                        target,
                        reason,
                        status.is_server_error(),
                    ),
                );
                if status.is_server_error() {
                    response.headers_mut().insert(
                        "retry-after",
                        self.backoff[0]
                            .as_secs()
                            .max(1)
                            .to_string()
                            .parse()
                            .unwrap(),
                    );
                }
                response
            }
        }
    }
}

#[async_trait::async_trait]
impl HttpServer for NamedInboxCacheServer {
    async fn serve_request(
        &self,
        req: Request<DispatchBody>,
        _info: StreamInfo,
    ) -> ServerResult<Response<DispatchBody>> {
        Ok(self.inner.handle(req).await)
    }
    fn id(&self) -> String {
        self.inner.config.id.clone()
    }
    fn http_version(&self) -> http::Version {
        http::Version::HTTP_11
    }
    fn http3_port(&self) -> Option<u16> {
        None
    }
}

pub struct NamedInboxCacheServerFactory;

#[async_trait::async_trait]
impl ServerFactory for NamedInboxCacheServerFactory {
    async fn create(
        &self,
        config: Arc<dyn ServerConfig>,
        _context: Option<ServerContextRef>,
    ) -> ServerResult<Vec<Server>> {
        let config = config
            .as_any()
            .downcast_ref::<NamedInboxCacheServerConfig>()
            .ok_or_else(|| {
                server_err!(
                    ServerErrorCode::InvalidConfig,
                    "invalid named-inbox-cache config"
                )
            })?;
        Ok(vec![Server::Http(Arc::new(
            NamedInboxCacheServer::new(config.clone()).await?,
        ))])
    }
}

#[cfg(test)]
#[path = "named_inbox_cache_tests.rs"]
mod tests;
