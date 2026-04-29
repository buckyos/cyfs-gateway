use crate::cert_mgr::{CertMaterial, CertProvider, CertRequest, CertStatus, CertStatusState};
use anyhow::Result;
use log::*;
use openssl::pkey::PKey;
use openssl::x509::X509;
use rustls::crypto::ring::sign::any_supported_type;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::ClientHello;
use rustls::sign::CertifiedKey;
use serde::Deserialize;
use serde_json::{Value, json};
use sfo_js::{JsEngine, JsPkgManager, JsPkgManagerRef, JsValue};
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use tokio::fs;
use tokio::task::JoinHandle;

const JS_ENGINE_THREAD_STACK_SIZE: usize = 256 * 1024 * 1024;
const JS_EXTEND_CERT_RETRY_INITIAL_INTERVAL_SECS: u64 = 15;
const JS_EXTEND_CERT_RETRY_MAX_INTERVAL_SECS: u64 = 600;

#[derive(Clone, Debug)]
pub struct JsExtendCertProviderRuntimeConfig {
    pub id: String,
    pub script_path: Option<PathBuf>,
    pub script_name: Option<String>,
    pub script_pkg_dir: Option<PathBuf>,
    pub store_root: PathBuf,
    pub check_interval: chrono::Duration,
    pub renew_before_expiry: chrono::Duration,
    pub params: Value,
}

#[derive(Clone)]
enum JsExtendCertScriptSource {
    Path(PathBuf),
    Package {
        manager: JsPkgManagerRef,
        name: String,
    },
}

#[derive(Clone)]
struct JsExtendCertScriptRunner {
    source: JsExtendCertScriptSource,
    params: Value,
}

struct JsExtendCertInfo {
    key: Arc<CertifiedKey>,
    certs: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
    expires: chrono::DateTime<chrono::Utc>,
}

impl Clone for JsExtendCertInfo {
    fn clone(&self) -> Self {
        Self {
            key: self.key.clone(),
            certs: self.certs.clone(),
            private_key: clone_private_key(&self.private_key),
            expires: self.expires,
        }
    }
}

enum JsExtendCertState {
    Pending,
    Ready(JsExtendCertInfo),
    Renewing(JsExtendCertInfo),
    Expired(JsExtendCertInfo),
    Error,
}

struct JsExtendCertRequestInner {
    state: JsExtendCertState,
    last_error: Option<String>,
}

struct JsExtendCertRequestState {
    request: CertRequest,
    store_dir: PathBuf,
    inner: Mutex<JsExtendCertRequestInner>,
    handle: Mutex<Option<JoinHandle<()>>>,
}

struct JsExtendCertProviderInner {
    id: String,
    store_root: PathBuf,
    runner: JsExtendCertScriptRunner,
    check_interval: chrono::Duration,
    renew_before_expiry: chrono::Duration,
    retry_config: JsExtendCertRetryConfig,
    requests: RwLock<HashMap<String, Arc<JsExtendCertRequestState>>>,
    check_handler: Mutex<Option<JoinHandle<()>>>,
}

#[derive(Clone)]
pub struct JsExtendCertProvider {
    inner: Arc<JsExtendCertProviderInner>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JsExtendCertScriptOutput {
    cert: String,
    key: String,
}

#[derive(Clone, Copy)]
struct JsExtendCertRetryConfig {
    initial_interval: std::time::Duration,
    max_interval: std::time::Duration,
}

impl Default for JsExtendCertRetryConfig {
    fn default() -> Self {
        Self {
            initial_interval: std::time::Duration::from_secs(
                JS_EXTEND_CERT_RETRY_INITIAL_INTERVAL_SECS,
            ),
            max_interval: std::time::Duration::from_secs(JS_EXTEND_CERT_RETRY_MAX_INTERVAL_SECS),
        }
    }
}

impl Drop for JsExtendCertProviderInner {
    fn drop(&mut self) {
        if let Some(handle) = self.check_handler.lock().unwrap().take() {
            if !handle.is_finished() {
                handle.abort();
            }
        }
        for state in self.requests.write().unwrap().values() {
            state.abort_task();
        }
    }
}

impl Debug for JsExtendCertProvider {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JsExtendCertProvider")
            .field("id", &self.inner.id)
            .field("store_root", &self.inner.store_root)
            .finish()
    }
}

impl JsExtendCertProvider {
    pub fn new(config: JsExtendCertProviderRuntimeConfig) -> Result<Arc<Self>> {
        Self::new_with_retry_config(config, JsExtendCertRetryConfig::default())
    }

    fn new_with_retry_config(
        config: JsExtendCertProviderRuntimeConfig,
        retry_config: JsExtendCertRetryConfig,
    ) -> Result<Arc<Self>> {
        if config.script_path.is_some() == config.script_name.is_some() {
            return Err(anyhow::anyhow!(
                "js_extend cert provider requires exactly one of script_path or script_name"
            ));
        }

        let source_desc = if let Some(script_path) = config.script_path.as_ref() {
            format!("path {}", script_path.display())
        } else {
            format!(
                "package {} under {}",
                config.script_name.as_deref().unwrap_or("<missing>"),
                config
                    .script_pkg_dir
                    .as_ref()
                    .map(|path| path.display().to_string())
                    .unwrap_or_else(|| "<missing>".to_string())
            )
        };

        if let Some(script_path) = config.script_path.as_ref() {
            if !script_path.is_file() {
                return Err(anyhow::anyhow!(
                    "js_extend cert provider script_path is not readable: {}",
                    script_path.display()
                ));
            }
        }

        std::fs::create_dir_all(&config.store_root).map_err(|e| {
            anyhow::anyhow!(
                "create js_extend cert provider store root {} failed: {}",
                config.store_root.display(),
                e
            )
        })?;

        info!(
            "create js_extend cert provider id={} source={} store_root={} check_interval={}s renew_before_expiry={}s",
            config.id,
            source_desc,
            config.store_root.display(),
            config.check_interval.num_seconds(),
            config.renew_before_expiry.num_seconds()
        );

        let source = if let Some(script_path) = config.script_path {
            JsExtendCertScriptSource::Path(script_path)
        } else {
            let script_pkg_dir = config.script_pkg_dir.ok_or_else(|| {
                anyhow::anyhow!("script_pkg_dir is required when script_name is configured")
            })?;
            JsExtendCertScriptSource::Package {
                manager: JsPkgManager::new(script_pkg_dir),
                name: config.script_name.unwrap(),
            }
        };

        let provider = Arc::new(Self {
            inner: Arc::new(JsExtendCertProviderInner {
                id: config.id,
                store_root: config.store_root,
                runner: JsExtendCertScriptRunner {
                    source,
                    params: config.params,
                },
                check_interval: config.check_interval,
                renew_before_expiry: config.renew_before_expiry,
                retry_config,
                requests: RwLock::new(HashMap::new()),
                check_handler: Mutex::new(None),
            }),
        });

        provider.start_check_task();
        Ok(provider)
    }

    fn start_check_task(self: &Arc<Self>) {
        let weak_provider = Arc::downgrade(self);
        let interval_secs = self.inner.check_interval.num_seconds().max(1) as u64;
        info!(
            "start js_extend cert provider check task id={} interval={}s",
            self.inner.id, interval_secs
        );
        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
            loop {
                interval.tick().await;
                let Some(provider) = weak_provider.upgrade() else {
                    break;
                };
                provider.check_all_requests();
            }
        });
        *self.inner.check_handler.lock().unwrap() = Some(handle);
    }

    fn check_all_requests(&self) {
        let requests = self
            .inner
            .requests
            .read()
            .unwrap()
            .values()
            .cloned()
            .collect::<Vec<_>>();
        for state in requests {
            if state.should_refresh(self.inner.renew_before_expiry) {
                info!(
                    "js_extend cert provider id={} schedule refresh for domain={}",
                    self.inner.id, state.request.domain
                );
                self.spawn_refresh(state);
            }
        }
    }

    fn spawn_load_or_refresh(&self, state: Arc<JsExtendCertRequestState>) {
        let runner = self.inner.runner.clone();
        let renew_before_expiry = self.inner.renew_before_expiry;
        let retry_config = self.inner.retry_config;
        let task_state = state.clone();
        state.spawn_task(async move {
            match task_state.load_latest().await {
                Ok(Some(info)) => {
                    task_state.set_ready(info);
                    if task_state.should_refresh(renew_before_expiry) {
                        task_state.refresh_with_retry(runner, retry_config).await?;
                    }
                    Ok(())
                }
                Ok(None) => task_state.refresh_with_retry(runner, retry_config).await,
                Err(err) => {
                    task_state.set_last_error(Some(err.to_string()));
                    task_state.refresh_with_retry(runner, retry_config).await
                }
            }
        });
    }

    fn spawn_refresh(&self, state: Arc<JsExtendCertRequestState>) {
        let runner = self.inner.runner.clone();
        let retry_config = self.inner.retry_config;
        let task_state = state.clone();
        state.spawn_task(async move { task_state.refresh_with_retry(runner, retry_config).await });
    }

    fn get_request(&self, domain: &str) -> Option<Arc<JsExtendCertRequestState>> {
        let domain = domain.to_lowercase();
        let requests = self.inner.requests.read().unwrap();
        requests.get(&domain).cloned().or_else(|| {
            requests
                .iter()
                .find(|(route_domain, _)| {
                    route_domain.starts_with("*.") && host_matches_wildcard(&domain, route_domain)
                })
                .map(|(_, state)| state.clone())
        })
    }
}

impl CertProvider for JsExtendCertProvider {
    fn id(&self) -> &str {
        &self.inner.id
    }

    fn add_request(&self, request: CertRequest) -> Result<()> {
        let domain = request.domain.to_lowercase();
        let store_dir = self
            .inner
            .store_root
            .join(sanitize_path_component(request.domain.as_str()));
        std::fs::create_dir_all(&store_dir).map_err(|e| {
            anyhow::anyhow!(
                "create js_extend cert request store {} failed: {}",
                store_dir.display(),
                e
            )
        })?;

        let state = {
            let mut requests = self.inner.requests.write().unwrap();
            if let Some(state) = requests.get(&domain) {
                info!(
                    "js_extend cert provider id={} reuse request domain={} usage={:?} challenge={:?} store_dir={}",
                    self.inner.id,
                    request.domain,
                    request.usage,
                    request.challenge_type,
                    store_dir.display()
                );
                state.clone()
            } else {
                info!(
                    "js_extend cert provider id={} add request domain={} usage={:?} challenge={:?} store_dir={}",
                    self.inner.id,
                    request.domain,
                    request.usage,
                    request.challenge_type,
                    store_dir.display()
                );
                let state = Arc::new(JsExtendCertRequestState::new(request, store_dir));
                requests.insert(domain, state.clone());
                state
            }
        };
        self.spawn_load_or_refresh(state);
        Ok(())
    }

    fn resolve_server_cert(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let server_name = client_hello.server_name()?.to_lowercase();
        self.get_request(&server_name)
            .and_then(|state| state.get_certified_key())
    }

    fn resolve_client_cert(&self, domain: &str) -> Result<Option<CertMaterial>> {
        Ok(self
            .get_request(domain)
            .and_then(|state| state.get_material()))
    }

    fn get_status(&self, domain: &str) -> CertStatus {
        let Some(state) = self.get_request(domain) else {
            return CertStatus {
                provider: self.inner.id.clone(),
                domain: domain.to_string(),
                state: CertStatusState::Unknown,
                expires: None,
                last_error: Some("certificate request is not registered".to_string()),
            };
        };
        state.status(self.inner.id.clone())
    }

    fn get_http01_auth(&self, _token: &str) -> Option<String> {
        None
    }
}

impl JsExtendCertRequestState {
    fn new(request: CertRequest, store_dir: PathBuf) -> Self {
        Self {
            request,
            store_dir,
            inner: Mutex::new(JsExtendCertRequestInner {
                state: JsExtendCertState::Pending,
                last_error: None,
            }),
            handle: Mutex::new(None),
        }
    }

    fn spawn_task<F>(self: &Arc<Self>, future: F)
    where
        F: std::future::Future<Output = Result<()>> + Send + 'static,
    {
        let mut handle = self.handle.lock().unwrap();
        if handle.as_ref().is_some_and(|handle| !handle.is_finished()) {
            debug!(
                "js_extend cert request domain={} skip spawn because previous task is still running",
                self.request.domain
            );
            return;
        }
        let state = self.clone();
        handle.replace(tokio::spawn(async move {
            if let Err(err) = future.await {
                state.record_refresh_error(err.to_string());
            }
        }));
    }

    fn abort_task(&self) {
        if let Some(handle) = self.handle.lock().unwrap().take() {
            if !handle.is_finished() {
                handle.abort();
            }
        }
    }

    async fn load_latest(&self) -> Result<Option<JsExtendCertInfo>> {
        if !self.store_dir.exists() {
            info!(
                "js_extend cert request domain={} has no store dir {}",
                self.request.domain,
                self.store_dir.display()
            );
            return Ok(None);
        }

        let mut dir = fs::read_dir(&self.store_dir).await?;
        let mut entries = Vec::new();
        while let Some(entry) = dir.next_entry().await? {
            let path = entry.path();
            if path
                .file_name()
                .is_some_and(|name| name.to_string_lossy().ends_with(".cert"))
            {
                entries.push(path);
            }
        }

        if entries.is_empty() {
            info!(
                "js_extend cert request domain={} has no cached cert under {}",
                self.request.domain,
                self.store_dir.display()
            );
            return Ok(None);
        }

        entries.sort_by(|a, b| b.file_name().unwrap().cmp(a.file_name().unwrap()));
        let mut last_error = None;
        for cert_path in entries {
            let key_path = cert_path.with_extension("key");
            let cert_data = fs::read(&cert_path).await;
            let key_data = fs::read(&key_path).await;
            let result = match (cert_data, key_data) {
                (Ok(cert_data), Ok(key_data)) => build_cert_info(&cert_data, &key_data),
                (Err(err), _) => Err(anyhow::anyhow!(
                    "read cert {} failed: {}",
                    cert_path.display(),
                    err
                )),
                (_, Err(err)) => Err(anyhow::anyhow!(
                    "read key {} failed: {}",
                    key_path.display(),
                    err
                )),
            };
            match result {
                Ok(info) => {
                    info!(
                        "js_extend cert request domain={} loaded cached cert {} expires={}",
                        self.request.domain,
                        cert_path.display(),
                        info.expires
                    );
                    return Ok(Some(info));
                }
                Err(err) => {
                    warn!(
                        "js_extend cert request domain={} ignored cached cert {}: {}",
                        self.request.domain,
                        cert_path.display(),
                        err
                    );
                    last_error = Some(err);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("no valid certificate material found")))
    }

    async fn refresh_with_retry(
        &self,
        runner: JsExtendCertScriptRunner,
        retry_config: JsExtendCertRetryConfig,
    ) -> Result<()> {
        let mut retry_interval = retry_config.initial_interval;
        loop {
            match self.refresh_once(runner.clone()).await {
                Ok(()) => return Ok(()),
                Err(err) => {
                    let err = err.to_string();
                    self.record_refresh_error(err.clone());
                    retry_interval = next_retry_interval(retry_interval, retry_config.max_interval);
                    warn!(
                        "js_extend cert request domain={} will retry refresh in {}ms after failure: {}",
                        self.request.domain,
                        retry_interval.as_millis(),
                        err
                    );
                    tokio::time::sleep(retry_interval).await;
                }
            }
        }
    }

    async fn refresh_once(&self, runner: JsExtendCertScriptRunner) -> Result<()> {
        info!(
            "js_extend cert request domain={} start refresh",
            self.request.domain
        );
        self.mark_refreshing();
        let output = runner.run(self.request.domain.as_str()).await?;
        let cert_data = output.cert.into_bytes();
        let key_data = output.key.into_bytes();
        let info = build_cert_info(&cert_data, &key_data)?;
        info!(
            "js_extend cert request domain={} script returned valid material expires={}",
            self.request.domain, info.expires
        );
        self.save_material(&cert_data, &key_data).await?;
        self.set_ready(info);
        info!(
            "js_extend cert request domain={} refresh completed",
            self.request.domain
        );
        Ok(())
    }

    async fn save_material(&self, cert_data: &[u8], key_data: &[u8]) -> Result<()> {
        fs::create_dir_all(&self.store_dir).await?;
        let timestamp = chrono::Utc::now().timestamp_millis();
        let cert_path = self.store_dir.join(format!("{}.cert", timestamp));
        let key_path = self.store_dir.join(format!("{}.key", timestamp));
        fs::write(&cert_path, cert_data).await?;
        fs::write(&key_path, key_data).await?;
        info!(
            "js_extend cert request domain={} saved material cert={} key={}",
            self.request.domain,
            cert_path.display(),
            key_path.display()
        );
        Ok(())
    }

    fn mark_refreshing(&self) {
        let mut inner = self.inner.lock().unwrap();
        let state = std::mem::replace(&mut inner.state, JsExtendCertState::Pending);
        inner.state = match state {
            JsExtendCertState::Ready(info) | JsExtendCertState::Renewing(info) => {
                JsExtendCertState::Renewing(info)
            }
            JsExtendCertState::Expired(info) => JsExtendCertState::Expired(info),
            JsExtendCertState::Pending | JsExtendCertState::Error => JsExtendCertState::Pending,
        };
    }

    fn record_refresh_error(&self, err: String) {
        warn!(
            "js_extend cert request domain={} refresh failed: {}",
            self.request.domain, err
        );
        let mut inner = self.inner.lock().unwrap();
        inner.last_error = Some(err);
        if matches!(inner.state, JsExtendCertState::Pending) {
            inner.state = JsExtendCertState::Error;
        }
    }

    fn set_ready(&self, info: JsExtendCertInfo) {
        let mut inner = self.inner.lock().unwrap();
        inner.state = JsExtendCertState::Ready(info);
        inner.last_error = None;
    }

    fn set_last_error(&self, err: Option<String>) {
        self.inner.lock().unwrap().last_error = err;
    }

    fn should_refresh(&self, renew_before_expiry: chrono::Duration) -> bool {
        let mut inner = self.inner.lock().unwrap();
        match &inner.state {
            JsExtendCertState::Pending
            | JsExtendCertState::Error
            | JsExtendCertState::Expired(_) => true,
            JsExtendCertState::Ready(info) => {
                let now = chrono::Utc::now();
                if now >= info.expires {
                    let info = info.clone();
                    inner.state = JsExtendCertState::Expired(info);
                    true
                } else {
                    now >= info.expires - renew_before_expiry
                }
            }
            JsExtendCertState::Renewing(_) => true,
        }
    }

    fn get_certified_key(&self) -> Option<Arc<CertifiedKey>> {
        let inner = self.inner.lock().unwrap();
        match &inner.state {
            JsExtendCertState::Ready(info) | JsExtendCertState::Renewing(info) => {
                Some(info.key.clone())
            }
            JsExtendCertState::Pending
            | JsExtendCertState::Expired(_)
            | JsExtendCertState::Error => None,
        }
    }

    fn get_material(&self) -> Option<CertMaterial> {
        let inner = self.inner.lock().unwrap();
        match &inner.state {
            JsExtendCertState::Ready(info) | JsExtendCertState::Renewing(info) => {
                Some(info.to_material())
            }
            JsExtendCertState::Pending
            | JsExtendCertState::Expired(_)
            | JsExtendCertState::Error => None,
        }
    }

    fn status(&self, provider: String) -> CertStatus {
        let inner = self.inner.lock().unwrap();
        let (state, expires) = match &inner.state {
            JsExtendCertState::Pending => (CertStatusState::Pending, None),
            JsExtendCertState::Ready(info) => (CertStatusState::Ready, Some(info.expires)),
            JsExtendCertState::Renewing(info) => (CertStatusState::Renewing, Some(info.expires)),
            JsExtendCertState::Expired(info) => (CertStatusState::Expired, Some(info.expires)),
            JsExtendCertState::Error => (CertStatusState::Error, None),
        };
        CertStatus {
            provider,
            domain: self.request.domain.clone(),
            state,
            expires,
            last_error: inner.last_error.clone(),
        }
    }
}

impl Drop for JsExtendCertRequestState {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.lock().unwrap().take() {
            if !handle.is_finished() {
                handle.abort();
            }
        }
    }
}

impl JsExtendCertScriptRunner {
    async fn run(&self, domain: &str) -> Result<JsExtendCertScriptOutput> {
        let payload = json!({
            "domain": domain,
            "params": self.params.clone(),
        });
        let value = match &self.source {
            JsExtendCertScriptSource::Path(path) => {
                info!(
                    "js_extend cert script run domain={} source=path path={}",
                    domain,
                    path.display()
                );
                run_js_file(path.clone(), payload).await?
            }
            JsExtendCertScriptSource::Package { manager, name } => {
                info!(
                    "js_extend cert script resolve package domain={} name={}",
                    domain, name
                );
                let pkg = manager
                    .get_pkg(name.clone())
                    .await
                    .map_err(|e| anyhow::anyhow!(e))?;
                info!(
                    "js_extend cert script run domain={} source=package name={} main={}",
                    domain,
                    name,
                    pkg.main()
                );
                run_js_file(PathBuf::from(pkg.main()), payload).await?
            }
        };
        let output = serde_json::from_value::<JsExtendCertScriptOutput>(value)
            .map_err(|e| anyhow::anyhow!("invalid js_extend cert script output: {}", e))?;
        info!("js_extend cert script completed domain={}", domain);
        Ok(output)
    }
}

async fn run_js_file(path: PathBuf, payload: Value) -> Result<Value> {
    debug!("run js_extend cert script file {}", path.display());
    let (sender, receiver) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("cyfs-js-extend-cert-provider".to_string())
        .stack_size(JS_ENGINE_THREAD_STACK_SIZE)
        .spawn(move || {
            let result = run_js_file_on_current_thread(path, payload);
            let _ = sender.send(result);
        })
        .map_err(|e| anyhow::anyhow!("spawn js_extend cert script thread failed: {}", e))?;

    receiver
        .await
        .map_err(|e| anyhow::anyhow!("run js_extend cert script thread failed: {}", e))?
}

fn run_js_file_on_current_thread(path: PathBuf, payload: Value) -> Result<Value> {
    let mut js_engine = JsEngine::builder()
        .enable_fetch(true)
        .enable_console(true)
        .enable_commonjs(true)
        .build()
        .map_err(|e| anyhow::anyhow!(e))?;
    js_engine
        .eval_file(path.as_path())
        .map_err(|e| anyhow::anyhow!(e))?;
    let arg = JsValue::from_json(&payload, js_engine.context())
        .map_err(|e| anyhow::anyhow!("convert js input failed: {:?}", e))?;
    let result = js_engine
        .call("main", vec![arg])
        .map_err(|e| anyhow::anyhow!(e))?;
    result
        .to_json(js_engine.context())
        .map_err(|e| anyhow::anyhow!("convert js output failed: {:?}", e))?
        .ok_or_else(|| anyhow::anyhow!("js_extend cert script must return a json value"))
}

fn build_cert_info(cert_data: &[u8], key_data: &[u8]) -> Result<JsExtendCertInfo> {
    validate_cert_key_match(cert_data, key_data)?;
    let certs = parse_cert_chain(cert_data)?;
    let private_key = parse_private_key(key_data)?;
    let key = create_certified_key(certs.clone(), &private_key)?;
    let expires = get_cert_expiry(cert_data)?;
    if chrono::Utc::now() >= expires {
        return Err(anyhow::anyhow!("certificate is expired"));
    }
    Ok(JsExtendCertInfo {
        key: Arc::new(key),
        certs,
        private_key,
        expires,
    })
}

fn parse_cert_chain(cert_data: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    let mut cert_chain = vec![];
    for cert in rustls_pemfile::certs(&mut &*cert_data) {
        cert_chain.push(cert?);
    }
    if cert_chain.is_empty() {
        return Err(anyhow::anyhow!("No certificate found"));
    }
    Ok(cert_chain)
}

fn parse_private_key(key_data: &[u8]) -> Result<PrivateKeyDer<'static>> {
    rustls_pemfile::private_key(&mut &*key_data)?
        .ok_or_else(|| anyhow::anyhow!("No private key found"))
}

fn create_certified_key(
    cert_chain: Vec<CertificateDer<'static>>,
    key: &PrivateKeyDer<'static>,
) -> Result<CertifiedKey> {
    let signing_key =
        any_supported_type(key).map_err(|e| anyhow::anyhow!("Invalid private key: {}", e))?;
    Ok(CertifiedKey::new(cert_chain, signing_key))
}

fn validate_cert_key_match(cert_data: &[u8], key_data: &[u8]) -> Result<()> {
    let cert = X509::from_pem(cert_data)?;
    let public_key = cert.public_key()?;
    let private_key = PKey::private_key_from_pem(key_data)?;
    if !public_key.public_eq(&private_key) {
        return Err(anyhow::anyhow!("certificate and private key do not match"));
    }
    Ok(())
}

fn get_cert_expiry(cert_data: &[u8]) -> Result<chrono::DateTime<chrono::Utc>> {
    let cert = X509::from_pem(cert_data)?;
    let not_after = cert.not_after().to_string();
    let datetime_str = not_after
        .rsplitn(2, ' ')
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("Invalid datetime format"))?;
    let expires = chrono::NaiveDateTime::parse_from_str(datetime_str, "%b %e %H:%M:%S %Y")?;
    Ok(chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(
        expires,
        chrono::Utc,
    ))
}

fn clone_private_key(key: &PrivateKeyDer<'static>) -> PrivateKeyDer<'static> {
    match key {
        PrivateKeyDer::Pkcs8(key) => PrivateKeyDer::Pkcs8(key.clone_key()),
        PrivateKeyDer::Pkcs1(key) => PrivateKeyDer::Pkcs1(key.clone_key()),
        PrivateKeyDer::Sec1(key) => PrivateKeyDer::Sec1(key.clone_key()),
        _ => panic!("Unsupported key type"),
    }
}

impl JsExtendCertInfo {
    fn to_material(&self) -> CertMaterial {
        CertMaterial {
            certs: self.certs.clone(),
            private_key: clone_private_key(&self.private_key),
            expires: self.expires,
        }
    }
}

fn sanitize_path_component(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '*' => "_star_".to_string(),
            '?' => "_qmark_".to_string(),
            ':' => "_colon_".to_string(),
            '/' | '\\' => "_slash_".to_string(),
            c if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' => c.to_string(),
            c => format!("_x{:02x}_", c as u32),
        })
        .collect()
}

fn host_matches_wildcard(domain: &str, wildcard: &str) -> bool {
    if !wildcard.starts_with("*.") {
        return false;
    }
    let suffix = &wildcard[1..];
    domain.ends_with(suffix) && domain[..domain.len() - suffix.len()].find('.').is_none()
}

fn next_retry_interval(
    current: std::time::Duration,
    max: std::time::Duration,
) -> std::time::Duration {
    current.checked_mul(2).unwrap_or(max).min(max)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CertUsage, ChallengeType};
    use rcgen::generate_simple_self_signed;
    use std::time::Duration;

    fn unique_temp_dir(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "cyfs-js-extend-cert-provider-{}-{}",
            name,
            chrono::Utc::now().timestamp_nanos_opt().unwrap()
        ));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    fn generate_cert(domain: &str) -> (String, String) {
        let cert_key = generate_simple_self_signed(vec![domain.to_string()]).unwrap();
        (cert_key.cert.pem(), cert_key.signing_key.serialize_pem())
    }

    fn write_script(path: &Path, cert: &str, key: &str) {
        let cert_json = serde_json::to_string(cert).unwrap();
        let key_json = serde_json::to_string(key).unwrap();
        std::fs::write(
            path,
            format!(
                r#"
export function main(input) {{
  if ("op" in input || "provider" in input || "usage" in input || "derived_store_path" in input || "request" in input) {{
    throw new Error("unexpected internal field");
  }}
  if (input.domain !== "example.com") {{
    throw new Error("unexpected domain " + input.domain);
  }}
  if (!input.params || input.params.token !== "secret") {{
    throw new Error("unexpected params");
  }}
  return {{ cert: {cert_json}, key: {key_json} }};
}}
"#
            ),
        )
        .unwrap();
    }

    async fn wait_ready(provider: &JsExtendCertProvider, domain: &str) -> CertStatus {
        for _ in 0..50 {
            let status = provider.get_status(domain);
            if status.state == CertStatusState::Ready || status.state == CertStatusState::Error {
                return status;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        provider.get_status(domain)
    }

    async fn wait_for_state(
        provider: &JsExtendCertProvider,
        domain: &str,
        expected: CertStatusState,
    ) -> CertStatus {
        for _ in 0..100 {
            let status = provider.get_status(domain);
            if status.state == expected {
                return status;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        provider.get_status(domain)
    }

    #[tokio::test]
    async fn test_js_extend_cert_provider_script_contract_and_store() {
        let temp = unique_temp_dir("success");
        let script_path = temp.join("provider.js");
        let store_root = temp.join("store");
        let (cert, key) = generate_cert("example.com");
        write_script(&script_path, &cert, &key);

        let provider = JsExtendCertProvider::new(JsExtendCertProviderRuntimeConfig {
            id: "custom-js".to_string(),
            script_path: Some(script_path),
            script_name: None,
            script_pkg_dir: None,
            store_root: store_root.clone(),
            check_interval: chrono::Duration::seconds(3600),
            renew_before_expiry: chrono::Duration::days(30),
            params: json!({ "token": "secret" }),
        })
        .unwrap();

        provider
            .add_request(CertRequest {
                provider: Some("custom-js".to_string()),
                usage: CertUsage::Server,
                domain: "example.com".to_string(),
                challenge_type: ChallengeType::Http01,
                data: Some(json!({ "request": "not-forwarded" })),
            })
            .unwrap();

        let status = wait_ready(&provider, "example.com").await;
        assert_eq!(status.state, CertStatusState::Ready);
        assert!(
            provider
                .resolve_client_cert("example.com")
                .unwrap()
                .is_some()
        );

        let domain_store = store_root.join("example.com");
        assert!(domain_store.exists());
        assert!(std::fs::read_dir(&domain_store).unwrap().any(|entry| {
            entry
                .unwrap()
                .path()
                .extension()
                .is_some_and(|ext| ext == "cert")
        }));
    }

    #[tokio::test]
    async fn test_js_extend_cert_provider_rejects_alias_output() {
        let temp = unique_temp_dir("alias");
        let script_path = temp.join("provider.js");
        std::fs::write(
            &script_path,
            r#"
export function main(input) {
  return { fullchain: "x", private_key: "y" };
}
"#,
        )
        .unwrap();

        let provider = JsExtendCertProvider::new(JsExtendCertProviderRuntimeConfig {
            id: "custom-js".to_string(),
            script_path: Some(script_path),
            script_name: None,
            script_pkg_dir: None,
            store_root: temp.join("store"),
            check_interval: chrono::Duration::seconds(3600),
            renew_before_expiry: chrono::Duration::days(30),
            params: json!({}),
        })
        .unwrap();

        provider
            .add_request(CertRequest::server(
                "example.com".to_string(),
                Some("custom-js".to_string()),
                ChallengeType::Http01,
                None,
            ))
            .unwrap();

        let status = wait_ready(&provider, "example.com").await;
        assert_eq!(status.state, CertStatusState::Error);
        assert!(status.last_error.unwrap().contains("unknown field"));
    }

    #[tokio::test]
    async fn test_js_extend_cert_provider_retries_failed_refresh() {
        let temp = unique_temp_dir("retry");
        let script_path = temp.join("provider.js");
        let (cert, key) = generate_cert("example.com");
        std::fs::write(
            &script_path,
            r#"
export function main(input) {
  return { fullchain: "x", private_key: "y" };
}
"#,
        )
        .unwrap();

        let provider = JsExtendCertProvider::new_with_retry_config(
            JsExtendCertProviderRuntimeConfig {
                id: "custom-js".to_string(),
                script_path: Some(script_path.clone()),
                script_name: None,
                script_pkg_dir: None,
                store_root: temp.join("store"),
                check_interval: chrono::Duration::seconds(3600),
                renew_before_expiry: chrono::Duration::days(30),
                params: json!({ "token": "secret" }),
            },
            JsExtendCertRetryConfig {
                initial_interval: Duration::from_millis(5),
                max_interval: Duration::from_millis(5),
            },
        )
        .unwrap();

        provider
            .add_request(CertRequest::server(
                "example.com".to_string(),
                Some("custom-js".to_string()),
                ChallengeType::Http01,
                None,
            ))
            .unwrap();

        let status = wait_for_state(&provider, "example.com", CertStatusState::Error).await;
        assert_eq!(status.state, CertStatusState::Error);

        write_script(&script_path, &cert, &key);
        let status = wait_for_state(&provider, "example.com", CertStatusState::Ready).await;
        assert_eq!(status.state, CertStatusState::Ready);
        assert!(status.last_error.is_none());
    }

    #[tokio::test]
    async fn test_js_extend_cert_provider_drop_aborts_request_tasks() {
        let temp = unique_temp_dir("drop-abort");
        let script_path = temp.join("provider.js");
        std::fs::write(
            &script_path,
            r#"
export function main(input) {
  return { fullchain: "x", private_key: "y" };
}
"#,
        )
        .unwrap();

        let provider = JsExtendCertProvider::new_with_retry_config(
            JsExtendCertProviderRuntimeConfig {
                id: "custom-js".to_string(),
                script_path: Some(script_path),
                script_name: None,
                script_pkg_dir: None,
                store_root: temp.join("store"),
                check_interval: chrono::Duration::seconds(3600),
                renew_before_expiry: chrono::Duration::days(30),
                params: json!({}),
            },
            JsExtendCertRetryConfig {
                initial_interval: Duration::from_secs(60),
                max_interval: Duration::from_secs(60),
            },
        )
        .unwrap();

        provider
            .add_request(CertRequest::server(
                "example.com".to_string(),
                Some("custom-js".to_string()),
                ChallengeType::Http01,
                None,
            ))
            .unwrap();

        let status = wait_for_state(&provider, "example.com", CertStatusState::Error).await;
        assert_eq!(status.state, CertStatusState::Error);

        let request_weak = {
            let requests = provider.inner.requests.read().unwrap();
            Arc::downgrade(requests.get("example.com").unwrap())
        };

        drop(provider);

        for _ in 0..100 {
            if request_weak.upgrade().is_none() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            request_weak.upgrade().is_none(),
            "request task should be aborted when provider is dropped"
        );
    }

    #[test]
    fn test_js_extend_cert_provider_retry_interval_caps() {
        assert_eq!(
            next_retry_interval(Duration::from_secs(15), Duration::from_secs(600)),
            Duration::from_secs(30)
        );
        assert_eq!(
            next_retry_interval(Duration::from_secs(480), Duration::from_secs(600)),
            Duration::from_secs(600)
        );
    }

    #[tokio::test]
    async fn test_js_extend_cert_provider_does_not_inject_native_csr_helper() {
        let temp = unique_temp_dir("no-native-csr");
        let script_path = temp.join("provider.js");

        std::fs::write(
            &script_path,
            r#"
export function main(input) {
  return { has_native_csr: typeof __cyfs_create_csr === "function" };
}
"#,
        )
        .unwrap();

        let value = run_js_file(script_path, json!({})).await.unwrap();
        assert_eq!(value["has_native_csr"], json!(false));
    }

    #[tokio::test]
    async fn test_js_extend_cert_provider_supports_bigint_modpow() {
        let temp = unique_temp_dir("bigint-modpow");
        let script_path = temp.join("provider.js");

        std::fs::write(
            &script_path,
            r#"
function modPow(base, exponent, modulus) {
  let result = 1n;
  base = base % modulus;
  while (exponent > 0n) {
    if ((exponent & 1n) === 1n) {
      result = (result * base) % modulus;
    }
    exponent >>= 1n;
    base = (base * base) % modulus;
  }
  return result;
}

export function main(input) {
  const n = BigInt("0x" + input.n);
  const d = BigInt("0x" + input.d);
  const e = BigInt("0x" + input.e);
  const m = BigInt("0x" + input.m);
  const s = modPow(m, d, n);
  return { verified: modPow(s, e, n) === m };
}
"#,
        )
        .unwrap();

        let value = run_js_file(
            script_path,
            json!({ "n": "ca1", "d": "ac1", "e": "11", "m": "41" }),
        )
        .await
        .unwrap();
        assert_eq!(value["verified"], json!(true));
    }

    #[tokio::test]
    async fn test_js_extend_cert_provider_large_commonjs_parse_stack() {
        let temp = unique_temp_dir("large-commonjs");
        let script_path = temp.join("provider.js");
        let module_path = temp.join("large_dep.js");
        let depth = 1500;
        let expr = format!("{}1{}", "(".repeat(depth), ")".repeat(depth));

        std::fs::write(
            &module_path,
            format!(
                r#"
module.exports = {expr};
"#
            ),
        )
        .unwrap();
        std::fs::write(
            &script_path,
            r#"
const value = require("./large_dep");
export function main(input) {
  return { value: value + input.n };
}
"#,
        )
        .unwrap();

        let value = run_js_file(script_path, json!({ "n": 41 })).await.unwrap();
        assert_eq!(value["value"], json!(42));
    }
}
