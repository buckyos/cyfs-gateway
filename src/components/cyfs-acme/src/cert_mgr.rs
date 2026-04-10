use crate::acme_client::{AcmeAccount, AcmeChallengeResponderRef, AcmeClient, AcmeOrderSession};
use crate::default_challenge_responder::DefaultChallengeResponder;
use crate::{Challenge, ChallengeData, ChallengeType};
use anyhow::Result;
use log::*;
use openssl::x509::X509;
use rand::Rng;
use rustls::crypto::ring::sign::any_supported_type;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign;
use rustls::sign::CertifiedKey;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sfo_js::{JsPkgManager, JsPkgManagerRef, JsString, JsValue};
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::RwLock;
use std::sync::{Arc, Weak};
use std::time::Duration;
use tokio::fs;
use tokio::task;
use tokio::task::JoinHandle;

pub const ACME_TLS_ALPN_NAME: &[u8] = b"acme-tls/1";

pub fn is_tls_alpn_challenge(client_hello: &ClientHello) -> bool {
    client_hello
        .alpn()
        .into_iter()
        .flatten()
        .eq([ACME_TLS_ALPN_NAME])
}

struct CertInfo {
    key: Arc<CertifiedKey>,
    certs: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
    expires: chrono::DateTime<chrono::Utc>,
}

impl Clone for CertInfo {
    fn clone(&self) -> Self {
        Self {
            key: self.key.clone(),
            certs: self.certs.clone(),
            private_key: CertStub::clone_private_key(&self.private_key),
            expires: self.expires,
        }
    }
}

enum CertState {
    None,
    Ready(CertInfo),
    Renewing(CertInfo),
    Expired(CertInfo),
}

struct CertMutPart {
    state: CertState,
    order: Option<AcmeOrderSession>,
    last_error: Option<String>,
}

struct CertStubInner {
    acme_item: AcmeItem,
    keystore_path: String,
    issuer: Arc<IssuerRuntime>,
    responder: AcmeChallengeResponderRef,
    mut_part: Mutex<CertMutPart>,
    handle: Mutex<Option<JoinHandle<()>>>,
}

impl Drop for CertStubInner {
    fn drop(&mut self) {
        debug!("drop CertStubInner, stub: {:#?}", self.acme_item);
        if let Some(handle) = self.handle.lock().unwrap().take() {
            if !handle.is_finished() {
                handle.abort();
            }
        }
    }
}
pub struct CertStub {
    inner: Arc<CertStubInner>,
}

impl Clone for CertStub {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl std::fmt::Display for CertStub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CertStub domains: {:?}", self.inner.acme_item)
    }
}

impl CertStub {
    fn new(
        acme_item: AcmeItem,
        keystore_path: String,
        issuer: Arc<IssuerRuntime>,
        responder: AcmeChallengeResponderRef,
    ) -> Self {
        Self {
            inner: Arc::new(CertStubInner {
                acme_item,
                keystore_path,
                issuer,
                responder,
                mut_part: Mutex::new(CertMutPart {
                    state: CertState::None,
                    order: None,
                    last_error: None,
                }),
                handle: Mutex::new(None),
            }),
        }
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

    fn clone_private_key(key: &PrivateKeyDer<'static>) -> PrivateKeyDer<'static> {
        match key {
            PrivateKeyDer::Pkcs8(key) => PrivateKeyDer::Pkcs8(key.clone_key()),
            PrivateKeyDer::Pkcs1(key) => PrivateKeyDer::Pkcs1(key.clone_key()),
            PrivateKeyDer::Sec1(key) => PrivateKeyDer::Sec1(key.clone_key()),
            _ => panic!("Unsupported key type"),
        }
    }

    fn create_certified_key(
        cert_chain: Vec<CertificateDer<'static>>,
        key: &PrivateKeyDer<'static>,
    ) -> Result<CertifiedKey> {
        let signing_key =
            any_supported_type(key).map_err(|e| anyhow::anyhow!("Invalid private key: {}", e))?;

        Ok(CertifiedKey::new(cert_chain, signing_key))
    }

    fn get_cert_expiry(cert_data: &[u8]) -> Result<chrono::DateTime<chrono::Utc>> {
        let cert = X509::from_pem(cert_data)?;
        let not_after = cert.not_after().to_string();
        // info!("cert expiry raw: {}", not_after);

        // 移除最后的时区名称，因为证书时间总是 UTC
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

    pub fn get_cert(&self) -> Option<Arc<CertifiedKey>> {
        let mut_part = self.inner.mut_part.lock().unwrap();
        match &mut_part.state {
            CertState::Ready(info) => Some(info.key.clone()),
            CertState::Renewing(info) => Some(info.key.clone()),
            CertState::Expired(_) => None,
            CertState::None => None,
        }
    }

    pub fn get_state(&self) -> CertStubState {
        let mut_part = self.inner.mut_part.lock().unwrap();
        match &mut_part.state {
            CertState::None => CertStubState::Pending,
            CertState::Ready(_) => CertStubState::Ready,
            CertState::Renewing(_) => CertStubState::Renewing,
            CertState::Expired(_) => CertStubState::Expired,
        }
    }

    pub fn get_material(&self) -> Option<CertMaterial> {
        let mut_part = self.inner.mut_part.lock().unwrap();
        match &mut_part.state {
            CertState::Ready(info) | CertState::Renewing(info) => Some(info.to_material()),
            CertState::Expired(_) | CertState::None => None,
        }
    }

    pub fn get_last_error(&self) -> Option<String> {
        self.inner.mut_part.lock().unwrap().last_error.clone()
    }

    fn set_last_error(&self, err: Option<String>) {
        self.inner.mut_part.lock().unwrap().last_error = err;
    }

    pub fn load_cert(&self) {
        let mut handle = self.inner.handle.lock().unwrap();
        if handle.is_some() && !handle.as_ref().unwrap().is_finished() {
            return;
        }

        let stub = self.clone();
        handle.replace(task::spawn(async move {
            if let Err(e) = stub.load_cert_inner().await {
                stub.set_last_error(Some(e.to_string()));
                error!("load cert failed, stub: {}, {}", stub, e);
            }
        }));
    }

    async fn load_cert_inner(&self) -> Result<()> {
        // 尝试�?keystore_path 加载最新的证书
        let dir = tokio::fs::read_dir(&self.inner.keystore_path)
            .await
            .map_err(|e| {
                anyhow::anyhow!(
                    "read keystore dir failed, stub: {}, path: {}, {}",
                    self,
                    self.inner.keystore_path,
                    e
                )
            })?;

        let mut entries = Vec::new();
        tokio::pin!(dir);
        while let Some(entry) = dir.next_entry().await? {
            if entry.file_name().to_string_lossy().ends_with(".cert") {
                entries.push(entry.path());
            }
        }

        if entries.is_empty() {
            // 如果没有找到证书，启动证书申请流程
            info!(
                "no cert found in keystore, start ordering new cert, stub: {}",
                self
            );
            self.start_order().await?;
            return Ok(());
        }

        // 按文件名（时间戳）排序，取最新的
        entries.sort_by(|a, b| b.file_name().unwrap().cmp(a.file_name().unwrap()));
        let cert_path = entries[0].to_string_lossy().to_string();

        info!("load cert, stub: {}, cert_path: {}", self, cert_path);
        let key_path = cert_path.replace(".cert", ".key");

        let cert_data = fs::read(&cert_path).await.map_err(|e| {
            error!(
                "load cert failed, stub: {}, cert_path: {}, {}",
                self, cert_path, e
            );
            anyhow::anyhow!(
                "load cert failed, stub: {}, cert_path: {}, {}",
                self,
                cert_path,
                e
            )
        })?;
        let key_data = fs::read(&key_path).await.map_err(|e| {
            error!(
                "load cert failed, stub: {}, key_path: {}, {}",
                self, key_path, e
            );
            anyhow::anyhow!(
                "load cert failed, stub: {}, key_path: {}, {}",
                self,
                key_path,
                e
            )
        })?;

        let cert_chain = Self::parse_cert_chain(&cert_data).map_err(|e| {
            error!(
                "parse cert chain failed, stub: {}, cert_path: {}, key_path: {}, {}",
                self, cert_path, key_path, e
            );
            anyhow::anyhow!(
                "parse cert chain failed, stub: {}, cert_path: {}, key_path: {}, {}",
                self,
                cert_path,
                key_path,
                e
            )
        })?;
        let private_key = Self::parse_private_key(&key_data).map_err(|e| {
            error!(
                "parse private key failed, stub: {}, cert_path: {}, key_path: {}, {}",
                self, cert_path, key_path, e
            );
            anyhow::anyhow!(
                "parse private key failed, stub: {}, cert_path: {}, key_path: {}, {}",
                self,
                cert_path,
                key_path,
                e
            )
        })?;
        let certified_key =
            Self::create_certified_key(cert_chain.clone(), &private_key).map_err(|e| {
                error!(
                    "create certified key failed, stub: {}, cert_path: {}, key_path: {}, {}",
                    self, cert_path, key_path, e
                );
                anyhow::anyhow!(
                    "create certified key failed, stub: {}, cert_path: {}, key_path: {}, {}",
                    self,
                    cert_path,
                    key_path,
                    e
                )
            })?;
        let expires = Self::get_cert_expiry(&cert_data).map_err(|e| {
            error!(
                "get cert expiry failed, stub: {}, cert_path: {}, key_path: {}, {}",
                self, cert_path, key_path, e
            );
            anyhow::anyhow!(
                "get cert expiry failed, stub: {}, cert_path: {}, key_path: {}, {}",
                self,
                cert_path,
                key_path,
                e
            )
        })?;

        info!(
            "load cert success, stub: {}, cert_path: {}, key_path: {}, expires: {}",
            self, cert_path, key_path, expires
        );

        let mut mut_part = self.inner.mut_part.lock().unwrap();
        mut_part.state = CertState::Ready(CertInfo {
            key: Arc::new(certified_key),
            certs: cert_chain,
            private_key,
            expires,
        });
        mut_part.last_error = None;

        Ok(())
    }

    fn check_cert(&self) -> Result<()> {
        let renew_before_expiry = self.inner.issuer.renew_before_expiry;
        let should_order = {
            {
                let handle = self.inner.handle.lock().unwrap();
                if handle.is_some() && !handle.as_ref().unwrap().is_finished() {
                    return Ok(());
                }
            }

            let mut mut_part = self.inner.mut_part.lock().unwrap();
            match &mut_part.state {
                CertState::None => true,
                CertState::Ready(info) => {
                    let now = chrono::Utc::now();
                    if now >= info.expires {
                        mut_part.state = CertState::Expired(info.clone());
                        true
                    } else {
                        let renew_time = info.expires - renew_before_expiry;
                        if now >= renew_time {
                            mut_part.state = CertState::Renewing(info.clone());
                            true
                        } else {
                            false
                        }
                    }
                }
                CertState::Renewing(_) => true,
                CertState::Expired(_) => true,
            }
        };

        if should_order {
            self.renew_cert();
        }

        Ok(())
    }

    async fn order_inner(&self) -> Result<()> {
        let mut order = AcmeOrderSession::new(
            self.inner.acme_item.domain.clone(),
            self.inner.issuer.acme_client.clone(),
            self.inner.responder.clone(),
        );
        let (cert_data, key_data) = order.start().await?;

        let timestamp = chrono::Utc::now().timestamp();
        let cert_path = format!("{}/{}.cert", self.inner.keystore_path, timestamp);
        let key_path = format!("{}/{}.key", self.inner.keystore_path, timestamp);

        fs::write(&cert_path, &cert_data).await?;
        fs::write(&key_path, &key_data).await?;

        let cert_chain = Self::parse_cert_chain(&cert_data)?;
        let private_key = Self::parse_private_key(&key_data)?;
        let certified_key = Self::create_certified_key(cert_chain.clone(), &private_key)?;
        let expires = Self::get_cert_expiry(&cert_data)?;

        info!(
            "save cert success, stub: {}, cert_path: {}, key_path: {}, expires: {}",
            self, cert_path, key_path, expires
        );

        {
            let mut mut_part = self.inner.mut_part.lock().unwrap();
            mut_part.state = CertState::Ready(CertInfo {
                key: Arc::new(certified_key),
                certs: cert_chain,
                private_key,
                expires,
            });
            mut_part.last_error = None;
        }

        Ok(())
    }

    async fn start_order(&self) -> Result<()> {
        let mut interval = 15;
        loop {
            let result = self.order_inner().await;

            match result {
                Ok(()) => {
                    self.set_last_error(None);
                    break Ok(());
                }
                Err(e) => {
                    self.set_last_error(Some(e.to_string()));
                    error!("order cert failed, stub: {}, {}", self, e);
                    interval *= 2;
                    if interval > 600 {
                        interval = 600;
                    }
                    tokio::time::sleep(Duration::from_secs(interval)).await;
                }
            }
        }
    }

    fn renew_cert(&self) {
        let mut handle = self.inner.handle.lock().unwrap();
        if handle.is_some() && !handle.as_ref().unwrap().is_finished() {
            return;
        }

        let stub = self.clone();
        handle.replace(tokio::spawn(async move {
            if let Err(e) = stub.start_order().await {
                error!("renew cert failed, stub: {}, {}", stub, e);
            }
        }));
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CertStubState {
    Pending,
    Ready,
    Renewing,
    Expired,
}

#[derive(Debug)]
pub struct CertMaterial {
    pub certs: Vec<CertificateDer<'static>>,
    pub private_key: PrivateKeyDer<'static>,
    pub expires: chrono::DateTime<chrono::Utc>,
}

impl Clone for CertMaterial {
    fn clone(&self) -> Self {
        Self {
            certs: self.certs.clone(),
            private_key: CertStub::clone_private_key(&self.private_key),
            expires: self.expires,
        }
    }
}

impl CertInfo {
    fn to_material(&self) -> CertMaterial {
        CertMaterial {
            certs: self.certs.clone(),
            private_key: CertStub::clone_private_key(&self.private_key),
            expires: self.expires,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcmeItem {
    domain: String,
    challenge_type: ChallengeType,
    issuer: Option<String>,
    data: Option<serde_json::Value>,
}

impl AcmeItem {
    pub fn new(
        domain: String,
        challenge_type: ChallengeType,
        issuer: Option<String>,
        data: Option<serde_json::Value>,
    ) -> Self {
        Self {
            domain,
            challenge_type,
            issuer,
            data,
        }
    }
}

#[callback_trait::callback_trait]
pub trait DnsProvider: Send + Sync + 'static {
    async fn call(&self, op: String, domain: String, key_hash: String) -> Result<()>;
}
pub type DnsProviderRef = Arc<dyn DnsProvider>;

pub struct ExternalDnsProvider {
    name: String,
    provider_params: Value,
    js_pkg_manager: JsPkgManagerRef,
}

impl ExternalDnsProvider {
    pub fn new(
        js_pkg_manager: JsPkgManagerRef,
        name: impl Into<String>,
        provider_params: Value,
    ) -> Arc<Self> {
        Arc::new(Self {
            name: name.into(),
            provider_params,
            js_pkg_manager,
        })
    }
}

#[async_trait::async_trait]
impl DnsProvider for ExternalDnsProvider {
    async fn call(&self, op: String, domain: String, key_hash: String) -> Result<()> {
        let pkg = self
            .js_pkg_manager
            .get_pkg(self.name.clone())
            .await
            .map_err(|e| anyhow::anyhow!(e))?;
        pkg.run_with_json(vec![
            Value::String(op),
            self.provider_params.clone(),
            Value::String(domain),
            Value::String(key_hash),
        ])
        .await
        .map_err(|e| anyhow::anyhow!(e))?;
        Ok(())
    }
}

#[async_trait::async_trait]
pub trait DnsProviderFactory: Send + Sync + 'static {
    async fn create(
        &self,
        acme_mgr: Weak<AcmeCertManager>,
        params: serde_json::Value,
    ) -> Result<DnsProviderRef>;
}
pub type DnsProviderFactoryRef = Arc<dyn DnsProviderFactory>;

lazy_static::lazy_static! {
    static ref DNS_PROVIDER_FACTORYS: RwLock<HashMap<String, DnsProviderFactoryRef>> = RwLock::new(HashMap::new());
}

#[derive(Serialize, Deserialize)]
struct DnsProviderInfo {
    pub dns_provider: String,
}

#[derive(Clone)]
struct IssuerRuntime {
    name: Option<String>,
    acme_client: AcmeClient,
    check_interval: chrono::Duration,
    renew_before_expiry: chrono::Duration,
}

pub struct AcmeCertManager {
    config: CertManagerConfig,
    default_issuer: Arc<IssuerRuntime>,
    issuers: HashMap<String, Arc<IssuerRuntime>>,
    certs: RwLock<HashMap<String, CertStub>>,
    check_handlers: Mutex<Vec<JoinHandle<()>>>,
    responder: Mutex<Option<AcmeChallengeResponderRef>>,
    challenge_certs: Mutex<HashMap<String, Arc<sign::CertifiedKey>>>,
    http_challenges: Mutex<HashMap<String, String>>,
    dns_providers: RwLock<HashMap<String, DnsProviderRef>>,
}

pub type AcmeCertManagerRef = Arc<AcmeCertManager>;

#[derive(Clone, Debug, Deserialize)]
pub struct CertManagerIssuerConfig {
    pub account: Option<String>,
    pub acme_server: String,
    #[serde(default = "default_check_interval")]
    pub check_interval: chrono::Duration,
    #[serde(default = "default_renew_before_expiry")]
    pub renew_before_expiry: chrono::Duration,
}

#[derive(Clone, Debug, Deserialize)]
pub struct CertManagerConfig {
    pub account: Option<String>,
    pub acme_server: String,
    pub dns_providers: Option<HashMap<String, serde_json::Value>>,
    pub keystore_path: String,
    pub dns_provider_path: Option<String>,
    #[serde(default = "default_check_interval")]
    pub check_interval: chrono::Duration,
    #[serde(default = "default_renew_before_expiry")]
    pub renew_before_expiry: chrono::Duration,
    #[serde(default)]
    pub issuers: HashMap<String, CertManagerIssuerConfig>,
}

fn default_check_interval() -> chrono::Duration {
    chrono::Duration::hours(12)
}

fn default_renew_before_expiry() -> chrono::Duration {
    chrono::Duration::days(30)
}

impl Default for CertManagerConfig {
    fn default() -> Self {
        Self {
            account: None,
            acme_server: "https://acme-v02.api.letsencrypt.org/directory".to_string(),
            dns_providers: None,
            keystore_path: String::new(),
            dns_provider_path: None,
            check_interval: default_check_interval(),
            renew_before_expiry: default_renew_before_expiry(),
            issuers: HashMap::new(),
        }
    }
}

impl std::fmt::Display for AcmeCertManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CertManager")
    }
}

impl Drop for AcmeCertManager {
    fn drop(&mut self) {
        debug!("drop cert manager, {}", self);
        let mut check_handlers = self.check_handlers.lock().unwrap();
        for handler in check_handlers.drain(..) {
            handler.abort();
        }
    }
}

impl AcmeCertManager {
    pub fn register_dns_provider_factory(name: impl Into<String>, factory: DnsProviderFactoryRef) {
        DNS_PROVIDER_FACTORYS
            .write()
            .unwrap()
            .insert(name.into(), factory);
    }

    fn default_issuer_config(config: &CertManagerConfig) -> CertManagerIssuerConfig {
        CertManagerIssuerConfig {
            account: config.account.clone(),
            acme_server: config.acme_server.clone(),
            check_interval: config.check_interval,
            renew_before_expiry: config.renew_before_expiry,
        }
    }

    fn issuer_account_path(config: &CertManagerConfig, issuer_name: Option<&str>) -> PathBuf {
        match issuer_name {
            Some(issuer_name) => buckyos_kit::path_join(
                &config.keystore_path,
                &format!("accounts/{}/acme_account.json", sanitize_path_component(issuer_name)),
            ),
            None => buckyos_kit::path_join(&config.keystore_path, "acme_account.json"),
        }
    }

    async fn load_or_create_account(
        account_path: &Path,
        account_name: Option<String>,
    ) -> Result<AcmeAccount> {
        if let Some(parent) = account_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        match AcmeAccount::from_file(account_path).await {
            Ok(account) => {
                info!("Loading ACME account from {}", account_path.to_string_lossy());
                match account_name {
                    Some(account_name) if account_name.as_str() != account.email() => {
                        let account = AcmeAccount::new(account_name);
                        if let Err(e) = account.save_to_file(account_path).await {
                            error!("Failed to save ACME account: {}", e);
                        }
                        Ok(account)
                    }
                    _ => Ok(account),
                }
            }
            Err(_) => {
                let account = match account_name {
                    Some(account_name) => AcmeAccount::new(account_name),
                    None => {
                        let random_str = rand::rng().random_range(0..1000000);
                        let random_domain = rand::rng().random_range(0..1000000);
                        let email = format!("{}@{}.com", random_str, random_domain);
                        info!("Generated random email address: {}", email);
                        AcmeAccount::new(email)
                    }
                };
                if let Err(e) = account.save_to_file(account_path).await {
                    error!("Failed to save ACME account: {}", e);
                }
                Ok(account)
            }
        }
    }

    async fn create_issuer_runtime(
        config: &CertManagerConfig,
        issuer_name: Option<&str>,
        issuer_config: &CertManagerIssuerConfig,
    ) -> Result<Arc<IssuerRuntime>> {
        let account_path = Self::issuer_account_path(config, issuer_name);
        let account =
            Self::load_or_create_account(account_path.as_path(), issuer_config.account.clone())
                .await?;
        let acme_client = AcmeClient::new(account, issuer_config.acme_server.clone()).await?;
        Ok(Arc::new(IssuerRuntime {
            name: issuer_name.map(|value| value.to_string()),
            acme_client,
            check_interval: issuer_config.check_interval,
            renew_before_expiry: issuer_config.renew_before_expiry,
        }))
    }

    fn resolve_issuer_runtime(&self, issuer_name: Option<&str>) -> Result<Arc<IssuerRuntime>> {
        match issuer_name {
            None => Ok(self.default_issuer.clone()),
            Some(name) => self
                .issuers
                .get(name)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("unknown acme issuer: {}", name)),
        }
    }

    fn issuer_matches(item_issuer: Option<&str>, issuer_name: Option<&str>) -> bool {
        item_issuer == issuer_name
    }

    pub async fn create(config: CertManagerConfig) -> Result<AcmeCertManagerRef> {
        info!("create cert manager, config: {:?}", config);

        if !Path::new(config.keystore_path.as_str()).exists() {
            tokio::fs::create_dir_all(config.keystore_path.as_str())
                .await
                .map_err(|e| {
                    error!("Failed to create keystore path: {}", e);
                    e
                })?;
        }
        let default_issuer_config = Self::default_issuer_config(&config);
        let default_issuer =
            Self::create_issuer_runtime(&config, None, &default_issuer_config).await?;
        let mut issuers = HashMap::new();
        for (issuer_name, issuer_config) in &config.issuers {
            let runtime =
                Self::create_issuer_runtime(&config, Some(issuer_name.as_str()), issuer_config)
                    .await?;
            issuers.insert(issuer_name.clone(), runtime);
        }

        let mut dns_providers = HashMap::<String, DnsProviderRef>::new();
        let manager = AcmeCertManagerRef::new(Self {
            config: config.clone(),
            default_issuer,
            issuers,
            certs: RwLock::new(HashMap::new()),
            check_handlers: Mutex::new(Vec::new()),
            responder: Mutex::new(None),
            challenge_certs: Mutex::new(Default::default()),
            http_challenges: Mutex::new(Default::default()),
            dns_providers: RwLock::new(dns_providers.clone()),
        });

        if let Some(dns_providers_config) = &config.dns_providers {
            let provider_manager = if config.dns_provider_path.is_some() {
                let dns_provider_path =
                    Path::new(config.dns_provider_path.as_ref().unwrap()).to_path_buf();
                let js_pkg_manager = JsPkgManager::new(dns_provider_path);
                Some(js_pkg_manager)
            } else {
                None
            };
            for (name, provider_config) in dns_providers_config.iter() {
                let factory = { DNS_PROVIDER_FACTORYS.read().unwrap().get(name).cloned() };
                if let Some(factory) = factory {
                    let provider = factory
                        .create(Arc::downgrade(&manager), provider_config.clone())
                        .await?;
                    dns_providers.insert(name.clone(), provider);
                } else {
                    if provider_manager.is_some() {
                        let provider = ExternalDnsProvider::new(
                            provider_manager.as_ref().unwrap().clone(),
                            name.as_str(),
                            provider_config.clone(),
                        );
                        dns_providers.insert(name.clone(), provider);
                    }
                }
            }
        }
        {
            manager.dns_providers.write().unwrap().extend(dns_providers);
        }

        {
            let mut responder = manager.responder.lock().unwrap();
            *responder = Some(Arc::new(DefaultChallengeResponder::new(manager.clone())));
        }
        // 启动定期检查任务
        {
            let runtimes = std::iter::once(manager.default_issuer.clone())
                .chain(manager.issuers.values().cloned())
                .collect::<Vec<_>>();
            let mut check_handlers = manager.check_handlers.lock().unwrap();
            for runtime in runtimes {
                let weak_manager = Arc::downgrade(&manager);
                let issuer_name = runtime.name.clone();
                let check_interval = tokio::time::Duration::from_secs(
                    runtime.check_interval.num_seconds().max(1) as u64,
                );
                let handle: JoinHandle<()> = tokio::spawn(async move {
                    let mut interval = tokio::time::interval(check_interval);
                    loop {
                        interval.tick().await;
                        if let Some(manager) = weak_manager.upgrade() {
                            if let Err(e) = manager.check_all_certs(issuer_name.as_deref()) {
                                error!("check certs failed: {}", e);
                            }
                        } else {
                            break;
                        }
                    }
                });
                check_handlers.push(handle);
            }
        }

        Ok(manager)
    }

    pub fn register_dns_provider(&self, name: impl Into<String>, provider: impl DnsProvider) {
        self.dns_providers
            .write()
            .unwrap()
            .insert(name.into(), Arc::new(provider));
    }

    pub fn add_acme_item(&self, item: AcmeItem) -> Result<()> {
        let keystore_path = buckyos_kit::path_join(
            &self.config.keystore_path,
            &sanitize_path_component(&item.domain),
        );
        if !keystore_path.exists() {
            if let Err(e) = std::fs::create_dir_all(&keystore_path) {
                error!(
                    "Failed to create certificate storage directory: {} {}",
                    e,
                    keystore_path.to_str().unwrap()
                );
                return Err(anyhow::anyhow!(
                    "Failed to create certificate storage directory: {}",
                    e
                ));
            }
        }

        let responder = { self.responder.lock().unwrap().clone().unwrap() };
        let issuer = self.resolve_issuer_runtime(item.issuer.as_deref())?;
        let mut certs = self.certs.write().unwrap();
        if let Some(existing) = certs.get(&item.domain) {
            if existing.inner.acme_item == item {
                return Ok(());
            }
            return Err(anyhow::anyhow!(
                "acme domain {} conflicts with existing certificate config",
                item.domain
            ));
        }
        let domain = item.domain.clone();
        let cert_stub = CertStub::new(
            item,
            keystore_path.to_str().unwrap().to_string(),
            issuer,
            responder,
        );
        certs.insert(domain, cert_stub.clone());
        cert_stub.load_cert();
        Ok(())
    }

    pub fn get_cert_by_host(&self, host: &str) -> Option<CertStub> {
        let certs = self.certs.read().unwrap();
        let cert = certs.get(host);
        if cert.is_some() {
            info!("find tls config for host: {}", host);
            return Some(cert.unwrap().clone());
        }

        for (key, value) in certs.iter() {
            if key.starts_with("*.") {
                if host.ends_with(&key[2..]) {
                    info!("find tls config for host: {} ==> key:{}", host, key);
                    return Some(value.clone());
                }
            }
        }

        None
    }

    fn check_all_certs(&self, issuer_name: Option<&str>) -> Result<()> {
        let certs = self
            .certs
            .read()
            .unwrap()
            .values()
            .filter(|cert| {
                Self::issuer_matches(cert.inner.acme_item.issuer.as_deref(), issuer_name)
            })
            .cloned()
            .collect::<Vec<_>>();

        for cert in certs {
            if let Err(e) = cert.check_cert() {
                error!("check cert failed, stub: {}, error: {}", cert, e);
            }
        }
        Ok(())
    }

    pub(crate) async fn respond_challenge<'a>(
        &self,
        challenges: &'a [Challenge],
    ) -> anyhow::Result<&'a Challenge> {
        for challenge in challenges {
            let cert_stub = {
                let certs = self.certs.read().unwrap();
                certs.get(challenge.domain.as_str()).cloned()
            };
            if cert_stub.is_none() {
                continue;
            }
            let cert_stub = cert_stub.unwrap();

            match challenge.data {
                ChallengeData::TlsAlpn01 { ref cert } => {
                    if cert_stub.inner.acme_item.challenge_type == ChallengeType::TlsAlpn01 {
                        let mut challenge_certs = self.challenge_certs.lock().unwrap();
                        challenge_certs.insert(challenge.domain.clone(), cert.clone());
                        return Ok(challenge);
                    } else {
                        continue;
                    }
                }
                ChallengeData::Dns01 {
                    token: _,
                    ref key_hash,
                } => {
                    if cert_stub.inner.acme_item.challenge_type == ChallengeType::Dns01 {
                        self.call_dns_provider(&cert_stub, key_hash.as_str(), "add_challenge")
                            .await?;
                        return Ok(challenge);
                    } else {
                        continue;
                    }
                }
                ChallengeData::Http01 {
                    ref token,
                    ref key_auth,
                } => {
                    if cert_stub.inner.acme_item.challenge_type == ChallengeType::Http01 {
                        let mut http_challenges = self.http_challenges.lock().unwrap();
                        http_challenges.insert(token.clone(), key_auth.clone());
                        return Ok(challenge);
                    } else {
                        continue;
                    }
                }
            }
        }
        Err(anyhow::anyhow!("no challenge responder"))
    }

    pub fn get_auth_of_token(&self, token: &str) -> Option<String> {
        let http_challenges = self.http_challenges.lock().unwrap();
        http_challenges.get(token).cloned()
    }

    pub(crate) fn revert_challenge(self: &Arc<Self>, challenge: &Challenge) {
        match challenge.data {
            ChallengeData::TlsAlpn01 { cert: _ } => {
                let mut challenge_certs = self.challenge_certs.lock().unwrap();
                challenge_certs.remove(&challenge.domain);
            }
            ChallengeData::Dns01 {
                token: _,
                ref key_hash,
            } => {
                let cert_stub = {
                    let certs = self.certs.read().unwrap();
                    certs.get(challenge.domain.as_str()).cloned()
                };
                if cert_stub.is_none() {
                    return;
                }
                let cert_stub = cert_stub.unwrap();
                let key_hash = key_hash.to_string();
                let this = self.clone();
                tokio::spawn(async move {
                    if let Err(e) = this
                        .call_dns_provider(&cert_stub, key_hash.as_str(), "del_challenge")
                        .await
                    {
                        error!("revert challenge failed: {}", e);
                    }
                });
            }
            ChallengeData::Http01 {
                token: _,
                key_auth: _,
            } => {
                let mut http_challenges = self.http_challenges.lock().unwrap();
                http_challenges.remove(&challenge.domain);
            }
        }
    }

    fn get_provider(&self, provider_name: &str) -> Option<DnsProviderRef> {
        let providers = self.dns_providers.read().unwrap();
        providers.get(provider_name).cloned()
    }

    async fn call_dns_provider(
        &self,
        cert_stub: &CertStub,
        key_hash: &str,
        op: &str,
    ) -> Result<()> {
        if cert_stub.inner.acme_item.data.is_none() {
            return Err(anyhow::anyhow!("dns challenge provider params is empty"));
        }

        let provider_data = cert_stub.inner.acme_item.data.clone().unwrap();
        let provider_info: DnsProviderInfo = serde_json::from_value(provider_data.clone())
            .map_err(|e| {
                anyhow::anyhow!(
                    "parse plugin data {} failed: {}",
                    serde_json::to_string(&provider_data).unwrap_or("".to_string()),
                    e
                )
            })?;

        let provider = self.get_provider(provider_info.dns_provider.as_str());
        if provider.is_none() {
            return Err(anyhow::anyhow!(
                "dns challenge provider {} not exists",
                provider_info.dns_provider
            ));
        }
        let provider = provider.unwrap().clone();

        let domain = if cert_stub.inner.acme_item.domain.starts_with("*.") {
            format!("_acme-challenge{}", &cert_stub.inner.acme_item.domain[1..])
        } else {
            format!("_acme-challenge.{}", cert_stub.inner.acme_item.domain)
        };

        provider
            .call(op.to_string(), domain, key_hash.to_string())
            .await
    }
}

impl std::fmt::Debug for AcmeCertManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CertManager")
    }
}

impl ResolvesServerCert for AcmeCertManager {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        if is_tls_alpn_challenge(&client_hello) {
            let challenge_certs = self.challenge_certs.lock().unwrap();
            return if let Some(server_name) = client_hello.server_name() {
                challenge_certs.get(server_name).cloned()
            } else {
                None
            };
        }

        let server_name = client_hello.server_name().unwrap_or("").to_string();
        let cert_stub = self.get_cert_by_host(&server_name);
        if cert_stub.is_some() {
            return cert_stub.unwrap().get_cert();
        }
        None
    }
}

fn sanitize_path_component(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '*' => "_star_".to_string(),
            '?' => "_qmark_".to_string(),
            ':' => "_colon_".to_string(),
            '/' => "_slash_".to_string(),
            '\\' => "_bslash_".to_string(),
            '|' => "_pipe_".to_string(),
            '<' => "_lt_".to_string(),
            '>' => "_gt_".to_string(),
            '"' => "_quote_".to_string(),
            c => c.to_string(),
        })
        .collect()
}

