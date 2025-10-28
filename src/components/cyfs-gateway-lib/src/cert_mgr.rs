use rand::Rng;
use tokio::fs;
use anyhow::Result;
use std::collections::HashMap;
use std::path::Path;
use rustls::server::{ResolvesServerCert, ClientHello};
use rustls::sign::CertifiedKey;
use std::sync::Arc;
use std::sync::RwLock;
use tokio::task;
use log::*;
use crate::acme_client::{AcmeClient, AcmeOrderSession, AcmeAccount};
use openssl::x509::X509;
use std::sync::Mutex;
use std::time::Duration;
use rustls::crypto::ring::sign::any_supported_type;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde::Deserialize;
use tokio::task::JoinHandle;
use crate::{AcmeChallengeResponderRef};

pub const ACME_TLS_ALPN_NAME: &[u8] = b"acme-tls/1";

pub fn is_tls_alpn_challenge(client_hello: &ClientHello) -> bool {
    client_hello.alpn().into_iter().flatten().eq([ACME_TLS_ALPN_NAME])
}

#[derive(Clone)]
struct CertInfo {
    key: Arc<CertifiedKey>,
    expires: chrono::DateTime<chrono::Utc>,
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
}

struct CertStubInner {
    domains: Vec<String>,
    keystore_path: String,
    acme_client: AcmeClient,
    responder: AcmeChallengeResponderRef,
    mut_part: Mutex<CertMutPart>,
    handle: Mutex<Option<JoinHandle<()>>>,
}

impl Drop for CertStubInner {
    fn drop(&mut self) {
        debug!("drop CertStubInner, stub: {:#?}", self.domains);
        if let Some(handle) = self.handle.lock().unwrap().take() {
            if !handle.is_finished() {
                handle.abort();
            }
        }
    }
}
pub struct CertStub {
    inner: Arc<CertStubInner>
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
        write!(f, "CertStub domains: {}", self.inner.domains.join(","))
    }
}


impl CertStub {
    fn new(
        domains: Vec<String>,
        keystore_path: String,
        acme_client: AcmeClient,
        responder: AcmeChallengeResponderRef,
    ) -> Self {
        Self {
            inner: Arc::new(CertStubInner {
                domains,
                keystore_path,
                acme_client,
                responder,
                mut_part: Mutex::new(CertMutPart {
                    state: CertState::None,
                    order: None,
                }),
                handle: Mutex::new(None),
            })
        }
    }

    fn create_certified_key(cert_data: &[u8], key_data: &[u8]) -> Result<CertifiedKey> {
        let cert_chain = vec![rustls_pemfile::certs(&mut &*cert_data)?.remove(0)];
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(rustls_pemfile::pkcs8_private_keys(&mut &*key_data)?.remove(0)));

        let signing_key = any_supported_type(&key)
            .map_err(|e| anyhow::anyhow!("Invalid private key: {}", e))?;

        let cert_chain = cert_chain.into_iter().map(|v| CertificateDer::from(v)).collect();
        Ok(CertifiedKey::new(cert_chain, signing_key))
    }

    fn get_cert_expiry(cert_data: &[u8]) -> Result<chrono::DateTime<chrono::Utc>> {
        let cert = X509::from_pem(cert_data)?;
        let not_after = cert.not_after().to_string();
        // info!("cert expiry raw: {}", not_after);

        // 移除最后的时区名称，因为证书时间总是 UTC
        let datetime_str = not_after.rsplitn(2, ' ')
            .nth(1)
            .ok_or_else(|| anyhow::anyhow!("Invalid datetime format"))?;

        let expires = chrono::NaiveDateTime::parse_from_str(datetime_str, "%b %e %H:%M:%S %Y")?;
        Ok(chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(expires, chrono::Utc))
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


    pub fn load_cert(&self) {
        let mut handle = self.inner.handle.lock().unwrap();
        if handle.is_some() && !handle.as_ref().unwrap().is_finished() {
            return;
        }

        let stub = self.clone();
        handle.replace(task::spawn(async move {
            if let Err(e) = stub.load_cert_inner().await {
                error!("load cert failed, stub: {}, {}", stub, e);
            }
        }));
    }

    async fn load_cert_inner(&self) -> Result<()> {
        // 尝试从 keystore_path 加载最新的证书
        let dir = tokio::fs::read_dir(&self.inner.keystore_path).await
            .map_err(|e| anyhow::anyhow!("read keystore dir failed, stub: {}, path: {}, {}", self, self.inner.keystore_path, e))?;

        let mut entries = Vec::new();
        tokio::pin!(dir);
        while let Some(entry) = dir.next_entry().await? {
            if entry.file_name().to_string_lossy().ends_with(".cert") {
                entries.push(entry.path());
            }
        }

        if entries.is_empty() {
            // 如果没有找到证书，启动证书申请流程
            info!("no cert found in keystore, start ordering new cert, stub: {}", self);
            self.start_order().await?;
            return Ok(());
        }

        // 按文件名（时间戳）排序，取最新的
        entries.sort_by(|a, b| b.file_name().unwrap().cmp(a.file_name().unwrap()));
        let cert_path = entries[0].to_string_lossy().to_string();

        info!("load cert, stub: {}, cert_path: {}", self, cert_path);
        let key_path = cert_path.replace(".cert", ".key");

        let cert_data = fs::read(&cert_path).await
            .map_err(|e| {
                error!("load cert failed, stub: {}, cert_path: {}, {}", self, cert_path, e);
                anyhow::anyhow!("load cert failed, stub: {}, cert_path: {}, {}", self, cert_path, e)
            })?;
        let key_data = fs::read(&key_path).await
            .map_err(|e| {
                error!("load cert failed, stub: {}, key_path: {}, {}", self, key_path, e);
                anyhow::anyhow!("load cert failed, stub: {}, key_path: {}, {}", self, key_path, e)
            })?;

        let certified_key = Self::create_certified_key(&cert_data, &key_data)
            .map_err(|e| {
                error!("create certified key failed, stub: {}, cert_path: {}, key_path: {}, {}", self, cert_path, key_path, e);
                anyhow::anyhow!("create certified key failed, stub: {}, cert_path: {}, key_path: {}, {}", self, cert_path, key_path, e)
            })?;
        let expires = Self::get_cert_expiry(&cert_data)
            .map_err(|e| {
                error!("get cert expiry failed, stub: {}, cert_path: {}, key_path: {}, {}", self, cert_path, key_path, e);
                anyhow::anyhow!("get cert expiry failed, stub: {}, cert_path: {}, key_path: {}, {}", self, cert_path, key_path, e)
            })?;

        info!("load cert success, stub: {}, cert_path: {}, key_path: {}, expires: {}", self, cert_path, key_path, expires);

        let mut mut_part = self.inner.mut_part.lock().unwrap();
        mut_part.state = CertState::Ready(CertInfo {
            key: Arc::new(certified_key),
            expires
        });

        Ok(())
    }

    fn check_cert(&self, renew_before_expiry: chrono::Duration) -> Result<()> {
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
                CertState::Expired(_) => true
            }
        };

        if should_order {
            self.renew_cert();
        }

        Ok(())
    }

    async fn order_inner(&self) -> Result<(CertifiedKey, chrono::DateTime<chrono::Utc>)> {
        let order = AcmeOrderSession::new(
            self.inner.domains.clone(),
            self.inner.acme_client.clone(),
            self.inner.responder.clone()
        );
        let (cert_data, key_data) = order.start().await?;

        let timestamp = chrono::Utc::now().timestamp();
        let cert_path = format!("{}/{}.cert", self.inner.keystore_path, timestamp);
        let key_path = format!("{}/{}.key", self.inner.keystore_path, timestamp);

        fs::write(&cert_path, &cert_data).await?;
        fs::write(&key_path, &key_data).await?;

        let certified_key = Self::create_certified_key(&cert_data, &key_data)?;
        let expires = Self::get_cert_expiry(&cert_data)?;

        info!("save cert success, stub: {}, cert_path: {}, key_path: {}, expires: {}",
            self, cert_path, key_path, expires);

        Ok((certified_key, expires))
    }

    async fn start_order(&self) -> Result<()> {
        let mut interval = 15;
        loop {
            let result = self.order_inner().await;

            match result {
                Ok((certified_key, expires)) => {
                    let mut mut_part = self.inner.mut_part.lock().unwrap();
                    mut_part.state = CertState::Ready(CertInfo {
                        key: Arc::new(certified_key),
                        expires,
                    });
                    break Ok(());
                }
                Err(e) => {
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

pub struct CertManager {
    config: CertManagerConfig,
    acme_client: AcmeClient,
    certs: RwLock<HashMap<String, CertStub>>,
    check_handler: Mutex<Option<JoinHandle<()>>>,
}
pub type CertManagerRef = Arc<CertManager>;

#[derive(Clone, Debug, Deserialize)]
pub struct CertManagerConfig {
    pub account: Option<String>,
    pub acme_server: String,
    pub keystore_path: String,
    #[serde(default = "default_check_interval")]
    pub check_interval: chrono::Duration,     // 检查证书的时间间隔
    #[serde(default = "default_renew_before_expiry")]
    pub renew_before_expiry: chrono::Duration, // 过期前多久开始续期
}

fn default_check_interval() -> chrono::Duration {
    chrono::Duration::hours(12)  // 默认每12小时检查一次
}

fn default_renew_before_expiry() -> chrono::Duration {
    chrono::Duration::days(30)   // 默认过期前30天续期
}

impl Default for CertManagerConfig {
    fn default() -> Self {
        Self {
            account: None,
            acme_server: "https://acme-v02.api.letsencrypt.org/directory".to_string(),
            keystore_path: String::new(),
            check_interval: default_check_interval(),
            renew_before_expiry: default_renew_before_expiry(),
        }
    }
}

impl std::fmt::Display for CertManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CertManager")
    }
}

impl Drop for CertManager {
    fn drop(&mut self) {
        debug!("drop cert manager, {}", self);
        let mut check_handler = self.check_handler.lock().unwrap();
        if let Some(handler) = check_handler.take() {
            handler.abort();
        }
    }
}

impl CertManager {
    pub async fn create(config: CertManagerConfig) -> Result<CertManagerRef> {
        info!("create cert manager, config: {:?}", config);

        if !Path::new(config.keystore_path.as_str()).exists() {
            tokio::fs::create_dir_all(config.keystore_path.as_str()).await.map_err(|e| {
                error!("Failed to create keystore path: {}", e);
                e
            })?;
        }

        let account_path = buckyos_kit::path_join(&config.keystore_path, "acme_account.json");
        let account = match AcmeAccount::from_file(&*account_path).await {
            Ok(account) => {
                info!("Loading ACME account from {}", account_path.to_str().unwrap());
                match config.account.clone() {
                    Some(account_name) => {
                        if account_name.as_str() != account.email() {
                            let account = AcmeAccount::new(account_name);
                            if let Err(e) = account.save_to_file(&*account_path).await {
                                error!("Failed to save ACME account: {}", e);
                            }
                            account
                        } else {
                            account
                        }
                    }
                    None => {
                        account
                    }
                }
            }
            Err(_) => {
                let account = match config.account.clone() {
                    Some(account_name) => {
                        AcmeAccount::new(account_name)
                    }
                    None => {
                        // 生成随机邮箱并创建新账号
                        let random_str = rand::rng().random_range(0..1000000);
                        let random_domain = rand::rng().random_range(0..1000000);
                        let email = format!("{}@{}.com", random_str, random_domain);
                        info!("Generated random email address: {}", email);

                        let account = AcmeAccount::new(email);
                        account
                    }
                };
                if let Err(e) = account.save_to_file(&*account_path).await {
                    error!("Failed to save ACME account: {}", e);
                }
                account
            }
        };

        let acme_client = AcmeClient::new(account, config.acme_server.clone()).await?;

        let manager = Arc::new(Self {
            config: config.clone(),
            acme_client,
            certs: RwLock::new(HashMap::new()),
            check_handler: Mutex::new(None),
        });

        // 启动定期检查任务
        {
            let weak_manager = Arc::downgrade(&manager);
            let handle: JoinHandle<()> = tokio::spawn(async move {
                let check_interval = tokio::time::Duration::from_secs(
                    config.check_interval.num_seconds() as u64
                );
                let mut interval = tokio::time::interval(check_interval);
                loop {
                    interval.tick().await;
                    if let Some(manager) = weak_manager.upgrade() {
                        if let Err(e) = manager.check_all_certs() {
                            error!("check certs failed: {}", e);
                        }
                    }
                }
            });
            *manager.check_handler.lock().unwrap() = Some(handle);
        }

        Ok(manager)
    }

    pub fn insert_config(&self, host: String, responder: AcmeChallengeResponderRef) -> Result<()> {
        let keystore_path = buckyos_kit::path_join(&self.config.keystore_path, &sanitize_path_component(&host));
        if !keystore_path.exists() {
            if let Err(e) = std::fs::create_dir_all(&keystore_path) {
                error!("Failed to create certificate storage directory: {} {}", e, keystore_path.to_str().unwrap());
                return Err(anyhow::anyhow!("Failed to create certificate storage directory: {}", e));
            }
        }

        let cert_stub = CertStub::new(
            vec![host.clone()],
            keystore_path.to_str().unwrap().to_string(),
            self.acme_client.clone(),
            responder,
        );
        self.certs.write().unwrap().insert(host, cert_stub.clone());
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

        for (key,value) in certs.iter() {
            if key.starts_with("*.") {
                if host.ends_with(&key[2..]) {
                    info!("find tls config for host: {} ==> key:{}",host,key);
                    return Some(value.clone());
                }
            }
        }

        None
    }

    fn check_all_certs(&self) -> Result<()> {
        let certs = self.certs.read().unwrap().values().cloned().collect::<Vec<_>>();

        for cert in certs {
            if let Err(e) = cert.check_cert(self.config.renew_before_expiry) {
                error!("check cert failed, stub: {}, error: {}", cert, e);
            }
        }
        Ok(())
    }
}

impl std::fmt::Debug for CertManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CertManager")
    }
}

impl ResolvesServerCert for CertManager {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
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
