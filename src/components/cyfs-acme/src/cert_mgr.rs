use crate::acme_client::{
    AcmeAccount, AcmeChallengeResponderRef, AcmeClient, AcmeHttpError, AcmeOrderSession,
};
use crate::default_challenge_responder::DefaultChallengeResponder;
use crate::{Challenge, ChallengeData, ChallengeType};
use anyhow::Result;
use cyfs_identity_cert::{
    CertManager, InstalledCertificate, certificate_manager, certificate_summary,
    install_acme_certificate, installed_certificate, reissue_requested,
    validate_identity_certificate,
};
use log::*;
use name_client::{IdentityMaterial, IdentityRoots, IdentityUsage};
use openssl::pkey::PKey;
use openssl::x509::X509;
use rand::Rng;
use rustls::crypto::ring::sign::any_supported_type;
use rustls::pki_types::PrivateKeyDer;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign;
use rustls::sign::CertifiedKey;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use boa_engine::{JsString, JsValue};
use buckyos_js_runtime::{JsPkgManager, JsPkgManagerRef};
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

#[derive(Clone)]
struct CertInfo {
    key: Arc<CertifiedKey>,
    expires: chrono::DateTime<chrono::Utc>,
    renew_before: chrono::Duration,
}

enum CertState {
    None,
    Ready(CertInfo),
    Renewing(CertInfo),
    /// Uploaded by the user, usable or not: never ordered or replaced here.
    Manual(Option<CertInfo>),
}

struct CertMutPart {
    state: CertState,
    last_error: Option<AcmeCertError>,
    next_retry_at: Option<u64>,
    /// Orders that failed for another reason than the network or the server's
    /// limits while there was no usable certificate.
    refused_orders: u32,
}

impl CertMutPart {
    fn is_stopped(&self) -> bool {
        matches!(self.state, CertState::None) && self.refused_orders >= MAX_REFUSED_ORDERS
    }
}

/// Outlives the gateway: a computer that is switched off at night would never stop.
#[derive(Default, Serialize, Deserialize)]
struct RefusedOrders {
    count: u32,
    last_error: Option<AcmeCertError>,
}

const REFUSED_ORDERS_FILE: &str = "refused_orders.json";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CertCheck {
    Current,
    OrderNeeded,
    Manual,
}

#[cfg(not(test))]
const MANUAL_CHECK_INTERVAL: Duration = Duration::from_secs(60);
#[cfg(test)]
const MANUAL_CHECK_INTERVAL: Duration = Duration::from_millis(20);
const MAX_ERROR_CHARS: usize = 1000;
const MAX_RETRY_SECS: u64 = 600;
/// While the installed certificate is good for longer than a day. Let's Encrypt
/// pauses a name after 1152 failed validations in a row: 10 days of retries every
/// 10 minutes, less than the renewal window of a 90-day certificate.
const MAX_EARLY_RETRY_SECS: u64 = 3600;
/// About a day. After that somebody has to change something first.
const MAX_REFUSED_ORDERS: u32 = 144;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AcmeCertState {
    None,
    Ordering,
    Ready,
    Renewing,
    Manual,
    /// Refused too often without a usable certificate; ordered again when asked to.
    Stopped,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RetryWait {
    Elapsed,
    Restarted,
    /// A certificate installed by someone else.
    Superseded,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AcmeCertError {
    pub message: String,
    /// Unix seconds.
    pub at: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AcmeCertStatus {
    pub host: String,
    pub state: AcmeCertState,
    pub last_error: Option<AcmeCertError>,
    /// Unix seconds.
    pub next_retry_at: Option<u64>,
    pub installed: Option<InstalledCertificate>,
}

fn unix_now() -> u64 {
    chrono::Utc::now().timestamp().max(0) as u64
}

lazy_static::lazy_static! {
    // Configuration reloads create separate managers. Their per-stub task handles
    // cannot prevent simultaneous orders for the same domain.
    static ref CERT_ORDER_LOCKS: Mutex<HashMap<String, Weak<tokio::sync::Mutex<()>>>> =
        Mutex::new(HashMap::new());
}

fn cert_order_lock(domain: &str) -> Arc<tokio::sync::Mutex<()>> {
    let mut locks = CERT_ORDER_LOCKS.lock().unwrap();
    locks.retain(|_, lock| lock.strong_count() > 0);
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    if let Some(lock) = locks.get(&domain).and_then(Weak::upgrade) {
        return lock;
    }
    let lock = Arc::new(tokio::sync::Mutex::new(()));
    locks.insert(domain, Arc::downgrade(&lock));
    lock
}

struct CertStubInner {
    acme_item: AcmeItem,
    work_dir: PathBuf,
    identity_roots: IdentityRoots,
    acme_client: AcmeClient,
    responder: AcmeChallengeResponderRef,
    renew_before_expiry: Option<chrono::Duration>,
    order_lock: Arc<tokio::sync::Mutex<()>>,
    restart: tokio::sync::Notify,
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
        work_dir: PathBuf,
        identity_roots: IdentityRoots,
        acme_client: AcmeClient,
        responder: AcmeChallengeResponderRef,
        renew_before_expiry: Option<chrono::Duration>,
    ) -> Self {
        let refused = std::fs::read(work_dir.join(REFUSED_ORDERS_FILE))
            .ok()
            .and_then(|content| serde_json::from_slice::<RefusedOrders>(&content).ok())
            .unwrap_or_default();
        Self {
            inner: Arc::new(CertStubInner {
                order_lock: cert_order_lock(&acme_item.domain),
                acme_item,
                work_dir,
                identity_roots,
                acme_client,
                responder,
                renew_before_expiry,
                restart: tokio::sync::Notify::new(),
                mut_part: Mutex::new(CertMutPart {
                    state: CertState::None,
                    last_error: refused.last_error,
                    next_retry_at: None,
                    refused_orders: refused.count,
                }),
                handle: Mutex::new(None),
            }),
        }
    }

    fn create_certified_key(cert_data: &[u8], key_data: &[u8]) -> Result<CertifiedKey> {
        let mut cert_chain = vec![];
        for cert in rustls_pemfile::certs(&mut &*cert_data) {
            cert_chain.push(cert?);
        }

        let mut keys = vec![];
        for key in rustls_pemfile::pkcs8_private_keys(&mut &*key_data) {
            keys.push(key?);
        }

        if keys.is_empty() {
            return Err(anyhow::anyhow!("No private key found"));
        }

        let key = PrivateKeyDer::Pkcs8(keys.remove(0));

        let signing_key =
            any_supported_type(&key).map_err(|e| anyhow::anyhow!("Invalid private key: {}", e))?;

        Ok(CertifiedKey::new(cert_chain, signing_key))
    }

    // A configured period that is not shorter than the certificate's lifetime would
    // renew it at every check.
    fn renewal_period(
        configured: Option<chrono::Duration>,
        lifetime: chrono::Duration,
    ) -> chrono::Duration {
        configured
            .filter(|configured| *configured < lifetime)
            .unwrap_or(lifetime / 3)
    }

    fn cert_info(&self, cert_data: &[u8], key_data: &[u8]) -> Result<CertInfo> {
        let key = Self::create_certified_key(cert_data, key_data)?;
        let leaf = key
            .cert
            .first()
            .ok_or_else(|| anyhow::anyhow!("No certificate found"))?;
        let validity = certificate_summary(leaf)?;
        let lifetime =
            chrono::Duration::seconds(validity.not_after as i64 - validity.not_before as i64);
        Ok(CertInfo {
            expires: chrono::DateTime::from_timestamp(validity.not_after as i64, 0)
                .ok_or_else(|| anyhow::anyhow!("Invalid certificate expiry"))?,
            renew_before: Self::renewal_period(self.inner.renew_before_expiry, lifetime),
            key: Arc::new(key),
        })
    }

    pub fn get_cert(&self) -> Option<Arc<CertifiedKey>> {
        let mut_part = self.inner.mut_part.lock().unwrap();
        match &mut_part.state {
            CertState::Ready(info) | CertState::Renewing(info) | CertState::Manual(Some(info))
                if chrono::Utc::now() < info.expires =>
            {
                Some(info.key.clone())
            }
            _ => None,
        }
    }

    fn status(&self) -> AcmeCertStatus {
        let working = self
            .inner
            .handle
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|handle| !handle.is_finished());
        let installed =
            installed_certificate(&self.inner.identity_roots, self.inner.acme_item.identity())
                .unwrap_or_else(|e| {
                    warn!("read installed certificate failed, stub: {}, {}", self, e);
                    None
                });
        let mut_part = self.inner.mut_part.lock().unwrap();
        AcmeCertStatus {
            host: self.inner.acme_item.domain.clone(),
            state: match &mut_part.state {
                // Uploaded since the last check.
                _ if self.is_manual() => AcmeCertState::Manual,
                _ if mut_part.is_stopped() => AcmeCertState::Stopped,
                CertState::None if working => AcmeCertState::Ordering,
                CertState::None => AcmeCertState::None,
                CertState::Ready(_) => AcmeCertState::Ready,
                CertState::Renewing(_) => AcmeCertState::Renewing,
                CertState::Manual(_) => AcmeCertState::Manual,
            },
            last_error: mut_part.last_error.clone(),
            next_retry_at: mut_part.next_retry_at,
            installed,
        }
    }

    pub fn load_cert(&self) {
        let mut handle = self.inner.handle.lock().unwrap();
        if handle.is_some() && !handle.as_ref().unwrap().is_finished() {
            return;
        }

        let stub = self.clone();
        handle.replace(task::spawn(async move {
            if let Err(e) = stub.start_order().await {
                error!("load cert failed, stub: {}, {}", stub, e);
            }
        }));
    }

    // Re-read under order_lock before ordering: another manager may have installed
    // a certificate while we waited, or the user uploaded one.
    fn refresh_cert(&self) -> Result<CertCheck> {
        let info = self.load_identity_cert_info()?;
        let roots = &self.inner.identity_roots;
        let identity = self.inner.acme_item.identity();
        let (state, check) = if self.is_manual() {
            (CertState::Manual(info), CertCheck::Manual)
        } else {
            match info {
                Some(info)
                    if Self::cert_needs_renewal(&info) || reissue_requested(roots, identity) =>
                {
                    (CertState::Renewing(info), CertCheck::OrderNeeded)
                }
                Some(info) => (CertState::Ready(info), CertCheck::Current),
                None => (CertState::None, CertCheck::OrderNeeded),
            }
        };
        let mut mut_part = self.inner.mut_part.lock().unwrap();
        mut_part.state = state;
        if check != CertCheck::OrderNeeded {
            self.clear_failures(&mut mut_part);
        }
        Ok(check)
    }

    fn clear_failures(&self, mut_part: &mut CertMutPart) {
        mut_part.last_error = None;
        self.clear_refused(mut_part);
    }

    fn clear_refused(&self, mut_part: &mut CertMutPart) {
        mut_part.next_retry_at = None;
        if std::mem::take(&mut mut_part.refused_orders) > 0 {
            let path = self.inner.work_dir.join(REFUSED_ORDERS_FILE);
            if let Err(e) = std::fs::remove_file(&path) {
                warn!("remove {} failed: {}", path.display(), e);
            }
        }
    }

    // Being offline, and limits that pass, are no reason to stop.
    fn counts_as_refused(error: &anyhow::Error) -> bool {
        match error.downcast_ref::<AcmeHttpError>() {
            Some(error) => error.is_refusal(),
            None => !error.chain().any(|cause| cause.is::<reqwest::Error>()),
        }
    }

    // Returns false when it is not tried again by itself.
    fn note_failure(&self, error: &anyhow::Error, retry_delay: Duration) -> bool {
        let mut mut_part = self.inner.mut_part.lock().unwrap();
        mut_part.last_error = Some(AcmeCertError {
            message: format!("{error:#}").chars().take(MAX_ERROR_CHARS).collect(),
            at: unix_now(),
        });
        if matches!(mut_part.state, CertState::None) && Self::counts_as_refused(error) {
            mut_part.refused_orders += 1;
            let refused = RefusedOrders {
                count: mut_part.refused_orders,
                last_error: mut_part.last_error.clone(),
            };
            let path = self.inner.work_dir.join(REFUSED_ORDERS_FILE);
            let saved = serde_json::to_vec(&refused)
                .map_err(anyhow::Error::from)
                .and_then(|content| Ok(std::fs::write(&path, content)?));
            if let Err(e) = saved {
                warn!("save {} failed: {}", path.display(), e);
            }
        }
        let stopped = mut_part.is_stopped();
        mut_part.next_retry_at =
            (!stopped).then(|| unix_now().saturating_add(retry_delay.as_secs()));
        !stopped
    }

    /// Orders again now what is failing or was stopped.
    fn restart(&self) {
        self.clear_refused(&mut self.inner.mut_part.lock().unwrap());
        self.inner.restart.notify_one();
        self.load_cert();
    }

    // The uploaded certificate of exactly this host. A manual wildcard certificate
    // of the parent name does not stop this host from getting its own.
    fn is_manual(&self) -> bool {
        certificate_manager(&self.inner.identity_roots, self.inner.acme_item.identity())
            == Some(CertManager::Manual)
    }

    fn load_identity_cert_info(&self) -> Result<Option<CertInfo>> {
        let identity = self.inner.acme_item.identity();
        let cert_match = match self.inner.identity_roots.find_public_file(
            identity,
            IdentityUsage::Server,
            IdentityMaterial::Fullchain,
        ) {
            Ok(cert_match) => cert_match,
            Err(e) => {
                debug!(
                    "find identity fullchain failed, stub: {}, identity: {}, {}",
                    self, identity, e
                );
                return Ok(None);
            }
        };
        let key_path = identity_private_key_path(&self.inner.identity_roots, &cert_match.dir_name);
        let cert_data = match std::fs::read(&cert_match.path) {
            Ok(cert_data) => cert_data,
            Err(e) => {
                debug!(
                    "read identity fullchain failed, stub: {}, path: {}, {}",
                    self,
                    cert_match.path.display(),
                    e
                );
                return Ok(None);
            }
        };
        let key_data = match std::fs::read(&key_path) {
            Ok(key_data) => key_data,
            Err(e) => {
                debug!(
                    "read identity private key failed, stub: {}, path: {}, {}",
                    self,
                    key_path.display(),
                    e
                );
                return Ok(None);
            }
        };
        let certificates = match X509::stack_from_pem(&cert_data) {
            Ok(certificates) => certificates,
            Err(e) => {
                debug!(
                    "parse identity fullchain failed, stub: {}, path: {}, {}",
                    self,
                    cert_match.path.display(),
                    e
                );
                return Ok(None);
            }
        };
        let Some(leaf) = certificates.first() else {
            debug!(
                "identity fullchain is empty, stub: {}, path: {}",
                self,
                cert_match.path.display()
            );
            return Ok(None);
        };
        let private_key = match PKey::private_key_from_pem(&key_data) {
            Ok(private_key) => private_key,
            Err(e) => {
                debug!(
                    "parse identity private key failed, stub: {}, path: {}, {}",
                    self,
                    key_path.display(),
                    e
                );
                return Ok(None);
            }
        };
        if let Err(e) = validate_identity_certificate(
            &self.inner.identity_roots,
            identity,
            &self.inner.acme_item.domain,
            leaf,
            &private_key,
        ) {
            debug!(
                "identity certificate validation failed, stub: {}, identity: {}, fullchain: {}, key: {}, {}",
                self,
                identity,
                cert_match.path.display(),
                key_path.display(),
                e
            );
            return Ok(None);
        }
        let info = match self.cert_info(&cert_data, &key_data) {
            Ok(info) => info,
            Err(e) => {
                debug!(
                    "parse identity certificate/key failed, stub: {}, fullchain: {}, key: {}, {}",
                    self,
                    cert_match.path.display(),
                    key_path.display(),
                    e
                );
                return Ok(None);
            }
        };

        info!(
            "load identity cert success, stub: {}, identity: {}, fullchain: {}, key: {}, expires: {}",
            self,
            identity,
            cert_match.path.display(),
            key_path.display(),
            info.expires
        );
        Ok(Some(info))
    }

    fn cert_needs_renewal(info: &CertInfo) -> bool {
        chrono::Utc::now() >= info.expires - info.renew_before
    }

    // Returns false when the order was overtaken by an uploaded certificate.
    async fn order_inner(&self, issued_cert: &mut Option<(Vec<u8>, Vec<u8>)>) -> Result<bool> {
        if issued_cert.is_none() {
            let mut order = AcmeOrderSession::new(
                self.inner.acme_item.domain.clone(),
                self.inner.acme_client.clone(),
                self.inner.responder.clone(),
            );
            *issued_cert = Some(order.start().await?);
        }
        if self.is_manual() {
            info!(
                "discard issued cert, stub: {} has a manual certificate",
                self
            );
            return Ok(false);
        }
        // An installation failure must retry the downloaded certificate, not
        // consume another issuance for the same identifiers.
        let (cert_data, key_data) = issued_cert.as_ref().unwrap();
        let info = self.cert_info(cert_data, key_data)?;

        install_acme_certificate(
            &self.inner.identity_roots,
            self.inner.acme_item.identity(),
            &self.inner.acme_item.domain,
            &self.inner.work_dir,
            cert_data,
            key_data,
            info.renew_before,
        )?;

        info!(
            "install identity cert success, stub: {}, identity: {}, expires: {}",
            self,
            self.inner.acme_item.identity(),
            info.expires
        );

        {
            let mut mut_part = self.inner.mut_part.lock().unwrap();
            mut_part.state = CertState::Ready(info);
            self.clear_failures(&mut mut_part);
        }

        Ok(true)
    }

    async fn start_order(&self) -> Result<()> {
        loop {
            // Make an existing certificate available even while another manager is
            // renewing it and holds the order lock.
            match self.refresh_cert()? {
                CertCheck::Current => return Ok(()),
                CertCheck::OrderNeeded => {
                    if self.inner.mut_part.lock().unwrap().is_stopped() {
                        let _ = tokio::time::timeout(
                            MANUAL_CHECK_INTERVAL,
                            self.inner.restart.notified(),
                        )
                        .await;
                        continue;
                    }
                }
                CertCheck::Manual => {
                    while self.is_manual() {
                        tokio::time::sleep(MANUAL_CHECK_INTERVAL).await;
                    }
                    continue;
                }
            }
            if self.order_until_installed().await? {
                return Ok(());
            }
        }
    }

    // Returns false when the certificate turned out to be managed by the user, or
    // the order was refused too often.
    async fn order_until_installed(&self) -> Result<bool> {
        let _order_guard = self.inner.order_lock.lock().await;
        let mut interval = 15;
        let mut issued_cert = None;
        loop {
            match self.refresh_cert()? {
                CertCheck::Current => return Ok(true),
                CertCheck::Manual => return Ok(false),
                CertCheck::OrderNeeded => {}
            }
            let result = self.order_inner(&mut issued_cert).await;

            match result {
                Ok(installed) => return Ok(installed),
                Err(e) => {
                    interval = (interval * 2).min(self.max_retry_secs());
                    let retry_delay = e
                        .downcast_ref::<AcmeHttpError>()
                        .and_then(|error| error.retry_after)
                        .unwrap_or_default()
                        .max(Duration::from_secs(interval));
                    error!(
                        "order cert failed, stub: {}, {:#}; retry in {:?}",
                        self, e, retry_delay
                    );
                    if !self.note_failure(&e, retry_delay) {
                        error!("order cert stopped, stub: {}", self);
                        return Ok(false);
                    }
                    match self.wait_for_retry(retry_delay).await? {
                        RetryWait::Elapsed => {}
                        RetryWait::Restarted => interval = 15,
                        RetryWait::Superseded => {
                            return Ok(self.refresh_cert()? == CertCheck::Current);
                        }
                    }
                }
            }
        }
    }

    fn max_retry_secs(&self) -> u64 {
        match &self.inner.mut_part.lock().unwrap().state {
            CertState::Renewing(info)
                if info.expires - chrono::Utc::now() > chrono::Duration::days(1) =>
            {
                MAX_EARLY_RETRY_SECS
            }
            _ => MAX_RETRY_SECS,
        }
    }

    async fn wait_for_retry(&self, retry_delay: Duration) -> Result<RetryWait> {
        let retry_at = tokio::time::Instant::now() + retry_delay;
        loop {
            let check_at = retry_at.min(tokio::time::Instant::now() + Duration::from_secs(60));
            let restarted = tokio::time::timeout_at(check_at, self.inner.restart.notified())
                .await
                .is_ok();
            if self.refresh_cert()? != CertCheck::OrderNeeded {
                return Ok(RetryWait::Superseded);
            }
            if restarted {
                return Ok(RetryWait::Restarted);
            }
            if tokio::time::Instant::now() >= retry_at {
                return Ok(RetryWait::Elapsed);
            }
        }
    }

    fn cancel_load(&self) {
        if let Some(handle) = self.inner.handle.lock().unwrap().take() {
            handle.abort();
        }
    }
}

fn identity_private_key_path(roots: &IdentityRoots, dir_name: &str) -> PathBuf {
    roots
        .security_root
        .join(dir_name)
        .join("server.private.pem")
}

#[derive(Clone, Debug)]
pub struct AcmeItem {
    domain: String,
    identity: Option<String>,
    identity_manager: Option<AcmeIdentityConfig>,
    challenge_type: ChallengeType,
    data: Option<serde_json::Value>,
}

impl AcmeItem {
    pub fn new(
        domain: String,
        challenge_type: ChallengeType,
        data: Option<serde_json::Value>,
    ) -> Self {
        Self {
            domain,
            identity: None,
            identity_manager: None,
            challenge_type,
            data,
        }
    }

    pub fn with_identity(
        mut self,
        identity: Option<String>,
        identity_manager: Option<AcmeIdentityConfig>,
    ) -> Self {
        self.identity = identity;
        self.identity_manager = identity_manager;
        self
    }

    pub fn identity(&self) -> &str {
        self.identity.as_deref().unwrap_or(self.domain.as_str())
    }

    fn identity_roots(
        &self,
        default_identity_manager: &Option<AcmeIdentityConfig>,
    ) -> Result<IdentityRoots> {
        let config = self
            .identity_manager
            .as_ref()
            .or(default_identity_manager.as_ref());
        match config {
            Some(config) => config.to_roots(),
            None => IdentityRoots::from_env_or_buckyos_root()
                .map_err(|e| anyhow::anyhow!("load default identity roots failed: {}", e)),
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

    fn propagation_delay(&self) -> Duration {
        Duration::ZERO
    }

    /// Returns once the CA can be asked to look up the challenge record `domain`
    /// with the value `key_hash`: after the fixed delay, unless the factory is able
    /// to check. An error fails the order.
    async fn wait_propagation(&self, domain: &str, _key_hash: &str) -> Result<()> {
        let delay = self.propagation_delay();
        if !delay.is_zero() {
            info!(
                "wait {:?} for ACME challenge propagation: {}",
                delay, domain
            );
            tokio::time::sleep(delay).await;
        }
        Ok(())
    }
}
pub type DnsProviderFactoryRef = Arc<dyn DnsProviderFactory>;

lazy_static::lazy_static! {
    static ref DNS_PROVIDER_FACTORYS: RwLock<HashMap<String, DnsProviderFactoryRef>> = RwLock::new(HashMap::new());
}

#[derive(Serialize, Deserialize)]
struct DnsProviderInfo {
    pub dns_provider: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct AcmeIdentityConfig {
    #[serde(
        default,
        alias = "public_root",
        alias = "public_identity_root",
        alias = "public_identity_root_path",
        skip_serializing_if = "Option::is_none"
    )]
    pub public_root_path: Option<String>,
    #[serde(
        default,
        alias = "security_root",
        skip_serializing_if = "Option::is_none"
    )]
    pub security_root_path: Option<String>,
}

impl AcmeIdentityConfig {
    fn to_roots(&self) -> Result<IdentityRoots> {
        let mut roots = IdentityRoots::from_env_or_buckyos_root()
            .map_err(|e| anyhow::anyhow!("load default identity roots failed: {}", e))?;
        if let Some(public_root_path) = self.public_root_path.as_ref() {
            roots.public_root = PathBuf::from(public_root_path);
        }
        if let Some(security_root_path) = self.security_root_path.as_ref() {
            roots.security_root = PathBuf::from(security_root_path);
        }
        Ok(roots)
    }
}

pub struct AcmeCertManager {
    config: CertManagerConfig,
    acme_client: AcmeClient,
    certs: RwLock<HashMap<String, CertStub>>,
    check_handler: Mutex<Option<JoinHandle<()>>>,
    responder: Mutex<Option<AcmeChallengeResponderRef>>,
    challenge_certs: Mutex<HashMap<String, Arc<sign::CertifiedKey>>>,
    http_challenges: Mutex<HashMap<String, String>>,
    dns_providers: RwLock<HashMap<String, DnsProviderRef>>,
    dns_provider_factories: RwLock<HashMap<String, DnsProviderFactoryRef>>,
}

pub type AcmeCertManagerRef = Arc<AcmeCertManager>;

#[derive(Clone, Debug, Deserialize)]
pub struct CertManagerConfig {
    pub account: Option<String>,
    pub acme_server: String,
    pub dns_providers: Option<HashMap<String, serde_json::Value>>,
    pub keystore_path: String,
    pub dns_provider_path: Option<String>,
    pub identity_manager: Option<AcmeIdentityConfig>,
    #[serde(default = "default_check_interval")]
    pub check_interval: chrono::Duration, // 检查证书的时间间隔
    /// 过期前多久开始续期，不填为证书有效期的三分之一
    pub renew_before_expiry: Option<chrono::Duration>,
}

fn default_check_interval() -> chrono::Duration {
    chrono::Duration::hours(12) // 默认每12小时检查一次
}

impl Default for CertManagerConfig {
    fn default() -> Self {
        Self {
            account: None,
            acme_server: "https://acme-v02.api.letsencrypt.org/directory".to_string(),
            dns_providers: None,
            keystore_path: String::new(),
            dns_provider_path: None,
            identity_manager: None,
            check_interval: default_check_interval(),
            renew_before_expiry: None,
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
        let mut check_handler = self.check_handler.lock().unwrap();
        if let Some(handler) = check_handler.take() {
            handler.abort();
        }
        // Workers own a CertStub clone, so CertStubInner::drop alone cannot
        // cancel a retry loop when this manager is replaced during a reload.
        for cert in self.certs.read().unwrap().values() {
            cert.cancel_load();
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

        let account_path = buckyos_kit::path_join(&config.keystore_path, "acme_account.json");
        let account = match AcmeAccount::from_file(&*account_path).await {
            Ok(account) => {
                info!(
                    "Loading ACME account from {}",
                    account_path.to_str().unwrap()
                );
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
                    None => account,
                }
            }
            Err(_) => {
                let account = match config.account.clone() {
                    Some(account_name) => AcmeAccount::new(account_name),
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

        let mut dns_providers = HashMap::<String, DnsProviderRef>::new();
        let mut dns_provider_factories = HashMap::<String, DnsProviderFactoryRef>::new();
        let manager = AcmeCertManagerRef::new(Self {
            config: config.clone(),
            acme_client,
            certs: RwLock::new(HashMap::new()),
            check_handler: Mutex::new(None),
            responder: Mutex::new(None),
            challenge_certs: Mutex::new(Default::default()),
            http_challenges: Mutex::new(Default::default()),
            dns_providers: RwLock::new(dns_providers.clone()),
            dns_provider_factories: RwLock::new(dns_provider_factories.clone()),
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
                    dns_provider_factories.insert(name.clone(), factory);
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
            manager
                .dns_provider_factories
                .write()
                .unwrap()
                .extend(dns_provider_factories);
        }

        {
            let mut responder = manager.responder.lock().unwrap();
            *responder = Some(Arc::new(DefaultChallengeResponder::new(manager.clone())));
        }
        // 启动定期检查任务
        {
            let weak_manager = Arc::downgrade(&manager);
            let handle: JoinHandle<()> = tokio::spawn(async move {
                let check_interval =
                    tokio::time::Duration::from_secs(config.check_interval.num_seconds() as u64);
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

    pub fn register_dns_provider(&self, name: impl Into<String>, provider: impl DnsProvider) {
        self.dns_providers
            .write()
            .unwrap()
            .insert(name.into(), Arc::new(provider));
    }

    pub fn add_acme_item(&self, item: AcmeItem) -> Result<()> {
        let work_dir = buckyos_kit::path_join(
            &self.config.keystore_path,
            &sanitize_path_component(&item.domain),
        );
        if !work_dir.exists() {
            if let Err(e) = std::fs::create_dir_all(&work_dir) {
                error!(
                    "Failed to create certificate storage directory: {} {}",
                    e,
                    work_dir.to_str().unwrap()
                );
                return Err(anyhow::anyhow!(
                    "Failed to create certificate storage directory: {}",
                    e
                ));
            }
        }

        let responder = { self.responder.lock().unwrap().clone().unwrap() };
        let identity_roots = item.identity_roots(&self.config.identity_manager)?;
        let mut certs = self.certs.write().unwrap();
        if certs.contains_key(&item.domain) {
            return Ok(());
        }
        let domain = item.domain.clone();
        let cert_stub = CertStub::new(
            item,
            work_dir,
            identity_roots,
            self.acme_client.clone(),
            responder,
            self.config.renew_before_expiry,
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

    fn check_all_certs(&self) -> Result<()> {
        let certs = self
            .certs
            .read()
            .unwrap()
            .values()
            .cloned()
            .collect::<Vec<_>>();

        for cert in certs {
            cert.load_cert();
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

    fn get_dns_provider_for_cert(&self, cert_stub: &CertStub) -> Result<DnsProviderRef> {
        let provider_data = cert_stub
            .inner
            .acme_item
            .data
            .clone()
            .ok_or_else(|| anyhow::anyhow!("dns challenge provider params is empty"))?;
        let provider_info: DnsProviderInfo = serde_json::from_value(provider_data.clone())
            .map_err(|e| {
                anyhow::anyhow!(
                    "parse plugin data {} failed: {}",
                    serde_json::to_string(&provider_data).unwrap_or_default(),
                    e
                )
            })?;

        self.get_provider(provider_info.dns_provider.as_str())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "dns challenge provider {} not exists",
                    provider_info.dns_provider
                )
            })
    }

    pub(crate) async fn wait_challenge_propagation(&self, challenge: &Challenge) -> Result<()> {
        let ChallengeData::Dns01 { key_hash, .. } = &challenge.data else {
            return Ok(());
        };
        let cert_stub = {
            let certs = self.certs.read().unwrap();
            certs.get(challenge.domain.as_str()).cloned()
        };
        let Some(cert_stub) = cert_stub else {
            return Ok(());
        };
        let factory = cert_stub
            .inner
            .acme_item
            .data
            .clone()
            .and_then(|data| serde_json::from_value::<DnsProviderInfo>(data).ok())
            .and_then(|info| {
                self.dns_provider_factories
                    .read()
                    .unwrap()
                    .get(info.dns_provider.as_str())
                    .cloned()
            });
        match factory {
            Some(factory) => {
                factory
                    .wait_propagation(&dns_challenge_name(&challenge.domain), key_hash)
                    .await
            }
            None => Ok(()),
        }
    }

    async fn call_dns_provider(
        &self,
        cert_stub: &CertStub,
        key_hash: &str,
        op: &str,
    ) -> Result<()> {
        let provider = self.get_dns_provider_for_cert(cert_stub)?;

        provider
            .call(
                op.to_string(),
                dns_challenge_name(&cert_stub.inner.acme_item.domain),
                key_hash.to_string(),
            )
            .await
    }

    /// Orders the certificate of a host again now; false when it is not managed here.
    pub fn restart_cert(&self, host: &str) -> bool {
        let stub = self
            .certs
            .read()
            .unwrap()
            .iter()
            .find(|(domain, _)| domain.eq_ignore_ascii_case(host))
            .map(|(_, stub)| stub.clone());
        match stub {
            Some(stub) => {
                info!("restart cert order, stub: {}", stub);
                stub.restart();
                true
            }
            None => false,
        }
    }

    /// Every managed host, sorted by name.
    pub fn cert_statuses(&self) -> Vec<AcmeCertStatus> {
        let certs = self
            .certs
            .read()
            .unwrap()
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let mut statuses = certs.iter().map(CertStub::status).collect::<Vec<_>>();
        statuses.sort_by(|a, b| a.host.cmp(&b.host));
        statuses
    }
}

/// `<domain>` and `*.<domain>` share one challenge name.
fn dns_challenge_name(domain: &str) -> String {
    format!(
        "_acme-challenge.{}",
        domain.strip_prefix("*.").unwrap_or(domain)
    )
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_acme::MockAcme;
    use cyfs_identity_cert::{PreparedCertificate, clear_manual_mark, install_manual_certificates};
    use openssl::asn1::Asn1Time;
    use openssl::bn::BigNum;
    use openssl::hash::MessageDigest;
    use openssl::x509::extension::SubjectAlternativeName;
    use openssl::x509::{X509Builder, X509NameBuilder};
    use std::sync::atomic::Ordering;

    fn test_config(temp: &Path, server: &MockAcme) -> CertManagerConfig {
        CertManagerConfig {
            account: Some("test@example.com".to_string()),
            acme_server: format!("{}/directory", server.url),
            keystore_path: temp.join("acme").to_string_lossy().into_owned(),
            identity_manager: Some(AcmeIdentityConfig {
                public_root_path: Some(temp.join("identity").to_string_lossy().into_owned()),
                security_root_path: Some(temp.join("security").to_string_lossy().into_owned()),
            }),
            ..CertManagerConfig::default()
        }
    }

    fn test_stub(manager: &AcmeCertManagerRef, domain: &str) -> CertStub {
        let item = AcmeItem::new(domain.to_string(), ChallengeType::Http01, None);
        CertStub::new(
            item.clone(),
            Path::new(&manager.config.keystore_path).join(sanitize_path_component(domain)),
            item.identity_roots(&manager.config.identity_manager)
                .unwrap(),
            manager.acme_client.clone(),
            manager.responder.lock().unwrap().clone().unwrap(),
            manager.config.renew_before_expiry,
        )
    }

    fn install_test_cert(stub: &CertStub, valid_days: i64) {
        let lifetime = chrono::Duration::days(valid_days);
        install_aged_cert(stub, lifetime, lifetime);
    }

    // A certificate of `lifetime` that expires in `left`.
    fn install_aged_cert(stub: &CertStub, lifetime: chrono::Duration, left: chrono::Duration) {
        let domain = &stub.inner.acme_item.domain;
        let not_after = chrono::Utc::now() + left;
        let (cert, key) = generate_test_cert_between(domain, not_after - lifetime, not_after);
        install_acme_certificate(
            &stub.inner.identity_roots,
            stub.inner.acme_item.identity(),
            domain,
            &stub.inner.work_dir,
            &cert,
            &key,
            chrono::Duration::days(7),
        )
        .unwrap();
    }

    async fn wait_until(mut condition: impl FnMut() -> bool) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while !condition() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("ACME test condition timed out");
    }

    #[tokio::test]
    async fn concurrent_managers_issue_once_per_domain() {
        let temp = tempfile::tempdir().unwrap();
        let server = MockAcme::new().await;
        let config = test_config(temp.path(), &server);
        let first = AcmeCertManager::create(config.clone()).await.unwrap();
        let second = AcmeCertManager::create(config).await.unwrap();
        let domains = ["example.com", "*.example.com"];
        for manager in [&first, &second] {
            for domain in domains {
                // Repeated registration and periodic checks must share the
                // same work, including across a configuration reload.
                for _ in 0..3 {
                    manager
                        .add_acme_item(AcmeItem::new(
                            domain.to_string(),
                            ChallengeType::Http01,
                            None,
                        ))
                        .unwrap();
                }
            }
            manager.check_all_certs().unwrap();
        }
        wait_until(|| server.orders() >= 2).await;
        server.order_gate.add_permits(100);
        wait_until(|| {
            [&first, &second].iter().all(|manager| {
                domains.iter().all(|domain| {
                    manager
                        .get_cert_by_host(domain)
                        .unwrap()
                        .get_cert()
                        .is_some()
                })
            })
        })
        .await;
        assert_eq!(
            server.orders(),
            2,
            "one order for the apex and one for the wildcard"
        );
        for domain in domains {
            let first_cert = first.get_cert_by_host(domain).unwrap().get_cert().unwrap();
            let second_cert = second.get_cert_by_host(domain).unwrap().get_cert().unwrap();
            assert_eq!(first_cert.cert, second_cert.cert);
        }
    }

    #[tokio::test]
    async fn start_order_reuses_installed_cert_and_renews_only_inside_window() {
        let temp = tempfile::tempdir().unwrap();
        let server = MockAcme::new().await;
        server.order_gate.add_permits(100);
        let manager = AcmeCertManager::create(test_config(temp.path(), &server))
            .await
            .unwrap();
        let stub = test_stub(&manager, "example.com");
        install_test_cert(&stub, 90);
        stub.start_order().await.unwrap();
        assert!(stub.get_cert().is_some());
        assert_eq!(server.orders(), 0);

        install_aged_cert(&stub, chrono::Duration::days(90), chrono::Duration::days(3));
        stub.start_order().await.unwrap();
        assert_eq!(server.orders(), 1);
        // A later check must load the renewal instead of ordering again.
        stub.start_order().await.unwrap();
        assert_eq!(server.orders(), 1);
    }

    #[test]
    fn a_third_of_the_lifetime_is_left_for_renewing() {
        let (days, hours) = (chrono::Duration::days, chrono::Duration::hours);
        for (lifetime, configured, expected) in [
            (days(90), None, days(30)),
            (days(64), None, hours(512)),
            (days(45), None, days(15)),
            (hours(160), None, chrono::Duration::minutes(3200)),
            (days(90), Some(days(7)), days(7)),
            (days(90), Some(days(0)), days(0)),
            (days(90), Some(days(89)), days(89)),
            (days(90), Some(days(90)), days(30)),
            (hours(160), Some(days(7)), chrono::Duration::minutes(3200)),
        ] {
            assert_eq!(
                CertStub::renewal_period(configured, lifetime),
                expected,
                "{lifetime} {configured:?}"
            );
        }
    }

    #[tokio::test]
    async fn the_renewal_window_follows_the_certificate_unless_configured() {
        let temp = tempfile::tempdir().unwrap();
        let server = MockAcme::new().await;
        let mut config = test_config(temp.path(), &server);
        let manager = AcmeCertManager::create(config.clone()).await.unwrap();
        let stub = test_stub(&manager, "window.example.com");
        let (days, hours) = (chrono::Duration::days, chrono::Duration::hours);
        for lifetime in [days(90), days(64), days(45), hours(160)] {
            install_aged_cert(&stub, lifetime, lifetime / 3 + hours(1));
            assert_eq!(
                stub.refresh_cert().unwrap(),
                CertCheck::Current,
                "{lifetime}"
            );
            install_aged_cert(&stub, lifetime, lifetime / 3 - hours(1));
            assert_eq!(
                stub.refresh_cert().unwrap(),
                CertCheck::OrderNeeded,
                "{lifetime}"
            );
            assert!(stub.get_cert().is_some());
        }

        config.renew_before_expiry = Some(days(7));
        let configured = AcmeCertManager::create(config).await.unwrap();
        let configured = test_stub(&configured, "window.example.com");
        for (left, expected) in [
            (days(20), CertCheck::Current),
            (days(7) + hours(1), CertCheck::Current),
            (days(7) - hours(1), CertCheck::OrderNeeded),
        ] {
            install_aged_cert(&configured, days(90), left);
            assert_eq!(configured.refresh_cert().unwrap(), expected, "{left}");
        }

        let fullchain = stub
            .inner
            .identity_roots
            .x509_paths("window.example.com", IdentityUsage::Server)
            .unwrap()
            .fullchain;
        std::fs::write(fullchain, "broken").unwrap();
        assert_eq!(stub.refresh_cert().unwrap(), CertCheck::OrderNeeded);
        assert!(stub.get_cert().is_none());
        assert_eq!(server.orders(), 0);
    }

    #[tokio::test]
    async fn the_issued_certificate_records_its_renewal_period() {
        let temp = tempfile::tempdir().unwrap();
        let server = MockAcme::new().await;
        server.order_gate.add_permits(100);
        let manager = AcmeCertManager::create(test_config(temp.path(), &server))
            .await
            .unwrap();
        let stub = test_stub(&manager, "issued.example.com");
        stub.start_order().await.unwrap();
        let installed = stub.status().installed.unwrap();
        let paths = stub
            .inner
            .identity_roots
            .x509_paths("issued.example.com", IdentityUsage::Server)
            .unwrap();
        let metadata: Value =
            serde_json::from_slice(&std::fs::read(paths.metadata).unwrap()).unwrap();
        assert_eq!(
            metadata["renewal"]["renew_before"],
            format!("PT{}S", (installed.not_after - installed.not_before) / 3)
        );
    }

    // Retry delays in the order they were chosen, each listed once.
    async fn retry_delays(stub: &CertStub, time: Duration) -> Vec<u64> {
        let mut delays = Vec::new();
        let end = tokio::time::Instant::now() + time;
        stub.load_cert();
        while tokio::time::Instant::now() < end {
            tokio::time::sleep(Duration::from_secs(5)).await;
            let mut_part = stub.inner.mut_part.lock().unwrap();
            if let (Some(error), Some(retry_at)) = (&mut_part.last_error, mut_part.next_retry_at) {
                let delay = retry_at - error.at;
                if delays.last() != Some(&delay) {
                    delays.push(delay);
                }
            }
        }
        stub.cancel_load();
        delays
    }

    #[tokio::test(start_paused = true)]
    async fn renewing_early_is_retried_less_often() {
        let temp = tempfile::tempdir().unwrap();
        let closed_port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let manager = AcmeCertManager::create(CertManagerConfig {
            acme_server: format!("http://{closed_port}/directory"),
            keystore_path: temp.path().join("acme").to_string_lossy().into_owned(),
            identity_manager: Some(AcmeIdentityConfig {
                public_root_path: Some(temp.path().join("identity").to_string_lossy().into_owned()),
                security_root_path: Some(
                    temp.path().join("security").to_string_lossy().into_owned(),
                ),
            }),
            ..CertManagerConfig::default()
        })
        .await
        .unwrap();
        let day = chrono::Duration::days(1);
        for (domain, left, expected) in [
            (
                "early.example.com",
                Some(day * 29),
                vec![30, 60, 120, 240, 480, 960, 1920, 3600],
            ),
            (
                "late.example.com",
                Some(day / 2),
                vec![30, 60, 120, 240, 480, 600],
            ),
            ("none.example.com", None, vec![30, 60, 120, 240, 480, 600]),
        ] {
            let stub = test_stub(&manager, domain);
            if let Some(left) = left {
                install_aged_cert(&stub, day * 90, left);
            }
            let delays = retry_delays(&stub, Duration::from_secs(4 * 3600)).await;
            assert_eq!(delays, expected, "{domain}");
        }
    }

    #[tokio::test]
    async fn installation_retry_reuses_downloaded_certificate() {
        let temp = tempfile::tempdir().unwrap();
        let server = MockAcme::new().await;
        server.order_gate.add_permits(100);
        let manager = AcmeCertManager::create(test_config(temp.path(), &server))
            .await
            .unwrap();
        let stub = test_stub(&manager, "example.com");
        // A file where the state directory belongs forces installation to fail
        // after the ACME server has already issued and returned the certificate.
        std::fs::write(&stub.inner.work_dir, "blocked").unwrap();
        let mut issued_cert = None;
        assert!(stub.order_inner(&mut issued_cert).await.is_err());
        assert!(issued_cert.is_some());
        assert_eq!(server.orders(), 1);
        std::fs::remove_file(&stub.inner.work_dir).unwrap();
        stub.order_inner(&mut issued_cert).await.unwrap();
        assert_eq!(server.orders(), 1);
        assert!(stub.get_cert().is_some());
        assert!(stub.load_identity_cert_info().unwrap().is_some());
    }

    #[tokio::test]
    async fn waiting_renewal_serves_existing_certificate_only_until_expiry() {
        let temp = tempfile::tempdir().unwrap();
        let server = MockAcme::new().await;
        let manager = AcmeCertManager::create(test_config(temp.path(), &server))
            .await
            .unwrap();
        let stub = test_stub(&manager, "example.com");
        install_aged_cert(&stub, chrono::Duration::days(90), chrono::Duration::days(3));
        let _guard = stub.inner.order_lock.lock().await;
        stub.load_cert();
        wait_until(|| stub.get_cert().is_some()).await;
        {
            let mut state = stub.inner.mut_part.lock().unwrap();
            let CertState::Renewing(info) = &mut state.state else {
                panic!("expected renewal")
            };
            info.expires = chrono::Utc::now() - chrono::Duration::seconds(1);
        }
        assert!(stub.get_cert().is_none());
        assert_eq!(server.orders(), 0);
        stub.cancel_load();
    }

    #[tokio::test]
    async fn dropping_manager_cancels_inflight_order() {
        let temp = tempfile::tempdir().unwrap();
        let server = MockAcme::new().await;
        let manager = AcmeCertManager::create(test_config(temp.path(), &server))
            .await
            .unwrap();
        manager
            .add_acme_item(AcmeItem::new(
                "example.com".to_string(),
                ChallengeType::Http01,
                None,
            ))
            .unwrap();
        let stub = manager.get_cert_by_host("example.com").unwrap();
        let weak_stub = Arc::downgrade(&stub.inner);
        wait_until(|| server.orders() == 1).await;
        drop(stub);
        drop(manager);
        wait_until(|| weak_stub.upgrade().is_none()).await;
        // Cancellation must also release the shared lock for the next manager.
        let lock = cert_order_lock("example.com");
        assert!(lock.try_lock().is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn retry_wait_honors_deadline_and_observes_external_certificate() {
        let temp = tempfile::tempdir().unwrap();
        let server = MockAcme::new().await;
        let manager = AcmeCertManager::create(test_config(temp.path(), &server))
            .await
            .unwrap();
        let stub = test_stub(&manager, "example.com");
        let start = tokio::time::Instant::now();
        assert!(
            stub.wait_for_retry(Duration::from_secs(3600))
                .await
                .unwrap()
                == RetryWait::Elapsed
        );
        assert!(start.elapsed() >= Duration::from_secs(3600));

        let start = tokio::time::Instant::now();
        let (loaded, ()) = tokio::join!(stub.wait_for_retry(Duration::from_secs(3600)), async {
            tokio::time::sleep(Duration::from_secs(10)).await;
            install_test_cert(&stub, 90);
        });
        assert_eq!(loaded.unwrap(), RetryWait::Superseded);
        assert!(start.elapsed() < Duration::from_secs(3600));
        assert!(stub.get_cert().is_some());
        assert_eq!(server.orders(), 0);
    }

    #[test]
    fn install_acme_certificate_writes_active_files() {
        let temp = tempfile::tempdir().unwrap();
        let roots = IdentityRoots::new(temp.path().join("identity"), temp.path().join("security"));
        let work_dir = temp.path().join("state").join("acme").join("example.com");
        let (cert, key) = generate_test_cert("example.com", 90);
        let paths = roots
            .x509_paths("example.com", IdentityUsage::Server)
            .unwrap();
        let keyref_path = paths.keyref.as_ref().unwrap();
        std::fs::create_dir_all(keyref_path.parent().unwrap()).unwrap();
        std::fs::write(keyref_path, "stale keyref").unwrap();

        install_acme_certificate(
            &roots,
            "example.com",
            "example.com",
            &work_dir,
            &cert,
            &key,
            chrono::Duration::days(7),
        )
        .unwrap();

        assert!(paths.cert.exists());
        assert!(paths.chain.exists());
        assert!(paths.fullchain.exists());
        assert!(paths.metadata.exists());
        assert!(paths.private_key.exists());
        assert!(!keyref_path.exists());
    }

    #[test]
    fn install_acme_certificate_rejects_san_mismatch_without_overwrite() {
        let temp = tempfile::tempdir().unwrap();
        let roots = IdentityRoots::new(temp.path().join("identity"), temp.path().join("security"));
        let work_dir = temp.path().join("state").join("acme").join("example.com");
        let (cert, key) = generate_test_cert("example.com", 90);

        install_acme_certificate(
            &roots,
            "example.com",
            "example.com",
            &work_dir,
            &cert,
            &key,
            chrono::Duration::days(7),
        )
        .unwrap();
        let paths = roots
            .x509_paths("example.com", IdentityUsage::Server)
            .unwrap();
        let old_fullchain = std::fs::read(&paths.fullchain).unwrap();

        let (wrong_cert, wrong_key) = generate_test_cert("other.example.com", 90);
        let result = install_acme_certificate(
            &roots,
            "example.com",
            "example.com",
            &work_dir,
            &wrong_cert,
            &wrong_key,
            chrono::Duration::days(7),
        );

        assert!(result.is_err());
        assert_eq!(std::fs::read(&paths.fullchain).unwrap(), old_fullchain);
    }

    fn install_manual(stub: &CertStub, valid_days: u32) {
        let domain = &stub.inner.acme_item.domain;
        let (fullchain_pem, key_pem) = generate_test_cert(domain, valid_days);
        install_manual_certificates(
            &stub.inner.identity_roots,
            &[PreparedCertificate {
                host: domain.clone(),
                fullchain_pem,
                key_pem,
            }],
        )
        .unwrap();
    }

    fn installed_fingerprint(stub: &CertStub) -> String {
        stub.status().installed.unwrap().fingerprint
    }

    #[tokio::test]
    async fn manual_certificate_is_neither_ordered_nor_replaced() {
        let temp = tempfile::tempdir().unwrap();
        let server = MockAcme::new().await;
        server.order_gate.add_permits(100);
        let config = test_config(temp.path(), &server);
        let manager = AcmeCertManager::create(config.clone()).await.unwrap();
        let stub = test_stub(&manager, "example.com");
        // Inside the renewal window already.
        install_manual(&stub, 3);
        let fingerprint = installed_fingerprint(&stub);

        stub.load_cert();
        wait_until(|| stub.get_cert().is_some()).await;
        tokio::time::sleep(MANUAL_CHECK_INTERVAL * 5).await;
        let status = stub.status();
        assert_eq!(status.state, AcmeCertState::Manual);
        assert_eq!((status.last_error, status.next_retry_at), (None, None));
        assert_eq!(status.installed.unwrap().manager, Some(CertManager::Manual));
        assert_eq!(server.orders(), 0);

        // Expired: not served any more, still nobody else's to replace.
        {
            let mut mut_part = stub.inner.mut_part.lock().unwrap();
            let CertState::Manual(Some(info)) = &mut mut_part.state else {
                panic!("expected a manual certificate")
            };
            info.expires = chrono::Utc::now() - chrono::Duration::seconds(1);
        }
        assert!(stub.get_cert().is_none());
        assert_eq!(installed_fingerprint(&stub), fingerprint);
        // Unusable on disk.
        let key = stub
            .inner
            .identity_roots
            .x509_paths("example.com", IdentityUsage::Server)
            .unwrap()
            .private_key;
        std::fs::write(key, "broken").unwrap();
        assert_eq!(stub.refresh_cert().unwrap(), CertCheck::Manual);
        assert!(stub.get_cert().is_none());
        tokio::time::sleep(MANUAL_CHECK_INTERVAL * 5).await;
        assert_eq!(stub.status().state, AcmeCertState::Manual);
        assert_eq!(server.orders(), 0);

        // Other hosts of the same manager are not affected.
        manager
            .add_acme_item(AcmeItem::new(
                "*.example.com".to_string(),
                ChallengeType::Http01,
                None,
            ))
            .unwrap();
        let wildcard = manager.get_cert_by_host("*.example.com").unwrap();
        wait_until(|| wildcard.get_cert().is_some()).await;
        assert_eq!(wildcard.status().state, AcmeCertState::Ready);
        assert_eq!(server.orders(), 1);
        stub.cancel_load();
    }

    #[tokio::test]
    async fn clearing_the_manual_mark_lets_acme_issue() {
        let temp = tempfile::tempdir().unwrap();
        let server = MockAcme::new().await;
        server.order_gate.add_permits(100);
        let manager = AcmeCertManager::create(test_config(temp.path(), &server))
            .await
            .unwrap();
        let stub = test_stub(&manager, "example.com");
        // Valid far beyond the renewal window.
        install_manual(&stub, 3650);
        let manual = installed_fingerprint(&stub);
        stub.load_cert();
        wait_until(|| stub.status().state == AcmeCertState::Manual).await;
        assert_eq!(server.orders(), 0);

        clear_manual_mark(&stub.inner.identity_roots, "example.com").unwrap();
        wait_until(|| installed_fingerprint(&stub) != manual).await;
        wait_until(|| stub.status().state == AcmeCertState::Ready).await;
        assert_eq!(
            stub.status().installed.unwrap().manager,
            Some(CertManager::Acme)
        );
        stub.start_order().await.unwrap();
        assert_eq!(server.orders(), 1, "issued once, not on every check");
    }

    #[tokio::test]
    async fn an_upload_during_an_order_is_not_overwritten() {
        let temp = tempfile::tempdir().unwrap();
        let server = MockAcme::new().await;
        let manager = AcmeCertManager::create(test_config(temp.path(), &server))
            .await
            .unwrap();
        let stub = test_stub(&manager, "example.com");
        stub.load_cert();
        wait_until(|| server.orders() == 1).await;
        assert_eq!(stub.status().state, AcmeCertState::Ordering);
        install_manual(&stub, 90);
        let manual = installed_fingerprint(&stub);
        assert_eq!(stub.status().state, AcmeCertState::Manual);
        server.order_gate.add_permits(100);
        wait_until(|| stub.inner.order_lock.try_lock().is_ok()).await;
        tokio::time::sleep(MANUAL_CHECK_INTERVAL * 5).await;
        assert_eq!(installed_fingerprint(&stub), manual);
        assert_eq!(server.orders(), 1);
        stub.cancel_load();
    }

    #[tokio::test]
    async fn status_keeps_the_last_error_until_a_certificate_is_there() {
        let temp = tempfile::tempdir().unwrap();
        let server = MockAcme::new().await;
        server.state.fail_orders.store(true, Ordering::SeqCst);
        server.order_gate.add_permits(100);
        let manager = AcmeCertManager::create(test_config(temp.path(), &server))
            .await
            .unwrap();
        manager
            .add_acme_item(AcmeItem::new(
                "example.com".to_string(),
                ChallengeType::Http01,
                None,
            ))
            .unwrap();
        let status = || manager.cert_statuses().remove(0);
        wait_until(|| status().last_error.is_some()).await;
        let failed = status();
        assert_eq!(failed.state, AcmeCertState::Ordering);
        assert!(
            failed
                .last_error
                .as_ref()
                .unwrap()
                .message
                .contains("test issuance limit"),
            "{failed:?}"
        );
        let wait = failed.next_retry_at.unwrap() - failed.last_error.unwrap().at;
        assert!((3600..=3601).contains(&wait), "Retry-After is honored");
        assert!(failed.installed.is_none());

        let stub = manager.get_cert_by_host("example.com").unwrap();
        stub.cancel_load();
        assert_eq!(status().state, AcmeCertState::None);
        server.state.fail_orders.store(false, Ordering::SeqCst);
        stub.load_cert();
        wait_until(|| status().state == AcmeCertState::Ready).await;
        let ready = status();
        assert_eq!((ready.last_error, ready.next_retry_at), (None, None));
        assert_eq!(ready.installed.unwrap().manager, Some(CertManager::Acme));
    }

    #[test]
    fn being_offline_and_limits_that_pass_are_no_refusals() {
        let http = |status: u16| -> anyhow::Error {
            AcmeHttpError::of(reqwest::StatusCode::from_u16(status).unwrap()).into()
        };
        for status in [429, 500, 503] {
            assert!(!CertStub::counts_as_refused(&http(status)), "{status}");
        }
        for status in [400, 403] {
            assert!(CertStub::counts_as_refused(&http(status)), "{status}");
        }
        assert!(CertStub::counts_as_refused(&anyhow::anyhow!(
            "Authorization failed: no TXT record"
        )));
    }

    #[tokio::test]
    async fn an_unreachable_server_is_no_refusal() {
        let closed = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let error = reqwest::get(format!("http://{closed}/")).await.unwrap_err();
        let error = anyhow::Error::new(error).context("get acme directory failed");
        assert!(!CertStub::counts_as_refused(&error));
    }

    #[tokio::test]
    async fn refused_too_often_it_stops_until_it_is_asked_to_go_on() {
        let temp = tempfile::tempdir().unwrap();
        let server = MockAcme::new().await;
        server.state.refuse_orders.store(true, Ordering::SeqCst);
        server.order_gate.add_permits(1000);
        let config = test_config(temp.path(), &server);
        let item = || AcmeItem::new("example.com".to_string(), ChallengeType::Http01, None);
        let manager = AcmeCertManager::create(config.clone()).await.unwrap();
        manager.add_acme_item(item()).unwrap();
        let status = |manager: &AcmeCertManagerRef| manager.cert_statuses().remove(0);
        wait_until(|| status(&manager).last_error.is_some()).await;
        assert_eq!(status(&manager).state, AcmeCertState::Ordering);
        assert!(status(&manager).next_retry_at.is_some());
        let stub = manager.get_cert_by_host("example.com").unwrap();
        {
            let mut mut_part = stub.inner.mut_part.lock().unwrap();
            assert_eq!(mut_part.refused_orders, 1);
            mut_part.refused_orders = MAX_REFUSED_ORDERS - 1;
        }
        // One more attempt, now.
        stub.inner.restart.notify_one();
        wait_until(|| status(&manager).state == AcmeCertState::Stopped).await;
        assert_eq!(status(&manager).next_retry_at, None);
        assert!(status(&manager).last_error.is_some());
        let orders = server.orders();
        tokio::time::sleep(MANUAL_CHECK_INTERVAL * 5).await;
        manager.check_all_certs().unwrap();
        tokio::time::sleep(MANUAL_CHECK_INTERVAL * 5).await;
        assert_eq!(server.orders(), orders, "no periodic check goes on");

        // Neither does a restart of the gateway.
        drop(stub);
        drop(manager);
        let manager = AcmeCertManager::create(config).await.unwrap();
        manager.add_acme_item(item()).unwrap();
        tokio::time::sleep(MANUAL_CHECK_INTERVAL * 5).await;
        assert_eq!(status(&manager).state, AcmeCertState::Stopped);
        assert!(status(&manager).last_error.is_some());
        assert_eq!(server.orders(), orders);

        assert!(!manager.restart_cert("other.example"));
        server.state.refuse_orders.store(false, Ordering::SeqCst);
        assert!(manager.restart_cert("Example.com"));
        wait_until(|| status(&manager).state == AcmeCertState::Ready).await;
        assert!(status(&manager).last_error.is_none());
        let left = Path::new(&manager.config.keystore_path)
            .join("example.com")
            .join(REFUSED_ORDERS_FILE);
        assert!(!left.exists());
    }

    #[tokio::test]
    async fn an_uploaded_certificate_ends_the_stop() {
        let temp = tempfile::tempdir().unwrap();
        let server = MockAcme::new().await;
        server.state.refuse_orders.store(true, Ordering::SeqCst);
        server.order_gate.add_permits(100);
        let manager = AcmeCertManager::create(test_config(temp.path(), &server))
            .await
            .unwrap();
        let stub = test_stub(&manager, "example.com");
        stub.inner.mut_part.lock().unwrap().refused_orders = MAX_REFUSED_ORDERS;
        stub.load_cert();
        tokio::time::sleep(MANUAL_CHECK_INTERVAL * 3).await;
        assert_eq!(stub.status().state, AcmeCertState::Stopped);
        assert_eq!(server.orders(), 0);
        install_test_cert(&stub, 90);
        wait_until(|| stub.status().state == AcmeCertState::Ready).await;
        assert_eq!(stub.inner.mut_part.lock().unwrap().refused_orders, 0);
    }

    #[tokio::test]
    async fn issuing_in_the_background_is_awaited() {
        let temp = tempfile::tempdir().unwrap();
        let server = MockAcme::new().await;
        server.state.issue_later.store(true, Ordering::SeqCst);
        server.order_gate.add_permits(100);
        let manager = AcmeCertManager::create(test_config(temp.path(), &server))
            .await
            .unwrap();
        let stub = test_stub(&manager, "example.com");
        stub.start_order().await.unwrap();
        assert!(stub.get_cert().is_some());
        assert_eq!(server.orders(), 1);
    }

    /// Records by name, changed value by value.
    #[derive(Default)]
    struct FakeDns {
        records: Mutex<HashMap<String, Vec<String>>>,
        propagates: std::sync::atomic::AtomicBool,
    }

    impl FakeDns {
        fn values(&self, name: &str) -> Vec<String> {
            self.records
                .lock()
                .unwrap()
                .get(name)
                .cloned()
                .unwrap_or_default()
        }
    }

    struct FakeDnsFactory(Arc<FakeDns>);

    #[async_trait::async_trait]
    impl DnsProviderFactory for FakeDnsFactory {
        async fn create(
            &self,
            _acme_mgr: Weak<AcmeCertManager>,
            _params: serde_json::Value,
        ) -> Result<DnsProviderRef> {
            let dns = self.0.clone();
            Ok(Arc::new(
                move |op: String, domain: String, value: String| {
                    let dns = dns.clone();
                    async move {
                        let mut records = dns.records.lock().unwrap();
                        let values = records.entry(domain).or_default();
                        match op.as_str() {
                            "add_challenge" => values.push(value),
                            "del_challenge" => values.retain(|known| *known != value),
                            _ => return Err(anyhow::anyhow!("unexpected operation {op}")),
                        }
                        Ok(())
                    }
                },
            ))
        }

        async fn wait_propagation(&self, domain: &str, key_hash: &str) -> Result<()> {
            assert!(self.0.values(domain).iter().any(|value| value == key_hash));
            if self.0.propagates.load(Ordering::SeqCst) {
                Ok(())
            } else {
                Err(anyhow::anyhow!("{domain} is not visible in time"))
            }
        }
    }

    async fn dns_manager(
        temp: &Path,
        server: &MockAcme,
        provider: &str,
        dns: &Arc<FakeDns>,
    ) -> AcmeCertManagerRef {
        server.state.dns_challenges.store(true, Ordering::SeqCst);
        server.order_gate.add_permits(100);
        AcmeCertManager::register_dns_provider_factory(
            provider,
            Arc::new(FakeDnsFactory(dns.clone())),
        );
        let mut config = test_config(temp, server);
        config.dns_providers = Some(HashMap::from([(
            provider.to_string(),
            serde_json::json!({}),
        )]));
        let manager = AcmeCertManager::create(config).await.unwrap();
        for domain in ["example.com", "*.example.com"] {
            manager
                .add_acme_item(AcmeItem::new(
                    domain.to_string(),
                    ChallengeType::Dns01,
                    Some(serde_json::json!({ "dns_provider": provider })),
                ))
                .unwrap();
        }
        manager
    }

    #[tokio::test]
    async fn two_hosts_share_a_challenge_name_without_overwriting() {
        const NAME: &str = "_acme-challenge.example.com";
        let temp = tempfile::tempdir().unwrap();
        let server = MockAcme::new().await;
        let dns = Arc::new(FakeDns::default());
        dns.propagates.store(true, Ordering::SeqCst);
        let manager = dns_manager(temp.path(), &server, "test-shared-name", &dns).await;

        wait_until(|| server.validations_waiting() == 2).await;
        let values = dns.values(NAME);
        assert_eq!(values.len(), 2);
        assert_ne!(values[0], values[1]);

        // The first to finish takes only its own value away.
        server.validation_gate.add_permits(1);
        wait_until(|| dns.values(NAME).len() == 1).await;
        assert!(values.contains(&dns.values(NAME)[0]));
        server.validation_gate.add_permits(1);
        wait_until(|| dns.values(NAME).is_empty()).await;
        for domain in ["example.com", "*.example.com"] {
            let stub = manager.get_cert_by_host(domain).unwrap();
            wait_until(|| stub.status().state == AcmeCertState::Ready).await;
            assert_eq!(
                stub.status().installed.unwrap().dns_names,
                vec![domain.to_string()]
            );
        }
        assert_eq!(server.orders(), 2);
    }

    #[tokio::test]
    async fn propagation_timeout_fails_the_order_and_removes_the_challenge() {
        let temp = tempfile::tempdir().unwrap();
        let server = MockAcme::new().await;
        let dns = Arc::new(FakeDns::default());
        let manager = dns_manager(temp.path(), &server, "test-timeout", &dns).await;

        wait_until(|| {
            manager
                .cert_statuses()
                .iter()
                .all(|status| status.last_error.is_some())
        })
        .await;
        for status in manager.cert_statuses() {
            assert_eq!(status.state, AcmeCertState::Ordering);
            assert!(
                status
                    .last_error
                    .as_ref()
                    .unwrap()
                    .message
                    .contains("_acme-challenge.example.com is not visible in time")
            );
            assert!(status.next_retry_at.unwrap() > status.last_error.unwrap().at);
        }
        wait_until(|| dns.values("_acme-challenge.example.com").is_empty()).await;
        assert_eq!(server.validations_waiting(), 0, "the CA was never asked");
    }

    /// Keeps the TXT values of pebble's challenge test server, which can only set or
    /// clear a whole name.
    struct ChallengeServerDns {
        url: String,
        records: tokio::sync::Mutex<HashMap<String, Vec<String>>>,
        most_values: std::sync::atomic::AtomicUsize,
    }

    impl ChallengeServerDns {
        async fn change(&self, op: &str, name: &str, value: &str) -> Result<()> {
            let client = reqwest::Client::new();
            let mut records = self.records.lock().await;
            let values = records.entry(name.to_string()).or_default();
            match op {
                "add_challenge" => values.push(value.to_string()),
                _ => values.retain(|known| known != value),
            }
            self.most_values.fetch_max(values.len(), Ordering::SeqCst);
            let host = format!("{name}.");
            client
                .post(format!("{}/clear-txt", self.url))
                .json(&serde_json::json!({ "host": host }))
                .send()
                .await?
                .error_for_status()?;
            for value in values {
                client
                    .post(format!("{}/set-txt", self.url))
                    .json(&serde_json::json!({ "host": host, "value": value }))
                    .send()
                    .await?
                    .error_for_status()?;
            }
            Ok(())
        }
    }

    struct ChallengeServerFactory(Arc<ChallengeServerDns>);

    #[async_trait::async_trait]
    impl DnsProviderFactory for ChallengeServerFactory {
        async fn create(
            &self,
            _acme_mgr: Weak<AcmeCertManager>,
            _params: serde_json::Value,
        ) -> Result<DnsProviderRef> {
            let dns = self.0.clone();
            Ok(Arc::new(
                move |op: String, domain: String, value: String| {
                    let dns = dns.clone();
                    async move { dns.change(&op, &domain, &value).await }
                },
            ))
        }

        // Both orders have written their challenge before either is checked.
        async fn wait_propagation(&self, domain: &str, _key_hash: &str) -> Result<()> {
            for _ in 0..500 {
                if self.0.most_values.load(Ordering::SeqCst) == 2 {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Err(anyhow::anyhow!("{domain} has one value only"))
        }
    }

    /// Against a real ACME server:
    /// `pebble-challtestsrv -doh "" -http01 "" -https01 "" -tlsalpn01 "" -dnsserver :8053`,
    /// `pebble -config … -dnsserver 127.0.0.1:8053`, then
    /// `SSL_CERT_FILE=<ca of pebble> PEBBLE_DIRECTORY=https://localhost:14000/dir
    /// PEBBLE_CHALLTESTSRV=http://127.0.0.1:8055 cargo test -p cyfs-acme pebble -- --ignored`.
    #[tokio::test]
    #[ignore]
    async fn pebble_issues_two_hosts_with_one_challenge_name() {
        const PROVIDER: &str = "test-pebble";
        let temp = tempfile::tempdir().unwrap();
        let dns = Arc::new(ChallengeServerDns {
            url: std::env::var("PEBBLE_CHALLTESTSRV").unwrap(),
            records: Default::default(),
            most_values: Default::default(),
        });
        AcmeCertManager::register_dns_provider_factory(
            PROVIDER,
            Arc::new(ChallengeServerFactory(dns.clone())),
        );
        let manager = AcmeCertManager::create(CertManagerConfig {
            account: Some("test@example.org".to_string()),
            acme_server: std::env::var("PEBBLE_DIRECTORY").unwrap(),
            keystore_path: temp.path().join("acme").to_string_lossy().into_owned(),
            dns_providers: Some(HashMap::from([(
                PROVIDER.to_string(),
                serde_json::json!({}),
            )])),
            identity_manager: Some(AcmeIdentityConfig {
                public_root_path: Some(temp.path().join("identity").to_string_lossy().into_owned()),
                security_root_path: Some(
                    temp.path().join("security").to_string_lossy().into_owned(),
                ),
            }),
            ..CertManagerConfig::default()
        })
        .await
        .unwrap();
        let domains = ["home.pebble-test.org", "*.home.pebble-test.org"];
        for domain in domains {
            manager
                .add_acme_item(AcmeItem::new(
                    domain.to_string(),
                    ChallengeType::Dns01,
                    Some(serde_json::json!({ "dns_provider": PROVIDER })),
                ))
                .unwrap();
        }
        for _ in 0..600 {
            let statuses = manager.cert_statuses();
            if let Some(error) = statuses.iter().find_map(|s| s.last_error.clone()) {
                panic!("{}", error.message);
            }
            if statuses.iter().all(|s| s.state == AcmeCertState::Ready) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        for domain in domains {
            let status = manager.get_cert_by_host(domain).unwrap().status();
            assert_eq!(status.state, AcmeCertState::Ready, "{status:?}");
            assert_eq!(
                status.installed.unwrap().dns_names,
                vec![domain.to_string()]
            );
        }
        for _ in 0..100 {
            if dns.records.lock().await.values().all(Vec::is_empty) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("challenges left behind");
    }

    fn generate_test_cert(domain: &str, valid_days: u32) -> (Vec<u8>, Vec<u8>) {
        let now = chrono::Utc::now();
        generate_test_cert_between(domain, now, now + chrono::Duration::days(valid_days.into()))
    }

    fn generate_test_cert_between(
        domain: &str,
        not_before: chrono::DateTime<chrono::Utc>,
        not_after: chrono::DateTime<chrono::Utc>,
    ) -> (Vec<u8>, Vec<u8>) {
        let rsa = openssl::rsa::Rsa::generate(2048).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();
        let mut builder = X509Builder::new().unwrap();
        builder.set_version(2).unwrap();

        let serial = BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap();
        builder.set_serial_number(&serial).unwrap();

        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", domain).unwrap();
        let name = name.build();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&pkey).unwrap();

        let not_before = Asn1Time::from_unix(not_before.timestamp()).unwrap();
        let not_after = Asn1Time::from_unix(not_after.timestamp()).unwrap();
        builder.set_not_before(&not_before).unwrap();
        builder.set_not_after(&not_after).unwrap();

        let san = SubjectAlternativeName::new()
            .dns(domain)
            .build(&builder.x509v3_context(None, None))
            .unwrap();
        builder.append_extension(san).unwrap();
        builder.sign(&pkey, MessageDigest::sha256()).unwrap();

        let cert = builder.build().to_pem().unwrap();
        let key = pkey.private_key_to_pem_pkcs8().unwrap();
        (cert, key)
    }
}
