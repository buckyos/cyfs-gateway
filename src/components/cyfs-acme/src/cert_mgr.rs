use crate::acme_client::{
    AcmeAccount, AcmeChallengeResponderRef, AcmeClient, AcmeHttpError, AcmeOrderSession,
};
use crate::default_challenge_responder::DefaultChallengeResponder;
use crate::{Challenge, ChallengeData, ChallengeType};
use anyhow::Result;
use log::*;
use name_client::{
    IdentityMaterial, IdentityRoots, IdentityUsage, X509_METADATA_SCHEMA, X509CertificateMetadata,
    X509MatchMetadata, X509Metadata, X509PathMetadata, X509SanMetadata,
};
use openssl::asn1::Asn1TimeRef;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::x509::{X509, X509NameRef};
use rand::Rng;
use rustls::crypto::ring::sign::any_supported_type;
use rustls::pki_types::PrivateKeyDer;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign;
use rustls::sign::CertifiedKey;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sfo_js::{JsPkgManager, JsPkgManagerRef, JsString, JsValue};
use sha2::Digest;
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::fs::OpenOptions;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::RwLock;
use std::sync::{Arc, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::fs;
use tokio::task;
use tokio::task::JoinHandle;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

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
}

enum CertState {
    None,
    Ready(CertInfo),
    Renewing(CertInfo),
}

struct CertMutPart {
    state: CertState,
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
    renew_before_expiry: chrono::Duration,
    order_lock: Arc<tokio::sync::Mutex<()>>,
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
        renew_before_expiry: chrono::Duration,
    ) -> Self {
        Self {
            inner: Arc::new(CertStubInner {
                order_lock: cert_order_lock(&acme_item.domain),
                acme_item,
                work_dir,
                identity_roots,
                acme_client,
                responder,
                renew_before_expiry,
                mut_part: Mutex::new(CertMutPart {
                    state: CertState::None,
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
            CertState::Ready(info) | CertState::Renewing(info)
                if chrono::Utc::now() < info.expires =>
            {
                Some(info.key.clone())
            }
            _ => None,
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

    // Returns true when a new order is needed. Re-read under order_lock before
    // ordering: another manager may have installed a certificate while we waited.
    fn refresh_cert(&self) -> Result<bool> {
        if let Some(info) = self.load_identity_cert_info()? {
            let should_renew = Self::cert_needs_renewal(&info, self.inner.renew_before_expiry);
            {
                let mut mut_part = self.inner.mut_part.lock().unwrap();
                mut_part.state = if should_renew {
                    CertState::Renewing(info)
                } else {
                    CertState::Ready(info)
                };
            }
            return Ok(should_renew);
        }

        self.inner.mut_part.lock().unwrap().state = CertState::None;
        Ok(true)
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
        let certified_key = match Self::create_certified_key(&cert_data, &key_data) {
            Ok(certified_key) => certified_key,
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
        let expires = match Self::get_cert_expiry(&cert_data) {
            Ok(expires) => expires,
            Err(e) => {
                debug!(
                    "read identity certificate expiry failed, stub: {}, fullchain: {}, {}",
                    self,
                    cert_match.path.display(),
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
            expires
        );
        Ok(Some(CertInfo {
            key: Arc::new(certified_key),
            expires,
        }))
    }

    fn cert_needs_renewal(info: &CertInfo, renew_before_expiry: chrono::Duration) -> bool {
        let now = chrono::Utc::now();
        now >= info.expires || now >= info.expires - renew_before_expiry
    }

    async fn order_inner(&self, issued_cert: &mut Option<(Vec<u8>, Vec<u8>)>) -> Result<()> {
        if issued_cert.is_none() {
            let mut order = AcmeOrderSession::new(
                self.inner.acme_item.domain.clone(),
                self.inner.acme_client.clone(),
                self.inner.responder.clone(),
            );
            *issued_cert = Some(order.start().await?);
        }
        // An installation failure must retry the downloaded certificate, not
        // consume another issuance for the same identifiers.
        let (cert_data, key_data) = issued_cert.as_ref().unwrap();

        install_identity_certificate(
            &self.inner.identity_roots,
            self.inner.acme_item.identity(),
            &self.inner.acme_item.domain,
            &self.inner.work_dir,
            cert_data,
            key_data,
            self.inner.renew_before_expiry,
        )?;

        let certified_key = Self::create_certified_key(cert_data, key_data)?;
        let expires = Self::get_cert_expiry(cert_data)?;

        info!(
            "install identity cert success, stub: {}, identity: {}, expires: {}",
            self,
            self.inner.acme_item.identity(),
            expires
        );

        {
            let mut mut_part = self.inner.mut_part.lock().unwrap();
            mut_part.state = CertState::Ready(CertInfo {
                key: Arc::new(certified_key),
                expires,
            });
        }

        Ok(())
    }

    async fn start_order(&self) -> Result<()> {
        // Make an existing certificate available even while another manager is
        // renewing it and holds the order lock.
        if !self.refresh_cert()? {
            return Ok(());
        }
        let _order_guard = self.inner.order_lock.lock().await;
        let mut interval = 15;
        let mut issued_cert = None;
        loop {
            if !self.refresh_cert()? {
                return Ok(());
            }
            let result = self.order_inner(&mut issued_cert).await;

            match result {
                Ok(()) => {
                    break Ok(());
                }
                Err(e) => {
                    interval *= 2;
                    if interval > 600 {
                        interval = 600;
                    }
                    let retry_delay = e
                        .downcast_ref::<AcmeHttpError>()
                        .and_then(|error| error.retry_after)
                        .unwrap_or_default()
                        .max(Duration::from_secs(interval));
                    error!(
                        "order cert failed, stub: {}, {:#}; retry in {:?}",
                        self, e, retry_delay
                    );
                    if self.wait_for_retry(retry_delay).await? {
                        return Ok(());
                    }
                }
            }
        }
    }

    // Return true if an externally installed certificate ends the retry loop.
    async fn wait_for_retry(&self, retry_delay: Duration) -> Result<bool> {
        let retry_at = tokio::time::Instant::now() + retry_delay;
        loop {
            tokio::time::sleep_until(
                retry_at.min(tokio::time::Instant::now() + Duration::from_secs(60)),
            )
            .await;
            if !self.refresh_cert()? {
                return Ok(true);
            }
            if tokio::time::Instant::now() >= retry_at {
                return Ok(false);
            }
        }
    }

    fn cancel_load(&self) {
        if let Some(handle) = self.inner.handle.lock().unwrap().take() {
            handle.abort();
        }
    }
}

struct PreparedIdentityCertificate {
    cert_pem: Vec<u8>,
    chain_pem: Vec<u8>,
    fullchain_pem: Vec<u8>,
    key_pem: Vec<u8>,
    metadata_json: Vec<u8>,
}

struct StagedFile {
    tmp_path: PathBuf,
    final_path: PathBuf,
}

fn install_identity_certificate(
    roots: &IdentityRoots,
    identity: &str,
    domain: &str,
    work_dir: &Path,
    fullchain_pem: &[u8],
    key_pem: &[u8],
    renew_before_expiry: chrono::Duration,
) -> Result<()> {
    let prepared = prepare_identity_certificate(
        roots,
        identity,
        domain,
        work_dir,
        fullchain_pem,
        key_pem,
        renew_before_expiry,
    )?;
    let paths = roots
        .x509_paths(identity, IdentityUsage::Server)
        .map_err(|e| anyhow::anyhow!("calculate identity x509 paths failed: {}", e))?;
    let private_key_path = &paths.private_key;

    let mut staged = Vec::new();
    let stage_result = (|| -> Result<()> {
        staged.push(stage_file(&paths.cert, &prepared.cert_pem, false)?);
        staged.push(stage_file(&paths.chain, &prepared.chain_pem, false)?);
        staged.push(stage_file(
            &paths.fullchain,
            &prepared.fullchain_pem,
            false,
        )?);
        staged.push(stage_file(&paths.metadata, &prepared.metadata_json, false)?);
        staged.push(stage_file(private_key_path, &prepared.key_pem, true)?);
        Ok(())
    })();

    if let Err(err) = stage_result {
        cleanup_staged_files(&staged);
        return Err(err);
    }

    for staged_file in staged.iter() {
        std::fs::rename(&staged_file.tmp_path, &staged_file.final_path).map_err(|e| {
            anyhow::anyhow!(
                "rename staged identity file {} to {} failed: {}",
                staged_file.tmp_path.display(),
                staged_file.final_path.display(),
                e
            )
        })?;
    }

    if let Some(keyref_path) = paths.keyref.as_deref() {
        remove_legacy_keyref(keyref_path)?;
    }
    sync_parent_dir(&paths.fullchain)?;
    sync_parent_dir(private_key_path)?;
    Ok(())
}

fn prepare_identity_certificate(
    roots: &IdentityRoots,
    identity: &str,
    domain: &str,
    work_dir: &Path,
    fullchain_pem: &[u8],
    key_pem: &[u8],
    renew_before_expiry: chrono::Duration,
) -> Result<PreparedIdentityCertificate> {
    std::fs::create_dir_all(work_dir).map_err(|e| {
        anyhow::anyhow!("create acme work dir {} failed: {}", work_dir.display(), e)
    })?;

    let certificates = X509::stack_from_pem(fullchain_pem)
        .map_err(|e| anyhow::anyhow!("parse acme certificate chain failed: {}", e))?;
    let leaf = certificates
        .first()
        .ok_or_else(|| anyhow::anyhow!("acme certificate chain is empty"))?;
    let private_key = PKey::private_key_from_pem(key_pem)
        .map_err(|e| anyhow::anyhow!("parse acme private key failed: {}", e))?;
    validate_identity_certificate(roots, identity, domain, leaf, &private_key)?;

    let cert_pem = leaf.to_pem()?;
    let mut chain_pem = Vec::new();
    for cert in certificates.iter().skip(1) {
        chain_pem.extend(cert.to_pem()?);
    }
    let mut normalized_fullchain = cert_pem.clone();
    normalized_fullchain.extend(chain_pem.iter());

    let public_key_fingerprint = public_key_fingerprint(leaf)?;
    let raw_host_uri = roots
        .raw_host_uri(identity)
        .map_err(|e| anyhow::anyhow!("calculate raw host uri failed: {}", e))?;
    let dir_name = roots
        .dir_name(identity)
        .map_err(|e| anyhow::anyhow!("calculate identity dir name failed: {}", e))?;
    let did = canonical_did(identity, &raw_host_uri);
    let updated_at = chrono::Utc::now().to_rfc3339();

    let metadata = build_x509_metadata(
        roots,
        identity,
        domain,
        leaf,
        &did,
        raw_host_uri,
        dir_name,
        public_key_fingerprint,
        work_dir,
        renew_before_expiry,
        updated_at,
    )?;

    Ok(PreparedIdentityCertificate {
        cert_pem,
        chain_pem,
        fullchain_pem: normalized_fullchain,
        key_pem: key_pem.to_vec(),
        metadata_json: serde_json::to_vec_pretty(&metadata)?,
    })
}

fn validate_identity_certificate(
    roots: &IdentityRoots,
    identity: &str,
    domain: &str,
    cert: &X509,
    private_key: &PKey<Private>,
) -> Result<()> {
    let now = chrono::Utc::now();
    let not_before = asn1_time_to_utc(cert.not_before())?;
    let not_after = asn1_time_to_utc(cert.not_after())?;
    if now < not_before {
        return Err(anyhow::anyhow!(
            "acme certificate is not valid yet: {}",
            not_before
        ));
    }
    if now >= not_after {
        return Err(anyhow::anyhow!(
            "acme certificate is expired: {}",
            not_after
        ));
    }

    let cert_public_key = cert.public_key()?;
    if !cert_public_key.public_eq(private_key) {
        return Err(anyhow::anyhow!(
            "acme certificate public key does not match private key"
        ));
    }

    let dns_names = cert_dns_names(cert);
    let expected_dns = roots
        .did_web_dns_san(identity)
        .unwrap_or_else(|_| domain.to_string());
    if !dns_names
        .iter()
        .any(|dns_name| dns_san_matches(dns_name, &expected_dns))
    {
        return Err(anyhow::anyhow!(
            "acme certificate DNS SAN does not cover identity host: expected {}, got {:?}",
            expected_dns,
            dns_names
        ));
    }

    Ok(())
}

fn build_x509_metadata(
    roots: &IdentityRoots,
    identity: &str,
    domain: &str,
    cert: &X509,
    did: &str,
    raw_host_uri: String,
    dir_name: String,
    public_key_fingerprint: String,
    work_dir: &Path,
    renew_before_expiry: chrono::Duration,
    updated_at: String,
) -> Result<X509Metadata> {
    let not_before = asn1_time_to_utc(cert.not_before())?.to_rfc3339();
    let not_after = asn1_time_to_utc(cert.not_after())?.to_rfc3339();
    let serial_number = cert
        .serial_number()
        .to_bn()
        .and_then(|bn| bn.to_hex_str())
        .map(|s| s.to_string())
        .ok();
    let match_info = if domain.starts_with("*.") {
        X509MatchMetadata::Wildcard {
            host_pattern: domain.to_string(),
        }
    } else {
        X509MatchMetadata::Exact {
            host: domain.to_string(),
        }
    };
    let generation = format!(
        "{}-{}",
        chrono::Utc::now().format("%Y%m%dT%H%M%SZ"),
        cert_fingerprint_sha256(cert)?
    );

    Ok(X509Metadata {
        schema: Some(X509_METADATA_SCHEMA.to_string()),
        did: did.to_string(),
        raw_host_uri,
        dir_name,
        usage: IdentityUsage::Server,
        match_info: Some(match_info),
        certificate: Some(X509CertificateMetadata {
            serial_number,
            issuer: Some(x509_name_to_string(cert.issuer_name())),
            subject: Some(x509_name_to_string(cert.subject_name())),
            not_before: Some(not_before),
            not_after,
            fingerprint_sha256: Some(cert_fingerprint_sha256(cert)?),
            public_key_fingerprint: Some(public_key_fingerprint),
        }),
        san: Some(X509SanMetadata {
            dns: cert_dns_names(cert),
            uri: cert_uri_names(cert),
        }),
        paths: Some(X509PathMetadata {
            cert: Some("server.cert.pem".to_string()),
            chain: Some("server.chain.pem".to_string()),
            fullchain: Some("server.fullchain.pem".to_string()),
            ca: None,
            key_ref: None,
        }),
        did_binding: roots
            .did_web_document_url(identity)
            .ok()
            .map(|did_document_url| {
                serde_json::json!({
                    "type": "did-web-domain",
                    "did": did,
                    "web_origin": format!("https://{}", domain.trim_start_matches("*.")),
                    "did_document_url": did_document_url
                })
            }),
        renewal: Some(serde_json::json!({
            "manager": "acme",
            "renew_before": format!("PT{}S", renew_before_expiry.num_seconds()),
            "last_renewed_at": updated_at,
            "state_ref": work_dir.to_string_lossy()
        })),
        updated_at: Some(updated_at),
        generation: Some(generation),
    })
}

fn cert_dns_names(cert: &X509) -> Vec<String> {
    cert.subject_alt_names()
        .map(|names| {
            names
                .iter()
                .filter_map(|name| name.dnsname().map(ToOwned::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

fn cert_uri_names(cert: &X509) -> Vec<String> {
    cert.subject_alt_names()
        .map(|names| {
            names
                .iter()
                .filter_map(|name| name.uri().map(ToOwned::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

fn dns_san_matches(pattern: &str, host: &str) -> bool {
    if pattern.eq_ignore_ascii_case(host) {
        return true;
    }

    let Some(suffix) = pattern.strip_prefix("*.") else {
        return false;
    };
    let host = host.to_ascii_lowercase();
    let suffix = suffix.to_ascii_lowercase();
    if host == suffix || !host.ends_with(&suffix) {
        return false;
    }
    let prefix_len = host.len() - suffix.len();
    prefix_len > 1
        && host.as_bytes()[prefix_len - 1] == b'.'
        && !host[..prefix_len - 1].contains('.')
}

fn cert_fingerprint_sha256(cert: &X509) -> Result<String> {
    let digest = cert.digest(MessageDigest::sha256())?;
    Ok(format!("sha256:{}", hex::encode(digest)))
}

fn public_key_fingerprint(cert: &X509) -> Result<String> {
    let public_key = cert.public_key()?;
    let der = public_key.public_key_to_der()?;
    Ok(format!(
        "sha256:{}",
        hex::encode(sha2::Sha256::digest(&der))
    ))
}

fn asn1_time_to_utc(time: &Asn1TimeRef) -> Result<chrono::DateTime<chrono::Utc>> {
    let raw = time.to_string();
    let datetime_str = raw
        .rsplit_once(' ')
        .map(|(datetime, _)| datetime)
        .ok_or_else(|| anyhow::anyhow!("Invalid ASN.1 datetime format: {}", raw))?;
    let expires = chrono::NaiveDateTime::parse_from_str(datetime_str, "%b %e %H:%M:%S %Y")?;
    Ok(chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(
        expires,
        chrono::Utc,
    ))
}

fn x509_name_to_string(name: &X509NameRef) -> String {
    name.entries()
        .map(|entry| {
            let key = entry.object().nid().short_name().unwrap_or("OID");
            let value = entry
                .data()
                .to_string()
                .unwrap_or_else(|_| hex::encode(entry.data().as_slice()));
            format!("{key}={value}")
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn canonical_did(identity: &str, raw_host_uri: &str) -> String {
    if identity.trim().starts_with("did:") {
        identity.trim().to_string()
    } else {
        let host_uri = raw_host_uri.replace('/', ":");
        format!("did:web:{host_uri}")
    }
}

fn stage_file(path: &Path, data: &[u8], private: bool) -> Result<StagedFile> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("identity file path has no parent: {}", path.display()))?;
    std::fs::create_dir_all(parent)
        .map_err(|e| anyhow::anyhow!("create identity dir {} failed: {}", parent.display(), e))?;

    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("identity file path has no file name: {}", path.display()))?
        .to_string_lossy();
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let tmp_path = parent.join(format!(".{file_name}.{unique}.tmp"));

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        options.mode(if private { 0o600 } else { 0o644 });
    }
    let mut file = options.open(&tmp_path).map_err(|e| {
        anyhow::anyhow!(
            "create temp identity file {} failed: {}",
            tmp_path.display(),
            e
        )
    })?;
    file.write_all(data).map_err(|e| {
        anyhow::anyhow!(
            "write temp identity file {} failed: {}",
            tmp_path.display(),
            e
        )
    })?;
    file.sync_all().map_err(|e| {
        anyhow::anyhow!(
            "sync temp identity file {} failed: {}",
            tmp_path.display(),
            e
        )
    })?;

    Ok(StagedFile {
        tmp_path,
        final_path: path.to_path_buf(),
    })
}

fn cleanup_staged_files(staged: &[StagedFile]) {
    for staged_file in staged {
        let _ = std::fs::remove_file(&staged_file.tmp_path);
    }
}

fn sync_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        let dir = std::fs::File::open(parent)
            .map_err(|e| anyhow::anyhow!("open identity dir {} failed: {}", parent.display(), e))?;
        dir.sync_all()
            .map_err(|e| anyhow::anyhow!("sync identity dir {} failed: {}", parent.display(), e))?;
    }
    Ok(())
}

fn remove_legacy_keyref(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => {
            info!("removed legacy identity keyref {}", path.display());
            sync_parent_dir(path)?;
        }
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => {
            return Err(anyhow::anyhow!(
                "remove legacy identity keyref {} failed: {}",
                path.display(),
                e
            ));
        }
    }

    Ok(())
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
    dns_provider_propagation_delays: RwLock<HashMap<String, Duration>>,
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
    #[serde(default = "default_renew_before_expiry")]
    pub renew_before_expiry: chrono::Duration, // 过期前多久开始续期
}

fn default_check_interval() -> chrono::Duration {
    chrono::Duration::hours(12) // 默认每12小时检查一次
}

fn default_renew_before_expiry() -> chrono::Duration {
    chrono::Duration::days(7) // 默认过期前7天续期
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
            renew_before_expiry: default_renew_before_expiry(),
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
        let mut dns_provider_propagation_delays = HashMap::<String, Duration>::new();
        let manager = AcmeCertManagerRef::new(Self {
            config: config.clone(),
            acme_client,
            certs: RwLock::new(HashMap::new()),
            check_handler: Mutex::new(None),
            responder: Mutex::new(None),
            challenge_certs: Mutex::new(Default::default()),
            http_challenges: Mutex::new(Default::default()),
            dns_providers: RwLock::new(dns_providers.clone()),
            dns_provider_propagation_delays: RwLock::new(dns_provider_propagation_delays.clone()),
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
                    let propagation_delay = factory.propagation_delay();
                    let provider = factory
                        .create(Arc::downgrade(&manager), provider_config.clone())
                        .await?;
                    dns_providers.insert(name.clone(), provider);
                    if !propagation_delay.is_zero() {
                        dns_provider_propagation_delays.insert(name.clone(), propagation_delay);
                    }
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
                .dns_provider_propagation_delays
                .write()
                .unwrap()
                .extend(dns_provider_propagation_delays);
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

    pub(crate) fn challenge_propagation_delay(&self, challenge: &Challenge) -> Duration {
        if !matches!(&challenge.data, ChallengeData::Dns01 { .. }) {
            return Duration::ZERO;
        }

        let cert_stub = {
            let certs = self.certs.read().unwrap();
            certs.get(challenge.domain.as_str()).cloned()
        };
        cert_stub
            .as_ref()
            .and_then(|stub| stub.inner.acme_item.data.clone())
            .and_then(|data| serde_json::from_value::<DnsProviderInfo>(data).ok())
            .and_then(|info| {
                self.dns_provider_propagation_delays
                    .read()
                    .unwrap()
                    .get(info.dns_provider.as_str())
                    .copied()
            })
            .unwrap_or(Duration::ZERO)
    }

    async fn call_dns_provider(
        &self,
        cert_stub: &CertStub,
        key_hash: &str,
        op: &str,
    ) -> Result<()> {
        let provider = self.get_dns_provider_for_cert(cert_stub)?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_acme::MockAcme;
    use openssl::asn1::Asn1Time;
    use openssl::bn::BigNum;
    use openssl::x509::extension::SubjectAlternativeName;
    use openssl::x509::{X509Builder, X509NameBuilder};

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

    fn install_test_cert(stub: &CertStub, valid_days: u32) {
        let domain = &stub.inner.acme_item.domain;
        let (cert, key) = generate_test_cert(domain, valid_days);
        install_identity_certificate(
            &stub.inner.identity_roots,
            stub.inner.acme_item.identity(),
            domain,
            &stub.inner.work_dir,
            &cert,
            &key,
            stub.inner.renew_before_expiry,
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

        install_test_cert(&stub, 3);
        stub.start_order().await.unwrap();
        assert_eq!(server.orders(), 1);
        // A later check must load the renewal instead of ordering again.
        stub.start_order().await.unwrap();
        assert_eq!(server.orders(), 1);
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
        install_test_cert(&stub, 3);
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
            !stub
                .wait_for_retry(Duration::from_secs(3600))
                .await
                .unwrap()
        );
        assert!(start.elapsed() >= Duration::from_secs(3600));

        let start = tokio::time::Instant::now();
        let (loaded, ()) = tokio::join!(stub.wait_for_retry(Duration::from_secs(3600)), async {
            tokio::time::sleep(Duration::from_secs(10)).await;
            install_test_cert(&stub, 90);
        });
        assert!(loaded.unwrap());
        assert!(start.elapsed() < Duration::from_secs(3600));
        assert!(stub.get_cert().is_some());
        assert_eq!(server.orders(), 0);
    }

    #[test]
    fn install_identity_certificate_writes_active_files() {
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

        install_identity_certificate(
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
    fn install_identity_certificate_rejects_san_mismatch_without_overwrite() {
        let temp = tempfile::tempdir().unwrap();
        let roots = IdentityRoots::new(temp.path().join("identity"), temp.path().join("security"));
        let work_dir = temp.path().join("state").join("acme").join("example.com");
        let (cert, key) = generate_test_cert("example.com", 90);

        install_identity_certificate(
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
        let result = install_identity_certificate(
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

    fn generate_test_cert(domain: &str, valid_days: u32) -> (Vec<u8>, Vec<u8>) {
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

        let not_before = Asn1Time::days_from_now(0).unwrap();
        let not_after = Asn1Time::days_from_now(valid_days).unwrap();
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
