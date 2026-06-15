use crate::SelfCertMgrRef;
use name_client::{IdentityMaterial, IdentityRoots, IdentityUsage};
use rustls::client::verify_server_name;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{DnsName, ServerName};
use rustls::server::{ClientHello, ParsedCertificate, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{Error, server, sign};
use std::collections::HashMap;
use std::fmt::Debug;
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tokio::task::JoinHandle;

#[derive(Debug)]
pub(crate) struct ResolvesServerCertUsingSni {
    by_name: Mutex<HashMap<String, Arc<sign::CertifiedKey>>>,
    external_resolver: Option<Arc<dyn server::ResolvesServerCert>>,
}

impl ResolvesServerCertUsingSni {
    pub fn new(external_resolver: Option<Arc<dyn server::ResolvesServerCert>>) -> Self {
        Self {
            by_name: Mutex::new(HashMap::new()),
            external_resolver,
        }
    }

    pub fn add(&self, name: &str, ck: sign::CertifiedKey) -> Result<(), Error> {
        let server_name = {
            let check_name = if name.starts_with("*.") {
                name.replace("*.", "test.")
            } else {
                name.to_string()
            };
            let checked_name = DnsName::try_from(check_name)
                .map_err(|_| Error::General("Bad DNS name".into()))
                .map(|name| name.to_lowercase_owned())?;
            ServerName::DnsName(checked_name)
        };

        ck.end_entity_cert()
            .and_then(ParsedCertificate::try_from)
            .and_then(|cert| verify_server_name(&cert, &server_name))?;

        self.by_name
            .lock()
            .unwrap()
            .insert(name.to_lowercase(), Arc::new(ck));

        Ok(())
    }

    // 添加一个辅助函数来检查通配符匹配
    fn matches_wildcard(domain: &str, wildcard: &str) -> bool {
        if !wildcard.starts_with("*.") {
            return false;
        }

        let wildcard_domain = &wildcard[2..]; // 移除 "*." 前缀
        if wildcard_domain.is_empty() {
            return false;
        }

        // 确保域名至少有两个部分（例如 example.com）
        if wildcard_domain.matches('.').count() < 1 {
            return false;
        }

        // 检查域名是否以通配符后缀结尾，并且前面有一个子域名部分
        if domain.len() > wildcard_domain.len() {
            let prefix_len = domain.len() - wildcard_domain.len() - 1;
            domain.ends_with(wildcard_domain)
                && domain.as_bytes()[prefix_len] == b'.'
                && !domain[..prefix_len].contains('.')
        } else {
            false
        }
    }
}

impl server::ResolvesServerCert for ResolvesServerCertUsingSni {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<sign::CertifiedKey>> {
        if let Some(name) = client_hello.server_name() {
            {
                let certs = self.by_name.lock().unwrap();

                let name = name.to_lowercase();
                // 首先尝试精确匹配
                if let Some(cert) = certs.get(name.as_str()).cloned() {
                    return Some(cert);
                }

                // 然后尝试通配符匹配
                for (cert_name, cert) in certs.iter() {
                    if cert_name.starts_with("*.")
                        && Self::matches_wildcard(name.as_str(), cert_name)
                    {
                        return Some(cert.clone());
                    }
                }
            }

            if self.external_resolver.is_none() {
                return None;
            }
            self.external_resolver
                .as_ref()
                .unwrap()
                .resolve(client_hello)
        } else {
            None
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct TlsIdentityHost {
    pub identity: String,
    pub tls_host: String,
}

impl TlsIdentityHost {
    pub fn new(roots: &IdentityRoots, identity: impl Into<String>) -> Result<Self, String> {
        let identity = identity.into();
        let tls_host = identity_to_tls_host(roots, &identity)?;
        Ok(Self { identity, tls_host })
    }
}

#[derive(Clone, Debug)]
pub(crate) struct TlsIdentityCertConfig {
    pub roots: IdentityRoots,
    pub hosts: Vec<TlsIdentityHost>,
    pub refresh_interval: Duration,
}

#[derive(Debug)]
pub(crate) struct IdentityCertResolver {
    roots: IdentityRoots,
    hosts: Vec<TlsIdentityHost>,
    by_name: RwLock<HashMap<String, Arc<CertifiedKey>>>,
    errors: Mutex<HashMap<String, String>>,
    external_resolver: Option<Arc<dyn ResolvesServerCert>>,
    refresh_handle: Mutex<Option<JoinHandle<()>>>,
}

impl IdentityCertResolver {
    pub fn new(
        config: TlsIdentityCertConfig,
        external_resolver: Option<Arc<dyn ResolvesServerCert>>,
    ) -> Arc<Self> {
        let resolver = Arc::new(Self {
            roots: config.roots,
            hosts: config.hosts,
            by_name: RwLock::new(HashMap::new()),
            errors: Mutex::new(HashMap::new()),
            external_resolver,
            refresh_handle: Mutex::new(None),
        });

        resolver.refresh_all();
        resolver.start_refresh(config.refresh_interval);
        resolver
    }

    fn start_refresh(self: &Arc<Self>, interval: Duration) {
        if interval.is_zero() {
            return;
        }

        let weak = Arc::downgrade(self);
        let handle = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            loop {
                ticker.tick().await;
                let Some(resolver) = weak.upgrade() else {
                    break;
                };
                resolver.refresh_all();
            }
        });
        *self.refresh_handle.lock().unwrap() = Some(handle);
    }

    fn refresh_all(&self) {
        for host in self.hosts.iter() {
            self.refresh_host(host);
        }
    }

    fn refresh_host(&self, host: &TlsIdentityHost) {
        let cache_key = host.tls_host.to_lowercase();
        match self.load_host_cert(host) {
            Ok(cert) => {
                self.by_name.write().unwrap().insert(cache_key, cert);
                if self.errors.lock().unwrap().remove(&host.identity).is_some() {
                    log::info!("loaded TLS identity certificate for {}", host.identity);
                }
            }
            Err(err) => {
                self.by_name.write().unwrap().remove(&cache_key);
                let mut errors = self.errors.lock().unwrap();
                if errors.get(&host.identity) != Some(&err) {
                    log::warn!(
                        "TLS identity certificate for {} is unavailable: {}",
                        host.identity,
                        err
                    );
                    errors.insert(host.identity.clone(), err);
                }
            }
        }
    }

    fn load_host_cert(&self, host: &TlsIdentityHost) -> Result<Arc<CertifiedKey>, String> {
        let cert_match = self
            .roots
            .find_public_file(
                &host.identity,
                IdentityUsage::Server,
                IdentityMaterial::Fullchain,
            )
            .map_err(|e| format!("find server fullchain failed: {e}"))?;
        let key_path = self
            .roots
            .private_key_file_for_legacy_tool(&host.identity, IdentityUsage::Server)
            .map_err(|e| format!("find server private key failed: {e}"))?;

        let certs = load_cert_file(&cert_match.path)?;
        let key = load_key_file(&key_path)?;
        let crypto_provider = rustls::crypto::ring::default_provider();
        let cert_key = CertifiedKey::from_der(certs, key, &crypto_provider)
            .map_err(|e| format!("parse certificate/key failed: {e}"))?;
        verify_cert_name(&host.tls_host, &cert_key)?;
        Ok(Arc::new(cert_key))
    }

    fn resolve_cached(&self, name: &str) -> Option<Arc<CertifiedKey>> {
        let certs = self.by_name.read().unwrap();

        if let Some(cert) = certs.get(name).cloned() {
            return Some(cert);
        }

        for (cert_name, cert) in certs.iter() {
            if cert_name.starts_with("*.")
                && ResolvesServerCertUsingSni::matches_wildcard(name, cert_name)
            {
                return Some(cert.clone());
            }
        }

        None
    }

    fn refresh_matching_hosts(&self, name: &str) {
        for host in self.hosts.iter() {
            let configured = host.tls_host.to_lowercase();
            if configured == name
                || (configured.starts_with("*.")
                    && ResolvesServerCertUsingSni::matches_wildcard(name, &configured))
            {
                self.refresh_host(host);
            }
        }
    }
}

impl Drop for IdentityCertResolver {
    fn drop(&mut self) {
        if let Some(handle) = self.refresh_handle.lock().unwrap().take() {
            handle.abort();
        }
    }
}

impl ResolvesServerCert for IdentityCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let server_name = client_hello.server_name().map(|name| name.to_lowercase());
        if let Some(name) = server_name.as_deref() {
            if let Some(cert) = self.resolve_cached(name) {
                return Some(cert);
            }

            self.refresh_matching_hosts(name);
            if let Some(cert) = self.resolve_cached(name) {
                return Some(cert);
            }
        }

        self.external_resolver
            .as_ref()
            .and_then(|resolver| resolver.resolve(client_hello))
    }
}

fn identity_to_tls_host(roots: &IdentityRoots, identity: &str) -> Result<String, String> {
    match name_client::did_web_dns_san(identity) {
        Ok(host) => return Ok(host.to_lowercase()),
        Err(err) => {
            log::debug!(
                "identity {} is not did:web for TLS DNS SAN: {}",
                identity,
                err
            );
        }
    }

    let raw_host_uri = roots
        .raw_host_uri(identity)
        .map_err(|e| format!("invalid identity host {identity}: {e}"))?;
    let raw_host = raw_host_uri
        .split_once('/')
        .map(|(host, _)| host)
        .unwrap_or(raw_host_uri.as_str());
    let tls_host = raw_host
        .strip_prefix("_.")
        .map(|suffix| format!("*.{suffix}"))
        .unwrap_or_else(|| raw_host.to_string());
    Ok(tls_host.to_lowercase())
}

fn load_cert_file(path: &Path) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, String> {
    rustls::pki_types::CertificateDer::pem_file_iter(path)
        .map_err(|e| format!("read certificate {} failed: {e}", path.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("parse certificate {} failed: {e}", path.display()))
}

fn load_key_file(path: &Path) -> Result<rustls::pki_types::PrivateKeyDer<'static>, String> {
    rustls::pki_types::PrivateKeyDer::from_pem_file(path)
        .map_err(|e| format!("parse private key {} failed: {e}", path.display()))
}

fn verify_cert_name(name: &str, cert_key: &CertifiedKey) -> Result<(), String> {
    let check_name = if let Some(suffix) = name.strip_prefix("*.") {
        format!("test.{suffix}")
    } else {
        name.to_string()
    };
    let checked_name = DnsName::try_from(check_name)
        .map_err(|_| format!("bad DNS name: {name}"))?
        .to_lowercase_owned();
    let server_name = ServerName::DnsName(checked_name);
    cert_key
        .end_entity_cert()
        .and_then(ParsedCertificate::try_from)
        .and_then(|cert| verify_server_name(&cert, &server_name))
        .map_err(|e| format!("certificate does not match {name}: {e}"))
}

pub struct TlsCertResolver {
    resolve: Arc<dyn ResolvesServerCert>,
    self_cert_mgr: Option<SelfCertMgrRef>,
}

impl Debug for TlsCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsCertResolver").finish()
    }
}

impl TlsCertResolver {
    pub fn new(
        resolve: Arc<dyn ResolvesServerCert>,
        self_cert_mgr: Option<SelfCertMgrRef>,
    ) -> Self {
        Self {
            resolve,
            self_cert_mgr,
        }
    }
}

impl ResolvesServerCert for TlsCertResolver {
    fn resolve(&self, client_hello: rustls::server::ClientHello) -> Option<Arc<CertifiedKey>> {
        let server_name = client_hello
            .server_name()
            .map(|v| v.to_string())
            .unwrap_or("".to_string());
        if let Some(cert) = self.resolve.resolve(client_hello) {
            return Some(cert);
        }
        if let Some(cert) = self.self_cert_mgr.as_ref() {
            cert.get().get_cert(server_name.as_str())
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{IdentityCertResolver, TlsIdentityHost};
    use name_client::IdentityRoots;
    use rcgen::generate_simple_self_signed;
    use serde_json::json;
    use std::collections::HashMap;
    use std::sync::{Mutex, RwLock};

    #[test]
    fn test_matches_wildcard() {
        assert!(!super::ResolvesServerCertUsingSni::matches_wildcard(
            "example.com",
            "*.example.com"
        ));
        assert!(super::ResolvesServerCertUsingSni::matches_wildcard(
            "www.example.com",
            "*.example.com"
        ));
        assert!(!super::ResolvesServerCertUsingSni::matches_wildcard(
            "www.example1.com",
            "*.example.com"
        ));
        assert!(!super::ResolvesServerCertUsingSni::matches_wildcard(
            "www.example1.com",
            "example.com"
        ));
    }

    #[test]
    fn test_identity_resolver_loads_cert_from_identity_roots() {
        let cert_key = generate_simple_self_signed(vec!["example.com".to_string()]).unwrap();
        let tmp_dir = tempfile::tempdir().unwrap();
        let roots = IdentityRoots::new(
            tmp_dir.path().join("local").join("identity"),
            tmp_dir.path().join("security"),
        );
        let public_dir = roots.public_dir("example.com").unwrap();
        let security_dir = roots.security_dir("example.com").unwrap();
        std::fs::create_dir_all(&public_dir).unwrap();
        std::fs::create_dir_all(&security_dir).unwrap();
        std::fs::write(public_dir.join("server.fullchain.pem"), cert_key.cert.pem()).unwrap();
        std::fs::write(
            security_dir.join("server.private.pem"),
            cert_key.signing_key.serialize_pem(),
        )
        .unwrap();
        std::fs::write(
            security_dir.join("server.keyref.json"),
            json!({
                "schema": "buckyos.identity.keyref.v1",
                "kind": "key",
                "did": "did:web:example.com",
                "usage": "server",
                "algorithm": "P-256",
                "public_key_fingerprint": "sha256:test",
                "mode": "file",
                "exportable": true,
                "ref": {
                    "type": "file",
                    "path": "server.private.pem",
                    "format": "pkcs8-pem"
                }
            })
            .to_string(),
        )
        .unwrap();

        let host = TlsIdentityHost::new(&roots, "example.com").unwrap();
        let resolver = IdentityCertResolver {
            roots,
            hosts: vec![host.clone()],
            by_name: RwLock::new(HashMap::new()),
            errors: Mutex::new(HashMap::new()),
            external_resolver: None,
            refresh_handle: Mutex::new(None),
        };

        assert!(resolver.load_host_cert(&host).is_ok());
    }
}
