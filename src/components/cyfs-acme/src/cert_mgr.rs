use crate::ChallengeType;
use anyhow::Result;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use serde_json::Value;
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::sync::{Arc, RwLock};

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
            private_key: clone_private_key(&self.private_key),
            expires: self.expires,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CertUsage {
    Server,
    Client,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CertRequest {
    pub provider: Option<String>,
    pub usage: CertUsage,
    pub domain: String,
    pub challenge_type: ChallengeType,
    pub data: Option<Value>,
}

impl CertRequest {
    pub fn server(
        domain: String,
        provider: Option<String>,
        challenge_type: ChallengeType,
        data: Option<Value>,
    ) -> Self {
        Self {
            provider,
            usage: CertUsage::Server,
            domain,
            challenge_type,
            data,
        }
    }

    pub fn client(
        domain: String,
        provider: Option<String>,
        challenge_type: ChallengeType,
        data: Option<Value>,
    ) -> Self {
        Self {
            provider,
            usage: CertUsage::Client,
            domain,
            challenge_type,
            data,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CertStatusState {
    Pending,
    Ready,
    Renewing,
    Expired,
    Error,
    Unknown,
}

#[derive(Clone, Debug)]
pub struct CertStatus {
    pub provider: String,
    pub domain: String,
    pub state: CertStatusState,
    pub expires: Option<chrono::DateTime<chrono::Utc>>,
    pub last_error: Option<String>,
}

pub trait CertProvider: Send + Sync + Debug {
    fn id(&self) -> &str;
    fn add_request(&self, request: CertRequest) -> Result<()>;
    fn resolve_server_cert(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>>;
    fn resolve_client_cert(&self, domain: &str) -> Result<Option<CertMaterial>>;
    fn get_status(&self, domain: &str) -> CertStatus;
    fn get_http01_auth(&self, token: &str) -> Option<String>;
}

pub type CertProviderRef = Arc<dyn CertProvider>;
pub type CertManagerRef = Arc<CertManager>;

pub struct CertManager {
    providers: RwLock<HashMap<String, CertProviderRef>>,
    server_routes: RwLock<HashMap<String, String>>,
    client_routes: RwLock<HashMap<String, String>>,
}

impl CertManager {
    pub fn new() -> CertManagerRef {
        Arc::new(Self {
            providers: RwLock::new(HashMap::new()),
            server_routes: RwLock::new(HashMap::new()),
            client_routes: RwLock::new(HashMap::new()),
        })
    }

    pub fn add_provider(&self, provider: CertProviderRef) -> Result<()> {
        let id = provider.id().to_string();
        let mut providers = self.providers.write().unwrap();
        if providers.contains_key(&id) {
            return Err(anyhow::anyhow!("duplicate cert provider: {}", id));
        }
        providers.insert(id, provider);
        Ok(())
    }

    pub fn providers(&self) -> Vec<CertProviderRef> {
        self.providers.read().unwrap().values().cloned().collect()
    }

    pub fn provider_count(&self) -> usize {
        self.providers.read().unwrap().len()
    }

    pub fn add_request(&self, request: CertRequest) -> Result<()> {
        let provider = self.resolve_provider(request.provider.as_deref())?;
        provider.add_request(request.clone())?;
        match request.usage {
            CertUsage::Server => {
                self.server_routes
                    .write()
                    .unwrap()
                    .insert(request.domain.to_lowercase(), provider.id().to_string());
            }
            CertUsage::Client => {
                self.client_routes
                    .write()
                    .unwrap()
                    .insert(request.domain.to_lowercase(), provider.id().to_string());
            }
        }
        Ok(())
    }

    pub fn resolve_client_cert(
        &self,
        provider: Option<&str>,
        domain: &str,
    ) -> Result<Option<CertMaterial>> {
        let provider = if let Some(provider) = provider {
            self.resolve_provider(Some(provider))?
        } else if let Some(provider) = self.route_provider(&self.client_routes, domain) {
            provider
        } else {
            self.resolve_provider(None)?
        };
        provider.resolve_client_cert(domain)
    }

    pub fn get_status(&self, provider: Option<&str>, domain: &str) -> Result<CertStatus> {
        let provider = if let Some(provider) = provider {
            self.resolve_provider(Some(provider))?
        } else if let Some(provider) = self.route_provider(&self.client_routes, domain) {
            provider
        } else if let Some(provider) = self.route_provider(&self.server_routes, domain) {
            provider
        } else {
            self.resolve_provider(None)?
        };
        Ok(provider.get_status(domain))
    }

    pub fn get_http01_auth(&self, token: &str) -> Option<String> {
        for provider in self.providers.read().unwrap().values() {
            if let Some(auth) = provider.get_http01_auth(token) {
                return Some(auth);
            }
        }
        None
    }

    fn resolve_provider(&self, provider: Option<&str>) -> Result<CertProviderRef> {
        let providers = self.providers.read().unwrap();
        if let Some(provider) = provider {
            return providers
                .get(provider)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("unknown cert provider: {}", provider));
        }
        if providers.len() == 1 {
            return Ok(providers.values().next().unwrap().clone());
        }
        Err(anyhow::anyhow!(
            "cert_provider is required when {} cert providers are configured",
            providers.len()
        ))
    }

    fn route_provider(
        &self,
        routes: &RwLock<HashMap<String, String>>,
        domain: &str,
    ) -> Option<CertProviderRef> {
        let domain = domain.to_lowercase();
        let routes = routes.read().unwrap();
        let provider_id = routes.get(&domain).cloned().or_else(|| {
            routes
                .iter()
                .find(|(route_domain, _)| {
                    route_domain.starts_with("*.") && host_matches_wildcard(&domain, route_domain)
                })
                .map(|(_, provider)| provider.clone())
        })?;
        drop(routes);
        self.providers.read().unwrap().get(&provider_id).cloned()
    }
}

impl Debug for CertManager {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertManager").finish()
    }
}

impl ResolvesServerCert for CertManager {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let server_name = client_hello.server_name()?.to_lowercase();
        let provider = self.route_provider(&self.server_routes, &server_name)?;
        provider.resolve_server_cert(client_hello)
    }
}

fn clone_private_key(key: &PrivateKeyDer<'static>) -> PrivateKeyDer<'static> {
    match key {
        PrivateKeyDer::Pkcs8(key) => PrivateKeyDer::Pkcs8(key.clone_key()),
        PrivateKeyDer::Pkcs1(key) => PrivateKeyDer::Pkcs1(key.clone_key()),
        PrivateKeyDer::Sec1(key) => PrivateKeyDer::Sec1(key.clone_key()),
        _ => panic!("Unsupported key type"),
    }
}

fn host_matches_wildcard(domain: &str, wildcard: &str) -> bool {
    if !wildcard.starts_with("*.") {
        return false;
    }

    let wildcard_domain = &wildcard[2..];
    if wildcard_domain.is_empty() || wildcard_domain.matches('.').count() < 1 {
        return false;
    }

    if domain.len() <= wildcard_domain.len() {
        return false;
    }

    let prefix_len = domain.len() - wildcard_domain.len() - 1;
    domain.ends_with(wildcard_domain)
        && domain.as_bytes()[prefix_len] == b'.'
        && !domain[..prefix_len].contains('.')
}
