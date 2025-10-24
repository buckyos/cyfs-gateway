use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::{Arc, Mutex, Weak};
use rustls::{server, sign, Error};
use rustls::client::verify_server_name;
use rustls::pki_types::{DnsName, ServerName};
use rustls::server::{ClientHello, ParsedCertificate};
use crate::{is_tls_alpn_challenge, AcmeChallengeResponder, CertManager, CertManagerRef, Challenge, ChallengeData};

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
            let checked_name = DnsName::try_from(name)
                .map_err(|_| Error::General("Bad DNS name".into()))
                .map(|name| name.to_lowercase_owned())?;
            ServerName::DnsName(checked_name)
        };

        ck.end_entity_cert()
            .and_then(ParsedCertificate::try_from)
            .and_then(|cert| verify_server_name(&cert, &server_name))?;

        if let ServerName::DnsName(name) = server_name {
            self.by_name.lock().unwrap()
                .insert(name.as_ref().to_string(), Arc::new(ck));
        }
        Ok(())
    }
}

impl server::ResolvesServerCert for ResolvesServerCertUsingSni {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<sign::CertifiedKey>> {
        if let Some(name) = client_hello.server_name() {
            self.by_name.lock().unwrap().get(name).cloned()
        } else {
            if self.external_resolver.is_none() {
                return None;
            }
            self.external_resolver.as_ref().unwrap().resolve(client_hello)
        }
    }
}

pub struct AcmeCertResolver {
    cert_mgr: Weak<CertManager>,
    challenge_certs: Mutex<HashMap<String, Arc<sign::CertifiedKey>>>,
}
pub type AcmeCertResolverRef = Arc<AcmeCertResolver>;

impl Debug for AcmeCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AcmeCertResolver")
            .field("cert_mgr", &self.cert_mgr)
            .finish()
    }
}

impl AcmeCertResolver {
    pub fn new(cert_mgr: CertManagerRef) -> AcmeCertResolverRef {
        Arc::new(Self {
            cert_mgr: Arc::downgrade(&cert_mgr),
            challenge_certs: Mutex::new(Default::default()),
        })
    }

    pub fn add_acme_request(self: &Arc<Self>, domain: impl Into<String>) -> anyhow::Result<()> {
        if let Some(cert_mgr) = self.cert_mgr.upgrade() {
            cert_mgr.insert_config(domain.into(), self.clone())?;
        }
        Ok(())
    }
}

impl server::ResolvesServerCert for AcmeCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<sign::CertifiedKey>> {
        if is_tls_alpn_challenge(&client_hello) {
            let challenge_certs = self.challenge_certs.lock().unwrap();
            return if let Some(server_name) = client_hello.server_name() {
                challenge_certs.get(server_name).cloned()
            } else {
                None
            };
        }
        if let Some(cert_mgr) = self.cert_mgr.upgrade() {
            cert_mgr.resolve(client_hello)
        } else {
            None
        }
    }
}

#[async_trait::async_trait]
impl AcmeChallengeResponder for AcmeCertResolver {
    async fn respond_challenge<'a>(&self, challenges: &'a [Challenge]) -> anyhow::Result<&'a Challenge> {
        for challenge in challenges {
            if let ChallengeData::TlsAlpn01 { ref cert } = challenge.data {
                let mut challenge_certs = self.challenge_certs.lock().unwrap();
                challenge_certs.insert(challenge.domain.clone(), cert.clone());
                return Ok(challenge);
            }
        }
        Err(anyhow::anyhow!("No TLS-ALPN-01 challenge found"))
    }

    fn revert_challenge(&self, challenge: &Challenge) {
        let mut challenge_certs = self.challenge_certs.lock().unwrap();
        challenge_certs.remove(&challenge.domain);
    }
}
