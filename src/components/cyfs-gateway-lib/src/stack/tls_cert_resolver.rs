use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::{Arc, Mutex};
use rustls::{server, sign, Error};
use rustls::client::verify_server_name;
use rustls::pki_types::{DnsName, ServerName};
use rustls::server::{ClientHello, ParsedCertificate, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use crate::SelfCertMgrRef;

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

        self.by_name.lock().unwrap()
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
            domain.ends_with(wildcard_domain) &&
                domain.as_bytes()[prefix_len] == b'.' &&
                !domain[..prefix_len].contains('.')
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
                    if cert_name.starts_with("*.") && Self::matches_wildcard(name.as_str(), cert_name) {
                        return Some(cert.clone());
                    }
                }
            }

            if self.external_resolver.is_none() {
                return None;
            }
            self.external_resolver.as_ref().unwrap().resolve(client_hello)
        } else {
            None
        }
    }
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
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello,
    ) -> Option<Arc<CertifiedKey>> {
        let server_name = client_hello.server_name().map(|v| v.to_string()).unwrap_or("".to_string());
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
    #[test]
    fn test_matches_wildcard() {
        assert!(!super::ResolvesServerCertUsingSni::matches_wildcard("example.com", "*.example.com"));
        assert!(super::ResolvesServerCertUsingSni::matches_wildcard("www.example.com", "*.example.com"));
        assert!(!super::ResolvesServerCertUsingSni::matches_wildcard("www.example1.com", "*.example.com"));
        assert!(!super::ResolvesServerCertUsingSni::matches_wildcard("www.example1.com", "example.com"));
    }
}
