use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::{Arc, Mutex};
use rustls::{server, sign, Error};
use rustls::client::verify_server_name;
use rustls::pki_types::{DnsName, ServerName};
use rustls::server::{ClientHello, ParsedCertificate};

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
            {
                let cert = self.by_name.lock().unwrap().get(name).cloned();
                if cert.is_some() {
                    return cert;
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
