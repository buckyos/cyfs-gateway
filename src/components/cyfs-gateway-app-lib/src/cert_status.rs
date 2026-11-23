use cyfs_acme::{AcmeCertError, AcmeCertState, AcmeCertStatus};
use cyfs_gateway_lib::TlsHostCertificate;
use cyfs_identity_cert::CertManager;
use serde::{Deserialize, Serialize};

/// Result of the control method `get_cert_status`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct CertStatusReport {
    pub hosts: Vec<HostCertStatus>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct HostCertStatus {
    /// `<domain>` or `*.<domain>`.
    pub host: String,
    /// A TLS stack presents a certificate for this host.
    pub loaded: bool,
    /// Unix seconds.
    pub not_after: Option<u64>,
    pub issuer: Option<String>,
    /// `sha256:<hex>`.
    pub fingerprint: Option<String>,
    pub manager: Option<CertManager>,
    pub acme: Option<HostAcmeStatus>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct HostAcmeStatus {
    pub state: AcmeCertState,
    pub last_error: Option<AcmeCertError>,
    /// Unix seconds.
    pub next_retry_at: Option<u64>,
}

/// The TLS hosts in the order of the configuration, then the ACME hosts no TLS
/// stack serves.
pub fn host_cert_statuses(
    tls: Vec<TlsHostCertificate>,
    acme: Vec<AcmeCertStatus>,
) -> Vec<HostCertStatus> {
    let mut hosts: Vec<HostCertStatus> = Vec::new();
    for certificate in tls {
        let index = match hosts.iter().position(|host| host.host == certificate.host) {
            Some(index) => index,
            None => {
                hosts.push(HostCertStatus {
                    host: certificate.host.clone(),
                    loaded: false,
                    not_after: None,
                    issuer: None,
                    fingerprint: None,
                    manager: certificate.manager,
                    acme: None,
                });
                hosts.len() - 1
            }
        };
        let host = &mut hosts[index];
        if let Some(loaded) = certificate.loaded
            && !host.loaded
        {
            host.loaded = true;
            host.not_after = Some(loaded.not_after);
            host.issuer = Some(loaded.issuer);
            host.fingerprint = Some(loaded.fingerprint);
            host.manager = certificate.manager;
        }
    }
    for status in acme {
        let name = status.host.to_lowercase();
        let acme = Some(HostAcmeStatus {
            state: status.state,
            last_error: status.last_error,
            next_retry_at: status.next_retry_at,
        });
        if let Some(host) = hosts.iter_mut().find(|host| host.host == name) {
            host.acme = acme;
            continue;
        }
        let installed = status.installed;
        hosts.push(HostCertStatus {
            host: name,
            loaded: false,
            not_after: installed.as_ref().map(|cert| cert.not_after),
            issuer: installed.as_ref().and_then(|cert| cert.issuer.clone()),
            fingerprint: installed.as_ref().map(|cert| cert.fingerprint.clone()),
            manager: installed.and_then(|cert| cert.manager),
            acme,
        });
    }
    hosts
}

#[cfg(test)]
mod tests {
    use super::*;
    use cyfs_identity_cert::{CertificateSummary, InstalledCertificate};

    fn loaded(not_after: u64) -> Option<CertificateSummary> {
        Some(CertificateSummary {
            not_before: 1,
            not_after,
            issuer: "CN=CA".to_string(),
            dns_names: vec![],
            fingerprint: format!("sha256:{not_after}"),
        })
    }

    fn tls(host: &str, loaded: Option<CertificateSummary>) -> TlsHostCertificate {
        TlsHostCertificate {
            host: host.to_string(),
            manager: loaded.as_ref().map(|_| CertManager::Manual),
            loaded,
        }
    }

    #[test]
    fn tls_and_acme_hosts_are_merged() {
        let hosts = host_cert_statuses(
            vec![
                tls("*.d.example", None),
                tls("d.example", loaded(20)),
                tls("d.example", loaded(30)),
            ],
            vec![
                AcmeCertStatus {
                    host: "*.d.example".to_string(),
                    state: AcmeCertState::Ordering,
                    last_error: Some(AcmeCertError {
                        message: "refused".to_string(),
                        at: 5,
                    }),
                    next_retry_at: Some(35),
                    installed: None,
                },
                AcmeCertStatus {
                    host: "other.example".to_string(),
                    state: AcmeCertState::Ready,
                    last_error: None,
                    next_retry_at: None,
                    installed: Some(InstalledCertificate {
                        host: "other.example".to_string(),
                        manager: Some(CertManager::Acme),
                        not_before: 1,
                        not_after: 40,
                        issuer: Some("CN=CA".to_string()),
                        dns_names: vec![],
                        fingerprint: "sha256:40".to_string(),
                    }),
                },
            ],
        );
        assert_eq!(
            serde_json::to_value(CertStatusReport { hosts }).unwrap(),
            serde_json::json!({ "hosts": [
                {
                    "host": "*.d.example", "loaded": false, "not_after": null, "issuer": null,
                    "fingerprint": null, "manager": null,
                    "acme": {
                        "state": "ordering",
                        "last_error": { "message": "refused", "at": 5 },
                        "next_retry_at": 35
                    }
                },
                {
                    "host": "d.example", "loaded": true, "not_after": 20, "issuer": "CN=CA",
                    "fingerprint": "sha256:20", "manager": "manual", "acme": null
                },
                {
                    "host": "other.example", "loaded": false, "not_after": 40, "issuer": "CN=CA",
                    "fingerprint": "sha256:40", "manager": "acme",
                    "acme": { "state": "ready", "last_error": null, "next_retry_at": null }
                }
            ]})
        );
    }
}
