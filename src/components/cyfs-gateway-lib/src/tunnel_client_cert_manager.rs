use crate::{TunnelError, TunnelResult, normalize_config_file_path};
use anyhow::{Result, anyhow};
use chrono::{DateTime, Utc};
use cyfs_acme::{AcmeCertManagerRef, AcmeItem, CertMaterial, CertStubState, ChallengeType};
use openssl::pkey::PKey;
use openssl::x509::X509;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(tag = "type")]
pub enum TunnelClientCertConfig {
    #[serde(rename = "local")]
    Local { cert_path: String, key_path: String },
    #[serde(rename = "acme")]
    Acme {
        domain: String,
        acme_type: ChallengeType,
        dns_provider: Option<String>,
    },
}

#[derive(Debug)]
pub struct TunnelClientCertMaterial {
    pub certs: Vec<CertificateDer<'static>>,
    pub private_key: PrivateKeyDer<'static>,
    pub expires: Option<DateTime<Utc>>,
}

impl Clone for TunnelClientCertMaterial {
    fn clone(&self) -> Self {
        Self {
            certs: self.certs.clone(),
            private_key: clone_private_key(&self.private_key),
            expires: self.expires,
        }
    }
}

impl From<CertMaterial> for TunnelClientCertMaterial {
    fn from(value: CertMaterial) -> Self {
        Self {
            certs: value.certs,
            private_key: value.private_key,
            expires: Some(value.expires),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TunnelClientCertSource {
    Local,
    Acme,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TunnelClientCertState {
    Ready,
    Pending,
    Error,
}

#[derive(Clone, Debug)]
pub struct TunnelClientCertStatus {
    pub alias: String,
    pub source: TunnelClientCertSource,
    pub state: TunnelClientCertState,
    pub domain: Option<String>,
    pub expires: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
}

#[derive(Clone)]
enum TunnelClientCertEntry {
    Local {
        material: TunnelClientCertMaterial,
    },
    Acme {
        domain: String,
        acme_type: ChallengeType,
        dns_provider: Option<String>,
    },
}

#[derive(Clone, Default)]
struct TunnelClientCertSnapshot {
    entries: HashMap<String, TunnelClientCertEntry>,
    acme_manager: Option<AcmeCertManagerRef>,
}

pub struct TunnelClientCertManager {
    active_snapshot: RwLock<Arc<TunnelClientCertSnapshot>>,
    prepared_snapshot: Mutex<Option<Arc<TunnelClientCertSnapshot>>>,
}

pub type TunnelClientCertManagerRef = Arc<TunnelClientCertManager>;

impl TunnelClientCertManager {
    pub fn new() -> TunnelClientCertManagerRef {
        Arc::new(Self {
            active_snapshot: RwLock::new(Arc::new(TunnelClientCertSnapshot::default())),
            prepared_snapshot: Mutex::new(None),
        })
    }

    pub fn prepare_reload(
        &self,
        configs: Option<&HashMap<String, TunnelClientCertConfig>>,
        acme_manager: AcmeCertManagerRef,
        base_dir: &Path,
    ) -> Result<()> {
        let mut entries = HashMap::new();
        let mut acme_domains = HashMap::<String, (ChallengeType, Option<String>)>::new();

        if let Some(configs) = configs {
            for (alias, config) in configs {
                let entry = match config {
                    TunnelClientCertConfig::Local {
                        cert_path,
                        key_path,
                    } => {
                        let cert_path =
                            normalize_config_file_path(PathBuf::from(cert_path), base_dir);
                        let key_path =
                            normalize_config_file_path(PathBuf::from(key_path), base_dir);
                        let material = load_local_material(alias, &cert_path, &key_path)?;
                        TunnelClientCertEntry::Local { material }
                    }
                    TunnelClientCertConfig::Acme {
                        domain,
                        acme_type,
                        dns_provider,
                    } => {
                        validate_acme_entry(
                            alias,
                            domain,
                            acme_type.clone(),
                            dns_provider.as_deref(),
                        )?;

                        if let Some(previous) = acme_domains.get(domain) {
                            if previous != &(acme_type.clone(), dns_provider.clone()) {
                                return Err(anyhow!(
                                    "tunnel_client_certs.{} conflicts with another alias on ACME domain {}",
                                    alias,
                                    domain
                                ));
                            }
                        } else {
                            acme_domains
                                .insert(domain.clone(), (acme_type.clone(), dns_provider.clone()));
                        }

                        let data = dns_provider
                            .as_ref()
                            .map(|provider| json!({ "dns_provider": provider }));
                        acme_manager.add_acme_item(AcmeItem::new(
                            domain.clone(),
                            acme_type.clone(),
                            data,
                        ))?;

                        TunnelClientCertEntry::Acme {
                            domain: domain.clone(),
                            acme_type: acme_type.clone(),
                            dns_provider: dns_provider.clone(),
                        }
                    }
                };

                entries.insert(alias.clone(), entry);
            }
        }

        *self.prepared_snapshot.lock().unwrap() = Some(Arc::new(TunnelClientCertSnapshot {
            entries,
            acme_manager: Some(acme_manager),
        }));
        Ok(())
    }

    pub fn commit_prepared(&self) {
        if let Some(prepared) = self.prepared_snapshot.lock().unwrap().take() {
            *self.active_snapshot.write().unwrap() = prepared;
        }
    }

    pub fn discard_prepared(&self) {
        self.prepared_snapshot.lock().unwrap().take();
    }

    pub fn resolve_material(&self, alias: &str) -> TunnelResult<TunnelClientCertMaterial> {
        let snapshot = self.active_snapshot.read().unwrap().clone();
        let entry = snapshot.entries.get(alias).ok_or_else(|| {
            TunnelError::InvalidState(format!(
                "unknown tunnel client certificate alias: {}",
                alias
            ))
        })?;

        match entry {
            TunnelClientCertEntry::Local { material } => Ok(material.clone()),
            TunnelClientCertEntry::Acme {
                domain,
                acme_type: _,
                dns_provider: _,
            } => {
                let acme_manager = snapshot.acme_manager.as_ref().ok_or_else(|| {
                    TunnelError::InvalidState(format!(
                        "tunnel client certificate alias {} has no active ACME manager",
                        alias
                    ))
                })?;
                let cert_stub = acme_manager.get_cert_by_host(domain).ok_or_else(|| {
                    TunnelError::InvalidState(format!(
                        "tunnel client certificate alias {} is not registered in ACME manager",
                        alias
                    ))
                })?;

                if let Some(material) = cert_stub.get_material() {
                    return Ok(material.into());
                }

                let last_error = cert_stub.get_last_error();
                let state = cert_stub.get_state();
                let msg = match state {
                    CertStubState::Pending => format!(
                        "tunnel client certificate alias {} is pending ACME issuance{}",
                        alias,
                        last_error
                            .as_ref()
                            .map(|err| format!(": {}", err))
                            .unwrap_or_default()
                    ),
                    CertStubState::Expired => {
                        if let Some(last_error) = last_error {
                            format!(
                                "tunnel client certificate alias {} is expired: {}",
                                alias, last_error
                            )
                        } else {
                            format!("tunnel client certificate alias {} is expired", alias)
                        }
                    }
                    CertStubState::Ready | CertStubState::Renewing => {
                        format!("tunnel client certificate alias {} is not ready", alias)
                    }
                };

                Err(TunnelError::InvalidState(msg))
            }
        }
    }

    pub fn list_statuses(&self) -> Vec<TunnelClientCertStatus> {
        let snapshot = self.active_snapshot.read().unwrap().clone();
        snapshot
            .entries
            .iter()
            .map(|(alias, entry)| match entry {
                TunnelClientCertEntry::Local { material } => TunnelClientCertStatus {
                    alias: alias.clone(),
                    source: TunnelClientCertSource::Local,
                    state: TunnelClientCertState::Ready,
                    domain: None,
                    expires: material.expires.clone(),
                    last_error: None,
                },
                TunnelClientCertEntry::Acme {
                    domain,
                    acme_type: _,
                    dns_provider: _,
                } => build_acme_status(alias, domain, snapshot.acme_manager.as_ref()),
            })
            .collect()
    }
}

fn build_acme_status(
    alias: &str,
    domain: &str,
    acme_manager: Option<&AcmeCertManagerRef>,
) -> TunnelClientCertStatus {
    let Some(acme_manager) = acme_manager else {
        return TunnelClientCertStatus {
            alias: alias.to_string(),
            source: TunnelClientCertSource::Acme,
            state: TunnelClientCertState::Error,
            domain: Some(domain.to_string()),
            expires: None,
            last_error: Some("missing active ACME manager".to_string()),
        };
    };

    let Some(cert_stub) = acme_manager.get_cert_by_host(domain) else {
        return TunnelClientCertStatus {
            alias: alias.to_string(),
            source: TunnelClientCertSource::Acme,
            state: TunnelClientCertState::Error,
            domain: Some(domain.to_string()),
            expires: None,
            last_error: Some("alias not registered in ACME manager".to_string()),
        };
    };

    let material = cert_stub.get_material();
    let last_error = cert_stub.get_last_error();
    let state = if material.is_some() {
        TunnelClientCertState::Ready
    } else {
        match cert_stub.get_state() {
            CertStubState::Pending => {
                if last_error.is_some() {
                    TunnelClientCertState::Error
                } else {
                    TunnelClientCertState::Pending
                }
            }
            CertStubState::Expired => TunnelClientCertState::Error,
            CertStubState::Ready | CertStubState::Renewing => TunnelClientCertState::Error,
        }
    };

    TunnelClientCertStatus {
        alias: alias.to_string(),
        source: TunnelClientCertSource::Acme,
        state,
        domain: Some(domain.to_string()),
        expires: material.map(|material| material.expires),
        last_error,
    }
}

fn validate_acme_entry(
    alias: &str,
    domain: &str,
    acme_type: ChallengeType,
    dns_provider: Option<&str>,
) -> Result<()> {
    if matches!(acme_type, ChallengeType::Unknown) {
        return Err(anyhow!(
            "tunnel_client_certs.{} has unsupported acme_type",
            alias
        ));
    }

    let is_wildcard = domain.starts_with("*.");
    match acme_type {
        ChallengeType::Dns01 => {
            if dns_provider.is_none() {
                return Err(anyhow!(
                    "tunnel_client_certs.{} requires dns_provider for dns-01",
                    alias
                ));
            }
        }
        ChallengeType::Http01 | ChallengeType::TlsAlpn01 => {
            if is_wildcard {
                return Err(anyhow!(
                    "tunnel_client_certs.{} wildcard domain {} is only allowed for dns-01",
                    alias,
                    domain
                ));
            }
        }
        ChallengeType::Unknown => unreachable!(),
    }

    Ok(())
}

fn load_local_material(
    alias: &str,
    cert_path: &Path,
    key_path: &Path,
) -> Result<TunnelClientCertMaterial> {
    let cert_data = fs::read(cert_path).map_err(|e| {
        anyhow!(
            "tunnel_client_certs.{} failed to read cert_path {}: {}",
            alias,
            cert_path.display(),
            e
        )
    })?;
    let key_data = fs::read(key_path).map_err(|e| {
        anyhow!(
            "tunnel_client_certs.{} failed to read key_path {}: {}",
            alias,
            key_path.display(),
            e
        )
    })?;

    let certs = parse_cert_chain(alias, &cert_data)?;
    let private_key = parse_private_key(alias, &key_data)?;
    validate_cert_key_match(alias, &cert_data, &key_data)?;
    let expires = Some(parse_cert_expiry(alias, &cert_data)?);

    Ok(TunnelClientCertMaterial {
        certs,
        private_key,
        expires,
    })
}

fn parse_cert_chain(alias: &str, cert_data: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    let mut certs = Vec::new();
    for cert in rustls_pemfile::certs(&mut &*cert_data) {
        certs.push(cert.map_err(|e| {
            anyhow!(
                "tunnel_client_certs.{} contains invalid certificate PEM: {}",
                alias,
                e
            )
        })?);
    }
    if certs.is_empty() {
        return Err(anyhow!(
            "tunnel_client_certs.{} contains no certificate PEM entries",
            alias
        ));
    }
    Ok(certs)
}

fn parse_private_key(alias: &str, key_data: &[u8]) -> Result<PrivateKeyDer<'static>> {
    rustls_pemfile::private_key(&mut &*key_data)?
        .ok_or_else(|| anyhow!("tunnel_client_certs.{} contains no private key PEM", alias))
}

fn parse_cert_expiry(alias: &str, cert_data: &[u8]) -> Result<DateTime<Utc>> {
    let certs = X509::stack_from_pem(cert_data).map_err(|e| {
        anyhow!(
            "tunnel_client_certs.{} contains invalid certificate PEM: {}",
            alias,
            e
        )
    })?;
    let cert = certs
        .first()
        .ok_or_else(|| anyhow!("tunnel_client_certs.{} contains no certificate PEM", alias))?;
    let not_after = cert.not_after().to_string();
    let datetime_str = not_after
        .rsplitn(2, ' ')
        .nth(1)
        .ok_or_else(|| anyhow!("tunnel_client_certs.{} has invalid not_after format", alias))?;
    let expires = chrono::NaiveDateTime::parse_from_str(datetime_str, "%b %e %H:%M:%S %Y")
        .map_err(|e| anyhow!("tunnel_client_certs.{} has invalid expiry: {}", alias, e))?;
    Ok(DateTime::<Utc>::from_naive_utc_and_offset(expires, Utc))
}

fn validate_cert_key_match(alias: &str, cert_data: &[u8], key_data: &[u8]) -> Result<()> {
    let certs = X509::stack_from_pem(cert_data).map_err(|e| {
        anyhow!(
            "tunnel_client_certs.{} contains invalid certificate PEM: {}",
            alias,
            e
        )
    })?;
    let cert = certs
        .first()
        .ok_or_else(|| anyhow!("tunnel_client_certs.{} contains no certificate PEM", alias))?;
    let private_key = PKey::private_key_from_pem(key_data).map_err(|e| {
        anyhow!(
            "tunnel_client_certs.{} contains invalid private key PEM: {}",
            alias,
            e
        )
    })?;
    let public_key = cert.public_key().map_err(|e| {
        anyhow!(
            "tunnel_client_certs.{} failed to read certificate public key: {}",
            alias,
            e
        )
    })?;
    if !public_key.public_eq(&private_key) {
        return Err(anyhow!(
            "tunnel_client_certs.{} certificate and private key do not match",
            alias
        ));
    }
    Ok(())
}

fn clone_private_key(key: &PrivateKeyDer<'static>) -> PrivateKeyDer<'static> {
    match key {
        PrivateKeyDer::Pkcs8(key) => PrivateKeyDer::Pkcs8(key.clone_key()),
        PrivateKeyDer::Pkcs1(key) => PrivateKeyDer::Pkcs1(key.clone_key()),
        PrivateKeyDer::Sec1(key) => PrivateKeyDer::Sec1(key.clone_key()),
        _ => panic!("Unsupported key type"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cyfs_acme::{AcmeCertManager, CertManagerConfig};
    use rcgen::generate_simple_self_signed;
    use tempfile::tempdir;

    async fn create_test_acme_manager(dir: &Path) -> AcmeCertManagerRef {
        let config = CertManagerConfig {
            keystore_path: dir.join("acme-store").to_string_lossy().to_string(),
            ..Default::default()
        };

        AcmeCertManager::create(config).await.unwrap()
    }

    fn write_test_cert_files(
        dir: &Path,
        name: &str,
        domain: &str,
    ) -> (String, String, PathBuf, PathBuf) {
        let cert_dir = dir.join("certs");
        fs::create_dir_all(&cert_dir).unwrap();
        let cert = generate_simple_self_signed(vec![domain.to_string()]).unwrap();
        let cert_rel = format!("certs/{}.pem", name);
        let key_rel = format!("certs/{}.key", name);
        let cert_path = dir.join(&cert_rel);
        let key_path = dir.join(&key_rel);
        fs::write(&cert_path, cert.cert.pem()).unwrap();
        fs::write(&key_path, cert.signing_key.serialize_pem()).unwrap();
        (cert_rel, key_rel, cert_path, key_path)
    }

    #[tokio::test]
    async fn test_prepare_reload_replaces_active_snapshot_only_after_commit() {
        let dir = tempdir().unwrap();
        let (first_cert_rel, first_key_rel, first_cert_path, first_key_path) =
            write_test_cert_files(dir.path(), "first", "client-a.example.com");
        let (second_cert_rel, second_key_rel, _, _) =
            write_test_cert_files(dir.path(), "second", "client-b.example.com");
        let manager = TunnelClientCertManager::new();
        let acme_manager = create_test_acme_manager(dir.path()).await;
        let initial_config = HashMap::from([(
            "mtls".to_string(),
            TunnelClientCertConfig::Local {
                cert_path: first_cert_rel,
                key_path: first_key_rel,
            },
        )]);
        manager
            .prepare_reload(Some(&initial_config), acme_manager.clone(), dir.path())
            .unwrap();
        manager.commit_prepared();

        let initial_material = manager.resolve_material("mtls").unwrap();
        let expected_initial =
            load_local_material("mtls", &first_cert_path, &first_key_path).unwrap();
        assert_eq!(
            initial_material.certs[0].as_ref(),
            expected_initial.certs[0].as_ref()
        );

        let replacement_config = HashMap::from([(
            "mtls".to_string(),
            TunnelClientCertConfig::Local {
                cert_path: second_cert_rel,
                key_path: second_key_rel,
            },
        )]);
        manager
            .prepare_reload(Some(&replacement_config), acme_manager, dir.path())
            .unwrap();

        let before_commit = manager.resolve_material("mtls").unwrap();
        assert_eq!(
            before_commit.certs[0].as_ref(),
            initial_material.certs[0].as_ref()
        );

        manager.commit_prepared();
        let after_commit = manager.resolve_material("mtls").unwrap();
        assert_ne!(
            after_commit.certs[0].as_ref(),
            initial_material.certs[0].as_ref()
        );
        assert!(after_commit.expires.is_some());
    }

    #[tokio::test]
    async fn test_prepare_reload_failure_keeps_previous_active_snapshot() {
        let dir = tempdir().unwrap();
        let (cert_rel, key_rel, cert_path, key_path) =
            write_test_cert_files(dir.path(), "active", "active.example.com");
        let manager = TunnelClientCertManager::new();
        let acme_manager = create_test_acme_manager(dir.path()).await;
        let active_config = HashMap::from([(
            "mtls".to_string(),
            TunnelClientCertConfig::Local {
                cert_path: cert_rel,
                key_path: key_rel,
            },
        )]);
        manager
            .prepare_reload(Some(&active_config), acme_manager.clone(), dir.path())
            .unwrap();
        manager.commit_prepared();

        let previous = manager.resolve_material("mtls").unwrap();
        let err = manager
            .prepare_reload(
                Some(&HashMap::from([(
                    "mtls".to_string(),
                    TunnelClientCertConfig::Local {
                        cert_path: "certs/missing.pem".to_string(),
                        key_path: "certs/missing.key".to_string(),
                    },
                )])),
                acme_manager,
                dir.path(),
            )
            .unwrap_err();
        assert!(err.to_string().contains("failed to read cert_path"));

        let current = manager.resolve_material("mtls").unwrap();
        let expected = load_local_material("mtls", &cert_path, &key_path).unwrap();
        assert_eq!(current.certs[0].as_ref(), previous.certs[0].as_ref());
        assert_eq!(current.certs[0].as_ref(), expected.certs[0].as_ref());
    }

    #[tokio::test]
    async fn test_prepare_reload_none_clears_active_entries_after_commit() {
        let dir = tempdir().unwrap();
        let (cert_rel, key_rel, _, _) =
            write_test_cert_files(dir.path(), "active", "clear.example.com");
        let manager = TunnelClientCertManager::new();
        let acme_manager = create_test_acme_manager(dir.path()).await;
        let active_config = HashMap::from([(
            "mtls".to_string(),
            TunnelClientCertConfig::Local {
                cert_path: cert_rel,
                key_path: key_rel,
            },
        )]);
        manager
            .prepare_reload(Some(&active_config), acme_manager.clone(), dir.path())
            .unwrap();
        manager.commit_prepared();
        assert!(manager.resolve_material("mtls").is_ok());

        manager
            .prepare_reload(None, acme_manager, dir.path())
            .unwrap();
        manager.commit_prepared();

        assert!(manager.resolve_material("mtls").is_err());
        assert!(manager.list_statuses().is_empty());
    }

    #[test]
    fn test_local_entry_json_parser() {
        let dir = tempdir().unwrap();
        let (cert_rel, key_rel, _, _) =
            write_test_cert_files(dir.path(), "local", "client.example.com");
        let config = HashMap::from([(
            "local_alias".to_string(),
            TunnelClientCertConfig::Local {
                cert_path: cert_rel.clone(),
                key_path: key_rel.clone(),
            },
        )]);

        let parsed = serde_json::from_value::<HashMap<String, TunnelClientCertConfig>>(json!({
            "local_alias": {
                "type": "local",
                "cert_path": cert_rel,
                "key_path": key_rel
            }
        }))
        .unwrap();
        assert_eq!(parsed, config);
    }

    #[test]
    fn test_validate_acme_entry_rules() {
        assert!(
            validate_acme_entry("dns", "*.example.com", ChallengeType::Dns01, Some("aliyun"))
                .is_ok()
        );
        assert!(validate_acme_entry("dns", "example.com", ChallengeType::Dns01, None).is_err());
        assert!(validate_acme_entry("http", "*.example.com", ChallengeType::Http01, None).is_err());
        assert!(
            validate_acme_entry("alpn", "*.example.com", ChallengeType::TlsAlpn01, None).is_err()
        );
    }

    #[test]
    fn test_discard_prepared_keeps_active_snapshot() {
        let manager = TunnelClientCertManager::new();
        *manager.prepared_snapshot.lock().unwrap() = Some(Arc::new(TunnelClientCertSnapshot {
            entries: HashMap::from([(
                "pending".to_string(),
                TunnelClientCertEntry::Acme {
                    domain: "client.example.com".to_string(),
                    acme_type: ChallengeType::Http01,
                    dns_provider: None,
                },
            )]),
            acme_manager: None,
        }));

        manager.discard_prepared();
        assert!(manager.resolve_material("pending").is_err());
        assert!(manager.list_statuses().is_empty());
    }

    #[test]
    fn test_load_local_material_rejects_mismatched_key() {
        let dir = tempdir().unwrap();
        let (_, _, cert_path, _) = write_test_cert_files(dir.path(), "cert", "client.example.com");
        let (_, _, _, other_key_path) =
            write_test_cert_files(dir.path(), "other", "other.example.com");

        let err = load_local_material("mismatch", &cert_path, &other_key_path).unwrap_err();
        assert!(
            err.to_string()
                .contains("tunnel_client_certs.mismatch certificate and private key do not match")
        );
    }

    #[test]
    fn test_list_statuses_marks_acme_entry_without_manager_as_error() {
        let manager = TunnelClientCertManager::new();
        *manager.prepared_snapshot.lock().unwrap() = Some(Arc::new(TunnelClientCertSnapshot {
            entries: HashMap::from([(
                "acme_alias".to_string(),
                TunnelClientCertEntry::Acme {
                    domain: "client.example.com".to_string(),
                    acme_type: ChallengeType::Http01,
                    dns_provider: None,
                },
            )]),
            acme_manager: None,
        }));
        manager.commit_prepared();

        let statuses = manager.list_statuses();
        assert_eq!(statuses.len(), 1);
        let status = &statuses[0];
        assert_eq!(status.alias, "acme_alias");
        assert_eq!(status.source, TunnelClientCertSource::Acme);
        assert_eq!(status.state, TunnelClientCertState::Error);
        assert_eq!(status.domain.as_deref(), Some("client.example.com"));
        assert_eq!(
            status.last_error.as_deref(),
            Some("missing active ACME manager")
        );

        let err = manager.resolve_material("acme_alias").unwrap_err();
        assert!(
            err.to_string()
                .contains("tunnel client certificate alias acme_alias has no active ACME manager")
        );
    }
}
