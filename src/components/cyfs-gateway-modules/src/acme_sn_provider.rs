use anyhow::anyhow;
use cyfs_acme::{AcmeCertManager, DnsProvider, DnsProviderFactory, DnsProviderRef};
use serde::Deserialize;
use serde_json::json;
use std::sync::{Arc, Weak};

use crate::sn_device::SnDeviceClient;

const SN_DNS_CHALLENGE_TTL_SECS: u32 = 60;
const SN_DNS_PROPAGATION_DELAY: std::time::Duration =
    std::time::Duration::from_secs(SN_DNS_CHALLENGE_TTL_SECS as u64 + 5);

pub struct AcmeSnProviderFactory;

impl AcmeSnProviderFactory {
    pub fn new() -> Arc<AcmeSnProviderFactory> {
        Arc::new(AcmeSnProviderFactory)
    }
}

#[derive(Deserialize)]
pub struct AcmdSnProviderConfig {
    pub sn: String,
    pub key_path: String,
    pub device_config_path: Option<String>,
    pub access_token: Option<String>,
}

#[async_trait::async_trait]
impl DnsProviderFactory for AcmeSnProviderFactory {
    async fn create(
        &self,
        acme_mgr: Weak<AcmeCertManager>,
        params: serde_json::Value,
    ) -> anyhow::Result<DnsProviderRef> {
        let config: AcmdSnProviderConfig = serde_json::from_value(params)
            .map_err(|_| anyhow!("invalid acme sn provider config"))?;
        let device_config_path = config.device_config_path.as_deref().ok_or_else(|| {
            anyhow!("device_config_path is required for unattended SN authentication")
        })?;
        let client = SnDeviceClient::load(
            &config.sn,
            &config.key_path,
            device_config_path,
            config.access_token,
        )
        .await?;
        Ok(Arc::new(AcmeSnProvider {
            weak_acme_mgr: acme_mgr,
            client,
        }))
    }

    fn propagation_delay(&self) -> std::time::Duration {
        SN_DNS_PROPAGATION_DELAY
    }
}

struct AcmeSnProvider {
    weak_acme_mgr: Weak<AcmeCertManager>,
    client: SnDeviceClient,
}

#[async_trait::async_trait]
impl DnsProvider for AcmeSnProvider {
    async fn call(&self, op: String, domain: String, key_hash: String) -> anyhow::Result<()> {
        let krpc = self.client.krpc_for_route("/kapi/sn/auth")?;
        if op == "add_challenge" {
            krpc.call(
                "user.add_dns_record",
                json!({
                    "device_did": self.client.did(),
                    "domain": domain,
                    "record_type": "TXT",
                    "record": key_hash,
                    "ttl": SN_DNS_CHALLENGE_TTL_SECS
                }),
            )
            .await
            .map_err(|e| anyhow!("add_dns_record failed.{:?}", e))?;
        } else if op == "del_challenge" {
            let mut has_cert = false;
            if let Some(acme_mgr) = self.weak_acme_mgr.upgrade() {
                let original = domain.replace("_acme-challenge.", "*.");
                if let Some(cert) = acme_mgr.get_cert_by_host(original.as_str()) {
                    if let Some(_) = cert.get_cert() {
                        has_cert = true;
                    }
                }
                if !has_cert {
                    let original = domain.replace("_acme-challenge.", "");
                    if let Some(cert) = acme_mgr.get_cert_by_host(original.as_str()) {
                        if let Some(_) = cert.get_cert() {
                            has_cert = true;
                        }
                    }
                }
            }
            krpc.call(
                "user.remove_dns_record",
                json!({
                    "device_did": self.client.did(),
                    "domain": domain,
                    "record_type": "TXT",
                    "record": key_hash,
                    "has_cert": has_cert,
                }),
            )
            .await
            .map_err(|e| anyhow!("remove_dns_record failed.{:?}", e))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cyfs_acme::CertManagerConfig;
    use name_lib::{DID, DeviceDocument, generate_ed25519_key_pair};

    #[tokio::test]
    async fn web3_flat_device_files_create_real_provider() {
        let temp = tempfile::tempdir().unwrap();
        let key_path = temp.path().join("sn_private_key.pem");
        let device_path = temp.path().join("sn_device_config.json");
        let (private_key, public_jwk) = generate_ed25519_key_pair();
        tokio::fs::write(&key_path, private_key).await.unwrap();

        let mut device =
            DeviceDocument::new_by_jwk("ood1", serde_json::from_value(public_jwk).unwrap());
        device.id = DID::new("web", "ood1.example.com");
        tokio::fs::write(&device_path, serde_json::to_vec_pretty(&device).unwrap())
            .await
            .unwrap();

        let mut manager_config = CertManagerConfig::default();
        manager_config.keystore_path = temp.path().join("certs").to_string_lossy().to_string();
        let manager = AcmeCertManager::create(manager_config).await.unwrap();
        let factory = AcmeSnProviderFactory::new();
        let provider = factory
            .create(
                Arc::downgrade(&manager),
                json!({
                    "sn": "http://127.0.0.1:18090/kapi/sn",
                    "key_path": key_path,
                    "device_config_path": device_path
                }),
            )
            .await;
        assert!(
            provider.is_ok(),
            "provider create failed: {:?}",
            provider.err()
        );
        assert_eq!(
            factory.propagation_delay(),
            std::time::Duration::from_secs(65)
        );
    }

    #[tokio::test]
    async fn config_errors_do_not_show_the_access_token() {
        let error = AcmeSnProviderFactory::new()
            .create(
                Weak::new(),
                json!({ "key_path": "key", "access_token": "secret-token" }),
            )
            .await
            .err()
            .unwrap();
        assert!(!format!("{error:#}").contains("secret-token"));
    }
}
