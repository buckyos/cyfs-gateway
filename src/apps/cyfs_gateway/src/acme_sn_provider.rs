use std::path::Path;
use std::sync::{Arc, Mutex, Weak};
use anyhow::anyhow;
use kRPC::RPCSessionToken;
use name_lib::{encode_ed25519_pkcs8_sk_to_pk, get_x_from_jwk, load_raw_private_key, DeviceConfig, DID};
use serde::Deserialize;
use serde_json::json;
use cyfs_gateway_lib::{AcmeCertManagerHolder, AcmeCertManagerRef, DnsProvider, DnsProviderFactory, DnsProviderRef, RtcpStackConfig, StackProtocol};

pub struct AcmeSnProviderFactory {
    weak_acme_mgr: Arc<Mutex<Option<Weak<AcmeCertManagerHolder>>>>,
}

impl AcmeSnProviderFactory {
    pub fn new() -> Arc<AcmeSnProviderFactory> {
        Arc::new(AcmeSnProviderFactory {
            weak_acme_mgr: Arc::new(Mutex::new(None))
        })
    }

    pub fn set_acme_mgr(&self, acme_mgr: AcmeCertManagerRef) {
        *self.weak_acme_mgr.lock().unwrap() = Some(Arc::downgrade(&acme_mgr));
    }
}

#[derive(Deserialize)]
pub struct AcmdSnProviderConfig {
    pub sn: String,
    pub key_path: String,
    pub device_config_path: Option<String>,
}

#[async_trait::async_trait]
impl DnsProviderFactory for AcmeSnProviderFactory {
    async fn create(&self, params: serde_json::Value) -> anyhow::Result<DnsProviderRef> {
        let config: AcmdSnProviderConfig = serde_json::from_value(params.clone())
            .map_err(|_| anyhow!("invalid acme sn provider config.{}", params.to_string()))?;

        let private_key = load_raw_private_key(Path::new(config.key_path.as_str()))
            .map_err(|_| anyhow!("load private key {} failed", config.key_path))?;
        let public_key = encode_ed25519_pkcs8_sk_to_pk(&private_key);

        let device_config = if config.device_config_path.is_some() {
            let content = tokio::fs::read_to_string(config.device_config_path.as_ref().unwrap()).await
                .map_err(|e| anyhow!("load device config {} failed.{}", config.device_config_path.as_ref().unwrap(), e))?;
            let device_config = serde_json::from_str::<DeviceConfig>(content.as_str())
                .map_err(|e| anyhow!("parse device config {} failed.{}", config.device_config_path.as_ref().unwrap(), e))?;

            let default_key = device_config.get_default_key().ok_or(anyhow!(
                "device config {} no default key found",
                config.device_config_path.as_ref().unwrap()
            ))?;
            let x_of_auth_key = get_x_from_jwk(&default_key).map_err(|_e| {
                anyhow!(
                    "device config {} has no auth key",
                    config.device_config_path.as_ref().unwrap()
                )
            })?;
            if x_of_auth_key != public_key {
                return Err(anyhow!(
                    "device config {} auth key not match",
                    config.device_config_path.as_ref().unwrap()
                ));
            }
            device_config
        } else {
            DeviceConfig::new("cyfs_gateway", public_key)
        };
        let private_key = jsonwebtoken::EncodingKey::from_ed_der(private_key.as_slice());

        Ok(Arc::new(AcmeSnProvider::new(self.weak_acme_mgr.clone(), config.sn, private_key, device_config.id, device_config.name)))
    }
}

struct AcmeSnProvider {
    weak_acme_mgr: Arc<Mutex<Option<Weak<AcmeCertManagerHolder>>>>,
    sn: String,
    private_key: jsonwebtoken::EncodingKey,
    did: DID,
    user_name: String,
}

impl AcmeSnProvider {
    pub fn new(
        weak_acme_mgr: Arc<Mutex<Option<Weak<AcmeCertManagerHolder>>>>,
        sn: String,
        private_key: jsonwebtoken::EncodingKey,
        did: DID,
        user_name: String) -> AcmeSnProvider {
        AcmeSnProvider {
            weak_acme_mgr,
            sn,
            private_key,
            did,
            user_name,
        }
    }
}

#[async_trait::async_trait]
impl DnsProvider for AcmeSnProvider {
    async fn call(&self, op: String, domain: String, key_hash: String) -> anyhow::Result<()> {
        let (token, _) = RPCSessionToken::generate_jwt_token(self.user_name.as_str(), "cyfs_gateway", None, &self.private_key)
            .map_err(|_| anyhow!("generate jwt token failed"))?;
        let krpc = kRPC::kRPC::new(self.sn.as_str(), Some(token));
        if op == "add_challenge" {
            krpc.call("add_dns_record", json!({
                            "device_did": self.did.to_string(),
                            "domain": domain,
                            "record_type": "TXT",
                            "record": key_hash,
                            "ttl": 600
                        })).await.map_err(|e| anyhow!("add_dns_record failed.{:?}", e))?;
        } else if op == "del_challenge" {
            let mut has_cert = false;
            let weak_acme_mgr = {
                self.weak_acme_mgr.lock().unwrap().clone()
            };
            if let Some(weak_acme_mgr) = weak_acme_mgr {
                if let Some(acme_mgr) = weak_acme_mgr.upgrade() {
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
            }
            krpc.call("remove_dns_record", json!({
                            "device_did": self.did.to_string(),
                            "domain": domain,
                            "record_type": "TXT",
                            "has_cert": has_cert,
                        })).await.map_err(|e| anyhow!("add_dns_record failed.{:?}", e))?;
        }
        Ok(())
    }
}