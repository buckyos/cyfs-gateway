use anyhow::anyhow;
use cyfs_gateway_api::generate_sn_device_token;
use name_lib::{
    DID, DeviceDocument, encode_ed25519_pkcs8_sk_to_pk, get_x_from_jwk, load_raw_private_key,
};
use std::path::Path;

/// Calls the SN as this device.
pub(crate) struct SnDeviceClient {
    sn: String,
    private_key: jsonwebtoken::EncodingKey,
    did: DID,
    device_scoped_did: DID,
    access_token: Option<String>,
}

fn normalize_sn_rpc_url(sn: &str) -> String {
    let sn = sn.trim().trim_end_matches('/');
    for suffix in [
        "/kapi/sn/deviceinfo",
        "/kapi/sn/auth",
        "/kapi/sn/bns",
        "/kapi/sn",
    ] {
        if let Some(base) = sn.strip_suffix(suffix) {
            return base.to_string();
        }
    }
    sn.to_string()
}

impl SnDeviceClient {
    pub async fn load(
        sn: &str,
        key_path: &str,
        device_config_path: &str,
        access_token: Option<String>,
    ) -> anyhow::Result<Self> {
        let private_key = load_raw_private_key(Path::new(key_path))
            .map_err(|_| anyhow!("load private key {} failed", key_path))?;
        let public_key = encode_ed25519_pkcs8_sk_to_pk(&private_key);

        let content = tokio::fs::read_to_string(device_config_path)
            .await
            .map_err(|e| anyhow!("load device config {} failed.{}", device_config_path, e))?;
        let device_config = serde_json::from_str::<DeviceDocument>(content.as_str())
            .map_err(|e| anyhow!("parse device config {} failed.{}", device_config_path, e))?;

        let default_key = device_config.get_default_key().ok_or(anyhow!(
            "device config {} no default key found",
            device_config_path
        ))?;
        let x_of_auth_key = get_x_from_jwk(&default_key)
            .map_err(|_e| anyhow!("device config {} has no auth key", device_config_path))?;
        if x_of_auth_key != public_key {
            return Err(anyhow!(
                "device config {} auth key not match",
                device_config_path
            ));
        }
        let did = DID::new("dev", public_key.as_str());
        let device_scoped_did = match device_config.id.method.as_str() {
            "web" | "bns" => device_config.id.clone(),
            "dev" => {
                let zone = device_config
                    .zone_did
                    .as_ref()
                    .ok_or_else(|| anyhow!("device config with did:dev id is missing zone_did"))?;
                if !matches!(zone.method.as_str(), "web" | "bns") || device_config.name.is_empty() {
                    return Err(anyhow!(
                        "cannot derive zone-scoped device DID from zone_did {:?} and name {:?}",
                        zone,
                        device_config.name
                    ));
                }
                DID::new(
                    zone.method.as_str(),
                    format!("{}.{}", device_config.name, zone.id).as_str(),
                )
            }
            method => return Err(anyhow!("unsupported device DID method {}", method)),
        };
        Ok(Self {
            sn: normalize_sn_rpc_url(sn),
            private_key: jsonwebtoken::EncodingKey::from_ed_der(private_key.as_slice()),
            did,
            device_scoped_did,
            access_token,
        })
    }

    pub fn did(&self) -> String {
        self.did.to_string()
    }

    pub fn krpc_for_route(&self, route: &str) -> anyhow::Result<kRPC::kRPC> {
        let token = if let Some(access_token) = self.access_token.clone() {
            access_token
        } else {
            generate_sn_device_token(
                self.did.to_string().as_str(),
                self.device_scoped_did.to_string().as_str(),
                None,
                &self.private_key,
            )
            .map_err(|e| anyhow!("generate SN device token failed: {}", e))?
        };
        let url = format!(
            "{}/{}",
            self.sn.trim_end_matches('/'),
            route.trim_start_matches('/')
        );
        Ok(kRPC::kRPC::new(url.as_str(), Some(token)))
    }
}
