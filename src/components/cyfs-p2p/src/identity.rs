use bucky_raw_codec::{RawConvertTo, RawDecode, RawEncode, RawFrom};
use name_lib::{get_x_from_jwk, DeviceConfig};
use p2p_frame::endpoint::Endpoint;
use p2p_frame::error::{into_p2p_err, p2p_err, P2pErrorCode, P2pResult};
use p2p_frame::p2p_identity::{
    EncodedP2pIdentity, EncodedP2pIdentityCert, P2pId, P2pIdentity, P2pIdentityCert,
    P2pIdentityCertFactory, P2pIdentityCertRef, P2pIdentityFactory, P2pIdentityRef,
    P2pIdentitySignType, P2pSignature, P2pSn,
};
use p2p_frame::x509::{X509IdentityCert, X509IdentityFactory};
use ring::signature::{self, Ed25519KeyPair};
use serde::{Deserialize, Serialize};
use std::io::Cursor;
use std::path::Path;
use std::sync::Arc;

#[derive(Clone, RawEncode, RawDecode)]
struct EncodedX509IdentityCertData {
    raw_cert: Vec<u8>,
    sn_list: Vec<P2pSn>,
    endpoints: Vec<Endpoint>,
}

#[derive(Clone, RawEncode, RawDecode)]
struct EncodedX509IdentityData {
    key: Vec<u8>,
    cert: EncodedX509IdentityCertData,
}

#[derive(Serialize, Deserialize)]
struct DeviceIdentityData {
    private_key: Vec<u8>,
    device_config: DeviceConfig,
}

pub struct DeviceIdentityCert {
    device_config: DeviceConfig,
    encoded_cert: EncodedP2pIdentityCert,
}

impl DeviceIdentityCert {
    pub fn new(device_config: DeviceConfig) -> P2pResult<Self> {
        let encoded_cert = serde_json::to_vec(&device_config).map_err(|e| {
            p2p_err!(
                P2pErrorCode::CertError,
                "encode device config failed: {}",
                e
            )
        })?;
        Ok(Self {
            device_config,
            encoded_cert,
        })
    }

    fn get_public_key_bytes(&self) -> P2pResult<Vec<u8>> {
        let default_key = self.device_config.get_default_key().ok_or(p2p_err!(
            P2pErrorCode::CertError,
            "device config has no default key"
        ))?;
        let x = get_x_from_jwk(&default_key).map_err(into_p2p_err!(
            P2pErrorCode::CertError,
            "get x from jwk failed"
        ))?;
        hex::decode(x).map_err(into_p2p_err!(
            P2pErrorCode::CertError,
            "decode hex public key failed"
        ))
    }
}

impl P2pIdentityCert for DeviceIdentityCert {
    fn get_id(&self) -> P2pId {
        P2pId::from(self.device_config.id.to_string().as_bytes().to_vec())
    }

    fn get_name(&self) -> String {
        self.device_config.name.clone()
    }

    fn sign_type(&self) -> P2pIdentitySignType {
        P2pIdentitySignType::Ed25519
    }

    fn verify(&self, message: &[u8], sign: &P2pSignature) -> bool {
        let public_key_bytes = match self.get_public_key_bytes() {
            Ok(pk) => pk,
            Err(_) => return false,
        };

        signature::UnparsedPublicKey::new(&signature::ED25519, &public_key_bytes)
            .verify(message, sign.as_slice())
            .is_ok()
    }

    fn verify_cert(&self, name: &str) -> bool {
        if self.device_config.name.as_str() != name {
            return false;
        }
        true
    }

    fn get_encoded_cert(&self) -> P2pResult<EncodedP2pIdentityCert> {
        Ok(self.encoded_cert.clone())
    }

    fn endpoints(&self) -> Vec<p2p_frame::endpoint::Endpoint> {
        Vec::new()
    }

    fn sn_list(&self) -> Vec<P2pSn> {
        Vec::new()
    }

    fn update_endpoints(&self, _eps: Vec<p2p_frame::endpoint::Endpoint>) -> P2pIdentityCertRef {
        Arc::new(Self {
            device_config: self.device_config.clone(),
            encoded_cert: self.encoded_cert.clone(),
        })
    }
}

pub struct DeviceIdentity {
    device_config: DeviceConfig,
    private_key: Vec<u8>,
    encoded_identity: EncodedP2pIdentity,
}

impl DeviceIdentity {
    pub fn new(device_config: DeviceConfig, private_key: Vec<u8>) -> P2pResult<Self> {
        let _key = Ed25519KeyPair::from_pkcs8(private_key.as_slice())
            .or_else(|_| Ed25519KeyPair::from_pkcs8_maybe_unchecked(private_key.as_slice()))
            .map_err(|e| p2p_err!(P2pErrorCode::CertError, "load ed25519 key failed: {:?}", e))?;

        let data = DeviceIdentityData {
            private_key: private_key.clone(),
            device_config: device_config.clone(),
        };
        let encoded_identity = serde_json::to_vec(&data).map_err(|e| {
            p2p_err!(
                P2pErrorCode::CertError,
                "encode identity data failed: {}",
                e
            )
        })?;

        Ok(Self {
            device_config,
            private_key,
            encoded_identity,
        })
    }

    fn sign(&self, message: &[u8]) -> P2pResult<P2pSignature> {
        let key = Ed25519KeyPair::from_pkcs8(self.private_key.as_slice())
            .or_else(|_| Ed25519KeyPair::from_pkcs8_maybe_unchecked(self.private_key.as_slice()))
            .map_err(|e| p2p_err!(P2pErrorCode::CertError, "load ed25519 key failed: {:?}", e))?;
        Ok(key.sign(message).as_ref().to_vec())
    }
}

impl P2pIdentity for DeviceIdentity {
    fn get_identity_cert(&self) -> P2pResult<P2pIdentityCertRef> {
        Ok(Arc::new(DeviceIdentityCert::new(
            self.device_config.clone(),
        )?))
    }

    fn get_id(&self) -> P2pId {
        P2pId::from(self.device_config.id.to_string().as_bytes().to_vec())
    }

    fn get_name(&self) -> String {
        self.get_id().to_string()
    }

    fn sign_type(&self) -> P2pIdentitySignType {
        P2pIdentitySignType::Ed25519
    }

    fn sign(&self, message: &[u8]) -> P2pResult<P2pSignature> {
        self.sign(message)
    }

    fn get_encoded_identity(&self) -> P2pResult<EncodedP2pIdentity> {
        Ok(self.encoded_identity.clone())
    }

    fn endpoints(&self) -> Vec<p2p_frame::endpoint::Endpoint> {
        Vec::new()
    }

    fn update_endpoints(&self, _eps: Vec<p2p_frame::endpoint::Endpoint>) -> P2pIdentityRef {
        Arc::new(Self {
            device_config: self.device_config.clone(),
            private_key: self.private_key.clone(),
            encoded_identity: self.encoded_identity.clone(),
        })
    }
}

pub struct DeviceIdentityFactory;

impl P2pIdentityFactory for DeviceIdentityFactory {
    fn create(&self, id: &EncodedP2pIdentity) -> P2pResult<P2pIdentityRef> {
        let data: DeviceIdentityData = serde_json::from_slice(id.as_slice())
            .map_err(|e| p2p_err!(P2pErrorCode::CertError, "decode identity failed: {}", e))?;

        let identity = DeviceIdentity::new(data.device_config, data.private_key)?;
        Ok(Arc::new(identity))
    }
}

pub struct DeviceIdentityCertFactory;

impl P2pIdentityCertFactory for DeviceIdentityCertFactory {
    fn create(&self, cert: &EncodedP2pIdentityCert) -> P2pResult<P2pIdentityCertRef> {
        let device_config: DeviceConfig = serde_json::from_slice(cert.as_slice()).map_err(|e| {
            p2p_err!(
                P2pErrorCode::CertError,
                "decode device config failed: {}",
                e
            )
        })?;
        Ok(Arc::new(DeviceIdentityCert::new(device_config)?))
    }
}

pub fn load_x509_identity_from_paths(
    cert_path: &Path,
    key_path: &Path,
    sn_list: Vec<P2pSn>,
    endpoints: Vec<Endpoint>,
) -> P2pResult<P2pIdentityRef> {
    let cert_pem = std::fs::read(cert_path).map_err(into_p2p_err!(
        P2pErrorCode::IoError,
        "read cert {} failed",
        cert_path.display()
    ))?;
    let key_pem = std::fs::read(key_path).map_err(into_p2p_err!(
        P2pErrorCode::IoError,
        "read key {} failed",
        key_path.display()
    ))?;
    let raw_key = load_pkcs8_private_key(&key_pem, key_path)?;

    load_x509_identity_from_pem(cert_pem.as_slice(), raw_key, sn_list, endpoints)
}

pub fn load_x509_identity_from_pem(
    cert_pem: &[u8],
    raw_key: Vec<u8>,
    sn_list: Vec<P2pSn>,
    endpoints: Vec<Endpoint>,
) -> P2pResult<P2pIdentityRef> {
    let mut cert = X509IdentityCert::from_pem(cert_pem)?;
    cert.set_sn_list(sn_list);
    cert.set_endpoints(endpoints);
    let cert_data = EncodedX509IdentityCertData::clone_from_slice(&cert.get_encoded_cert()?)
        .map_err(into_p2p_err!(P2pErrorCode::RawCodecError))?;

    let encoded = EncodedX509IdentityData {
        key: raw_key,
        cert: cert_data,
    }
    .to_vec()
    .map_err(into_p2p_err!(P2pErrorCode::RawCodecError))?;

    X509IdentityFactory.create(&encoded)
}

pub fn generate_rsa_x509_key_to_files(
    name: &str,
    cert_path: &Path,
    key_path: &Path,
) -> P2pResult<P2pId> {
    use rcgen::{CertificateParams, KeyPair, PKCS_RSA_SHA256};
    use sha2::Digest;

    let key_pair = KeyPair::generate_for(&PKCS_RSA_SHA256)
        .map_err(into_p2p_err!(P2pErrorCode::CertError, "generate RSA key failed"))?;

    let mut sha256 = sha2::Sha256::new();
    sha256.update(key_pair.public_key_raw());
    let p2p_id = P2pId::from(sha256.finalize().as_slice());

    let params = CertificateParams::new(vec![name.to_string()])
        .map_err(into_p2p_err!(P2pErrorCode::CertError, "create cert params failed"))?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(into_p2p_err!(P2pErrorCode::CertError, "self sign cert failed"))?;

    std::fs::write(cert_path, cert.pem().as_bytes()).map_err(into_p2p_err!(
        P2pErrorCode::IoError,
        "write cert to {} failed",
        cert_path.display()
    ))?;
    std::fs::write(key_path, key_pair.serialize_pem().as_bytes()).map_err(into_p2p_err!(
        P2pErrorCode::IoError,
        "write key to {} failed",
        key_path.display()
    ))?;

    Ok(p2p_id)
}

pub fn generate_ed25519_x509_key_to_files(
    name: &str,
    cert_path: &Path,
    key_path: &Path,
) -> P2pResult<P2pId> {
    use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};
    use sha2::Digest;

    let key_pair = KeyPair::generate_for(&PKCS_ED25519)
        .map_err(into_p2p_err!(P2pErrorCode::CertError, "generate Ed25519 key failed"))?;

    let mut sha256 = sha2::Sha256::new();
    sha256.update(key_pair.public_key_raw());
    let p2p_id = P2pId::from(sha256.finalize().as_slice());

    let params = CertificateParams::new(vec![name.to_string()])
        .map_err(into_p2p_err!(P2pErrorCode::CertError, "create cert params failed"))?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(into_p2p_err!(P2pErrorCode::CertError, "self sign cert failed"))?;

    std::fs::write(cert_path, cert.pem().as_bytes()).map_err(into_p2p_err!(
        P2pErrorCode::IoError,
        "write cert to {} failed",
        cert_path.display()
    ))?;
    std::fs::write(key_path, key_pair.serialize_pem().as_bytes()).map_err(into_p2p_err!(
        P2pErrorCode::IoError,
        "write key to {} failed",
        key_path.display()
    ))?;

    Ok(p2p_id)
}

fn load_pkcs8_private_key(key_pem: &[u8], key_path: &Path) -> P2pResult<Vec<u8>> {
    let mut keys = Vec::new();
    for key in rustls_pemfile::pkcs8_private_keys(&mut Cursor::new(key_pem)) {
        keys.push(key.map_err(into_p2p_err!(
            P2pErrorCode::InvalidData,
            "load key {} failed",
            key_path.display()
        ))?);
    }

    if keys.is_empty() {
        return Err(p2p_err!(
            P2pErrorCode::InvalidParam,
            "no pkcs8 key found in {}",
            key_path.display()
        ));
    }

    Ok(keys.into_iter().next().unwrap().secret_pkcs8_der().to_vec())
}
