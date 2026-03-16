use bucky_raw_codec::{RawConvertTo, RawDecode, RawEncode, RawFrom};
use p2p_frame::endpoint::Endpoint;
use p2p_frame::error::{P2pErrorCode, P2pResult, into_p2p_err, p2p_err};
use p2p_frame::p2p_identity::{P2pIdentityCert, P2pIdentityFactory, P2pIdentityRef, P2pSn};
use p2p_frame::x509::{X509IdentityCert, X509IdentityFactory};
use std::io::Cursor;
use std::path::Path;

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
