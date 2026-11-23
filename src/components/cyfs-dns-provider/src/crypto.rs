use openssl::hash::{MessageDigest, hash};
use openssl::pkey::PKey;
use openssl::sign::Signer;

use crate::provider::{DnsProviderError, DnsProviderResult};

fn failed(error: openssl::error::ErrorStack) -> DnsProviderError {
    DnsProviderError::Api(format!("crypto: {error}"))
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(crate) fn sha1(data: &[u8]) -> DnsProviderResult<Vec<u8>> {
    Ok(hash(MessageDigest::sha1(), data).map_err(failed)?.to_vec())
}

pub(crate) fn sha256(data: &[u8]) -> DnsProviderResult<Vec<u8>> {
    Ok(hash(MessageDigest::sha256(), data)
        .map_err(failed)?
        .to_vec())
}

pub(crate) fn hmac(digest: MessageDigest, key: &[u8], data: &[u8]) -> DnsProviderResult<Vec<u8>> {
    let key = PKey::hmac(key).map_err(failed)?;
    let mut signer = Signer::new(digest, &key).map_err(failed)?;
    signer.sign_oneshot_to_vec(data).map_err(failed)
}

/// PKCS#1 v1.5 signature with a PEM private key.
pub(crate) fn rsa_sign(
    digest: MessageDigest,
    pem: &str,
    data: &[u8],
) -> DnsProviderResult<Vec<u8>> {
    let key = PKey::private_key_from_pem(pem.trim().as_bytes())
        .map_err(|_| DnsProviderError::InvalidCredential("not a PEM private key".to_string()))?;
    let mut signer = Signer::new(digest, &key)
        .map_err(|_| DnsProviderError::InvalidCredential("not an RSA private key".to_string()))?;
    signer.sign_oneshot_to_vec(data).map_err(failed)
}

pub(crate) fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    openssl::rand::rand_bytes(&mut bytes).expect("system random source");
    bytes
}

/// RFC 6238 with SHA-1, 6 digits.
pub(crate) fn totp(shared_secret: &str, step: u64) -> DnsProviderResult<String> {
    let invalid =
        || DnsProviderError::InvalidCredential("the shared secret is not base32".to_string());
    let mut bits = 0u64;
    let mut count = 0;
    let mut key = Vec::new();
    for ch in shared_secret.chars() {
        let value = match ch.to_ascii_uppercase() {
            letter @ 'A'..='Z' => letter as u64 - 'A' as u64,
            digit @ '2'..='7' => digit as u64 - '2' as u64 + 26,
            ' ' | '-' | '=' => continue,
            _ => return Err(invalid()),
        };
        bits = (bits << 5) | value;
        count += 5;
        if count >= 8 {
            count -= 8;
            key.push((bits >> count) as u8);
        }
    }
    if key.is_empty() {
        return Err(invalid());
    }
    let mac = hmac(MessageDigest::sha1(), &key, &step.to_be_bytes())?;
    let offset = usize::from(mac[mac.len() - 1] & 0x0f);
    let code = u32::from_be_bytes([
        mac[offset] & 0x7f,
        mac[offset + 1],
        mac[offset + 2],
        mac[offset + 3],
    ]);
    Ok(format!("{:06}", code % 1_000_000))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn totp_rfc6238() {
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        assert_eq!(totp(secret, 59 / 30).unwrap(), "287082");
        assert_eq!(totp(secret, 1111111109 / 30).unwrap(), "081804");
        assert!(totp("!!", 1).is_err());
    }
}
