use anyhow::Result;
use openssl::asn1::Asn1TimeRef;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{HasPublic, Id, PKeyRef};
use openssl::stack::Stack;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::verify::X509VerifyParam;
use openssl::x509::{X509, X509NameRef, X509Ref, X509StoreContext, X509VerifyResult};
use sha2::Digest;
use x509_parser::extensions::ParsedExtension;
use x509_parser::prelude::{FromDer, X509Certificate};

/// CA/Browser Forum EV policy.
const EV_POLICY_OID: &str = "2.23.140.1.1";

/// Public facts of a certificate, enough to show it.
#[derive(Clone, Debug, PartialEq)]
pub struct CertificateSummary {
    /// Unix seconds.
    pub not_before: u64,
    pub not_after: u64,
    pub issuer: String,
    pub dns_names: Vec<String>,
    /// `sha256:<hex>` of the DER.
    pub fingerprint: String,
}

pub fn certificate_summary(der: &[u8]) -> Result<CertificateSummary> {
    let cert = X509::from_der(der)?;
    summarize(&cert)
}

pub(crate) fn summarize(cert: &X509Ref) -> Result<CertificateSummary> {
    Ok(CertificateSummary {
        not_before: unix_seconds(cert.not_before())?,
        not_after: unix_seconds(cert.not_after())?,
        issuer: x509_name_to_string(cert.issuer_name()),
        dns_names: cert_dns_names(cert),
        fingerprint: cert_fingerprint_sha256(cert)?,
    })
}

/// The CAs a certificate has to chain to in order to count as publicly trusted.
pub struct TrustRoots {
    certificates: Vec<X509>,
}

impl TrustRoots {
    /// The system's roots. One that cannot be read or is expired is left out
    /// instead of failing the whole check.
    pub fn system() -> Self {
        let loaded = rustls_native_certs::load_native_certs();
        for error in &loaded.errors {
            log::warn!("load system root certificates: {}", error);
        }
        Self::from_der(loaded.certs.iter().map(|cert| cert.as_ref()))
    }

    pub fn from_der<'a>(certificates: impl IntoIterator<Item = &'a [u8]>) -> Self {
        let now = chrono::Utc::now();
        Self {
            certificates: certificates
                .into_iter()
                .filter_map(|der| X509::from_der(der).ok())
                .filter(|cert| asn1_time_to_utc(cert.not_after()).is_ok_and(|end| now < end))
                .collect(),
        }
    }

    /// `leaf` chains to one of these roots through `intermediates` at `time`
    /// (Unix seconds).
    pub(crate) fn verifies(&self, leaf: &X509, intermediates: &[X509], time: i64) -> bool {
        let verify = || -> Result<bool> {
            let mut store = X509StoreBuilder::new()?;
            for root in &self.certificates {
                store.add_cert(root.clone())?;
            }
            let mut param = X509VerifyParam::new()?;
            param.set_time(time.try_into()?);
            store.set_param(&param)?;
            let store = store.build();
            let mut chain = Stack::new()?;
            for cert in intermediates {
                chain.push(cert.clone())?;
            }
            let mut context = X509StoreContext::new()?;
            Ok(context.init(&store, leaf, &chain, |context| context.verify_cert())?)
        };
        verify().unwrap_or(false)
    }
}

/// What the extensions say about a certificate's use.
#[derive(Clone, Debug, Default)]
pub(crate) struct CertUsage {
    pub is_ca: bool,
    /// False only when usages are declared and server authentication is not among them.
    pub server_auth: bool,
    pub is_ev: bool,
}

pub(crate) fn cert_usage(cert: &X509Ref) -> Result<CertUsage> {
    let der = cert.to_der()?;
    let (_, parsed) =
        X509Certificate::from_der(&der).map_err(|e| anyhow::anyhow!("parse certificate: {}", e))?;
    let mut usage = CertUsage {
        server_auth: true,
        ..CertUsage::default()
    };
    for extension in parsed.extensions() {
        match extension.parsed_extension() {
            ParsedExtension::BasicConstraints(constraints) => usage.is_ca = constraints.ca,
            ParsedExtension::ExtendedKeyUsage(eku) => {
                usage.server_auth = eku.server_auth || eku.any;
            }
            ParsedExtension::CertificatePolicies(policies) => {
                usage.is_ev = policies
                    .iter()
                    .any(|policy| policy.policy_id.to_id_string() == EV_POLICY_OID);
            }
            _ => {}
        }
    }
    Ok(usage)
}

pub(crate) fn is_self_signed(cert: &X509Ref) -> bool {
    cert.subject_name()
        .try_cmp(cert.issuer_name())
        .is_ok_and(|order| order.is_eq())
        && cert
            .public_key()
            .and_then(|key| cert.verify(&key))
            .unwrap_or(false)
}

/// The intermediates above `leaf`, nearest first, taken from `pool`. Roots are dropped.
pub(crate) fn build_chain(leaf: &X509Ref, pool: &[X509], now: u64) -> Vec<X509> {
    let mut chain: Vec<X509> = Vec::new();
    let mut current = leaf.to_owned();
    while !is_self_signed(&current) {
        let next = pool
            .iter()
            .filter(|candidate| {
                !same_certificate(candidate, leaf)
                    && !chain.iter().any(|cert| same_certificate(cert, candidate))
                    && !is_self_signed(candidate)
                    && candidate.issued(&current) == X509VerifyResult::OK
                    && candidate
                        .public_key()
                        .and_then(|key| current.verify(&key))
                        .unwrap_or(false)
            })
            .max_by_key(|candidate| {
                let not_after = unix_seconds(candidate.not_after()).unwrap_or(0);
                (now < not_after, not_after)
            });
        let Some(next) = next else {
            break;
        };
        chain.push(next.to_owned());
        current = next.to_owned();
    }
    chain
}

pub(crate) fn same_certificate(a: &X509Ref, b: &X509Ref) -> bool {
    match (a.to_der(), b.to_der()) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

/// `RSA 2048`, `EC P-256`, …
pub(crate) fn key_label<T: HasPublic>(key: &PKeyRef<T>) -> String {
    match key.id() {
        Id::RSA => format!("RSA {}", key.bits()),
        Id::RSA_PSS => format!("RSA-PSS {}", key.bits()),
        Id::EC => {
            let curve = key.ec_key().ok().and_then(|key| key.group().curve_name());
            match curve {
                Some(Nid::X9_62_PRIME256V1) => "EC P-256".to_string(),
                Some(Nid::SECP384R1) => "EC P-384".to_string(),
                Some(Nid::SECP521R1) => "EC P-521".to_string(),
                Some(curve) => format!("EC {}", curve.short_name().unwrap_or("unknown")),
                None => "EC".to_string(),
            }
        }
        Id::ED25519 => "Ed25519".to_string(),
        Id::ED448 => "Ed448".to_string(),
        Id::DSA => "DSA".to_string(),
        _ => "unknown".to_string(),
    }
}

pub(crate) fn cert_dns_names(cert: &X509Ref) -> Vec<String> {
    cert.subject_alt_names()
        .map(|names| {
            names
                .iter()
                .filter_map(|name| name.dnsname().map(ToOwned::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) fn cert_uri_names(cert: &X509Ref) -> Vec<String> {
    cert.subject_alt_names()
        .map(|names| {
            names
                .iter()
                .filter_map(|name| name.uri().map(ToOwned::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) fn dns_san_matches(pattern: &str, host: &str) -> bool {
    if pattern.eq_ignore_ascii_case(host) {
        return true;
    }

    let Some(suffix) = pattern.strip_prefix("*.") else {
        return false;
    };
    let host = host.to_ascii_lowercase();
    let suffix = suffix.to_ascii_lowercase();
    if host == suffix || !host.ends_with(&suffix) {
        return false;
    }
    let prefix_len = host.len() - suffix.len();
    prefix_len > 1
        && host.as_bytes()[prefix_len - 1] == b'.'
        && !host[..prefix_len - 1].contains('.')
}

pub(crate) fn cert_fingerprint_sha256(cert: &X509Ref) -> Result<String> {
    let digest = cert.digest(MessageDigest::sha256())?;
    Ok(format!("sha256:{}", hex::encode(digest)))
}

pub(crate) fn public_key_fingerprint(cert: &X509Ref) -> Result<String> {
    let public_key = cert.public_key()?;
    let der = public_key.public_key_to_der()?;
    Ok(format!(
        "sha256:{}",
        hex::encode(sha2::Sha256::digest(&der))
    ))
}

pub(crate) fn asn1_time_to_utc(time: &Asn1TimeRef) -> Result<chrono::DateTime<chrono::Utc>> {
    let raw = time.to_string();
    let datetime_str = raw
        .rsplit_once(' ')
        .map(|(datetime, _)| datetime)
        .ok_or_else(|| anyhow::anyhow!("Invalid ASN.1 datetime format: {}", raw))?;
    let expires = chrono::NaiveDateTime::parse_from_str(datetime_str, "%b %e %H:%M:%S %Y")?;
    Ok(chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(
        expires,
        chrono::Utc,
    ))
}

pub(crate) fn unix_seconds(time: &Asn1TimeRef) -> Result<u64> {
    Ok(asn1_time_to_utc(time)?.timestamp().max(0) as u64)
}

pub(crate) fn x509_name_to_string(name: &X509NameRef) -> String {
    name.entries()
        .map(|entry| {
            let key = entry.object().nid().short_name().unwrap_or("OID");
            let value = entry
                .data()
                .to_string()
                .unwrap_or_else(|_| hex::encode(entry.data().as_slice()));
            format!("{key}={value}")
        })
        .collect::<Vec<_>>()
        .join(",")
}
