//! Certificates issued on the spot for the tests.
use openssl::asn1::{Asn1Object, Asn1OctetString, Asn1Time};
use openssl::bn::{BigNum, MsbOption};
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{Id, PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509::extension::{
    AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName,
    SubjectKeyIdentifier,
};
use openssl::x509::{X509, X509Extension, X509Name, X509NameBuilder};

pub(crate) const DAY: i64 = 24 * 3600;

pub(crate) struct Issued {
    pub cert: X509,
    pub key: PKey<Private>,
}

impl Issued {
    pub fn pem(&self) -> Vec<u8> {
        self.cert.to_pem().unwrap()
    }

    pub fn key_pem(&self) -> Vec<u8> {
        self.key.private_key_to_pem_pkcs8().unwrap()
    }
}

pub(crate) fn ec_key(curve: Nid) -> PKey<Private> {
    let group = EcGroup::from_curve_name(curve).unwrap();
    PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
}

pub(crate) fn p256() -> PKey<Private> {
    ec_key(Nid::X9_62_PRIME256V1)
}

pub(crate) fn rsa_key(bits: u32) -> PKey<Private> {
    PKey::from_rsa(Rsa::generate(bits).unwrap()).unwrap()
}

pub(crate) fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

pub(crate) struct Spec {
    pub common_name: String,
    pub dns: Vec<String>,
    pub key: PKey<Private>,
    pub not_before: i64,
    pub not_after: i64,
    pub ca: Option<bool>,
    pub server_auth: Option<bool>,
    pub ev: bool,
}

impl Spec {
    pub fn leaf(dns: &[&str]) -> Self {
        Self {
            common_name: "leaf".to_string(),
            dns: dns.iter().map(|name| name.to_string()).collect(),
            key: p256(),
            not_before: now() - DAY,
            not_after: now() + 90 * DAY,
            ca: Some(false),
            server_auth: Some(true),
            ev: false,
        }
    }

    pub fn ca(common_name: &str) -> Self {
        Self {
            common_name: common_name.to_string(),
            ca: Some(true),
            server_auth: None,
            not_before: now() - 365 * DAY,
            not_after: now() + 3650 * DAY,
            ..Self::leaf(&[])
        }
    }

    pub fn self_signed(self) -> Issued {
        self.build(None)
    }

    pub fn issued_by(self, issuer: &Issued) -> Issued {
        self.build(Some(issuer))
    }

    fn build(self, issuer: Option<&Issued>) -> Issued {
        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        let mut serial = BigNum::new().unwrap();
        serial.rand(64, MsbOption::MAYBE_ZERO, false).unwrap();
        builder
            .set_serial_number(&serial.to_asn1_integer().unwrap())
            .unwrap();
        let subject = name(&self.common_name);
        builder.set_subject_name(&subject).unwrap();
        builder
            .set_issuer_name(issuer.map_or(&*subject, |issuer| issuer.cert.subject_name()))
            .unwrap();
        builder.set_pubkey(&self.key).unwrap();
        builder
            .set_not_before(&Asn1Time::from_unix(self.not_before).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::from_unix(self.not_after).unwrap())
            .unwrap();
        if let Some(ca) = self.ca {
            let mut constraints = BasicConstraints::new();
            constraints.critical();
            if ca {
                constraints.ca();
                builder
                    .append_extension(
                        KeyUsage::new()
                            .critical()
                            .key_cert_sign()
                            .crl_sign()
                            .build()
                            .unwrap(),
                    )
                    .unwrap();
            }
            builder
                .append_extension(constraints.build().unwrap())
                .unwrap();
        }
        if let Some(server_auth) = self.server_auth {
            let mut eku = ExtendedKeyUsage::new();
            if server_auth {
                eku.server_auth();
            } else {
                eku.client_auth();
            }
            builder.append_extension(eku.build().unwrap()).unwrap();
        }
        if !self.dns.is_empty() {
            let mut san = SubjectAlternativeName::new();
            for name in &self.dns {
                san.dns(name);
            }
            let san = san
                .build(&builder.x509v3_context(issuer.map(|issuer| &*issuer.cert), None))
                .unwrap();
            builder.append_extension(san).unwrap();
        }
        if self.ev {
            // SEQUENCE { SEQUENCE { OID 2.23.140.1.1 } }
            let policies = Asn1OctetString::new_from_bytes(&[
                0x30, 0x09, 0x30, 0x07, 0x06, 0x05, 0x67, 0x81, 0x0c, 0x01, 0x01,
            ])
            .unwrap();
            let oid = Asn1Object::from_str("2.5.29.32").unwrap();
            builder
                .append_extension(X509Extension::new_from_der(&oid, false, &policies).unwrap())
                .unwrap();
        }
        let key_id = SubjectKeyIdentifier::new()
            .build(&builder.x509v3_context(issuer.map(|issuer| &*issuer.cert), None))
            .unwrap();
        builder.append_extension(key_id).unwrap();
        if let Some(issuer) = issuer {
            let authority = AuthorityKeyIdentifier::new()
                .keyid(true)
                .build(&builder.x509v3_context(Some(&issuer.cert), None))
                .unwrap();
            builder.append_extension(authority).unwrap();
        }
        let signer = issuer.map_or(&self.key, |issuer| &issuer.key);
        let digest = if matches!(signer.id(), Id::ED25519) {
            MessageDigest::null()
        } else {
            MessageDigest::sha256()
        };
        builder.sign(signer, digest).unwrap();
        Issued {
            cert: builder.build(),
            key: self.key,
        }
    }
}

fn name(common_name: &str) -> X509Name {
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("O", "Test").unwrap();
    name.append_entry_by_text("CN", common_name).unwrap();
    name.build()
}

/// Root and intermediate; `roots` trusts the root only.
pub(crate) struct TestCa {
    pub root: Issued,
    pub intermediate: Issued,
}

impl TestCa {
    pub fn new() -> Self {
        let root = Spec::ca("Root").self_signed();
        let intermediate = Spec::ca("Intermediate").issued_by(&root);
        Self { root, intermediate }
    }

    pub fn roots(&self) -> crate::TrustRoots {
        crate::TrustRoots::from_der([self.root.cert.to_der().unwrap().as_slice()])
    }

    pub fn issue(&self, dns: &[&str]) -> Issued {
        Spec::leaf(dns).issued_by(&self.intermediate)
    }
}
