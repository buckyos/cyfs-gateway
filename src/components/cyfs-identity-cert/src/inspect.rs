use openssl::pkey::{Id, PKey, Private};
use openssl::x509::X509;
use rustls::crypto::ring::sign::any_supported_type;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::ParsedCertificate;
use serde::{Deserialize, Serialize};

use crate::parse::parse_input;
use crate::x509::{
    CertUsage, CertificateSummary, TrustRoots, build_chain, cert_usage, dns_san_matches,
    is_self_signed, key_label, same_certificate, summarize, x509_name_to_string,
};

const EXPIRES_SOON_SECS: u64 = 30 * 24 * 3600;

/// What the user uploaded. Any mix: one file with everything, several files,
/// pasted text, PFX with a password. Two certificates (one per name) are fine.
#[derive(Clone, Default)]
pub struct CertificateInput {
    /// PEM or DER or PFX contents, recognized by content.
    pub files: Vec<Vec<u8>>,
    pub pfx_password: Option<String>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CheckLevel {
    Pass,
    /// The user has to confirm.
    Warn,
    /// Cannot be used.
    Reject,
}

/// Stable codes the pages translate.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum CheckCode {
    /// Parses; the key is not encrypted or the PFX password is right.
    Readable,
    KeyMatches,
    CoversDomain,
    CoversWildcard,
    Validity,
    ServerUsage,
    NotCa,
    PublicTrust,
    KeyAlgorithm,
}

/// Why, when a check does not pass; `None` on a pass.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum CheckReason {
    Empty,
    Unparsable,
    KeyMissing,
    KeyEncrypted,
    PfxPasswordWrong,
    KeyMismatch,
    /// `*.example.com` used for the Zone domain `home.example.com`.
    ParentWildcard,
    /// Single-domain certificate, no wildcard name.
    SingleDomain,
    /// Only `*.<domain>`, without `<domain>`.
    WildcardOnly,
    /// An EV certificate cannot carry a wildcard name.
    Ev,
    NotCovered,
    Expired,
    NotYetValid,
    ExpiresSoon,
    NoServerAuth,
    IsCa,
    SelfSigned,
    /// Private CA, or an intermediate is missing.
    ChainNotPublic,
    UnsupportedKey,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct CheckItem {
    pub code: CheckCode,
    pub level: CheckLevel,
    pub reason: Option<CheckReason>,
    /// Plain facts for the message (a name, a date, a key type). Never key material.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct NameCoverage {
    /// `<domain>` or `*.<domain>`.
    pub name: String,
    /// The SAN that covers it literally.
    pub covered_by: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct CertificateInspection {
    pub domain: String,
    pub items: Vec<CheckItem>,
    pub coverage: Vec<NameCoverage>,
    pub dns_names: Vec<String>,
    pub issuer: Option<String>,
    pub subject: Option<String>,
    /// Unix seconds; the earliest expiry when two certificates are used.
    pub not_before: Option<u64>,
    pub not_after: Option<u64>,
    pub publicly_trusted: bool,
    /// The node's clock, shown next to a validity failure.
    pub node_time: u64,
    /// `sha256:<hex>` of the leaf of `<domain>`.
    pub fingerprint: Option<String>,
}

impl CertificateInspection {
    pub fn rejected(&self) -> bool {
        self.items
            .iter()
            .any(|item| item.level == CheckLevel::Reject)
    }

    pub fn has_warning(&self) -> bool {
        self.items.iter().any(|item| item.level == CheckLevel::Warn)
    }
}

/// One installable certificate for one host (`<domain>` or `*.<domain>`).
#[derive(Clone)]
pub struct PreparedCertificate {
    pub host: String,
    /// Leaf first, intermediates ordered, roots dropped.
    pub fullchain_pem: Vec<u8>,
    /// PKCS#8 PEM.
    pub key_pem: Vec<u8>,
}

/// Every check of the table, and what to install when nothing is rejected.
pub fn inspect_certificate(
    input: &CertificateInput,
    domain: &str,
) -> (CertificateInspection, Option<Vec<PreparedCertificate>>) {
    inspect_certificate_with(
        input,
        domain,
        &TrustRoots::system(),
        chrono::Utc::now().timestamp().max(0) as u64,
    )
}

/// [`inspect_certificate`] against given roots and at a given time (Unix seconds).
pub fn inspect_certificate_with(
    input: &CertificateInput,
    domain: &str,
    roots: &TrustRoots,
    now: u64,
) -> (CertificateInspection, Option<Vec<PreparedCertificate>>) {
    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    let wildcard = format!("*.{domain}");
    let parsed = parse_input(input);

    let mut items = Vec::new();
    let mut problem = parsed.problem.clone();
    let mut leaves = Vec::new();
    for cert in &parsed.certificates {
        match Leaf::new(cert, &parsed.keys) {
            Some(leaf) => leaves.push(leaf),
            None => {
                problem.get_or_insert((CheckReason::Unparsable, None));
            }
        }
    }
    let leaves = end_entities(leaves);
    items.push(match problem {
        Some((reason, detail)) => item(CheckCode::Readable, CheckLevel::Reject, reason, detail),
        None => pass(CheckCode::Readable, None),
    });

    let mut inspection = CertificateInspection {
        domain: domain.clone(),
        items,
        coverage: Vec::new(),
        dns_names: Vec::new(),
        issuer: None,
        subject: None,
        not_before: None,
        not_after: None,
        publicly_trusted: false,
        node_time: now,
        fingerprint: None,
    };
    if leaves.is_empty() {
        return (inspection, None);
    }

    let for_domain = best_leaf(&leaves, now, |san| dns_san_matches(san, &domain), &wildcard);
    let for_wildcard = best_leaf(
        &leaves,
        now,
        |san| san.eq_ignore_ascii_case(&wildcard),
        &domain,
    );
    inspection.coverage = vec![
        NameCoverage {
            name: domain.clone(),
            covered_by: for_domain.as_ref().map(|(_, san)| san.clone()),
        },
        NameCoverage {
            name: wildcard.clone(),
            covered_by: for_wildcard.as_ref().map(|(_, san)| san.clone()),
        },
    ];
    let for_domain = for_domain.map(|(leaf, _)| leaf);
    let for_wildcard = for_wildcard.map(|(leaf, _)| leaf);

    let mut used: Vec<&Leaf> = for_domain.iter().copied().collect();
    if let Some(leaf) = for_wildcard
        && !used.iter().any(|known| std::ptr::eq(*known, leaf))
    {
        used.push(leaf);
    }
    if used.is_empty() {
        let keyed = leaves
            .iter()
            .filter(|leaf| leaf.key.is_some())
            .collect::<Vec<_>>();
        used = if keyed.is_empty() {
            leaves.iter().collect()
        } else {
            keyed
        };
    }

    let shown = for_domain.unwrap_or(used[0]);
    inspection.issuer = Some(shown.summary.issuer.clone());
    inspection.subject = Some(x509_name_to_string(shown.cert.subject_name()));
    inspection.fingerprint = Some(shown.summary.fingerprint.clone());
    inspection.not_before = used.iter().map(|leaf| leaf.summary.not_before).max();
    inspection.not_after = used.iter().map(|leaf| leaf.summary.not_after).min();
    for leaf in &used {
        for name in &leaf.summary.dns_names {
            if !inspection.dns_names.contains(name) {
                inspection.dns_names.push(name.clone());
            }
        }
    }

    if !parsed.keys.is_empty() {
        inspection.items.push(check_key_matches(&used));
    }
    inspection
        .items
        .push(check_domain(&domain, &wildcard, for_domain, &used));
    inspection.items.push(check_wildcard(
        &domain,
        &wildcard,
        for_wildcard,
        &leaves,
        &used,
    ));
    inspection.items.push(check_validity(&used, now));
    inspection
        .items
        .push(if used.iter().all(|leaf| leaf.usage.server_auth) {
            pass(CheckCode::ServerUsage, None)
        } else {
            item(
                CheckCode::ServerUsage,
                CheckLevel::Reject,
                CheckReason::NoServerAuth,
                None,
            )
        });
    inspection
        .items
        .push(if used.iter().any(|leaf| leaf.usage.is_ca) {
            item(CheckCode::NotCa, CheckLevel::Warn, CheckReason::IsCa, None)
        } else {
            pass(CheckCode::NotCa, None)
        });

    let trust = check_public_trust(&used, &parsed.certificates, roots, now);
    inspection.publicly_trusted = trust.level == CheckLevel::Pass;
    inspection.items.push(trust);
    inspection.items.push(check_key_algorithm(&used));

    if inspection.rejected() {
        return (inspection, None);
    }
    let prepared = [(&domain, for_domain), (&wildcard, for_wildcard)]
        .into_iter()
        .map(|(host, leaf)| prepare(host, leaf?, &parsed.certificates, now))
        .collect::<Option<Vec<_>>>();
    if prepared.is_none() {
        inspection.items[0] = item(
            CheckCode::Readable,
            CheckLevel::Reject,
            CheckReason::Unparsable,
            None,
        );
    }
    (inspection, prepared)
}

/// A certificate of the input that could be served, with its key if one was given.
struct Leaf {
    cert: X509,
    key: Option<PKey<Private>>,
    summary: CertificateSummary,
    usage: CertUsage,
}

impl Leaf {
    fn new(cert: &X509, keys: &[PKey<Private>]) -> Option<Self> {
        let public_key = cert.public_key().ok()?;
        Some(Self {
            key: keys.iter().find(|key| public_key.public_eq(key)).cloned(),
            summary: summarize(cert).ok()?,
            usage: cert_usage(cert).ok()?,
            cert: cert.clone(),
        })
    }

    fn valid_at(&self, now: u64) -> bool {
        self.summary.not_before <= now && now < self.summary.not_after
    }
}

/// Leaves out the intermediates and roots of the input.
fn end_entities(all: Vec<Leaf>) -> Vec<Leaf> {
    let issues_another = |leaf: &Leaf| {
        all.iter().any(|other| {
            !same_certificate(&leaf.cert, &other.cert)
                && leaf.cert.issued(&other.cert) == openssl::x509::X509VerifyResult::OK
        })
    };
    let keep = all
        .iter()
        .map(|leaf| leaf.key.is_some() || !(leaf.usage.is_ca || issues_another(leaf)))
        .collect::<Vec<_>>();
    if !keep.contains(&true) {
        return all;
    }
    all.into_iter()
        .zip(keep)
        .filter_map(|(leaf, keep)| keep.then_some(leaf))
        .collect()
}

/// The best certificate for a name: one with its key, valid now, covering the
/// other name too, expiring last.
fn best_leaf<'a>(
    leaves: &'a [Leaf],
    now: u64,
    covers: impl Fn(&str) -> bool,
    other_name: &str,
) -> Option<(&'a Leaf, String)> {
    leaves
        .iter()
        .filter_map(|leaf| {
            let names = &leaf.summary.dns_names;
            let san = names
                .iter()
                .filter(|san| covers(san))
                .min_by_key(|san| san.starts_with("*."))?;
            Some((leaf, san.to_ascii_lowercase()))
        })
        .max_by_key(|(leaf, _)| {
            (
                leaf.key.is_some(),
                leaf.valid_at(now),
                leaf.summary
                    .dns_names
                    .iter()
                    .any(|san| san.eq_ignore_ascii_case(other_name)),
                leaf.summary.not_after,
            )
        })
}

fn pass(code: CheckCode, detail: Option<String>) -> CheckItem {
    CheckItem {
        code,
        level: CheckLevel::Pass,
        reason: None,
        detail,
    }
}

fn item(
    code: CheckCode,
    level: CheckLevel,
    reason: CheckReason,
    detail: Option<String>,
) -> CheckItem {
    CheckItem {
        code,
        level,
        reason: Some(reason),
        detail,
    }
}

fn date(seconds: u64) -> Option<String> {
    chrono::DateTime::<chrono::Utc>::from_timestamp(seconds as i64, 0)
        .map(|time| time.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
}

fn names_of(leaves: &[&Leaf]) -> Option<String> {
    let names = leaves
        .iter()
        .flat_map(|leaf| leaf.summary.dns_names.iter().map(String::as_str))
        .collect::<Vec<_>>();
    (!names.is_empty()).then(|| names.join(", "))
}

fn check_key_matches(used: &[&Leaf]) -> CheckItem {
    match used.iter().find(|leaf| leaf.key.is_none()) {
        None => pass(CheckCode::KeyMatches, None),
        Some(leaf) => item(
            CheckCode::KeyMatches,
            CheckLevel::Reject,
            CheckReason::KeyMismatch,
            names_of(&[leaf]),
        ),
    }
}

fn check_domain(domain: &str, wildcard: &str, covered: Option<&Leaf>, used: &[&Leaf]) -> CheckItem {
    if covered.is_some() {
        return pass(CheckCode::CoversDomain, Some(domain.to_string()));
    }
    let wildcard_only = has_name(used, wildcard);
    item(
        CheckCode::CoversDomain,
        CheckLevel::Reject,
        if wildcard_only {
            CheckReason::WildcardOnly
        } else {
            CheckReason::NotCovered
        },
        names_of(used),
    )
}

fn check_wildcard(
    domain: &str,
    wildcard: &str,
    covered: Option<&Leaf>,
    leaves: &[Leaf],
    used: &[&Leaf],
) -> CheckItem {
    if covered.is_some() {
        return pass(CheckCode::CoversWildcard, Some(wildcard.to_string()));
    }
    let parent_wildcard = domain
        .split_once('.')
        .map(|(_, parent)| format!("*.{parent}"));
    let (reason, detail) = if leaves.iter().any(|leaf| leaf.usage.is_ev) {
        (CheckReason::Ev, names_of(used))
    } else if let Some(parent) = parent_wildcard.filter(|parent| has_name(used, parent)) {
        (CheckReason::ParentWildcard, Some(parent))
    } else if has_name(used, domain) {
        (CheckReason::SingleDomain, names_of(used))
    } else {
        (CheckReason::NotCovered, names_of(used))
    };
    item(
        CheckCode::CoversWildcard,
        CheckLevel::Reject,
        reason,
        detail,
    )
}

fn has_name(leaves: &[&Leaf], name: &str) -> bool {
    leaves
        .iter()
        .flat_map(|leaf| leaf.summary.dns_names.iter())
        .any(|san| san.eq_ignore_ascii_case(name))
}

fn check_validity(used: &[&Leaf], now: u64) -> CheckItem {
    let not_before = used
        .iter()
        .map(|leaf| leaf.summary.not_before)
        .max()
        .unwrap_or(0);
    let not_after = used
        .iter()
        .map(|leaf| leaf.summary.not_after)
        .min()
        .unwrap_or(0);
    if now >= not_after {
        item(
            CheckCode::Validity,
            CheckLevel::Reject,
            CheckReason::Expired,
            date(not_after),
        )
    } else if now < not_before {
        item(
            CheckCode::Validity,
            CheckLevel::Reject,
            CheckReason::NotYetValid,
            date(not_before),
        )
    } else if not_after - now < EXPIRES_SOON_SECS {
        item(
            CheckCode::Validity,
            CheckLevel::Warn,
            CheckReason::ExpiresSoon,
            date(not_after),
        )
    } else {
        pass(CheckCode::Validity, date(not_after))
    }
}

fn check_public_trust(used: &[&Leaf], pool: &[X509], roots: &TrustRoots, now: u64) -> CheckItem {
    for leaf in used {
        let chain = build_chain(&leaf.cert, pool, now);
        // A certificate outside its validity is reported by its own check.
        let last = leaf.summary.not_after.saturating_sub(1);
        let time = now.min(last).max(leaf.summary.not_before);
        if roots.verifies(&leaf.cert, &chain, time as i64) {
            continue;
        }
        let reason = if is_self_signed(&leaf.cert) {
            CheckReason::SelfSigned
        } else {
            CheckReason::ChainNotPublic
        };
        return item(
            CheckCode::PublicTrust,
            CheckLevel::Warn,
            reason,
            Some(leaf.summary.issuer.clone()),
        );
    }
    pass(CheckCode::PublicTrust, None)
}

/// RSA from 2048 bits, P-256 and P-384, and the gateway's own TLS library takes the key.
fn check_key_algorithm(used: &[&Leaf]) -> CheckItem {
    let mut labels = Vec::new();
    for leaf in used {
        let Ok(public_key) = leaf.cert.public_key() else {
            continue;
        };
        let label = key_label(&public_key);
        let allowed = match public_key.id() {
            Id::RSA => public_key.bits() >= 2048,
            Id::EC => matches!(label.as_str(), "EC P-256" | "EC P-384"),
            _ => false,
        };
        let usable = leaf.key.as_ref().is_none_or(gateway_takes_key);
        if !allowed || !usable {
            return item(
                CheckCode::KeyAlgorithm,
                CheckLevel::Reject,
                CheckReason::UnsupportedKey,
                Some(label),
            );
        }
        if !labels.contains(&label) {
            labels.push(label);
        }
    }
    pass(CheckCode::KeyAlgorithm, Some(labels.join(", ")))
}

fn gateway_takes_key(key: &PKey<Private>) -> bool {
    key.private_key_to_pkcs8().is_ok_and(|der| {
        any_supported_type(&PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der))).is_ok()
    })
}

/// Leaf first, intermediates ordered, roots dropped. `None` when the gateway's
/// TLS library cannot read the result.
fn prepare(host: &str, leaf: &Leaf, pool: &[X509], now: u64) -> Option<PreparedCertificate> {
    ParsedCertificate::try_from(&CertificateDer::from(leaf.cert.to_der().ok()?)).ok()?;
    let mut fullchain_pem = leaf.cert.to_pem().ok()?;
    for cert in build_chain(&leaf.cert, pool, now) {
        fullchain_pem.extend(cert.to_pem().ok()?);
    }
    Some(PreparedCertificate {
        host: host.to_string(),
        fullchain_pem,
        key_pem: leaf.key.as_ref()?.private_key_to_pem_pkcs8().ok()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_ca::*;
    use openssl::nid::Nid;
    use openssl::pkcs12::Pkcs12;
    use openssl::provider::Provider;
    use openssl::stack::Stack;
    use openssl::symm::Cipher;

    const DOMAIN: &str = "home.example.com";
    const BOTH: [&str; 2] = ["home.example.com", "*.home.example.com"];

    fn inspect(
        files: Vec<Vec<u8>>,
        ca: &TestCa,
    ) -> (CertificateInspection, Option<Vec<PreparedCertificate>>) {
        inspect_pfx(files, None, ca)
    }

    fn inspect_pfx(
        files: Vec<Vec<u8>>,
        password: Option<&str>,
        ca: &TestCa,
    ) -> (CertificateInspection, Option<Vec<PreparedCertificate>>) {
        inspect_certificate_with(
            &CertificateInput {
                files,
                pfx_password: password.map(str::to_string),
            },
            DOMAIN,
            &ca.roots(),
            now() as u64,
        )
    }

    fn check(
        inspection: &CertificateInspection,
        code: CheckCode,
    ) -> (CheckLevel, Option<CheckReason>) {
        let item = inspection
            .items
            .iter()
            .find(|item| item.code == code)
            .unwrap_or_else(|| panic!("no {code:?} item: {inspection:?}"));
        (item.level, item.reason)
    }

    fn assert_clean(inspection: &CertificateInspection) {
        assert!(
            !inspection.rejected() && !inspection.has_warning(),
            "{inspection:#?}"
        );
        assert!(inspection.publicly_trusted);
    }

    fn assert_reject(inspection: &CertificateInspection, code: CheckCode, reason: CheckReason) {
        assert_eq!(
            check(inspection, code),
            (CheckLevel::Reject, Some(reason)),
            "{inspection:#?}"
        );
    }

    fn assert_warn(inspection: &CertificateInspection, code: CheckCode, reason: CheckReason) {
        assert_eq!(
            check(inspection, code),
            (CheckLevel::Warn, Some(reason)),
            "{inspection:#?}"
        );
        assert!(!inspection.rejected(), "{inspection:#?}");
    }

    fn join(parts: &[Vec<u8>]) -> Vec<u8> {
        parts.concat()
    }

    fn chain_of(prepared: &PreparedCertificate) -> Vec<X509> {
        X509::stack_from_pem(&prepared.fullchain_pem).unwrap()
    }

    fn pfx(issued: &Issued, ca: &TestCa, password: &str, old: bool) -> Vec<u8> {
        let mut chain = Stack::new().unwrap();
        chain.push(ca.root.cert.clone()).unwrap();
        chain.push(ca.intermediate.cert.clone()).unwrap();
        let mut builder = Pkcs12::builder();
        builder
            .name("zone")
            .pkey(&issued.key)
            .cert(&issued.cert)
            .ca(chain);
        if old {
            builder
                .key_algorithm(Nid::PBE_WITHSHA1AND3_KEY_TRIPLEDES_CBC)
                .cert_algorithm(Nid::PBE_WITHSHA1AND40BITRC2_CBC)
                .mac_md(openssl::hash::MessageDigest::sha1());
        }
        builder.build2(password).unwrap().to_der().unwrap()
    }

    #[test]
    fn one_certificate_for_both_names_is_prepared_for_both_hosts() {
        let ca = TestCa::new();
        let leaf = ca.issue(&BOTH);
        let (inspection, prepared) = inspect(
            vec![join(&[leaf.pem(), ca.intermediate.pem(), leaf.key_pem()])],
            &ca,
        );
        assert_clean(&inspection);
        assert_eq!(
            inspection
                .items
                .iter()
                .map(|item| item.code)
                .collect::<Vec<_>>(),
            vec![
                CheckCode::Readable,
                CheckCode::KeyMatches,
                CheckCode::CoversDomain,
                CheckCode::CoversWildcard,
                CheckCode::Validity,
                CheckCode::ServerUsage,
                CheckCode::NotCa,
                CheckCode::PublicTrust,
                CheckCode::KeyAlgorithm,
            ]
        );
        assert_eq!(
            inspection.coverage,
            vec![
                NameCoverage {
                    name: "home.example.com".to_string(),
                    covered_by: Some("home.example.com".to_string()),
                },
                NameCoverage {
                    name: "*.home.example.com".to_string(),
                    covered_by: Some("*.home.example.com".to_string()),
                },
            ]
        );
        assert_eq!(inspection.issuer.as_deref(), Some("O=Test,CN=Intermediate"));
        assert_eq!(
            inspection.fingerprint.as_deref(),
            Some(summarize(&leaf.cert).unwrap().fingerprint.as_str())
        );
        let prepared = prepared.unwrap();
        assert_eq!(
            prepared.iter().map(|c| c.host.as_str()).collect::<Vec<_>>(),
            vec!["home.example.com", "*.home.example.com"]
        );
        for certificate in &prepared {
            assert_eq!(chain_of(certificate).len(), 2);
            assert!(
                certificate
                    .key_pem
                    .starts_with(b"-----BEGIN PRIVATE KEY-----")
            );
        }
    }

    #[test]
    fn two_certificates_may_cover_one_name_each() {
        let ca = TestCa::new();
        let exact = ca.issue(&["home.example.com"]);
        let wildcard = Spec {
            not_after: now() + 60 * DAY,
            ..Spec::leaf(&["*.home.example.com"])
        }
        .issued_by(&ca.intermediate);
        let (inspection, prepared) = inspect(
            vec![
                exact.key_pem(),
                wildcard.pem(),
                ca.intermediate.pem(),
                wildcard.key_pem(),
                exact.pem(),
            ],
            &ca,
        );
        assert_clean(&inspection);
        assert_eq!(
            inspection.not_after,
            Some(summarize(&wildcard.cert).unwrap().not_after)
        );
        let prepared = prepared.unwrap();
        for (certificate, issued) in prepared.iter().zip([&exact, &wildcard]) {
            assert!(same_certificate(&chain_of(certificate)[0], &issued.cert));
            let key = PKey::private_key_from_pem(&certificate.key_pem).unwrap();
            assert!(key.public_eq(&issued.key));
        }
    }

    #[test]
    fn a_key_for_only_one_of_two_certificates_is_rejected() {
        let ca = TestCa::new();
        let exact = ca.issue(&["home.example.com"]);
        let wildcard = ca.issue(&["*.home.example.com"]);
        let (inspection, prepared) = inspect(
            vec![
                exact.pem(),
                exact.key_pem(),
                wildcard.pem(),
                ca.intermediate.pem(),
            ],
            &ca,
        );
        assert_reject(&inspection, CheckCode::KeyMatches, CheckReason::KeyMismatch);
        assert!(prepared.is_none());
    }

    #[test]
    fn chain_is_sorted_and_the_root_dropped() {
        let ca = TestCa::new();
        let sub = Spec::ca("Sub").issued_by(&ca.intermediate);
        let leaf = Spec::leaf(&BOTH).issued_by(&sub);
        let (inspection, prepared) = inspect(
            vec![
                ca.root.pem(),
                join(&[ca.intermediate.pem(), leaf.key_pem(), sub.pem()]),
                join(&[leaf.pem(), ca.root.pem()]),
            ],
            &ca,
        );
        assert_clean(&inspection);
        let chain = chain_of(&prepared.unwrap()[0]);
        let expected = [&leaf.cert, &sub.cert, &ca.intermediate.cert];
        assert_eq!(chain.len(), expected.len());
        for (actual, expected) in chain.iter().zip(expected) {
            assert!(same_certificate(actual, expected));
        }
    }

    #[test]
    fn der_files_are_recognized() {
        let ca = TestCa::new();
        let leaf = ca.issue(&BOTH);
        let (inspection, prepared) = inspect(
            vec![
                leaf.cert.to_der().unwrap(),
                leaf.key.private_key_to_der().unwrap(),
                ca.intermediate.cert.to_der().unwrap(),
            ],
            &ca,
        );
        assert_clean(&inspection);
        assert!(prepared.is_some());
        let (inspection, _) = inspect(
            vec![
                leaf.cert.to_der().unwrap(),
                leaf.key.private_key_to_pkcs8().unwrap(),
                ca.intermediate.cert.to_der().unwrap(),
            ],
            &ca,
        );
        assert_clean(&inspection);
    }

    #[test]
    fn pasted_text_survives_extra_text_and_lost_line_breaks() {
        let ca = TestCa::new();
        let leaf = ca.issue(&BOTH);
        let flat = |pem: Vec<u8>| String::from_utf8(pem).unwrap().replace('\n', " ");
        let text = format!(
            "\u{feff}Bag Attributes\r\n    friendlyName: zone\r\n{}\r\nthanks\r\n{}{}",
            flat(leaf.key_pem()),
            flat(leaf.pem()),
            String::from_utf8(ca.intermediate.pem())
                .unwrap()
                .replace('\n', "\r\n"),
        );
        let (inspection, prepared) = inspect(vec![text.into_bytes(), b" \n".to_vec()], &ca);
        assert_clean(&inspection);
        assert!(prepared.is_some());
    }

    #[test]
    fn rsa_key_formats_become_pkcs8() {
        let ca = TestCa::new();
        let leaf = Spec {
            key: rsa_key(2048),
            ..Spec::leaf(&BOTH)
        }
        .issued_by(&ca.intermediate);
        let pkcs1 = leaf.key.rsa().unwrap().private_key_to_pem().unwrap();
        assert!(pkcs1.starts_with(b"-----BEGIN RSA PRIVATE KEY-----"));
        let (inspection, prepared) = inspect(vec![leaf.pem(), pkcs1, ca.intermediate.pem()], &ca);
        assert_clean(&inspection);
        assert!(
            prepared.unwrap()[0]
                .key_pem
                .starts_with(b"-----BEGIN PRIVATE KEY-----")
        );

        let ec = ca.issue(&BOTH);
        let sec1 = ec.key.ec_key().unwrap().private_key_to_pem().unwrap();
        assert!(sec1.starts_with(b"-----BEGIN EC PRIVATE KEY-----"));
        let (inspection, prepared) = inspect(vec![ec.pem(), sec1, ca.intermediate.pem()], &ca);
        assert_clean(&inspection);
        assert!(
            prepared.unwrap()[0]
                .key_pem
                .starts_with(b"-----BEGIN PRIVATE KEY-----")
        );
    }

    #[test]
    fn ec_key_without_its_public_part_is_completed() {
        let ca = TestCa::new();
        let leaf = ca.issue(&BOTH);
        let key = leaf.key.ec_key().unwrap();
        // ECPrivateKey { 1, scalar, [0] prime256v1 }
        let mut der = vec![0x30, 0x31, 0x02, 0x01, 0x01, 0x04, 0x20];
        der.extend(key.private_key().to_vec_padded(32).unwrap());
        der.extend([
            0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
        ]);
        let (inspection, prepared) = inspect(vec![leaf.pem(), der, ca.intermediate.pem()], &ca);
        assert_clean(&inspection);
        assert!(prepared.is_some());
    }

    #[test]
    fn empty_and_unreadable_input_is_rejected() {
        let ca = TestCa::new();
        let leaf = ca.issue(&BOTH);
        for files in [vec![], vec![Vec::new()], vec![b"  \n".to_vec()]] {
            let (inspection, prepared) = inspect(files, &ca);
            assert_reject(&inspection, CheckCode::Readable, CheckReason::Empty);
            assert!(prepared.is_none());
        }
        for garbage in [
            b"not a certificate".to_vec(),
            vec![0u8, 1, 2, 3, 0xff],
            b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n".to_vec(),
            b"-----BEGIN CERTIFICATE-----\nAAAA".to_vec(),
        ] {
            let (inspection, _) = inspect(vec![garbage.clone()], &ca);
            assert_reject(&inspection, CheckCode::Readable, CheckReason::Unparsable);
            let (inspection, prepared) = inspect(
                vec![leaf.pem(), leaf.key_pem(), ca.intermediate.pem(), garbage],
                &ca,
            );
            assert_reject(&inspection, CheckCode::Readable, CheckReason::Unparsable);
            assert!(prepared.is_none());
        }
        let (inspection, _) = inspect(vec![leaf.key_pem()], &ca);
        assert_reject(&inspection, CheckCode::Readable, CheckReason::Unparsable);
    }

    #[test]
    fn missing_key_is_rejected_and_the_names_still_shown() {
        let ca = TestCa::new();
        let leaf = ca.issue(&BOTH);
        let (inspection, prepared) = inspect(vec![leaf.pem(), ca.intermediate.pem()], &ca);
        assert_reject(&inspection, CheckCode::Readable, CheckReason::KeyMissing);
        assert_eq!(
            check(&inspection, CheckCode::CoversWildcard).0,
            CheckLevel::Pass
        );
        assert!(
            !inspection
                .items
                .iter()
                .any(|item| item.code == CheckCode::KeyMatches)
        );
        assert!(prepared.is_none());
    }

    #[test]
    fn encrypted_key_is_rejected() {
        let ca = TestCa::new();
        let leaf = Spec {
            key: rsa_key(2048),
            ..Spec::leaf(&BOTH)
        }
        .issued_by(&ca.intermediate);
        let pkcs8 = leaf
            .key
            .private_key_to_pem_pkcs8_passphrase(Cipher::aes_256_cbc(), b"secret")
            .unwrap();
        let traditional = leaf
            .key
            .rsa()
            .unwrap()
            .private_key_to_pem_passphrase(Cipher::aes_256_cbc(), b"secret")
            .unwrap();
        for key in [pkcs8, traditional] {
            let (inspection, prepared) = inspect(vec![leaf.pem(), key, ca.intermediate.pem()], &ca);
            assert_reject(&inspection, CheckCode::Readable, CheckReason::KeyEncrypted);
            assert!(prepared.is_none());
        }
    }

    #[test]
    fn pfx_with_right_and_wrong_password() {
        let ca = TestCa::new();
        let leaf = ca.issue(&BOTH);
        let file = pfx(&leaf, &ca, "pässword", false);
        let (inspection, prepared) = inspect_pfx(vec![file.clone()], Some("pässword"), &ca);
        assert_clean(&inspection);
        assert_eq!(chain_of(&prepared.unwrap()[0]).len(), 2);
        for password in [None, Some("wrong"), Some("pässword\0")] {
            let (inspection, prepared) = inspect_pfx(vec![file.clone()], password, &ca);
            assert_reject(
                &inspection,
                CheckCode::Readable,
                CheckReason::PfxPasswordWrong,
            );
            assert!(prepared.is_none());
        }
        let no_password = pfx(&leaf, &ca, "", false);
        let (inspection, _) = inspect_pfx(vec![no_password], None, &ca);
        assert_clean(&inspection);
    }

    #[test]
    fn pfx_with_old_algorithms() {
        let ca = TestCa::new();
        let leaf = ca.issue(&BOTH);
        let file = {
            let _legacy = Provider::try_load(None, "legacy", true).unwrap();
            pfx(&leaf, &ca, "secret", true)
        };
        let (inspection, prepared) = inspect_pfx(vec![file.clone()], Some("secret"), &ca);
        assert_clean(&inspection);
        assert_eq!(chain_of(&prepared.unwrap()[0]).len(), 2);
        let (inspection, _) = inspect_pfx(vec![file], Some("wrong"), &ca);
        assert_reject(
            &inspection,
            CheckCode::Readable,
            CheckReason::PfxPasswordWrong,
        );
    }

    #[test]
    fn pfx_mixes_with_other_files() {
        let ca = TestCa::new();
        let exact = ca.issue(&["home.example.com"]);
        let wildcard = ca.issue(&["*.home.example.com"]);
        let (inspection, prepared) = inspect_pfx(
            vec![
                pfx(&exact, &ca, "secret", false),
                join(&[wildcard.pem(), wildcard.key_pem()]),
            ],
            Some("secret"),
            &ca,
        );
        assert_clean(&inspection);
        assert_eq!(prepared.unwrap().len(), 2);
    }

    #[test]
    fn mismatched_key_is_rejected() {
        let ca = TestCa::new();
        let leaf = ca.issue(&BOTH);
        let other = ca.issue(&BOTH);
        let (inspection, prepared) = inspect(
            vec![leaf.pem(), other.key_pem(), ca.intermediate.pem()],
            &ca,
        );
        assert_reject(&inspection, CheckCode::KeyMatches, CheckReason::KeyMismatch);
        assert!(prepared.is_none());
    }

    #[test]
    fn names_are_taken_from_the_san_only() {
        let ca = TestCa::new();
        let leaf = Spec {
            common_name: DOMAIN.to_string(),
            ..Spec::leaf(&["www.other.example"])
        }
        .issued_by(&ca.intermediate);
        let (inspection, _) = inspect(vec![leaf.pem(), leaf.key_pem()], &ca);
        assert_reject(
            &inspection,
            CheckCode::CoversDomain,
            CheckReason::NotCovered,
        );
        assert_reject(
            &inspection,
            CheckCode::CoversWildcard,
            CheckReason::NotCovered,
        );
        assert_eq!(inspection.dns_names, vec!["www.other.example"]);
        assert!(inspection.coverage.iter().all(|c| c.covered_by.is_none()));
    }

    #[test]
    fn listed_subdomains_do_not_replace_the_wildcard() {
        let ca = TestCa::new();
        let leaf = ca.issue(&[
            "home.example.com",
            "sys.home.example.com",
            "ood1.home.example.com",
        ]);
        let (inspection, _) = inspect(vec![leaf.pem(), leaf.key_pem()], &ca);
        assert_eq!(
            check(&inspection, CheckCode::CoversDomain).0,
            CheckLevel::Pass
        );
        assert_reject(
            &inspection,
            CheckCode::CoversWildcard,
            CheckReason::SingleDomain,
        );
    }

    #[test]
    fn parent_wildcard_is_explained() {
        let ca = TestCa::new();
        let leaf = ca.issue(&["example.com", "*.example.com"]);
        let (inspection, prepared) =
            inspect(vec![leaf.pem(), leaf.key_pem(), ca.intermediate.pem()], &ca);
        assert_eq!(
            check(&inspection, CheckCode::CoversDomain).0,
            CheckLevel::Pass
        );
        assert_eq!(
            inspection.coverage[0].covered_by.as_deref(),
            Some("*.example.com")
        );
        assert_reject(
            &inspection,
            CheckCode::CoversWildcard,
            CheckReason::ParentWildcard,
        );
        assert!(prepared.is_none());
    }

    #[test]
    fn single_domain_certificate_is_explained() {
        let ca = TestCa::new();
        let leaf = ca.issue(&["home.example.com", "www.home.example.com"]);
        let (inspection, _) = inspect(vec![leaf.pem(), leaf.key_pem()], &ca);
        assert_reject(
            &inspection,
            CheckCode::CoversWildcard,
            CheckReason::SingleDomain,
        );
    }

    #[test]
    fn wildcard_only_certificate_is_explained() {
        let ca = TestCa::new();
        let leaf = ca.issue(&["*.home.example.com"]);
        let (inspection, _) = inspect(vec![leaf.pem(), leaf.key_pem()], &ca);
        assert_reject(
            &inspection,
            CheckCode::CoversDomain,
            CheckReason::WildcardOnly,
        );
        assert_eq!(
            check(&inspection, CheckCode::CoversWildcard).0,
            CheckLevel::Pass
        );
    }

    #[test]
    fn ev_certificate_is_explained() {
        let ca = TestCa::new();
        let leaf = Spec {
            ev: true,
            ..Spec::leaf(&["home.example.com", "www.home.example.com"])
        }
        .issued_by(&ca.intermediate);
        let (inspection, _) = inspect(vec![leaf.pem(), leaf.key_pem()], &ca);
        assert_reject(&inspection, CheckCode::CoversWildcard, CheckReason::Ev);
    }

    #[test]
    fn names_are_compared_without_case() {
        let ca = TestCa::new();
        let leaf = ca.issue(&["HOME.example.com", "*.Home.Example.com"]);
        let (inspection, _) = inspect_certificate_with(
            &CertificateInput {
                files: vec![leaf.pem(), leaf.key_pem(), ca.intermediate.pem()],
                pfx_password: None,
            },
            " Home.Example.com. ",
            &ca.roots(),
            now() as u64,
        );
        assert_clean(&inspection);
    }

    #[test]
    fn validity_window() {
        let ca = TestCa::new();
        let issue = |not_before: i64, not_after: i64| {
            let leaf = Spec {
                not_before,
                not_after,
                ..Spec::leaf(&BOTH)
            }
            .issued_by(&ca.intermediate);
            inspect(vec![leaf.pem(), leaf.key_pem(), ca.intermediate.pem()], &ca)
        };
        let (inspection, prepared) = issue(now() - 90 * DAY, now() - DAY);
        assert_reject(&inspection, CheckCode::Validity, CheckReason::Expired);
        assert!(inspection.publicly_trusted, "expiry is its own check");
        assert!(inspection.node_time.abs_diff(now() as u64) < 60);
        assert!(prepared.is_none());

        let (inspection, _) = issue(now() + DAY, now() + 90 * DAY);
        assert_reject(&inspection, CheckCode::Validity, CheckReason::NotYetValid);
        assert!(inspection.publicly_trusted);

        let (inspection, prepared) = issue(now() - DAY, now() + 29 * DAY);
        assert_warn(&inspection, CheckCode::Validity, CheckReason::ExpiresSoon);
        assert!(prepared.is_some());

        let (inspection, _) = issue(now() - DAY, now() + 31 * DAY);
        assert_clean(&inspection);
    }

    #[test]
    fn a_validity_that_ends_before_it_starts_is_expired() {
        let ca = TestCa::new();
        let leaf = Spec {
            not_before: now() + DAY,
            not_after: now() - DAY,
            ..Spec::leaf(&BOTH)
        }
        .issued_by(&ca.intermediate);
        let (inspection, _) = inspect(vec![leaf.pem(), leaf.key_pem()], &ca);
        assert_reject(&inspection, CheckCode::Validity, CheckReason::Expired);
    }

    #[test]
    fn declared_usage_must_include_server_authentication() {
        let ca = TestCa::new();
        let issue = |server_auth| {
            let leaf = Spec {
                server_auth,
                ..Spec::leaf(&BOTH)
            }
            .issued_by(&ca.intermediate);
            inspect(vec![leaf.pem(), leaf.key_pem(), ca.intermediate.pem()], &ca).0
        };
        assert_reject(
            &issue(Some(false)),
            CheckCode::ServerUsage,
            CheckReason::NoServerAuth,
        );
        assert_clean(&issue(None));
    }

    #[test]
    fn missing_intermediate_is_a_warning() {
        let ca = TestCa::new();
        let leaf = ca.issue(&BOTH);
        let (inspection, prepared) = inspect(vec![leaf.pem(), leaf.key_pem()], &ca);
        assert_warn(
            &inspection,
            CheckCode::PublicTrust,
            CheckReason::ChainNotPublic,
        );
        assert!(!inspection.publicly_trusted);
        assert!(prepared.is_some());
    }

    #[test]
    fn private_ca_is_a_warning() {
        let ca = TestCa::new();
        let private = TestCa::new();
        let leaf = private.issue(&BOTH);
        let (inspection, prepared) = inspect(
            vec![
                leaf.pem(),
                leaf.key_pem(),
                private.intermediate.pem(),
                private.root.pem(),
            ],
            &ca,
        );
        assert_warn(
            &inspection,
            CheckCode::PublicTrust,
            CheckReason::ChainNotPublic,
        );
        assert_eq!(chain_of(&prepared.unwrap()[0]).len(), 2);
    }

    #[test]
    fn self_signed_with_and_without_ca_mark() {
        let ca = TestCa::new();
        for (ca_mark, warns) in [(None, false), (Some(false), false), (Some(true), true)] {
            let leaf = Spec {
                ca: ca_mark,
                server_auth: None,
                ..Spec::leaf(&BOTH)
            }
            .self_signed();
            let (inspection, prepared) = inspect(vec![leaf.pem(), leaf.key_pem()], &ca);
            assert_warn(&inspection, CheckCode::PublicTrust, CheckReason::SelfSigned);
            assert_eq!(
                check(&inspection, CheckCode::NotCa),
                if warns {
                    (CheckLevel::Warn, Some(CheckReason::IsCa))
                } else {
                    (CheckLevel::Pass, None)
                }
            );
            assert_eq!(chain_of(&prepared.unwrap()[0]).len(), 1);
        }
    }

    #[test]
    fn expired_and_broken_roots_do_not_break_the_trust_check() {
        let ca = TestCa::new();
        let expired = Spec {
            not_before: now() - 20 * DAY,
            not_after: now() - DAY,
            ..Spec::ca("Expired Root")
        }
        .self_signed();
        let roots = TrustRoots::from_der([
            b"broken".as_slice(),
            expired.cert.to_der().unwrap().as_slice(),
            ca.root.cert.to_der().unwrap().as_slice(),
        ]);
        let leaf = ca.issue(&BOTH);
        let (inspection, _) = inspect_certificate_with(
            &CertificateInput {
                files: vec![leaf.pem(), leaf.key_pem(), ca.intermediate.pem()],
                pfx_password: None,
            },
            DOMAIN,
            &roots,
            now() as u64,
        );
        assert_clean(&inspection);
    }

    #[test]
    fn system_roots_are_loaded() {
        let ca = TestCa::new();
        let leaf = ca.issue(&BOTH);
        let (inspection, prepared) = inspect_certificate(
            &CertificateInput {
                files: vec![leaf.pem(), leaf.key_pem(), ca.intermediate.pem()],
                pfx_password: None,
            },
            DOMAIN,
        );
        assert_warn(
            &inspection,
            CheckCode::PublicTrust,
            CheckReason::ChainNotPublic,
        );
        assert!(prepared.is_some());
    }

    #[test]
    fn key_algorithms_of_the_table() {
        let ca = TestCa::new();
        let issue = |key| {
            let leaf = Spec {
                key,
                ..Spec::leaf(&BOTH)
            }
            .issued_by(&ca.intermediate);
            inspect(vec![leaf.pem(), leaf.key_pem(), ca.intermediate.pem()], &ca).0
        };
        for (key, label) in [
            (rsa_key(2048), "RSA 2048"),
            (rsa_key(3072), "RSA 3072"),
            (p256(), "EC P-256"),
            (ec_key(Nid::SECP384R1), "EC P-384"),
        ] {
            let inspection = issue(key);
            assert_clean(&inspection);
            assert_eq!(
                inspection.items.last().unwrap().detail.as_deref(),
                Some(label)
            );
        }
        for (key, label) in [
            (rsa_key(1024), "RSA 1024"),
            (ec_key(Nid::SECP521R1), "EC P-521"),
            (ec_key(Nid::SECP256K1), "EC secp256k1"),
            (PKey::generate_ed25519().unwrap(), "Ed25519"),
        ] {
            let inspection = issue(key);
            assert_reject(
                &inspection,
                CheckCode::KeyAlgorithm,
                CheckReason::UnsupportedKey,
            );
            assert_eq!(
                inspection.items.last().unwrap().detail.as_deref(),
                Some(label)
            );
        }
    }

    #[test]
    fn the_wire_form_is_snake_case() {
        let ca = TestCa::new();
        let (inspection, _) = inspect(vec![], &ca);
        assert_eq!(
            serde_json::to_value(&inspection).unwrap()["items"],
            serde_json::json!([{ "code": "readable", "level": "reject", "reason": "empty" }])
        );
    }
}
