//! The zone every mock holds, and what every service has to pass.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use cyfs_dns_provider::{
    DnsCredential, DnsProviderError, DnsProviderResult, DnsRecordProviderRef, RecordType,
    create_provider, provider_info,
};

use crate::net::{Handler, Request, Response, serve};

pub const ORIGIN: &str = "example.com";

#[derive(Clone, Debug, PartialEq)]
pub struct Rec {
    pub id: u64,
    pub name: String,
    pub ty: String,
    /// Bare text, hosts without the dot.
    pub value: String,
    pub ttl: u64,
    /// Whatever a mock needs to remember.
    pub mark: String,
}

impl Rec {
    /// Name relative to the zone.
    pub fn label(&self, apex: &str) -> String {
        label(&self.name, apex)
    }

    /// Target with the dot, TXT quoted.
    pub fn zone_file(&self) -> String {
        match self.ty.as_str() {
            "CNAME" | "NS" => format!("{}.", self.value),
            "TXT" => quoted(&self.value),
            _ => self.value.clone(),
        }
    }

    /// Target with the dot, TXT bare.
    pub fn dotted(&self) -> String {
        match self.ty.as_str() {
            "CNAME" | "NS" => format!("{}.", self.value),
            _ => self.value.clone(),
        }
    }
}

pub fn label(name: &str, apex: &str) -> String {
    match name.strip_suffix(ORIGIN) {
        Some("") => apex.to_string(),
        Some(rest) => rest.trim_end_matches('.').to_string(),
        None => panic!("{name} is outside of the zone"),
    }
}

pub fn absolute(label: &str) -> String {
    match label {
        "" | "@" => ORIGIN.to_string(),
        label => format!("{label}.{ORIGIN}"),
    }
}

pub fn quoted(text: &str) -> String {
    format!("\"{text}\"")
}

pub fn unquoted(text: &str) -> String {
    text.strip_prefix('"')
        .and_then(|text| text.strip_suffix('"'))
        .unwrap_or_else(|| panic!("TXT is not quoted: {text}"))
        .to_string()
}

pub fn undotted(text: &str) -> String {
    text.strip_suffix('.')
        .unwrap_or_else(|| panic!("the host has no dot: {text}"))
        .to_string()
}

/// A value sent in zone file form.
pub fn from_zone_file(ty: &str, text: &str) -> String {
    match ty {
        "CNAME" | "NS" => undotted(text),
        "TXT" => unquoted(text),
        _ => text.to_string(),
    }
}

/// A value sent with the dot but without quotes.
pub fn from_dotted(ty: &str, text: &str) -> String {
    match ty {
        "CNAME" | "NS" => undotted(text),
        "TXT" => {
            assert!(!text.starts_with('"'), "TXT is quoted: {text}");
            text.to_string()
        }
        _ => text.to_string(),
    }
}

/// A value sent bare.
pub fn from_bare(ty: &str, text: &str) -> String {
    match ty {
        "CNAME" | "NS" => assert!(!text.ends_with('.'), "the host has a dot: {text}"),
        "TXT" => assert!(!text.starts_with('"'), "TXT is quoted: {text}"),
        _ => {}
    }
    text.to_string()
}

#[derive(Default)]
pub struct Zone {
    pub records: Vec<Rec>,
    next: u64,
    /// Requests to turn away.
    pub limited: u32,
    pub revoked: bool,
    pub writes: u32,
    pub notes: BTreeMap<String, u64>,
}

impl Zone {
    pub fn add(&mut self, name: &str, ty: &str, value: &str, ttl: u64) -> Rec {
        let same = |rec: &Rec| rec.name == name && rec.ty == ty;
        assert!(
            !self
                .records
                .iter()
                .any(|rec| same(rec) && rec.value == value),
            "duplicate {name} {ty} {value}"
        );
        if ty == "CNAME" {
            assert!(!self.records.iter().any(same), "second CNAME at {name}");
        }
        self.next += 1;
        let rec = Rec {
            id: 1000 + self.next,
            name: name.to_string(),
            ty: ty.to_string(),
            value: value.to_string(),
            ttl,
            mark: String::new(),
        };
        self.records.push(rec.clone());
        rec
    }

    pub fn at(&self, name: &str, ty: &str) -> Vec<Rec> {
        self.records
            .iter()
            .filter(|rec| rec.name == name && rec.ty == ty)
            .cloned()
            .collect()
    }

    pub fn by_id(&mut self, id: &str) -> Option<&mut Rec> {
        self.records.iter_mut().find(|rec| rec.id.to_string() == id)
    }

    pub fn delete_id(&mut self, id: &str) -> bool {
        let before = self.records.len();
        self.records.retain(|rec| rec.id.to_string() != id);
        before != self.records.len()
    }

    /// Replaces one RRset.
    pub fn set(&mut self, name: &str, ty: &str, ttl: u64, values: &[String]) {
        self.records
            .retain(|rec| !(rec.name == name && rec.ty == ty));
        for value in values {
            self.add(name, ty, value, ttl);
        }
    }

    pub fn names(&self) -> Vec<(String, String)> {
        let mut names: Vec<_> = self
            .records
            .iter()
            .map(|rec| (rec.name.clone(), rec.ty.clone()))
            .collect();
        names.sort();
        names.dedup();
        names
    }

    pub fn note(&mut self, name: &str) {
        *self.notes.entry(name.to_string()).or_default() += 1;
    }
}

/// Nothing in the plan: has to be the same at the end.
const UNPLANNED: [(&str, &str, &str); 11] = [
    ("example.com", "A", "192.0.2.10"),
    ("example.com", "TXT", "v=spf1 -all"),
    ("example.com", "NS", "ns1.service.net"),
    ("example.com", "MX", "10 mail.example.com"),
    ("www.example.com", "CNAME", "example.com"),
    ("home.example.com", "AAAA", "2001:db8::9"),
    ("home.example.com", "TXT", "keep me"),
    ("xhome.example.com", "A", "192.0.2.13"),
    ("a.home.example.com", "A", "192.0.2.14"),
    ("xacme-challenge.home.example.com", "TXT", "not mine"),
    ("*.other.example.com", "A", "192.0.2.12"),
];

const CHALLENGE: &str = "_acme-challenge.home.example.com";
const WILDCARD: &str = "*.home.example.com";
const HOME: &str = "home.example.com";

pub type Mock = fn(&mut Zone, &Request) -> Response;

pub struct Service {
    pub id: &'static str,
    pub fields: Vec<(&'static str, String)>,
    pub hosts: &'static [&'static str],
    pub mock: Mock,
    /// Answer while the service is turning requests away.
    pub limited: fn() -> Response,
    /// Whether a zone the account does not have is told apart.
    pub missing_zone: bool,
}

pub struct Harness {
    pub zone: Arc<Mutex<Zone>>,
    pub credential: DnsCredential,
}

impl Harness {
    pub fn provider(&self) -> DnsRecordProviderRef {
        self.provider_for(ORIGIN)
    }

    pub fn provider_for(&self, origin: &str) -> DnsRecordProviderRef {
        create_provider(&self.credential, origin).unwrap()
    }

    pub fn values(&self, name: &str, ty: &str) -> Vec<String> {
        let mut values: Vec<_> = self
            .zone
            .lock()
            .unwrap()
            .at(name, ty)
            .into_iter()
            .map(|rec| rec.value)
            .collect();
        values.sort();
        values
    }

    fn writes(&self) -> u32 {
        self.zone.lock().unwrap().writes
    }

    fn limit(&self, requests: u32) {
        self.zone.lock().unwrap().limited = requests;
    }

    fn unplanned(&self) -> Vec<Rec> {
        self.zone
            .lock()
            .unwrap()
            .records
            .iter()
            .filter(|rec| {
                UNPLANNED
                    .iter()
                    .any(|(name, ty, _)| rec.name == *name && rec.ty == *ty)
            })
            .cloned()
            .collect()
    }
}

pub fn start(service: &Service) -> Harness {
    let mut zone = Zone::default();
    for (name, ty, value) in UNPLANNED {
        zone.add(name, ty, value, 7200);
    }
    zone.add(CHALLENGE, "TXT", "other client", 3600);
    let zone = Arc::new(Mutex::new(zone));
    let state = zone.clone();
    let mock = service.mock;
    let limited = service.limited;
    let handler: Handler = Arc::new(move |request: &Request| {
        let mut zone = state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if zone.limited > 0 {
            zone.limited -= 1;
            return limited();
        }
        mock(&mut zone, request)
    });
    for host in service.hosts {
        serve(host, handler.clone());
    }
    let credential = DnsCredential {
        provider: service.id.to_string(),
        fields: service
            .fields
            .iter()
            .map(|(id, value)| (id.to_string(), value.clone()))
            .collect(),
        endpoint: None,
    };
    credential.validate().unwrap();
    Harness { zone, credential }
}

fn list(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| value.to_string()).collect()
}

/// The text of an error carries no secret.
fn clean<T: std::fmt::Debug>(service: &Service, result: DnsProviderResult<T>) -> DnsProviderError {
    let error = result.unwrap_err();
    let text = format!("{error} {error:?}");
    let info = provider_info(service.id).unwrap();
    for (id, value) in &service.fields {
        let secret = info
            .fields
            .iter()
            .any(|field| field.id == *id && field.secret);
        assert!(!secret || !text.contains(value.as_str()), "{id} in {text}");
    }
    error
}

/// Adding and removing by value, repeating, replacing, waiting out rate limits,
/// refused keys, and records of the zone that nobody asked to change.
pub async fn check(service: Service) -> Harness {
    let harness = start(&service);
    let provider = harness.provider();
    let before = harness.unplanned();
    assert_eq!(before.len(), UNPLANNED.len());
    let txt = RecordType::TXT;

    provider
        .add_values(CHALLENGE, txt, 60, list(&["one"]))
        .await
        .unwrap();
    provider
        .add_values(CHALLENGE, txt, 60, list(&["two"]))
        .await
        .unwrap();
    assert_eq!(
        harness.values(CHALLENGE, "TXT"),
        ["one", "other client", "two"]
    );
    let writes = harness.writes();
    provider
        .add_values(CHALLENGE, txt, 60, list(&["one", "two"]))
        .await
        .unwrap();
    assert_eq!(harness.writes(), writes, "adding again writes");
    let mut listed = provider.list_values(CHALLENGE, txt).await.unwrap();
    listed.sort();
    assert_eq!(listed, ["one", "other client", "two"]);

    provider
        .remove_values(CHALLENGE, txt, list(&["one"]))
        .await
        .unwrap();
    assert_eq!(harness.values(CHALLENGE, "TXT"), ["other client", "two"]);
    let writes = harness.writes();
    provider
        .remove_values(CHALLENGE, txt, list(&["one", "never"]))
        .await
        .unwrap();
    provider
        .remove_values("no.such.name.example.com", txt, list(&["x"]))
        .await
        .unwrap();
    assert_eq!(harness.writes(), writes, "removing again writes");
    provider
        .remove_values(CHALLENGE, txt, list(&["two"]))
        .await
        .unwrap();

    // The same on a name that does not exist yet, down to nothing.
    let own = "_pkx.home.example.com";
    let key = "PKX(dGVzdC1rZXktZm9yLXRoZS1vd25lcg==)";
    provider
        .set_rrset(own, txt, 60, list(&[key]))
        .await
        .unwrap();
    assert_eq!(harness.values(own, "TXT"), [key]);
    provider
        .remove_values(own, txt, list(&[key]))
        .await
        .unwrap();
    assert!(harness.values(own, "TXT").is_empty());

    let cname = RecordType::CNAME;
    for target in ["alice.web3.buckyos.ai", "bob.web3.buckyos.ai"] {
        provider
            .set_rrset(WILDCARD, cname, 300, list(&[target]))
            .await
            .unwrap();
        assert_eq!(harness.values(WILDCARD, "CNAME"), [target]);
        let writes = harness.writes();
        provider
            .set_rrset(WILDCARD, cname, 300, list(&[target]))
            .await
            .unwrap();
        assert_eq!(harness.writes(), writes, "setting again writes");
    }
    provider
        .set_rrset(WILDCARD, cname, 300, vec![])
        .await
        .unwrap();
    assert!(harness.values(WILDCARD, "CNAME").is_empty());
    // A wildcard that keeps what another client wrote.
    provider
        .add_values(WILDCARD, txt, 300, list(&["w1"]))
        .await
        .unwrap();
    provider
        .add_values(WILDCARD, txt, 300, list(&["w2"]))
        .await
        .unwrap();
    provider
        .remove_values(WILDCARD, txt, list(&["w1"]))
        .await
        .unwrap();
    assert_eq!(harness.values(WILDCARD, "TXT"), ["w2"]);
    provider
        .set_rrset(WILDCARD, txt, 300, vec![])
        .await
        .unwrap();

    let a = RecordType::A;
    let twice = list(&["203.0.113.7", "203.0.113.8"]);
    provider
        .set_rrset(HOME, a, 300, twice.clone())
        .await
        .unwrap();
    assert_eq!(harness.values(HOME, "A"), twice);
    provider
        .set_rrset(HOME, a, 300, list(&["203.0.113.8", "203.0.113.9"]))
        .await
        .unwrap();
    assert_eq!(harness.values(HOME, "A"), ["203.0.113.8", "203.0.113.9"]);
    let aaaa = RecordType::AAAA;
    provider
        .add_values("v6.home.example.com", aaaa, 300, list(&["2001:DB8::7"]))
        .await
        .unwrap();
    assert_eq!(
        harness.values("v6.home.example.com", "AAAA"),
        ["2001:db8::7"]
    );
    provider
        .set_rrset("v6.home.example.com", aaaa, 300, vec![])
        .await
        .unwrap();

    harness.limit(1);
    provider
        .add_values(CHALLENGE, txt, 60, list(&["late"]))
        .await
        .unwrap();
    assert_eq!(harness.values(CHALLENGE, "TXT"), ["late", "other client"]);
    harness.limit(1);
    let fresh = harness.provider();
    fresh
        .remove_values(CHALLENGE, txt, list(&["late"]))
        .await
        .unwrap();
    assert_eq!(harness.values(CHALLENGE, "TXT"), ["other client"]);
    harness.limit(0);

    provider.set_rrset(HOME, a, 300, vec![]).await.unwrap();
    assert!(harness.values(HOME, "A").is_empty());
    assert_eq!(
        harness.unplanned(),
        before,
        "records outside of the plan changed"
    );
    assert_eq!(
        harness.zone.lock().unwrap().records.len(),
        UNPLANNED.len() + 1
    );

    if service.missing_zone {
        let missing = harness.provider_for("missing.example");
        let error = clean(
            &service,
            missing
                .add_values("x.missing.example", txt, 60, list(&["x"]))
                .await,
        );
        assert!(
            matches!(error, DnsProviderError::ZoneNotFound(_)),
            "{error:?}"
        );
    }

    harness.zone.lock().unwrap().revoked = true;
    let writes = harness.writes();
    let refused = harness.provider();
    for result in [
        refused.add_values(CHALLENGE, txt, 60, list(&["x"])).await,
        refused.set_rrset(HOME, a, 60, list(&["192.0.2.1"])).await,
        refused
            .remove_values(CHALLENGE, txt, list(&["other client"]))
            .await,
    ] {
        let error = clean(&service, result);
        assert!(
            matches!(error, DnsProviderError::Unauthorized(_)),
            "{error:?}"
        );
    }
    assert_eq!(harness.writes(), writes);
    harness.zone.lock().unwrap().revoked = false;
    assert_eq!(harness.unplanned(), before);
    harness
}
