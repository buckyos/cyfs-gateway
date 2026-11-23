//! Tries one DNS service with a real account: writes, reads back and deletes
//! temporary TXT and CNAME records, and checks that nothing else changed.
//!
//! cargo run -p cyfs-dns-provider --example selftest -- --credential <file> --domain <domain>

use std::collections::BTreeMap;
use std::error::Error;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use cyfs_dns_provider::{
    DnsCredential, DnsLookup, DnsRcode, DnsRecordProviderRef, RecordType, SystemDnsLookup,
    ZoneApex, create_provider, detect_provider, find_zone_apex, provider_info,
};
use futures::future::join_all;
use serde_json::{Value, json};

const USAGE: &str = "\
usage: selftest --credential <file> --domain <domain> [options]

  --credential <file>   {\"provider\": \"<id>\", \"fields\": {\"<field>\": \"<value>\"}}
  --domain <domain>     a domain in the account, or a name below it
  --zone <name>         the zone, when it cannot be looked up (test environments)
  --endpoint <url>      API address of an official test environment
  --txt-name <name>     name for the TXT records (default: random). Existing values stay.
  --cname-name <name>   name for the CNAME record (default: random). Must be unused.
  --api-only            do not ask the name servers (test environments)
  --accept-only         the service checks changes without making them (TransIP demo token)
  --ttl <seconds>       default 600
  --timeout <seconds>   how long to wait for the name servers, default 300
  --report <file>       write the JSON report there instead of to stdout";

const TARGETS: [&str; 2] = ["www.iana.org", "www.icann.org"];
const POLL: Duration = Duration::from_secs(3);
/// Some services list a new record only after a while.
const LIST_WAIT: Duration = Duration::from_secs(60);

type Failure = Box<dyn Error>;

struct Options {
    credential: PathBuf,
    domain: String,
    zone: Option<String>,
    endpoint: Option<String>,
    txt_name: Option<String>,
    cname_name: Option<String>,
    api_only: bool,
    accept_only: bool,
    ttl: u32,
    timeout: Duration,
    report: Option<PathBuf>,
}

fn host(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

impl Options {
    fn parse() -> Result<Self, Failure> {
        let mut values: BTreeMap<String, String> = BTreeMap::new();
        let mut arguments = std::env::args().skip(1);
        while let Some(argument) = arguments.next() {
            let name = argument
                .strip_prefix("--")
                .ok_or_else(|| format!("unexpected argument {argument}"))?
                .to_string();
            let value = match name.as_str() {
                "api-only" | "accept-only" => String::new(),
                "credential" | "domain" | "zone" | "endpoint" | "txt-name" | "cname-name"
                | "ttl" | "timeout" | "report" => arguments
                    .next()
                    .ok_or_else(|| format!("--{name} needs a value"))?,
                _ => return Err(format!("unknown option --{name}").into()),
            };
            values.insert(name, value);
        }
        let mut take = |name: &str| values.remove(name);
        let seconds = |value: Option<String>, default: u64| match value {
            Some(value) => value.parse().map_err(|_| format!("not a number: {value}")),
            None => Ok(default),
        };
        Ok(Self {
            credential: take("credential").ok_or("--credential is missing")?.into(),
            domain: host(&take("domain").ok_or("--domain is missing")?),
            zone: take("zone").map(|name| host(&name)),
            endpoint: take("endpoint"),
            txt_name: take("txt-name").map(|name| host(&name)),
            cname_name: take("cname-name").map(|name| host(&name)),
            api_only: take("api-only").is_some(),
            accept_only: take("accept-only").is_some(),
            ttl: seconds(take("ttl"), 600)? as u32,
            timeout: Duration::from_secs(seconds(take("timeout"), 300)?),
            report: take("report").map(PathBuf::from),
        })
    }
}

fn random() -> String {
    let mut bytes = [0u8; 5];
    openssl::rand::rand_bytes(&mut bytes).expect("system random source");
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn sorted(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values
}

/// One test run; everything it learns goes into `steps`.
struct Run {
    options: Options,
    zone: ZoneApex,
    provider: DnsRecordProviderRef,
    lookup: Arc<SystemDnsLookup>,
    steps: Vec<Value>,
    failed: bool,
    /// Test names that were unused at the start.
    unused: Vec<String>,
}

impl Run {
    /// The domain stays out of the report.
    fn hide(&self, text: &str) -> String {
        let mut text = text.to_string();
        for (name, shown) in [
            (&self.options.domain, "<domain>"),
            (&self.zone.apex, "<zone>"),
        ] {
            text = text.replace(name.as_str(), shown);
        }
        text
    }

    fn record(&mut self, step: &str, started: Instant, result: Result<String, Failure>) -> bool {
        let (passed, detail) = match result {
            Ok(detail) => (true, detail),
            Err(error) => (false, error.to_string()),
        };
        let detail = self.hide(&detail);
        let milliseconds = started.elapsed().as_millis() as u64;
        eprintln!(
            "{} {step} ({milliseconds} ms) {detail}",
            if passed { "ok    " } else { "FAILED" }
        );
        self.steps.push(json!({
            "step": step, "passed": passed, "ms": milliseconds, "detail": detail,
        }));
        self.failed |= !passed;
        passed
    }

    async fn api_has(
        &self,
        name: &str,
        ty: RecordType,
        expected: Vec<String>,
    ) -> Result<String, Failure> {
        if self.options.accept_only {
            return Ok("accepted".to_string());
        }
        let expected = sorted(expected);
        let started = Instant::now();
        loop {
            let found = sorted(self.provider.list_values(name, ty).await?);
            if found == expected {
                return Ok(format!("the service has {} value(s)", found.len()));
            }
            if started.elapsed() > LIST_WAIT {
                return Err(format!("the service has {found:?}, expected {expected:?}").into());
            }
            tokio::time::sleep(POLL).await;
        }
    }

    /// Every name server that answers has exactly these values among `ours`.
    async fn dns_has(
        &self,
        name: &str,
        ty: RecordType,
        ours: &[&str],
        expected: &[&str],
    ) -> Result<String, Failure> {
        if self.options.api_only || self.options.accept_only {
            return Ok("name servers not asked".to_string());
        }
        let started = Instant::now();
        loop {
            let answers = join_all(self.zone.ns.iter().map(|server| async move {
                let answer = self.lookup.direct(server, name, ty).await.ok()?;
                matches!(answer.rcode, DnsRcode::NoError | DnsRcode::NxDomain).then(|| {
                    let values = answer.values(ty);
                    let found: Vec<&str> = ours
                        .iter()
                        .copied()
                        .filter(|value| values.iter().any(|found| found == value))
                        .collect();
                    found == expected
                })
            }))
            .await;
            let answering: Vec<bool> = answers.into_iter().flatten().collect();
            if !answering.is_empty() && answering.iter().all(|same| *same) {
                return Ok(format!(
                    "{} of {} name servers agree after {} s",
                    answering.len(),
                    self.zone.ns.len(),
                    started.elapsed().as_secs()
                ));
            }
            if started.elapsed() > self.options.timeout {
                return Err(format!(
                    "{} of {} answering name servers have {expected:?}",
                    answering.iter().filter(|same| **same).count(),
                    answering.len()
                )
                .into());
            }
            tokio::time::sleep(POLL).await;
        }
    }

    /// Records around the test names, which have to be the same at the end.
    async fn surroundings(&self) -> Result<BTreeMap<String, Vec<String>>, Failure> {
        use RecordType::{A, AAAA, CNAME, NS, TXT};
        let domain = &self.options.domain;
        let apex = &self.zone.apex;
        let mut wanted = vec![(apex.clone(), vec![A, AAAA, TXT, NS])];
        if domain != apex {
            wanted.push((domain.clone(), vec![A, AAAA, TXT, CNAME]));
        }
        let mut found = BTreeMap::new();
        for (name, types) in &wanted {
            for ty in types {
                let values = self.provider.list_values(name, *ty).await?;
                found.insert(format!("service {name} {ty:?}"), sorted(values));
            }
        }
        if self.options.api_only || self.options.accept_only {
            return Ok(found);
        }
        for label in [
            "www",
            "mail",
            "_dmarc",
            "_acme-challenge",
            "_pkx",
            "*",
            "ood1",
            "sys",
        ] {
            wanted.push((format!("{label}.{domain}"), vec![A, AAAA, TXT, CNAME]));
        }
        for (name, types) in &wanted {
            for ty in types {
                let mut seen = Vec::new();
                for server in &self.zone.ns {
                    if let Ok(answer) = self.lookup.direct(server, name, *ty).await {
                        seen = sorted(answer.values(*ty));
                        break;
                    }
                }
                found.insert(format!("dns {name} {ty:?}"), seen);
            }
        }
        Ok(found)
    }

    async fn must_be_unused(&self, name: &str) -> Result<String, Failure> {
        use RecordType::{A, AAAA, CNAME, TXT};
        for ty in [CNAME, TXT, A, AAAA] {
            if !self.provider.list_values(name, ty).await?.is_empty() {
                return Err(format!("{name} already has {ty:?} records, use another name").into());
            }
        }
        Ok("unused".to_string())
    }

    async fn txt(&mut self, name: &str) -> Result<(), Failure> {
        let ty = RecordType::TXT;
        let ttl = self.options.ttl;
        let provider = self.provider.clone();
        let before = provider.list_values(name, ty).await?;
        let values = [
            format!("buckyos-test-{}", random()),
            format!("buckyos-test-{}", random()),
        ];
        let [first, second] = [values[0].as_str(), values[1].as_str()];
        let with = |added: &[&str]| -> Vec<String> {
            before
                .iter()
                .cloned()
                .chain(added.iter().map(|value| value.to_string()))
                .collect()
        };
        for (step, added, after) in [
            ("add a TXT value", first, vec![first]),
            (
                "add a second value of the same name",
                second,
                vec![first, second],
            ),
            ("add the first value again", first, vec![first, second]),
        ] {
            let started = Instant::now();
            let result = async {
                provider
                    .add_values(name, ty, ttl, vec![added.to_string()])
                    .await?;
                self.api_has(name, ty, with(&after)).await
            }
            .await;
            if !self.record(step, started, result) {
                return self.clean_txt(name, &values).await;
            }
        }
        let started = Instant::now();
        let result = self
            .dns_has(name, ty, &[first, second], &[first, second])
            .await;
        self.record("both values on the name servers", started, result);

        for (step, removed, after) in [
            ("remove one value", first, vec![second]),
            ("remove it again", first, vec![second]),
        ] {
            let started = Instant::now();
            let result = async {
                provider
                    .remove_values(name, ty, vec![removed.to_string()])
                    .await?;
                self.api_has(name, ty, with(&after)).await
            }
            .await;
            self.record(step, started, result);
        }
        let started = Instant::now();
        let result = self.dns_has(name, ty, &[first, second], &[second]).await;
        self.record(
            "only the other value is left on the name servers",
            started,
            result,
        );

        let started = Instant::now();
        let result = async {
            provider
                .remove_values(name, ty, vec![second.to_string()])
                .await?;
            self.api_has(name, ty, with(&[])).await?;
            self.dns_has(name, ty, &[first, second], &[]).await
        }
        .await;
        self.record("remove the last value", started, result);
        self.clean_txt(name, &values).await
    }

    async fn clean_txt(&mut self, name: &str, values: &[String]) -> Result<(), Failure> {
        let left = self.provider.list_values(name, RecordType::TXT).await?;
        if left.iter().any(|value| values.contains(value)) {
            self.provider
                .remove_values(name, RecordType::TXT, values.to_vec())
                .await?;
        }
        Ok(())
    }

    async fn cname(&mut self, kind: &str, name: &str, asked: &str) {
        let ty = RecordType::CNAME;
        let ttl = self.options.ttl;
        let provider = self.provider.clone();
        let started = Instant::now();
        let result = self.must_be_unused(name).await;
        if !self.record(&format!("{kind}: name is unused"), started, result) {
            return;
        }
        self.unused.push(name.to_string());
        for (step, target) in [("write", TARGETS[0]), ("replace", TARGETS[1])] {
            let started = Instant::now();
            let result = async {
                provider
                    .set_rrset(name, ty, ttl, vec![target.to_string()])
                    .await?;
                provider
                    .set_rrset(name, ty, ttl, vec![target.to_string()])
                    .await?;
                self.api_has(name, ty, vec![target.to_string()]).await?;
                self.dns_has(asked, ty, &TARGETS, &[target]).await
            }
            .await;
            self.record(&format!("{kind}: {step}"), started, result);
        }
        let started = Instant::now();
        let result = async {
            provider.set_rrset(name, ty, ttl, vec![]).await?;
            self.api_has(name, ty, vec![]).await?;
            self.dns_has(asked, ty, &TARGETS, &[]).await
        }
        .await;
        self.record(&format!("{kind}: delete"), started, result);
    }

    async fn all(&mut self) -> Result<(), Failure> {
        let domain = self.options.domain.clone();
        let started = Instant::now();
        let before = match self.surroundings().await {
            Ok(before) => before,
            Err(error) => {
                self.record("read the zone", started, Err(error));
                return Ok(());
            }
        };
        let count = before.values().map(Vec::len).sum::<usize>();
        self.record(
            "read the zone",
            started,
            Ok(format!("{count} values noted")),
        );

        let label = format!("buckyos-test-{}", random());
        let txt_name = match self.options.txt_name.clone() {
            Some(name) => name,
            None => format!("_{label}.{domain}"),
        };
        if let Err(error) = self.txt(&txt_name).await {
            self.record("TXT", Instant::now(), Err(error));
        }
        match self.options.cname_name.clone() {
            Some(name) => {
                let asked = name.replacen('*', &random(), 1);
                self.cname("CNAME", &name, &asked).await;
            }
            None => {
                let name = format!("{label}.{domain}");
                self.cname("CNAME", &name, &name).await;
                let wildcard = format!("*.{label}.{domain}");
                let asked = format!("{}.{label}.{domain}", random());
                self.cname("wildcard CNAME", &wildcard, &asked).await;
            }
        }

        for name in std::mem::take(&mut self.unused) {
            let left = self.provider.list_values(&name, RecordType::CNAME).await;
            if !left.is_ok_and(|left| left.is_empty())
                && let Err(error) = self
                    .provider
                    .set_rrset(&name, RecordType::CNAME, self.options.ttl, vec![])
                    .await
            {
                let error = format!("{name} may be left over: {error}");
                self.record("clean up", Instant::now(), Err(error.into()));
            }
        }

        let started = Instant::now();
        let result = self.surroundings().await.and_then(|after| {
            let changed: Vec<String> = before
                .iter()
                .filter(|(key, values)| after.get(*key) != Some(values))
                .map(|(key, values)| format!("{key}: {values:?} -> {:?}", after.get(key)))
                .collect();
            match changed.as_slice() {
                [] => Ok("nothing else changed".to_string()),
                changed => Err(changed.join("; ").into()),
            }
        });
        self.record("other records are the same", started, result);
        Ok(())
    }
}

async fn run(options: Options) -> Result<bool, Failure> {
    let text = std::fs::read_to_string(&options.credential)
        .map_err(|error| format!("{}: {error}", options.credential.display()))?;
    let mut credential: DnsCredential = serde_json::from_str(&text)
        .map_err(|error| format!("credential: line {} is invalid", error.line()))?;
    if let Some(endpoint) = &options.endpoint {
        credential.endpoint = Some(endpoint.clone());
    }
    credential.validate()?;
    let info = provider_info(&credential.provider).ok_or("unknown provider")?;

    let lookup = SystemDnsLookup::new();
    let zone = match &options.zone {
        Some(zone) if options.api_only || options.accept_only => ZoneApex {
            apex: zone.clone(),
            ns: Vec::new(),
        },
        _ => find_zone_apex(&*lookup, &options.domain).await?,
    };
    if options
        .zone
        .as_ref()
        .is_some_and(|given| *given != zone.apex)
    {
        return Err(format!("the zone of {} is {}", options.domain, zone.apex).into());
    }
    let detected = detect_provider(&zone.ns).map(|info| info.id);
    eprintln!(
        "{} in zone {}, name servers {:?}",
        options.domain, zone.apex, zone.ns
    );
    if !zone.ns.is_empty() && detected != Some(info.id) {
        eprintln!(
            "note: these name servers are recognized as {detected:?}, not {}",
            info.id
        );
    }

    let provider = create_provider(&credential, &zone.apex)?;
    let mut run = Run {
        options,
        zone,
        provider,
        lookup,
        steps: Vec::new(),
        failed: false,
        unused: Vec::new(),
    };
    run.all().await?;

    let finished = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default();
    let report = json!({
        "tool": concat!("cyfs-dns-provider selftest ", env!("CARGO_PKG_VERSION")),
        "provider": info.id,
        "endpoint": credential.endpoint,
        "finished_at": finished,
        "api_only": run.options.api_only,
        "accept_only": run.options.accept_only,
        "name_servers": run.zone.ns.iter().map(|ns| run.hide(ns)).collect::<Vec<_>>(),
        "detected_as": detected,
        "domain_is_zone": run.options.domain == run.zone.apex,
        "passed": !run.failed,
        "steps": run.steps,
    });
    let text = serde_json::to_string_pretty(&report)?;
    for (field, value) in &credential.fields {
        let secret = info
            .fields
            .iter()
            .any(|known| known.id == field && known.secret);
        if secret && text.contains(value.trim()) {
            return Err("the report would contain a secret, it is not written".into());
        }
    }
    match &run.options.report {
        Some(path) => std::fs::write(path, text)?,
        None => println!("{text}"),
    }
    eprintln!("{}", if run.failed { "FAILED" } else { "passed" });
    Ok(!run.failed)
}

#[tokio::main]
async fn main() -> ExitCode {
    let options = match Options::parse() {
        Ok(options) => options,
        Err(error) => {
            eprintln!("{error}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    match run(options).await {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
