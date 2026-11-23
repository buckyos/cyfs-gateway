use futures::future::join_all;
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType as WireType};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::{Instant, sleep, timeout};

use crate::crypto::random_bytes;
use crate::provider::RecordType;
use crate::values::{host, is_under, type_name, unquote_txt};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DnsRecordData {
    pub name: String,
    pub ty: RecordType,
    pub ttl: u32,
    /// Presentation form as in [`crate::provider::DnsRecordProvider`]. SOA is
    /// `<mname> <rname> <serial> …`; CAA is `<flags> <tag> "<value>"`.
    pub value: String,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DnsRcode {
    NoError,
    NxDomain,
    ServFail,
    Refused,
    Other,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsAnswer {
    pub rcode: DnsRcode,
    /// Answer section in order, a CNAME chain included; types without a
    /// [`RecordType`] are left out.
    pub answers: Vec<DnsRecordData>,
    /// Authority section (SOA of a negative answer, NS of a referral).
    pub authority: Vec<DnsRecordData>,
    /// The AA bit (always false for `public`).
    pub authoritative: bool,
}

impl DnsAnswer {
    /// Values of `ty` in the answer section.
    pub fn values(&self, ty: RecordType) -> Vec<String> {
        self.answers
            .iter()
            .filter(|record| record.ty == ty)
            .map(|record| record.value.clone())
            .collect()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DnsLookupError {
    #[error("dns lookup timed out: {0}")]
    Timeout(String),
    #[error("dns lookup failed: {0}")]
    Failed(String),
}

pub type DnsLookupResult<T> = Result<T, DnsLookupError>;

#[async_trait::async_trait]
pub trait DnsLookup: Send + Sync {
    /// Asks a public validating recursive resolver over DoH.
    async fn public(&self, name: &str, ty: RecordType) -> DnsLookupResult<DnsAnswer>;
    /// Asks one server directly without recursion (UDP, TCP when truncated).
    /// `server` is a host name or an IP, optionally `:port`.
    async fn direct(&self, server: &str, name: &str, ty: RecordType) -> DnsLookupResult<DnsAnswer>;
}

pub type DnsLookupRef = Arc<dyn DnsLookup>;

const GOOGLE: &str = "https://dns.google/resolve";
const CLOUDFLARE: &str = "https://cloudflare-dns.com/dns-query";
const DNS_PORT: u16 = 53;
const QUERY_TIMEOUT: Duration = Duration::from_secs(3);
const ATTEMPTS: usize = 2;
const UDP_PAYLOAD: u16 = 1232;
const POLL_INTERVAL: Duration = Duration::from_secs(3);
/// Delegations followed below the zone the public resolver knows.
const MAX_CUTS: usize = 16;

/// dns.google, then cloudflare-dns.com; direct queries on port 53.
pub struct SystemDnsLookup {
    http: reqwest::Client,
    resolvers: Vec<String>,
}

impl SystemDnsLookup {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(6))
                .build()
                .unwrap_or_default(),
            resolvers: vec![GOOGLE.to_string(), CLOUDFLARE.to_string()],
        })
    }

    async fn doh(&self, resolver: &str, name: &str, ty: RecordType) -> DnsLookupResult<DnsAnswer> {
        #[derive(Deserialize)]
        struct Item {
            name: String,
            #[serde(rename = "type")]
            ty: u16,
            #[serde(rename = "TTL", default)]
            ttl: u32,
            #[serde(default)]
            data: String,
        }
        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "Status")]
            status: u16,
            #[serde(rename = "Answer", default)]
            answer: Vec<Item>,
            #[serde(rename = "Authority", default)]
            authority: Vec<Item>,
        }

        let failed = |text: String| DnsLookupError::Failed(format!("{name} {ty:?}: {text}"));
        let response = self
            .http
            .get(resolver)
            .query(&[("name", name), ("type", type_name(ty))])
            .header("accept", "application/dns-json")
            .send()
            .await
            .map_err(|error| {
                if error.is_timeout() {
                    DnsLookupError::Timeout(format!("{resolver} {name}"))
                } else {
                    failed(error.to_string())
                }
            })?;
        if !response.status().is_success() {
            return Err(failed(format!("{resolver}: HTTP {}", response.status())));
        }
        let response: Response = response
            .json()
            .await
            .map_err(|error| failed(error.to_string()))?;
        let records = |items: Vec<Item>| -> Vec<DnsRecordData> {
            items
                .into_iter()
                .filter_map(|item| {
                    let ty = known_type(WireType::from(item.ty))?;
                    Some(DnsRecordData {
                        name: host(&item.name),
                        ty,
                        ttl: item.ttl,
                        value: json_value(ty, &item.data),
                    })
                })
                .collect()
        };
        Ok(DnsAnswer {
            rcode: rcode(ResponseCode::from(0, (response.status & 0x0f) as u8)),
            answers: records(response.answer),
            authority: records(response.authority),
            authoritative: false,
        })
    }

    /// IPv4 first.
    async fn addresses(&self, server: &str) -> DnsLookupResult<Vec<SocketAddr>> {
        let (name, port) = split_server(server);
        if let Ok(ip) = name.parse::<IpAddr>() {
            return Ok(vec![SocketAddr::new(ip, port)]);
        }
        let mut addresses: Vec<SocketAddr> = match timeout(
            QUERY_TIMEOUT,
            tokio::net::lookup_host((name.as_str(), port)),
        )
        .await
        {
            Ok(Ok(found)) => found.collect(),
            _ => Vec::new(),
        };
        if addresses.is_empty() {
            for ty in [RecordType::A, RecordType::AAAA] {
                let values = self.public(&name, ty).await?.values(ty);
                addresses.extend(
                    values
                        .iter()
                        .filter_map(|value| value.parse::<IpAddr>().ok())
                        .map(|ip| SocketAddr::new(ip, port)),
                );
            }
        }
        addresses.sort_by_key(SocketAddr::is_ipv6);
        addresses.dedup();
        if addresses.is_empty() {
            return Err(DnsLookupError::Failed(format!("{server} has no address")));
        }
        Ok(addresses)
    }
}

#[async_trait::async_trait]
impl DnsLookup for SystemDnsLookup {
    async fn public(&self, name: &str, ty: RecordType) -> DnsLookupResult<DnsAnswer> {
        let name = host(name);
        let mut last = DnsLookupError::Failed("no resolver".to_string());
        for resolver in &self.resolvers {
            match self.doh(resolver, &name, ty).await {
                Ok(answer) => return Ok(answer),
                Err(error) => last = error,
            }
        }
        Err(last)
    }

    async fn direct(&self, server: &str, name: &str, ty: RecordType) -> DnsLookupResult<DnsAnswer> {
        let name = host(name);
        let mut last = DnsLookupError::Failed(format!("{server} has no address"));
        for address in self.addresses(server).await? {
            match ask(address, &name, ty).await {
                Ok(answer) => return Ok(answer),
                Err(DnsLookupError::Timeout(_)) => {
                    last = DnsLookupError::Timeout(format!("{server} ({address})"));
                }
                Err(DnsLookupError::Failed(text)) => {
                    last = DnsLookupError::Failed(format!("{server} ({address}): {text}"));
                }
            }
        }
        Err(last)
    }
}

fn split_server(server: &str) -> (String, u16) {
    let server = server.trim();
    if let Ok(address) = server.parse::<SocketAddr>() {
        return (address.ip().to_string(), address.port());
    }
    let bare = server.trim_start_matches('[').trim_end_matches(']');
    if bare.parse::<Ipv6Addr>().is_ok() {
        return (bare.to_string(), DNS_PORT);
    }
    match server.rsplit_once(':') {
        Some((name, port)) => match port.parse() {
            Ok(port) => (host(name), port),
            Err(_) => (host(server), DNS_PORT),
        },
        None => (host(server), DNS_PORT),
    }
}

fn rcode(code: ResponseCode) -> DnsRcode {
    match code {
        ResponseCode::NoError => DnsRcode::NoError,
        ResponseCode::NXDomain => DnsRcode::NxDomain,
        ResponseCode::ServFail => DnsRcode::ServFail,
        ResponseCode::Refused => DnsRcode::Refused,
        _ => DnsRcode::Other,
    }
}

fn known_type(ty: WireType) -> Option<RecordType> {
    Some(match ty {
        WireType::A => RecordType::A,
        WireType::AAAA => RecordType::AAAA,
        WireType::CNAME => RecordType::CNAME,
        WireType::NS => RecordType::NS,
        WireType::TXT => RecordType::TXT,
        WireType::SOA => RecordType::SOA,
        WireType::CAA => RecordType::CAA,
        _ => return None,
    })
}

fn wire_type(ty: RecordType) -> WireType {
    match ty {
        RecordType::A => WireType::A,
        RecordType::AAAA => WireType::AAAA,
        RecordType::CNAME => WireType::CNAME,
        RecordType::NS => WireType::NS,
        RecordType::TXT => WireType::TXT,
        RecordType::SOA => WireType::SOA,
        RecordType::CAA => WireType::CAA,
    }
}

/// `data` of a DoH JSON record.
fn json_value(ty: RecordType, data: &str) -> String {
    let data = data.trim();
    match ty {
        RecordType::A | RecordType::AAAA => data
            .parse::<IpAddr>()
            .map_or_else(|_| data.to_string(), |ip| ip.to_string()),
        RecordType::CNAME | RecordType::NS => host(data),
        RecordType::TXT => unquote_txt(data),
        RecordType::SOA => {
            let mut fields = data.split_whitespace();
            let names = fields.by_ref().take(2).map(host).collect::<Vec<_>>();
            names
                .into_iter()
                .chain(fields.map(str::to_string))
                .collect::<Vec<_>>()
                .join(" ")
        }
        RecordType::CAA => caa_value(data),
    }
}

fn caa_value(data: &str) -> String {
    // Types a resolver does not print come in the generic form of RFC 3597.
    if let Some(generic) = data.strip_prefix("\\#") {
        let digits: String = generic.split_whitespace().skip(1).collect();
        let bytes: Vec<u8> = (0..digits.len() / 2)
            .filter_map(|at| u8::from_str_radix(digits.get(at * 2..at * 2 + 2)?, 16).ok())
            .collect();
        if let [flags, length, rest @ ..] = bytes.as_slice()
            && rest.len() >= usize::from(*length)
        {
            let (tag, value) = rest.split_at(usize::from(*length));
            return format!(
                "{flags} {} \"{}\"",
                String::from_utf8_lossy(tag),
                String::from_utf8_lossy(value)
            );
        }
        return data.to_string();
    }
    let mut fields = data.splitn(3, char::is_whitespace);
    match (fields.next(), fields.next(), fields.next()) {
        (Some(flags), Some(tag), Some(value)) => {
            format!("{flags} {tag} \"{}\"", value.trim().trim_matches('"'))
        }
        _ => data.to_string(),
    }
}

fn wire_record(record: &Record) -> Option<DnsRecordData> {
    let name_text = |name: &Name| host(&name.to_ascii());
    let (ty, value) = match record.data() {
        RData::A(ip) => (RecordType::A, ip.to_string()),
        RData::AAAA(ip) => (RecordType::AAAA, ip.to_string()),
        RData::CNAME(name) => (RecordType::CNAME, name_text(&name.0)),
        RData::NS(name) => (RecordType::NS, name_text(&name.0)),
        RData::TXT(text) => {
            let bytes: Vec<u8> = text.iter().flat_map(|part| part.iter().copied()).collect();
            (
                RecordType::TXT,
                String::from_utf8_lossy(&bytes).into_owned(),
            )
        }
        RData::SOA(soa) => (
            RecordType::SOA,
            format!(
                "{} {} {} {} {} {} {}",
                name_text(soa.mname()),
                name_text(soa.rname()),
                soa.serial(),
                soa.refresh(),
                soa.retry(),
                soa.expire(),
                soa.minimum()
            ),
        ),
        RData::CAA(caa) => (RecordType::CAA, caa.to_string()),
        _ => return None,
    };
    Some(DnsRecordData {
        name: name_text(record.name()),
        ty,
        ttl: record.ttl(),
        value,
    })
}

async fn ask(server: SocketAddr, name: &str, ty: RecordType) -> DnsLookupResult<DnsAnswer> {
    let timed_out = || DnsLookupError::Timeout(server.to_string());
    let mut last = timed_out();
    for attempt in 0..ATTEMPTS {
        // Some servers do not answer queries with EDNS.
        let query = query(name, ty, attempt == 0)?;
        let mut reply = match timeout(QUERY_TIMEOUT, ask_udp(server, &query)).await {
            Ok(Ok(reply)) => reply,
            Ok(Err(error)) => {
                last = error;
                continue;
            }
            Err(_) => {
                last = timed_out();
                continue;
            }
        };
        if reply.response_code() == ResponseCode::FormErr && attempt + 1 < ATTEMPTS {
            continue;
        }
        if reply.truncated() {
            reply = timeout(QUERY_TIMEOUT, ask_tcp(server, &query))
                .await
                .map_err(|_| timed_out())??;
        }
        return Ok(DnsAnswer {
            rcode: rcode(reply.response_code()),
            answers: reply.answers().iter().filter_map(wire_record).collect(),
            authority: reply
                .name_servers()
                .iter()
                .filter_map(wire_record)
                .collect(),
            authoritative: reply.authoritative(),
        });
    }
    Err(last)
}

fn query(name: &str, ty: RecordType, edns: bool) -> DnsLookupResult<Message> {
    let name = Name::from_ascii(format!("{name}."))
        .map_err(|error| DnsLookupError::Failed(format!("{name}: {error}")))?;
    let mut message = Message::new();
    message
        .set_id(u16::from_be_bytes(random_bytes()))
        .set_message_type(MessageType::Query)
        .set_op_code(OpCode::Query)
        .set_recursion_desired(false)
        .add_query(Query::query(name, wire_type(ty)));
    if edns {
        let mut options = Edns::new();
        options.set_max_payload(UDP_PAYLOAD);
        message.set_edns(options);
    }
    Ok(message)
}

fn io_error(error: std::io::Error) -> DnsLookupError {
    DnsLookupError::Failed(error.to_string())
}

fn encode(query: &Message) -> DnsLookupResult<Vec<u8>> {
    query
        .to_vec()
        .map_err(|error| DnsLookupError::Failed(error.to_string()))
}

fn answers(query: &Message, bytes: &[u8]) -> Option<Message> {
    let reply = Message::from_vec(bytes).ok()?;
    let same = reply.id() == query.id()
        && reply.message_type() == MessageType::Response
        && reply
            .queries()
            .first()
            .is_none_or(|question| query.queries().contains(question));
    same.then_some(reply)
}

async fn ask_udp(server: SocketAddr, query: &Message) -> DnsLookupResult<Message> {
    let local = if server.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(local).await.map_err(io_error)?;
    socket.connect(server).await.map_err(io_error)?;
    socket.send(&encode(query)?).await.map_err(io_error)?;
    let mut buffer = vec![0; 4096];
    loop {
        let length = socket.recv(&mut buffer).await.map_err(io_error)?;
        if let Some(reply) = answers(query, &buffer[..length]) {
            return Ok(reply);
        }
    }
}

async fn ask_tcp(server: SocketAddr, query: &Message) -> DnsLookupResult<Message> {
    let mut stream = TcpStream::connect(server).await.map_err(io_error)?;
    let query_bytes = encode(query)?;
    let mut framed = (query_bytes.len() as u16).to_be_bytes().to_vec();
    framed.extend(query_bytes);
    stream.write_all(&framed).await.map_err(io_error)?;
    let length = stream.read_u16().await.map_err(io_error)?;
    let mut buffer = vec![0; usize::from(length)];
    stream.read_exact(&mut buffer).await.map_err(io_error)?;
    answers(query, &buffer).ok_or_else(|| DnsLookupError::Failed("unexpected reply".to_string()))
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ZoneApex {
    /// The name that owns the SOA.
    pub apex: String,
    /// Its authoritative name servers.
    pub ns: Vec<String>,
}

fn last_labels(name: &str, count: usize) -> &str {
    name.rmatch_indices('.')
        .nth(count - 1)
        .map_or(name, |(at, _)| &name[at + 1..])
}

fn owner_of(records: &[DnsRecordData], ty: RecordType) -> Option<&str> {
    records
        .iter()
        .find(|record| record.ty == ty)
        .map(|record| record.name.as_str())
}

fn ns_of(records: &[DnsRecordData], owner: &str) -> Vec<String> {
    let mut servers: Vec<String> = records
        .iter()
        .filter(|record| record.ty == RecordType::NS && record.name == owner)
        .map(|record| record.value.clone())
        .collect();
    servers.sort();
    servers.dedup();
    servers
}

/// The zone above `name` that a public resolver can be asked about. Only its
/// last two labels are: they exist, so nothing is cached as missing.
async fn known_zone(lookup: &dyn DnsLookup, name: &str) -> DnsLookupResult<ZoneApex> {
    let start = last_labels(name, 2);
    let answer = lookup.public(start, RecordType::SOA).await?;
    if !matches!(answer.rcode, DnsRcode::NoError | DnsRcode::NxDomain) {
        return Err(DnsLookupError::Failed(format!(
            "{start} SOA: {:?}",
            answer.rcode
        )));
    }
    let own = answer
        .answers
        .iter()
        .find(|record| record.ty == RecordType::SOA && record.name == start)
        .map(|record| record.name.as_str());
    let apex = own
        .or_else(|| {
            owner_of(&answer.authority, RecordType::SOA).filter(|owner| is_under(start, owner))
        })
        .filter(|apex| !apex.is_empty())
        .ok_or_else(|| DnsLookupError::Failed(format!("{start} is in no zone")))?
        .to_string();
    let ns = ns_of(&lookup.public(&apex, RecordType::NS).await?.answers, &apex);
    if ns.is_empty() {
        return Err(DnsLookupError::Failed(format!(
            "{apex} has no name servers"
        )));
    }
    Ok(ZoneApex { apex, ns })
}

enum Below {
    /// The zone itself holds the name.
    Here,
    /// The name is in this zone below; its name servers when they are known.
    Zone(String, Vec<String>),
}

/// What one server of `zone` says about where `name` is.
fn below(zone: &ZoneApex, name: &str, answer: &DnsAnswer) -> Below {
    let deeper =
        |owner: &str| owner != zone.apex && is_under(owner, &zone.apex) && is_under(name, owner);
    if let Some(owner) = owner_of(&answer.answers, RecordType::SOA) {
        if deeper(owner) {
            return Below::Zone(owner.to_string(), Vec::new());
        }
        return Below::Here;
    }
    if !answer.answers.is_empty() {
        return Below::Here;
    }
    if let Some(owner) = owner_of(&answer.authority, RecordType::SOA) {
        // The server also holds the zone below.
        if deeper(owner) {
            return Below::Zone(owner.to_string(), Vec::new());
        }
        return Below::Here;
    }
    match owner_of(&answer.authority, RecordType::NS) {
        Some(owner) if deeper(owner) => {
            Below::Zone(owner.to_string(), ns_of(&answer.authority, owner))
        }
        _ => Below::Here,
    }
}

/// The zone `name` lives in, found by walking up to the closest SOA.
///
/// A public resolver is asked only about the last two labels of `name` (SOA and
/// NS); below that the name servers of each zone are asked directly, so a name
/// that does not exist yet is not cached as missing.
pub async fn find_zone_apex(lookup: &dyn DnsLookup, name: &str) -> DnsLookupResult<ZoneApex> {
    let name = host(name);
    let mut zone = known_zone(lookup, &name).await?;
    let mut delegated = false;
    for _ in 0..MAX_CUTS {
        if zone.apex == name {
            return Ok(zone);
        }
        let (server, answer) = match first_answer(lookup, &zone, &name).await {
            Ok(answered) => answered,
            // A delegation that nobody serves yet is still where the name is.
            Err(_) if delegated => return Ok(zone),
            Err(error) => return Err(error),
        };
        let Below::Zone(apex, mut ns) = below(&zone, &name, &answer) else {
            return Ok(zone);
        };
        if ns.is_empty() {
            let answer = lookup.direct(&server, &apex, RecordType::NS).await?;
            ns = ns_of(&answer.answers, &apex);
            if ns.is_empty() {
                ns = ns_of(&answer.authority, &apex);
            }
        }
        zone = ZoneApex { apex, ns };
        delegated = true;
    }
    Ok(zone)
}

async fn first_answer(
    lookup: &dyn DnsLookup,
    zone: &ZoneApex,
    name: &str,
) -> DnsLookupResult<(String, DnsAnswer)> {
    let mut last = DnsLookupError::Failed(format!("{} has no name servers", zone.apex));
    for server in &zone.ns {
        match lookup.direct(server, name, RecordType::SOA).await {
            Ok(answer) if matches!(answer.rcode, DnsRcode::NoError | DnsRcode::NxDomain) => {
                return Ok((server.clone(), answer));
            }
            Ok(answer) => last = DnsLookupError::Failed(format!("{server}: {:?}", answer.rcode)),
            Err(error) => last = error,
        }
    }
    Err(last)
}

/// The zone that holds the delegation of `name`: the closest enclosing zone of
/// its parent, so it is the same before and after `name` is delegated.
pub async fn find_parent_zone(lookup: &dyn DnsLookup, name: &str) -> DnsLookupResult<ZoneApex> {
    let name = host(name);
    let (_, parent) = name
        .split_once('.')
        .ok_or_else(|| DnsLookupError::Failed(format!("{name} has no parent")))?;
    find_zone_apex(lookup, parent).await
}

async fn ask_zone(
    lookup: &dyn DnsLookup,
    zone: &ZoneApex,
    name: &str,
    ty: RecordType,
) -> Vec<(String, Result<DnsAnswer, String>)> {
    join_all(zone.ns.iter().map(|server| async move {
        let answer = lookup
            .direct(server, name, ty)
            .await
            .map_err(|error| error.to_string());
        (server.clone(), answer)
    }))
    .await
}

/// Asks every name server of the zone `name` lives in.
/// One entry per server: (server, answer or error text).
pub async fn authoritative_answers(
    lookup: &dyn DnsLookup,
    name: &str,
    ty: RecordType,
) -> DnsLookupResult<Vec<(String, Result<DnsAnswer, String>)>> {
    let name = host(name);
    let zone = find_zone_apex(lookup, &name).await?;
    Ok(ask_zone(lookup, &zone, &name, ty).await)
}

/// Every server that answers for the zone, at least one, has `value`.
fn all_have(answers: &[(String, Result<DnsAnswer, String>)], value: &str) -> bool {
    let mut answering = answers
        .iter()
        .filter_map(|(_, answer)| answer.as_ref().ok())
        .filter(|answer| matches!(answer.rcode, DnsRcode::NoError | DnsRcode::NxDomain))
        .peekable();
    answering.peek().is_some()
        && answering.all(|answer| {
            answer
                .answers
                .iter()
                .any(|record| record.ty == RecordType::TXT && record.value == value)
        })
}

/// Every reachable name server (at least one) returns a TXT record equal to `value`.
pub async fn txt_visible(lookup: &dyn DnsLookup, name: &str, value: &str) -> DnsLookupResult<bool> {
    let answers = authoritative_answers(lookup, name, RecordType::TXT).await?;
    Ok(all_have(&answers, value))
}

/// Polls [`txt_visible`] every 3 seconds; `Ok(false)` when `timeout` passes.
pub async fn wait_txt_visible(
    lookup: &dyn DnsLookup,
    name: &str,
    value: &str,
    timeout: Duration,
) -> DnsLookupResult<bool> {
    let name = host(name);
    let deadline = Instant::now() + timeout;
    let mut zone = None;
    loop {
        if zone.is_none() {
            match find_zone_apex(lookup, &name).await {
                Ok(found) => zone = Some(found),
                Err(error) if Instant::now() + POLL_INTERVAL > deadline => return Err(error),
                Err(_) => {}
            }
        }
        if let Some(zone) = &zone {
            let answers = ask_zone(lookup, zone, &name, RecordType::TXT).await;
            if all_have(&answers, value) {
                return Ok(true);
            }
        }
        if Instant::now() + POLL_INTERVAL > deadline {
            return Ok(false);
        }
        sleep(POLL_INTERVAL).await;
    }
}

#[cfg(test)]
mod tests;
