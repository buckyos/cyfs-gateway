use super::*;
use hickory_proto::rr::rdata::{A, CAA, CNAME, NS, SOA, TXT};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::net::TcpListener;

/// Zones by apex: name servers, records, delegations.
#[derive(Default)]
struct Zone {
    ns: Vec<&'static str>,
    records: Vec<(&'static str, RecordType, &'static str)>,
    delegations: Vec<(&'static str, Vec<&'static str>)>,
}

#[derive(Default)]
struct World {
    zones: HashMap<&'static str, Zone>,
    dead: Vec<&'static str>,
    refusing: Vec<&'static str>,
    public_queries: Mutex<Vec<(String, RecordType)>>,
}

fn data(name: &str, ty: RecordType, value: &str) -> DnsRecordData {
    DnsRecordData {
        name: name.to_string(),
        ty,
        ttl: 60,
        value: value.to_string(),
    }
}

impl World {
    fn zone(
        &mut self,
        apex: &'static str,
        ns: &[&'static str],
        records: &[(&'static str, RecordType, &'static str)],
        delegations: &[(&'static str, &[&'static str])],
    ) {
        self.zones.insert(
            apex,
            Zone {
                ns: ns.to_vec(),
                records: records.to_vec(),
                delegations: delegations
                    .iter()
                    .map(|(name, ns)| (*name, ns.to_vec()))
                    .collect(),
            },
        );
    }

    fn answer(&self, server: &str, name: &str, ty: RecordType) -> DnsAnswer {
        let mut answer = DnsAnswer {
            rcode: DnsRcode::NoError,
            answers: Vec::new(),
            authority: Vec::new(),
            authoritative: true,
        };
        let held = self
            .zones
            .iter()
            .filter(|(apex, zone)| {
                zone.ns.contains(&server) && (apex.is_empty() || is_under(name, apex))
            })
            .max_by_key(|(apex, _)| apex.len());
        let Some((apex, zone)) = held.filter(|_| !self.refusing.contains(&server)) else {
            answer.rcode = DnsRcode::Refused;
            answer.authoritative = false;
            return answer;
        };
        if let Some((cut, ns)) = zone.delegations.iter().find(|(cut, _)| is_under(name, cut)) {
            answer.authoritative = false;
            answer.authority = ns.iter().map(|ns| data(cut, RecordType::NS, ns)).collect();
            return answer;
        }
        let soa = data(apex, RecordType::SOA, "ns.test hostmaster.test 1 2 3 4 5");
        if name == *apex && ty == RecordType::SOA {
            answer.answers.push(soa);
            return answer;
        }
        if name == *apex && ty == RecordType::NS {
            answer.answers = zone
                .ns
                .iter()
                .map(|ns| data(apex, RecordType::NS, ns))
                .collect();
            return answer;
        }
        answer.answers = zone
            .records
            .iter()
            .filter(|(n, t, _)| *n == name && (*t == ty || *t == RecordType::CNAME))
            .map(|(n, t, value)| data(n, *t, value))
            .collect();
        if answer.answers.is_empty() {
            let exists = name == *apex || zone.records.iter().any(|(n, _, _)| is_under(n, name));
            if !exists {
                answer.rcode = DnsRcode::NxDomain;
            }
            answer.authority.push(soa);
        }
        answer
    }

    fn public_names(&self) -> Vec<String> {
        self.public_queries
            .lock()
            .unwrap()
            .iter()
            .map(|(name, _)| name.clone())
            .collect()
    }
}

#[async_trait::async_trait]
impl DnsLookup for World {
    async fn public(&self, name: &str, ty: RecordType) -> DnsLookupResult<DnsAnswer> {
        self.public_queries
            .lock()
            .unwrap()
            .push((name.to_string(), ty));
        let mut server = "root";
        loop {
            let answer = self.answer(server, name, ty);
            let Some(next) = answer
                .authority
                .iter()
                .find(|record| record.ty == RecordType::NS)
                .filter(|_| !answer.authoritative)
            else {
                return Ok(answer);
            };
            server = self
                .zones
                .values()
                .flat_map(|zone| zone.ns.iter())
                .find(|ns| **ns == next.value)
                .unwrap();
        }
    }

    async fn direct(&self, server: &str, name: &str, ty: RecordType) -> DnsLookupResult<DnsAnswer> {
        if self.dead.contains(&server) {
            return Err(DnsLookupError::Timeout(server.to_string()));
        }
        Ok(self.answer(server, name, ty))
    }
}

fn world() -> World {
    let mut world = World::default();
    world.zone("", &["root"], &[], &[("com", &["tld"]), ("uk", &["uk1"])]);
    world.zone("com", &["tld"], &[], &[("example.com", &["a1", "a2"])]);
    world.zone("uk", &["uk1"], &[], &[("co.uk", &["uk2"])]);
    world.zone("co.uk", &["uk2"], &[], &[("foo.co.uk", &["f1"])]);
    world.zone("foo.co.uk", &["f1"], &[], &[]);
    world.zone(
        "example.com",
        &["a1", "a2"],
        &[
            ("www.example.com", RecordType::A, "192.0.2.1"),
            ("alias.example.com", RecordType::CNAME, "elsewhere.net"),
            ("_acme-challenge.example.com", RecordType::TXT, "token"),
        ],
        &[("home.example.com", &["sn1"])],
    );
    world
}

fn apex(name: &str, ns: &[&str]) -> ZoneApex {
    ZoneApex {
        apex: name.to_string(),
        ns: ns.iter().map(|ns| ns.to_string()).collect(),
    }
}

#[tokio::test]
async fn zone_apex() {
    let world = world();
    for (name, expected) in [
        ("example.com", apex("example.com", &["a1", "a2"])),
        ("WWW.Example.com.", apex("example.com", &["a1", "a2"])),
        ("a.b.c.example.com", apex("example.com", &["a1", "a2"])),
        ("*.example.com", apex("example.com", &["a1", "a2"])),
        ("alias.example.com", apex("example.com", &["a1", "a2"])),
        ("foo.co.uk", apex("foo.co.uk", &["f1"])),
        ("x.foo.co.uk", apex("foo.co.uk", &["f1"])),
        ("missing.com", apex("com", &["tld"])),
        // Delegated, and nobody serves it yet.
        ("home.example.com", apex("home.example.com", &["sn1"])),
        ("_pkx.home.example.com", apex("home.example.com", &["sn1"])),
    ] {
        assert_eq!(
            find_zone_apex(&world, name).await.unwrap(),
            expected,
            "{name}"
        );
    }
    for name in world.public_names() {
        assert!(
            name.split('.').count() <= 2,
            "asked a public resolver about {name}"
        );
    }
}

#[tokio::test]
async fn parent_zone_does_not_depend_on_the_delegation() {
    let world = world();
    for name in ["home.example.com", "other.example.com", "www.example.com"] {
        assert_eq!(
            find_parent_zone(&world, name).await.unwrap(),
            apex("example.com", &["a1", "a2"]),
            "{name}"
        );
    }
    assert_eq!(
        find_parent_zone(&world, "example.com").await.unwrap(),
        apex("com", &["tld"])
    );
    assert_eq!(
        find_parent_zone(&world, "x.home.example.com")
            .await
            .unwrap(),
        apex("home.example.com", &["sn1"])
    );
    assert!(find_parent_zone(&world, "com").await.is_err());
}

#[tokio::test]
async fn one_server_for_parent_and_child() {
    let mut world = World::default();
    world.zone("", &["root"], &[], &[("com", &["tld"])]);
    world.zone("com", &["tld"], &[], &[("example.com", &["a1"])]);
    world.zone("example.com", &["a1"], &[], &[]);
    world.zone("home.example.com", &["a1", "a9"], &[], &[]);
    for name in ["home.example.com", "x.home.example.com"] {
        assert_eq!(
            find_zone_apex(&world, name).await.unwrap(),
            apex("home.example.com", &["a1", "a9"]),
            "{name}"
        );
    }
}

#[tokio::test]
async fn unreachable_zone_is_an_error() {
    let mut world = world();
    world.dead = vec!["a1", "a2"];
    assert!(find_zone_apex(&world, "x.example.com").await.is_err());
    world.dead = vec!["a1"];
    assert!(find_zone_apex(&world, "x.example.com").await.is_ok());
}

#[tokio::test]
async fn txt_on_every_server() {
    let mut world = world();
    let name = "_acme-challenge.example.com";
    assert!(txt_visible(&world, name, "token").await.unwrap());
    assert!(!txt_visible(&world, name, "other").await.unwrap());
    world.dead = vec!["a2"];
    assert!(txt_visible(&world, name, "token").await.unwrap());
    world.dead = vec![];
    world.refusing = vec!["a2"];
    assert!(txt_visible(&world, name, "token").await.unwrap());
    let answers = authoritative_answers(&world, name, RecordType::TXT)
        .await
        .unwrap();
    assert_eq!(answers.len(), 2);
    // One server lags behind.
    world.refusing = vec![];
    world.zones.get_mut("example.com").unwrap().ns = vec!["a1", "a2", "a3"];
    world.zone("_acme-challenge.example.com", &["a3"], &[], &[]);
    assert!(!txt_visible(&world, name, "token").await.unwrap());
}

#[tokio::test(start_paused = true)]
async fn waiting_gives_up() {
    let world = world();
    let name = "_acme-challenge.example.com";
    let started = Instant::now();
    assert!(
        !wait_txt_visible(&world, name, "never", Duration::from_secs(10))
            .await
            .unwrap()
    );
    assert_eq!(started.elapsed().as_secs(), 9);
    assert!(
        wait_txt_visible(&world, name, "token", Duration::from_secs(10))
            .await
            .unwrap()
    );
}

#[test]
fn servers() {
    for (text, name, port) in [
        ("ns1.Example.com.", "ns1.example.com", 53),
        ("ns1.example.com:5353", "ns1.example.com", 5353),
        ("192.0.2.1", "192.0.2.1", 53),
        ("192.0.2.1:54", "192.0.2.1", 54),
        ("2001:db8::1", "2001:db8::1", 53),
        ("[2001:db8::1]", "2001:db8::1", 53),
        ("[2001:db8::1]:54", "2001:db8::1", 54),
    ] {
        assert_eq!(split_server(text), (name.to_string(), port), "{text}");
    }
}

#[test]
fn json_values() {
    assert_eq!(json_value(RecordType::TXT, "\"a\" \"b\""), "ab");
    assert_eq!(json_value(RecordType::TXT, "v=spf1 -all"), "v=spf1 -all");
    assert_eq!(
        json_value(RecordType::CNAME, "Foo.Example.com."),
        "foo.example.com"
    );
    assert_eq!(
        json_value(
            RecordType::SOA,
            "Ns1.Example.com. Host.Example.com. 1 2 3 4 5"
        ),
        "ns1.example.com host.example.com 1 2 3 4 5"
    );
    for text in [
        "0 issue \"letsencrypt.org\"",
        "0 issue letsencrypt.org",
        "\\# 22 00 05 69 73 73 75 65 6c 65 74 73 65 6e 63 72 79 70 74 2e 6f 72 67",
    ] {
        assert_eq!(
            json_value(RecordType::CAA, text),
            "0 issue \"letsencrypt.org\""
        );
    }
}

/// A server on the loopback that answers with `reply`.
struct Server {
    address: SocketAddr,
    udp: Arc<AtomicUsize>,
    tcp: Arc<AtomicUsize>,
}

async fn server<F>(reply: F) -> Server
where
    F: Fn(&Message, bool, usize) -> Option<Message> + Send + Sync + 'static,
{
    let reply = Arc::new(reply);
    let (udp, listener) = loop {
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        if let Ok(listener) = TcpListener::bind(udp.local_addr().unwrap()).await {
            break (udp, listener);
        }
    };
    let address = udp.local_addr().unwrap();
    let counts = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let (udp_count, tcp_count) = counts.clone();
    let udp_reply = reply.clone();
    tokio::spawn(async move {
        let mut buffer = vec![0; 4096];
        loop {
            let (length, peer) = udp.recv_from(&mut buffer).await.unwrap();
            let count = udp_count.fetch_add(1, Ordering::SeqCst);
            let query = Message::from_vec(&buffer[..length]).unwrap();
            if let Some(reply) = udp_reply(&query, false, count) {
                udp.send_to(&reply.to_vec().unwrap(), peer).await.unwrap();
            }
        }
    });
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let count = tcp_count.fetch_add(1, Ordering::SeqCst);
            let length = stream.read_u16().await.unwrap();
            let mut buffer = vec![0; usize::from(length)];
            stream.read_exact(&mut buffer).await.unwrap();
            let query = Message::from_vec(&buffer).unwrap();
            if let Some(reply) = reply(&query, true, count) {
                let bytes = reply.to_vec().unwrap();
                stream.write_u16(bytes.len() as u16).await.unwrap();
                stream.write_all(&bytes).await.unwrap();
            }
        }
    });
    Server {
        address,
        udp: counts.0,
        tcp: counts.1,
    }
}

fn response(query: &Message) -> Message {
    let mut reply = Message::new();
    reply
        .set_id(query.id())
        .set_message_type(MessageType::Response)
        .set_authoritative(true)
        .add_query(query.queries()[0].clone());
    reply
}

fn name(text: &str) -> Name {
    Name::from_ascii(text).unwrap()
}

#[tokio::test]
async fn direct_answer() {
    let server = server(|query, _, _| {
        assert!(!query.recursion_desired());
        assert!(query.extensions().is_some());
        let mut reply = response(query);
        let owner = query.queries()[0].name().clone();
        reply.add_answer(Record::from_rdata(
            owner.clone(),
            60,
            RData::CNAME(CNAME(name("Target.Example.com."))),
        ));
        reply.add_answer(Record::from_rdata(
            name("target.example.com."),
            60,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 7))),
        ));
        reply.add_answer(Record::from_rdata(
            owner.clone(),
            60,
            RData::TXT(TXT::new(vec!["part one ".into(), "part two".into()])),
        ));
        reply.add_answer(Record::from_rdata(
            owner,
            60,
            RData::CAA(CAA::new_issue(false, Some(name("letsencrypt.org")), vec![])),
        ));
        Some(reply)
    })
    .await;
    let answer = SystemDnsLookup::new()
        .direct(
            &server.address.to_string(),
            "_x.Example.com.",
            RecordType::TXT,
        )
        .await
        .unwrap();
    assert!(answer.authoritative);
    assert_eq!(answer.rcode, DnsRcode::NoError);
    assert_eq!(answer.answers[0].name, "_x.example.com");
    assert_eq!(answer.values(RecordType::CNAME), ["target.example.com"]);
    assert_eq!(answer.values(RecordType::A), ["192.0.2.7"]);
    assert_eq!(answer.values(RecordType::TXT), ["part one part two"]);
    assert_eq!(
        answer.values(RecordType::CAA),
        ["0 issue \"letsencrypt.org\""]
    );
    assert_eq!(server.tcp.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn direct_negative_and_referral() {
    let server = server(|query, _, _| {
        let mut reply = response(query);
        if query.queries()[0].query_type() == WireType::SOA {
            reply.set_response_code(ResponseCode::NXDomain);
            let soa = SOA::new(
                name("Ns.Example.com."),
                name("host.example.com."),
                7,
                1,
                2,
                3,
                4,
            );
            reply.add_name_server(Record::from_rdata(
                name("example.com."),
                60,
                RData::SOA(soa),
            ));
        } else {
            reply.set_authoritative(false);
            reply.add_name_server(Record::from_rdata(
                name("home.example.com."),
                60,
                RData::NS(NS(name("dns.sn.example."))),
            ));
        }
        Some(reply)
    })
    .await;
    let lookup = SystemDnsLookup::new();
    let address = server.address.to_string();
    let answer = lookup
        .direct(&address, "x.example.com", RecordType::SOA)
        .await
        .unwrap();
    assert_eq!(answer.rcode, DnsRcode::NxDomain);
    assert_eq!(
        answer.authority[0].value,
        "ns.example.com host.example.com 7 1 2 3 4"
    );
    let answer = lookup
        .direct(&address, "home.example.com", RecordType::NS)
        .await
        .unwrap();
    assert!(!answer.authoritative && answer.answers.is_empty());
    assert_eq!(
        answer.authority,
        [data("home.example.com", RecordType::NS, "dns.sn.example")]
    );
}

#[tokio::test]
async fn truncated_answers_use_tcp() {
    let server = server(|query, tcp, _| {
        let mut reply = response(query);
        if tcp {
            let text = "x".repeat(200);
            for index in 0..30 {
                reply.add_answer(Record::from_rdata(
                    query.queries()[0].name().clone(),
                    60,
                    RData::TXT(TXT::new(vec![format!("{index}{text}")])),
                ));
            }
        } else {
            reply.set_truncated(true);
        }
        Some(reply)
    })
    .await;
    let answer = SystemDnsLookup::new()
        .direct(
            &server.address.to_string(),
            "big.example.com",
            RecordType::TXT,
        )
        .await
        .unwrap();
    assert_eq!(answer.values(RecordType::TXT).len(), 30);
    assert_eq!(server.tcp.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn retries_without_edns() {
    for formerr in [true, false] {
        let server = server(move |query, _, _| {
            if query.extensions().is_some() {
                let mut reply = response(query);
                reply.set_response_code(ResponseCode::FormErr);
                return formerr.then_some(reply);
            }
            Some(response(query))
        })
        .await;
        let answer = SystemDnsLookup::new()
            .direct(&server.address.to_string(), "x.example.com", RecordType::A)
            .await
            .unwrap();
        assert_eq!(answer.rcode, DnsRcode::NoError);
        assert_eq!(server.udp.load(Ordering::SeqCst), 2);
    }
}

#[tokio::test]
async fn foreign_replies_are_ignored_and_silence_times_out() {
    let server = server(|query, _, _| {
        let mut reply = response(query);
        reply.set_id(query.id().wrapping_add(1));
        Some(reply)
    })
    .await;
    let result = SystemDnsLookup::new()
        .direct(&server.address.to_string(), "x.example.com", RecordType::A)
        .await;
    assert!(
        matches!(result, Err(DnsLookupError::Timeout(_))),
        "{result:?}"
    );
    assert_eq!(server.udp.load(Ordering::SeqCst), ATTEMPTS);
}

#[tokio::test]
async fn public_falls_back_to_the_next_resolver() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let seen = requests.clone();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = vec![0; 4096];
            let length = stream.read(&mut buffer).await.unwrap();
            let text = String::from_utf8_lossy(&buffer[..length]).into_owned();
            let path = text.split_whitespace().nth(1).unwrap().to_string();
            let reply = if path.starts_with("/broken") {
                "HTTP/1.1 500 no\r\ncontent-length: 0\r\nconnection: close\r\n\r\n".to_string()
            } else {
                let body = r#"{"Status":3,"Answer":[{"name":"X.Example.com.","type":46,"TTL":1,"data":"sig"}],
                    "Authority":[{"name":"example.com.","type":6,"TTL":60,"data":"ns1.example.com. h.example.com. 1 2 3 4 5"}]}"#;
                format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/dns-json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                )
            };
            seen.lock().unwrap().push(path);
            stream.write_all(reply.as_bytes()).await.unwrap();
        }
    });
    let lookup = SystemDnsLookup {
        http: reqwest::Client::builder().no_proxy().build().unwrap(),
        resolvers: vec![
            format!("http://{address}/broken"),
            format!("http://{address}/works"),
        ],
    };
    let answer = lookup
        .public("X.example.com.", RecordType::SOA)
        .await
        .unwrap();
    assert_eq!(answer.rcode, DnsRcode::NxDomain);
    assert!(answer.answers.is_empty() && !answer.authoritative);
    assert_eq!(
        answer.authority[0].value,
        "ns1.example.com h.example.com 1 2 3 4 5"
    );
    assert_eq!(
        *requests.lock().unwrap(),
        [
            "/broken?name=x.example.com&type=SOA",
            "/works?name=x.example.com&type=SOA"
        ]
    );
}

#[tokio::test]
async fn servfail_is_an_answer() {
    let lookup = SystemDnsLookup {
        http: reqwest::Client::builder().no_proxy().build().unwrap(),
        resolvers: vec![],
    };
    assert!(lookup.public("example.com", RecordType::A).await.is_err());
    assert_eq!(rcode(ResponseCode::from(0, 2)), DnsRcode::ServFail);
}

/// Needs the Internet: `cargo test -p cyfs-dns-provider -- --ignored live`.
#[tokio::test]
#[ignore]
async fn live() {
    let lookup = SystemDnsLookup::new();
    for name in [
        "example.com",
        "www.example.com",
        "a.b.cloudflare.com",
        "www.bbc.co.uk",
        "www.sakura.ad.jp",
        "foo.web3.buckyos.ai",
        "www.com.cn",
    ] {
        println!("{name}: {:?}", find_zone_apex(&*lookup, name).await);
        println!("  parent {:?}", find_parent_zone(&*lookup, name).await);
    }
    println!(
        "{:?}",
        lookup.public("dnssec-failed.org", RecordType::A).await
    );
    println!("{:?}", lookup.public("google.com", RecordType::CAA).await);
    for (server, answer) in authoritative_answers(&*lookup, "google.com", RecordType::CAA)
        .await
        .unwrap()
    {
        println!("{server}: {answer:?}");
    }
}
