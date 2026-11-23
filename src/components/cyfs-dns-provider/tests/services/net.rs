//! An intercepting proxy: every HTTPS request of this process goes to the mock
//! of its host, so the real addresses of the services are exercised too.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, LazyLock, Mutex, Once};

use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::ssl::{SslAcceptor, SslMethod};
use openssl::x509::extension::{BasicConstraints, SubjectAlternativeName};
use openssl::x509::{X509, X509Name};
use serde_json::Value;

#[derive(Clone, Debug, Default)]
pub struct Request {
    pub host: String,
    pub method: String,
    pub path: String,
    pub raw_query: String,
    pub query: HashMap<String, String>,
    pub headers: HashMap<String, String>,
    /// Header names as they were sent.
    pub names: Vec<String>,
    pub body: String,
}

impl Request {
    pub fn header(&self, name: &str) -> &str {
        self.headers.get(name).map_or("", String::as_str)
    }

    pub fn query(&self, name: &str) -> &str {
        self.query.get(name).map_or("", String::as_str)
    }

    pub fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or_else(|error| panic!("{error}: {self:?}"))
    }

    pub fn bearer(&self) -> &str {
        self.header("authorization")
            .strip_prefix("Bearer ")
            .unwrap_or_default()
    }
}

#[derive(Clone, Debug)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl Response {
    pub fn new(status: u16, body: impl ToString) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: body.to_string(),
        }
    }

    pub fn header(mut self, name: &str, value: impl ToString) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }
}

pub type Handler = Arc<dyn Fn(&Request) -> Response + Send + Sync>;

static HANDLERS: LazyLock<Mutex<HashMap<String, Handler>>> = LazyLock::new(Default::default);
static ACCEPTORS: LazyLock<Mutex<HashMap<String, Arc<SslAcceptor>>>> =
    LazyLock::new(Default::default);
static AUTHORITY: LazyLock<(X509, PKey<Private>)> = LazyLock::new(|| {
    let key = key();
    (certificate("mock authority", &key, None), key)
});

pub fn serve(host: &str, handler: Handler) {
    setup();
    HANDLERS.lock().unwrap().insert(host.to_string(), handler);
}

pub fn setup() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy = format!("http://{}", listener.local_addr().unwrap());
        let path = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("mock-authority-{}.pem", std::process::id()));
        std::fs::write(&path, AUTHORITY.0.to_pem().unwrap()).unwrap();
        for (name, value) in [
            ("HTTPS_PROXY", proxy.as_str()),
            ("https_proxy", proxy.as_str()),
            ("NO_PROXY", ""),
            ("no_proxy", ""),
            ("SSL_CERT_FILE", path.to_str().unwrap()),
        ] {
            // Before any client exists: every test starts here.
            unsafe { std::env::set_var(name, value) };
        }
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                std::thread::spawn(move || tunnel(stream));
            }
        });
    });
}

fn key() -> PKey<Private> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
}

fn certificate(
    name: &str,
    key: &PKey<Private>,
    authority: Option<(&X509, &PKey<Private>)>,
) -> X509 {
    let mut subject = X509Name::builder().unwrap();
    subject.append_entry_by_text("CN", name).unwrap();
    let subject = subject.build();
    let mut serial = BigNum::new().unwrap();
    serial.rand(120, MsbOption::MAYBE_ZERO, false).unwrap();
    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    builder
        .set_serial_number(&serial.to_asn1_integer().unwrap())
        .unwrap();
    builder.set_subject_name(&subject).unwrap();
    builder.set_pubkey(key).unwrap();
    builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::days_from_now(2).unwrap())
        .unwrap();
    match authority {
        Some((authority, authority_key)) => {
            builder.set_issuer_name(authority.subject_name()).unwrap();
            let names = SubjectAlternativeName::new()
                .dns(name)
                .build(&builder.x509v3_context(Some(authority), None))
                .unwrap();
            builder.append_extension(names).unwrap();
            builder
                .sign(authority_key, MessageDigest::sha256())
                .unwrap();
        }
        None => {
            builder.set_issuer_name(&subject).unwrap();
            builder
                .append_extension(BasicConstraints::new().critical().ca().build().unwrap())
                .unwrap();
            builder.sign(key, MessageDigest::sha256()).unwrap();
        }
    }
    builder.build()
}

fn acceptor(host: &str) -> Arc<SslAcceptor> {
    ACCEPTORS
        .lock()
        .unwrap()
        .entry(host.to_string())
        .or_insert_with(|| {
            let key = key();
            let (authority, authority_key) = &*AUTHORITY;
            let leaf = certificate(host, &key, Some((authority, authority_key)));
            let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
            builder.set_private_key(&key).unwrap();
            builder.set_certificate(&leaf).unwrap();
            Arc::new(builder.build())
        })
        .clone()
}

fn tunnel(stream: TcpStream) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let host = line
        .split_whitespace()
        .nth(1)
        .and_then(|target| target.split(':').next())
        .unwrap_or_default()
        .to_string();
    while reader.read_line(&mut line).is_ok_and(|read| read > 2) {}
    let mut plain = stream;
    plain.write_all(b"HTTP/1.1 200 OK\r\n\r\n").unwrap();
    let Ok(tls) = acceptor(&host).accept(plain) else {
        return;
    };
    let mut tls = BufReader::new(tls);
    while let Some(request) = read_request(&mut tls, &host) {
        let handler = HANDLERS.lock().unwrap().get(&host).cloned();
        let response = match handler {
            Some(handler) => {
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handler(&request)))
                    .unwrap_or_else(|_| Response::new(599, "mock panicked"))
            }
            None => Response::new(598, format!("no mock for {host}")),
        };
        let mut text = format!("HTTP/1.1 {} mock\r\n", response.status);
        if response.status != 204 {
            text += &format!("content-length: {}\r\n", response.body.len());
        }
        for (name, value) in &response.headers {
            text += &format!("{name}: {value}\r\n");
        }
        text += "\r\n";
        if response.status != 204 {
            text += &response.body;
        }
        if tls.get_mut().write_all(text.as_bytes()).is_err() {
            return;
        }
    }
}

fn read_request(stream: &mut impl BufRead, host: &str) -> Option<Request> {
    let mut line = String::new();
    stream.read_line(&mut line).ok().filter(|read| *read > 0)?;
    let mut parts = line.split_whitespace();
    let method = parts.next()?.to_string();
    let target = parts.next()?.to_string();
    let mut headers = HashMap::new();
    let mut names = Vec::new();
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).ok()?;
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        let (name, value) = line.split_once(':')?;
        headers.insert(name.to_ascii_lowercase(), value.trim().to_string());
        names.push(name.to_string());
    }
    let length = headers
        .get("content-length")
        .and_then(|length| length.parse().ok())
        .unwrap_or(0);
    let mut body = vec![0; length];
    stream.read_exact(&mut body).ok()?;
    let (path, raw_query) = target.split_once('?').unwrap_or((&target, ""));
    Some(Request {
        host: host.to_string(),
        method,
        path: path.to_string(),
        raw_query: raw_query.to_string(),
        query: url::form_urlencoded::parse(raw_query.as_bytes())
            .into_owned()
            .collect(),
        headers,
        names,
        body: String::from_utf8(body).ok()?,
    })
}
