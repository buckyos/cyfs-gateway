//! Local ACME fixture: accepts orders and signs their CSRs without contacting a CA.
use base64::Engine;
use openssl::asn1::Asn1Time;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::x509::{X509, X509Req};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::task::{JoinHandle, JoinSet};

#[derive(Default)]
pub(crate) struct MockAcmeState {
    pub orders: AtomicUsize,
    pub fail_orders: AtomicBool,
    certificates: Mutex<HashMap<String, Vec<u8>>>,
}

pub(crate) struct MockAcme {
    pub url: String,
    pub state: Arc<MockAcmeState>,
    pub order_gate: Arc<Semaphore>,
    handle: JoinHandle<()>,
}

impl MockAcme {
    pub async fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let state = Arc::new(MockAcmeState::default());
        let order_gate = Arc::new(Semaphore::new(0));
        let handle = tokio::spawn({
            let url = url.clone();
            let state = state.clone();
            let order_gate = order_gate.clone();
            async move {
                let mut requests = JoinSet::new();
                loop {
                    tokio::select! {
                        connection = listener.accept() => {
                            let (stream, _) = connection.unwrap();
                            requests.spawn(serve(stream, url.clone(), state.clone(), order_gate.clone()));
                        }
                        Some(result) = requests.join_next() => { result.unwrap(); }
                    }
                }
            }
        });
        Self {
            url,
            state,
            order_gate,
            handle,
        }
    }

    pub fn orders(&self) -> usize {
        self.state.orders.load(Ordering::SeqCst)
    }
}

impl Drop for MockAcme {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

async fn serve(stream: TcpStream, url: String, state: Arc<MockAcmeState>, gate: Arc<Semaphore>) {
    let mut stream = BufReader::new(stream);
    let mut line = String::new();
    if stream.read_line(&mut line).await.unwrap() == 0 {
        return;
    }
    let path = line.split_whitespace().nth(1).unwrap().to_string();
    let mut content_length = 0;
    loop {
        line.clear();
        if stream.read_line(&mut line).await.unwrap() == 0 {
            return;
        }
        if line == "\r\n" {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse().unwrap();
            }
        }
    }
    let mut body = vec![0; content_length];
    stream.read_exact(&mut body).await.unwrap();
    let payload = if body.is_empty() {
        Value::Null
    } else {
        let jws: Value = serde_json::from_slice(&body).unwrap();
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(jws["payload"].as_str().unwrap())
            .unwrap();
        if decoded.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&decoded).unwrap()
        }
    };

    let mut status = "200 OK";
    let body = match path.as_str() {
        "/directory" => json!({
            "newNonce": format!("{url}/nonce"),
            "newAccount": format!("{url}/account"),
            "newOrder": format!("{url}/order"),
            "revokeCert": format!("{url}/revoke")
        })
        .to_string()
        .into_bytes(),
        "/nonce" => Vec::new(),
        "/account" => json!({"status": "valid"}).to_string().into_bytes(),
        "/order" => {
            let id = state.orders.fetch_add(1, Ordering::SeqCst) + 1;
            gate.acquire().await.unwrap().forget();
            if state.fail_orders.load(Ordering::SeqCst) {
                status = "429 Too Many Requests";
                json!({"type": "urn:ietf:params:acme:error:rateLimited", "detail": "test issuance limit"})
                    .to_string().into_bytes()
            } else {
                json!({
                    "status": "ready", "expires": "2099-01-01T00:00:00Z",
                    "identifiers": payload["identifiers"], "authorizations": [],
                    "finalize": format!("{url}/finalize/{id}")
                })
                .to_string()
                .into_bytes()
            }
        }
        _ if path.starts_with("/finalize/") => {
            let id = path.trim_start_matches("/finalize/");
            let csr = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(payload["csr"].as_str().unwrap())
                .unwrap();
            state
                .certificates
                .lock()
                .unwrap()
                .insert(id.to_string(), sign_csr(&csr));
            json!({"status": "valid", "certificate": format!("{url}/cert/{id}")})
                .to_string()
                .into_bytes()
        }
        _ if path.starts_with("/cert/") => state
            .certificates
            .lock()
            .unwrap()
            .get(path.trim_start_matches("/cert/"))
            .unwrap()
            .clone(),
        _ => panic!("unexpected mock ACME request: {path}"),
    };
    let retry_after = if status.starts_with("429") {
        "Retry-After: 3600\r\n"
    } else {
        ""
    };
    let headers = format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nContent-Type: application/json\r\nReplay-Nonce: test-nonce\r\nLocation: {url}/account/1\r\n{retry_after}Connection: close\r\n\r\n",
        body.len()
    );
    stream
        .get_mut()
        .write_all(headers.as_bytes())
        .await
        .unwrap();
    stream.get_mut().write_all(&body).await.unwrap();
}

fn sign_csr(csr: &[u8]) -> Vec<u8> {
    let csr = X509Req::from_der(csr).unwrap();
    let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let mut cert = X509::builder().unwrap();
    cert.set_version(2).unwrap();
    cert.set_subject_name(csr.subject_name()).unwrap();
    cert.set_issuer_name(csr.subject_name()).unwrap();
    cert.set_pubkey(&csr.public_key().unwrap()).unwrap();
    cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    cert.set_not_after(&Asn1Time::days_from_now(90).unwrap())
        .unwrap();
    for extension in csr.extensions().unwrap() {
        cert.append_extension(extension).unwrap();
    }
    cert.sign(&key, MessageDigest::sha256()).unwrap();
    cert.build().to_pem().unwrap()
}
