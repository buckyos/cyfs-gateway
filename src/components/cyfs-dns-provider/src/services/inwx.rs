//! DomRobot JSON-RPC.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex as StdMutex};
use std::time::{Duration, Instant};

use reqwest::Method;
use reqwest::header::SET_COOKIE;
use serde_json::{Value, json};
use tokio::sync::Mutex;

use crate::crypto::{hex, sha256, totp};
use crate::engine::{RecordApi, Stored};
use crate::http::{Http, now, url};
use crate::provider::{DnsProviderError, DnsProviderResult, RecordType};
use crate::values::{host, stored_value, type_name};

const ENDPOINT: &str = "https://api.domrobot.com/jsonrpc/";
const SESSION_TTL: Duration = Duration::from_secs(30 * 60);
const TOTP_STEP: u64 = 30;

const NO_SESSION: i64 = 2002;
const AUTH_FAILED: [i64; 2] = [2200, 2201];
const EXISTS: i64 = 2302;
const NOT_FOUND: i64 = 2303;
const SESSION_LIMIT: i64 = 2502;

#[derive(Default)]
struct Session {
    cookie: Option<(String, Instant)>,
    /// A one-time code works once, so the next login has to wait for the next one.
    last_step: u64,
}

/// Sessions are limited per account and logging in again may need another
/// one-time code, so every provider of one account shares a session.
static SESSIONS: LazyLock<StdMutex<HashMap<String, Arc<Mutex<Session>>>>> =
    LazyLock::new(Default::default);

pub(crate) struct Inwx {
    http: Http,
    endpoint: String,
    username: String,
    password: String,
    shared_secret: Option<String>,
    origin: String,
    session: Arc<Mutex<Session>>,
}

fn message(body: &Value) -> String {
    format!(
        "{} {}",
        body["code"],
        body["msg"].as_str().unwrap_or_default()
    )
}

impl Inwx {
    pub(crate) fn new(
        username: &str,
        password: &str,
        shared_secret: Option<&str>,
        origin: &str,
        endpoint: Option<&str>,
    ) -> DnsProviderResult<Self> {
        let endpoint = endpoint.unwrap_or(ENDPOINT).to_string();
        let account = hex(&sha256(
            format!("{endpoint}\n{username}\n{password}").as_bytes(),
        )?);
        let session = SESSIONS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .entry(account)
            .or_default()
            .clone();
        Ok(Self {
            http: Http::new()?,
            endpoint,
            username: username.to_string(),
            password: password.to_string(),
            shared_secret: shared_secret.map(str::to_string),
            origin: origin.to_string(),
            session,
        })
    }

    async fn post(
        &self,
        method: &str,
        params: Value,
        cookie: Option<&str>,
    ) -> DnsProviderResult<(Value, Option<String>)> {
        let mut request = self
            .http
            .request(Method::POST, url(&self.endpoint, &[], &[])?)
            .json(&json!({ "method": method, "params": params }));
        if let Some(cookie) = cookie {
            request = request.header("cookie", cookie);
        }
        let reply = self.http.send(request).await?.ok()?;
        let cookie = reply
            .headers
            .get_all(SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok()?.split(';').next())
            .map(str::trim)
            .collect::<Vec<_>>()
            .join("; ");
        Ok((reply.json()?, (!cookie.is_empty()).then_some(cookie)))
    }

    async fn login(&self, session: &mut Session) -> DnsProviderResult<String> {
        let credentials = json!({ "user": self.username, "pass": self.password });
        let (body, cookie) = self.post("account.login", credentials, None).await?;
        match body["code"].as_i64().unwrap_or_default() {
            code if code / 1000 == 1 => {}
            SESSION_LIMIT => {
                return Err(DnsProviderError::RateLimited {
                    message: message(&body),
                    retry_after: None,
                });
            }
            _ => return Err(DnsProviderError::Unauthorized(message(&body))),
        }
        let cookie = cookie
            .ok_or_else(|| DnsProviderError::Api("no session in the login response".to_string()))?;
        let second_factor = body["resData"]["tfa"].as_str().unwrap_or("0");
        if !matches!(second_factor, "" | "0") {
            let secret = self.shared_secret.as_deref().ok_or_else(|| {
                DnsProviderError::InvalidCredential(
                    "the account uses two-factor authentication, the shared secret is missing"
                        .to_string(),
                )
            })?;
            let mut step = now() / TOTP_STEP;
            if step <= session.last_step {
                let next = (session.last_step + 1) * TOTP_STEP;
                tokio::time::sleep(Duration::from_secs(next.saturating_sub(now()))).await;
                step = session.last_step + 1;
            }
            session.last_step = step;
            let tan = totp(secret, step)?;
            let (body, _) = self
                .post("account.unlock", json!({ "tan": tan }), Some(&cookie))
                .await?;
            if body["code"].as_i64().unwrap_or_default() / 1000 != 1 {
                return Err(DnsProviderError::Unauthorized(message(&body)));
            }
        }
        session.cookie = Some((cookie.clone(), Instant::now() + SESSION_TTL));
        Ok(cookie)
    }

    async fn call(&self, method: &str, params: Value) -> DnsProviderResult<Value> {
        let mut session = self.session.lock().await;
        let mut fresh = false;
        loop {
            let cookie = match &session.cookie {
                Some((cookie, expires)) if Instant::now() < *expires => cookie.clone(),
                _ => {
                    fresh = true;
                    self.login(&mut session).await?
                }
            };
            let (body, _) = self.post(method, params.clone(), Some(&cookie)).await?;
            let code = body["code"].as_i64().unwrap_or_default();
            if code == NO_SESSION && !fresh {
                session.cookie = None;
                continue;
            }
            return Ok(body);
        }
    }

    fn check(body: Value, ok: &[i64]) -> DnsProviderResult<Value> {
        match body["code"].as_i64().unwrap_or_default() {
            code if code / 1000 == 1 || ok.contains(&code) => Ok(body),
            code if AUTH_FAILED.contains(&code) => {
                Err(DnsProviderError::Unauthorized(message(&body)))
            }
            NOT_FOUND => Err(DnsProviderError::ZoneNotFound(message(&body))),
            _ => Err(DnsProviderError::Api(message(&body))),
        }
    }
}

#[async_trait::async_trait]
impl RecordApi for Inwx {
    const UPDATES: bool = true;

    fn ttl_range(&self) -> (u32, u32) {
        (300, 86400)
    }

    async fn list(&self, name: &str, ty: RecordType) -> DnsProviderResult<Vec<Stored>> {
        let params = json!({ "domain": self.origin, "name": name, "type": type_name(ty) });
        let body = Self::check(self.call("nameserver.info", params).await?, &[])?;
        Ok(body["resData"]["record"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|record| {
                host(record["name"].as_str().unwrap_or_default()) == name
                    && record["type"] == type_name(ty)
            })
            .map(|record| Stored {
                id: match &record["id"] {
                    Value::String(id) => id.clone(),
                    id => id.to_string(),
                },
                value: stored_value(ty, record["content"].as_str().unwrap_or_default()),
                ttl: record["ttl"].as_u64().unwrap_or_default() as u32,
                ..Default::default()
            })
            .collect())
    }

    async fn create(
        &self,
        name: &str,
        ty: RecordType,
        ttl: u32,
        value: &str,
    ) -> DnsProviderResult<()> {
        let params = json!({
            "domain": self.origin,
            "name": name,
            "type": type_name(ty),
            "content": value,
            "ttl": ttl,
        });
        Self::check(
            self.call("nameserver.createRecord", params).await?,
            &[EXISTS],
        )
        .map(drop)
    }

    async fn update(
        &self,
        name: &str,
        ty: RecordType,
        ttl: u32,
        record: &Stored,
        value: &str,
    ) -> DnsProviderResult<()> {
        let params = json!({
            "id": record.id,
            "name": name,
            "type": type_name(ty),
            "content": value,
            "ttl": ttl,
        });
        Self::check(self.call("nameserver.updateRecord", params).await?, &[]).map(drop)
    }

    async fn delete(&self, _name: &str, _ty: RecordType, record: &Stored) -> DnsProviderResult<()> {
        let params = json!({ "id": record.id });
        Self::check(
            self.call("nameserver.deleteRecord", params).await?,
            &[NOT_FOUND],
        )
        .map(drop)
    }
}
