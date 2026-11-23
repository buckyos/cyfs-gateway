use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use openssl::hash::MessageDigest;
use reqwest::{Method, Url};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tokio::sync::OnceCell;

use crate::crypto::rsa_sign;
use crate::engine::{Backend, Change, Stored};
use crate::http::{Http, Reply, busy, now, url};
use crate::provider::{DnsProviderError, DnsProviderResult, RecordType};
use crate::values::{fqdn, host, quote_txt, stored_value, type_name};

const ENDPOINT: &str = "https://dns.googleapis.com";
const SCOPE: &str = "https://www.googleapis.com/auth/ndev.clouddns.readwrite";

#[derive(Deserialize)]
struct ServiceAccount {
    client_email: String,
    private_key: String,
    token_uri: String,
    #[serde(default)]
    project_id: String,
}

pub(crate) struct Google {
    http: Http,
    base: String,
    account: ServiceAccount,
    project: String,
    origin: String,
    token: Mutex<Option<(String, Instant)>>,
    zone: OnceCell<String>,
}

impl Google {
    pub(crate) fn new(
        service_account_json: &str,
        project_id: Option<&str>,
        origin: &str,
        endpoint: Option<&str>,
    ) -> DnsProviderResult<Self> {
        let invalid = |text: &str| DnsProviderError::InvalidCredential(text.to_string());
        let account: ServiceAccount = serde_json::from_str(service_account_json)
            .map_err(|_| invalid("not a service account key"))?;
        let token_uri =
            Url::parse(&account.token_uri).map_err(|_| invalid("token_uri is not a URL"))?;
        if token_uri.scheme() != "https" {
            return Err(invalid("token_uri is not https"));
        }
        let project = project_id.unwrap_or(&account.project_id).to_string();
        if project.is_empty() {
            return Err(invalid("the project id is missing"));
        }
        Ok(Self {
            http: Http::new()?,
            base: endpoint.unwrap_or(ENDPOINT).to_string(),
            account,
            project,
            origin: origin.to_string(),
            token: Mutex::new(None),
            zone: OnceCell::new(),
        })
    }

    async fn token(&self) -> DnsProviderResult<String> {
        let mut cached = self.token.lock().await;
        if let Some((token, expires)) = cached.as_ref()
            && Instant::now() < *expires
        {
            return Ok(token.clone());
        }
        let part = |value: Value| URL_SAFE_NO_PAD.encode(value.to_string());
        let issued = now();
        let unsigned = format!(
            "{}.{}",
            part(json!({ "alg": "RS256", "typ": "JWT" })),
            part(json!({
                "iss": self.account.client_email,
                "scope": SCOPE,
                "aud": self.account.token_uri,
                "iat": issued,
                "exp": issued + 3600,
            }))
        );
        let signature = rsa_sign(
            MessageDigest::sha256(),
            &self.account.private_key,
            unsigned.as_bytes(),
        )?;
        let assertion = format!("{unsigned}.{}", URL_SAFE_NO_PAD.encode(signature));
        let url = url(&self.account.token_uri, &[], &[])?;
        let request = self.http.request(Method::POST, url).form(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("assertion", &assertion),
        ]);
        let reply = self.http.send(request).await?;
        if !reply.is_ok() {
            return Err(match reply.status {
                400 | 401 => DnsProviderError::Unauthorized(reply.message()),
                _ => failure(&reply),
            });
        }
        let body: Value = reply.json()?;
        let token = body["access_token"]
            .as_str()
            .ok_or_else(|| DnsProviderError::Api("no access token in the response".to_string()))?
            .to_string();
        let lifetime = body["expires_in"]
            .as_u64()
            .unwrap_or(3600)
            .saturating_sub(120);
        *cached = Some((
            token.clone(),
            Instant::now() + Duration::from_secs(lifetime),
        ));
        Ok(token)
    }

    async fn call(
        &self,
        method: Method,
        path: &[&str],
        query: &[(&str, &str)],
        body: Option<Value>,
    ) -> DnsProviderResult<Value> {
        let path = [
            &["dns", "v1", "projects", &self.project, "managedZones"],
            path,
        ]
        .concat();
        let mut request = self
            .http
            .request(method, url(&self.base, &path, query)?)
            .bearer_auth(self.token().await?);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let reply: Reply = self.http.send(request).await?;
        if reply.is_ok() {
            reply.json()
        } else {
            Err(failure(&reply))
        }
    }

    async fn zone(&self) -> DnsProviderResult<&str> {
        self.zone
            .get_or_try_init(|| async {
                let body = self
                    .call(Method::GET, &[], &[("dnsName", &fqdn(&self.origin))], None)
                    .await?;
                body["managedZones"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .find(|zone| {
                        host(zone["dnsName"].as_str().unwrap_or_default()) == self.origin
                            && zone["visibility"] != "private"
                    })
                    .and_then(|zone| zone["name"].as_str())
                    .map(str::to_string)
                    .ok_or_else(|| DnsProviderError::ZoneNotFound(self.origin.clone()))
            })
            .await
            .map(String::as_str)
    }
}

fn failure(reply: &Reply) -> DnsProviderError {
    let body: Value = reply.json().unwrap_or_default();
    let reason = body["error"]["errors"][0]["reason"]
        .as_str()
        .unwrap_or_default();
    match (reply.status, reason) {
        (403, "rateLimitExceeded" | "userRateLimitExceeded" | "quotaExceeded") => {
            DnsProviderError::RateLimited {
                message: reply.message(),
                retry_after: reply.retry_after(),
            }
        }
        // The RRset changed between reading and writing it.
        (409 | 412, "alreadyExists" | "conditionNotMet" | "preconditionFailed") => {
            busy(reply.message())
        }
        _ => reply.error(),
    }
}

fn rrset(name: &str, ty: RecordType, ttl: u32, values: Vec<Value>) -> Value {
    json!({ "name": fqdn(name), "type": type_name(ty), "ttl": ttl, "rrdatas": values })
}

#[async_trait::async_trait]
impl Backend for Google {
    fn ttl_range(&self) -> (u32, u32) {
        (1, 86400)
    }

    async fn list(&self, name: &str, ty: RecordType) -> DnsProviderResult<Vec<Stored>> {
        let zone = self.zone().await?;
        let body = self
            .call(
                Method::GET,
                &[zone, "rrsets"],
                &[("name", &fqdn(name)), ("type", type_name(ty))],
                None,
            )
            .await?;
        Ok(body["rrsets"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|rrset| {
                host(rrset["name"].as_str().unwrap_or_default()) == name
                    && rrset["type"] == type_name(ty)
            })
            .flat_map(|rrset| {
                let ttl = rrset["ttl"].as_u64().unwrap_or_default() as u32;
                rrset["rrdatas"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .enumerate()
                    .map(move |(position, raw)| Stored {
                        id: position.to_string(),
                        value: stored_value(ty, raw),
                        ttl,
                        raw: raw.into(),
                        ..Default::default()
                    })
            })
            .collect())
    }

    async fn apply(&self, name: &str, ty: RecordType, change: Change) -> DnsProviderResult<()> {
        let raw = |records: &[Stored]| -> Vec<Value> {
            records.iter().map(|record| record.raw.clone()).collect()
        };
        let mut body = json!({});
        // A deletion has to repeat the RRset exactly as it is.
        let mut existing: Vec<Stored> = [change.keep.as_slice(), &change.remove].concat();
        existing.sort_by_key(|record| record.id.parse::<usize>().unwrap_or_default());
        if let Some(first) = existing.first() {
            body["deletions"] = json!([rrset(name, ty, first.ttl, raw(&existing))]);
        }
        let mut values = raw(&change.keep);
        values.extend(change.add.iter().map(|value| match ty {
            RecordType::TXT => Value::from(quote_txt(value)),
            RecordType::CNAME | RecordType::NS => Value::from(fqdn(value)),
            _ => Value::from(value.as_str()),
        }));
        if !values.is_empty() {
            body["additions"] = json!([rrset(name, ty, change.ttl, values)]);
        }
        let zone = self.zone().await?;
        self.call(Method::POST, &[zone, "changes"], &[], Some(body))
            .await
            .map(drop)
    }
}
