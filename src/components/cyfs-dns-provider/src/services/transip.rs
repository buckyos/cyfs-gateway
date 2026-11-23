use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use openssl::hash::MessageDigest;
use reqwest::Method;
use serde_json::{Value, json};
use tokio::sync::Mutex;

use crate::crypto::{hex, random_bytes, rsa_sign};
use crate::engine::{RecordApi, Stored};
use crate::http::{Http, Reply, busy, url};
use crate::provider::{DnsProviderError, DnsProviderResult, RecordType};
use crate::values::{fqdn, host, relative, stored_value, type_name};

const ENDPOINT: &str = "https://api.transip.nl/v6";

pub(crate) struct TransIp {
    http: Http,
    base: String,
    login: String,
    private_key: String,
    origin: String,
    token: Mutex<Option<(String, Instant)>>,
}

impl TransIp {
    pub(crate) fn new(
        login: &str,
        private_key: &str,
        origin: &str,
        endpoint: Option<&str>,
    ) -> DnsProviderResult<Self> {
        Ok(Self {
            http: Http::new()?,
            base: endpoint.unwrap_or(ENDPOINT).to_string(),
            login: login.to_string(),
            private_key: private_key.trim().to_string(),
            origin: origin.to_string(),
            token: Mutex::new(None),
        })
    }

    async fn token(&self) -> DnsProviderResult<String> {
        // An access token can be used as it is: the control panel issues them,
        // and so is the public demo account.
        if !self.private_key.contains("PRIVATE KEY") && self.private_key.starts_with("eyJ") {
            return Ok(self.private_key.clone());
        }
        let mut cached = self.token.lock().await;
        if let Some((token, expires)) = cached.as_ref()
            && Instant::now() < *expires
        {
            return Ok(token.clone());
        }
        let nonce = hex(&random_bytes::<8>());
        let body = json!({
            "login": self.login,
            "nonce": nonce,
            "read_only": false,
            "expiration_time": "30 minutes",
            "label": format!("buckyos-{nonce}"),
            "global_key": true,
        })
        .to_string();
        let signature = rsa_sign(MessageDigest::sha512(), &self.private_key, body.as_bytes())?;
        let request = self
            .http
            .request(Method::POST, url(&self.base, &["auth"], &[])?)
            .header("content-type", "application/json")
            .header("signature", STANDARD.encode(signature))
            .body(body);
        let reply = self.http.send(request).await?;
        if matches!(reply.status, 400..=404 | 406) {
            return Err(DnsProviderError::Unauthorized(reply.message()));
        }
        let body: Value = reply.ok()?.json()?;
        let token = body["token"]
            .as_str()
            .ok_or_else(|| DnsProviderError::Api("no token in the response".to_string()))?
            .to_string();
        *cached = Some((token.clone(), Instant::now() + Duration::from_secs(25 * 60)));
        Ok(token)
    }

    async fn call(&self, method: Method, body: Option<Value>) -> DnsProviderResult<Reply> {
        let token = self.token().await?;
        let mut request = self
            .http
            .request(
                method,
                url(&self.base, &["domains", &self.origin, "dns"], &[])?,
            )
            .bearer_auth(token);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let reply = self.http.send(request).await?;
        if reply.status == 409 {
            return Err(busy(reply.message()));
        }
        Ok(reply)
    }
}

#[async_trait::async_trait]
impl RecordApi for TransIp {
    async fn list(&self, name: &str, ty: RecordType) -> DnsProviderResult<Vec<Stored>> {
        let label = relative(name, &self.origin, "@");
        let body: Value = self.call(Method::GET, None).await?.ok()?.json()?;
        Ok(body["dnsEntries"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|entry| entry["name"] == label.as_str() && entry["type"] == type_name(ty))
            .map(|entry| {
                let content = entry["content"].as_str().unwrap_or_default();
                let value = match ty {
                    RecordType::CNAME | RecordType::NS if content == "@" => self.origin.clone(),
                    RecordType::CNAME | RecordType::NS if !content.ends_with('.') => {
                        format!("{}.{}", host(content), self.origin)
                    }
                    _ => stored_value(ty, content),
                };
                Stored {
                    value,
                    ttl: entry["expire"].as_u64().unwrap_or_default() as u32,
                    raw: entry.clone(),
                    ..Default::default()
                }
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
        let content = match ty {
            RecordType::CNAME | RecordType::NS => fqdn(value),
            _ => value.to_string(),
        };
        let body = json!({ "dnsEntry": {
            "name": relative(name, &self.origin, "@"),
            "expire": ttl,
            "type": type_name(ty),
            "content": content,
        }});
        self.call(Method::POST, Some(body)).await?.ok()?;
        Ok(())
    }

    /// Entries have no id: the whole entry names the one to delete.
    async fn delete(&self, _name: &str, _ty: RecordType, record: &Stored) -> DnsProviderResult<()> {
        let body = json!({ "dnsEntry": record.raw });
        match self.call(Method::DELETE, Some(body)).await?.ok() {
            Ok(_) | Err(DnsProviderError::ZoneNotFound(_)) => Ok(()),
            Err(error) => Err(error),
        }
    }
}
