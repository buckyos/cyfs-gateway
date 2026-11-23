//! CORE API v1.

use reqwest::Method;
use serde_json::{Value, json};

use crate::engine::{RecordApi, Stored};
use crate::http::{Http, Reply, url};
use crate::provider::{DnsProviderError, DnsProviderResult, RecordType};
use crate::values::{host, relative, stored_value, type_name};

const ENDPOINT: &str = "https://api.name.com";

pub(crate) struct NameCom {
    http: Http,
    base: String,
    username: String,
    token: String,
    origin: String,
}

impl NameCom {
    pub(crate) fn new(
        username: &str,
        token: &str,
        origin: &str,
        endpoint: Option<&str>,
    ) -> DnsProviderResult<Self> {
        Ok(Self {
            http: Http::new()?,
            base: endpoint.unwrap_or(ENDPOINT).to_string(),
            username: username.to_string(),
            token: token.to_string(),
            origin: origin.to_string(),
        })
    }

    async fn call(
        &self,
        method: Method,
        id: &[&str],
        query: &[(&str, &str)],
        body: Option<Value>,
    ) -> DnsProviderResult<Reply> {
        let mut path = vec!["core", "v1", "domains", &self.origin, "records"];
        path.extend(id);
        let mut request = self
            .http
            .request(method, url(&self.base, &path, query)?)
            .basic_auth(&self.username, Some(&self.token));
        if let Some(body) = body {
            request = request.json(&body);
        }
        self.http.send(request).await
    }

    fn record(&self, name: &str, ty: RecordType, ttl: u32, value: &str) -> Value {
        json!({
            "host": relative(name, &self.origin, ""),
            "type": type_name(ty),
            "answer": value,
            "ttl": ttl,
        })
    }
}

#[async_trait::async_trait]
impl RecordApi for NameCom {
    const UPDATES: bool = true;

    fn ttl_range(&self) -> (u32, u32) {
        (300, 86400)
    }

    async fn list(&self, name: &str, ty: RecordType) -> DnsProviderResult<Vec<Stored>> {
        let label = relative(name, &self.origin, "");
        let mut records = Vec::new();
        let mut page = 1;
        loop {
            let body: Value = self
                .call(
                    Method::GET,
                    &[],
                    &[("perPage", "1000"), ("page", &page.to_string())],
                    None,
                )
                .await?
                .ok()?
                .json()?;
            for item in body["records"].as_array().into_iter().flatten() {
                let item_label = match host(item["host"].as_str().unwrap_or_default()) {
                    apex if apex == "@" => String::new(),
                    label => label,
                };
                if item["type"] != type_name(ty) || item_label != label {
                    continue;
                }
                records.push(Stored {
                    id: item["id"].to_string(),
                    value: stored_value(ty, item["answer"].as_str().unwrap_or_default()),
                    ttl: item["ttl"].as_u64().unwrap_or_default() as u32,
                    ..Default::default()
                });
            }
            match body["nextPage"].as_u64() {
                Some(next) if next > page => page = next,
                _ => break,
            }
        }
        Ok(records)
    }

    async fn create(
        &self,
        name: &str,
        ty: RecordType,
        ttl: u32,
        value: &str,
    ) -> DnsProviderResult<()> {
        let body = self.record(name, ty, ttl, value);
        self.call(Method::POST, &[], &[], Some(body)).await?.ok()?;
        Ok(())
    }

    async fn update(
        &self,
        name: &str,
        ty: RecordType,
        ttl: u32,
        record: &Stored,
        value: &str,
    ) -> DnsProviderResult<()> {
        let body = self.record(name, ty, ttl, value);
        self.call(Method::PUT, &[&record.id], &[], Some(body))
            .await?
            .ok()?;
        Ok(())
    }

    async fn delete(&self, _name: &str, _ty: RecordType, record: &Stored) -> DnsProviderResult<()> {
        let reply = self.call(Method::DELETE, &[&record.id], &[], None).await?;
        match reply.ok() {
            Ok(_) | Err(DnsProviderError::ZoneNotFound(_)) => Ok(()),
            Err(error) => Err(error),
        }
    }
}
