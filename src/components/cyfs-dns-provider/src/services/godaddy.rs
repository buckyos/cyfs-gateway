//! Domains API v3, the one that takes Personal Access Tokens.

use reqwest::Method;
use serde_json::{Value, json};

use crate::engine::{RecordApi, Stored};
use crate::http::{Http, Reply, url};
use crate::provider::{DnsProviderError, DnsProviderResult, RecordType};
use crate::values::{fqdn, relative, stored_value, type_name};

const ENDPOINT: &str = "https://api.godaddy.com";
const PAGE_SIZE: usize = 100;

pub(crate) struct GoDaddy {
    http: Http,
    base: String,
    token: String,
    origin: String,
}

impl GoDaddy {
    pub(crate) fn new(
        token: &str,
        origin: &str,
        endpoint: Option<&str>,
    ) -> DnsProviderResult<Self> {
        Ok(Self {
            http: Http::new()?,
            base: endpoint.unwrap_or(ENDPOINT).to_string(),
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
        let mut path = vec!["v3", "domains", "zones", &self.origin, "dns-records"];
        path.extend(id);
        let mut request = self
            .http
            .request(method, url(&self.base, &path, query)?)
            .bearer_auth(&self.token);
        if let Some(body) = body {
            request = request.json(&body);
        }
        self.http.send(request).await
    }

    fn record(&self, name: &str, ty: RecordType, ttl: u32, value: &str) -> Value {
        let data = match ty {
            RecordType::CNAME | RecordType::NS => fqdn(value),
            _ => value.to_string(),
        };
        json!({
            "name": relative(name, &self.origin, "@"),
            "type": type_name(ty),
            "data": data,
            "ttl": ttl,
        })
    }
}

#[async_trait::async_trait]
impl RecordApi for GoDaddy {
    const UPDATES: bool = true;

    fn ttl_range(&self) -> (u32, u32) {
        (600, 86400)
    }

    async fn list(&self, name: &str, ty: RecordType) -> DnsProviderResult<Vec<Stored>> {
        let label = relative(name, &self.origin, "@");
        let mut records = Vec::new();
        for page in 1.. {
            let body: Value = self
                .call(
                    Method::GET,
                    &[],
                    &[
                        ("type", type_name(ty)),
                        ("name", &label),
                        ("page", &page.to_string()),
                        ("pageSize", &PAGE_SIZE.to_string()),
                    ],
                    None,
                )
                .await?
                .ok()?
                .json()?;
            let items = body["items"].as_array().cloned().unwrap_or_default();
            for item in &items {
                let matches = item["type"] == type_name(ty)
                    && item["name"]
                        .as_str()
                        .is_some_and(|value| value.eq_ignore_ascii_case(&label));
                if matches {
                    records.push(Stored {
                        id: item["recordId"].as_str().unwrap_or_default().to_string(),
                        value: stored_value(ty, item["data"].as_str().unwrap_or_default()),
                        ttl: item["ttl"].as_u64().unwrap_or_default() as u32,
                        ..Default::default()
                    });
                }
            }
            if items.len() < PAGE_SIZE {
                break;
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
