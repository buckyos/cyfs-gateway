use reqwest::Method;
use serde_json::{Value, json};

use crate::engine::{RecordApi, Stored};
use crate::http::{Http, Reply, url};
use crate::provider::{DnsProviderError, DnsProviderResult, RecordType};
use crate::values::{fqdn, relative, stored_value, type_name};

const ENDPOINT: &str = "https://api.digitalocean.com";
const PAGE_SIZE: usize = 200;

pub(crate) struct DigitalOcean {
    http: Http,
    base: String,
    token: String,
    origin: String,
}

impl DigitalOcean {
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
        let mut path = vec!["v2", "domains", &self.origin, "records"];
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
impl RecordApi for DigitalOcean {
    const UPDATES: bool = true;

    fn ttl_range(&self) -> (u32, u32) {
        (30, 86400)
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
                        ("name", name),
                        ("per_page", &PAGE_SIZE.to_string()),
                        ("page", &page.to_string()),
                    ],
                    None,
                )
                .await?
                .ok()?
                .json()?;
            let items = body["domain_records"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            for item in &items {
                if item["type"] != type_name(ty) || item["name"] != label.as_str() {
                    continue;
                }
                // Targets come back without the dot they have to be sent with.
                let value = match item["data"].as_str().unwrap_or_default() {
                    "@" if matches!(ty, RecordType::CNAME | RecordType::NS) => self.origin.clone(),
                    data => stored_value(ty, data),
                };
                records.push(Stored {
                    id: item["id"].to_string(),
                    value,
                    ttl: item["ttl"].as_u64().unwrap_or_default() as u32,
                    ..Default::default()
                });
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
