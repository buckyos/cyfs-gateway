use reqwest::Method;
use serde_json::{Value, json};

use crate::engine::{Backend, Change, Stored};
use crate::http::{Http, Reply, url};
use crate::provider::{DnsProviderError, DnsProviderResult, RecordType};
use crate::values::{fqdn, quote_txt, relative, stored_value, type_name};

const ENDPOINT: &str = "https://api.gandi.net/v5";

pub(crate) struct Gandi {
    http: Http,
    base: String,
    token: String,
    origin: String,
}

impl Gandi {
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
        name: &str,
        ty: RecordType,
        body: Option<Value>,
    ) -> DnsProviderResult<Reply> {
        let label = relative(name, &self.origin, "@");
        let path = [
            "livedns",
            "domains",
            &self.origin,
            "records",
            &label,
            type_name(ty),
        ];
        let mut request = self
            .http
            .request(method, url(&self.base, &path, &[])?)
            .bearer_auth(&self.token);
        if let Some(body) = body {
            request = request.json(&body);
        }
        self.http.send(request).await
    }
}

#[async_trait::async_trait]
impl Backend for Gandi {
    fn ttl_range(&self) -> (u32, u32) {
        (300, 2_592_000)
    }

    async fn list(&self, name: &str, ty: RecordType) -> DnsProviderResult<Vec<Stored>> {
        let reply = self.call(Method::GET, name, ty, None).await?;
        if reply.status == 404 {
            return Ok(Vec::new());
        }
        let body: Value = reply.ok()?.json()?;
        let ttl = body["rrset_ttl"].as_u64().unwrap_or_default() as u32;
        Ok(body["rrset_values"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(|raw| Stored {
                value: stored_value(ty, raw),
                ttl,
                raw: raw.into(),
                ..Default::default()
            })
            .collect())
    }

    async fn apply(&self, name: &str, ty: RecordType, change: Change) -> DnsProviderResult<()> {
        let mut values: Vec<Value> = change.keep.into_iter().map(|record| record.raw).collect();
        values.extend(change.add.iter().map(|value| match ty {
            RecordType::TXT => Value::from(quote_txt(value)),
            RecordType::CNAME | RecordType::NS => Value::from(fqdn(value)),
            _ => Value::from(value.as_str()),
        }));
        if values.is_empty() {
            let reply = self.call(Method::DELETE, name, ty, None).await?;
            return match reply.ok() {
                Ok(_) | Err(DnsProviderError::ZoneNotFound(_)) => Ok(()),
                Err(error) => Err(error),
            };
        }
        let body = json!({ "rrset_ttl": change.ttl, "rrset_values": values });
        self.call(Method::PUT, name, ty, Some(body)).await?.ok()?;
        Ok(())
    }
}
