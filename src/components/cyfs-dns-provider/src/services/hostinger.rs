use reqwest::Method;
use serde_json::{Value, json};

use crate::engine::{Backend, Change, Stored};
use crate::http::{Http, Reply, url};
use crate::provider::{DnsProviderError, DnsProviderResult, RecordType};
use crate::values::{fqdn, relative, stored_value, type_name};

const ENDPOINT: &str = "https://developers.hostinger.com";

pub(crate) struct Hostinger {
    http: Http,
    base: String,
    token: String,
    origin: String,
}

impl Hostinger {
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

    async fn call(&self, method: Method, body: Option<Value>) -> DnsProviderResult<Reply> {
        let path = ["api", "dns", "v1", "zones", &self.origin];
        let mut request = self
            .http
            .request(method, url(&self.base, &path, &[])?)
            .bearer_auth(&self.token)
            .header("accept", "application/json");
        if let Some(body) = body {
            request = request.json(&body);
        }
        self.http.send(request).await?.ok()
    }
}

#[async_trait::async_trait]
impl Backend for Hostinger {
    async fn list(&self, name: &str, ty: RecordType) -> DnsProviderResult<Vec<Stored>> {
        let label = relative(name, &self.origin, "@");
        let body: Value = self.call(Method::GET, None).await?.json()?;
        Ok(body
            .as_array()
            .into_iter()
            .flatten()
            .filter(|rrset| rrset["name"] == label.as_str() && rrset["type"] == type_name(ty))
            .flat_map(|rrset| {
                let ttl = rrset["ttl"].as_u64().unwrap_or_default() as u32;
                rrset["records"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(move |record| Stored {
                        // TXT comes back quoted, targets with a dot.
                        value: stored_value(ty, record["content"].as_str().unwrap_or_default()),
                        ttl,
                        raw: json!({ "content": record["content"] }),
                        stale: record["is_disabled"] == true,
                        ..Default::default()
                    })
            })
            .collect())
    }

    async fn apply(&self, name: &str, ty: RecordType, change: Change) -> DnsProviderResult<()> {
        let label = relative(name, &self.origin, "@");
        let overwrite = change.keep.is_empty() || !change.remove.is_empty();
        let mut records: Vec<Value> = Vec::new();
        if overwrite {
            // A disabled record cannot be written back as it is.
            if change.keep.iter().any(|record| record.stale) {
                return Err(DnsProviderError::Unsupported(format!(
                    "{name} has disabled records"
                )));
            }
            records.extend(change.keep.iter().map(|record| record.raw.clone()));
        }
        records.extend(change.add.iter().map(|value| {
            json!({ "content": match ty {
                RecordType::CNAME | RecordType::NS => fqdn(value),
                _ => value.clone(),
            }})
        }));
        if records.is_empty() {
            let body = json!({ "filters": [{ "name": label, "type": type_name(ty) }] });
            return match self.call(Method::DELETE, Some(body)).await {
                Ok(_) | Err(DnsProviderError::ZoneNotFound(_)) => Ok(()),
                Err(error) => Err(error),
            };
        }
        // Either way only the records of this name and type are touched:
        // replaced, or appended to.
        let body = json!({
            "overwrite": overwrite,
            "zone": [{
                "name": label,
                "type": type_name(ty),
                "ttl": change.ttl,
                "records": records,
            }],
        });
        self.call(Method::PUT, Some(body)).await.map(drop)
    }
}
