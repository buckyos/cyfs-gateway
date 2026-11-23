//! netcup API v1, for domains on CloudDNS.

use reqwest::Method;
use serde_json::{Value, json};
use tokio::sync::OnceCell;

use crate::engine::{Backend, Change, Stored};
use crate::http::{Http, snippet, url};
use crate::provider::{DnsProviderError, DnsProviderResult, RecordType};
use crate::values::{fqdn, host, quote_txt, relative, stored_value, type_name};

const ENDPOINT: &str = "https://api.netcup.com/v1";
const PAGE_SIZE: &str = "100";

pub(crate) struct NetcupCloud {
    http: Http,
    base: String,
    api_key: String,
    origin: String,
    domain: OnceCell<String>,
}

impl NetcupCloud {
    pub(crate) fn new(
        api_key: &str,
        origin: &str,
        endpoint: Option<&str>,
    ) -> DnsProviderResult<Self> {
        Ok(Self {
            http: Http::new()?,
            base: endpoint.unwrap_or(ENDPOINT).to_string(),
            api_key: api_key.to_string(),
            origin: origin.to_string(),
            domain: OnceCell::new(),
        })
    }

    async fn call(
        &self,
        method: Method,
        path: &[&str],
        query: &[(&str, &str)],
        body: Option<Value>,
    ) -> DnsProviderResult<Value> {
        let mut request = self
            .http
            .request(method, url(&self.base, path, query)?)
            .bearer_auth(&self.api_key);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let reply = self.http.send(request).await?;
        let body: Value = reply.json().unwrap_or_default();
        if reply.is_ok() && body["success"] == true {
            return Ok(body);
        }
        // A refused key is a bad request here.
        let refused = body["errors"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|error| error["code"] == "authenticationError");
        Err(if refused {
            DnsProviderError::Unauthorized(reply.message())
        } else if reply.is_ok() {
            DnsProviderError::Api(snippet(&reply.body).to_string())
        } else {
            reply.error()
        })
    }

    async fn all(&self, path: &[&str]) -> DnsProviderResult<Vec<Value>> {
        let mut items = Vec::new();
        for page in 1.. {
            let page_text = page.to_string();
            let query = [("page", page_text.as_str()), ("perPage", PAGE_SIZE)];
            let body = self.call(Method::GET, path, &query, None).await?;
            let found = body["result"].as_array().cloned().unwrap_or_default();
            let last = body["meta"]["pagination"]["lastPage"].as_u64().unwrap_or(1);
            let empty = found.is_empty();
            items.extend(found);
            if empty || page >= last {
                break;
            }
        }
        Ok(items)
    }

    async fn domain(&self) -> DnsProviderResult<&str> {
        self.domain
            .get_or_try_init(|| async {
                let body = self
                    .call(Method::GET, &["domain"], &[("fqdn", &self.origin)], None)
                    .await?;
                let domain = body["result"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .find(|domain| host(domain["fqdn"].as_str().unwrap_or_default()) == self.origin)
                    .ok_or_else(|| DnsProviderError::ZoneNotFound(self.origin.clone()))?;
                if domain["isDnsManaged"] == false {
                    return Err(DnsProviderError::ZoneNotFound(format!(
                        "{} is not on CloudDNS, the Legacy API is needed",
                        self.origin
                    )));
                }
                Ok(domain["id"].to_string())
            })
            .await
            .map(String::as_str)
    }
}

#[async_trait::async_trait]
impl Backend for NetcupCloud {
    async fn list(&self, name: &str, ty: RecordType) -> DnsProviderResult<Vec<Stored>> {
        let label = relative(name, &self.origin, "@");
        let domain = self.domain().await?;
        // Only what is served has a serial; drafts do not.
        let revisions = self.all(&["domain", domain, "dns", "revision"]).await?;
        let Some(revision) = revisions
            .iter()
            .filter(|revision| revision["serial"].is_u64())
            .max_by_key(|revision| revision["serial"].as_u64())
            .and_then(|revision| revision["identifier"].as_str())
        else {
            return Ok(Vec::new());
        };
        let records = self
            .all(&["domain", domain, "dns", "revision", revision, "record"])
            .await?;
        Ok(records
            .iter()
            .filter(|record| {
                record["type"] == type_name(ty)
                    && match host(record["name"].as_str().unwrap_or_default()).as_str() {
                        "" => label == "@",
                        found => found == label,
                    }
            })
            .map(|record| Stored {
                value: stored_value(ty, record["rdata"].as_str().unwrap_or_default()),
                ttl: record["ttl"].as_u64().unwrap_or_default() as u32,
                raw: json!({
                    "name": record["name"],
                    "type": record["type"],
                    "rdata": record["rdata"],
                    "ttl": record["ttl"],
                }),
                ..Default::default()
            })
            .collect())
    }

    /// One change set, applied as a whole.
    async fn apply(&self, name: &str, ty: RecordType, change: Change) -> DnsProviderResult<()> {
        let label = relative(name, &self.origin, "@");
        let create: Vec<Value> = change
            .add
            .iter()
            .map(|value| {
                let rdata = match ty {
                    RecordType::TXT => quote_txt(value),
                    RecordType::CNAME | RecordType::NS => fqdn(value),
                    _ => value.clone(),
                };
                json!({ "name": label, "type": type_name(ty), "rdata": rdata, "ttl": change.ttl })
            })
            .collect();
        let delete: Vec<Value> = change.remove.into_iter().map(|record| record.raw).collect();
        let body = json!({
            "autoCommit": true,
            "strict": true,
            "create": create,
            "delete": delete,
        });
        let domain = self.domain().await?;
        self.call(
            Method::POST,
            &["domain", domain, "changeset"],
            &[],
            Some(body),
        )
        .await
        .map(drop)
    }
}
