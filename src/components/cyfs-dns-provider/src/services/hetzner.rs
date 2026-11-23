//! Cloud API (the DNS Console API is gone).

use std::time::Duration;

use reqwest::Method;
use serde_json::{Value, json};

use crate::engine::{Backend, Change, Stored};
use crate::http::{Http, Reply, busy, url};
use crate::provider::{DnsProviderError, DnsProviderResult, RecordType};
use crate::values::{fqdn, quote_txt, relative, stored_value, type_name};

const ENDPOINT: &str = "https://api.hetzner.cloud/v1";
const ACTION_POLLS: u32 = 20;

pub(crate) struct Hetzner {
    http: Http,
    base: String,
    token: String,
    origin: String,
}

impl Hetzner {
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
        path: &[&str],
        query: &[(&str, &str)],
        body: Option<Value>,
    ) -> DnsProviderResult<Reply> {
        let mut request = self
            .http
            .request(method, url(&self.base, path, query)?)
            .bearer_auth(&self.token);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let reply = self.http.send(request).await?;
        // Another change of the zone is still running.
        if matches!(reply.status, 409 | 423) {
            let body: Value = reply.json().unwrap_or_default();
            if matches!(body["error"]["code"].as_str(), Some("locked" | "conflict")) {
                return Err(busy(reply.message()));
            }
        }
        Ok(reply)
    }

    /// Changes run in the background; the next one has to wait for them.
    async fn finish(&self, reply: Reply) -> DnsProviderResult<()> {
        let mut body: Value = reply.ok()?.json()?;
        for _ in 0..ACTION_POLLS {
            let action = &body["action"];
            match action["status"].as_str() {
                Some("error") => {
                    return Err(DnsProviderError::Api(format!(
                        "change failed: {}",
                        action["error"]["message"].as_str().unwrap_or_default()
                    )));
                }
                Some("running") => {
                    let id = action["id"].to_string();
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    body = self
                        .call(Method::GET, &["zones", "actions", &id], &[], None)
                        .await?
                        .ok()?
                        .json()?;
                }
                _ => return Ok(()),
            }
        }
        Ok(())
    }

    fn records(&self, ty: RecordType, keep: &[Stored], add: &[String]) -> Vec<Value> {
        let mut records: Vec<Value> = keep.iter().map(|record| record.raw.clone()).collect();
        records.extend(add.iter().map(|value| {
            json!({ "value": match ty {
                RecordType::TXT => quote_txt(value),
                RecordType::CNAME | RecordType::NS => fqdn(value),
                _ => value.clone(),
            }})
        }));
        records
    }
}

#[async_trait::async_trait]
impl Backend for Hetzner {
    async fn list(&self, name: &str, ty: RecordType) -> DnsProviderResult<Vec<Stored>> {
        let label = relative(name, &self.origin, "@");
        let body: Value = self
            .call(
                Method::GET,
                &["zones", &self.origin, "rrsets"],
                &[("name", &label), ("type", type_name(ty))],
                None,
            )
            .await?
            .ok()?
            .json()?;
        Ok(body["rrsets"]
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
                        value: stored_value(ty, record["value"].as_str().unwrap_or_default()),
                        ttl,
                        raw: json!({
                            "value": record["value"],
                            "comment": record["comment"].as_str().unwrap_or_default(),
                        }),
                        ..Default::default()
                    })
            })
            .collect())
    }

    async fn apply(&self, name: &str, ty: RecordType, change: Change) -> DnsProviderResult<()> {
        let label = relative(name, &self.origin, "@");
        let zone = ["zones", self.origin.as_str(), "rrsets"];
        let rrset = [zone[0], zone[1], zone[2], label.as_str(), type_name(ty)];
        let action = |name| [&rrset[..], &["actions", name]].concat();
        let records = self.records(ty, &change.keep, &change.add);

        let exists = !change.keep.is_empty() || !change.remove.is_empty();
        let reply = if !exists {
            let body = json!({
                "name": label,
                "type": type_name(ty),
                "ttl": change.ttl,
                "records": records,
            });
            self.call(Method::POST, &zone, &[], Some(body)).await?
        } else if records.is_empty() {
            let reply = self.call(Method::DELETE, &rrset, &[], None).await?;
            if reply.status == 404 {
                return Ok(());
            }
            reply
        } else if change.remove.is_empty() {
            let body = json!({ "records": self.records(ty, &[], &change.add) });
            self.call(Method::POST, &action("add_records"), &[], Some(body))
                .await?
        } else {
            let body = json!({ "records": records });
            self.call(Method::POST, &action("set_records"), &[], Some(body))
                .await?
        };
        self.finish(reply).await
    }
}
