//! さくらのクラウド DNS. Records are written by replacing the list of the whole
//! zone, so everything else goes back exactly as it was read and the result is
//! read again.

use reqwest::Method;
use serde_json::{Value, json};
use tokio::sync::OnceCell;

use crate::engine::{Backend, Change, Stored};
use crate::http::{Http, Reply, busy, url};
use crate::provider::{DnsProviderError, DnsProviderResult, RecordType};
use crate::values::{fqdn, host, relative, stored_value, type_name};

const ENDPOINT: &str = "https://secure.sakura.ad.jp/cloud/zone/is1a/api/cloud/1.1";

pub(crate) struct Sakura {
    http: Http,
    base: String,
    access_token: String,
    access_token_secret: String,
    origin: String,
    item: OnceCell<String>,
}

impl Sakura {
    pub(crate) fn new(
        access_token: &str,
        access_token_secret: &str,
        origin: &str,
        endpoint: Option<&str>,
    ) -> DnsProviderResult<Self> {
        Ok(Self {
            http: Http::new()?,
            base: endpoint.unwrap_or(ENDPOINT).to_string(),
            access_token: access_token.to_string(),
            access_token_secret: access_token_secret.to_string(),
            origin: origin.to_string(),
            item: OnceCell::new(),
        })
    }

    async fn call(
        &self,
        method: Method,
        id: &[&str],
        filter: Option<Value>,
        body: Option<Value>,
    ) -> DnsProviderResult<Value> {
        let mut url = url(&self.base, &[&["commonserviceitem"], id].concat(), &[])?;
        if let Some(filter) = filter {
            // The query string is the JSON itself.
            url.set_query(Some(&filter.to_string()));
        }
        let mut request = self
            .http
            .request(method, url)
            .basic_auth(&self.access_token, Some(&self.access_token_secret));
        if let Some(body) = body {
            request = request.json(&body);
        }
        let reply: Reply = self.http.send(request).await?;
        match reply.status {
            409 | 423 => Err(busy(reply.message())),
            _ => reply.ok()?.json(),
        }
    }

    async fn item(&self) -> DnsProviderResult<&str> {
        self.item
            .get_or_try_init(|| async {
                let mut from = 0;
                loop {
                    let filter = json!({ "Filter": { "Provider.Class": "dns" }, "From": from });
                    let body = self.call(Method::GET, &[], Some(filter), None).await?;
                    let items = body["CommonServiceItems"]
                        .as_array()
                        .cloned()
                        .unwrap_or_default();
                    let found = items.iter().find(|item| {
                        host(item["Status"]["Zone"].as_str().unwrap_or_default()) == self.origin
                    });
                    if let Some(item) = found {
                        return Ok(match &item["ID"] {
                            Value::String(id) => id.clone(),
                            id => id.to_string(),
                        });
                    }
                    from += items.len() as u64;
                    if items.is_empty() || from >= body["Total"].as_u64().unwrap_or_default() {
                        return Err(DnsProviderError::ZoneNotFound(self.origin.clone()));
                    }
                }
            })
            .await
            .map(String::as_str)
    }

    async fn read(&self) -> DnsProviderResult<Value> {
        let id = self.item().await?;
        let body = self.call(Method::GET, &[id], None, None).await?;
        let item = body["CommonServiceItem"].clone();
        if host(item["Status"]["Zone"].as_str().unwrap_or_default()) != self.origin {
            return Err(DnsProviderError::ZoneNotFound(self.origin.clone()));
        }
        Ok(item)
    }
}

fn records(item: &Value) -> DnsProviderResult<Vec<Value>> {
    match &item["Settings"]["DNS"]["ResourceRecordSets"] {
        Value::Array(records) => Ok(records.clone()),
        Value::Null => Ok(Vec::new()),
        _ => Err(DnsProviderError::Api(
            "unexpected response: ResourceRecordSets is not a list".to_string(),
        )),
    }
}

/// What has to be the same after the write, in any order.
fn comparable(records: &[Value]) -> Vec<(String, String, String, u64)> {
    let mut list: Vec<_> = records
        .iter()
        .map(|record| {
            let text = |key: &str| record[key].as_str().unwrap_or_default().to_string();
            (
                text("Name"),
                text("Type"),
                text("RData"),
                record["TTL"].as_u64().unwrap_or(3600),
            )
        })
        .collect();
    list.sort();
    list
}

#[async_trait::async_trait]
impl Backend for Sakura {
    fn ttl_range(&self) -> (u32, u32) {
        (10, 3_600_000)
    }

    async fn list(&self, name: &str, ty: RecordType) -> DnsProviderResult<Vec<Stored>> {
        let label = relative(name, &self.origin, "@");
        Ok(records(&self.read().await?)?
            .iter()
            .filter(|record| record["Name"] == label.as_str() && record["Type"] == type_name(ty))
            .map(|record| Stored {
                value: stored_value(ty, record["RData"].as_str().unwrap_or_default()),
                ttl: record["TTL"].as_u64().unwrap_or(3600) as u32,
                raw: record.clone(),
                ..Default::default()
            })
            .collect())
    }

    async fn apply(&self, name: &str, ty: RecordType, change: Change) -> DnsProviderResult<()> {
        let label = relative(name, &self.origin, "@");
        let item = self.read().await?;
        let mut expected = records(&item)?;
        expected.retain(|record| !change.remove.iter().any(|removed| removed.raw == *record));
        // Every record of one name has to have the same TTL.
        let ttl = expected
            .iter()
            .find(|record| record["Name"] == label.as_str())
            .map_or(u64::from(change.ttl), |record| {
                record["TTL"].as_u64().unwrap_or(3600)
            });
        expected.extend(change.add.iter().map(|value| {
            let data = match ty {
                RecordType::CNAME | RecordType::NS => fqdn(value),
                _ => value.clone(),
            };
            json!({ "Name": label, "Type": type_name(ty), "RData": data, "TTL": ttl })
        }));

        let mut settings = item["Settings"].clone();
        if !settings.is_object() {
            settings = json!({ "DNS": {} });
        }
        settings["DNS"]["ResourceRecordSets"] = Value::Array(expected.clone());
        let mut body = json!({ "CommonServiceItem": { "Settings": settings } });
        if let Some(hash) = item["SettingsHash"].as_str() {
            body["OriginalSettingsHash"] = json!(hash);
        }
        let id = self.item().await?;
        self.call(Method::PUT, &[id], None, Some(body)).await?;

        let written = records(&self.read().await?)?;
        if comparable(&written) != comparable(&expected) {
            return Err(DnsProviderError::Api(
                "the records read back differ from the ones written, check the zone".to_string(),
            ));
        }
        Ok(())
    }
}
