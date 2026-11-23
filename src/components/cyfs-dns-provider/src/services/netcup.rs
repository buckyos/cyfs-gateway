//! CCP web service: the legacy API, for domains that are not on CloudDNS.

use std::time::{Duration, Instant};

use reqwest::Method;
use serde_json::{Value, json};
use tokio::sync::Mutex;

use crate::engine::{Backend, Change, Stored};
use crate::http::{Http, url};
use crate::provider::{DnsProviderError, DnsProviderResult, RecordType};
use crate::values::{relative, stored_value, type_name};

const ENDPOINT: &str = "https://ccp.netcup.net/run/webservice/servers/endpoint.php?JSON";
const SESSION_TTL: Duration = Duration::from_secs(10 * 60);
/// `infoDnsRecords` of a zone without records.
const NO_RECORDS: i64 = 5029;

pub(crate) struct Netcup {
    http: Http,
    endpoint: String,
    customer_number: String,
    api_key: String,
    api_password: String,
    origin: String,
    session: Mutex<Option<(String, Instant)>>,
}

impl Netcup {
    pub(crate) fn new(
        customer_number: &str,
        api_key: &str,
        api_password: &str,
        origin: &str,
        endpoint: Option<&str>,
    ) -> DnsProviderResult<Self> {
        Ok(Self {
            http: Http::new()?,
            endpoint: endpoint.unwrap_or(ENDPOINT).to_string(),
            customer_number: customer_number.to_string(),
            api_key: api_key.to_string(),
            api_password: api_password.to_string(),
            origin: origin.to_string(),
            session: Mutex::new(None),
        })
    }

    async fn post(&self, action: &str, param: Value) -> DnsProviderResult<Value> {
        let request = self
            .http
            .request(Method::POST, url(&self.endpoint, &[], &[])?)
            .json(&json!({ "action": action, "param": param }));
        self.http.send(request).await?.ok()?.json()
    }

    async fn login(&self) -> DnsProviderResult<String> {
        let param = json!({
            "customernumber": self.customer_number,
            "apikey": self.api_key,
            "apipassword": self.api_password,
        });
        let body = self.post("login", param).await?;
        if body["status"] != "success" {
            return Err(match failure(&body) {
                DnsProviderError::Api(text) => DnsProviderError::Unauthorized(text),
                other => other,
            });
        }
        body["responsedata"]["apisessionid"]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| DnsProviderError::Api("no session in the login response".to_string()))
    }

    async fn call(&self, action: &str, extra: Value) -> DnsProviderResult<Value> {
        let mut session = self.session.lock().await;
        let mut fresh = false;
        loop {
            let id = match session.as_ref() {
                Some((id, expires)) if Instant::now() < *expires => id.clone(),
                _ => {
                    fresh = true;
                    let id = self.login().await?;
                    *session = Some((id.clone(), Instant::now() + SESSION_TTL));
                    id
                }
            };
            let mut param = json!({
                "domainname": self.origin,
                "customernumber": self.customer_number,
                "apikey": self.api_key,
                "apisessionid": id,
            });
            if let (Some(param), Value::Object(extra)) = (param.as_object_mut(), extra.clone()) {
                param.extend(extra);
            }
            let body = self.post(action, param).await?;
            if body["status"] == "success" {
                return Ok(body);
            }
            let expired = body["longmessage"]
                .as_str()
                .is_some_and(|text| text.to_ascii_lowercase().contains("session"));
            if expired && !fresh {
                *session = None;
                continue;
            }
            if action == "infoDnsRecords" && body["statuscode"] == NO_RECORDS {
                return Ok(json!({}));
            }
            return Err(failure(&body));
        }
    }
}

fn failure(body: &Value) -> DnsProviderError {
    let text = |key: &str| body[key].as_str().unwrap_or_default().to_string();
    let message = format!(
        "{} {} {}",
        body["statuscode"],
        text("shortmessage"),
        text("longmessage")
    );
    let lower = message.to_ascii_lowercase();
    if lower.contains("requests per minute") {
        DnsProviderError::RateLimited {
            message,
            retry_after: Some(Duration::from_secs(10)),
        }
    } else if lower.contains("domain") && lower.contains("not found") {
        DnsProviderError::ZoneNotFound(message)
    } else {
        DnsProviderError::Api(message)
    }
}

#[async_trait::async_trait]
impl Backend for Netcup {
    async fn list(&self, name: &str, ty: RecordType) -> DnsProviderResult<Vec<Stored>> {
        let label = relative(name, &self.origin, "@");
        let body = self.call("infoDnsRecords", json!({})).await?;
        Ok(body["responsedata"]["dnsrecords"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|record| {
                record["hostname"] == label.as_str() && record["type"] == type_name(ty)
            })
            .map(|record| Stored {
                id: match &record["id"] {
                    Value::String(id) => id.clone(),
                    id => id.to_string(),
                },
                value: stored_value(ty, record["destination"].as_str().unwrap_or_default()),
                raw: record.clone(),
                ..Default::default()
            })
            .collect())
    }

    /// Only the records sent are touched; one without an id is added.
    async fn apply(&self, name: &str, ty: RecordType, change: Change) -> DnsProviderResult<()> {
        let label = relative(name, &self.origin, "@");
        let mut add = change.add.iter();
        let mut records: Vec<Value> = Vec::new();
        for record in &change.remove {
            let mut sent = record.raw.clone();
            match add.next() {
                Some(value) => sent["destination"] = json!(value),
                None => sent["deleterecord"] = json!(true),
            }
            records.push(sent);
        }
        records.extend(add.map(
            |value| json!({ "hostname": label, "type": type_name(ty), "destination": value }),
        ));
        self.call(
            "updateDnsRecords",
            json!({ "dnsrecordset": { "dnsrecords": records } }),
        )
        .await
        .map(drop)
    }
}
