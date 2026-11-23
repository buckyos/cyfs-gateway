use reqwest::Method;
use serde_json::{Value, json};
use tokio::sync::OnceCell;

use crate::engine::{RecordApi, Stored};
use crate::http::{Http, Reply, snippet, url};
use crate::provider::{DnsProviderError, DnsProviderResult, RecordType};
use crate::values::{host, quote_txt, stored_value, type_name};

const ENDPOINT: &str = "https://api.cloudflare.com/client/v4";
/// Invalid, unknown, expired or not permitted tokens.
const AUTH_CODES: [i64; 10] = [
    1000, 6003, 6111, 9103, 9106, 9107, 9109, 10000, 10001, 10405,
];
const IDENTICAL_RECORD: [i64; 2] = [81057, 81058];

pub(crate) struct Cloudflare {
    http: Http,
    base: String,
    token: String,
    origin: String,
    zone: OnceCell<String>,
}

fn codes(body: &Value) -> Vec<i64> {
    let mut codes = Vec::new();
    for error in body["errors"].as_array().into_iter().flatten() {
        codes.extend(error["code"].as_i64());
        for cause in error["error_chain"].as_array().into_iter().flatten() {
            codes.extend(cause["code"].as_i64());
        }
    }
    codes
}

impl Cloudflare {
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
            zone: OnceCell::new(),
        })
    }

    async fn call(
        &self,
        method: Method,
        path: &[&str],
        query: &[(&str, &str)],
        body: Option<Value>,
    ) -> Result<Value, (Vec<i64>, DnsProviderError)> {
        let failed = |error| (Vec::new(), error);
        let mut request = self
            .http
            .request(method, url(&self.base, path, query).map_err(failed)?)
            .bearer_auth(&self.token);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let reply: Reply = self.http.send(request).await.map_err(failed)?;
        let body: Value = serde_json::from_str(&reply.body).unwrap_or_default();
        if reply.is_ok() && body["success"] == true {
            return Ok(body);
        }
        let codes = codes(&body);
        let error = if reply.status == 429 || reply.status == 503 {
            reply.error()
        } else if codes.iter().any(|code| AUTH_CODES.contains(code)) {
            DnsProviderError::Unauthorized(reply.message())
        } else if reply.is_ok() {
            DnsProviderError::Api(snippet(&reply.body).to_string())
        } else {
            reply.error()
        };
        Err((codes, error))
    }

    async fn zone(&self) -> DnsProviderResult<&str> {
        self.zone
            .get_or_try_init(|| async {
                let body = self
                    .call(Method::GET, &["zones"], &[("name", &self.origin)], None)
                    .await
                    .map_err(|(_, error)| error)?;
                let mut zones: Vec<&Value> = body["result"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter(|zone| host(zone["name"].as_str().unwrap_or_default()) == self.origin)
                    .collect();
                // The same name can sit in two accounts; only one is in use.
                zones.sort_by_key(|zone| zone["status"] != "active");
                zones
                    .first()
                    .and_then(|zone| zone["id"].as_str())
                    .map(str::to_string)
                    .ok_or_else(|| DnsProviderError::ZoneNotFound(self.origin.clone()))
            })
            .await
            .map(String::as_str)
    }

    fn record(&self, ty: RecordType, ttl: u32, value: &str) -> Value {
        let content = match ty {
            RecordType::TXT => quote_txt(value),
            _ => value.to_string(),
        };
        let mut record = json!({ "content": content, "ttl": ttl });
        if proxiable(ty) {
            record["proxied"] = json!(false);
        }
        record
    }
}

fn proxiable(ty: RecordType) -> bool {
    matches!(ty, RecordType::A | RecordType::AAAA | RecordType::CNAME)
}

#[async_trait::async_trait]
impl RecordApi for Cloudflare {
    const UPDATES: bool = true;

    async fn list(&self, name: &str, ty: RecordType) -> DnsProviderResult<Vec<Stored>> {
        let zone = self.zone().await?;
        let mut records = Vec::new();
        for page in 1.. {
            let page_text = page.to_string();
            let body = self
                .call(
                    Method::GET,
                    &["zones", zone, "dns_records"],
                    &[
                        ("type", type_name(ty)),
                        ("name", name),
                        ("per_page", "100"),
                        ("page", &page_text),
                    ],
                    None,
                )
                .await
                .map_err(|(_, error)| error)?;
            for record in body["result"].as_array().into_iter().flatten() {
                let content = record["content"].as_str().unwrap_or_default();
                if host(record["name"].as_str().unwrap_or_default()) != name
                    || record["type"] != type_name(ty)
                {
                    continue;
                }
                records.push(Stored {
                    id: record["id"].as_str().unwrap_or_default().to_string(),
                    value: stored_value(ty, content),
                    ttl: record["ttl"].as_u64().unwrap_or_default() as u32,
                    raw: Value::Null,
                    stale: record["proxied"] == true,
                });
            }
            if body["result_info"]["total_pages"].as_u64().unwrap_or(1) <= page {
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
        let zone = self.zone().await?;
        let mut record = self.record(ty, ttl, value);
        record["name"] = json!(name);
        record["type"] = json!(type_name(ty));
        let created = self
            .call(
                Method::POST,
                &["zones", zone, "dns_records"],
                &[],
                Some(record),
            )
            .await;
        match created {
            Ok(_) => Ok(()),
            Err((codes, _)) if codes.iter().any(|code| IDENTICAL_RECORD.contains(code)) => Ok(()),
            Err((_, error)) => Err(error),
        }
    }

    async fn update(
        &self,
        _name: &str,
        ty: RecordType,
        ttl: u32,
        record: &Stored,
        value: &str,
    ) -> DnsProviderResult<()> {
        let zone = self.zone().await?;
        self.call(
            Method::PATCH,
            &["zones", zone, "dns_records", &record.id],
            &[],
            Some(self.record(ty, ttl, value)),
        )
        .await
        .map(drop)
        .map_err(|(_, error)| error)
    }

    async fn delete(&self, _name: &str, _ty: RecordType, record: &Stored) -> DnsProviderResult<()> {
        let zone = self.zone().await?;
        match self
            .call(
                Method::DELETE,
                &["zones", zone, "dns_records", &record.id],
                &[],
                None,
            )
            .await
        {
            Ok(_) | Err((_, DnsProviderError::ZoneNotFound(_))) => Ok(()),
            Err((_, error)) => Err(error),
        }
    }
}
