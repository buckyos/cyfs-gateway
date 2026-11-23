use std::sync::atomic::{AtomicBool, Ordering};

use reqwest::Method;
use serde_json::{Value, json};
use tokio::sync::OnceCell;

use crate::crypto::{hex, sha1};
use crate::engine::{RecordApi, Stored};
use crate::http::{Http, Reply, now, url};
use crate::provider::{DnsProviderError, DnsProviderResult, RecordType};
use crate::values::{fqdn, host, relative, stored_value, type_name};

pub(crate) struct Ovh {
    http: Http,
    base: String,
    application_key: String,
    application_secret: String,
    consumer_key: String,
    origin: String,
    /// Service time minus local time.
    clock: OnceCell<i64>,
    dirty: AtomicBool,
}

impl Ovh {
    pub(crate) fn new(
        region: &str,
        application_key: &str,
        application_secret: &str,
        consumer_key: &str,
        origin: &str,
        endpoint: Option<&str>,
    ) -> DnsProviderResult<Self> {
        let base = match endpoint {
            Some(endpoint) => endpoint.to_string(),
            None => format!("https://api.{region}.ovhcloud.com/1.0"),
        };
        Ok(Self {
            http: Http::new()?,
            base,
            application_key: application_key.to_string(),
            application_secret: application_secret.to_string(),
            consumer_key: consumer_key.to_string(),
            origin: origin.to_string(),
            clock: OnceCell::new(),
            dirty: AtomicBool::new(false),
        })
    }

    async fn timestamp(&self) -> DnsProviderResult<u64> {
        let offset = self
            .clock
            .get_or_try_init(|| async {
                let request = self
                    .http
                    .request(Method::GET, url(&self.base, &["auth", "time"], &[])?);
                let time: i64 = self.http.send(request).await?.ok()?.json()?;
                Ok::<_, DnsProviderError>(time - now() as i64)
            })
            .await?;
        Ok(now().saturating_add_signed(*offset))
    }

    async fn call(
        &self,
        method: Method,
        path: &[&str],
        query: &[(&str, &str)],
        body: Option<Value>,
    ) -> DnsProviderResult<Reply> {
        let path = [&["domain", "zone", &self.origin], path].concat();
        let url = url(&self.base, &path, query)?;
        let body = body.map(|body| body.to_string()).unwrap_or_default();
        let timestamp = self.timestamp().await?;
        let signed = format!(
            "{}+{}+{method}+{url}+{body}+{timestamp}",
            self.application_secret, self.consumer_key
        );
        let request = self
            .http
            .request(method, url)
            .header("content-type", "application/json")
            .header("x-ovh-application", &self.application_key)
            .header("x-ovh-consumer", &self.consumer_key)
            .header("x-ovh-timestamp", timestamp)
            .header(
                "x-ovh-signature",
                format!("$1${}", hex(&sha1(signed.as_bytes())?)),
            )
            .body(body);
        self.http.send(request).await
    }

    fn target(ty: RecordType, value: &str) -> String {
        match ty {
            RecordType::CNAME | RecordType::NS => fqdn(value),
            _ => value.to_string(),
        }
    }
}

#[async_trait::async_trait]
impl RecordApi for Ovh {
    const UPDATES: bool = true;

    async fn list(&self, name: &str, ty: RecordType) -> DnsProviderResult<Vec<Stored>> {
        let label = relative(name, &self.origin, "");
        let ids: Vec<u64> = self
            .call(
                Method::GET,
                &["record"],
                &[("fieldType", type_name(ty)), ("subDomain", &label)],
                None,
            )
            .await?
            .ok()?
            .json()?;
        let mut records = Vec::new();
        for id in ids {
            let id = id.to_string();
            let reply = self.call(Method::GET, &["record", &id], &[], None).await?;
            if reply.status == 404 {
                continue;
            }
            let record: Value = reply.ok()?.json()?;
            // The filters match patterns, not exact names.
            if record["fieldType"] != type_name(ty)
                || host(record["subDomain"].as_str().unwrap_or_default()) != label
            {
                continue;
            }
            let target = record["target"].as_str().unwrap_or_default();
            let value = match ty {
                // A target without a dot is relative to the zone.
                RecordType::CNAME | RecordType::NS if !target.ends_with('.') => {
                    format!("{}.{}", host(target), self.origin)
                }
                _ => stored_value(ty, target),
            };
            records.push(Stored {
                id,
                value,
                ttl: record["ttl"].as_u64().unwrap_or_default() as u32,
                ..Default::default()
            });
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
        let body = json!({
            "fieldType": type_name(ty),
            "subDomain": relative(name, &self.origin, ""),
            "target": Self::target(ty, value),
            "ttl": ttl,
        });
        self.dirty.store(true, Ordering::Relaxed);
        self.call(Method::POST, &["record"], &[], Some(body))
            .await?
            .ok()?;
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
        let body = json!({
            "subDomain": relative(name, &self.origin, ""),
            "target": Self::target(ty, value),
            "ttl": ttl,
        });
        self.dirty.store(true, Ordering::Relaxed);
        self.call(Method::PUT, &["record", &record.id], &[], Some(body))
            .await?
            .ok()?;
        Ok(())
    }

    async fn delete(&self, _name: &str, _ty: RecordType, record: &Stored) -> DnsProviderResult<()> {
        self.dirty.store(true, Ordering::Relaxed);
        let reply = self
            .call(Method::DELETE, &["record", &record.id], &[], None)
            .await?;
        match reply.ok() {
            Ok(_) | Err(DnsProviderError::ZoneNotFound(_)) => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// Changes are served only after the zone is refreshed.
    async fn commit(&self) -> DnsProviderResult<()> {
        if self.dirty.load(Ordering::Relaxed) {
            self.call(Method::POST, &["refresh"], &[], None)
                .await?
                .ok()?;
            self.dirty.store(false, Ordering::Relaxed);
        }
        Ok(())
    }
}
