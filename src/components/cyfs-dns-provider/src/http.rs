use std::time::{Duration, SystemTime, UNIX_EPOCH};

use reqwest::header::HeaderMap;
use reqwest::{Client, Method, RequestBuilder, Url, redirect};
use serde::de::DeserializeOwned;

use crate::provider::{DnsProviderError, DnsProviderResult};

pub(crate) const TIMEOUT: Duration = Duration::from_secs(30);
/// How long to wait for a service that says it is still applying a change.
const BUSY_WAIT: Duration = Duration::from_secs(1);

#[derive(Clone)]
pub(crate) struct Http(Client);

pub(crate) struct Reply {
    pub status: u16,
    pub headers: HeaderMap,
    pub body: String,
}

pub(crate) fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default()
}

/// `base` plus percent-encoded path segments and query pairs.
pub(crate) fn url(base: &str, path: &[&str], query: &[(&str, &str)]) -> DnsProviderResult<Url> {
    let invalid = || DnsProviderError::InvalidCredential("invalid API address".to_string());
    let mut url = Url::parse(base).map_err(|_| invalid())?;
    if !path.is_empty() {
        url.path_segments_mut()
            .map_err(|_| invalid())?
            .pop_if_empty()
            .extend(path);
    }
    if !query.is_empty() {
        url.query_pairs_mut().extend_pairs(query);
    }
    Ok(url)
}

pub(crate) fn snippet(text: &str) -> &str {
    let text = text.trim();
    let mut end = text.len().min(300);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

pub(crate) fn busy(message: impl Into<String>) -> DnsProviderError {
    DnsProviderError::RateLimited {
        message: message.into(),
        retry_after: Some(BUSY_WAIT),
    }
}

impl Http {
    pub(crate) fn new() -> DnsProviderResult<Self> {
        Client::builder()
            .timeout(TIMEOUT)
            .redirect(redirect::Policy::none())
            // netcup does not see a lower-case "authorization".
            .http1_title_case_headers()
            .user_agent("buckyos-dns-provider")
            .build()
            .map(Self)
            .map_err(|error| DnsProviderError::Network(error.to_string()))
    }

    pub(crate) fn request(&self, method: Method, url: Url) -> RequestBuilder {
        self.0.request(method, url)
    }

    pub(crate) async fn send(&self, request: RequestBuilder) -> DnsProviderResult<Reply> {
        let network = |error: reqwest::Error| {
            let timed_out = error.is_timeout();
            let error = anyhow::Error::from(error.without_url());
            DnsProviderError::Network(if timed_out {
                "request timed out".to_string()
            } else {
                format!("{error:#}")
            })
        };
        let response = request.send().await.map_err(network)?;
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let body = response.text().await.map_err(network)?;
        Ok(Reply {
            status,
            headers,
            body,
        })
    }
}

impl Reply {
    pub(crate) fn is_ok(&self) -> bool {
        (200..300).contains(&self.status)
    }

    pub(crate) fn json<T: DeserializeOwned>(&self) -> DnsProviderResult<T> {
        serde_json::from_str(&self.body).map_err(|error| {
            DnsProviderError::Api(format!(
                "unexpected response ({error}): {}",
                snippet(&self.body)
            ))
        })
    }

    /// When the service says to come back.
    pub(crate) fn retry_after(&self) -> Option<Duration> {
        [
            "retry-after",
            "ratelimit-reset",
            "x-ratelimit-reset",
            "x-rate-limit-reset",
        ]
        .iter()
        .find_map(|name| self.headers.get(*name)?.to_str().ok()?.trim().parse().ok())
        .map(|seconds: u64| {
            // Some services send a moment instead of a delay.
            let seconds = if seconds > 1_000_000_000 {
                seconds.saturating_sub(now())
            } else {
                seconds
            };
            Duration::from_secs(seconds)
        })
    }

    pub(crate) fn message(&self) -> String {
        format!("HTTP {}: {}", self.status, snippet(&self.body))
    }

    /// What a failed response means when the service's own codes say nothing more.
    pub(crate) fn error(&self) -> DnsProviderError {
        match self.status {
            401 | 403 => DnsProviderError::Unauthorized(self.message()),
            404 => DnsProviderError::ZoneNotFound(self.message()),
            429 | 503 => DnsProviderError::RateLimited {
                message: self.message(),
                retry_after: self.retry_after(),
            },
            _ => DnsProviderError::Api(self.message()),
        }
    }

    pub(crate) fn ok(self) -> DnsProviderResult<Self> {
        if self.is_ok() {
            Ok(self)
        } else {
            Err(self.error())
        }
    }
}
