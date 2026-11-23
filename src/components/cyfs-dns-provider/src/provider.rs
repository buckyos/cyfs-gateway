use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;

use crate::credential::DnsCredential;
use crate::engine::Engine;
use crate::services;
use crate::values::host;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "UPPERCASE")]
pub enum RecordType {
    A,
    AAAA,
    CNAME,
    NS,
    TXT,
    SOA,
    CAA,
}

#[derive(Debug, thiserror::Error)]
pub enum DnsProviderError {
    /// The service refused the credential (revoked, expired, wrong, or not allowed to edit this zone).
    #[error("credential rejected: {0}")]
    Unauthorized(String),
    #[error("zone not found: {0}")]
    ZoneNotFound(String),
    #[error("rate limited: {message}")]
    RateLimited {
        message: String,
        retry_after: Option<Duration>,
    },
    #[error("invalid credential: {0}")]
    InvalidCredential(String),
    #[error("unsupported: {0}")]
    Unsupported(String),
    #[error("network error: {0}")]
    Network(String),
    #[error("{0}")]
    Api(String),
}

pub type DnsProviderResult<T> = Result<T, DnsProviderError>;

/// Names are absolute host names without the trailing dot (`*` allowed as the
/// first label). Values are in presentation form: an address, a host name
/// without the trailing dot, or the bare TXT text without quotes.
///
/// `ttl` applies to values that are new; it is raised to what the service
/// accepts and gives way to the TTL of the values that stay. A, AAAA and CNAME
/// records written to Cloudflare are "DNS only", one that already has the right
/// value but is proxied is changed. SOA and CAA records, and the NS records of
/// the zone itself, are never written.
#[async_trait::async_trait]
pub trait DnsRecordProvider: Send + Sync {
    /// Replaces the whole RRset; an empty list deletes it. Records of other
    /// types of the same name stay, so a CNAME conflicts until the caller has
    /// emptied those.
    async fn set_rrset(
        &self,
        name: &str,
        ty: RecordType,
        ttl: u32,
        values: Vec<String>,
    ) -> DnsProviderResult<()>;
    /// Adds only these values; other values of the same name stay. Idempotent.
    async fn add_values(
        &self,
        name: &str,
        ty: RecordType,
        ttl: u32,
        values: Vec<String>,
    ) -> DnsProviderResult<()>;
    /// Removes only these values; other values of the same name stay. Idempotent.
    async fn remove_values(
        &self,
        name: &str,
        ty: RecordType,
        values: Vec<String>,
    ) -> DnsProviderResult<()>;
    /// What the service holds, which can be ahead of its name servers.
    async fn list_values(&self, _name: &str, _ty: RecordType) -> DnsProviderResult<Vec<String>> {
        Err(DnsProviderError::Unsupported("list_values".to_string()))
    }
}

pub type DnsRecordProviderRef = Arc<dyn DnsRecordProvider>;

/// Builds the provider of `credential` for the zone `origin` (the zone apex,
/// found with [`crate::lookup::find_zone_apex`], never by cutting labels).
pub fn create_provider(
    credential: &DnsCredential,
    origin: &str,
) -> DnsProviderResult<DnsRecordProviderRef> {
    credential.validate()?;
    let origin = host(origin);
    if origin.is_empty() {
        return Err(DnsProviderError::ZoneNotFound("no zone given".to_string()));
    }
    let backend = services::backend(credential, &origin)?;
    Ok(Arc::new(Engine::new(
        &credential.provider,
        &origin,
        backend,
        credential.secrets(),
    )))
}
