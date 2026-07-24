use name_client::{NameInfo, RecordType};
use name_lib::{DID, EncodedDocument};
use std::net::IpAddr;

use crate::ServerResult;

/// Stable metadata required to construct authoritative positive and negative
/// DNS responses.  The DNS wire server owns the Hickory-specific record
/// encoding; name servers only decide authority and name/RRset existence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsAuthority {
    pub zone_apex: String,
    pub primary_ns: String,
    pub responsible_mailbox: String,
    pub soa_serial: u32,
    pub soa_refresh: i32,
    pub soa_retry: i32,
    pub soa_expire: i32,
    pub soa_minimum: u32,
    pub positive_ttl: u32,
}

#[derive(Clone, Debug)]
pub enum DnsQueryResult {
    Answer {
        name_info: NameInfo,
        authority: Option<DnsAuthority>,
    },
    AuthoritativeNoData {
        authority: DnsAuthority,
    },
    AuthoritativeNxDomain {
        authority: DnsAuthority,
    },
    TemporaryFailure {
        cause: String,
    },
}

impl DnsQueryResult {
    pub fn non_authoritative_answer(name_info: NameInfo) -> Self {
        Self::Answer {
            name_info,
            authority: None,
        }
    }
}

#[async_trait::async_trait]
pub trait NameServer: Send + Sync {
    fn id(&self) -> String;

    /// Structured DNS entry point. Implementations that do not provide
    /// authoritative semantics retain the legacy `query` behavior through
    /// this default adapter.
    async fn query_dns(
        &self,
        name: &str,
        record_type: &str,
        from_ip: Option<IpAddr>,
    ) -> ServerResult<DnsQueryResult> {
        let record_type = RecordType::from_str(record_type).ok_or_else(|| {
            crate::server_err!(
                crate::ServerErrorCode::InvalidParam,
                "unsupported record type {}",
                record_type
            )
        })?;
        self.query(name, Some(record_type), from_ip)
            .await
            .map(DnsQueryResult::non_authoritative_answer)
    }

    async fn query(
        &self,
        name: &str,
        record_type: Option<RecordType>,
        from_ip: Option<IpAddr>,
    ) -> ServerResult<NameInfo>;
    async fn query_did(
        &self,
        did: &DID,
        fragment: Option<&str>,
        from_ip: Option<IpAddr>,
    ) -> ServerResult<EncodedDocument>;
}
