//! Services `dns-update` handles as needed.

use dns_update::providers::azuredns::{AzureDnsConfig, AzureEnvironment};
use dns_update::{DnsRecord, DnsRecordType, DnsUpdater, Error};

use crate::engine::{Backend, Change, Stored};
use crate::http::TIMEOUT;
use crate::provider::{DnsProviderError, DnsProviderResult, RecordType};
use crate::values::stored_value;

pub(crate) struct Wrapped {
    updater: DnsUpdater,
    service: Service,
    origin: String,
}

#[derive(Clone, Copy, PartialEq)]
enum Service {
    Porkbun,
    Ionos,
    Azure,
    Desec,
    AliDns,
    DnsPod,
}

impl Wrapped {
    fn new(
        service: Service,
        origin: &str,
        updater: dns_update::Result<DnsUpdater>,
    ) -> DnsProviderResult<Self> {
        Ok(Self {
            updater: updater
                .map_err(|error| DnsProviderError::InvalidCredential(error.to_string()))?,
            service,
            origin: origin.to_string(),
        })
    }

    pub(crate) fn porkbun(api_key: &str, secret: &str, origin: &str) -> DnsProviderResult<Self> {
        let updater = DnsUpdater::new_porkbun(api_key, secret, Some(TIMEOUT));
        Self::new(Service::Porkbun, origin, updater)
    }

    pub(crate) fn ionos(api_key: &str, origin: &str) -> DnsProviderResult<Self> {
        let updater = DnsUpdater::new_ionos(api_key, Some(TIMEOUT));
        Self::new(Service::Ionos, origin, updater)
    }

    pub(crate) fn azure(
        tenant_id: &str,
        client_id: &str,
        client_secret: &str,
        subscription_id: &str,
        resource_group: &str,
        origin: &str,
    ) -> DnsProviderResult<Self> {
        let updater = DnsUpdater::new_azuredns(AzureDnsConfig {
            tenant_id: tenant_id.to_string(),
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            subscription_id: subscription_id.to_string(),
            resource_group: resource_group.to_string(),
            environment: AzureEnvironment::Public,
            request_timeout: Some(TIMEOUT),
        });
        Self::new(Service::Azure, origin, updater)
    }

    pub(crate) fn desec(token: &str, origin: &str) -> DnsProviderResult<Self> {
        let updater = DnsUpdater::new_desec(token, Some(TIMEOUT));
        Self::new(Service::Desec, origin, updater)
    }

    pub(crate) fn alidns(key_id: &str, secret: &str, origin: &str) -> DnsProviderResult<Self> {
        let updater = DnsUpdater::new_alidns(
            key_id,
            secret,
            None::<&str>,
            None::<&str>,
            None::<&str>,
            Some(TIMEOUT),
        );
        Self::new(Service::AliDns, origin, updater)
    }

    pub(crate) fn dnspod(
        secret_id: &str,
        secret_key: &str,
        origin: &str,
    ) -> DnsProviderResult<Self> {
        let updater = DnsUpdater::new_tencentcloud(
            secret_id,
            secret_key,
            None::<&str>,
            None::<&str>,
            Some(TIMEOUT),
        );
        Self::new(Service::DnsPod, origin, updater)
    }

    fn error(&self, error: Error) -> DnsProviderError {
        let text = match error {
            Error::Unauthorized => {
                return DnsProviderError::Unauthorized("the service refused the key".to_string());
            }
            // An unknown access key is reported as "not found".
            Error::NotFound if self.service == Service::AliDns => {
                return DnsProviderError::Unauthorized("access key not found".to_string());
            }
            Error::NotFound => return DnsProviderError::ZoneNotFound(self.origin.clone()),
            Error::Unsupported(text) => return DnsProviderError::Unsupported(text),
            Error::Api(text) => text,
            other => other.to_string(),
        };
        let has = |marks: &[&str]| marks.iter().any(|mark| text.contains(mark));
        if has(&["Failed to send request", "Failed to read response"]) {
            return DnsProviderError::Network(text);
        }
        if text.starts_with("HTTP 429")
            || text.starts_with("HTTP 503")
            || has(&["Throttling", "RequestLimitExceeded", "RATE_LIMIT_EXCEEDED"])
        {
            return DnsProviderError::RateLimited {
                message: text,
                retry_after: None,
            };
        }
        // Somebody changed the RRset between reading and writing it.
        if text.starts_with("HTTP 412") {
            return crate::http::busy(text);
        }
        let (refused, missing): (&[&str], &[&str]) = match self.service {
            Service::Porkbun => (
                &[
                    "API_KEY",
                    "API_ACCESS_DISABLED",
                    "DOMAIN_NOT_ALLOWED",
                    "INSUFFICIENT_SCOPE",
                    "IP_NOT_ALLOWED",
                    "Invalid API key",
                    "not opted in to API access",
                ],
                &["INVALID_DOMAIN", "Invalid domain"],
            ),
            Service::Ionos => (&["UNAUTHORIZED"], &["No IONOS zone found"]),
            Service::Azure => (
                &[
                    "invalid_client",
                    "unauthorized_client",
                    "AADSTS",
                    "AuthorizationFailed",
                ],
                &["InvalidSubscriptionId", "SubscriptionNotFound"],
            ),
            Service::Desec => (&[], &[]),
            Service::AliDns => (
                &[
                    "InvalidAccessKey",
                    "SignatureDoesNotMatch",
                    "IncompleteSignature",
                    "Forbidden",
                    "InvalidSecurityToken",
                ],
                &[
                    "zone not found",
                    "InvalidDomainName.NoExist",
                    "IncorrectDomainUser",
                ],
            ),
            Service::DnsPod => (
                &[
                    "AuthFailure",
                    "UnauthorizedOperation",
                    "NoPermissionToOperateDomain",
                    "NotDomainOwner",
                ],
                &["zone not found", "DomainNotExists"],
            ),
        };
        if text.starts_with("HTTP 403") || has(refused) {
            DnsProviderError::Unauthorized(text)
        } else if has(missing) {
            DnsProviderError::ZoneNotFound(text)
        } else {
            DnsProviderError::Api(text)
        }
    }

    async fn add(
        &self,
        name: &str,
        ty: RecordType,
        ttl: u32,
        value: &str,
    ) -> DnsProviderResult<()> {
        let added = self
            .updater
            .add_to_rrset(
                name,
                record_type(ty),
                ttl,
                vec![record(ty, value)?],
                &self.origin,
            )
            .await;
        match added {
            Err(Error::Api(text))
                if [
                    "DUPLICATE_RECORD",
                    "DomainRecordDuplicate",
                    "DomainRecordExist",
                ]
                .iter()
                .any(|mark| text.contains(mark)) =>
            {
                Ok(())
            }
            other => other.map_err(|error| self.error(error)),
        }
    }
}

fn record_type(ty: RecordType) -> DnsRecordType {
    match ty {
        RecordType::A => DnsRecordType::A,
        RecordType::AAAA => DnsRecordType::AAAA,
        RecordType::CNAME => DnsRecordType::CNAME,
        RecordType::NS => DnsRecordType::NS,
        RecordType::CAA => DnsRecordType::CAA,
        RecordType::TXT | RecordType::SOA => DnsRecordType::TXT,
    }
}

fn record(ty: RecordType, value: &str) -> DnsProviderResult<DnsRecord> {
    let invalid = || DnsProviderError::Api(format!("invalid {ty:?} value: {value}"));
    Ok(match ty {
        RecordType::A => DnsRecord::A(value.parse().map_err(|_| invalid())?),
        RecordType::AAAA => DnsRecord::AAAA(value.parse().map_err(|_| invalid())?),
        RecordType::CNAME => DnsRecord::CNAME(value.to_string()),
        RecordType::NS => DnsRecord::NS(value.to_string()),
        RecordType::TXT => DnsRecord::TXT(value.to_string()),
        RecordType::SOA | RecordType::CAA => return Err(invalid()),
    })
}

fn all(ty: RecordType, values: &[String]) -> DnsProviderResult<Vec<DnsRecord>> {
    values.iter().map(|value| record(ty, value)).collect()
}

#[async_trait::async_trait]
impl Backend for Wrapped {
    fn ttl_range(&self) -> (u32, u32) {
        match self.service {
            Service::Porkbun | Service::AliDns | Service::DnsPod => (600, 86400),
            Service::Desec => (3600, 86400),
            _ => (60, 86400),
        }
    }

    async fn list(&self, name: &str, ty: RecordType) -> DnsProviderResult<Vec<Stored>> {
        let records = self
            .updater
            .list_rrset(name, record_type(ty), &self.origin)
            .await
            .map_err(|error| self.error(error))?;
        Ok(records
            .into_iter()
            .map(|record| Stored {
                value: match record {
                    DnsRecord::TXT(text) => text,
                    other => stored_value(ty, &other.to_string()),
                },
                ..Default::default()
            })
            .collect())
    }

    async fn apply(&self, name: &str, ty: RecordType, change: Change) -> DnsProviderResult<()> {
        let old: Vec<String> = change
            .remove
            .into_iter()
            .map(|record| record.value)
            .collect();
        if change.keep.is_empty() && !old.is_empty() && !change.add.is_empty() {
            let set = |values| {
                self.updater
                    .set_rrset(name, record_type(ty), change.ttl, values, &self.origin)
            };
            let replaced = set(all(ty, &change.add)?).await;
            if replaced.is_err() {
                // It deletes before it adds.
                let _ = set(all(ty, &old)?).await;
            }
            return replaced.map_err(|error| self.error(error));
        }
        for value in &change.add {
            self.add(name, ty, change.ttl, value).await?;
        }
        if old.is_empty() {
            return Ok(());
        }
        self.updater
            .remove_from_rrset(name, record_type(ty), all(ty, &old)?, &self.origin)
            .await
            .map_err(|error| self.error(error))
    }
}
