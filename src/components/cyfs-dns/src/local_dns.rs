use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use name_client::{LocalConfigDnsProvider, NameInfo, NsProvider, RecordType};
use name_lib::{EncodedDocument, DID};
use serde::{Deserialize, Serialize};
use cyfs_gateway_lib::{into_service_err, service_err, InnerDnsService, InnerService, InnerServiceConfig, InnerServiceFactory, ServiceErrorCode, ServiceResult};

pub struct LocalDns {
    id: String,
    local_provider: LocalConfigDnsProvider,
}

impl LocalDns {
    pub fn create(id: String, local_config: String) -> ServiceResult<Self> {
        Ok(LocalDns {
            id,
            local_provider: LocalConfigDnsProvider::new(Path::new(local_config.as_str()))
                .map_err(into_service_err!(ServiceErrorCode::InvalidConfig, "{}", local_config))?,
        })
    }
}

#[async_trait::async_trait]
impl InnerDnsService for LocalDns {
    fn id(&self) -> String {
        self.id.clone()
    }

    async fn query(&self, name: &str, record_type: Option<RecordType>, from_ip: Option<IpAddr>) -> ServiceResult<NameInfo> {
        self.local_provider.query(name, record_type, from_ip).await
            .map_err(into_service_err!(ServiceErrorCode::DnsQueryError))
    }

    async fn query_did(&self, did: &DID, fragment: Option<&str>, from_ip: Option<IpAddr>) -> ServiceResult<EncodedDocument> {
        self.local_provider.query_did(did, fragment, from_ip).await
            .map_err(into_service_err!(ServiceErrorCode::DnsQueryError))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalDnsConfig {
    id: String,
    #[serde(rename = "type")]
    ty: String,
    path: String,
}

impl InnerServiceConfig for LocalDnsConfig {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn service_type(&self) -> String {
        "local_dns".to_string()
    }

    fn get_config_json(&self) -> String {
        serde_json::to_string(self).unwrap()
    }
}

pub struct LocalDnsFactory {
    config_path: String,
}

impl LocalDnsFactory {
    pub fn new(config_path: String) -> Self {
        LocalDnsFactory {
            config_path,
        }
    }
}

#[async_trait::async_trait]
impl InnerServiceFactory for LocalDnsFactory {
    async fn create(&self, config: Arc<dyn InnerServiceConfig>) -> ServiceResult<Vec<InnerService>> {
        let config = config.as_any().downcast_ref::<LocalDnsConfig>()
            .ok_or(service_err!(ServiceErrorCode::InvalidConfig, "invalid CyfsCmdServer config {}", config.service_type()))?;
        
        let path = Path::new(config.path.as_str());
        if path.is_absolute() {
            Ok(vec![InnerService::DnsService(Arc::new(LocalDns::create(config.id.clone(), config.path.clone())?))])
        } else {
            let path = Path::new(self.config_path.as_str()).join(config.path.as_str()).canonicalize()
                .map_err(into_service_err!(ServiceErrorCode::InvalidConfig, "invalid local dns config {}", config.path))?;
            Ok(vec![InnerService::DnsService(Arc::new(LocalDns::create(config.id.clone(), path.to_string_lossy().to_string())?))])
        }
    }
}
