use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use cyfs_gateway_lib::{NameServer, ProcessChainConfig, Server, ServerConfig, ServerFactory};
use name_client::{LocalConfigDnsProvider, NameInfo, NsProvider, RecordType};
use name_lib::{EncodedDocument, DID};
use serde::{Deserialize, Serialize};
use cyfs_gateway_lib::{into_server_err, server_err, ServerErrorCode, ServerResult};

pub struct LocalDns {
    id: String,
    local_provider: LocalConfigDnsProvider,
}

impl LocalDns {
    pub fn create(id: String, local_config: String) -> ServerResult<Self> {
        Ok(LocalDns {
            id,
            local_provider: LocalConfigDnsProvider::new(Path::new(local_config.as_str()))
                .map_err(into_server_err!(ServerErrorCode::InvalidConfig, "{}", local_config))?,
        })
    }
}

#[async_trait::async_trait]
impl NameServer for LocalDns {
    fn id(&self) -> String {
        self.id.clone()
    }

    async fn query(&self, name: &str, record_type: Option<RecordType>, from_ip: Option<IpAddr>) -> ServerResult<NameInfo> {
        self.local_provider.query(name, record_type, from_ip).await
            .map_err(into_server_err!(ServerErrorCode::DnsQueryError))
    }

    async fn query_did(&self, did: &DID, fragment: Option<&str>, from_ip: Option<IpAddr>) -> ServerResult<EncodedDocument> {
        self.local_provider.query_did(did, fragment, from_ip).await
            .map_err(into_server_err!(ServerErrorCode::DnsQueryError))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalDnsConfig {
    id: String,
    #[serde(rename = "type")]
    ty: String,
    path: String,
}

impl ServerConfig for LocalDnsConfig {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn server_type(&self) -> String {
        "local_dns".to_string()
    }

    fn get_config_json(&self) -> String {
        serde_json::to_string(self).unwrap()
    }

    fn add_pre_hook_point_process_chain(&self, process_chain: ProcessChainConfig) -> Arc<dyn ServerConfig> {
        unimplemented!();
    }

    fn remove_pre_hook_point_process_chain(&self, process_chain_id: &str) -> Arc<dyn ServerConfig> {
        unimplemented!();
    }
    
    fn add_post_hook_point_process_chain(&self, process_chain: ProcessChainConfig) -> Arc<dyn ServerConfig> {
        unimplemented!();
    }

    fn remove_post_hook_point_process_chain(&self, process_chain_id: &str) -> Arc<dyn ServerConfig> {
        unimplemented!();
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
impl ServerFactory for LocalDnsFactory {
    async fn create(&self, config: Arc<dyn ServerConfig>) -> ServerResult<Vec<Server>> {
        let config = config.as_any().downcast_ref::<LocalDnsConfig>()
            .ok_or(server_err!(ServerErrorCode::InvalidConfig, "invalid local dns config {}", config.get_config_json()))?;
        
        let path = Path::new(config.path.as_str());
        if path.is_absolute() {
            Ok(vec![Server::NameServer(Arc::new(LocalDns::create(config.id.clone(), config.path.clone())?))])
        } else {
            let path = Path::new(self.config_path.as_str()).join(config.path.as_str()).canonicalize()
                .map_err(into_server_err!(ServerErrorCode::InvalidConfig, "invalid local dns config {}", config.path))?;
            Ok(vec![Server::NameServer(Arc::new(LocalDns::create(config.id.clone(), path.to_string_lossy().to_string())?))])
        }
    }
}
