use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use cyfs_gateway_lib::{NameServer, ProcessChainConfig, Server, ServerConfig, ServerContext, ServerContextRef, ServerFactory};
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
    file_path: String,
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

    fn add_pre_hook_point_process_chain(&self, _process_chain: ProcessChainConfig) -> Arc<dyn ServerConfig> {
        Arc::new(self.clone())
    }

    fn remove_pre_hook_point_process_chain(&self, _process_chain_id: &str) -> Arc<dyn ServerConfig> {
        Arc::new(self.clone())
    }
    
    fn add_post_hook_point_process_chain(&self, _process_chain: ProcessChainConfig) -> Arc<dyn ServerConfig> {
        Arc::new(self.clone())
    }

    fn remove_post_hook_point_process_chain(&self, _process_chain_id: &str) -> Arc<dyn ServerConfig> {
        Arc::new(self.clone())
    }
}

#[derive(Clone)]
pub struct LocalDnsServerContext {
    pub config_path: Option<String>,
}

impl LocalDnsServerContext {
    pub fn new(config_path: Option<String>) -> Self {
        Self { config_path }
    }
}

impl ServerContext for LocalDnsServerContext {
    fn get_server_type(&self) -> String {
        "local_dns".to_string()
    }
}

pub struct LocalDnsFactory;

impl LocalDnsFactory {
    pub fn new() -> Self {
        LocalDnsFactory
    }
}

#[async_trait::async_trait]
impl ServerFactory for LocalDnsFactory {
    async fn create(
        &self,
        config: Arc<dyn ServerConfig>,
        context: Option<ServerContextRef>,
    ) -> ServerResult<Vec<Server>> {
        let config = config.as_any().downcast_ref::<LocalDnsConfig>()
            .ok_or(server_err!(ServerErrorCode::InvalidConfig, "invalid local dns config {}", config.get_config_json()))?;

        let context = context.ok_or(server_err!(
            ServerErrorCode::InvalidConfig,
            "local dns server context is required"
        ))?;
        let context = context
            .as_ref()
            .as_any()
            .downcast_ref::<LocalDnsServerContext>()
            .ok_or(server_err!(
                ServerErrorCode::InvalidConfig,
                "invalid local dns server context"
            ))?;
        
        let path = Path::new(config.file_path.as_str());
        if path.is_absolute() {
            Ok(vec![Server::NameServer(Arc::new(LocalDns::create(config.id.clone(), config.file_path.clone())?))])
        } else {
            let config_path = if let Some(ref config_path) = context.config_path {
                config_path.to_string()
            } else {
                std::env::current_dir()
                    .map_err(into_server_err!(ServerErrorCode::InvalidConfig, "invalid local dns config {}", config.file_path))?
                    .to_string_lossy().to_string()
            };
            let path = Path::new(config_path.as_str()).join(config.file_path.as_str()).canonicalize()
                .map_err(into_server_err!(ServerErrorCode::InvalidConfig, "invalid local dns config {}", config.file_path))?;
            Ok(vec![Server::NameServer(Arc::new(LocalDns::create(config.id.clone(), path.to_string_lossy().to_string())?))])
        }
    }
}
