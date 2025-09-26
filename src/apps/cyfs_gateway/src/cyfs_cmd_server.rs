use std::sync::Arc;
use bytes::Bytes;
use serde::{Deserialize, Deserializer, Serialize};
use cyfs_gateway_lib::{config_err, service_err, BoxBody, ConfigErrorCode, ConfigResult, InnerHttpService, InnerService, InnerServiceConfig, InnerServiceFactory, Request, Response, ServiceErrorCode, ServiceResult};
use crate::config_loader::InnerServiceConfigParser;

pub const CYFS_CMD_SERVER_CONFIG: &str = include_str!("cyfs_cmd_server.yaml");

#[derive(Serialize, Deserialize, Clone)]
pub struct CyfsCmdServerConfig {
    pub id: String,
    #[serde(rename = "type")]
    pub ty: String,
}

impl InnerServiceConfig for CyfsCmdServerConfig {
    fn service_type(&self) -> String {
        String::from("cmd_server")
    }
}


pub struct CyfsCmdServerFactory {}

impl CyfsCmdServerFactory {
    pub fn new() -> Self {
        CyfsCmdServerFactory {}
    }
}

impl Default for CyfsCmdServerFactory {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl InnerServiceFactory for CyfsCmdServerFactory {
    async fn create(&self, config: Arc<dyn InnerServiceConfig>) -> ServiceResult<InnerService> {
        let config = config.as_any().downcast_ref::<CyfsCmdServerConfig>()
            .ok_or(service_err!(ServiceErrorCode::InvalidConfig, "invalid CyfsCmdServer config {}", config.service_type()))?;
        Ok(InnerService::HttpService(Arc::new(CyfsCmdServer::new(config.clone()))))
    }
}

pub struct CyfsCmdServerConfigParser {

}

impl CyfsCmdServerConfigParser {
    pub fn new() -> Self {
        CyfsCmdServerConfigParser {}
    }
}

impl Default for CyfsCmdServerConfigParser {
    fn default() -> Self {
        Self::new()
    }
}

impl<D: for<'de> Deserializer<'de>> InnerServiceConfigParser<D> for CyfsCmdServerConfigParser {
    fn parse(&self, de: D) -> ConfigResult<Arc<dyn InnerServiceConfig>> {
        let config = CyfsCmdServerConfig::deserialize(de)
            .map_err(|e| config_err!(ConfigErrorCode::InvalidConfig, "invalid CyfsCmdServer config {:?}", e))?;
        Ok(Arc::new(config))
    }
}

pub struct CyfsCmdServer {
    config: CyfsCmdServerConfig
}

impl CyfsCmdServer {
    pub fn new(config: CyfsCmdServerConfig) -> Self {
        CyfsCmdServer {
            config,
        }
    }
}

#[async_trait::async_trait]
impl InnerHttpService for CyfsCmdServer {
    fn id(&self) -> String {
        self.config.id.clone()
    }

    async fn handle(&self, request: Request<BoxBody<Bytes, ()>>) -> Response<BoxBody<Bytes, ()>> {
        todo!()
    }
}
