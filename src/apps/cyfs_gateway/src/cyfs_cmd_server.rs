use http_body_util::{BodyExt, Full};
use std::sync::Arc;
use bytes::Bytes;
use serde::{Deserialize, Deserializer, Serialize};
use cyfs_gateway_lib::{config_err, into_service_err, service_err, BoxBody, ConfigErrorCode, ConfigResult, InnerHttpService, InnerService, InnerServiceConfig, InnerServiceFactory, Request, Response, ServiceErrorCode, ServiceResult};
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

#[derive(Deserialize)]
struct CmdReq {
    method: String,
    params: serde_json::Value,
    sys: Vec<serde_json::Value>,
}

#[derive(Serialize)]
struct CmdResp {
    sys: Vec<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<serde_json::Value>,
}

#[async_trait::async_trait]
impl InnerHttpService for CyfsCmdServer {
    fn id(&self) -> String {
        self.config.id.clone()
    }

    async fn handle(&self, request: Request<BoxBody<Bytes, ()>>) -> Response<BoxBody<Bytes, ()>> {
        if request.method() != http::Method::POST {
            return Response::builder()
                .status(http::StatusCode::FORBIDDEN)
                .body(Full::new(Bytes::new()).map_err(|_| ()).boxed()).unwrap();
        }
        let body = request.into_body();
        let ret: ServiceResult<Response<BoxBody<Bytes, ()>>> = async move {
            let data = body.collect().await
                .map(|chunk| chunk.to_bytes())
                .map_err(|e| service_err!(ServiceErrorCode::Failed, "{:?}", e))?;

            let req: CmdReq = serde_json::from_slice(&data)
                .map_err(|e| service_err!(ServiceErrorCode::Failed, "{}", e))?;
            match req.method.as_str() {
                "test" => {
                    let resp = Response::new(Full::new(Bytes::from("test ok"))
                        .map_err(|_| ()).boxed());
                    Ok(resp)
                }
                v => {
                    let resp = Response::new(Full::new(Bytes::from(format!("unknown cmd {}", v)))
                        .map_err(|_| ()).boxed());
                    Ok(resp)
                }
            }
        }.await;

        ret.unwrap_or_else(|_e| {
            let resp = Response::builder()
                .status(http::StatusCode::INTERNAL_SERVER_ERROR)
                .body(Full::new(Bytes::new())
                    .map_err(|_e| ()).boxed()).unwrap();
            resp
        })
    }
}
