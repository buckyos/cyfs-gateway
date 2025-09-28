use http_body_util::{BodyExt, Full};
use std::sync::{Arc, Weak};
use bytes::Bytes;
use serde::{Deserialize, Deserializer, Serialize};
use cyfs_gateway_lib::{config_err, into_service_err, service_err, BoxBody, ConfigErrorCode, ConfigResult, InnerHttpService, InnerService, InnerServiceConfig, InnerServiceFactory, Request, Response, ServiceErrorCode, ServiceResult};
use crate::config_loader::InnerServiceConfigParser;
use crate::service_main;

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

    fn get_config_json(&self) -> String {
        serde_json::to_string(self).unwrap()
    }
}


pub struct CyfsCmdServerFactory {
    handler: Weak<dyn CyfsCmdHandler>,
}

impl CyfsCmdServerFactory {
    pub fn new(handler: Arc<dyn CyfsCmdHandler>) -> Self {
        CyfsCmdServerFactory {
            handler: Arc::downgrade(&handler),
        }
    }
}

#[async_trait::async_trait]
impl InnerServiceFactory for CyfsCmdServerFactory {
    async fn create(&self, config: Arc<dyn InnerServiceConfig>) -> ServiceResult<InnerService> {
        let config = config.as_any().downcast_ref::<CyfsCmdServerConfig>()
            .ok_or(service_err!(ServiceErrorCode::InvalidConfig, "invalid CyfsCmdServer config {}", config.service_type()))?;
        Ok(InnerService::HttpService(Arc::new(CyfsCmdServer::new(config.clone(), self.handler.clone()))))
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

#[async_trait::async_trait]
pub trait CyfsCmdHandler: Send + Sync + 'static {
    async fn handle(&self, method: &str, params: &serde_json::Value) -> ServiceResult<serde_json::Value>;
}

pub struct CyfsCmdServer {
    config: CyfsCmdServerConfig,
    handler: Weak<dyn CyfsCmdHandler>,
}

impl CyfsCmdServer {
    pub fn new(config: CyfsCmdServerConfig, handler: Weak<dyn CyfsCmdHandler>) -> Self {
        CyfsCmdServer {
            config,
            handler,
        }
    }
}

#[derive(Deserialize)]
struct CmdReq<P> {
    method: String,
    params: P,
    sys: Vec<serde_json::Value>,
}

#[derive(Serialize)]
struct CmdResp<R: Serialize> {
    sys: Vec<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<R>,
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

            let req: CmdReq<serde_json::Value> = serde_json::from_slice(&data)
                .map_err(|e| service_err!(ServiceErrorCode::Failed, "{}", e))?;
            if let Some(handler) = self.handler.upgrade() {
                let result = handler.handle(req.method.as_str(), &req.params).await?;
                let resp = CmdResp::<serde_json::Value> {
                    sys: vec![],
                    result: Some(result),
                    error: None,
                };
                let data = serde_json::to_vec(&resp)
                    .map_err(|e| service_err!(ServiceErrorCode::Failed, "{}", e))?;
                Ok(Response::new(Full::new(Bytes::from(data)).map_err(|e| ()).boxed()))
            } else {
                Err(service_err!(ServiceErrorCode::Failed, "{}", "cmd handler has released"))
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
