use http_body_util::{BodyExt, Full};
use std::sync::{Arc, Weak};
use bytes::Bytes;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use cyfs_gateway_lib::{config_err, service_err, BoxBody, ConfigErrorCode, ConfigResult, InnerHttpService, InnerService, InnerServiceConfig, InnerServiceFactory, Request, Response, ServiceErrorCode, ServiceResult};
use crate::config_loader::InnerServiceConfigParser;
use crate::cyfs_cmd_client::cmd_err;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum CmdErrorCode {
    Failed,
    RpcError,
    InvalidData,
    NoGateway,
    UnknownCmd,
    Expired,
    InvalidUserName,
    InvalidPassword,
    InvalidToken,
    CreateTokenFailed,
    NotSupportLogin,
    ReadFileFailed,
    RunPythonFailed,
    InvalidConfigType,
    ConfigNotFound,
    InvalidParams,
    SerializeFailed,
    InvalidMethod,
}
pub type CmdResult<T> = sfo_result::Result<T, CmdErrorCode>;
pub type CmdError = sfo_result::Error<CmdErrorCode>;

pub const CYFS_CMD_SERVER_CONFIG: &str = include_str!("cyfs_cmd_server.yaml");

#[derive(Serialize, Deserialize, Clone)]
pub struct CyfsCmdServerConfig {
    pub id: String,
    #[serde(rename = "type")]
    pub ty: String,
}

impl InnerServiceConfig for CyfsCmdServerConfig {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn service_type(&self) -> String {
        String::from("cmd_server")
    }

    fn get_config_json(&self) -> String {
        serde_json::to_string(self).unwrap()
    }
}


pub struct CyfsCmdServerFactory {
    handler: Weak<dyn CyfsCmdHandler>,
    token_factory: Arc<dyn CyfsTokenFactory>,
    token_verifier: Arc<dyn CyfsTokenVerifier>,
}

impl CyfsCmdServerFactory {
    pub fn new(handler: Arc<dyn CyfsCmdHandler>,
               token_verifier: Arc<dyn CyfsTokenVerifier>,
               token_factory: Arc<dyn CyfsTokenFactory>, ) -> Self {
        CyfsCmdServerFactory {
            handler: Arc::downgrade(&handler),
            token_factory,
            token_verifier,
        }
    }
}

#[async_trait::async_trait]
impl InnerServiceFactory for CyfsCmdServerFactory {
    async fn create(&self, config: Arc<dyn InnerServiceConfig>) -> ServiceResult<Vec<InnerService>> {
        let config = config.as_any().downcast_ref::<CyfsCmdServerConfig>()
            .ok_or(service_err!(ServiceErrorCode::InvalidConfig, "invalid CyfsCmdServer config {}", config.service_type()))?;
        Ok(vec![InnerService::HttpService(Arc::new(CyfsCmdServer::new(config.clone(),
                                                                 self.handler.clone(),
                                                                 self.token_factory.clone(),
                                                                 self.token_verifier.clone())))])
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
    async fn handle(&self, method: &str, params: Value) -> CmdResult<Value>;
}

#[async_trait::async_trait]
pub trait CyfsTokenFactory: Send + Sync + 'static {
    async fn create(&self, use_name: &str, password: &str, timestamp: u64) -> CmdResult<String>;
}

#[async_trait::async_trait]
pub trait CyfsTokenVerifier: Send + Sync + 'static {
    async fn verify_and_renew(&self, token: &str) -> CmdResult<Option<String>>;
}

pub struct CyfsCmdServer {
    config: CyfsCmdServerConfig,
    handler: Weak<dyn CyfsCmdHandler>,
    token_factory: Arc<dyn CyfsTokenFactory>,
    token_verifier: Arc<dyn CyfsTokenVerifier>,
}

impl CyfsCmdServer {
    pub fn new(config: CyfsCmdServerConfig,
               handler: Weak<dyn CyfsCmdHandler>,
               token_factory: Arc<dyn CyfsTokenFactory>,
               token_verifier: Arc<dyn CyfsTokenVerifier>, ) -> Self {
        CyfsCmdServer {
            config,
            handler,
            token_factory,
            token_verifier,
        }
    }
}

#[derive(Deserialize, Serialize)]
pub struct LoginReq {
    pub user_name: String,
    pub password: String,
    pub timestamp: u64,
}

#[derive(Deserialize)]
struct CmdReq<P> {
    method: String,
    params: P,
    sys: Vec<Value>,
}

#[derive(Serialize)]
struct CmdResp<R: Serialize> {
    sys: Vec<Value>,
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
        let ret: CmdResult<Response<BoxBody<Bytes, ()>>> = async move {
            let data = body.collect().await
                .map(|chunk| chunk.to_bytes())
                .map_err(|e| cmd_err!(CmdErrorCode::Failed, "{:?}", e))?;

            let req: CmdReq<Value> = serde_json::from_slice(&data)
                .map_err(|e| cmd_err!(CmdErrorCode::Failed, "{}", e))?;

            if req.method == "login" {
                if req.sys.len() != 1 {
                    let resp = Response::builder()
                        .status(http::StatusCode::BAD_REQUEST)
                        .body(Full::new(Bytes::from("invalid sys param"))
                            .map_err(|_e| ()).boxed()).unwrap();
                    return Ok(resp)
                }
                let seq = req.sys[0].clone();

                let login_req: LoginReq = match serde_json::from_value(req.params) {
                    Ok(req) => req,
                    Err(_e) => {
                        let resp = Response::builder()
                            .status(http::StatusCode::BAD_REQUEST)
                            .body(Full::new(Bytes::from("invalid login param"))
                                .map_err(|_e| ()).boxed()).unwrap();
                        return Ok(resp)
                    }
                };

                let resp = match self.token_factory.create(
                    login_req.user_name.as_str(),
                    login_req.password.as_str(),
                    login_req.timestamp).await {
                    Ok(token) => {
                        let sys = vec![seq, Value::String(token.clone())];
                        let resp = CmdResp::<Value> {
                            sys,
                            result: Some(Value::String(token)),
                            error: None,
                        };
                        resp
                    }
                    Err(e) => {
                        let resp = CmdResp::<Value> {
                            sys: vec![seq],
                            result: None,
                            error: Some(format!("{:?}", e.code())),
                        };
                        resp
                    }
                };
                let data = serde_json::to_vec(&resp)
                    .map_err(|e| cmd_err!(CmdErrorCode::Failed, "{}", e))?;
                return Ok(Response::new(Full::new(Bytes::from(data)).map_err(|_e| ()).boxed()));
            }

            if req.sys.len() != 2 {
                let resp = Response::builder()
                    .status(http::StatusCode::UNAUTHORIZED)
                    .body(Full::new(Bytes::new())
                        .map_err(|_e| ()).boxed()).unwrap();
                return Ok(resp)
            }
            let seq = req.sys[0].clone();
            let token = req.sys[1].clone();
            let new_token = match self.token_verifier.verify_and_renew(token.as_str().unwrap_or("")).await {
                Ok(token) => {
                    token
                },
                Err(e) => {
                    let resp = Response::builder()
                        .status(http::StatusCode::UNAUTHORIZED)
                        .body(Full::new(Bytes::from(e.msg().to_string()))
                            .map_err(|_e| ()).boxed()).unwrap();
                    return Ok(resp);
                }
            };

            if let Some(handler) = self.handler.upgrade() {
                let result = handler.handle(req.method.as_str(), req.params).await?;
                let sys = if new_token.is_some() {
                    vec![seq, Value::String(new_token.unwrap())]
                } else {
                    vec![seq]
                };
                let resp = CmdResp::<Value> {
                    sys,
                    result: Some(result),
                    error: None,
                };
                let data = serde_json::to_vec(&resp)
                    .map_err(|e| cmd_err!(CmdErrorCode::Failed, "{}", e))?;
                Ok(Response::new(Full::new(Bytes::from(data)).map_err(|_e| ()).boxed()))
            } else {
                Err(cmd_err!(CmdErrorCode::Failed, "{}", "cmd handler has released"))
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
