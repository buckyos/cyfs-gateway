use log::*;
use http_body_util::{BodyExt, Full};
use http_body_util::combinators::BoxBody;
use std::sync::{Arc, Weak};
use bytes::Bytes;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use cyfs_gateway_lib::{ConfigErrorCode, ConfigResult, ProcessChainConfig, Server, ServerConfig, StreamInfo, config_err, ServerError};
use cyfs_gateway_lib::{ServerFactory, HttpServer};
use crate::config_loader::{ServerConfigParser};
use crate::gateway_control_client::cmd_err;
use cyfs_gateway_lib::{server_err, ServerErrorCode, ServerResult};

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ControlErrorCode {
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
    RunJsFailed,
    InvalidConfigType,
    ConfigNotFound,
    InvalidParams,
    SerializeFailed,
    InvalidMethod,
}
pub type ControlResult<T> = sfo_result::Result<T, ControlErrorCode>;
pub type ControlError = sfo_result::Error<ControlErrorCode>;

pub const GATEWAY_CONTROL_SERVER_CONFIG: &str = include_str!("gateway_control_server.yaml");
pub const GATEWAY_CONTROL_SERVER_KEY: &str = "__control_server__";

#[derive(Serialize, Deserialize, Clone)]
pub struct GatewayControlServerConfig {
    pub id: String,
    #[serde(rename = "type")]
    pub ty: String,
}

impl ServerConfig for GatewayControlServerConfig {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn server_type(&self) -> String {
        String::from("control_server")
    }

    fn get_config_json(&self) -> String {
        serde_json::to_string(self).unwrap()
    }

    fn add_pre_hook_point_process_chain(&self, _process_chain: ProcessChainConfig) -> Arc<dyn ServerConfig> {
        unimplemented!();
    }

    fn remove_pre_hook_point_process_chain(&self, _process_chain_id: &str) -> Arc<dyn ServerConfig> {
        unimplemented!();
    }

    fn add_post_hook_point_process_chain(&self, _process_chain: ProcessChainConfig) -> Arc<dyn ServerConfig> {
        unimplemented!();
    }

    fn remove_post_hook_point_process_chain(&self, _process_chain_id: &str) -> Arc<dyn ServerConfig> {
        unimplemented!();
    }
}


pub struct GatewayControlServerFactory {
    handler: Weak<dyn GatewayControlCmdHandler>,
    token_factory: Arc<dyn CyfsTokenFactory>,
    token_verifier: Arc<dyn CyfsTokenVerifier>,
}

impl GatewayControlServerFactory {
    pub fn new(handler: Arc<dyn GatewayControlCmdHandler>,
               token_verifier: Arc<dyn CyfsTokenVerifier>,
               token_factory: Arc<dyn CyfsTokenFactory>, ) -> Self {
        GatewayControlServerFactory {
            handler: Arc::downgrade(&handler),
            token_factory,
            token_verifier,
        }
    }
}

#[async_trait::async_trait]
impl ServerFactory for GatewayControlServerFactory {
    async fn create(&self, config: Arc<dyn ServerConfig>) -> ServerResult<Vec<Server>> {
        let config = config.as_any().downcast_ref::<GatewayControlServerConfig>()
            .ok_or(server_err!(ServerErrorCode::InvalidConfig, "invalid CyfsCmdServer config {}", config.server_type()))?;
        Ok(vec![Server::Http(Arc::new(GatewayControlServer::new(config.clone(),
                                                           self.handler.clone(),
                                                           self.token_factory.clone(),
                                                                self.token_verifier.clone())))])
    }
}

pub struct GatewayControlServerConfigParser {

}

impl GatewayControlServerConfigParser {
    pub fn new() -> Self {
        GatewayControlServerConfigParser {}
    }
}

impl Default for GatewayControlServerConfigParser {
    fn default() -> Self {
        Self::new()
    }
}

impl<D: for<'de> Deserializer<'de>> ServerConfigParser<D> for GatewayControlServerConfigParser {
    fn parse(&self, de: D) -> ConfigResult<Arc<dyn ServerConfig>> {
        let config = GatewayControlServerConfig::deserialize(de)
            .map_err(|e| config_err!(ConfigErrorCode::InvalidConfig, "invalid CyfsCmdServer config {:?}", e))?;
        Ok(Arc::new(config))
    }
}

#[async_trait::async_trait]
pub trait GatewayControlCmdHandler: Send + Sync + 'static {
    async fn handle(&self, method: &str, params: Value) -> ControlResult<Value>;
}

#[async_trait::async_trait]
pub trait CyfsTokenFactory: Send + Sync + 'static {
    async fn create(&self, use_name: &str, password: &str, timestamp: u64) -> ControlResult<String>;
}

#[async_trait::async_trait]
pub trait CyfsTokenVerifier: Send + Sync + 'static {
    async fn verify_and_renew(&self, token: &str) -> ControlResult<Option<String>>;
}

pub struct GatewayControlServer {
    config: GatewayControlServerConfig,
    handler: Weak<dyn GatewayControlCmdHandler>,
    token_factory: Arc<dyn CyfsTokenFactory>,
    token_verifier: Arc<dyn CyfsTokenVerifier>,
}

impl GatewayControlServer {
    pub fn new(config: GatewayControlServerConfig,
               handler: Weak<dyn GatewayControlCmdHandler>,
               token_factory: Arc<dyn CyfsTokenFactory>,
               token_verifier: Arc<dyn CyfsTokenVerifier>, ) -> Self {
        GatewayControlServer {
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
impl HttpServer for GatewayControlServer {
    fn id(&self) -> String {
        self.config.id.clone()
    }

    fn http_version(&self) -> http::Version {
        http::Version::HTTP_11
    }

    fn http3_port(&self) -> Option<u16> {
        None
    }

    async fn serve_request(&self, request: http::Request<BoxBody<Bytes, ServerError>>, _info: StreamInfo) -> ServerResult<http::Response<BoxBody<Bytes, ServerError>>> {
        if request.method() != http::Method::POST {
            return Ok(http::Response::builder()
                .status(http::StatusCode::FORBIDDEN)
                .body(Full::new(Bytes::new()).map_err(|e| ServerError::new(ServerErrorCode::BadRequest, format!("{:?}", e))).boxed()).unwrap());
        }
        let body = request.into_body();
        let ret: ControlResult<http::Response<BoxBody<Bytes, ServerError>>> = async move {
            let data = body.collect().await
                .map(|chunk| chunk.to_bytes())
                .map_err(|e| cmd_err!(ControlErrorCode::Failed, "{:?}", e))?;

            let req: CmdReq<Value> = serde_json::from_slice(&data)
                .map_err(|e| cmd_err!(ControlErrorCode::Failed, "{}", e))?;

            if req.method == "login" {
                if req.sys.len() != 1 {
                    let resp = http::Response::builder()
                        .status(http::StatusCode::BAD_REQUEST)
                        .body(Full::new(Bytes::from("invalid sys param"))
                            .map_err(|e| ServerError::new(ServerErrorCode::BadRequest, format!("{:?}", e))).boxed()).unwrap();
                    return Ok(resp)
                }
                let seq = req.sys[0].clone();

                let login_req: LoginReq = match serde_json::from_value(req.params) {
                    Ok(req) => req,
                    Err(_e) => {
                        let resp = http::Response::builder()
                            .status(http::StatusCode::BAD_REQUEST)
                            .body(Full::new(Bytes::from("invalid login param"))
                                .map_err(|e| ServerError::new(ServerErrorCode::BadRequest, format!("{:?}", e))).boxed()).unwrap();
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
                    .map_err(|e| cmd_err!(ControlErrorCode::Failed, "{}", e))?;
                return Ok(http::Response::new(Full::new(Bytes::from(data)).map_err(|e| ServerError::new(ServerErrorCode::EncodeError, format!("{:?}", e))).boxed()));
            }

            if req.sys.len() != 2 {
                let resp = http::Response::builder()
                    .status(http::StatusCode::UNAUTHORIZED)
                    .body(Full::new(Bytes::new())
                        .map_err(|e| ServerError::new(ServerErrorCode::BadRequest, format!("{:?}", e))).boxed()).unwrap();
                return Ok(resp)
            }
            let seq = req.sys[0].clone();
            let token = req.sys[1].clone();
            let new_token = match self.token_verifier.verify_and_renew(token.as_str().unwrap_or("")).await {
                Ok(token) => {
                    token
                },
                Err(e) => {
                    let resp = http::Response::builder()
                        .status(http::StatusCode::UNAUTHORIZED)
                        .body(Full::new(Bytes::from(e.msg().to_string()))
                            .map_err(|e| ServerError::new(ServerErrorCode::BadRequest, format!("{:?}", e))).boxed()).unwrap();
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
                    .map_err(|e| cmd_err!(ControlErrorCode::Failed, "{}", e))?;
                Ok(http::Response::new(Full::new(Bytes::from(data)).map_err(|e| ServerError::new(ServerErrorCode::EncodeError, format!("{:?}", e))).boxed()))
            } else {
                Err(cmd_err!(ControlErrorCode::Failed, "{}", "cmd handler has released"))
            }
        }.await;

        Ok(ret.unwrap_or_else(|_e| {
            http::Response::builder()
                .status(http::StatusCode::INTERNAL_SERVER_ERROR)
                .body(Full::new(Bytes::new())
                    .map_err(|e| ServerError::new(ServerErrorCode::IOError, format!("{:?}", e))).boxed()).unwrap()
        }))
    }
}
