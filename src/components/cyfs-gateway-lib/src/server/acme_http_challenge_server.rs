use crate::{
    CertManagerRef, HttpServer, Server, ServerConfig, ServerContext, ServerContextRef, ServerError,
    ServerErrorCode, ServerFactory, ServerResult, StreamInfo, server_err,
};
use http::{Request, Response, StatusCode, Version};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub struct AcmeHttpChallengeServer {
    id: String,
    cert_manager: CertManagerRef,
}

impl AcmeHttpChallengeServer {
    pub fn new(id: String, cert_manager: CertManagerRef) -> Self {
        AcmeHttpChallengeServer { id, cert_manager }
    }

    fn extract_token_from_path(&self, path: &str) -> Option<String> {
        let prefix = "/.well-known/acme-challenge/";
        if path.starts_with(prefix) {
            let token = &path[prefix.len()..];
            if !token.is_empty() {
                return Some(token.to_string());
            }
        }
        None
    }
}

#[async_trait::async_trait]
impl HttpServer for AcmeHttpChallengeServer {
    async fn serve_request(
        &self,
        req: Request<BoxBody<Bytes, ServerError>>,
        _info: StreamInfo,
    ) -> ServerResult<Response<BoxBody<Bytes, ServerError>>> {
        let path = req.uri().path();

        // 提取ACME挑战token
        if let Some(token) = self.extract_token_from_path(path) {
            if let Some(key_auth) = self.cert_manager.get_http01_auth(token.as_str()) {
                let response = Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", "application/octet-stream")
                    .body(
                        Full::new(Bytes::from(key_auth.clone()))
                            .map_err(|e| server_err!(ServerErrorCode::InvalidConfig, "{e}"))
                            .boxed(),
                    )
                    .map_err(|e| server_err!(ServerErrorCode::InvalidConfig, "{e}"))?;
                return Ok(response);
            }
        }

        log::info!("acme challenge {} failed", path);
        // 如果不是有效的ACME挑战请求，返回404
        let response = Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(
                Full::new(Bytes::from("Not Found"))
                    .map_err(|e| server_err!(ServerErrorCode::InvalidConfig, "{e}"))
                    .boxed(),
            )
            .map_err(|e| server_err!(ServerErrorCode::InvalidConfig, "{e}"))?;
        Ok(response)
    }

    fn id(&self) -> String {
        self.id.clone()
    }

    fn http_version(&self) -> Version {
        Version::HTTP_11
    }

    fn http3_port(&self) -> Option<u16> {
        None
    }
}

#[derive(Deserialize, Serialize, Clone)]
pub struct AcmeHttpChallengeServerConfig {
    id: String,
    #[serde(rename = "type")]
    pub ty: String,
}

impl ServerConfig for AcmeHttpChallengeServerConfig {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn server_type(&self) -> String {
        "acme_response".to_string()
    }

    fn get_config_json(&self) -> String {
        serde_json::to_string(self).unwrap()
    }
}

#[derive(Clone)]
pub struct AcmeHttpChallengeServerContext {
    pub cert_manager: CertManagerRef,
}

impl AcmeHttpChallengeServerContext {
    pub fn new(cert_manager: CertManagerRef) -> Self {
        Self { cert_manager }
    }
}

impl ServerContext for AcmeHttpChallengeServerContext {
    fn get_server_type(&self) -> String {
        "acme_response".to_string()
    }
}

pub struct AcmeHttpChallengeServerFactory;

impl AcmeHttpChallengeServerFactory {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl ServerFactory for AcmeHttpChallengeServerFactory {
    async fn create(
        &self,
        config: Arc<dyn ServerConfig>,
        context: Option<ServerContextRef>,
    ) -> ServerResult<Vec<Server>> {
        let config = config
            .as_any()
            .downcast_ref::<AcmeHttpChallengeServerConfig>()
            .ok_or(server_err!(
                ServerErrorCode::InvalidConfig,
                "invalid acme http challenge server config"
            ))?;
        let context = context.ok_or(server_err!(
            ServerErrorCode::InvalidConfig,
            "acme response server context is required"
        ))?;
        let context = context
            .as_ref()
            .as_any()
            .downcast_ref::<AcmeHttpChallengeServerContext>()
            .ok_or(server_err!(
                ServerErrorCode::InvalidConfig,
                "invalid acme response server context"
            ))?;
        let server = AcmeHttpChallengeServer::new(config.id.clone(), context.cert_manager.clone());
        Ok(vec![Server::Http(Arc::new(server))])
    }
}
