use http::{Request, Response, Version, StatusCode};
use http_body_util::combinators::BoxBody;
use hyper::body::Bytes;
use crate::{server_err, AcmeCertManagerRef, HttpServer, ProcessChainConfig, Server, ServerConfig, ServerError, ServerErrorCode, ServerFactory, ServerResult, StreamInfo};
use std::sync::Arc;
use http_body_util::{BodyExt, Full};
use serde::{Deserialize, Serialize};

pub struct AcmeHttpChallengeServer {
    id: String,
    acme_mgr: AcmeCertManagerRef,
}

impl AcmeHttpChallengeServer {
    pub fn new(id: String,
               acme_mgr: AcmeCertManagerRef) -> Self {
        AcmeHttpChallengeServer { id, acme_mgr }
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
    async fn serve_request(&self, req: Request<BoxBody<Bytes, ServerError>>, _info: StreamInfo) -> ServerResult<Response<BoxBody<Bytes, ServerError>>> {
        let path = req.uri().path();

        // 提取ACME挑战token
        if let Some(token) = self.extract_token_from_path(path) {
            if let Some(key_auth) = self.acme_mgr.get_auth_of_token(token.as_str()) {
                let response = Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", "application/octet-stream")
                    .body(Full::new(Bytes::from(key_auth.clone()))
                        .map_err(|e| server_err!(ServerErrorCode::InvalidConfig, "{e}"))
                        .boxed())
                    .map_err(|e| server_err!(ServerErrorCode::InvalidConfig, "{e}"))?;
                return Ok(response);
            }
        }

        log::info!("acme challenge {} failed", path);
        // 如果不是有效的ACME挑战请求，返回404
        let response = Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::from("Not Found"))
                .map_err(|e| server_err!(ServerErrorCode::InvalidConfig, "{e}"))
                .boxed())
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

pub struct AcmeHttpChallengeServerFactory {
    acme_mgr: AcmeCertManagerRef,
}

impl AcmeHttpChallengeServerFactory {
    pub fn new(acme_mgr: AcmeCertManagerRef) -> Self {
        AcmeHttpChallengeServerFactory { acme_mgr }
    }
}

#[async_trait::async_trait]
impl ServerFactory for AcmeHttpChallengeServerFactory {
    async fn create(&self, config: Arc<dyn ServerConfig>) -> ServerResult<Vec<Server>> {
        let config = config.as_any().downcast_ref::<AcmeHttpChallengeServerConfig>()
            .ok_or(server_err!(ServerErrorCode::InvalidConfig, "invalid config"))?;
        let server = AcmeHttpChallengeServer::new(config.id.clone(), self.acme_mgr.clone());
        Ok(vec![Server::Http(Arc::new(server))])
    }
}
