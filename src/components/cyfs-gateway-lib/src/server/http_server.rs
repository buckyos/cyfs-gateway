use std::sync::{Arc, Mutex};
use http::{Version};
use http_body_util::combinators::{BoxBody};
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes};
use hyper::{http, StatusCode, Request};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use serde::{Deserialize, Serialize};
use cyfs_process_chain::{CommandControl, ProcessChainLibExecutor};
use crate::{get_server_external_commands, GlobalCollectionManagerRef, HttpRequestHeaderMap, HttpServer, ProcessChainConfig, ProcessChainConfigs, Server, ServerConfig, ServerError, ServerErrorCode, ServerFactory, ServerManagerRef, ServerResult, StreamInfo, TunnelManager};
use crate::global_process_chains::{create_process_chain_executor, GlobalProcessChainsRef};
use super::{server_err,into_server_err};
use crate::tunnel_connector::TunnelConnector;
use url::Url;

pub struct ProcessChainHttpServerBuilder {
    id: Option<String>,
    version: Option<String>,
    h3_port: Option<u16>,
    hook_point: Option<ProcessChainConfigs>,
    global_process_chains: Option<GlobalProcessChainsRef>,
    server_mgr: Option<ServerManagerRef>,
    tunnel_manager: Option<TunnelManager>,
    global_collection_manager: Option<GlobalCollectionManagerRef>,
}

// Add setter methods for HttpServerBuilder
impl ProcessChainHttpServerBuilder {
    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    pub fn version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }

    pub fn hook_point(mut self, hook_point: ProcessChainConfigs) -> Self {
        self.hook_point = Some(hook_point);
        self
    }

    pub fn global_process_chains(mut self, global_process_chains: GlobalProcessChainsRef) -> Self {
        self.global_process_chains = Some(global_process_chains);
        self
    }

    pub fn server_mgr(mut self, server_mgr: ServerManagerRef) -> Self {
        self.server_mgr = Some(server_mgr);
        self
    }

    pub fn h3_port(mut self, h3_port: u16) -> Self {
        self.h3_port = Some(h3_port);
        self
    }

    pub fn tunnel_manager(mut self, tunnel_manager: TunnelManager) -> Self {
        self.tunnel_manager = Some(tunnel_manager);
        self
    }

    pub fn global_collection_manager(mut self, global_collection_manager: GlobalCollectionManagerRef) -> Self {
        self.global_collection_manager = Some(global_collection_manager);
        self
    }

    pub async fn build(self) -> ServerResult<ProcessChainHttpServer> {
        ProcessChainHttpServer::create_server(self).await
    }
}

pub struct ProcessChainHttpServer {
    id: String,
    version: http::Version,
    h3_port: Option<u16>,
    server_mgr: ServerManagerRef,
    executor: Arc<Mutex<ProcessChainLibExecutor>>,
    tunnel_manager: TunnelManager,
}

impl ProcessChainHttpServer {
    pub fn builder() -> ProcessChainHttpServerBuilder {
        ProcessChainHttpServerBuilder {
            id: None,
            version: None,
            h3_port: None,
            hook_point: None,
            global_process_chains: None,
            server_mgr: None,
            tunnel_manager: None,
            global_collection_manager: None,
        }
    }

    async fn create_server(builder: ProcessChainHttpServerBuilder) -> ServerResult<ProcessChainHttpServer> {
        if builder.id.is_none() {
            return Err(server_err!(ServerErrorCode::InvalidConfig, "id is none"));
        }

        if builder.hook_point.is_none() {
            return Err(server_err!(ServerErrorCode::InvalidConfig, "hook_point is none"));
        }

        if builder.server_mgr.is_none() {
            return Err(server_err!(ServerErrorCode::InvalidConfig, "server_mgr is none"));
        }

        if builder.tunnel_manager.is_none() {
            return Err(server_err!(ServerErrorCode::InvalidConfig, "tunnel_manager is none"));
        }

        let version: http::Version = match builder.version {
            Some(ref version) => {
                match version.as_str() {
                    "HTTP/0.9" => http::Version::HTTP_09,
                    "HTTP/1.0" => http::Version::HTTP_10,
                    "HTTP/1.1" => http::Version::HTTP_11,
                    "HTTP/2" => http::Version::HTTP_2,
                    "HTTP/3" => http::Version::HTTP_3,
                    _ => return Err(server_err!(ServerErrorCode::InvalidConfig, "invalid http version")),
                }
            },
            None => http::Version::HTTP_11,
        };

        let (executor, _) = create_process_chain_executor(builder.hook_point.as_ref().unwrap(),
                                                          builder.global_process_chains,
                                                          builder.global_collection_manager,
                                                          Some(get_server_external_commands(builder.server_mgr.clone().unwrap()))).await
            .map_err(into_server_err!(ServerErrorCode::ProcessChainError))?;
        Ok(ProcessChainHttpServer {
            id: builder.id.unwrap(),
            version,
            h3_port: builder.h3_port,
            server_mgr: builder.server_mgr.unwrap(),
            executor: Arc::new(Mutex::new(executor)),
            tunnel_manager: builder.tunnel_manager.unwrap(),
        })
    }

    async fn handle_forward_upstream(&self, req: http::Request<BoxBody<Bytes, ServerError>>, target_url: &str) -> ServerResult<http::Response<BoxBody<Bytes, ServerError>>> {
        let org_url = req.uri().to_string();
        // Trim URL boundary slashes so we don't end up with "//" when target_url ends with '/'
        // and org_url starts with '/'.
        let base = target_url.trim_end_matches('/');
        let path = org_url.trim_start_matches('/');
        let url = format!("{}/{}", base, path);
        info!("handle_upstream url: {}", url);
        let upstream_url = Url::parse(target_url);
        if upstream_url.is_err() {
            return Err(server_err!(ServerErrorCode::InvalidConfig, "Failed to parse upstream url: {}", target_url));
        }
        //TODO:support url rewrite
        let upstream_url = upstream_url.unwrap();
        let scheme = upstream_url.scheme();
        match scheme {
            "http" | "https" => {
                let client: Client<_, BoxBody<Bytes, Box<dyn std::error::Error + Send + Sync>>> = Client::builder(TokioExecutor::new()).build_http();
                let header = req.headers().clone();
                let method = req.method().clone();
                let body = req.into_body().map_err(|e| {
                    Box::new(e) as Box<dyn std::error::Error + Send + Sync>
                }).boxed();
                let mut upstream_req = Request::builder()
                .method(method)
                .uri(&url)
                .body(body).map_err(|e| {
                    server_err!(ServerErrorCode::InvalidConfig, "Failed to build request: {}", e)
                })?;

                *upstream_req.headers_mut() = header;

                let resp = client.request(upstream_req).await.map_err(|e| {
                    server_err!(ServerErrorCode::InvalidConfig, "Failed to request upstream: {}", e)
                })?;
                let resp = resp.map(|body| body.map_err(|e| ServerError::new(ServerErrorCode::StreamError, format!("{:?}", e))).boxed());
                return Ok(resp)
            },
            _ => {
                let tunnel_connector = TunnelConnector {
                    target_stream_url: target_url.to_string(),
                    tunnel_manager: self.tunnel_manager.clone(),
                };


                let client: Client<TunnelConnector, BoxBody<Bytes, Box<dyn std::error::Error + Send + Sync>>> = Client::builder(TokioExecutor::new())
                    .build(tunnel_connector);

                let header = req.headers().clone();
                let mut host_name = "localhost".to_string();
                let hname =  req.headers().get("host");
                if hname.is_some() {
                    host_name = hname.unwrap().to_str().unwrap().to_string();
                }
                let fake_url = format!("http://{}{}", host_name, org_url);
                let method = req.method().clone();
                let body = req.into_body().map_err(|e| {
                    Box::new(e) as Box<dyn std::error::Error + Send + Sync>
                }).boxed();
                let mut upstream_req = Request::builder()
                    .method(method)
                    .uri(fake_url)
                    .body(body).map_err(|e| {
                        server_err!(ServerErrorCode::BadRequest, "Failed to build upstream_req: {}", e)
                    })?;

                *upstream_req.headers_mut() = header;
                let resp = client.request(upstream_req).await.map_err(|e| {
                    server_err!(ServerErrorCode::TunnelError, "Failed to request upstream: {}", e)
                })?;
                let resp = resp.map(|body| body.map_err(|e| ServerError::new(ServerErrorCode::StreamError, format!("{:?}", e))).boxed());
                return Ok(resp)
            }
        }
    }
}

#[async_trait::async_trait]
impl HttpServer for ProcessChainHttpServer {
    async fn serve_request(&self, req: http::Request<BoxBody<Bytes, ServerError>>, info: StreamInfo) -> ServerResult<http::Response<BoxBody<Bytes, ServerError>>> {
        let executor = {
            self.executor.lock().unwrap().fork()
        };

        let req_map = HttpRequestHeaderMap::new(req);
        let global_env = executor.global_env();
        req_map.register_visitors(&global_env).await.map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{}", e))?;

        let ret = executor.execute_lib().await.map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{}", e))?;
        if ret.is_control() {
            if ret.is_drop() {
                debug!("Request dropped by the process chain");
                return Ok(http::Response::new(Full::new(Bytes::from("Request dropped")).map_err(|e| match e {}).boxed()));
            } else if ret.is_reject() {
                debug!("Request rejected by the process chain");
                let mut response = http::Response::new(Full::new(Bytes::new()).map_err(|e| match e {}).boxed());
                *response.status_mut() = StatusCode::FORBIDDEN;
                return Ok(response);
            }
            if let Some(CommandControl::Return(ret)) = ret.as_control() {
                if let Some(list) = shlex::split(ret.value.as_str()) {
                    if list.is_empty() {
                        log::error!("process chain return is empty");
                        let mut response = http::Response::new(Full::new(Bytes::new()).map_err(|e| match e {}).boxed());
                        *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                        return Ok(response);
                    }

                    let cmd = list[0].as_str();
                    match cmd {
                        "server" => {
                            if list.len() < 2 {
                                return Err(server_err!(
                                    ServerErrorCode::InvalidConfig,
                                    "invalid server command"
                                ));
                            }

                            let server_id = list[1].as_str();
                            let post_req= req_map.into_request()
                                .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{}", e))?;

                            if let Some(service) = self.server_mgr.get_http_server(server_id) {
                                let resp = service.serve_request(post_req, info).await;
                                return resp;
                            }
                        },
                        "forward" => {
                            if list.len() < 2 {
                                return Err(server_err!(
                                    ServerErrorCode::InvalidConfig,
                                    "invalid forward command"
                                ));
                            }
                            let target_url = list[1].as_str();
                            let post_req= req_map.into_request()
                                .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{}", e))?;
                            let resp = self.handle_forward_upstream(post_req, target_url).await;
                            return resp;
                        },
                        _ => {
                            log::error!("unknown command: {}", cmd);
                        }
                    }
                }
            }
        }
        let mut response = http::Response::new(Full::new(Bytes::new()).map_err(|e| match e {}).boxed());
        *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
        Ok(response)
    }

    fn id(&self) -> String {
        self.id.clone()
    }

    fn http_version(&self) -> Version {
        self.version
    }

    fn http3_port(&self) -> Option<u16> {
        self.h3_port
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ProcessChainHttpServerConfig {
    pub id: String,
    #[serde(rename = "type")]
    pub ty: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub h3_port: Option<u16>,
    pub hook_point: ProcessChainConfigs,
}

impl ServerConfig for ProcessChainHttpServerConfig {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn server_type(&self) -> String {
        "http".to_string()
    }

    fn get_config_json(&self) -> String {
        serde_json::to_string(self).unwrap()
    }

    fn add_pre_hook_point_process_chain(&self, process_chain: ProcessChainConfig) -> Arc<dyn ServerConfig> {
        let mut config = self.clone();
        config.hook_point.push(process_chain);
        Arc::new(config)
    }

    fn remove_pre_hook_point_process_chain(&self, process_chain_id: &str) -> Arc<dyn ServerConfig> {
        let mut config = self.clone();
        config.hook_point.retain(|chain| chain.id != process_chain_id);
        Arc::new(config)
    }

    fn add_post_hook_point_process_chain(&self, _process_chain: ProcessChainConfig) -> Arc<dyn ServerConfig> {
        let config = self.clone();
        Arc::new(config)
    }

    fn remove_post_hook_point_process_chain(&self, _process_chain_id: &str) -> Arc<dyn ServerConfig> {
        let config = self.clone();
        Arc::new(config)
    }
}

pub struct ProcessChainHttpServerFactory {
    server_mgr: ServerManagerRef,
    global_process_chains: GlobalProcessChainsRef,
    tunnel_mgr: TunnelManager,
    global_collection_manager: GlobalCollectionManagerRef,
}

impl ProcessChainHttpServerFactory {
    pub fn new(server_mgr: ServerManagerRef,
               global_process_chains: GlobalProcessChainsRef,
               tunnel_mgr: TunnelManager,
               global_collection_manager: GlobalCollectionManagerRef, ) -> Self {
        Self {
            server_mgr,
            global_process_chains,
            tunnel_mgr,
            global_collection_manager,
        }
    }
}

#[async_trait::async_trait]
impl ServerFactory for ProcessChainHttpServerFactory {
    async fn create(&self, config: Arc<dyn ServerConfig>) -> ServerResult<Vec<Server>> {
        let config = config.as_any().downcast_ref::<ProcessChainHttpServerConfig>()
            .ok_or(server_err!(ServerErrorCode::InvalidConfig, "invalid process chain http server config"))?;

        let mut builder = ProcessChainHttpServer::builder()
            .hook_point(config.hook_point.clone())
            .id(config.id.clone())
            .server_mgr(self.server_mgr.clone())
            .tunnel_manager(self.tunnel_mgr.clone())
            .global_process_chains(self.global_process_chains.clone())
            .global_collection_manager(self.global_collection_manager.clone());
        if config.h3_port.is_some() {
            builder = builder.h3_port(config.h3_port.clone().unwrap());
        }
        if config.version.is_some() {
            builder = builder.version(config.version.clone().unwrap());
        }
        let server = builder.build().await?;
        Ok(vec![Server::Http(Arc::new(server))])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use buckyos_kit::init_logging;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use crate::{GlobalProcessChains, ServerManager, StreamInfo, hyper_serve_http, hyper_serve_http1, GlobalCollectionManager};

    #[tokio::test]
    async fn test_http_server_builder_creation() {
        let builder = ProcessChainHttpServer::builder();
        assert!(builder.version.is_none());
        assert!(builder.hook_point.is_none());
        assert!(builder.global_process_chains.is_none());
        assert!(builder.server_mgr.is_none());
    }

    #[tokio::test]
    async fn test_create_server_without_hook_point() {
        let mock_server_mgr = Arc::new(ServerManager::new());

        let result = ProcessChainHttpServer::builder()
            .server_mgr(mock_server_mgr).build().await;
        if let Err(e) = result {
            assert_eq!(e.code(), ServerErrorCode::InvalidConfig);
        }
    }

    #[tokio::test]
    async fn test_create_server_without_inner_services() {
        let builder = ProcessChainHttpServer::builder()
            .hook_point(vec![]);
        let result = ProcessChainHttpServer::create_server(builder).await;
        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(e.code(), ServerErrorCode::InvalidConfig);
        }
    }

    #[tokio::test]
    async fn test_create_server_with_invalid_version() {
        let mock_server_mgr = Arc::new(ServerManager::new());

        let result = ProcessChainHttpServer::builder()
            .version("HTTP/1.2".to_string())
            .hook_point(vec![])
            .server_mgr(mock_server_mgr).build().await;

        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(e.code(), ServerErrorCode::InvalidConfig);
        }
    }

    #[tokio::test]
    async fn test_create_server_with_http11_version() {
        let mock_server_mgr = Arc::new(ServerManager::new());

        let result = ProcessChainHttpServer::builder()
            .id("1")
            .version("HTTP/1.1".to_string())
            .hook_point(vec![])
            .tunnel_manager(TunnelManager::new())
            .server_mgr(mock_server_mgr).build().await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_create_server_with_http2_version() {
        let mock_server_mgr = Arc::new(ServerManager::new());

        let result = ProcessChainHttpServer::builder()
            .id("1")
            .version("HTTP/2".to_string())
            .hook_point(vec![])
            .tunnel_manager(TunnelManager::new())
            .server_mgr(mock_server_mgr).build().await;
        assert!(result.is_ok());
    }


    #[tokio::test]
    async fn test_handle_http1_request_http1_server() {
        let mock_server_mgr = Arc::new(ServerManager::new());
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        reject;
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let result = ProcessChainHttpServer::builder()
            .id("1")
            .version("HTTP/1.1".to_string())
            .hook_point(chains)
            .tunnel_manager(TunnelManager::new())
            .server_mgr(mock_server_mgr).build().await;

        assert!(result.is_ok());
        let http_server = Arc::new(result.unwrap());

        let (client, server) = tokio::io::duplex(128);

        tokio::spawn(async move {
            hyper_serve_http1(Box::new(server), http_server, StreamInfo::default()).await.unwrap();
        });

        let request = http::Request::builder()
            .method("GET")
            .uri("http://localhost/")
            .body(Full::new(Bytes::new()))
            .unwrap();

        let (mut sender, conn) = hyper::client::conn::http1::Builder::new().handshake(TokioIo::new(client)).await.unwrap();
        tokio::spawn(async move {
            conn.await.unwrap();
        });
        let resp = sender.send_request(request).await.unwrap();
        assert_eq!(resp.version(), Version::HTTP_11);
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_handle_http1_request_http2_server() {
        let mock_server_mgr = Arc::new(ServerManager::new());
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        reject;
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let result = ProcessChainHttpServer::builder()
            .id("1")
            .version("HTTP/2".to_string())
            .hook_point(chains)
            .tunnel_manager(TunnelManager::new())
            .server_mgr(mock_server_mgr).build().await;

        assert!(result.is_ok());
        let http_server = Arc::new(result.unwrap());

        let (client, server) = tokio::io::duplex(128);

        tokio::spawn(async move {
            hyper_serve_http(Box::new(server), http_server, StreamInfo::default()).await.unwrap();
        });

        let request = http::Request::builder()
            .method("GET")
            .uri("http://localhost/")
            .body(Full::new(Bytes::new()))
            .unwrap();

        let (mut sender, conn) = hyper::client::conn::http1::Builder::new().handshake(TokioIo::new(client)).await.unwrap();
        tokio::spawn(async move {
            conn.await.unwrap();
        });
        let resp = sender.send_request(request).await.unwrap();
        assert_eq!(resp.version(), Version::HTTP_11);
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_handle_http2_request_http2_server() {
        let mock_server_mgr = Arc::new(ServerManager::new());
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        reject;
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let result = ProcessChainHttpServer::builder()
            .id("1")
            .version("HTTP/2".to_string())
            .hook_point(chains)
            .tunnel_manager(TunnelManager::new())
            .server_mgr(mock_server_mgr).build().await;

        assert!(result.is_ok());
        let http_server = Arc::new(result.unwrap());

        let (client, server) = tokio::io::duplex(128);

        tokio::spawn(async move {
            hyper_serve_http(Box::new(server), http_server, StreamInfo::default()).await.unwrap();
        });

        let request = http::Request::builder()
            .version(http::Version::HTTP_2)
            .method("GET")
            .uri("http://localhost/")
            .body(Full::new(Bytes::new()))
            .unwrap();

        let (mut sender, conn) = hyper::client::conn::http2::Builder::new(TokioExecutor::new()).handshake(TokioIo::new(client)).await.unwrap();
        tokio::spawn(async move {
            conn.await.unwrap();
        });
        let resp = sender.send_request(request).await.unwrap();
        assert_eq!(resp.version(), Version::HTTP_2);
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_handle_http2_request_http1_server() {
        let mock_server_mgr = Arc::new(ServerManager::new());
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        reject;
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let result = ProcessChainHttpServer::builder()
            .id("1")
            .version("HTTP/1.1".to_string())
            .hook_point(chains)
            .tunnel_manager(TunnelManager::new())
            .server_mgr(mock_server_mgr).build().await;

        assert!(result.is_ok());
        let http_server = Arc::new(result.unwrap());

        let (client, server) = tokio::io::duplex(128);

        tokio::spawn(async move {
            let ret = hyper_serve_http(Box::new(server), http_server, StreamInfo::default()).await;
            assert!(ret.is_err());
        });

        let request = http::Request::builder()
            .version(http::Version::HTTP_2)
            .method("GET")
            .uri("http://localhost/")
            .body(Full::new(Bytes::new()))
            .unwrap();

        let (mut sender, conn) = hyper::client::conn::http2::Builder::new(TokioExecutor::new()).handshake(TokioIo::new(client)).await.unwrap();
        tokio::spawn(async move {
            let ret = conn.await;
            assert!(ret.is_err());
        });
        let resp = sender.send_request(request).await;
        assert!(resp.is_err());
    }

    #[tokio::test]
    async fn test_process_chain_http_server_forward() {
        // 创建一个监听8090端口的HTTP服务器来处理请求
        tokio::spawn(async move {
            use http_body_util::BodyExt;
            use tokio::net::TcpListener;

            let listener = TcpListener::bind("127.0.0.1:18090").await.unwrap();

            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let service = hyper::service::service_fn(|req: http::Request<hyper::body::Incoming>| async move {
                    println!("{:?}", req.headers());
                    let _ = req.collect().await; // 消费请求体
                    Ok::<_, ServerError>(http::Response::builder()
                        .status(StatusCode::OK)
                        .body(Full::new(Bytes::from("forward success")).map_err(|e| match e {}).boxed())
                        .unwrap())
                });

                tokio::spawn(async move {
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });

        // 等待服务器启动
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let mock_server_mgr = Arc::new(ServerManager::new());
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        forward http://127.0.0.1:18090;
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let result = ProcessChainHttpServer::builder()
            .id("test_forward")
            .version("HTTP/1.1".to_string())
            .hook_point(chains)
            .server_mgr(mock_server_mgr)
            .tunnel_manager(TunnelManager::new())
            .build()
            .await;

        assert!(result.is_ok());
        let http_server = Arc::new(result.unwrap());

        let (client, server) = tokio::io::duplex(128);

        tokio::spawn(async move {
            hyper_serve_http(Box::new(server), http_server, StreamInfo::default()).await.unwrap();
        });

        let request = http::Request::builder()
            .method("GET")
            .uri("/test")
            .body(Full::new(Bytes::new()).map_err(|e| match e {}).boxed())
            .unwrap();

        let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
            .handshake(TokioIo::new(client))
            .await
            .unwrap();

        tokio::spawn(async move {
            conn.await.unwrap();
        });

        let resp = sender.send_request(request).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = resp.collect().await.unwrap().to_bytes();
        assert_eq!(body, Bytes::from("forward success"));
    }

    #[tokio::test]
    async fn test_process_chain_http_server_forward_tcp() {
        tokio::spawn(async move {
            use http_body_util::BodyExt;
            use tokio::net::TcpListener;

            let listener = TcpListener::bind("127.0.0.1:18091").await.unwrap();

            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let service = hyper::service::service_fn(|req: http::Request<hyper::body::Incoming>| async move {
                    println!("{:?}", req.headers());
                    let _ = req.collect().await; // 消费请求体
                    Ok::<_, ServerError>(http::Response::builder()
                        .status(StatusCode::OK)
                        .body(Full::new(Bytes::from("forward success")).map_err(|e| match e {}).boxed())
                        .unwrap())
                });

                tokio::spawn(async move {
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });

        // 等待服务器启动
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let mock_server_mgr = Arc::new(ServerManager::new());
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        forward tcp:///127.0.0.1:18091;
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let result = ProcessChainHttpServer::builder()
            .id("test_forward")
            .version("HTTP/1.1".to_string())
            .hook_point(chains)
            .server_mgr(mock_server_mgr)
            .tunnel_manager(TunnelManager::new())
            .build()
            .await;

        assert!(result.is_ok());
        let http_server = Arc::new(result.unwrap());

        let (client, server) = tokio::io::duplex(128);

        tokio::spawn(async move {
            hyper_serve_http(Box::new(server), http_server, StreamInfo::default()).await.unwrap();
        });

        let request = http::Request::builder()
            .method("GET")
            .uri("/test")
            .body(Full::new(Bytes::new()).map_err(|e| match e {}).boxed())
            .unwrap();

        let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
            .handshake(TokioIo::new(client))
            .await
            .unwrap();

        tokio::spawn(async move {
            conn.await.unwrap();
        });

        let resp = sender.send_request(request).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = resp.collect().await.unwrap().to_bytes();
        assert_eq!(body, Bytes::from("forward success"));
    }

    #[tokio::test]
    async fn test_process_chain_http_server_forward_err() {
        init_logging("test", false);
        let mock_server_mgr = Arc::new(ServerManager::new());
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "forward http://127.0.0.1:19999";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let result = ProcessChainHttpServer::builder()
            .id("test_forward_err")
            .version("HTTP/1.1".to_string())
            .hook_point(chains)
            .server_mgr(mock_server_mgr)
            .tunnel_manager(TunnelManager::new())
            .build()
            .await;

        assert!(result.is_ok());
        let http_server = Arc::new(result.unwrap());

        let (client, server) = tokio::io::duplex(128);

        tokio::spawn(async move {
            hyper_serve_http(Box::new(server), http_server, StreamInfo::default()).await.unwrap();
        });

        let request = http::Request::builder()
            .method("GET")
            .uri("/test")
            .body(Full::new(Bytes::new()).map_err(|e| match e {}).boxed())
            .unwrap();

        let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
            .handshake(TokioIo::new(client))
            .await
            .unwrap();

        tokio::spawn(async move {
            conn.await.unwrap();
        });

        let resp = sender.send_request(request).await.unwrap();
        // 当forward失败时，应该返回500错误
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_factory() {
        let config = ProcessChainHttpServerConfig {
            id: "test".to_string(),
            ty: "http".to_string(),
            version: None,
            h3_port: None,
            hook_point: ProcessChainConfigs::default(),
        };
        let factory = ProcessChainHttpServerFactory::new(
            Arc::new(ServerManager::new()),
            Arc::new(GlobalProcessChains::new()),
            TunnelManager::new(),
            GlobalCollectionManager::create(vec![]).await.unwrap()
        );
        let result = factory.create(Arc::new(config)).await;
        assert!(result.is_ok());
    }
}
