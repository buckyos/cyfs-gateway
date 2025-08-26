use std::sync::{Arc, Mutex};
use buckyos_kit::AsyncStream;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::{http, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use cyfs_process_chain::{CollectionValue, HyperHttpRequestHeaderMap, MapCollection, ProcessChainLibExecutor};
use crate::{InnerHttpServiceManagerRef, ProcessChainConfigs, ServerError, ServerErrorCode, ServerResult, StreamServer};
use crate::global_process_chains::{create_process_chain_executor, GlobalProcessChainsRef};
use super::{server_err, into_server_err};
pub struct HttpServerBuilder {
    version: Option<String>,
    hook_point: Option<ProcessChainConfigs>,
    global_process_chains: Option<GlobalProcessChainsRef>,
    inner_services: Option<InnerHttpServiceManagerRef>,
}

// Add setter methods for HttpServerBuilder
impl HttpServerBuilder {
    pub fn version(mut self, version: String) -> Self {
        self.version = Some(version);
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

    pub fn inner_services(mut self, inner_services: InnerHttpServiceManagerRef) -> Self {
        self.inner_services = Some(inner_services);
        self
    }

    pub async fn build(self) -> ServerResult<HttpServer> {
        HttpServer::create_server(self).await
    }
}

pub struct HttpServer {
    version: http::Version,
    inner_services: InnerHttpServiceManagerRef,
    executor: Arc<Mutex<ProcessChainLibExecutor>>,
}

impl HttpServer {
    pub fn builder() -> HttpServerBuilder {
        HttpServerBuilder {
            version: None,
            hook_point: None,
            global_process_chains: None,
            inner_services: None,
        }
    }

    async fn create_server(builder: HttpServerBuilder) -> ServerResult<HttpServer> {
        if builder.hook_point.is_none() {
            return Err(server_err!(ServerErrorCode::InvalidConfig, "hook_point is none"));
        }

        if builder.inner_services.is_none() {
            return Err(server_err!(ServerErrorCode::InvalidConfig, "inner_services is none"));
        }

        let version: http::Version = match builder.version {
            Some(ref version) => {
                match version.as_str() {
                    "HTTP/1.1" => http::Version::HTTP_11,
                    "HTTP/2" => http::Version::HTTP_2,
                    _ => return Err(server_err!(ServerErrorCode::InvalidConfig, "invalid http version")),
                }
            },
            None => http::Version::HTTP_11,
        };

        let (executor, _) = create_process_chain_executor(builder.hook_point.as_ref().unwrap()).await
            .map_err(into_server_err!(ServerErrorCode::ProcessChainError))?;
        Ok(HttpServer {
            version,
            inner_services: builder.inner_services.unwrap(),
            executor: Arc::new(Mutex::new(executor)),
        })
    }

    async fn serve_http1(&self, stream: Box<dyn AsyncStream>) -> ServerResult<()> {
        let executor = self.executor.clone();
        hyper::server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(stream), hyper::service::service_fn(move |req| {
                let executor = {
                    executor.lock().unwrap().fork()
                };
                async move {
                    match Self::handle_http_request(req, executor).await {
                        Ok(response) => Ok::<_, ServerError>(response),
                        Err(e) => {
                            error!("Error processing HTTP request: {}", e);
                            Ok(Response::new(Full::new(Bytes::from(format!("Error processing HTTP request: {}", e))).map_err(|e| match e {}).boxed()))
                        }
                    }
                }
            })).await.map_err(into_server_err!(ServerErrorCode::StreamError))?;
        Ok(())
    }

    async fn serve_http2(&self, stream: Box<dyn AsyncStream>) -> ServerResult<()> {
        let executor = self.executor.clone();
        hyper::server::conn::http2::Builder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(stream), hyper::service::service_fn(move |req| {
                let executor = {
                    executor.lock().unwrap().fork()
                };
                async move {
                    match Self::handle_http_request(req, executor).await {
                        Ok(response) => Ok::<_, ServerError>(response),
                        Err(e) => {
                            error!("Error processing HTTP request: {}", e);
                            Ok(Response::new(Full::new(Bytes::from(format!("Error processing HTTP request: {}", e))).map_err(|e| match e {}).boxed()))
                        }
                    }
                }
            })).await.map_err(into_server_err!(ServerErrorCode::StreamError))?;
        Ok(())
    }

    async fn handle_http_request(
        request: Request<Incoming>,
        executor: ProcessChainLibExecutor,
    ) -> ServerResult<Response<BoxBody<Bytes, ServerError>>> {
        let req_map = HyperHttpRequestHeaderMap::new(request);
        let chain_env = executor.chain_env();
        req_map.register_visitors(&chain_env).await.map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{}", e))?;

        let req_collection = Arc::new(Box::new(req_map.clone()) as Box<dyn MapCollection>);
        chain_env.create("REQ", CollectionValue::Map(req_collection)).await.map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{}", e))?;

        let ret = executor.execute_lib().await.map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{}", e))?;
        if ret.is_control() {
            if ret.is_drop() {
                info!("Request dropped by the process chain");
                return Ok(Response::new(Full::new(Bytes::from("Request dropped")).map_err(|e| match e {}).boxed()));
            } else if ret.is_reject() {
                info!("Request rejected by the process chain");
                let mut response = Response::new(Full::new(Bytes::new()).map_err(|e| match e {}).boxed());
                *response.status_mut() = StatusCode::FORBIDDEN;
                return Ok(response);
            } else {
                info!("Request accepted by the process chain");
            }
        }

        Ok(hyper::Response::new(Full::new(Bytes::from(
            "Hello, World!",
        )).map_err(|e| match e {}).boxed()))
    }
}

#[async_trait::async_trait]
impl StreamServer for HttpServer {
    async fn serve_connection(&self, stream: Box<dyn AsyncStream>) -> ServerResult<()> {
        match self.version {
            http::Version::HTTP_11 => self.serve_http1(stream).await,
            http::Version::HTTP_2 => self.serve_http2(stream).await,
            _ => Err(server_err!(ServerErrorCode::InvalidConfig, "invalid http version")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use crate::{InnerHttpServiceManager};

    #[tokio::test]
    async fn test_http_server_builder_creation() {
        let builder = HttpServer::builder();
        assert!(builder.version.is_none());
        assert!(builder.hook_point.is_none());
        assert!(builder.global_process_chains.is_none());
        assert!(builder.inner_services.is_none());
    }

    // 由于create_process_chain_executor的实现依赖于具体逻辑，我们不直接测试它
    // 而是专注于测试create_server的验证逻辑
    #[tokio::test]
    async fn test_create_server_without_hook_point() {
        let mock_inner_services = Arc::new(InnerHttpServiceManager::new());

        let result = HttpServer::builder()
            .inner_services(mock_inner_services).build().await;
        if let Err(e) = result {
            assert_eq!(e.code(), ServerErrorCode::InvalidConfig);
        }
    }

    #[tokio::test]
    async fn test_create_server_without_inner_services() {
        let mock_inner_services = Arc::new(InnerHttpServiceManager::new());

        let builder = HttpServer::builder()
            .hook_point(vec![]);
        let result = HttpServer::create_server(builder).await;
        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(e.code(), ServerErrorCode::InvalidConfig);
        }
    }

    #[tokio::test]
    async fn test_create_server_with_invalid_version() {
        let mock_inner_services = Arc::new(InnerHttpServiceManager::new());

        let result = HttpServer::builder()
            .version("HTTP/3".to_string())
            .hook_point(vec![])
            .inner_services(mock_inner_services).build().await;

        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(e.code(), ServerErrorCode::InvalidConfig);
        }
    }

    #[tokio::test]
    async fn test_create_server_with_http11_version() {
        let mock_inner_services = Arc::new(InnerHttpServiceManager::new());

        let result = HttpServer::builder()
            .version("HTTP/1.1".to_string())
            .hook_point(vec![])
            .inner_services(mock_inner_services).build().await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_create_server_with_http2_version() {
        let mock_inner_services = Arc::new(InnerHttpServiceManager::new());

        let result = HttpServer::builder()
            .version("HTTP/2".to_string())
            .hook_point(vec![])
            .inner_services(mock_inner_services).build().await;
        assert!(result.is_ok());
    }


    #[tokio::test]
    async fn test_handle_http1_request() {
        let mock_inner_services = Arc::new(InnerHttpServiceManager::new());
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        reject;
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let result = HttpServer::builder()
            .version("HTTP/1.1".to_string())
            .hook_point(chains)
            .inner_services(mock_inner_services).build().await;

        assert!(result.is_ok());
        let http_server = result.unwrap();

        let (client, server) = tokio::io::duplex(128);

        tokio::spawn(async move {
            let ret = http_server.serve_connection(Box::new(server)).await;
            assert!(ret.is_ok());
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
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }


    #[tokio::test]
    async fn test_handle_http2_request() {
        let mock_inner_services = Arc::new(InnerHttpServiceManager::new());
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        reject;
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let result = HttpServer::builder()
            .version("HTTP/2".to_string())
            .hook_point(chains)
            .inner_services(mock_inner_services).build().await;

        assert!(result.is_ok());
        let http_server = result.unwrap();

        let (client, server) = tokio::io::duplex(128);

        tokio::spawn(async move {
            let ret = http_server.serve_connection(Box::new(server)).await;
            assert!(ret.is_ok());
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
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }
}
