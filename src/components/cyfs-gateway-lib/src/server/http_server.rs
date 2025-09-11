use std::sync::{Arc, Mutex};
use http::{Version};
use http_body_util::combinators::{BoxBody};
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes};
use hyper::{http, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use cyfs_process_chain::{CollectionValue, MapCollection, ProcessChainLibExecutor};
use crate::{HttpRequestHeaderMap, HttpServer, InnerHttpServiceManagerRef, ProcessChainConfigs, ServerError, ServerErrorCode, ServerResult};
use crate::global_process_chains::{create_process_chain_executor, GlobalProcessChainsRef};
use super::{server_err, into_server_err};

pub struct ProcessChainHttpServerBuilder {
    version: Option<String>,
    h3_port: Option<u16>,
    hook_point: Option<ProcessChainConfigs>,
    global_process_chains: Option<GlobalProcessChainsRef>,
    inner_services: Option<InnerHttpServiceManagerRef>,
}

// Add setter methods for HttpServerBuilder
impl ProcessChainHttpServerBuilder {
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

    pub fn inner_services(mut self, inner_services: InnerHttpServiceManagerRef) -> Self {
        self.inner_services = Some(inner_services);
        self
    }

    pub fn h3_port(mut self, h3_port: u16) -> Self {
        self.h3_port = Some(h3_port);
        self
    }

    pub async fn build(self) -> ServerResult<ProcessChainHttpServer> {
        ProcessChainHttpServer::create_server(self).await
    }
}

pub struct ProcessChainHttpServer {
    version: http::Version,
    h3_port: Option<u16>,
    inner_services: InnerHttpServiceManagerRef,
    executor: Arc<Mutex<ProcessChainLibExecutor>>,
}

impl ProcessChainHttpServer {
    pub fn builder() -> ProcessChainHttpServerBuilder {
        ProcessChainHttpServerBuilder {
            version: None,
            h3_port: None,
            hook_point: None,
            global_process_chains: None,
            inner_services: None,
        }
    }

    async fn create_server(builder: ProcessChainHttpServerBuilder) -> ServerResult<ProcessChainHttpServer> {
        if builder.hook_point.is_none() {
            return Err(server_err!(ServerErrorCode::InvalidConfig, "hook_point is none"));
        }

        if builder.inner_services.is_none() {
            return Err(server_err!(ServerErrorCode::InvalidConfig, "inner_services is none"));
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
                                                          builder.global_process_chains).await
            .map_err(into_server_err!(ServerErrorCode::ProcessChainError))?;
        Ok(ProcessChainHttpServer {
            version,
            h3_port: builder.h3_port,
            inner_services: builder.inner_services.unwrap(),
            executor: Arc::new(Mutex::new(executor)),
        })
    }
}

#[async_trait::async_trait]
impl HttpServer for ProcessChainHttpServer {
    async fn serve_request(&self, req: http::Request<BoxBody<Bytes, ServerError>>) -> ServerResult<http::Response<BoxBody<Bytes, ServerError>>> {
        let executor = {
            self.executor.lock().unwrap().fork()
        };

        let req_map = HttpRequestHeaderMap::new(req);
        let chain_env = executor.chain_env();
        req_map.register_visitors(&chain_env).await.map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{}", e))?;

        let req_collection = Arc::new(Box::new(req_map.clone()) as Box<dyn MapCollection>);
        chain_env.create("REQ", CollectionValue::Map(req_collection)).await.map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{}", e))?;

        let ret = executor.execute_lib().await.map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{}", e))?;
        if ret.is_control() {
            if ret.is_drop() {
                info!("Request dropped by the process chain");
                Ok(http::Response::new(Full::new(Bytes::from("Request dropped")).map_err(|e| match e {}).boxed()))
            } else if ret.is_reject() {
                info!("Request rejected by the process chain");
                let mut response = http::Response::new(Full::new(Bytes::new()).map_err(|e| match e {}).boxed());
                *response.status_mut() = StatusCode::FORBIDDEN;
                Ok(response)
            } else {
                let mut response = http::Response::new(Full::new(Bytes::new()).map_err(|e| match e {}).boxed());
                *response.status_mut() = StatusCode::OK;
                Ok(response)
            }
        } else {
            let mut response = http::Response::new(Full::new(Bytes::new()).map_err(|e| match e {}).boxed());
            *response.status_mut() = StatusCode::OK;
            Ok(response)
        }
    }

    fn http_version(&self) -> Version {
        self.version
    }

    fn http3_port(&self) -> Option<u16> {
        self.h3_port
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use crate::{hyper_serve_http, hyper_serve_http1, InnerHttpServiceManager};

    #[tokio::test]
    async fn test_http_server_builder_creation() {
        let builder = ProcessChainHttpServer::builder();
        assert!(builder.version.is_none());
        assert!(builder.hook_point.is_none());
        assert!(builder.global_process_chains.is_none());
        assert!(builder.inner_services.is_none());
    }

    #[tokio::test]
    async fn test_create_server_without_hook_point() {
        let mock_inner_services = Arc::new(InnerHttpServiceManager::new());

        let result = ProcessChainHttpServer::builder()
            .inner_services(mock_inner_services).build().await;
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
        let mock_inner_services = Arc::new(InnerHttpServiceManager::new());

        let result = ProcessChainHttpServer::builder()
            .version("HTTP/1.2".to_string())
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

        let result = ProcessChainHttpServer::builder()
            .version("HTTP/1.1".to_string())
            .hook_point(vec![])
            .inner_services(mock_inner_services).build().await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_create_server_with_http2_version() {
        let mock_inner_services = Arc::new(InnerHttpServiceManager::new());

        let result = ProcessChainHttpServer::builder()
            .version("HTTP/2".to_string())
            .hook_point(vec![])
            .inner_services(mock_inner_services).build().await;
        assert!(result.is_ok());
    }


    #[tokio::test]
    async fn test_handle_http1_request_http1_server() {
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

        let result = ProcessChainHttpServer::builder()
            .version("HTTP/1.1".to_string())
            .hook_point(chains)
            .inner_services(mock_inner_services).build().await;

        assert!(result.is_ok());
        let http_server = Arc::new(result.unwrap());

        let (client, server) = tokio::io::duplex(128);

        tokio::spawn(async move {
            hyper_serve_http1(Box::new(server), http_server).await.unwrap();
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

        let result = ProcessChainHttpServer::builder()
            .version("HTTP/2".to_string())
            .hook_point(chains)
            .inner_services(mock_inner_services).build().await;

        assert!(result.is_ok());
        let http_server = Arc::new(result.unwrap());

        let (client, server) = tokio::io::duplex(128);

        tokio::spawn(async move {
            hyper_serve_http(Box::new(server), http_server).await.unwrap();
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

        let result = ProcessChainHttpServer::builder()
            .version("HTTP/2".to_string())
            .hook_point(chains)
            .inner_services(mock_inner_services).build().await;

        assert!(result.is_ok());
        let http_server = Arc::new(result.unwrap());

        let (client, server) = tokio::io::duplex(128);

        tokio::spawn(async move {
            hyper_serve_http(Box::new(server), http_server).await.unwrap();
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

        let result = ProcessChainHttpServer::builder()
            .version("HTTP/1.1".to_string())
            .hook_point(chains)
            .inner_services(mock_inner_services).build().await;

        assert!(result.is_ok());
        let http_server = Arc::new(result.unwrap());

        let (client, server) = tokio::io::duplex(128);

        tokio::spawn(async move {
            let ret = hyper_serve_http(Box::new(server), http_server).await;
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
}
