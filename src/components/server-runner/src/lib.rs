use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, RwLock};

use buckyos_kit::AsyncStream;
use cyfs_gateway_lib::{
    hyper_serve_http, server_err, HttpServer, ServerErrorCode, ServerResult, StreamInfo,
};
use log::{error, info};
use tokio::net::{TcpListener, TcpStream};

/// Run a single `HttpServer` on top of a plain TCP listener.
#[derive(Clone)]
pub struct Runner {
    bind_addr: SocketAddr,
    http_server: Arc<RwLock<Option<Arc<dyn HttpServer>>>>,
}

impl Runner {
    /// Bind to `0.0.0.0:port`.
    pub fn new(port: u16) -> Self {
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port));
        Self::with_addr(addr)
    }

    /// Bind to a custom socket address.
    pub fn with_addr(addr: SocketAddr) -> Self {
        Self {
            bind_addr: addr,
            http_server: Arc::new(RwLock::new(None)),
        }
    }

    /// Read the address Runner will bind to.
    pub fn bind_addr(&self) -> SocketAddr {
        self.bind_addr
    }

    /// Register the only HttpServer instance Runner will serve.
    pub fn add_http_server(&self, server: Arc<dyn HttpServer>) -> ServerResult<()> {
        let mut slot = self.http_server.write().unwrap();
        if slot.is_some() {
            return Err(server_err!(
                ServerErrorCode::AlreadyExists,
                "HttpServer already registered"
            ));
        }
        *slot = Some(server);
        Ok(())
    }

    /// Start accepting TCP traffic and forward every stream to the registered HttpServer.
    pub async fn start(&self) -> ServerResult<()> {
        let http_server = self.http_server()?;

        let listener = TcpListener::bind(self.bind_addr)
            .await
            .map_err(|e| server_err!(ServerErrorCode::BindFailed, "{}", e))?;

        let local_addr = listener.local_addr().unwrap_or(self.bind_addr);
        info!("server-runner listening on {}", local_addr);

        loop {
            let (stream, peer_addr) = match listener.accept().await {
                Ok(ret) => ret,
                Err(e) => {
                    error!("failed to accept tcp connection: {}", e);
                    continue;
                }
            };

            let server = http_server.clone();
            tokio::spawn(async move {
                if let Err(err) = serve_tcp_stream(stream, server, peer_addr).await {
                    error!("failed to serve {}: {:?}", peer_addr, err);
                }
            });
        }
    }

    fn http_server(&self) -> ServerResult<Arc<dyn HttpServer>> {
        self.http_server
            .read()
            .unwrap()
            .clone()
            .ok_or_else(|| {
                server_err!(
                    ServerErrorCode::InvalidConfig,
                    "HttpServer must be registered before start"
                )
            })
    }
}

async fn serve_tcp_stream(
    stream: TcpStream,
    server: Arc<dyn HttpServer>,
    peer_addr: SocketAddr,
) -> ServerResult<()> {
    let info = StreamInfo::new(peer_addr.to_string());
    let stream: Box<dyn AsyncStream> = Box::new(stream);
    hyper_serve_http(stream, server, info).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use cyfs_gateway_lib::ServerError;
    use http::{Response, StatusCode};
    use http_body_util::combinators::BoxBody;
    use http_body_util::{BodyExt, Full};
    use hyper::body::Bytes;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct DummyHttpServer;

    #[async_trait]
    impl HttpServer for DummyHttpServer {
        async fn serve_request(
            &self,
            _req: http::Request<BoxBody<Bytes, ServerError>>,
            _info: StreamInfo,
        ) -> ServerResult<http::Response<BoxBody<Bytes, ServerError>>> {
            let mut resp = Response::new(
                Full::new(Bytes::from_static(b"runner-ok"))
                    .map_err(|e| match e {})
                    .boxed(),
            );
            *resp.status_mut() = StatusCode::OK;
            Ok(resp)
        }

        fn id(&self) -> String {
            "dummy".to_string()
        }

        fn http_version(&self) -> http::Version {
            http::Version::HTTP_11
        }

        fn http3_port(&self) -> Option<u16> {
            None
        }
    }

    fn random_loopback() -> SocketAddr {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        addr
    }

    #[tokio::test]
    async fn add_twice_is_rejected() {
        let runner = Runner::new(0);
        runner.add_http_server(Arc::new(DummyHttpServer)).unwrap();
        let err = runner
            .add_http_server(Arc::new(DummyHttpServer))
            .unwrap_err();
        assert_eq!(err.code(), ServerErrorCode::AlreadyExists);
    }

    #[tokio::test]
    async fn serves_basic_http_request() {
        let addr = random_loopback();
        let runner = Runner::with_addr(addr);
        runner.add_http_server(Arc::new(DummyHttpServer)).unwrap();

        let runner_handle = runner.clone();
        let server_task = tokio::spawn(async move {
            let _ = runner_handle.start().await;
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();

        let mut buf = vec![0u8; 256];
        let n = client.read(&mut buf).await.unwrap();
        let text = String::from_utf8_lossy(&buf[..n]);
        assert!(text.contains("200 OK"), "{text}");
        assert!(text.contains("runner-ok"), "{text}");

        server_task.abort();
        let _ = server_task.await;
    }
}

