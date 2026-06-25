//! HTTP/kRPC server adapter for the centralized BNS indexer.
//!
//! `bns-indexer` owns the registry state machine. `bns-client` owns the RPC
//! protocol and envelope. This crate only wires those pieces into an HTTP
//! server that can be mounted by gateway stacks or run behind a `TcpListener`.

use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use bns_client::{
    BnsIndexerApi, BnsIndexerRpcHandler, CentralizedBnsIndexerHandler, BNS_INDEXER_RPC_PATH,
};
use bns_indexer::{
    BnsRegistryResult, BnsRegistryStore, CentralizedBnsRegistry, SqliteBnsRegistryStore,
};
use bytes::Bytes;
use cyfs_gateway_lib::{
    hyper_serve_http, serve_http_by_rpc_handler, server_err, HttpServer, ServerError,
    ServerErrorCode, ServerResult, StreamInfo,
};
use http::{HeaderValue, Method, Response, StatusCode, Version};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use kRPC::{RPCErrors, RPCHandler, RPCRequest, RPCResponse};
use log::warn;
use tokio::net::{TcpListener, ToSocketAddrs};
use tokio::task::JoinHandle;

pub type SqliteBnsIndexerHttpServer =
    BnsIndexerHttpServer<CentralizedBnsIndexerHandler<SqliteBnsRegistryStore>>;

#[derive(Debug, Clone)]
pub struct BnsIndexerHttpServerConfig {
    pub id: String,
    pub rpc_path: String,
    pub http_version: Version,
    pub http3_port: Option<u16>,
}

impl Default for BnsIndexerHttpServerConfig {
    fn default() -> Self {
        Self {
            id: "bns-indexer".to_string(),
            rpc_path: BNS_INDEXER_RPC_PATH.to_string(),
            http_version: Version::HTTP_11,
            http3_port: None,
        }
    }
}

impl BnsIndexerHttpServerConfig {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            ..Self::default()
        }
    }

    pub fn with_rpc_path(mut self, rpc_path: impl Into<String>) -> Self {
        self.rpc_path = normalize_rpc_path(rpc_path.into());
        self
    }

    pub fn with_http_version(mut self, http_version: Version) -> Self {
        self.http_version = http_version;
        self
    }

    pub fn with_http3_port(mut self, http3_port: Option<u16>) -> Self {
        self.http3_port = http3_port;
        self
    }
}

pub struct BnsIndexerHttpServer<T>
where
    T: BnsIndexerApi,
{
    config: BnsIndexerHttpServerConfig,
    rpc_handler: BnsIndexerRpcHandler<T>,
}

impl<T> BnsIndexerHttpServer<T>
where
    T: BnsIndexerApi,
{
    pub fn new(handler: T) -> Self {
        Self::with_config(handler, BnsIndexerHttpServerConfig::default())
    }

    pub fn with_config(handler: T, mut config: BnsIndexerHttpServerConfig) -> Self {
        config.rpc_path = normalize_rpc_path(config.rpc_path);
        Self {
            config,
            rpc_handler: BnsIndexerRpcHandler::new(handler),
        }
    }

    pub fn config(&self) -> &BnsIndexerHttpServerConfig {
        &self.config
    }

    pub fn rpc_path(&self) -> &str {
        &self.config.rpc_path
    }

    pub fn rpc_handler(&self) -> &BnsIndexerRpcHandler<T> {
        &self.rpc_handler
    }
}

impl<S> BnsIndexerHttpServer<CentralizedBnsIndexerHandler<S>>
where
    S: BnsRegistryStore + 'static,
{
    pub fn from_registry(registry: Arc<CentralizedBnsRegistry<S>>) -> Self {
        Self::new(CentralizedBnsIndexerHandler::new(registry))
    }

    pub fn from_registry_with_config(
        registry: Arc<CentralizedBnsRegistry<S>>,
        config: BnsIndexerHttpServerConfig,
    ) -> Self {
        Self::with_config(CentralizedBnsIndexerHandler::new(registry), config)
    }
}

impl SqliteBnsIndexerHttpServer {
    pub fn open_sqlite(path: impl AsRef<Path>) -> BnsRegistryResult<Self> {
        let registry = open_sqlite_registry(path)?;
        Ok(Self::from_registry(registry))
    }

    pub fn open_sqlite_with_config(
        path: impl AsRef<Path>,
        config: BnsIndexerHttpServerConfig,
    ) -> BnsRegistryResult<Self> {
        let registry = open_sqlite_registry(path)?;
        Ok(Self::from_registry_with_config(registry, config))
    }

    pub fn open_memory() -> BnsRegistryResult<Self> {
        let registry = Arc::new(CentralizedBnsRegistry::new(
            SqliteBnsRegistryStore::open_memory()?,
        ));
        Ok(Self::from_registry(registry))
    }
}

pub fn open_sqlite_registry(
    path: impl AsRef<Path>,
) -> BnsRegistryResult<Arc<CentralizedBnsRegistry<SqliteBnsRegistryStore>>> {
    Ok(Arc::new(CentralizedBnsRegistry::new(
        SqliteBnsRegistryStore::open(path)?,
    )))
}

#[async_trait]
impl<T> RPCHandler for BnsIndexerHttpServer<T>
where
    T: BnsIndexerApi + 'static,
{
    async fn handle_rpc_call(
        &self,
        req: RPCRequest,
        ip_from: IpAddr,
    ) -> Result<RPCResponse, RPCErrors> {
        self.rpc_handler.handle_rpc_call(req, ip_from).await
    }
}

#[async_trait]
impl<T> HttpServer for BnsIndexerHttpServer<T>
where
    T: BnsIndexerApi + 'static,
{
    async fn serve_request(
        &self,
        req: http::Request<BoxBody<Bytes, ServerError>>,
        info: StreamInfo,
    ) -> ServerResult<http::Response<BoxBody<Bytes, ServerError>>> {
        let path = req.uri().path().to_string();

        if req.method() == Method::OPTIONS && path == self.config.rpc_path {
            return response_with_cors(StatusCode::NO_CONTENT, "");
        }

        if req.method() == Method::GET && path == "/health" {
            return response_with_cors(StatusCode::OK, "ok");
        }

        if path != self.config.rpc_path {
            return response_with_cors(StatusCode::NOT_FOUND, "Not Found");
        }

        let mut response = serve_http_by_rpc_handler(req, info, self).await?;
        add_cors_headers(response.headers_mut());
        Ok(response)
    }

    fn id(&self) -> String {
        self.config.id.clone()
    }

    fn http_version(&self) -> Version {
        self.config.http_version
    }

    fn http3_port(&self) -> Option<u16> {
        self.config.http3_port
    }
}

pub async fn bind_and_serve<A>(bind: A, server: Arc<dyn HttpServer>) -> ServerResult<()>
where
    A: ToSocketAddrs,
{
    let listener = TcpListener::bind(bind).await.map_err(|e| {
        server_err!(
            ServerErrorCode::BindFailed,
            "failed to bind bns-indexer server: {}",
            e
        )
    })?;
    serve_listener(listener, server).await
}

pub async fn serve_listener(
    listener: TcpListener,
    server: Arc<dyn HttpServer>,
) -> ServerResult<()> {
    loop {
        let (stream, remote_addr) = listener.accept().await.map_err(|e| {
            server_err!(
                ServerErrorCode::StreamError,
                "failed to accept bns-indexer connection: {}",
                e
            )
        })?;
        let server = server.clone();
        tokio::spawn(async move {
            let info = StreamInfo::new(remote_addr.to_string());
            if let Err(e) = hyper_serve_http(Box::new(stream), server, info).await {
                warn!("bns-indexer http connection failed: {}", e);
            }
        });
    }
}

pub struct BnsIndexerServerHandle {
    local_addr: SocketAddr,
    task: JoinHandle<ServerResult<()>>,
}

impl BnsIndexerServerHandle {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub async fn shutdown(self) {
        self.task.abort();
        let _ = self.task.await;
    }
}

pub fn spawn_listener(
    listener: TcpListener,
    server: Arc<dyn HttpServer>,
) -> ServerResult<BnsIndexerServerHandle> {
    let local_addr = listener.local_addr().map_err(|e| {
        server_err!(
            ServerErrorCode::InvalidConfig,
            "failed to read bns-indexer listener address: {}",
            e
        )
    })?;
    let task = tokio::spawn(serve_listener(listener, server));
    Ok(BnsIndexerServerHandle { local_addr, task })
}

fn normalize_rpc_path(path: String) -> String {
    let trimmed = path.trim_end_matches('/');
    let normalized = if trimmed.is_empty() {
        BNS_INDEXER_RPC_PATH.to_string()
    } else if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{trimmed}")
    };
    if normalized == "/" {
        BNS_INDEXER_RPC_PATH.to_string()
    } else {
        normalized
    }
}

fn response_with_cors(
    status: StatusCode,
    body: impl Into<Bytes>,
) -> ServerResult<Response<BoxBody<Bytes, ServerError>>> {
    let mut response = Response::builder()
        .status(status)
        .body(full_body(body.into()))
        .map_err(|e| {
            server_err!(
                ServerErrorCode::EncodeError,
                "failed to build bns-indexer response: {}",
                e
            )
        })?;
    add_cors_headers(response.headers_mut());
    Ok(response)
}

fn full_body(body: Bytes) -> BoxBody<Bytes, ServerError> {
    Full::new(body).map_err(|never| match never {}).boxed()
}

fn add_cors_headers(headers: &mut http::HeaderMap) {
    headers.insert(
        http::header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    headers.insert(
        http::header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("GET, POST, OPTIONS"),
    );
    headers.insert(
        http::header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static("Content-Type, Authorization"),
    );
    headers.insert(
        http::header::ACCESS_CONTROL_MAX_AGE,
        HeaderValue::from_static("86400"),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use bns_client::{
        BnsIndexerApi, BnsIndexerClient, BnsNameReq, BnsRegisterNameReq, BnsRpcEnvelope,
        METHOD_QUERY_NAME_STATE,
    };
    use bns_indexer::{CallAuthority, MutationGuard, Principal, RegisterOptions};
    use http::{Request, StatusCode};
    use kRPC::{RPCRequest, RPCResult};

    const OWNER: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[tokio::test]
    async fn normalizes_configured_rpc_path() {
        let server = SqliteBnsIndexerHttpServer::open_memory()
            .unwrap()
            .config()
            .clone()
            .with_rpc_path("kapi/custom/");
        assert_eq!(server.rpc_path, "/kapi/custom");
    }

    #[tokio::test]
    async fn rejects_non_bns_indexer_paths() {
        let server = SqliteBnsIndexerHttpServer::open_memory().unwrap();
        let request = Request::builder()
            .method(Method::POST)
            .uri("/wrong")
            .body(full_body(Bytes::new()))
            .unwrap();

        let response = server
            .serve_request(request, StreamInfo::new("127.0.0.1:1".to_string()))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn serves_bns_indexer_rpc_over_http() {
        let server = Arc::new(SqliteBnsIndexerHttpServer::open_memory().unwrap());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let handle = spawn_listener(listener, server).unwrap();
        let endpoint = format!("http://{}", handle.local_addr());
        let client = BnsIndexerClient::new_krpc_url(&endpoint, None);

        let registered = client
            .register_name(BnsRegisterNameReq {
                name: "alice".to_string(),
                asset_owner: OWNER.to_string(),
                options: RegisterOptions::default(),
                initial_documents: vec![],
                authority: CallAuthority::public(),
                guard: MutationGuard::default(),
            })
            .await
            .unwrap();
        assert_eq!(registered.name_seq, 1);

        let state = client.query_name_state("alice").await.unwrap().unwrap();
        assert_eq!(state.name, "alice");
        assert_eq!(state.asset_owner, OWNER);

        handle.shutdown().await;
    }

    #[tokio::test]
    async fn wraps_registry_errors_in_successful_rpc_envelope() {
        let server = SqliteBnsIndexerHttpServer::open_memory().unwrap();
        let rpc_req = RPCRequest::new(
            METHOD_QUERY_NAME_STATE,
            serde_json::to_value(BnsNameReq::new("not..valid")).unwrap(),
        );

        let response = server
            .handle_rpc_call(rpc_req, "127.0.0.1".parse().unwrap())
            .await
            .unwrap();
        let value = match response.result {
            RPCResult::Success(value) => value,
            RPCResult::Failed(error) => panic!("unexpected rpc failure: {error}"),
        };
        let envelope: BnsRpcEnvelope<Option<serde_json::Value>> =
            serde_json::from_value(value).unwrap();

        assert!(!envelope.ok);
        assert_eq!(
            envelope.error.unwrap().code,
            bns_indexer::BnsRegistryError::InvalidName {
                name: "not..valid".to_string(),
                reason: String::new(),
            }
            .code()
        );
    }

    #[tokio::test]
    async fn health_endpoint_returns_ok() {
        let server = SqliteBnsIndexerHttpServer::open_memory().unwrap();
        let request = Request::builder()
            .method(Method::GET)
            .uri("/health")
            .body(full_body(Bytes::new()))
            .unwrap();

        let response = server
            .serve_request(request, StreamInfo::new("127.0.0.1:1".to_string()))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn constructs_server_from_existing_registry() {
        let registry = Arc::new(CentralizedBnsRegistry::new(
            SqliteBnsRegistryStore::open_memory().unwrap(),
        ));
        registry
            .register_name(
                "bob",
                OWNER,
                RegisterOptions::default(),
                vec![],
                CallAuthority::public(),
                MutationGuard::default(),
            )
            .unwrap();

        let server = SqliteBnsIndexerHttpServer::from_registry(registry.clone());
        assert_eq!(server.id(), "bns-indexer");
        assert_eq!(
            registry.resolve_owner("bob").unwrap().effective_owner,
            Principal::chain_account(OWNER)
        );
    }
}
