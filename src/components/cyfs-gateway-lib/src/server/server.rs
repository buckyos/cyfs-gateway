use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::sync::atomic::AtomicU32;
use as_any::AsAny;
use buckyos_kit::AsyncStream;
use http::{HeaderName, Request, Uri};
use http_body_util::BodyExt;
use http_body_util::combinators::{BoxBody};
use hyper::body::{Bytes};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::sync::RwLock;
use cyfs_process_chain::{CollectionValue, EnvRef, MapCollection, MapCollectionTraverseCallBackRef, TraverseGuard, VariableVisitor, VariableVisitorWrapperForMapCollection, HTTP_REQUEST_HEADER_VARS};
use crate::{server_err, ProcessChainConfig, ServerError, ServerErrorCode, ServerResult};

pub trait ServerConfig: AsAny + Send + Sync {
    fn id(&self) -> String;
    fn server_type(&self) -> String;
    fn get_config_json(&self) -> String;
    fn add_pre_hook_point_process_chain(&self, process_chain: ProcessChainConfig) -> Arc<dyn ServerConfig>;
    fn remove_pre_hook_point_process_chain(&self, process_chain_id: &str) -> Arc<dyn ServerConfig>;
    fn add_post_hook_point_process_chain(&self, process_chain: ProcessChainConfig) -> Arc<dyn ServerConfig>;
    fn remove_post_hook_point_process_chain(&self, process_chain_id: &str) -> Arc<dyn ServerConfig>;
}

#[async_trait::async_trait]
pub trait ServerFactory: Send + Sync {
    async fn create(&self, config: Arc<dyn ServerConfig>) -> ServerResult<Server>;
}

pub struct CyfsServerFactory {
    server_factory: Mutex<HashMap<String, Arc<dyn ServerFactory>>>,
}

impl Default for CyfsServerFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl CyfsServerFactory {
    pub fn new() -> Self {
        Self {
            server_factory: Mutex::new(HashMap::new()),
        }
    }
    pub fn register(&self, server_type: String, factory: Arc<dyn ServerFactory>) {
        self.server_factory.lock().unwrap().insert(server_type, factory);
    }
}

#[async_trait::async_trait]
impl ServerFactory for CyfsServerFactory {
    async fn create(&self, config: Arc<dyn ServerConfig>) -> ServerResult<Server> {
        let factory = {
            self.server_factory.lock().unwrap().get(config.server_type().as_str()).cloned()
        };
        match factory {
            Some(factory) => factory.create(config).await,
            None => Err(server_err!(ServerErrorCode::UnknownServerType, "unknown server type {}", config.server_type())),
        }
    }
}

#[derive(Clone)]
pub enum Server {
    Http(Arc<dyn HttpServer>),
    Stream(Arc<dyn StreamServer>),
    Datagram(Arc<dyn DatagramServer>),
}

impl Server {
    pub fn id(&self) -> String {
        match self {
            Server::Http(server) => server.id(),
            Server::Stream(server) => server.id(),
            Server::Datagram(server) => server.id(),
        }
    }

    pub async fn update_config(&self, config: Arc<dyn ServerConfig>) -> ServerResult<()> {
        match self {
            Server::Http(server) => server.update_config(config).await,
            Server::Stream(server) => server.update_config(config).await,
            Server::Datagram(server) => server.update_config(config).await,
        }
    }
}

#[derive(Default, Debug, Clone)]
pub struct StreamInfo {
    pub src_addr: Option<String>,
}

impl StreamInfo {
    pub fn new(src_addr: String) -> Self {
        Self {
            src_addr: Some(src_addr),
        }
    }
}

// 流处理服务
#[async_trait::async_trait]
pub trait StreamServer: Send + Sync {
    async fn serve_connection(&self, stream: Box<dyn AsyncStream>, info: StreamInfo) -> ServerResult<()>;
    fn id(&self) -> String;
    async fn update_config(&self, config: Arc<dyn ServerConfig>) -> ServerResult<()>;
}

#[derive(Clone)]
pub struct HttpRequestHeaderMap {
    request: Arc<RwLock<http::Request<BoxBody<Bytes, ServerError>>>>,
    transverse_counter: Arc<AtomicU32>, // Indicates if a traversal is currently happening
}

impl HttpRequestHeaderMap {
    pub fn new(request: http::Request<BoxBody<Bytes, ServerError>>) -> Self {
        Self {
            request: Arc::new(RwLock::new(request)),
            transverse_counter: Arc::new(AtomicU32::new(0)), // Initialize counter to 0
        }
    }

    fn is_during_traversal(&self) -> bool {
        self.transverse_counter
            .load(std::sync::atomic::Ordering::SeqCst)
            > 0
    }

    pub fn into_request(self) -> Result<http::Request<BoxBody<Bytes, ServerError>>, String> {
        let req = Arc::try_unwrap(self.request)
            .map_err(|_| {
                let msg = "Failed to unwrap HyperHttpRequestHeaderMap".to_string();
                error!("{}", msg);
                msg
            })?
            .into_inner();

        Ok(req)
    }

    pub async fn register_visitors(&self, env: &EnvRef) -> Result<(), String> {
        // First register visitors for var in header
        let coll = Arc::new(Box::new(self.clone()) as Box<dyn MapCollection>);
        let mut wrapper = VariableVisitorWrapperForMapCollection::new(coll);

        for item in HTTP_REQUEST_HEADER_VARS {
            wrapper.add_variable(item.0, item.1, item.2);
        }

        let visitor = Arc::new(Box::new(wrapper) as Box<dyn VariableVisitor>);
        for (id, _, _) in HTTP_REQUEST_HEADER_VARS {
            env.create(*id, CollectionValue::Visitor(Arc::clone(&visitor)))
                .await?;
        }

        // Url visitor
        let url_visitor = HttpRequestUrlVisitor::new(self.request.clone(), false);
        let visitor = Arc::new(Box::new(url_visitor) as Box<dyn VariableVisitor>);
        env.create("REQ_url", CollectionValue::Visitor(visitor))
            .await?;

        Ok(())
    }
}

#[async_trait::async_trait]
impl MapCollection for HttpRequestHeaderMap {
    async fn len(&self) -> Result<usize, String> {
        let request = self.request.read().await;
        Ok(request.headers().len())
    }

    async fn insert_new(&self, key: &str, value: CollectionValue) -> Result<bool, String> {
        if self.is_during_traversal() {
            let msg = format!("Cannot insert new header '{}' during traversal", key);
            warn!("{}", msg);
            return Err(msg);
        }

        let mut request = self.request.write().await;
        let header = value.try_as_str()?.parse().map_err(|e| {
            let msg = format!("Invalid header value '{}': {}", value, e);
            warn!("{}", msg);
            msg
        })?;

        let name = HeaderName::from_bytes(key.as_bytes()).map_err(|e| {
            let msg = format!("Invalid header name '{}': {}", key, e);
            warn!("{}", msg);
            msg.to_string()
        })?;

        if request.headers().contains_key(&name) {
            let msg = format!("Header '{}' already exists", key);
            warn!("{}", msg);
            return Ok(false);
        }

        request.headers_mut().insert(name, header);
        Ok(true)
    }

    async fn insert(
        &self,
        key: &str,
        value: CollectionValue,
    ) -> Result<Option<CollectionValue>, String> {
        if self.is_during_traversal() {
            let msg = format!("Cannot insert header '{}' during traversal", key);
            warn!("{}", msg);
            return Err(msg);
        }

        let mut request = self.request.write().await;
        let header = value.try_as_str()?.parse().map_err(|e| {
            let msg = format!("Invalid header value '{}': {}", value, e);
            warn!("{}", msg);
            msg
        })?;

        let name = HeaderName::from_bytes(key.as_bytes()).map_err(|e| {
            let msg = format!("Invalid header name '{}': {}", key, e);
            warn!("{}", msg);
            msg.to_string()
        })?;

        let prev = request.headers_mut().insert(name, header);
        if let Some(prev_value) = prev {
            let prev = match prev_value.to_str() {
                Ok(s) => s.to_string(),
                Err(_) => {
                    let msg = format!("Header value for '{}' is not valid UTF-8", key);
                    warn!("{}", msg);
                    "".to_string()
                }
            };
            Ok(Some(CollectionValue::String(prev)))
        } else {
            Ok(None)
        }
    }

    async fn get(&self, key: &str) -> Result<Option<CollectionValue>, String> {
        let request = self.request.read().await;
        let ret = request.headers().get(key);
        if let Some(value) = ret {
            if let Ok(value_str) = value.to_str() {
                Ok(Some(CollectionValue::String(value_str.to_string())))
            } else {
                warn!("Header value for '{}' is not valid UTF-8", key);
                Ok(Some(CollectionValue::String("".to_string())))
            }
        } else {
            warn!("Header '{}' not found", key);
            Ok(None)
        }
    }

    async fn contains_key(&self, key: &str) -> Result<bool, String> {
        let request = self.request.read().await;
        Ok(request.headers().get(key).is_some())
    }

    async fn remove(&self, key: &str) -> Result<Option<CollectionValue>, String> {
        if self.is_during_traversal() {
            let msg = format!("Cannot remove header '{}' during traversal", key);
            warn!("{}", msg);
            return Err(msg);
        }

        let mut request = self.request.write().await;
        let prev = request.headers_mut().remove(key);
        if let Some(prev_value) = prev {
            let prev = match prev_value.to_str() {
                Ok(s) => s.to_string(),
                Err(_) => {
                    let msg = format!("Header value for '{}' is not valid UTF-8", key);
                    warn!("{}", msg);
                    "".to_string()
                }
            };
            Ok(Some(CollectionValue::String(prev)))
        } else {
            Ok(None)
        }
    }

    async fn traverse(&self, callback: MapCollectionTraverseCallBackRef) -> Result<(), String> {
        let _guard = TraverseGuard::new(&self.transverse_counter);

        let request = self.request.read().await;
        for (key, value) in request.headers().iter() {
            if let Ok(value_str) = value.to_str() {
                if !callback
                    .call(key.as_str(), &CollectionValue::String(value_str.to_owned()))
                    .await?
                {
                    break; // Stop traversal if callback returns false
                }
            } else {
                warn!("Header value for '{}' is not valid UTF-8", key);
            }
        }
        Ok(())
    }

    async fn dump(&self) -> Result<Vec<(String, CollectionValue)>, String> {
        let request = self.request.read().await;
        let mut result = Vec::new();
        for (key, value) in request.headers().iter() {
            if let Ok(value_str) = value.to_str() {
                result.push((
                    key.as_str().to_string(),
                    CollectionValue::String(value_str.to_string()),
                ));
            } else {
                warn!("Header value for '{}' is not valid UTF-8", key);
            }
        }
        Ok(result)
    }
}

// Url visitor for HTTP requests
#[derive(Clone)]
pub struct HttpRequestUrlVisitor {
    request: Arc<RwLock<http::Request<BoxBody<Bytes, ServerError>>>>,
    read_only: bool,
}

impl HttpRequestUrlVisitor {
    pub fn new(request: Arc<RwLock<http::Request<BoxBody<Bytes, ServerError>>>>, read_only: bool) -> Self {
        Self { request, read_only }
    }
}

#[async_trait::async_trait]
impl VariableVisitor for HttpRequestUrlVisitor {
    async fn get(&self, _id: &str) -> Result<CollectionValue, String> {
        let request = self.request.read().await;
        let ret = request.uri().to_string();

        Ok(CollectionValue::String(ret))
    }

    async fn set(
        &self,
        id: &str,
        value: CollectionValue,
    ) -> Result<Option<CollectionValue>, String> {
        if self.read_only {
            let msg = format!("Cannot set read-only variable '{}'", id);
            warn!("{}", msg);
            return Err(msg);
        }

        let new_url = value.try_as_str()?.parse::<Uri>().map_err(|e| {
            let msg = format!("Invalid URL '{}': {}", value, e);
            warn!("{}", msg);
            msg
        })?;

        let mut request = self.request.write().await;
        let old_value = request.uri().to_string();
        *request.uri_mut() = new_url;

        info!("Set request url variable '{}' to '{}'", id, value);
        Ok(Some(CollectionValue::String(old_value)))
    }
}

#[async_trait::async_trait]
pub trait HttpServer: Send + Sync + 'static {
    async fn serve_request(&self, req: http::Request<BoxBody<Bytes, ServerError>>, info: StreamInfo) -> ServerResult<http::Response<BoxBody<Bytes, ServerError>>>;
    fn id(&self) -> String;
    fn http_version(&self) -> http::Version;
    fn http3_port(&self) -> Option<u16>;
    async fn update_config(&self, config: Arc<dyn ServerConfig>) -> ServerResult<()>;
}

pub struct DatagramInfo {
    pub src_addr: Option<String>,
}

impl DatagramInfo {
    pub fn new(src_addr: Option<String>) -> Self {
        DatagramInfo {
            src_addr,
        }
    }
}

#[async_trait::async_trait]
pub trait DatagramServer: Send + Sync + 'static {
    async fn serve_datagram(&self, buf: &[u8], info: DatagramInfo) -> ServerResult<Vec<u8>>;
    fn id(&self) -> String;
    async fn update_config(&self, config: Arc<dyn ServerConfig>) -> ServerResult<()>;
}

pub struct ServerManager {
    servers: Mutex<HashMap<String, Server>>
}

impl ServerManager {
    pub fn new() -> Self {
        ServerManager {
            servers: Mutex::new(HashMap::new()),
        }
    }
    pub fn add_server(&self, server: Server) -> ServerResult<()> {
        if self.get_server(server.id().as_str()).is_some() {
            return Err(server_err!(ServerErrorCode::AlreadyExists, "Server {} already exists", server.id().as_str()));
        }

        self.servers.lock().unwrap().insert(server.id(), server);
        Ok(())
    }

    pub fn get_server(&self, name: &str) -> Option<Server> {
        self.servers.lock().unwrap().get(name).cloned()
    }

}

pub type ServerManagerRef = Arc<ServerManager>;

pub async fn hyper_serve_http(stream: Box<dyn AsyncStream>, server: Arc<dyn HttpServer>, info: StreamInfo) -> ServerResult<()> {
    if server.http_version() <= http::Version::HTTP_11 {
        hyper::server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(stream), hyper::service::service_fn(|req| {
                let server = server.clone();
                let info = info.clone();
                async move {
                    let (parts, body) = req.into_parts();
                    let req = Request::new(BoxBody::new(body)).map_err(|e| server_err!(ServerErrorCode::BadRequest, "{}", e)).boxed();
                    let req = Request::from_parts(parts, req);
                    server.serve_request(req, info).await
                }
            })).await.map_err(|e| server_err!(ServerErrorCode::StreamError, "{e}"))?;
    } else if server.http_version() == http::Version::HTTP_3 && server.http3_port().is_some() {
        hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(stream), hyper::service::service_fn(|req| {
                let server = server.clone();
                let info = info.clone();
                async move {
                    let (parts, body) = req.into_parts();
                    let req = Request::new(BoxBody::new(body))
                        .map_err(|e| server_err!(ServerErrorCode::BadRequest, "{}", e)).boxed();
                    let req = Request::from_parts(parts, req);
                    let http3_port = server.http3_port().unwrap();
                    match server.serve_request(req, info).await {
                        Ok(mut res) => {
                            res.headers_mut().insert(
                                http::header::ALT_SVC,
                                http::HeaderValue::from_str(format!("h3=\":{http3_port}\"; ma=86400").as_str()).unwrap(),
                            );
                            Ok(res)
                        },
                        Err(e) => Err(e),
                    }
                }
            })).await.map_err(|e| server_err!(ServerErrorCode::StreamError, "{e}"))?;
    } else {
        hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(stream), hyper::service::service_fn(|req| {
                let server = server.clone();
                let info = info.clone();
                async move {
                    let (parts, body) = req.into_parts();
                    let req = Request::new(BoxBody::new(body))
                        .map_err(|e| server_err!(ServerErrorCode::BadRequest, "{}", e)).boxed();
                    let req = Request::from_parts(parts, req);
                    server.serve_request(req, info).await
                }
            })).await.map_err(|e| server_err!(ServerErrorCode::StreamError, "{e}"))?;
    }

    Ok(())
}

pub async fn hyper_serve_http1(stream: Box<dyn AsyncStream>, server: Arc<dyn HttpServer>, info: StreamInfo) -> ServerResult<()> {
    hyper::server::conn::http1::Builder::new()
        .serve_connection(TokioIo::new(stream), hyper::service::service_fn(|req| {
            let server = server.clone();
            let info = info.clone();
            async move {
                let (parts, body) = req.into_parts();
                let req = Request::new(BoxBody::new(body))
                    .map_err(|e| server_err!(ServerErrorCode::BadRequest, "{}", e)).boxed();
                let req = Request::from_parts(parts, req);
                server.serve_request(req, info).await
            }
        })).await.map_err(|e| server_err!(ServerErrorCode::StreamError, "{e}"))?;
    Ok(())
}
