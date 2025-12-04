use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::sync::atomic::AtomicU32;
use ::kRPC::{RPCHandler, RPCRequest, RPCResponse};
use as_any::AsAny;
use buckyos_kit::AsyncStream;
use http::{HeaderName, Method, Request, Response, StatusCode, Uri};
use http::uri::{Parts, PathAndQuery};
use http_body_util::{BodyExt, Full};
use http_body_util::combinators::{BoxBody};
use hyper::body::{Bytes};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::sync::RwLock;
use cyfs_process_chain::{CollectionValue, EnvRef, MapCollection, MapCollectionTraverseCallBackRef, TraverseGuard, VariableVisitor, VariableVisitorWrapperForMapCollection, HTTP_REQUEST_HEADER_VARS};
use crate::server::dns_server::NameServer;
use crate::{server_err, ProcessChainConfig, ServerError, ServerErrorCode, ServerResult, QAServer};

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
    async fn create(&self, config: Arc<dyn ServerConfig>) -> ServerResult<Vec<Server>>;
}

pub struct CyfsServerFactory {
    server_factory: Mutex<HashMap<String, Arc<dyn ServerFactory>>>,
}
pub type CyfsServerFactoryRef = Arc<CyfsServerFactory>;

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
    async fn create(&self, config: Arc<dyn ServerConfig>) -> ServerResult<Vec<Server>> {
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
    Stream(Arc<dyn StreamServer>),
    Datagram(Arc<dyn DatagramServer>),

    QA(Arc<dyn QAServer>),
    NameServer(Arc<dyn NameServer>),
    Http(Arc<dyn HttpServer>),
}

impl Server {
    /// 获取 server 的基础 id（不含类型后缀）
    pub fn id(&self) -> String {
        match self {
            Server::Http(server) => server.id(),
            Server::Stream(server) => server.id(),
            Server::Datagram(server) => server.id(),
            Server::QA(server) => server.id(),
            Server::NameServer(server) => server.id(),
        }
    }

    /// 获取 server 的 trait 类型名称
    pub fn trait_type(&self) -> &'static str {
        match self {
            Server::Http(_) => "http",
            Server::Stream(_) => "stream",
            Server::Datagram(_) => "datagram",
            Server::QA(_) => "qa",
            Server::NameServer(_) => "ns",
        }
    }

    /// 获取完整的 server key: $id.$trait_type
    /// 例如: "my-server.http", "my-server.stream"
    pub fn full_key(&self) -> String {
        format!("{}.{}", self.id(), self.trait_type())
    }

    /// 根据 trait 类型构建完整 key
    pub fn build_key(id: &str, trait_type: &str) -> String {
        format!("{}.{}", id, trait_type)
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
}

pub fn str_to_http_version(version: &str) -> Option<http::Version> {
    match version.to_lowercase().as_str() {
        "http/0.9" => Some(http::Version::HTTP_09),
        "http/1.0" => Some(http::Version::HTTP_10),
        "http/1.1" => Some(http::Version::HTTP_11),
        "http/2" => Some(http::Version::HTTP_2),
        "http/3" => Some(http::Version::HTTP_3),
        _ => None,
    }
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
        let coll = Arc::new(Box::new(self.clone()) as Box<dyn MapCollection>);
        let mut wrapper = VariableVisitorWrapperForMapCollection::new(coll.clone());

        for item in HTTP_REQUEST_HEADER_VARS {
            wrapper.add_variable(item.0, item.1, item.2);
        }

        let visitor = Arc::new(Box::new(wrapper) as Box<dyn VariableVisitor>);
        for (id, _, _) in HTTP_REQUEST_HEADER_VARS {
            env.create(*id, CollectionValue::Visitor(visitor.clone()))
                .await?;
        }

        // Url visitor
        let url_visitor = HttpRequestUrlVisitor::new(self.request.clone(), false);
        let visitor = Arc::new(Box::new(url_visitor) as Box<dyn VariableVisitor>);
        env.create("REQ_url", CollectionValue::Visitor(visitor))
            .await?;

        env.create("REQ", CollectionValue::Map(coll))
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

        if key == "path" || key == "method" || key == "uri" || key == "version" {
            let msg = format!("Cannot insert new value '{}'", key);
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
        if key == "uri" {
            let old_value = CollectionValue::String(request.uri().to_string());
            *request.uri_mut() = Uri::try_from(value.try_as_str()?).map_err(|e| {
                let msg = format!("Invalid URI '{}': {}", value, e);
                warn!("{}", msg);
                msg.to_string()
            })?;
            Ok(Some(old_value))
        } else if key == "method" {
            let old_value = CollectionValue::String(request.method().to_string());
            *request.method_mut() = Method::from_str(value.try_as_str()?).map_err(|e| {
                let msg = format!("Invalid method '{}': {}", value, e);
                warn!("{}", msg);
                msg.to_string()
            })?;
            Ok(Some(old_value))
        } else if key == "version" {
            let old_value = CollectionValue::String(format!("{:?}", request.version()));
            *request.version_mut() = str_to_http_version(value.try_as_str()?).ok_or({
                let msg = format!("Invalid HTTP version '{}'", value);
                warn!("{}", msg);
                msg.to_string()
            })?;
            Ok(Some(old_value))
        } else if key == "path" {
            let old_value = CollectionValue::String(request.uri().path().to_string());
            let mut parts = Parts::from(request.uri().clone());
            parts.path_and_query = if parts.path_and_query.is_none() {
                Some(PathAndQuery::from_str(value.try_as_str()?).map_err(|e| {
                    let msg = format!("Invalid path '{}': {}", value, e);
                    warn!("{}", msg);
                    msg.to_string()
                })?)
            } else {
                let query = parts.path_and_query.as_ref().unwrap().query();
                if let Some(query) = query {
                    Some(PathAndQuery::from_str(format!("{}?{}", value.try_as_str()?, query).as_str()).map_err(|e| {
                        let msg = format!("Invalid path '{}': {}", value, e);
                        warn!("{}", msg);
                        msg.to_string()
                    })?)
                } else {
                    Some(PathAndQuery::from_str(value.try_as_str()?).map_err(|e| {
                        let msg = format!("Invalid path '{}': {}", value, e);
                        warn!("{}", msg);
                        msg.to_string()
                    })?)
                }
            };
            *request.uri_mut() = Uri::from_parts(parts).map_err(|e| {
                let msg = format!("Invalid path '{}': {}", value, e);
                warn!("{}", msg);
                msg.to_string()
            })?;
            Ok(Some(old_value))
        } else {
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

    }

    async fn get(&self, key: &str) -> Result<Option<CollectionValue>, String> {
        let request = self.request.read().await;
        if key == "path" {
            Ok(Some(CollectionValue::String(request.uri().path().to_string())))
        } else if key == "method" {
            Ok(Some(CollectionValue::String(request.method().to_string())))
        } else if key == "uri" {
            Ok(Some(CollectionValue::String(request.uri().to_string())))
        } else if key == "version" {
            Ok(Some(CollectionValue::String(format!("{:?}", request.version()))))
        } else {
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
    }

    async fn contains_key(&self, key: &str) -> Result<bool, String> {
        let request = self.request.read().await;
        if key == "path" || key == "method" || key == "uri" || key == "version" {
            return Ok(true);
        }
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
        if !callback.call("path", &CollectionValue::String(request.uri().path().to_string())).await? {
            return Ok(());
        }
        if !callback.call("method", &CollectionValue::String(request.method().to_string())).await? {
            return Ok(());
        }
        if !callback.call("uri", &CollectionValue::String(request.uri().to_string())).await? {
            return Ok(());
        }
        if !callback.call("version", &CollectionValue::String(format!("{:?}", request.version()))).await? {
            return Ok(());
        }
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
        result.push(("path".to_string(), CollectionValue::String(request.uri().path().to_string())));
        result.push(("method".to_string(), CollectionValue::String(request.method().to_string())));
        result.push(("uri".to_string(), CollectionValue::String(request.uri().to_string())));
        result.push(("version".to_string(), CollectionValue::String(format!("{:?}", request.version()))));
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
}

pub async fn serve_http_by_rpc_handler<T: RPCHandler + Send + Sync + 'static>(
    req: http::Request<BoxBody<Bytes, ServerError>>,
    info: StreamInfo,
    rpc_handler: &T,
) -> ServerResult<http::Response<BoxBody<Bytes, ServerError>>> {
    if req.method() != hyper::Method::POST {
        return Ok(http::Response::builder()
            .status(hyper::StatusCode::METHOD_NOT_ALLOWED)
            .body(BoxBody::new(
                http_body_util::Full::new(Bytes::from_static(b"Method Not Allowed"))
                    .map_err(|never| match never {})
                    .boxed(),
            ))
            .map_err(|e| server_err!(ServerErrorCode::BadRequest, "Failed to build response: {}", e))?);
    }

    let client_ip = match info.src_addr.as_ref() {
        Some(addr) => match addr.parse::<std::net::SocketAddr>() {
            Ok(sa) => sa.ip(),
            Err(e) => {
                error!("parse client ip {} err {}", addr, e);
                return Ok(http::Response::builder()
                    .status(hyper::StatusCode::BAD_REQUEST)
                    .body(BoxBody::new(
                        http_body_util::Full::new(Bytes::from_static(b"Bad Request"))
                            .map_err(|never| match never {})
                            .boxed(),
                    ))
                    .map_err(|e| server_err!(ServerErrorCode::BadRequest, "Failed to build response: {}", e))?);
            }
        },
        None => {
            error!("Failed to get client ip");
            return Ok(http::Response::builder()
                .status(hyper::StatusCode::BAD_REQUEST)
                .body(BoxBody::new(
                    http_body_util::Full::new(Bytes::from_static(b"Bad Request"))
                        .map_err(|never| match never {})
                        .boxed(),
                ))
                .map_err(|e| server_err!(ServerErrorCode::BadRequest, "Failed to build response: {}", e))?);
        }
    };

    let body_bytes = match req.collect().await {
        Ok(data) => data.to_bytes(),
        Err(e) => {
            return Ok(http::Response::builder()
                .status(hyper::StatusCode::BAD_REQUEST)
                .body(BoxBody::new(
                    http_body_util::Full::new(Bytes::from(format!("Failed to read body: {:?}", e)))
                        .map_err(|never| match never {})
                        .boxed(),
                ))
                .map_err(|e| server_err!(ServerErrorCode::BadRequest, "Failed to build response: {}", e))?);
        }
    };

    let body_str = match String::from_utf8(body_bytes.to_vec()) {
        Ok(s) => s,
        Err(e) => {
            return Ok(http::Response::builder()
                .status(hyper::StatusCode::BAD_REQUEST)
                .body(BoxBody::new(
                    http_body_util::Full::new(Bytes::from(format!("Failed to convert body to string: {}", e)))
                        .map_err(|never| match never {})
                        .boxed(),
                ))
                .map_err(|e| server_err!(ServerErrorCode::BadRequest, "Failed to build response: {}", e))?);
        }
    };

    debug!("|==>recv kRPC req: {}", body_str);

    let rpc_request: RPCRequest = match serde_json::from_str(body_str.as_str()) {
        Ok(rpc_request) => rpc_request,
        Err(e) => {
            return Ok(http::Response::builder()
                .status(hyper::StatusCode::BAD_REQUEST)
                .body(BoxBody::new(
                    http_body_util::Full::new(Bytes::from(format!(
                        "Failed to parse request body to RPCRequest: {}",
                        e
                    )))
                    .map_err(|never| match never {})
                    .boxed(),
                ))
                .map_err(|e| server_err!(ServerErrorCode::BadRequest, "Failed to build response: {}", e))?);
        }
    };

    let resp: RPCResponse = match rpc_handler.handle_rpc_call(rpc_request, client_ip).await {
        Ok(resp) => resp,
        Err(e) => {
            return Ok(http::Response::builder()
                .status(hyper::StatusCode::INTERNAL_SERVER_ERROR)
                .body(BoxBody::new(
                    http_body_util::Full::new(Bytes::from(format!("Failed to handle rpc call: {}", e)))
                        .map_err(|never| match never {})
                        .boxed(),
                ))
                .map_err(|e| server_err!(ServerErrorCode::InvalidData, "Failed to build response: {}", e))?);
        }
    };

    let body_json = serde_json::to_string(&resp)
        .map_err(|e| server_err!(ServerErrorCode::EncodeError, "Failed to convert response to string: {}", e))?;

    Ok(http::Response::builder()
        .body(BoxBody::new(
            http_body_util::Full::new(Bytes::from(body_json))
                .map_err(|never| match never {})
                .boxed(),
        ))
        .map_err(|e| server_err!(ServerErrorCode::InvalidData, "Failed to build response: {}", e))?)
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
}

pub struct ServerManager {
    // key 格式: "$id.$trait_type", 例如 "my-server.http", "my-server.stream"
    servers: Mutex<HashMap<String, Server>>
}

impl ServerManager {
    pub fn new() -> Self {
        ServerManager {
            servers: Mutex::new(HashMap::new()),
        }
    }

    /// 添加 server，使用 full_key 作为存储键
    /// 同一个 id 的 server 可以注册多个不同的 trait 类型
    pub fn add_server(&self, server: Server) -> ServerResult<()> {
        let full_key = server.full_key();

        if self.get_server_by_key(&full_key).is_some() {
            return Err(server_err!(
                ServerErrorCode::AlreadyExists,
                "Server {} already exists",
                full_key
            ));
        }

        self.servers.lock().unwrap().insert(full_key, server);
        Ok(())
    }

    /// 通过完整 key 获取 server: "$id.$trait_type"
    pub fn get_server_by_key(&self, key: &str) -> Option<Server> {
        self.servers.lock().unwrap().get(key).cloned()
    }

    /// 通过 id 和 trait_type 获取 server
    pub fn get_server_by_type(&self, id: &str, trait_type: &str) -> Option<Server> {
        let key = if id.contains(".") {
            id.to_string()
        } else {
            Server::build_key(id, trait_type)
        };

        let result = self.get_server_by_key(&key);
        if result.is_none() {
            return None;
        }
        let result = result.unwrap();
        if result.trait_type() == trait_type {
            return Some(result);
        }

        None
    }

    pub fn get_http_server(&self, id: &str) -> Option<Arc<dyn HttpServer>> {
        let server = self.get_server_by_type(id, "http");
        if server.is_none() {
            return None;
        }
        let server = server.unwrap();
        match server {
            Server::Http(server) => Some(server.clone()),
            _ => None,
        }
    }

    pub fn get_stream_server(&self, id: &str) -> Option<Arc<dyn StreamServer>> {
        let server = self.get_server_by_type(id, "stream");
        if server.is_none() {
            return None;
        }
        let server = server.unwrap();
        match server {
            Server::Stream(server) => Some(server.clone()),
            _ => None,
        }
    }

    pub fn get_datagram_server(&self, id: &str) -> Option<Arc<dyn DatagramServer>> {
        let server = self.get_server_by_type(id, "datagram");
        if server.is_none() {
            return None;
        }
        let server = server.unwrap();
        match server {
            Server::Datagram(server) => Some(server.clone()),
            _ => None,
        }
    }

    pub fn get_qa_server(&self, id: &str) -> Option<Arc<dyn QAServer>> {
        let server = self.get_server_by_type(id, "qa");
        if server.is_none() {
            return None;
        }
        let server = server.unwrap();
        match server {
            Server::QA(server) => Some(server.clone()),
            _ => None,
        }
    }

    pub fn get_name_server(&self, id: &str) -> Option<Arc<dyn NameServer>> {
        let server = self.get_server_by_type(id, "ns");
        if server.is_none() {
            return None;
        }
        let server = server.unwrap();
        match server {
            Server::NameServer(server) => Some(server.clone()),
            _ => None,
        }
    }
    /// 兼容旧接口：通过 id 获取第一个匹配的 server
    /// 如果一个 id 注册了多个 trait，返回任意一个
    pub fn get_server(&self, id: &str) -> Option<Server> {
        let servers = self.servers.lock().unwrap();
        let prefix = format!("{}.", id);

        // 先尝试精确匹配（向后兼容没有使用 full_key 的旧代码）
        if let Some(server) = servers.get(id) {
            return Some(server.clone());
        }

        // 再尝试前缀匹配
        servers.iter()
            .find(|(key, _)| key.starts_with(&prefix))
            .map(|(_, server)| server.clone())
    }

    /// 获取某个 id 的所有 trait 实现
    pub fn get_all_servers_by_id(&self, id: &str) -> Vec<Server> {
        let servers = self.servers.lock().unwrap();
        let prefix = format!("{}.", id);

        servers.iter()
            .filter(|(key, _)| key.starts_with(&prefix) || key.as_str() == id)
            .map(|(_, server)| server.clone())
            .collect()
    }

    /// 获取所有 server 的完整列表
    pub fn get_all_servers(&self) -> Vec<Server> {
        self.servers.lock().unwrap().values().cloned().collect()
    }

    /// 替换 server（使用 full_key）
    pub fn replace_server(&self, server: Server) {
        let full_key = server.full_key();
        self.servers.lock().unwrap().insert(full_key, server);
    }

    /// 删除指定的 server
    pub fn remove_server(&self, key: &str) -> Option<Server> {
        self.servers.lock().unwrap().remove(key)
    }

    /// 删除某个 id 的所有 server
    pub fn remove_servers_by_id(&self, id: &str) {
        let prefix = format!("{}.", id);
        self.servers.lock().unwrap().retain(|key, _| {
            !key.starts_with(&prefix) && key.as_str() != id
        });
    }

    /// 保留满足条件的 server (key 为完整的 full_key)
    pub fn retain(&self, f: impl Fn(&str) -> bool) {
        self.servers.lock().unwrap().retain(|key, _| f(key.as_str()));
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
                    match server.serve_request(req, info).await {
                        Ok(resp) => Ok(resp),
                        Err(e) => {
                            log::error!("http error {}", e);
                            Response::builder()
                                .status(StatusCode::INTERNAL_SERVER_ERROR)
                                .body(Full::new(Bytes::from(e.msg().to_string()))
                                    .map_err(|e| server_err!(ServerErrorCode::BadRequest, "{:?}", e)).boxed())
                                .map_err(|e| server_err!(ServerErrorCode::StreamError, "{:?}", e))
                        }
                    }
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
                        Err(e) => {
                            log::error!("http error {}", e);
                            Response::builder()
                                .status(StatusCode::INTERNAL_SERVER_ERROR)
                                .body(Full::new(Bytes::from(e.msg().to_string()))
                                    .map_err(|e| server_err!(ServerErrorCode::BadRequest, "{:?}", e)).boxed())
                                .map_err(|e| server_err!(ServerErrorCode::StreamError, "{:?}", e))
                        }
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
                    match server.serve_request(req, info).await {
                        Ok(resp) => Ok(resp),
                        Err(e) => {
                            log::error!("http error {}", e);
                            Response::builder()
                                .status(StatusCode::INTERNAL_SERVER_ERROR)
                                .body(Full::new(Bytes::from(e.msg().to_string()))
                                    .map_err(|e| server_err!(ServerErrorCode::BadRequest, "{:?}", e)).boxed())
                                .map_err(|e| server_err!(ServerErrorCode::StreamError, "{:?}", e))
                        }
                    }
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
                match server.serve_request(req, info).await {
                    Ok(resp) => Ok(resp),
                    Err(e) => {
                        log::error!("http error {}", e);
                        Response::builder()
                            .status(StatusCode::INTERNAL_SERVER_ERROR)
                            .body(Full::new(Bytes::from(e.msg().to_string()))
                                .map_err(|e| server_err!(ServerErrorCode::BadRequest, "{:?}", e)).boxed())
                            .map_err(|e| server_err!(ServerErrorCode::StreamError, "{:?}", e))
                    }
                }
            }
        })).await.map_err(|e| server_err!(ServerErrorCode::StreamError, "{e}"))?;
    Ok(())
}
