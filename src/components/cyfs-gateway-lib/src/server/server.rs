use crate::server::dns_server::NameServer;
use crate::{
    HttpServer, QAServer, ServerError, ServerErrorCode, ServerResult, StreamInfo, server_err,
};
use as_any::AsAny;
use buckyos_kit::AsyncStream;
use cyfs_process_chain::{
    CollectionValue, EnvRef, HTTP_REQUEST_HEADER_VARS, MapCollection,
    MapCollectionTraverseCallBackRef, TraverseGuard, VariableVisitor,
    VariableVisitorWrapperForMapCollection,
};
use http::uri::{Parts, PathAndQuery};
use http::{HeaderName, Method, Uri};
use http_body_util::combinators::BoxBody;
use hyper::body::Bytes;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::atomic::AtomicU32;
use std::sync::{Arc, Mutex, Weak};
use tokio::sync::RwLock;

pub trait ServerConfig: AsAny + Send + Sync {
    fn id(&self) -> String;
    fn server_type(&self) -> String;
    fn get_config_json(&self) -> String;
}

pub trait ServerContext: AsAny + Send + Sync {
    fn get_server_type(&self) -> String;
}
pub type ServerContextRef = Arc<dyn ServerContext>;

#[async_trait::async_trait]
#[callback_trait::callback_trait]
pub trait ServerFactory: Send + Sync {
    async fn create(
        &self,
        config: Arc<dyn ServerConfig>,
        context: Option<ServerContextRef>,
    ) -> ServerResult<Vec<Server>>;
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
        self.server_factory
            .lock()
            .unwrap()
            .insert(server_type, factory);
    }
}

#[async_trait::async_trait]
impl ServerFactory for CyfsServerFactory {
    async fn create(
        &self,
        config: Arc<dyn ServerConfig>,
        context: Option<ServerContextRef>,
    ) -> ServerResult<Vec<Server>> {
        let factory = {
            self.server_factory
                .lock()
                .unwrap()
                .get(config.server_type().as_str())
                .cloned()
        };
        match factory {
            Some(factory) => factory.create(config, context).await,
            None => Err(server_err!(
                ServerErrorCode::UnknownServerType,
                "unknown server type {}",
                config.server_type()
            )),
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
pub struct HttpRequestProcessChainVars {
    pub req_remote_ip: Option<String>,
    pub req_remote_port: Option<String>,
    pub req_conn_remote_ip: Option<String>,
    pub req_conn_remote_port: Option<String>,
    pub req_real_remote_ip: Option<String>,
    pub req_real_remote_port: Option<String>,
}

/// Source variables resolved from a [`StreamInfo`] (and optionally from
/// trusted forwarded headers) for one HTTP request.
///
/// - `source_*`: effective source seen by this hook point (real source when a
///   trusted restore exists, otherwise the connection source)
/// - `conn_source_*`: connection-layer direct previous hop
/// - `real_source_*`: source restored through a trusted mechanism only; never
///   fabricated when no trusted mechanism applies
///
/// `*_addr` keeps the raw address string (usually `IP:PORT`, may be a bare IP
/// when restored from forwarded headers); `*_ip` / `*_port` are only present
/// when they can be derived.
#[derive(Default, Debug, Clone)]
pub struct RequestSourceInfo {
    pub source_addr: Option<String>,
    pub source_ip: Option<String>,
    pub source_port: Option<String>,
    pub conn_source_addr: Option<String>,
    pub conn_source_ip: Option<String>,
    pub conn_source_port: Option<String>,
    pub real_source_addr: Option<String>,
    pub real_source_ip: Option<String>,
    pub real_source_port: Option<String>,
}

/// Reserved source keys exposed through the HTTP `REQ` map. These keys always
/// resolve from the connection's [`RequestSourceInfo`] and never fall back to
/// same-named HTTP headers, so clients cannot forge them.
pub const HTTP_REQ_SOURCE_KEYS: [&str; 9] = [
    "source_addr",
    "source_ip",
    "source_port",
    "conn_source_addr",
    "conn_source_ip",
    "conn_source_port",
    "real_source_addr",
    "real_source_ip",
    "real_source_port",
];

fn addr_group_from_str(addr: &str) -> (Option<String>, Option<String>, Option<String>) {
    if let Ok(socket_addr) = addr.parse::<SocketAddr>() {
        (
            Some(addr.to_string()),
            Some(socket_addr.ip().to_string()),
            Some(socket_addr.port().to_string()),
        )
    } else if addr.parse::<std::net::IpAddr>().is_ok() {
        (Some(addr.to_string()), Some(addr.to_string()), None)
    } else {
        (Some(addr.to_string()), None, None)
    }
}

impl RequestSourceInfo {
    pub fn is_reserved_key(key: &str) -> bool {
        HTTP_REQ_SOURCE_KEYS.contains(&key)
    }

    pub fn from_stream_info(info: &StreamInfo) -> Self {
        let mut this = Self::default();
        if let Some(addr) = info.src_addr.as_deref() {
            (this.source_addr, this.source_ip, this.source_port) = addr_group_from_str(addr);
        }
        if let Some(addr) = info.conn_src_addr.as_deref() {
            (
                this.conn_source_addr,
                this.conn_source_ip,
                this.conn_source_port,
            ) = addr_group_from_str(addr);
        }
        if let Some(addr) = info.real_src_addr.as_deref() {
            (
                this.real_source_addr,
                this.real_source_ip,
                this.real_source_port,
            ) = addr_group_from_str(addr);
        }
        this
    }

    /// Install `addr` as the trusted restored source and make it the
    /// effective source as well.
    pub fn set_real_source(&mut self, addr: &str) {
        (
            self.real_source_addr,
            self.real_source_ip,
            self.real_source_port,
        ) = addr_group_from_str(addr);
        (self.source_addr, self.source_ip, self.source_port) = addr_group_from_str(addr);
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        let value = match key {
            "source_addr" => &self.source_addr,
            "source_ip" => &self.source_ip,
            "source_port" => &self.source_port,
            "conn_source_addr" => &self.conn_source_addr,
            "conn_source_ip" => &self.conn_source_ip,
            "conn_source_port" => &self.conn_source_port,
            "real_source_addr" => &self.real_source_addr,
            "real_source_ip" => &self.real_source_ip,
            "real_source_port" => &self.real_source_port,
            _ => &None,
        };
        value.as_deref()
    }

    fn present_entries(&self) -> Vec<(&'static str, String)> {
        HTTP_REQ_SOURCE_KEYS
            .iter()
            .filter_map(|key| self.get(key).map(|value| (*key, value.to_string())))
            .collect()
    }
}

// 流处理服务
#[async_trait::async_trait]
pub trait StreamServer: Send + Sync {
    async fn serve_connection(
        &self,
        stream: Box<dyn AsyncStream>,
        info: StreamInfo,
    ) -> ServerResult<()>;
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
    sources: Arc<RequestSourceInfo>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct HttpRequestHostOverride;

impl HttpRequestHeaderMap {
    pub fn new(request: http::Request<BoxBody<Bytes, ServerError>>) -> Self {
        Self {
            request: Arc::new(RwLock::new(request)),
            transverse_counter: Arc::new(AtomicU32::new(0)), // Initialize counter to 0
            sources: Arc::new(RequestSourceInfo::default()),
        }
    }

    pub fn new_with_sources(
        request: http::Request<BoxBody<Bytes, ServerError>>,
        sources: RequestSourceInfo,
    ) -> Self {
        Self {
            request: Arc::new(RwLock::new(request)),
            transverse_counter: Arc::new(AtomicU32::new(0)),
            sources: Arc::new(sources),
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

        env.create("REQ", CollectionValue::Map(coll)).await?;

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

        if RequestSourceInfo::is_reserved_key(key) {
            let msg = format!("Cannot insert read-only source variable '{}'", key);
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

        let overrides_host = name == http::header::HOST;
        request.headers_mut().insert(name, header);
        if overrides_host {
            request.extensions_mut().insert(HttpRequestHostOverride);
        }
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

        if RequestSourceInfo::is_reserved_key(key) {
            let msg = format!("Cannot set read-only source variable '{}'", key);
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
                    Some(
                        PathAndQuery::from_str(
                            format!("{}?{}", value.try_as_str()?, query).as_str(),
                        )
                        .map_err(|e| {
                            let msg = format!("Invalid path '{}': {}", value, e);
                            warn!("{}", msg);
                            msg.to_string()
                        })?,
                    )
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

            let overrides_host = name == http::header::HOST;
            let prev = request.headers_mut().insert(name, header);
            if overrides_host {
                request.extensions_mut().insert(HttpRequestHostOverride);
            }
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
        if RequestSourceInfo::is_reserved_key(key) {
            // Reserved source keys resolve from stream info only; a
            // same-named HTTP header must never shadow them.
            return Ok(self
                .sources
                .get(key)
                .map(|value| CollectionValue::String(value.to_string())));
        }

        let request = self.request.read().await;
        if key == "path" {
            Ok(Some(CollectionValue::String(
                request.uri().path().to_string(),
            )))
        } else if key == "method" {
            Ok(Some(CollectionValue::String(request.method().to_string())))
        } else if key == "uri" {
            Ok(Some(CollectionValue::String(request.uri().to_string())))
        } else if key == "version" {
            Ok(Some(CollectionValue::String(format!(
                "{:?}",
                request.version()
            ))))
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
        if RequestSourceInfo::is_reserved_key(key) {
            return Ok(self.sources.get(key).is_some());
        }
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

        if RequestSourceInfo::is_reserved_key(key) {
            let msg = format!("Cannot remove read-only source variable '{}'", key);
            warn!("{}", msg);
            return Err(msg);
        }

        let mut request = self.request.write().await;
        let prev = request.headers_mut().remove(key);
        if key.eq_ignore_ascii_case(http::header::HOST.as_str()) {
            request.extensions_mut().insert(HttpRequestHostOverride);
        }
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
        if !callback
            .call(
                "path",
                &CollectionValue::String(request.uri().path().to_string()),
            )
            .await?
        {
            return Ok(());
        }
        if !callback
            .call(
                "method",
                &CollectionValue::String(request.method().to_string()),
            )
            .await?
        {
            return Ok(());
        }
        if !callback
            .call("uri", &CollectionValue::String(request.uri().to_string()))
            .await?
        {
            return Ok(());
        }
        if !callback
            .call(
                "version",
                &CollectionValue::String(format!("{:?}", request.version())),
            )
            .await?
        {
            return Ok(());
        }
        for (key, value) in self.sources.present_entries() {
            if !callback.call(key, &CollectionValue::String(value)).await? {
                return Ok(());
            }
        }
        for (key, value) in request.headers().iter() {
            if RequestSourceInfo::is_reserved_key(key.as_str()) {
                // Reserved source keys never resolve to headers; skip the
                // colliding header to keep the traversal view consistent.
                continue;
            }
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
        result.push((
            "path".to_string(),
            CollectionValue::String(request.uri().path().to_string()),
        ));
        result.push((
            "method".to_string(),
            CollectionValue::String(request.method().to_string()),
        ));
        result.push((
            "uri".to_string(),
            CollectionValue::String(request.uri().to_string()),
        ));
        result.push((
            "version".to_string(),
            CollectionValue::String(format!("{:?}", request.version())),
        ));
        for (key, value) in self.sources.present_entries() {
            result.push((key.to_string(), CollectionValue::String(value)));
        }
        for (key, value) in request.headers().iter() {
            if RequestSourceInfo::is_reserved_key(key.as_str()) {
                continue;
            }
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

#[derive(Clone)]
pub struct HttpResponseHeaderMap {
    response: Arc<RwLock<http::Response<BoxBody<Bytes, ServerError>>>>,
    transverse_counter: Arc<AtomicU32>,
}

impl HttpResponseHeaderMap {
    pub fn new(response: http::Response<BoxBody<Bytes, ServerError>>) -> Self {
        Self {
            response: Arc::new(RwLock::new(response)),
            transverse_counter: Arc::new(AtomicU32::new(0)),
        }
    }

    fn is_during_traversal(&self) -> bool {
        self.transverse_counter
            .load(std::sync::atomic::Ordering::SeqCst)
            > 0
    }

    pub fn into_response(self) -> Result<http::Response<BoxBody<Bytes, ServerError>>, String> {
        let resp = Arc::try_unwrap(self.response)
            .map_err(|_| {
                let msg = "Failed to unwrap HttpResponseHeaderMap".to_string();
                error!("{}", msg);
                msg
            })?
            .into_inner();

        Ok(resp)
    }

    pub async fn register_visitors(&self, env: &EnvRef) -> Result<(), String> {
        let coll = Arc::new(Box::new(self.clone()) as Box<dyn MapCollection>);
        env.create("RESP", CollectionValue::Map(coll)).await?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl MapCollection for HttpResponseHeaderMap {
    async fn len(&self) -> Result<usize, String> {
        let response = self.response.read().await;
        Ok(response.headers().len())
    }

    async fn insert_new(&self, key: &str, value: CollectionValue) -> Result<bool, String> {
        if self.is_during_traversal() {
            let msg = format!("Cannot insert new header '{}' during traversal", key);
            warn!("{}", msg);
            return Err(msg);
        }

        let mut response = self.response.write().await;
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

        if response.headers().contains_key(&name) {
            let msg = format!("Header '{}' already exists", key);
            warn!("{}", msg);
            return Ok(false);
        }

        response.headers_mut().insert(name, header);
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

        let mut response = self.response.write().await;
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

        let prev = response.headers_mut().insert(name, header);
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
        let response = self.response.read().await;
        let ret = response.headers().get(key);
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
        let response = self.response.read().await;
        Ok(response.headers().get(key).is_some())
    }

    async fn remove(&self, key: &str) -> Result<Option<CollectionValue>, String> {
        if self.is_during_traversal() {
            let msg = format!("Cannot remove header '{}' during traversal", key);
            warn!("{}", msg);
            return Err(msg);
        }

        let mut response = self.response.write().await;
        let prev = response.headers_mut().remove(key);
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

        let response = self.response.read().await;
        for (key, value) in response.headers().iter() {
            if let Ok(value_str) = value.to_str() {
                if !callback
                    .call(key.as_str(), &CollectionValue::String(value_str.to_owned()))
                    .await?
                {
                    break;
                }
            } else {
                warn!("Header value for '{}' is not valid UTF-8", key);
            }
        }
        Ok(())
    }

    async fn dump(&self) -> Result<Vec<(String, CollectionValue)>, String> {
        let response = self.response.read().await;
        let mut result = Vec::new();
        for (key, value) in response.headers().iter() {
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
    pub fn new(
        request: Arc<RwLock<http::Request<BoxBody<Bytes, ServerError>>>>,
        read_only: bool,
    ) -> Self {
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

        debug!("Set request url variable '{}' to '{}'", id, value);
        Ok(Some(CollectionValue::String(old_value)))
    }
}

pub struct DatagramInfo {
    pub src_addr: Option<String>,
    pub dst_addr: Option<String>,
    pub source_mac: Option<String>,
    pub source_hostname: Option<String>,
    pub source_online_secs: Option<String>,
}

impl DatagramInfo {
    pub fn new(src_addr: Option<String>) -> Self {
        DatagramInfo {
            src_addr,
            dst_addr: None,
            source_mac: None,
            source_hostname: None,
            source_online_secs: None,
        }
    }

    pub fn with_dst_addr(mut self, dst_addr: Option<String>) -> Self {
        self.dst_addr = dst_addr;
        self
    }

    pub fn with_device_info(
        mut self,
        source_mac: Option<String>,
        source_hostname: Option<String>,
        source_online_secs: Option<String>,
    ) -> Self {
        self.source_mac = source_mac;
        self.source_hostname = source_hostname;
        self.source_online_secs = source_online_secs;
        self
    }
}

#[async_trait::async_trait]
pub trait DatagramServer: Send + Sync + 'static {
    async fn serve_datagram(&self, buf: &[u8], info: DatagramInfo) -> ServerResult<Vec<u8>>;
    fn id(&self) -> String;
}

pub struct ServerManager {
    // key 格式: "$id.$trait_type", 例如 "my-server.http", "my-server.stream"
    servers: Mutex<HashMap<String, Server>>,
}

impl Drop for ServerManager {
    fn drop(&mut self) {
        log::debug!("ServerManager dropped");
    }
}

impl ServerManager {
    pub fn new() -> Self {
        ServerManager {
            servers: Mutex::new(HashMap::new()),
        }
    }

    pub fn clone_manager(&self) -> ServerManager {
        let new = ServerManager {
            servers: Mutex::new(HashMap::new()),
        };

        for (key, server) in self.servers.lock().unwrap().iter() {
            new.servers
                .lock()
                .unwrap()
                .insert(key.clone(), server.clone());
        }
        new
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
        servers
            .iter()
            .find(|(key, _)| key.starts_with(&prefix))
            .map(|(_, server)| server.clone())
    }

    /// 获取某个 id 的所有 trait 实现
    pub fn get_all_servers_by_id(&self, id: &str) -> Vec<Server> {
        let servers = self.servers.lock().unwrap();
        let prefix = format!("{}.", id);

        servers
            .iter()
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
        self.servers
            .lock()
            .unwrap()
            .retain(|key, _| !key.starts_with(&prefix) && key.as_str() != id);
    }

    /// 保留满足条件的 server (key 为完整的 full_key)
    pub fn retain(&self, f: impl Fn(&str) -> bool) {
        self.servers
            .lock()
            .unwrap()
            .retain(|key, _| f(key.as_str()));
    }
}

pub type ServerManagerRef = Arc<ServerManager>;
pub type ServerManagerWeakRef = Weak<ServerManager>;

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::{BodyExt, Full};

    fn test_request(headers: &[(&str, &str)]) -> http::Request<BoxBody<Bytes, ServerError>> {
        let mut builder = http::Request::builder().method("GET").uri("/test");
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        builder
            .body(Full::new(Bytes::new()).map_err(|e| match e {}).boxed())
            .unwrap()
    }

    #[test]
    fn test_request_source_info_from_stream_info() {
        let info = StreamInfo::with_addrs(
            Some("127.0.0.1:9000".to_string()),
            Some("198.51.100.7:6001".to_string()),
        );
        let sources = RequestSourceInfo::from_stream_info(&info);
        assert_eq!(sources.source_ip.as_deref(), Some("198.51.100.7"));
        assert_eq!(sources.source_port.as_deref(), Some("6001"));
        assert_eq!(sources.conn_source_addr.as_deref(), Some("127.0.0.1:9000"));
        assert_eq!(sources.real_source_ip.as_deref(), Some("198.51.100.7"));

        // Bare-IP real source (e.g. restored from X-Forwarded-For): the ip is
        // derivable but the port is not.
        let mut sources =
            RequestSourceInfo::from_stream_info(&StreamInfo::new("192.168.1.9:5555".to_string()));
        assert_eq!(sources.real_source_addr, None);
        sources.set_real_source("203.0.113.7");
        assert_eq!(sources.real_source_addr.as_deref(), Some("203.0.113.7"));
        assert_eq!(sources.real_source_ip.as_deref(), Some("203.0.113.7"));
        assert_eq!(sources.real_source_port, None);
        // Effective source follows the restored value.
        assert_eq!(sources.source_ip.as_deref(), Some("203.0.113.7"));
    }

    #[tokio::test]
    async fn test_http_req_map_reserved_source_keys() {
        let info = StreamInfo::with_addrs(
            Some("127.0.0.1:9000".to_string()),
            Some("198.51.100.7:6001".to_string()),
        );
        let sources = RequestSourceInfo::from_stream_info(&info);
        // Forged same-named headers must never shadow the reserved keys.
        let req = test_request(&[("source_ip", "6.6.6.6"), ("x-plain", "1")]);
        let map = HttpRequestHeaderMap::new_with_sources(req, sources);

        let get = |key: &str| {
            let map = map.clone();
            let key = key.to_string();
            async move {
                map.get(&key)
                    .await
                    .unwrap()
                    .map(|v| v.try_as_str().unwrap().to_string())
            }
        };

        assert_eq!(get("source_ip").await.as_deref(), Some("198.51.100.7"));
        assert_eq!(
            get("source_addr").await.as_deref(),
            Some("198.51.100.7:6001")
        );
        assert_eq!(get("conn_source_ip").await.as_deref(), Some("127.0.0.1"));
        assert_eq!(get("conn_source_port").await.as_deref(), Some("9000"));
        assert_eq!(get("real_source_ip").await.as_deref(), Some("198.51.100.7"));
        // Normal headers still resolve.
        assert_eq!(get("x-plain").await.as_deref(), Some("1"));

        assert!(map.contains_key("real_source_addr").await.unwrap());

        // Reserved keys are read-only.
        assert!(
            map.insert("source_ip", CollectionValue::String("9.9.9.9".to_string()))
                .await
                .is_err()
        );
        assert!(
            map.insert_new(
                "real_source_ip",
                CollectionValue::String("9.9.9.9".to_string())
            )
            .await
            .is_err()
        );
        assert!(map.remove("conn_source_addr").await.is_err());

        // dump: reserved keys come from stream info; the forged header is
        // dropped so the view stays consistent with get().
        let dumped = map.dump().await.unwrap();
        let dumped: std::collections::HashMap<String, String> = dumped
            .into_iter()
            .map(|(k, v)| (k, v.try_as_str().unwrap().to_string()))
            .collect();
        assert_eq!(
            dumped.get("source_ip").map(String::as_str),
            Some("198.51.100.7")
        );
        assert_eq!(dumped.get("x-plain").map(String::as_str), Some("1"));
    }

    #[tokio::test]
    async fn test_http_req_map_absent_source_keys() {
        // No stream info at all: reserved keys resolve to None instead of
        // falling back to forged headers.
        let req = test_request(&[("real_source_ip", "7.7.7.7")]);
        let map = HttpRequestHeaderMap::new(req);
        assert!(map.get("real_source_ip").await.unwrap().is_none());
        assert!(!map.contains_key("real_source_ip").await.unwrap());
        assert!(map.get("source_addr").await.unwrap().is_none());
    }
}
