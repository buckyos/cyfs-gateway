use crate::{StackErrorCode, StackResult, StreamInfo, stack_err};
use as_any::AsAny;
use buckyos_kit::AsyncStream;
use cyfs_process_chain::{CollectionValue, EnvRef, StreamRequest};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Weak;
use std::sync::{Arc, Mutex};

#[derive(PartialEq, Eq, Debug, Clone, Hash)]
pub enum StackProtocol {
    Tcp,
    Udp,
    Quic,
    Rtcp,
    Tls,
    Extension(String),
}

impl Serialize for StackProtocol {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(match self {
            StackProtocol::Tcp => "tcp",
            StackProtocol::Udp => "udp",
            StackProtocol::Quic => "quic",
            StackProtocol::Rtcp => "rtcp",
            StackProtocol::Tls => "tls",
            StackProtocol::Extension(name) => name.as_str(),
        })
    }
}

impl<'de> Deserialize<'de> for StackProtocol {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.to_lowercase().as_str() {
            "tcp" => Ok(StackProtocol::Tcp),
            "udp" => Ok(StackProtocol::Udp),
            "quic" => Ok(StackProtocol::Quic),
            "rtcp" => Ok(StackProtocol::Rtcp),
            "tls" => Ok(StackProtocol::Tls),
            _ => Ok(StackProtocol::Extension(s)),
        }
    }
}

pub trait StackConfig: AsAny + Send + Sync {
    fn id(&self) -> String;
    fn stack_protocol(&self) -> StackProtocol;
    fn get_config_json(&self) -> String;
}

pub trait StackContext: AsAny + Send + Sync {
    fn stack_protocol(&self) -> StackProtocol;
}

#[derive(Clone)]
pub struct StackStreamContext {
    pub ingress_stack_id: String,
    pub route: Vec<String>,
    pub conn_source_addr: Option<SocketAddr>,
    pub source_addr: Option<SocketAddr>,
    pub real_source_addr: Option<SocketAddr>,
    pub dest_addr: Option<SocketAddr>,
    pub dest_host: Option<String>,
    pub dest_port: u16,
    pub app_protocol: Option<String>,
    pub dest_url: Option<String>,
    pub source_mac: Option<String>,
    pub source_hostname: Option<String>,
    pub source_device_id: Option<String>,
    pub source_app_id: Option<String>,
    pub source_user_id: Option<String>,
}

impl StackStreamContext {
    pub fn from_request(ingress_stack_id: impl Into<String>, request: &StreamRequest) -> Self {
        let ingress_stack_id = ingress_stack_id.into();
        Self {
            route: vec![ingress_stack_id.clone()],
            ingress_stack_id,
            conn_source_addr: request.conn_source_addr,
            source_addr: request.source_addr,
            real_source_addr: request.real_source_addr,
            dest_addr: request.dest_addr,
            dest_host: request.dest_host.clone(),
            dest_port: request.dest_port,
            app_protocol: request.app_protocol.clone(),
            dest_url: request.dest_url.clone(),
            source_mac: request.source_mac.clone(),
            source_hostname: request.source_hostname.clone(),
            source_device_id: request.source_device_id.clone(),
            source_app_id: request.source_app_id.clone(),
            source_user_id: request.source_user_id.clone(),
        }
    }

    pub fn create_request(&self, stream: Box<dyn AsyncStream>) -> StreamRequest {
        let mut request = StreamRequest::new(
            stream,
            self.dest_addr
                .or(self.source_addr)
                .unwrap_or_else(|| "0.0.0.0:0".parse().unwrap()),
        );
        request.dest_port = self.dest_port;
        request.dest_host = self.dest_host.clone();
        request.dest_addr = self.dest_addr;
        request.app_protocol = self.app_protocol.clone();
        request.dest_url = self.dest_url.clone();
        request.source_addr = self.source_addr;
        request.conn_source_addr = self.conn_source_addr;
        request.real_source_addr = self.real_source_addr;
        request.source_mac = self.source_mac.clone();
        request.source_hostname = self.source_hostname.clone();
        request.source_device_id = self.source_device_id.clone();
        request.source_app_id = self.source_app_id.clone();
        request.source_user_id = self.source_user_id.clone();
        request
    }

    pub async fn refresh_from_env(&mut self, env: &EnvRef) -> StackResult<()> {
        let req = match env.get("REQ").await {
            Ok(Some(CollectionValue::Map(req))) => req,
            Ok(_) => return Ok(()),
            Err(e) => {
                return Err(stack_err!(
                    StackErrorCode::ProcessChainError,
                    "read REQ for stack handoff failed: {}",
                    e
                ));
            }
        };

        macro_rules! refresh_string {
            ($key:literal, $field:ident) => {
                if let Some(CollectionValue::String(value)) = req.get($key).await.map_err(|e| {
                    stack_err!(
                        StackErrorCode::ProcessChainError,
                        "read REQ.{} for stack handoff failed: {}",
                        $key,
                        e
                    )
                })? {
                    self.$field = Some(value);
                }
            };
        }

        macro_rules! refresh_addr {
            ($key:literal, $field:ident) => {
                if let Some(CollectionValue::String(value)) = req.get($key).await.map_err(|e| {
                    stack_err!(
                        StackErrorCode::ProcessChainError,
                        "read REQ.{} for stack handoff failed: {}",
                        $key,
                        e
                    )
                })? {
                    self.$field = Some(value.parse().map_err(|e| {
                        stack_err!(
                            StackErrorCode::ProcessChainError,
                            "invalid REQ.{} address {}: {}",
                            $key,
                            value,
                            e
                        )
                    })?);
                }
            };
        }

        refresh_addr!("conn_source_addr", conn_source_addr);
        refresh_addr!("source_addr", source_addr);
        refresh_addr!("real_source_addr", real_source_addr);
        refresh_addr!("dest_addr", dest_addr);
        refresh_string!("dest_host", dest_host);
        refresh_string!("app_protocol", app_protocol);
        refresh_string!("dest_url", dest_url);
        refresh_string!("source_mac", source_mac);
        refresh_string!("source_hostname", source_hostname);
        refresh_string!("source_device_id", source_device_id);
        refresh_string!("source_app_id", source_app_id);
        refresh_string!("source_user_id", source_user_id);
        if let Some(CollectionValue::String(value)) = req.get("dest_port").await.map_err(|e| {
            stack_err!(
                StackErrorCode::ProcessChainError,
                "read REQ.dest_port for stack handoff failed: {}",
                e
            )
        })? {
            self.dest_port = value.parse().map_err(|e| {
                stack_err!(
                    StackErrorCode::ProcessChainError,
                    "invalid REQ.dest_port {}: {}",
                    value,
                    e
                )
            })?;
        }
        Ok(())
    }

    pub fn stream_info(&self, source_online_secs: Option<String>) -> StreamInfo {
        StreamInfo::with_addrs(
            self.conn_source_addr.map(|addr| addr.to_string()),
            self.real_source_addr.map(|addr| addr.to_string()),
        )
        .with_dst_addr(self.dest_addr.map(|addr| addr.to_string()))
        .with_device_info(
            self.source_mac.clone(),
            self.source_hostname.clone(),
            source_online_secs,
        )
    }
}

#[async_trait::async_trait]
pub trait StreamStack: Stack {
    async fn serve_stream(
        &self,
        stream: Box<dyn AsyncStream>,
        context: StackStreamContext,
    ) -> StackResult<()>;
}

#[async_trait::async_trait]
pub trait Stack: Send + Sync + 'static {
    fn id(&self) -> String;
    fn stack_protocol(&self) -> StackProtocol;
    fn get_bind_addr(&self) -> String;
    async fn start(&self) -> StackResult<()>;
    async fn update_config(&self, config: Arc<dyn StackConfig>) -> StackResult<()> {
        self.prepare_update(config, None).await?;
        self.commit_update().await;
        Ok(())
    }
    async fn prepare_update(
        &self,
        config: Arc<dyn StackConfig>,
        context: Option<Arc<dyn StackContext>>,
    ) -> StackResult<()>;
    async fn commit_update(&self);
    async fn rollback_update(&self);

    fn as_stream_stack(&self) -> Option<&dyn StreamStack> {
        None
    }
}

pub type StackRef = Arc<dyn Stack>;

pub struct StackManager {
    stacks: Mutex<Vec<StackRef>>,
}
pub type StackManagerRef = Arc<StackManager>;
pub type StackManagerWeakRef = Weak<StackManager>;

impl StackManager {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            stacks: Mutex::new(vec![]),
        })
    }

    pub fn add_stack(&self, stack: StackRef) -> StackResult<()> {
        if self.get_stack(stack.id().as_str()).is_some() {
            return Err(stack_err!(
                StackErrorCode::AlreadyExists,
                "stack {} already exists",
                stack.id()
            ));
        }
        self.stacks.lock().unwrap().push(stack);
        Ok(())
    }

    pub async fn start(&self) -> StackResult<()> {
        let mut stacks = Vec::new();
        for stack in self.stacks.lock().unwrap().iter() {
            stacks.push(stack.clone());
        }
        for stack in stacks.iter() {
            stack.start().await?;
        }
        Ok(())
    }

    pub fn get_stack(&self, id: &str) -> Option<StackRef> {
        for stack in self.stacks.lock().unwrap().iter() {
            if stack.id() == id {
                return Some(stack.clone());
            }
        }
        None
    }

    pub async fn serve_stream(
        &self,
        target_id: &str,
        stream: Box<dyn AsyncStream>,
        mut context: StackStreamContext,
    ) -> StackResult<()> {
        let target = self.get_stack(target_id).ok_or_else(|| {
            stack_err!(
                StackErrorCode::StackNotFound,
                "stack handoff target {} not found",
                target_id
            )
        })?;
        if context.route.iter().any(|id| id == target_id) {
            return Err(stack_err!(
                StackErrorCode::StackHandoffCycle,
                "stack handoff cycle detected: {} -> {}",
                context.route.join(" -> "),
                target_id
            ));
        }
        let stream_stack = target.as_stream_stack().ok_or_else(|| {
            stack_err!(
                StackErrorCode::IncompatibleStack,
                "stack handoff target {} does not accept ordered streams",
                target_id
            )
        })?;
        context.route.push(target_id.to_string());
        stream_stack.serve_stream(stream, context).await
    }

    pub fn retain<F>(&self, f: F)
    where
        F: Fn(&str) -> bool,
    {
        let mut stacks = self.stacks.lock().unwrap();
        stacks.retain(|stack| f(stack.id().as_str()));
    }

    pub fn remove(&self, id: &str) {
        self.retain(|stack_id| stack_id != id);
    }
}

#[async_trait::async_trait]
pub trait StackFactory: Send + Sync {
    async fn create(
        &self,
        config: Arc<dyn StackConfig>,
        context: Arc<dyn StackContext>,
    ) -> StackResult<StackRef>;
}

pub struct CyfsStackFactory {
    stack_factory: Mutex<HashMap<StackProtocol, Arc<dyn StackFactory>>>,
}
pub type CyfsStackFactoryRef = Arc<CyfsStackFactory>;

impl Default for CyfsStackFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl CyfsStackFactory {
    pub fn new() -> Self {
        Self {
            stack_factory: Mutex::new(HashMap::new()),
        }
    }

    pub fn register(&self, protocol: StackProtocol, factory: Arc<dyn StackFactory>) {
        self.stack_factory.lock().unwrap().insert(protocol, factory);
    }
}

#[async_trait::async_trait]
impl StackFactory for CyfsStackFactory {
    async fn create(
        &self,
        config: Arc<dyn StackConfig>,
        context: Arc<dyn StackContext>,
    ) -> StackResult<StackRef> {
        let protocol = config.stack_protocol();
        let factory = { self.stack_factory.lock().unwrap().get(&protocol).cloned() };
        if factory.is_none() {
            return Err(stack_err!(
                StackErrorCode::UnsupportedStackProtocol,
                "unsupported stack protocol {:?}",
                protocol
            ));
        }
        factory.unwrap().create(config, context).await
    }
}
