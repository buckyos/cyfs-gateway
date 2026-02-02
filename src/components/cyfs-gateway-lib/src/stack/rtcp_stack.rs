use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};
use buckyos_kit::AsyncStream;
use name_lib::{encode_ed25519_pkcs8_sk_to_pk, get_x_from_jwk, load_raw_private_key, DeviceConfig};
use sfo_io::{LimitStream, StatStream};
use cyfs_process_chain::{CollectionValue, CommandControl, MemoryMapCollection, ProcessChainLibExecutor};
use crate::{hyper_serve_http, into_stack_err, stack_err, ConnectionInfo, ConnectionManagerRef, HandleConnectionController, ProcessChainConfigs, RTcp, RTcpListener, Server, ServerManagerRef, Stack, StackRef, StackConfig, StackContext, StackErrorCode, StackFactory, StackProtocol, StackResult, TunnelBox, TunnelBuilder, TunnelEndpoint, TunnelManager, TunnelResult, StreamInfo, ProcessChainConfig, get_min_priority, DatagramInfo, LimiterManagerRef, StatManagerRef, MutComposedSpeedStat, MutComposedSpeedStatRef, get_stat_info, TunnelError, has_scheme, GlobalCollectionManagerRef, get_external_commands};
use crate::global_process_chains::{create_process_chain_executor, execute_chain, GlobalProcessChainsRef};
use crate::rtcp::{AsyncStreamWithDatagram, RTcpTunnelDatagramClient};
use crate::stack::limiter::Limiter;
use crate::stack::{datagram_forward, get_limit_info, stream_forward};
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Clone)]
pub struct RtcpStackContext {
    pub servers: ServerManagerRef,
    pub tunnel_manager: TunnelManager,
    pub limiter_manager: LimiterManagerRef,
    pub stat_manager: StatManagerRef,
    pub global_process_chains: Option<GlobalProcessChainsRef>,
    pub global_collection_manager: Option<GlobalCollectionManagerRef>,
}

impl RtcpStackContext {
    pub fn new(
        servers: ServerManagerRef,
        tunnel_manager: TunnelManager,
        limiter_manager: LimiterManagerRef,
        stat_manager: StatManagerRef,
        global_process_chains: Option<GlobalProcessChainsRef>,
        global_collection_manager: Option<GlobalCollectionManagerRef>,
    ) -> Self {
        Self {
            servers,
            tunnel_manager,
            limiter_manager,
            stat_manager,
            global_process_chains,
            global_collection_manager,
        }
    }
}

impl StackContext for RtcpStackContext {
    fn stack_protocol(&self) -> StackProtocol {
        StackProtocol::Rtcp
    }
}

struct RtcpConnectionHandler {
    env: Arc<RtcpStackContext>,
    executor: ProcessChainLibExecutor,
}

impl RtcpConnectionHandler {
    async fn create(
        hook_point: ProcessChainConfigs,
        env: Arc<RtcpStackContext>,
    ) -> StackResult<Self> {
        let (executor, _) = create_process_chain_executor(
            &hook_point,
            env.global_process_chains.clone(),
            env.global_collection_manager.clone(),
            Some(get_external_commands(Arc::downgrade(&env.servers))),
        )
            .await
            .map_err(into_stack_err!(StackErrorCode::ProcessChainError))?;
        Ok(Self {
            env,
            executor,
        })
    }

    async fn rebuild_with_hook_point(
        &self,
        hook_point: ProcessChainConfigs,
        env: Arc<RtcpStackContext>,
    ) -> StackResult<Self> {
        let (executor, _) = create_process_chain_executor(
            &hook_point,
            env.global_process_chains.clone(),
            env.global_collection_manager.clone(),
            Some(get_external_commands(Arc::downgrade(&env.servers))),
        )
            .await
            .map_err(into_stack_err!(StackErrorCode::ProcessChainError))?;
        Ok(Self {
            env,
            executor,
        })
    }

    async fn handle_stream(
        &self,
        stream: Box<dyn AsyncStream>,
        protocol: String,
        dest_host: Option<String>,
        dest_port: u16,
        path: String,
        _endpoint: TunnelEndpoint,
        stat: MutComposedSpeedStatRef,
    ) -> StackResult<()> {
        let executor = self.executor.fork();
        let servers = self.env.servers.clone();
        let map = MemoryMapCollection::new_ref();
        map.insert("dest_port", CollectionValue::String(dest_port.to_string())).await
            .map_err(|e| stack_err!(StackErrorCode::ProcessChainError, "{e}"))?;
        map.insert("dest_host", CollectionValue::String(dest_host.clone().unwrap_or_default())).await
            .map_err(|e| stack_err!(StackErrorCode::ProcessChainError, "{e}"))?;
        map.insert("protocol", CollectionValue::String(protocol)).await
            .map_err(|e| stack_err!(StackErrorCode::ProcessChainError, "{e}"))?;
        map.insert("path", CollectionValue::String(path)).await
            .map_err(|e| stack_err!(StackErrorCode::ProcessChainError, "{e}"))?;
        let global_env = executor.global_env().clone();
        let ret = execute_chain(executor, map)
            .await
            .map_err(into_stack_err!(StackErrorCode::ProcessChainError))?;
        if ret.is_control() {
            if ret.is_drop() {
                return Ok(());
            } else if ret.is_reject() {
                return Ok(());
            }

            if let Some(CommandControl::Return(ret)) = ret.as_control() {
                if let Some(list) = shlex::split(ret.value.as_str()) {
                    if list.is_empty() {
                        return Ok(());
                    }

                    let (limiter_id, down_speed, up_speed) = get_limit_info(global_env.clone()).await?;
                    let upper = if limiter_id.is_some() {
                        self.env.limiter_manager.get_limiter(limiter_id.unwrap())
                    } else {
                        None
                    };
                    let limiter = if down_speed.is_some() && up_speed.is_some() {
                        Some(Limiter::new(upper, Some(1), down_speed.map(|v| v as u32), up_speed.map(|v| v as u32)))
                    } else {
                        upper
                    };

                    let stat_group_ids = get_stat_info(global_env).await?;
                    let speed_groups = self.env.stat_manager.get_speed_stats(stat_group_ids.as_slice());
                    stat.set_external_stats(speed_groups);

                    let cmd = list[0].as_str();
                    match cmd {
                        "forward" => {
                            if list.len() < 2 {
                                return Err(stack_err!(
                                    StackErrorCode::InvalidConfig,
                                    "invalid forward command"
                                ));
                            }
                            let target = list[1].as_str();
                            let stream = if limiter.is_some() {
                                let (read_limit, write_limit) = limiter.as_ref().unwrap().new_limit_session();
                                let limit_stream = LimitStream::new(stream, read_limit, write_limit);
                                Box::new(limit_stream)
                            } else {
                                stream
                            };
                            stream_forward(stream, target, &self.env.tunnel_manager).await?;
                        }
                        "server" => {
                            if list.len() < 2 {
                                return Err(stack_err!(
                                    StackErrorCode::InvalidConfig,
                                    "invalid server command"
                                ));
                            }
                            let stream = if limiter.is_some() {
                                let (read_limit, write_limit) = limiter.as_ref().unwrap().new_limit_session();
                                let limit_stream = LimitStream::new(stream, read_limit, write_limit);
                                Box::new(limit_stream)
                            } else {
                                stream
                            };

                            let server_name = list[1].as_str();
                            if let Some(server) = servers.get_server(server_name) {
                                match server {
                                    Server::Http(server) => {
                                        hyper_serve_http(stream, server, StreamInfo::default()).await
                                            .map_err(into_stack_err!(StackErrorCode::ServerError, "server {server_name}"))?;
                                    }
                                    Server::Stream(server) => {
                                        server
                                            .serve_connection(stream, StreamInfo::default())
                                            .await
                                            .map_err(into_stack_err!(StackErrorCode::ServerError, "server {server_name}"))?;
                                    }
                                    _ => {
                                        return Err(stack_err!(
                                            StackErrorCode::InvalidConfig,
                                            "unsupported server type {server_name}"
                                        ));
                                    }
                                }
                            }
                        }
                        v => {
                            log::error!("unknown command: {}", v);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    async fn handle_datagram(
        &self,
        datagram: Box<dyn AsyncStream>,
        protocol: String,
        dest_host: Option<String>,
        dest_port: u16,
        path: String,
        _endpoint: TunnelEndpoint,
        stat: MutComposedSpeedStatRef,
    ) -> StackResult<()> {
        let executor = self.executor.fork();
        let servers = self.env.servers.clone();
        let remote_addr = match dest_host.clone() {
            Some(host) => format!("{}:{}", host, dest_port),
            None => format!("127.0.0.1:{}", dest_port),
        };
        let map = MemoryMapCollection::new_ref();
        map.insert("dest_port", CollectionValue::String(dest_port.to_string())).await
            .map_err(|e| stack_err!(StackErrorCode::ProcessChainError, "{e}"))?;
        map.insert("dest_host", CollectionValue::String(dest_host.unwrap_or_default())).await
            .map_err(|e| stack_err!(StackErrorCode::ProcessChainError, "{e}"))?;
        map.insert("protocol", CollectionValue::String(protocol)).await
            .map_err(|e| stack_err!(StackErrorCode::ProcessChainError, "{e}"))?;
        map.insert("path", CollectionValue::String(path)).await
            .map_err(|e| stack_err!(StackErrorCode::ProcessChainError, "{e}"))?;
        let global_env = executor.global_env().clone();
        let ret = execute_chain(executor, map)
            .await
            .map_err(into_stack_err!(StackErrorCode::ProcessChainError))?;
        if ret.is_control() {
            if ret.is_drop() {
                return Ok(());
            } else if ret.is_reject() {
                return Ok(());
            }

            if let Some(CommandControl::Return(ret)) = ret.as_control() {
                if let Some(list) = shlex::split(ret.value.as_str()) {
                    if list.is_empty() {
                        return Ok(());
                    }

                    let (limiter_id, down_speed, up_speed) = get_limit_info(global_env.clone()).await?;
                    let upper = if limiter_id.is_some() {
                        self.env.limiter_manager.get_limiter(limiter_id.unwrap())
                    } else {
                        None
                    };
                    let limiter = if down_speed.is_some() && up_speed.is_some() {
                        Some(Limiter::new(upper, Some(1), down_speed.map(|v| v as u32), up_speed.map(|v| v as u32)))
                    } else {
                        upper
                    };

                    let stat_group_ids = get_stat_info(global_env).await?;
                    let speed_groups = self.env.stat_manager.get_speed_stats(stat_group_ids.as_slice());
                    stat.set_external_stats(speed_groups);

                    let cmd = list[0].as_str();
                    match cmd {
                        "forward" => {
                            if list.len() < 2 {
                                return Err(stack_err!(
                                    StackErrorCode::InvalidConfig,
                                    "invalid forward command"
                                ));
                            }
                            let target = list[1].as_str();
                            let stream = if limiter.is_some() {
                                let (read_limit, write_limit) = limiter.as_ref().unwrap().new_limit_session();
                                let limit_stream = LimitStream::new(datagram, read_limit, write_limit);
                                Box::new(limit_stream)
                            } else {
                                datagram
                            };
                            let datagram_stream = Box::new(RTcpTunnelDatagramClient::new(stream));
                            datagram_forward(datagram_stream, target, &self.env.tunnel_manager).await?;
                        }
                        "server" => {
                            if list.len() < 2 {
                                return Err(stack_err!(
                                    StackErrorCode::InvalidConfig,
                                    "invalid server command"
                                ));
                            }
                            let server_name = list[1].as_str();
                            if let Some(server) = servers.get_server(server_name) {
                                match server {
                                    Server::Datagram(server) => {
                                        let stream = if limiter.is_some() {
                                            let (read_limit, write_limit) = limiter.as_ref().unwrap().new_limit_session();
                                            let limit_stream = LimitStream::new(datagram, read_limit, write_limit);
                                            Box::new(limit_stream)
                                        } else {
                                            datagram
                                        };
                                        let datagram_stream = AsyncStreamWithDatagram::new(stream);
                                        let mut buf = vec![0; 4096];
                                        loop {
                                            let len = datagram_stream.recv_datagram(&mut buf).await
                                                .map_err(into_stack_err!(StackErrorCode::IoError, "recv datagram error"))?;
                                            let resp = server.serve_datagram(&buf[..len], DatagramInfo::new(Some(remote_addr.clone()))).await
                                                .map_err(into_stack_err!(StackErrorCode::ServerError, "serve datagram error"))?;
                                            datagram_stream.send_datagram(resp.as_slice()).await
                                                .map_err(into_stack_err!(StackErrorCode::IoError, "send datagram error"))?;
                                        }
                                    }
                                    _ => {
                                        return Err(stack_err!(
                                            StackErrorCode::InvalidConfig,
                                            "unsupported server type {server_name}"
                                        ));
                                    }
                                }
                            }
                        }
                        v => {
                            log::error!("unknown command: {}", v);
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

struct Listener {
    bind_addr: String,
    connection_manager: Option<ConnectionManagerRef>,
    handler: Arc<RwLock<Arc<RtcpConnectionHandler>>>,
}

impl Listener {
    pub fn new(
        bind_addr: String,
        connection_manager: Option<ConnectionManagerRef>,
        handler: Arc<RwLock<Arc<RtcpConnectionHandler>>>,
    ) -> Self {
        Self {
            bind_addr,
            connection_manager,
            handler,
        }
    }
}

#[async_trait::async_trait]
impl RTcpListener for Listener {
    async fn on_new_stream(&self, stream: Box<dyn AsyncStream>, dest_host: Option<String>, dest_port: u16, endpoint: TunnelEndpoint) -> TunnelResult<()> {
        let (protocol, dest_host, dest_port, path) = if dest_port == 0 {
            if dest_host.is_none() {
                let msg = format!("dest_host and dest_port can not be empty {:?}", endpoint);
                log::error!("{}", msg);
                return Err(TunnelError::ReasonError(msg));
            }
            let dest_host = dest_host.unwrap();
            if !has_scheme(dest_host.as_str()) {
                let msg = format!("invalid url {}", dest_host);
                log::error!("{}", msg);
                return Err(TunnelError::ReasonError(msg));
            };
            let url = Url::parse(dest_host.as_str()).map_err(|e| {
                let msg = format!("invalid url {}", dest_host);
                log::error!("{}", msg);
                TunnelError::UrlParseError(dest_host.clone(), format!("{}", e))
            })?;
            if url.port().is_none() {
                return Err(TunnelError::UrlParseError(dest_host, "The port must be include".to_string()));
            }
            let scheme = url.scheme();
            let dest_host = url.host_str().map(|s| s.to_string());
            let dest_port = url.port().unwrap();
            let path = url.path();
            let path = if path == "/" {
                String::from("")
            } else {
                path.to_string()
            };
            (scheme.to_string(), dest_host, dest_port, path)
        } else {
            ("tcp".to_string(), dest_host, dest_port, "".to_string())
        };

        let handler_snapshot = {
            let handler = self.handler.read().unwrap();
            handler.clone()
        };
        let stat = MutComposedSpeedStat::new();
        let stat_stream = Box::new(StatStream::new_with_tracker(stream, stat.clone()));
        let remote_addr = match dest_host.clone() {
            Some(host) => format!("{}:{}", host, dest_port),
            None => format!("{}:{}", endpoint.device_id, dest_port),
        };


        let speed = stat_stream.get_speed_stat();
        let handle = tokio::spawn(async move {
            if let Err(e) = handler_snapshot.handle_stream(stat_stream, protocol, dest_host, dest_port, path, endpoint, stat).await {
                error!("on_new_stream error: {}", e);
            }
        });
        if let Some(manager) = &self.connection_manager {
            let controller = HandleConnectionController::new(handle);
            manager.add_connection(ConnectionInfo::new(remote_addr, self.bind_addr.clone(), StackProtocol::Rtcp, speed, controller))
        }
        Ok(())
    }

    async fn on_new_datagram(&self, stream: Box<dyn AsyncStream>, dest_host: Option<String>, dest_port: u16, endpoint: TunnelEndpoint) -> TunnelResult<()> {
        let (protocol, dest_host, dest_port, path) = if dest_port == 0 {
            if dest_host.is_none() {
                let msg = format!("dest_host and dest_port can not be empty {:?}", endpoint);
                log::error!("{}", msg);
                return Err(TunnelError::ReasonError(msg));
            }
            let dest_host = dest_host.unwrap();
            if !has_scheme(dest_host.as_str()) {
                let msg = format!("invalid url {}", dest_host);
                log::error!("{}", msg);
                return Err(TunnelError::ReasonError(msg));
            };
            let url = Url::parse(dest_host.as_str()).map_err(|e| {
                let msg = format!("invalid url {}", dest_host);
                log::error!("{}", msg);
                TunnelError::UrlParseError(dest_host.clone(), format!("{}", e))
            })?;
            if url.port().is_none() {
                return Err(TunnelError::UrlParseError(dest_host, "The port must be include".to_string()));
            }
            let scheme = url.scheme();
            let dest_host = url.host_str().map(|s| s.to_string());
            let dest_port = url.port().unwrap();
            let path = url.path();
            let path = if path == "/" {
                String::from("")
            } else {
                path.to_string()
            };
            (scheme.to_string(), dest_host, dest_port, path)
        } else {
            ("udp".to_string(), dest_host, dest_port, "".to_string())
        };

        let handler_snapshot = {
            let handler = self.handler.read().unwrap();
            handler.clone()
        };
        let stat = MutComposedSpeedStat::new();
        let stat_stream = Box::new(StatStream::new_with_tracker(stream, stat.clone()));
        let remote_addr = match dest_host.clone() {
            Some(host) => format!("{}:{}", host, dest_port),
            None => format!("{}:{}", endpoint.device_id, dest_port),
        };

        let speed = stat_stream.get_speed_stat();
        let handle = tokio::spawn(async move {
            if let Err(e) = handler_snapshot.handle_datagram(stat_stream, protocol, dest_host, dest_port, path, endpoint, stat).await {
                error!("on_new_stream error: {}", e);
            }
        });

        if let Some(manager) = &self.connection_manager {
            let controller = HandleConnectionController::new(handle);
            manager.add_connection(ConnectionInfo::new(remote_addr, self.bind_addr.clone(), StackProtocol::Rtcp, speed, controller))
        }
        Ok(())
    }
}

struct RtcpTunnelBuilder {
    rtcp: Arc<RTcp>,
}

impl RtcpTunnelBuilder {
    pub fn new(rtcp: Arc<RTcp>) -> Self {
        RtcpTunnelBuilder {
            rtcp
        }
    }
}

#[async_trait::async_trait]
impl TunnelBuilder for RtcpTunnelBuilder {
    async fn create_tunnel(&self, tunnel_stack_id: Option<&str>) -> TunnelResult<Box<dyn TunnelBox>> {
        self.rtcp.create_tunnel(tunnel_stack_id).await
    }
}

pub struct RtcpStack {
    id: String,
    bind_addr: String,
    rtcp: Mutex<Option<RTcp>>,
    rtcp_ref: Mutex<Option<Arc<RTcp>>>,
    connection_manager: Option<ConnectionManagerRef>,
    tunnel_manager: TunnelManager,
    handler: Arc<RwLock<Arc<RtcpConnectionHandler>>>,
    prepare_handler: Arc<RwLock<Option<Arc<RtcpConnectionHandler>>>>,
}

impl Drop for RtcpStack {
    fn drop(&mut self) {
        self.tunnel_manager.remove_tunnel_builder("rtcp");
        self.tunnel_manager.remove_tunnel_builder("rudp");
    }
}

impl RtcpStack {
    pub fn builder() -> RtcpStackBuilder {
        RtcpStackBuilder::new()
    }

    async fn create(mut builder: RtcpStackBuilder) -> StackResult<Self> {
        if builder.id.is_none() {
            return Err(stack_err!(StackErrorCode::InvalidConfig, "id is required"));
        }
        if builder.bind_addr.is_none() {
            return Err(stack_err!(StackErrorCode::InvalidConfig, "bind is required"));
        }
        if builder.device_config.is_none() {
            return Err(stack_err!(StackErrorCode::InvalidConfig, "device_config is required"));
        }
        if builder.private_key.is_none() {
            return Err(stack_err!(StackErrorCode::InvalidConfig, "private_key is required"));
        }
        if builder.hook_point.is_none() {
            return Err(stack_err!(StackErrorCode::InvalidConfig, "hook_point is required"));
        }

        let id = builder.id.take().unwrap();
        let bind_addr = builder.bind_addr.clone().unwrap();
        let device_config = builder.device_config.take().unwrap();
        let private_key = builder.private_key.take();
        let connection_manager = builder.connection_manager.clone();
        let stack_context = if let Some(stack_context) = builder.stack_context.take() {
            stack_context
        } else {
            return Err(stack_err!(StackErrorCode::InvalidConfig, "stack_context is required"));
        };
        let handler = RtcpConnectionHandler::create(builder.hook_point.unwrap(), stack_context.clone()).await?;
        let handler = Arc::new(RwLock::new(Arc::new(handler)));
        let listener = Listener::new(bind_addr.clone(), connection_manager.clone(), handler.clone());
        let rtcp = RTcp::new(device_config.id.clone(), bind_addr.clone(), private_key, Arc::new(listener));
        Ok(Self {
            id,
            bind_addr,
            rtcp: Mutex::new(Some(rtcp)),
            rtcp_ref: Mutex::new(None),
            connection_manager,
            tunnel_manager: stack_context.tunnel_manager.clone(),
            handler,
            prepare_handler: Arc::new(Default::default()),
        })
    }
}

#[async_trait::async_trait]
impl Stack for RtcpStack {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn stack_protocol(&self) -> StackProtocol {
        StackProtocol::Rtcp
    }

    fn get_bind_addr(&self) -> String {
        self.bind_addr.clone()
    }

    async fn start(&self) -> StackResult<()> {
        let mut rtcp = {
            self.rtcp.lock().unwrap().take().unwrap()
        };
        rtcp.start().await
            .map_err(|e| stack_err!(StackErrorCode::IoError, "start rtcp failed: {:?}", e))?;
        let rtcp = Arc::new(rtcp);
        let tunnel_builder = Arc::new(RtcpTunnelBuilder::new(rtcp.clone()));
        self.tunnel_manager.register_tunnel_builder("rtcp", tunnel_builder.clone());
        self.tunnel_manager.register_tunnel_builder("rudp", tunnel_builder);
        *self.rtcp_ref.lock().unwrap() = Some(rtcp);
        Ok(())
    }

    async fn prepare_update(&self, config: Arc<dyn StackConfig>, context: Option<Arc<dyn StackContext>>) -> StackResult<()> {
        let config = config.as_ref().as_any().downcast_ref::<RtcpStackConfig>()
            .ok_or(stack_err!(StackErrorCode::InvalidConfig, "invalid rtcp stack config"))?;

        if config.id != self.id {
            return Err(stack_err!(StackErrorCode::InvalidConfig, "id unmatch"));
        }

        if config.bind != self.bind_addr {
            return Err(stack_err!(StackErrorCode::BindUnmatched, "bind unmatch"));
        }

        let env = match context {
            Some(context) => {
                let rtcp_context = context.as_ref().as_any().downcast_ref::<RtcpStackContext>()
                    .ok_or(stack_err!(StackErrorCode::InvalidConfig, "invalid rtcp stack context"))?;
                Arc::new(rtcp_context.clone())
            }
            None => self.handler.read().unwrap().env.clone(),
        };
        let handler = RtcpConnectionHandler::create(config.hook_point.clone(), env).await?;
        *self.prepare_handler.write().unwrap() = Some(Arc::new(handler));
        Ok(())
    }

    async fn commit_update(&self) {
        if let Some(handler) = self.prepare_handler.write().unwrap().take() {
            *self.handler.write().unwrap() = handler;
        }
    }

    async fn rollback_update(&self) {
        self.prepare_handler.write().unwrap().take();
    }
}

pub struct RtcpStackBuilder {
    id: Option<String>,
    bind_addr: Option<String>,
    device_config: Option<DeviceConfig>,
    private_key: Option<[u8; 48]>,
    hook_point: Option<ProcessChainConfigs>,
    connection_manager: Option<ConnectionManagerRef>,
    stack_context: Option<Arc<RtcpStackContext>>,
}

impl RtcpStackBuilder {
    fn new() -> Self {
        Self {
            id: None,
            bind_addr: None,
            device_config: None,
            private_key: None,
            hook_point: None,
            connection_manager: None,
            stack_context: None,
        }
    }

    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    pub fn bind(mut self, bind_addr: String) -> Self {
        self.bind_addr = Some(bind_addr);
        self
    }

    pub fn device_config(mut self, device_config: DeviceConfig) -> Self {
        self.device_config = Some(device_config);
        self
    }

    pub fn private_key(mut self, private_key: [u8; 48]) -> Self {
        self.private_key = Some(private_key);
        self
    }

    pub fn hook_point(mut self, hook_point: ProcessChainConfigs) -> Self {
        self.hook_point = Some(hook_point);
        self
    }

    pub fn connection_manager(mut self, connection_manager: ConnectionManagerRef) -> Self {
        self.connection_manager = Some(connection_manager);
        self
    }

    pub fn stack_context(mut self, stack_context: Arc<RtcpStackContext>) -> Self {
        self.stack_context = Some(stack_context);
        self
    }

    pub async fn build(self) -> StackResult<RtcpStack> {
        RtcpStack::create(self).await
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct RtcpStackConfig {
    pub id: String,
    pub protocol: StackProtocol,
    pub bind: String,
    pub hook_point: Vec<crate::ProcessChainConfig>,
    pub key_path: String,
    pub device_config_path: Option<String>,
    pub name: Option<String>,
}

impl crate::StackConfig for RtcpStackConfig {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn stack_protocol(&self) -> StackProtocol {
        StackProtocol::Rtcp
    }

    fn get_config_json(&self) -> String {
        serde_json::to_string(self).unwrap()
    }

    fn add_process_chain(&self, mut process_chain: ProcessChainConfig) -> Arc<dyn StackConfig> {
        let mut config = self.clone();
        process_chain.priority = get_min_priority(&config.hook_point) - 1;
        config.hook_point.push(process_chain);
        Arc::new(config)
    }

    fn remove_process_chain(&self, process_chain_id: &str) -> Arc<dyn StackConfig> {
        let mut config = self.clone();
        config.hook_point.retain(|chain| chain.id != process_chain_id);
        Arc::new(config)
    }
}

pub struct RtcpStackFactory {
    connection_manager: ConnectionManagerRef,
}

impl RtcpStackFactory {
    pub fn new(
        connection_manager: ConnectionManagerRef,
    ) -> Self {
        Self {
            connection_manager,
        }
    }
}

#[async_trait::async_trait]
impl StackFactory for RtcpStackFactory {
    async fn create(
        &self,
        config: Arc<dyn StackConfig>,
        context: Arc<dyn StackContext>,
    ) -> StackResult<StackRef> {
        let config = config
            .as_any()
            .downcast_ref::<RtcpStackConfig>()
            .ok_or(stack_err!(StackErrorCode::InvalidConfig, "invalid rtcp stack config"))?;


        let private_key = load_raw_private_key(Path::new(config.key_path.as_str()))
            .map_err(into_stack_err!(StackErrorCode::InvalidConfig, "load private key {} failed", config.key_path))?;
        let public_key = encode_ed25519_pkcs8_sk_to_pk(&private_key);
        let device_config = if config.device_config_path.is_some() {
            let content = tokio::fs::read_to_string(config.device_config_path.as_ref().unwrap()).await
                .map_err(into_stack_err!(StackErrorCode::InvalidConfig, "load device config {} failed", config.device_config_path.as_ref().unwrap()))?;
            let device_config = serde_json::from_str::<DeviceConfig>(content.as_str())
                .map_err(into_stack_err!(StackErrorCode::InvalidConfig, "parse device config {} failed", config.device_config_path.as_ref().unwrap()))?;
            let default_key = device_config.get_default_key()
                .ok_or(stack_err!(StackErrorCode::InvalidConfig, "device config {} has no default key", config.device_config_path.as_ref().unwrap()))?;
            let x_of_auth_key = get_x_from_jwk(&default_key)
                .map_err(into_stack_err!(StackErrorCode::InvalidConfig, "device config {} has no auth key", config.device_config_path.as_ref().unwrap()))?;
            if x_of_auth_key != public_key {
                return Err(stack_err!(StackErrorCode::InvalidConfig, "device config {} public key not match", config.device_config_path.as_ref().unwrap()));
            }
            device_config
        } else {
            if config.name.is_none() {
                return Err(stack_err!(StackErrorCode::InvalidConfig, "name is required"));
            }
            let device_config = DeviceConfig::new(
                config.name.as_ref().unwrap().as_str(),
                public_key,
            );
            device_config
        };
        let stack_context = context
            .as_ref()
            .as_any()
            .downcast_ref::<RtcpStackContext>()
            .ok_or(stack_err!(StackErrorCode::InvalidConfig, "invalid rtcp stack context"))?;
        let stack_context = Arc::new(stack_context.clone());
        let stack = RtcpStack::builder()
            .id(config.id.clone())
            .bind(config.bind.clone())
            .connection_manager(self.connection_manager.clone())
            .device_config(device_config)
            .private_key(private_key)
            .hook_point(config.hook_point.clone())
            .stack_context(stack_context)
            .build().await?;
        Ok(Arc::new(stack))
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::collections::HashMap;
    use crate::global_process_chains::GlobalProcessChains;
    use crate::{ProcessChainConfigs, ServerResult, StreamServer, ServerManager, TunnelManager, Server, ConnectionManager, Stack, RtcpStack, RtcpStackFactory, RtcpStackConfig, StackContext, StackProtocol, StackFactory, StreamInfo, DatagramInfo, DefaultLimiterManager, StatManager, GlobalCollectionManager, LimiterManagerRef, StatManagerRef, ServerManagerRef, RtcpStackContext};
    use buckyos_kit::{AsyncStream};
    use name_lib::{encode_ed25519_sk_to_pk_jwk, generate_ed25519_key, generate_ed25519_key_pair, DeviceConfig, EncodedDocument};
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use name_client::{add_nameinfo_cache, init_name_lib_for_test, update_did_cache, NameInfo};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, UdpSocket};
    use url::Url;

    fn build_stack_context(
        servers: ServerManagerRef,
        tunnel_manager: TunnelManager,
        limiter_manager: LimiterManagerRef,
        stat_manager: StatManagerRef,
        global_process_chains: Option<Arc<GlobalProcessChains>>,
    ) -> Arc<RtcpStackContext> {
        Arc::new(RtcpStackContext::new(
            servers,
            tunnel_manager,
            limiter_manager,
            stat_manager,
            global_process_chains,
            None,
        ))
    }

    #[tokio::test]
    async fn test_rtcp_stack_creation() {
        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test", serde_json::from_value(jwk).unwrap());

        let result = RtcpStack::builder().build().await;
        assert!(result.is_err());
        let result = RtcpStack::builder().bind("127.0.0.1:2980".to_string()).build().await;
        assert!(result.is_err());
        let result = RtcpStack::builder()
            .id("test")
            .bind("127.0.0.1:2980".to_string())
            .device_config(device_config.clone())
            .build()
            .await;
        assert!(result.is_err());
        let result = RtcpStack::builder()
            .id("test")
            .bind("127.0.0.1:2980".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .build()
            .await;
        assert!(result.is_err());
        let result = RtcpStack::builder()
            .id("test")
            .bind("127.0.0.1:2980".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(vec![])
            .build()
            .await;
        assert!(result.is_err());

        let tunnel_manager = TunnelManager::new();
        let result = RtcpStack::builder()
            .id("test")
            .bind("127.0.0.1:2980".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(vec![])
            .stack_context(build_stack_context(
                Arc::new(ServerManager::new()),
                tunnel_manager.clone(),
                Arc::new(DefaultLimiterManager::new()),
                StatManager::new(),
                None,
            ))
            .build()
            .await;
        assert!(result.is_ok());
        let result = RtcpStack::builder()
            .id("test")
            .bind("127.0.0.1:2980".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(vec![])
            .stack_context(build_stack_context(
                Arc::new(ServerManager::new()),
                tunnel_manager.clone(),
                Arc::new(DefaultLimiterManager::new()),
                StatManager::new(),
                Some(Arc::new(GlobalProcessChains::new())),
            ))
            .build()
            .await;
        assert!(result.is_ok());
        let result = RtcpStack::builder()
            .id("test")
            .bind("127.0.0.1:2980".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(vec![])
            .connection_manager(ConnectionManager::new())
            .stack_context(build_stack_context(
                Arc::new(ServerManager::new()),
                tunnel_manager,
                Arc::new(DefaultLimiterManager::new()),
                StatManager::new(),
                Some(Arc::new(GlobalProcessChains::new())),
            ))
            .build()
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_rtcp_stack_reject() {
        let _ = init_name_lib_for_test(&HashMap::new()).await;
        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let mut device_config = DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        device_config.iat = chrono::Utc::now().timestamp() as u64;
        device_config.exp = chrono::Utc::now().timestamp() as u64 + 1000;
        let id1 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
         update_did_cache(device_config.id.clone(), None, encoded_doc).await.unwrap();
         add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(device_config.id.to_string().as_str(), "127.0.0.1".parse().unwrap()),
         )
         .await
         .unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        reject;
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let tunnel_manager1 = TunnelManager::new();
        let connection_manager = ConnectionManager::new();
        let stack_context = build_stack_context(
            Arc::new(ServerManager::new()),
            tunnel_manager1.clone(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = RtcpStack::builder()
            .id("test")
            .bind("127.0.0.1:2981".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());

        let stack1 = result.unwrap();
        let result = stack1.start().await;
        assert!(result.is_ok());

        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let mut device_config = DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        device_config.iat = chrono::Utc::now().timestamp() as u64;
        device_config.exp = chrono::Utc::now().timestamp() as u64 + 1000;
        let _id2 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
         update_did_cache(device_config.id.clone(), None, encoded_doc).await.unwrap();
         add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(device_config.id.to_string().as_str(), "127.0.0.1".parse().unwrap()),
         )
         .await
         .unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        reject;
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let tunnel_manager2 = TunnelManager::new();
        let stack_context = build_stack_context(
            Arc::new(ServerManager::new()),
            tunnel_manager2.clone(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = RtcpStack::builder()
            .id("test2")
            .bind("127.0.0.1:2982".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());

        let stack2 = result.unwrap();
        let result = stack2.start().await;
        assert!(result.is_ok());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let url = Url::parse(format!("rtcp://{}:2981/test:80", id1.to_host_name()).as_str()).unwrap();
        let ret = tunnel_manager2.open_stream_by_url(&url).await;
        assert!(ret.is_ok());
        let mut stream = ret.unwrap();
        let result = stream
            .write_all(b"GET / HTTP/1.1\r\nHost: httpbin.org\r\n\r\n")
            .await;
        assert!(result.is_ok());
        let ret = stream.read(&mut [0; 1024]).await;
        assert!(ret.is_err());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        assert_eq!(connection_manager.get_all_connection_info().len(), 0);
    }

    #[tokio::test]
    async fn test_rtcp_stack_drop() {
        let _ = init_name_lib_for_test(&HashMap::new()).await;
        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let id1 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
         update_did_cache(device_config.id.clone(), None, encoded_doc).await.unwrap();
         add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(device_config.id.to_string().as_str(), "127.0.0.1".parse().unwrap()),
         )
         .await
         .unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        drop;
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let tunnel_manager1 = TunnelManager::new();
        let connection_manager = ConnectionManager::new();
        let stack_context = build_stack_context(
            Arc::new(ServerManager::new()),
            tunnel_manager1.clone(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = RtcpStack::builder()
            .id("test")
            .bind("127.0.0.1:2983".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(stack_context)
            .build()
            .await;
        // assert!(result.is_ok());

        let stack1 = result.unwrap();
        let result = stack1.start().await;
        assert!(result.is_ok());

        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let _id2 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
         update_did_cache(device_config.id.clone(), None, encoded_doc).await.unwrap();
         add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(device_config.id.to_string().as_str(), "127.0.0.1".parse().unwrap()),
         )
         .await
         .unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        drop;
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let tunnel_manager2 = TunnelManager::new();
        let stack_context = build_stack_context(
            Arc::new(ServerManager::new()),
            tunnel_manager2.clone(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = RtcpStack::builder()
            .id("test2")
            .bind("127.0.0.1:2984".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());

        let stack2 = result.unwrap();
        let result = stack2.start().await;
        assert!(result.is_ok());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let url = Url::parse(format!("rtcp://{}:2983/test:80", id1.to_host_name()).as_str()).unwrap();
        let ret = tunnel_manager2.open_stream_by_url(&url).await;
        assert!(ret.is_ok());
        let mut stream = ret.unwrap();
        let result = stream
            .write_all(b"GET / HTTP/1.1\r\nHost: httpbin.org\r\n\r\n")
            .await;
        assert!(result.is_ok());
        let ret = stream.read(&mut [0; 1024]).await;
        assert!(ret.is_err());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        assert_eq!(connection_manager.get_all_connection_info().len(), 0);
    }

    #[tokio::test]
    async fn test_rtcp_stack_forward() {
        let _ = init_name_lib_for_test(&HashMap::new()).await;
        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let id1 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
         update_did_cache(device_config.id.clone(), None, encoded_doc).await.unwrap();
         add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(device_config.id.to_string().as_str(), "127.0.0.1".parse().unwrap()),
         )
         .await
         .unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "forward tcp:///127.0.0.1:2987";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let tunnel_manager1 = TunnelManager::new();
        let connection_manager = ConnectionManager::new();
        let stack_context = build_stack_context(
            Arc::new(ServerManager::new()),
            tunnel_manager1.clone(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = RtcpStack::builder()
            .id("test")
            .bind("127.0.0.1:2985".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());

        let stack1 = result.unwrap();
        let result = stack1.start().await;
        assert!(result.is_ok());

        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let _id2 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
         update_did_cache(device_config.id.clone(), None, encoded_doc).await.unwrap();
         add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(device_config.id.to_string().as_str(), "127.0.0.1".parse().unwrap()),
         )
         .await
         .unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "forward tcp:///127.0.0.1:2987";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let tunnel_manager2 = TunnelManager::new();
        let stack_context = build_stack_context(
            Arc::new(ServerManager::new()),
            tunnel_manager2.clone(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = RtcpStack::builder()
            .id("test2")
            .bind("127.0.0.1:2986".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());

        let stack2 = result.unwrap();
        let result = stack2.start().await;
        assert!(result.is_ok());

        tokio::spawn(async move {
            let tcp_listener = TcpListener::bind("127.0.0.1:2987").await.unwrap();
            if let Ok((mut tcp_stream, _)) = tcp_listener.accept().await {
                let mut buf = [0u8; 4];
                tcp_stream.read_exact(&mut buf).await.unwrap();
                assert_eq!(&buf, b"test");
                tcp_stream.write_all("recv".as_bytes()).await.unwrap();
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        });

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let url = Url::parse(format!("rtcp://{}:2985/test:80", id1.to_host_name()).as_str()).unwrap();
        let ret = tunnel_manager2.open_stream_by_url(&url).await;
        assert!(ret.is_ok());
        let mut stream = ret.unwrap();
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        assert_eq!(connection_manager.get_all_connection_info().len(), 1);
        let result = stream.write_all(b"test").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 4];
        let ret = stream.read_exact(&mut buf).await;

        assert!(ret.is_ok());
        assert_eq!(&buf, b"recv");
        stream.shutdown().await.unwrap();

        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        assert_eq!(connection_manager.get_all_connection_info().len(), 0);
    }

    #[tokio::test]
    async fn test_rtcp_stack_forward_err() {
        let _ = init_name_lib_for_test(&HashMap::new()).await;
        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let id1 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
         update_did_cache(device_config.id.clone(), None, encoded_doc).await.unwrap();
         add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(device_config.id.to_string().as_str(), "127.0.0.1".parse().unwrap()),
         )
         .await
         .unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "forward tcp:///127.0.0.1:12987";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let tunnel_manager1 = TunnelManager::new();
        let connection_manager = ConnectionManager::new();
        let stack_context = build_stack_context(
            Arc::new(ServerManager::new()),
            tunnel_manager1.clone(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = RtcpStack::builder()
            .id("test")
            .bind("127.0.0.1:2988".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());

        let stack1 = result.unwrap();
        let result = stack1.start().await;
        assert!(result.is_ok());

        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let _id2 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
         update_did_cache(device_config.id.clone(), None, encoded_doc).await.unwrap();
         add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(device_config.id.to_string().as_str(), "127.0.0.1".parse().unwrap()),
         )
         .await
         .unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "forward tcp:///127.0.0.1:12987";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let tunnel_manager2 = TunnelManager::new();
        let stack_context = build_stack_context(
            Arc::new(ServerManager::new()),
            tunnel_manager2.clone(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = RtcpStack::builder()
            .id("test2")
            .bind("127.0.0.1:2989".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());

        let stack2 = result.unwrap();
        let result = stack2.start().await;
        assert!(result.is_ok());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let url = Url::parse(format!("rtcp://{}:2988/test:80", id1.to_host_name()).as_str()).unwrap();
        let ret = tunnel_manager2.open_stream_by_url(&url).await;
        assert!(ret.is_ok());
        let mut stream = ret.unwrap();
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        // assert_eq!(connection_manager.get_all_connection_info().len(), 1);
        let result = stream.write_all(b"test").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 4];
        let ret = stream.read_exact(&mut buf).await;

        assert!(ret.is_err());
    }

    pub struct MockServer {
        id: String,
    }

    impl MockServer {
        pub fn new(id: String) -> Self {
            Self {
                id,
            }
        }
    }

    #[async_trait::async_trait]
    impl StreamServer for MockServer {
        async fn serve_connection(&self, mut stream: Box<dyn AsyncStream>, _info: StreamInfo) -> ServerResult<()> {
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"test");
            stream.write_all("recv".as_bytes()).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            Ok(())
        }

        fn id(&self) -> String {
            self.id.clone()
        }
    }

    #[tokio::test]
    async fn test_rtcp_stack_server() {
        let _ = init_name_lib_for_test(&HashMap::new()).await;
        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let id1 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
         update_did_cache(device_config.id.clone(), None, encoded_doc).await.unwrap();
         add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(device_config.id.to_string().as_str(), "127.0.0.1".parse().unwrap()),
         )
         .await
         .unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "server www.buckyos.com";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let server_manager = Arc::new(ServerManager::new());
        server_manager.add_server(Server::Stream(Arc::new(MockServer::new("www.buckyos.com".to_string())))).unwrap();
        let tunnel_manager1 = TunnelManager::new();
        let connection_manager = ConnectionManager::new();
        let stack_context = build_stack_context(
            server_manager,
            tunnel_manager1.clone(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = RtcpStack::builder()
            .id("test")
            .bind("127.0.0.1:2990".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());

        let stack1 = result.unwrap();
        let result = stack1.start().await;
        assert!(result.is_ok());

        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let _id2 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
         update_did_cache(device_config.id.clone(), None, encoded_doc).await.unwrap();
         add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(device_config.id.to_string().as_str(), "127.0.0.1".parse().unwrap()),
         )
         .await
         .unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "server www.buckyos.com";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let server_manager = Arc::new(ServerManager::new());
        server_manager.add_server(Server::Stream(Arc::new(MockServer::new("www.buckyos.com".to_string())))).unwrap();
        let tunnel_manager2 = TunnelManager::new();
        let stack_context = build_stack_context(
            server_manager,
            tunnel_manager2.clone(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = RtcpStack::builder()
            .id("test2")
            .bind("127.0.0.1:2991".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());

        let stack2 = result.unwrap();
        let result = stack2.start().await;
        assert!(result.is_ok());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let url = Url::parse(format!("rtcp://{}:2990/test:80", id1.to_host_name()).as_str()).unwrap();
        let ret = tunnel_manager2.open_stream_by_url(&url).await;
        assert!(ret.is_ok());
        let mut stream = ret.unwrap();
        let result = stream.write_all(b"test").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 4];
        let ret = stream.read_exact(&mut buf).await;
        ret.as_ref().unwrap();
        assert!(ret.is_ok());
        assert_eq!(&buf, b"recv");
    }


    #[tokio::test]
    async fn test_rudp_stack_reject() {
        let _ = init_name_lib_for_test(&HashMap::new()).await;
        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let id1 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
         update_did_cache(device_config.id.clone(), None, encoded_doc).await.unwrap();
         add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(device_config.id.to_string().as_str(), "127.0.0.1".parse().unwrap()),
         )
         .await
         .unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        reject;
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let server_manager = Arc::new(ServerManager::new());
        let tunnel_manager1 = TunnelManager::new();
        let connection_manager = ConnectionManager::new();
        let stack_context = build_stack_context(
            server_manager,
            tunnel_manager1.clone(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = RtcpStack::builder()
            .id("test")
            .bind("127.0.0.1:2995".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());

        let stack1 = result.unwrap();
        let result = stack1.start().await;
        assert!(result.is_ok());

        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let _id2 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
         update_did_cache(device_config.id.clone(), None, encoded_doc).await.unwrap();
         add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(device_config.id.to_string().as_str(), "127.0.0.1".parse().unwrap()),
         )
         .await
         .unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        reject;
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let server_manager = Arc::new(ServerManager::new());
        let tunnel_manager2 = TunnelManager::new();
        let stack_context = build_stack_context(
            server_manager,
            tunnel_manager2.clone(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = RtcpStack::builder()
            .id("test2")
            .bind("127.0.0.1:2996".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());

        let stack2 = result.unwrap();
        let result = stack2.start().await;
        assert!(result.is_ok());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let url = Url::parse(format!("rudp://{}:2995/test:80", id1.to_host_name()).as_str()).unwrap();
        let ret = tunnel_manager2.create_datagram_client_by_url(&url).await;
        assert!(ret.is_ok());
        let stream = ret.unwrap();
        let result = stream
            .send_datagram(b"GET / HTTP/1.1\r\nHost: httpbin.org\r\n\r\n")
            .await;
        assert!(result.is_ok());
        let ret = stream.recv_datagram(&mut [0; 1024]).await;
        assert!(ret.is_err());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        assert_eq!(connection_manager.get_all_connection_info().len(), 0);
    }

    #[tokio::test]
    async fn test_udp_stack_drop() {
        let _ = init_name_lib_for_test(&HashMap::new()).await;
        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let id1 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
         update_did_cache(device_config.id.clone(), None, encoded_doc).await.unwrap();
         add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(device_config.id.to_string().as_str(), "127.0.0.1".parse().unwrap()),
         )
         .await
         .unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        drop;
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let server_manager = Arc::new(ServerManager::new());
        let tunnel_manager1 = TunnelManager::new();
        let connection_manager = ConnectionManager::new();
        let stack_context = build_stack_context(
            server_manager,
            tunnel_manager1.clone(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = RtcpStack::builder()
            .id("test")
            .bind("127.0.0.1:2997".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());

        let stack1 = result.unwrap();
        let result = stack1.start().await;
        assert!(result.is_ok());

        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let _id2 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
         update_did_cache(device_config.id.clone(), None, encoded_doc).await.unwrap();
         add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(device_config.id.to_string().as_str(), "127.0.0.1".parse().unwrap()),
         )
         .await
         .unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        drop;
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let server_manager = Arc::new(ServerManager::new());
        let tunnel_manager2 = TunnelManager::new();
        let stack_context = build_stack_context(
            server_manager,
            tunnel_manager2.clone(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = RtcpStack::builder()
            .id("test2")
            .bind("127.0.0.1:2313".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());

        let stack2 = result.unwrap();
        let result = stack2.start().await;
        assert!(result.is_ok());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let url = Url::parse(format!("rudp://{}:2997/test:80", id1.to_host_name()).as_str()).unwrap();
        let ret = tunnel_manager2.create_datagram_client_by_url(&url).await;
        assert!(ret.is_ok());
        let stream = ret.unwrap();
        let result = stream
            .send_datagram(b"GET / HTTP/1.1\r\nHost: httpbin.org\r\n\r\n")
            .await;
        assert!(result.is_ok());
        let ret = stream.recv_datagram(&mut [0; 1024]).await;
        assert!(ret.is_err());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        assert_eq!(connection_manager.get_all_connection_info().len(), 0);
    }

    #[tokio::test]
    async fn test_udp_stack_forward() {
        let _ = init_name_lib_for_test(&HashMap::new()).await;
        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let id1 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
         update_did_cache(device_config.id.clone(), None, encoded_doc).await.unwrap();
         add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(device_config.id.to_string().as_str(), "127.0.0.1".parse().unwrap()),
         )
         .await
         .unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "forward udp:///127.0.0.1:2300";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let server_manager = Arc::new(ServerManager::new());
        let tunnel_manager1 = TunnelManager::new();
        let connection_manager = ConnectionManager::new();
        let stack_context = build_stack_context(
            server_manager,
            tunnel_manager1.clone(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = RtcpStack::builder()
            .id("test")
            .bind("127.0.0.1:2998".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());

        let stack1 = result.unwrap();
        let result = stack1.start().await;
        assert!(result.is_ok());

        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let _id2 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
         update_did_cache(device_config.id.clone(), None, encoded_doc).await.unwrap();
         add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(device_config.id.to_string().as_str(), "127.0.0.1".parse().unwrap()),
         )
         .await
         .unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "forward udp:///127.0.0.1:2300";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let server_manager = Arc::new(ServerManager::new());
        let tunnel_manager2 = TunnelManager::new();
        let stack_context = build_stack_context(
            server_manager,
            tunnel_manager2.clone(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = RtcpStack::builder()
            .id("test2")
            .bind("127.0.0.1:2999".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());

        let stack2 = result.unwrap();
        let result = stack2.start().await;
        assert!(result.is_ok());

        tokio::spawn(async move {
            let udp_socket = UdpSocket::bind("127.0.0.1:2300").await.unwrap();
            let mut buf = [0; 1024];
            let (n, addr) = udp_socket.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"test");
            let _ = udp_socket.send_to(b"recv", addr).await;
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        });

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let url = Url::parse(format!("rudp://{}:2998/test:80", id1.to_host_name()).as_str()).unwrap();
        let ret = tunnel_manager2.create_datagram_client_by_url(&url).await;
        assert!(ret.is_ok());
        let stream = ret.unwrap();
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        assert_eq!(connection_manager.get_all_connection_info().len(), 1);
        let result = stream.send_datagram(b"test").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 4];
        let ret = stream.recv_datagram(&mut buf).await;

        assert!(ret.is_ok());
        assert_eq!(&buf, b"recv");
        drop(stream);

        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        assert_eq!(connection_manager.get_all_connection_info().len(), 0);
    }

    #[tokio::test]
    async fn test_rudp_stack_forward_err() {
        let _ = init_name_lib_for_test(&HashMap::new()).await;
        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let id1 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
         update_did_cache(device_config.id.clone(), None, encoded_doc).await.unwrap();
         add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(device_config.id.to_string().as_str(), "127.0.0.1".parse().unwrap()),
         )
         .await
         .unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "forward udp:///127.0.0.1:22987";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let server_manager = Arc::new(ServerManager::new());
        let tunnel_manager1 = TunnelManager::new();
        let connection_manager = ConnectionManager::new();
        let stack_context = build_stack_context(
            server_manager,
            tunnel_manager1.clone(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = RtcpStack::builder()
            .id("test")
            .bind("127.0.0.1:2301".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());

        let stack1 = result.unwrap();
        let result = stack1.start().await;
        assert!(result.is_ok());

        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let _id2 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
         update_did_cache(device_config.id.clone(), None, encoded_doc).await.unwrap();
         add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(device_config.id.to_string().as_str(), "127.0.0.1".parse().unwrap()),
         )
         .await
         .unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "forward udp:///127.0.0.1:22987";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let server_manager = Arc::new(ServerManager::new());
        let tunnel_manager2 = TunnelManager::new();
        let stack_context = build_stack_context(
            server_manager,
            tunnel_manager2.clone(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = RtcpStack::builder()
            .id("test2")
            .bind("127.0.0.1:2302".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());

        let stack2 = result.unwrap();
        let result = stack2.start().await;
        assert!(result.is_ok());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let url = Url::parse(format!("rudp://{}:2301/test:80", id1.to_host_name()).as_str()).unwrap();
        let ret = tunnel_manager2.create_datagram_client_by_url(&url).await;
        assert!(ret.is_ok());
        let stream = ret.unwrap();
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        assert_eq!(connection_manager.get_all_connection_info().len(), 1);
        let result = stream.send_datagram(b"test").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 4];
        let ret = tokio::time::timeout(Duration::from_secs(5),
                                       stream.recv_datagram(&mut buf)).await;

        assert!(ret.is_err() || ret.unwrap().is_err());
    }

    #[tokio::test]
    async fn test_rtcp_stack_stat_server() {
        let _ = init_name_lib_for_test(&HashMap::new()).await;
        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let id1 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
         update_did_cache(device_config.id.clone(), None, encoded_doc).await.unwrap();
         add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(device_config.id.to_string().as_str(), "127.0.0.1".parse().unwrap()),
         )
         .await
         .unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        set-stat test;
        return "server www.buckyos.com";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let server_manager = Arc::new(ServerManager::new());
        server_manager.add_server(Server::Stream(Arc::new(MockServer::new("www.buckyos.com".to_string())))).unwrap();
        let tunnel_manager1 = TunnelManager::new();
        let limiter_manager1 = Arc::new(DefaultLimiterManager::new());
        let stat1 = StatManager::new();
        let connection_manager = ConnectionManager::new();
        let stack_context = build_stack_context(
            server_manager,
            tunnel_manager1.clone(),
            limiter_manager1.clone(),
            stat1.clone(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = RtcpStack::builder()
            .id("test")
            .bind("127.0.0.1:2322".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());

        let stack1 = result.unwrap();
        let result = stack1.start().await;
        assert!(result.is_ok());

        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let _id2 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
         update_did_cache(device_config.id.clone(), None, encoded_doc).await.unwrap();
         add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(device_config.id.to_string().as_str(), "127.0.0.1".parse().unwrap()),
         )
         .await
         .unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "server www.buckyos.com";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let server_manager = Arc::new(ServerManager::new());
        server_manager.add_server(Server::Stream(Arc::new(MockServer::new("www.buckyos.com".to_string())))).unwrap();
        let tunnel_manager2 = TunnelManager::new();
        let stack_context = build_stack_context(
            server_manager,
            tunnel_manager2.clone(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = RtcpStack::builder()
            .id("test2")
            .bind("127.0.0.1:2323".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());

        let stack2 = result.unwrap();
        let result = stack2.start().await;
        assert!(result.is_ok());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let url = Url::parse(format!("rtcp://{}:2322/test:80", id1.to_host_name()).as_str()).unwrap();
        let ret = tunnel_manager2.open_stream_by_url(&url).await;
        assert!(ret.is_ok());
        let mut stream = ret.unwrap();
        let result = stream.write_all(b"test").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 4];
        let ret = stream.read_exact(&mut buf).await;
        assert!(ret.is_ok());
        assert_eq!(&buf, b"recv");
        let test_stat = stat1.get_speed_stat("test");
        assert!(test_stat.is_some());
        let test_stat = test_stat.unwrap();
        assert_eq!(test_stat.get_read_sum_size(), 4);
        assert_eq!(test_stat.get_write_sum_size(), 4);
    }

    #[tokio::test]
    async fn test_rtcp_stack_stat_limiter_server() {
        let _ = init_name_lib_for_test(&HashMap::new()).await;
        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let id1 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
         update_did_cache(device_config.id.clone(), None, encoded_doc).await.unwrap();
         add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(device_config.id.to_string().as_str(), "127.0.0.1".parse().unwrap()),
         )
         .await
         .unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        set-stat test;
        set-limit "2B/s" "2B/s";
        return "server www.buckyos.com";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let server_manager = Arc::new(ServerManager::new());
        server_manager.add_server(Server::Stream(Arc::new(MockServer::new("www.buckyos.com".to_string())))).unwrap();
        let tunnel_manager1 = TunnelManager::new();
        let limiter_manager1 = Arc::new(DefaultLimiterManager::new());
        let stat1 = StatManager::new();
        let connection_manager = ConnectionManager::new();
        let stack_context = build_stack_context(
            server_manager,
            tunnel_manager1.clone(),
            limiter_manager1.clone(),
            stat1.clone(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = RtcpStack::builder()
            .id("test")
            .bind("127.0.0.1:2324".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());

        let stack1 = result.unwrap();
        let result = stack1.start().await;
        assert!(result.is_ok());

        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let _id2 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
         update_did_cache(device_config.id.clone(), None, encoded_doc).await.unwrap();
         add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(device_config.id.to_string().as_str(), "127.0.0.1".parse().unwrap()),
         )
         .await
         .unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "server www.buckyos.com";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let server_manager = Arc::new(ServerManager::new());
        server_manager.add_server(Server::Stream(Arc::new(MockServer::new("www.buckyos.com".to_string())))).unwrap();
        let tunnel_manager2 = TunnelManager::new();
        let stack_context = build_stack_context(
            server_manager,
            tunnel_manager2.clone(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = RtcpStack::builder()
            .id("test2")
            .bind("127.0.0.1:2325".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());

        let stack2 = result.unwrap();
        let result = stack2.start().await;
        assert!(result.is_ok());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let url = Url::parse(format!("rtcp://{}:2324/test:80", id1.to_host_name()).as_str()).unwrap();
        let ret = tunnel_manager2.open_stream_by_url(&url).await;
        assert!(ret.is_ok());
        let start = Instant::now();
        let mut stream = ret.unwrap();
        let result = stream.write_all(b"test").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 4];
        let ret = stream.read_exact(&mut buf).await;
        assert!(ret.is_ok());
        assert_eq!(&buf, b"recv");
        let test_stat = stat1.get_speed_stat("test");
        assert!(test_stat.is_some());
        let test_stat = test_stat.unwrap();
        assert_eq!(test_stat.get_read_sum_size(), 4);
        assert_eq!(test_stat.get_write_sum_size(), 4);
        assert!(start.elapsed().as_millis() > 1800);
        assert!(start.elapsed().as_millis() < 2500);
    }

    #[tokio::test]
    async fn test_rtcp_stack_stat_group_limiter_server() {
        let _ = init_name_lib_for_test(&HashMap::new()).await;
        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let id1 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
         update_did_cache(device_config.id.clone(), None, encoded_doc).await.unwrap();
         add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(device_config.id.to_string().as_str(), "127.0.0.1".parse().unwrap()),
         )
         .await
         .unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        set-stat test;
        set-limit test;
        return "server www.buckyos.com";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let server_manager = Arc::new(ServerManager::new());
        server_manager.add_server(Server::Stream(Arc::new(MockServer::new("www.buckyos.com".to_string())))).unwrap();
        let tunnel_manager1 = TunnelManager::new();
        let mut limiter_manager1 = DefaultLimiterManager::new();
        let _ = limiter_manager1.new_limiter("test".to_string(), None::<String>, Some(1), Some(2), Some(2));
        let stat1 = StatManager::new();
        let connection_manager = ConnectionManager::new();
        let stack_context = build_stack_context(
            server_manager,
            tunnel_manager1.clone(),
            Arc::new(limiter_manager1),
            stat1.clone(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = RtcpStack::builder()
            .id("test")
            .bind("127.0.0.1:2326".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());

        let stack1 = result.unwrap();
        let result = stack1.start().await;
        assert!(result.is_ok());

        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let _id2 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
         update_did_cache(device_config.id.clone(), None, encoded_doc).await.unwrap();
         add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(device_config.id.to_string().as_str(), "127.0.0.1".parse().unwrap()),
         )
         .await
         .unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "server www.buckyos.com";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let server_manager = Arc::new(ServerManager::new());
        server_manager.add_server(Server::Stream(Arc::new(MockServer::new("www.buckyos.com".to_string())))).unwrap();
        let tunnel_manager2 = TunnelManager::new();
        let stack_context = build_stack_context(
            server_manager,
            tunnel_manager2.clone(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = RtcpStack::builder()
            .id("test2")
            .bind("127.0.0.1:2327".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());

        let stack2 = result.unwrap();
        let result = stack2.start().await;
        assert!(result.is_ok());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let url = Url::parse(format!("rtcp://{}:2326/test:80", id1.to_host_name()).as_str()).unwrap();
        let ret = tunnel_manager2.open_stream_by_url(&url).await;
        assert!(ret.is_ok());
        let start = Instant::now();
        let mut stream = ret.unwrap();
        let result = stream.write_all(b"test").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 4];
        let ret = stream.read_exact(&mut buf).await;
        assert!(ret.is_ok());
        assert_eq!(&buf, b"recv");
        let test_stat = stat1.get_speed_stat("test");
        assert!(test_stat.is_some());
        let test_stat = test_stat.unwrap();
        assert_eq!(test_stat.get_read_sum_size(), 4);
        assert_eq!(test_stat.get_write_sum_size(), 4);
        assert!(start.elapsed().as_millis() > 1800);
        assert!(start.elapsed().as_millis() < 2500);
    }

    #[tokio::test]
    async fn test_rtcp_stack_stat_group_limiter_server2() {
        let _ = init_name_lib_for_test(&HashMap::new()).await;
        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let id1 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
         update_did_cache(device_config.id.clone(), None, encoded_doc).await.unwrap();
         add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(device_config.id.to_string().as_str(), "127.0.0.1".parse().unwrap()),
         )
         .await
         .unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        set-stat test;
        set-limit test "10KB/s" "10KB/s";
        return "server www.buckyos.com";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let server_manager = Arc::new(ServerManager::new());
        server_manager.add_server(Server::Stream(Arc::new(MockServer::new("www.buckyos.com".to_string())))).unwrap();
        let tunnel_manager1 = TunnelManager::new();
        let mut limiter_manager1 = DefaultLimiterManager::new();
        let _ = limiter_manager1.new_limiter("test".to_string(), None::<String>, Some(1), Some(2), Some(2));
        let stat1 = StatManager::new();
        let connection_manager = ConnectionManager::new();
        let stack_context = build_stack_context(
            server_manager,
            tunnel_manager1.clone(),
            Arc::new(limiter_manager1),
            stat1.clone(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = RtcpStack::builder()
            .id("test")
            .bind("127.0.0.1:2328".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());

        let stack1 = result.unwrap();
        let result = stack1.start().await;
        assert!(result.is_ok());

        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let _id2 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
         update_did_cache(device_config.id.clone(), None, encoded_doc).await.unwrap();
         add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(device_config.id.to_string().as_str(), "127.0.0.1".parse().unwrap()),
         )
         .await
         .unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "server www.buckyos.com";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let server_manager = Arc::new(ServerManager::new());
        server_manager.add_server(Server::Stream(Arc::new(MockServer::new("www.buckyos.com".to_string())))).unwrap();
        let tunnel_manager2 = TunnelManager::new();
        let stack_context = build_stack_context(
            server_manager,
            tunnel_manager2.clone(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = RtcpStack::builder()
            .id("test2")
            .bind("127.0.0.1:2329".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());

        let stack2 = result.unwrap();
        let result = stack2.start().await;
        assert!(result.is_ok());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let url = Url::parse(format!("rtcp://{}:2328/test:80", id1.to_host_name()).as_str()).unwrap();
        let ret = tunnel_manager2.open_stream_by_url(&url).await;
        assert!(ret.is_ok());
        let start = Instant::now();
        let mut stream = ret.unwrap();
        let result = stream.write_all(b"test").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 4];
        let ret = stream.read_exact(&mut buf).await;
        assert!(ret.is_ok());
        assert_eq!(&buf, b"recv");
        let test_stat = stat1.get_speed_stat("test");
        assert!(test_stat.is_some());
        let test_stat = test_stat.unwrap();
        assert_eq!(test_stat.get_read_sum_size(), 4);
        assert_eq!(test_stat.get_write_sum_size(), 4);
        assert!(start.elapsed().as_millis() > 1800);
        assert!(start.elapsed().as_millis() < 2500);
    }

    struct MockDatagramServer {
        id: String,
    }

    impl MockDatagramServer {
        pub fn new(id: String) -> Self {
            Self {
                id,
            }
        }
    }

    #[async_trait::async_trait]
    impl crate::server::DatagramServer for MockDatagramServer {
        async fn serve_datagram(&self, buf: &[u8], _info: DatagramInfo) -> ServerResult<Vec<u8>> {
            assert_eq!(buf, b"test_server");
            Ok("datagram".as_bytes().to_vec())
        }

        fn id(&self) -> String {
            self.id.clone()
        }
    }

    #[tokio::test]
    async fn test_rudp_stack_server() {
        let _ = init_name_lib_for_test(&HashMap::new()).await;
        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let id1 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
         update_did_cache(device_config.id.clone(), None, encoded_doc).await.unwrap();
         add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(device_config.id.to_string().as_str(), "127.0.0.1".parse().unwrap()),
         )
         .await
         .unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "server www.buckyos.com";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let server_manager = Arc::new(ServerManager::new());
        let _ = server_manager.add_server(Server::Datagram(Arc::new(MockDatagramServer::new("www.buckyos.com".to_string()))));
        let tunnel_manager1 = TunnelManager::new();
        let connection_manager = ConnectionManager::new();
        let stack_context = build_stack_context(
            server_manager,
            tunnel_manager1.clone(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = RtcpStack::builder()
            .id("test")
            .bind("127.0.0.1:2310".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());

        let stack1 = result.unwrap();
        let result = stack1.start().await;
        assert!(result.is_ok());

        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let _id2 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
         update_did_cache(device_config.id.clone(), None, encoded_doc).await.unwrap();
         add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(device_config.id.to_string().as_str(), "127.0.0.1".parse().unwrap()),
         )
         .await
         .unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "server www.buckyos.com";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let server_manager = Arc::new(ServerManager::new());
        let _ = server_manager.add_server(Server::Datagram(Arc::new(MockDatagramServer::new("www.buckyos.com".to_string()))));
        let tunnel_manager2 = TunnelManager::new();
        let stack_context = build_stack_context(
            server_manager,
            tunnel_manager2.clone(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = RtcpStack::builder()
            .id("test2")
            .bind("127.0.0.1:2311".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());

        let stack2 = result.unwrap();
        let result = stack2.start().await;
        assert!(result.is_ok());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let url = Url::parse(format!("rudp://{}:2310/test2:80", id1.to_host_name()).as_str()).unwrap();
        let ret = tunnel_manager2.create_datagram_client_by_url(&url).await;
        assert!(ret.is_ok());
        let stream = ret.unwrap();
        let result = stream.send_datagram(b"test_server").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 8];
        let ret = stream.recv_datagram(&mut buf).await;
        assert!(ret.is_ok());
        assert_eq!(&buf, b"datagram");
    }

    #[tokio::test]
    async fn test_rudp_stack_stat_server() {
        let _ = init_name_lib_for_test(&HashMap::new()).await;
        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let id1 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
         update_did_cache(device_config.id.clone(), None, encoded_doc).await.unwrap();
         add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(device_config.id.to_string().as_str(), "127.0.0.1".parse().unwrap()),
         )
         .await
         .unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        set-stat test;
        return "server www.buckyos.com";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let server_manager = Arc::new(ServerManager::new());
        let _ = server_manager.add_server(Server::Datagram(Arc::new(MockDatagramServer::new("www.buckyos.com".to_string()))));
        let tunnel_manager1 = TunnelManager::new();
        let stat1 = StatManager::new();
        let connection_manager = ConnectionManager::new();
        let stack_context = build_stack_context(
            server_manager,
            tunnel_manager1.clone(),
            Arc::new(DefaultLimiterManager::new()),
            stat1.clone(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = RtcpStack::builder()
            .id("test")
            .bind("127.0.0.1:2332".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());

        let stack1 = result.unwrap();
        let result = stack1.start().await;
        assert!(result.is_ok());

        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let _id2 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
         update_did_cache(device_config.id.clone(), None, encoded_doc).await.unwrap();
         add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(device_config.id.to_string().as_str(), "127.0.0.1".parse().unwrap()),
         )
         .await
         .unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        set-stat test;
        return "server www.buckyos.com";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let server_manager = Arc::new(ServerManager::new());
        let _ = server_manager.add_server(Server::Datagram(Arc::new(MockDatagramServer::new("www.buckyos.com".to_string()))));
        let tunnel_manager2 = TunnelManager::new();
        let stat2 = StatManager::new();
        let stack_context = build_stack_context(
            server_manager,
            tunnel_manager2.clone(),
            Arc::new(DefaultLimiterManager::new()),
            stat2.clone(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = RtcpStack::builder()
            .id("test2")
            .bind("127.0.0.1:2333".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());

        let stack2 = result.unwrap();
        let result = stack2.start().await;
        assert!(result.is_ok());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let url = Url::parse(format!("rudp://{}:2332/test:80", id1.to_host_name()).as_str()).unwrap();
        let ret = tunnel_manager2.create_datagram_client_by_url(&url).await;
        assert!(ret.is_ok());
        let stream = ret.unwrap();
        let result = stream.send_datagram(b"test_server").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 8];
        let ret = stream.recv_datagram(&mut buf).await;
        assert!(ret.is_ok());
        assert_eq!(&buf, b"datagram");

        let test_stat = stat1.get_speed_stat("test");
        assert!(test_stat.is_some());
        let test_stat = test_stat.unwrap();
        assert_eq!(test_stat.get_read_sum_size(), 15);
        assert_eq!(test_stat.get_write_sum_size(), 12);


        let url = Url::parse(format!("rudp://{}:2332/udp://test:80", id1.to_host_name()).as_str()).unwrap();
        let ret = tunnel_manager2.create_datagram_client_by_url(&url).await;
        assert!(ret.is_ok());
        let stream = ret.unwrap();
        let result = stream.send_datagram(b"test_server").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 8];
        let ret = stream.recv_datagram(&mut buf).await;
        assert!(ret.is_ok());
        assert_eq!(&buf, b"datagram");
    }

    #[tokio::test]
    async fn test_rudp_stack_stat_limiter_server() {
        let _ = init_name_lib_for_test(&HashMap::new()).await;
        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let id1 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
         update_did_cache(device_config.id.clone(), None, encoded_doc).await.unwrap();
         add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(device_config.id.to_string().as_str(), "127.0.0.1".parse().unwrap()),
         )
         .await
         .unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        set-stat test;
        set-limit "4B/s" "4B/s";
        return "server www.buckyos.com";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let server_manager = Arc::new(ServerManager::new());
        let _ = server_manager.add_server(Server::Datagram(Arc::new(MockDatagramServer::new("www.buckyos.com".to_string()))));
        let tunnel_manager1 = TunnelManager::new();
        let limiter_manager1 = DefaultLimiterManager::new();
        let stat1 = StatManager::new();
        let connection_manager = ConnectionManager::new();
        let stack_context = build_stack_context(
            server_manager,
            tunnel_manager1.clone(),
            Arc::new(limiter_manager1),
            stat1.clone(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = RtcpStack::builder()
            .id("test")
            .bind("127.0.0.1:2314".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());

        let stack1 = result.unwrap();
        let result = stack1.start().await;
        assert!(result.is_ok());

        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let _id2 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
         update_did_cache(device_config.id.clone(), None, encoded_doc).await.unwrap();
         add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(device_config.id.to_string().as_str(), "127.0.0.1".parse().unwrap()),
         )
         .await
         .unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        set-stat test;
        return "server www.buckyos.com";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let server_manager = Arc::new(ServerManager::new());
        let _ = server_manager.add_server(Server::Datagram(Arc::new(MockDatagramServer::new("www.buckyos.com".to_string()))));
        let tunnel_manager2 = TunnelManager::new();
        let stat2 = StatManager::new();
        let stack_context = build_stack_context(
            server_manager,
            tunnel_manager2.clone(),
            Arc::new(DefaultLimiterManager::new()),
            stat2.clone(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = RtcpStack::builder()
            .id("test2")
            .bind("127.0.0.1:2315".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());

        let stack2 = result.unwrap();
        let result = stack2.start().await;
        assert!(result.is_ok());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let url = Url::parse(format!("rudp://{}:2314/test:80", id1.to_host_name()).as_str()).unwrap();
        let ret = tunnel_manager2.create_datagram_client_by_url(&url).await;
        assert!(ret.is_ok());
        let stream = ret.unwrap();
        let start = Instant::now();
        let result = stream.send_datagram(b"test_server").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 8];
        let ret = stream.recv_datagram(&mut buf).await;
        assert!(ret.is_ok());
        assert_eq!(&buf, b"datagram");

        let test_stat = stat1.get_speed_stat("test");
        assert!(test_stat.is_some());
        let test_stat = test_stat.unwrap();
        assert_eq!(test_stat.get_read_sum_size(), 15);
        assert_eq!(test_stat.get_write_sum_size(), 12);
        assert!(start.elapsed().as_millis() > 4600);
        assert!(start.elapsed().as_millis() < 5200);
    }

    #[tokio::test]
    async fn test_rudp_stack_stat_group_limiter_server() {
        let _ = init_name_lib_for_test(&HashMap::new()).await;
        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let id1 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
         update_did_cache(device_config.id.clone(), None, encoded_doc).await.unwrap();
         add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(device_config.id.to_string().as_str(), "127.0.0.1".parse().unwrap()),
         )
         .await
         .unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        set-stat test;
        set-limit test;
        return "server www.buckyos.com";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let server_manager = Arc::new(ServerManager::new());
        let _ = server_manager.add_server(Server::Datagram(Arc::new(MockDatagramServer::new("www.buckyos.com".to_string()))));
        let tunnel_manager1 = TunnelManager::new();
        let mut limiter_manager1 = DefaultLimiterManager::new();
        let _ = limiter_manager1.new_limiter("test".to_string(), None::<String>, Some(1), Some(4), Some(4));
        let stat1 = StatManager::new();
        let connection_manager = ConnectionManager::new();
        let stack_context = build_stack_context(
            server_manager,
            tunnel_manager1.clone(),
            Arc::new(limiter_manager1),
            stat1.clone(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = RtcpStack::builder()
            .id("test")
            .bind("127.0.0.1:2316".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());

        let stack1 = result.unwrap();
        let result = stack1.start().await;
        assert!(result.is_ok());

        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let _id2 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
         update_did_cache(device_config.id.clone(), None, encoded_doc).await.unwrap();
         add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(device_config.id.to_string().as_str(), "127.0.0.1".parse().unwrap()),
         )
         .await
         .unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        set-stat test;
        return "server www.buckyos.com";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let server_manager = Arc::new(ServerManager::new());
        let _ = server_manager.add_server(Server::Datagram(Arc::new(MockDatagramServer::new("www.buckyos.com".to_string()))));
        let tunnel_manager2 = TunnelManager::new();
        let stat2 = StatManager::new();
        let stack_context = build_stack_context(
            server_manager,
            tunnel_manager2.clone(),
            Arc::new(DefaultLimiterManager::new()),
            stat2.clone(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = RtcpStack::builder()
            .id("test2")
            .bind("127.0.0.1:2317".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());

        let stack2 = result.unwrap();
        let result = stack2.start().await;
        assert!(result.is_ok());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let url = Url::parse(format!("rudp://{}:2316/test:80", id1.to_host_name()).as_str()).unwrap();
        let ret = tunnel_manager2.create_datagram_client_by_url(&url).await;
        assert!(ret.is_ok());
        let stream = ret.unwrap();
        let start = Instant::now();
        let result = stream.send_datagram(b"test_server").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 8];
        let ret = stream.recv_datagram(&mut buf).await;
        assert!(ret.is_ok());
        assert_eq!(&buf, b"datagram");

        let test_stat = stat1.get_speed_stat("test");
        assert!(test_stat.is_some());
        let test_stat = test_stat.unwrap();
        assert_eq!(test_stat.get_read_sum_size(), 15);
        assert_eq!(test_stat.get_write_sum_size(), 12);
        assert!(start.elapsed().as_millis() > 4600);
        assert!(start.elapsed().as_millis() < 5000);
    }

    #[tokio::test]
    async fn test_rudp_stack_stat_group_limiter_server2() {
        let _ = init_name_lib_for_test(&HashMap::new()).await;
        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let id1 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
         update_did_cache(device_config.id.clone(), None, encoded_doc).await.unwrap();
         add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(device_config.id.to_string().as_str(), "127.0.0.1".parse().unwrap()),
         )
         .await
         .unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        set-stat test;
        set-limit test "10KB/s" "10KB/s";
        return "server www.buckyos.com";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let server_manager = Arc::new(ServerManager::new());
        let _ = server_manager.add_server(Server::Datagram(Arc::new(MockDatagramServer::new("www.buckyos.com".to_string()))));
        let tunnel_manager1 = TunnelManager::new();
        let mut limiter_manager1 = DefaultLimiterManager::new();
        let _ = limiter_manager1.new_limiter("test".to_string(), None::<String>, Some(1), Some(4), Some(4));
        let stat1 = StatManager::new();
        let connection_manager = ConnectionManager::new();
        let stack_context = build_stack_context(
            server_manager,
            tunnel_manager1.clone(),
            Arc::new(limiter_manager1),
            stat1.clone(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = RtcpStack::builder()
            .id("test")
            .bind("127.0.0.1:2318".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());

        let stack1 = result.unwrap();
        let result = stack1.start().await;
        assert!(result.is_ok());

        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let _id2 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
         update_did_cache(device_config.id.clone(), None, encoded_doc).await.unwrap();
         add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(device_config.id.to_string().as_str(), "127.0.0.1".parse().unwrap()),
         )
         .await
         .unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        set-stat test;
        return "server www.buckyos.com";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let server_manager = Arc::new(ServerManager::new());
        let _ = server_manager.add_server(Server::Datagram(Arc::new(MockDatagramServer::new("www.buckyos.com".to_string()))));
        let tunnel_manager2 = TunnelManager::new();
        let stat2 = StatManager::new();
        let stack_context = build_stack_context(
            server_manager,
            tunnel_manager2.clone(),
            Arc::new(DefaultLimiterManager::new()),
            stat2.clone(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = RtcpStack::builder()
            .id("test2")
            .bind("127.0.0.1:2319".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());

        let stack2 = result.unwrap();
        let result = stack2.start().await;
        assert!(result.is_ok());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let url = Url::parse(format!("rudp://{}:2318/test:80", id1.to_host_name()).as_str()).unwrap();
        let ret = tunnel_manager2.create_datagram_client_by_url(&url).await;
        assert!(ret.is_ok());
        let stream = ret.unwrap();
        let start = Instant::now();
        let result = stream.send_datagram(b"test_server").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 8];
        let ret = stream.recv_datagram(&mut buf).await;
        assert!(ret.is_ok());
        assert_eq!(&buf, b"datagram");

        let test_stat = stat1.get_speed_stat("test");
        assert!(test_stat.is_some());
        let test_stat = test_stat.unwrap();
        assert_eq!(test_stat.get_read_sum_size(), 15);
        assert_eq!(test_stat.get_write_sum_size(), 12);
        assert!(start.elapsed().as_millis() > 4600);
        assert!(start.elapsed().as_millis() < 5000);
    }

    #[tokio::test]
    async fn test_factory() {
        let server_manager = Arc::new(ServerManager::new());
        let global_process_chains = Arc::new(GlobalProcessChains::new());
        let tunnel_manager = TunnelManager::new();
        let limiter_manager = Arc::new(DefaultLimiterManager::new());
        let stat_manager = StatManager::new();
        let collection_manager = GlobalCollectionManager::create(vec![]).await.unwrap();
        let factory = RtcpStackFactory::new(ConnectionManager::new());

        let (signing_key, pkcs8_bytes) = generate_ed25519_key_pair();

        let key_file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(key_file.path(), signing_key).unwrap();

        let device_config = DeviceConfig::new_by_jwk("test", serde_json::from_value(pkcs8_bytes).unwrap());
        let device_doc = serde_json::to_string(&device_config).unwrap();
        let config_file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(config_file.path(), device_doc).unwrap();

        let config = RtcpStackConfig {
            id: "test".to_string(),
            protocol: StackProtocol::Rtcp,
            bind: "127.0.0.1:394".to_string(),
            hook_point: vec![],
            key_path: key_file.path().to_string_lossy().to_string(),
            device_config_path: None,
            name: Some("test".to_string()),
        };

        let stack_context: Arc<dyn StackContext> = Arc::new(RtcpStackContext::new(
            server_manager,
            tunnel_manager,
            limiter_manager,
            stat_manager,
            Some(global_process_chains),
            Some(collection_manager),
        ));
        let ret = factory.create(Arc::new(config), stack_context.clone()).await;
        assert!(ret.is_ok());

        let config = RtcpStackConfig {
            id: "test1".to_string(),
            protocol: StackProtocol::Rtcp,
            bind: "127.0.0.1:394".to_string(),
            hook_point: vec![],
            key_path: key_file.path().to_string_lossy().to_string(),
            device_config_path: Some(config_file.path().to_string_lossy().to_string()),
            name: Some("test".to_string()),
        };

        let ret = factory.create(Arc::new(config), stack_context).await;
        assert!(ret.is_ok());
    }
}
