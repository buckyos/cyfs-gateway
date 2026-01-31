use std::io::Error;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, RwLock};
use buckyos_kit::AsyncStream;
use ipstack::{IpStackStream, IpStackTcpStream, IpStackUdpStream};
use serde::{Deserialize, Serialize};
use sfo_io::{LimitDatagramRecv, LimitDatagramSend, LimitStream, StatStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::task::JoinHandle;
use cyfs_gateway_lib::*;
use cyfs_process_chain::{CollectionValue, CommandControl, MemoryMapCollection, ProcessChainLibExecutor, StreamRequest};

pub const DEFAULT_MTU: u16 = 1500;

#[derive(Clone)]
pub struct TunStackContext {
    pub servers: ServerManagerRef,
    pub tunnel_manager: TunnelManager,
    pub limiter_manager: LimiterManagerRef,
    pub stat_manager: StatManagerRef,
    pub global_process_chains: Option<GlobalProcessChainsRef>,
    pub global_collection_manager: Option<GlobalCollectionManagerRef>,
}

impl TunStackContext {
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

impl StackContext for TunStackContext {
    fn stack_protocol(&self) -> StackProtocol {
        StackProtocol::Extension("tun".to_string())
    }
}

struct TunConnectionHandler {
    env: Arc<TunStackContext>,
    executor: ProcessChainLibExecutor,
}

impl TunConnectionHandler {
    async fn create(hook_point: ProcessChainConfigs, env: Arc<TunStackContext>) -> StackResult<Self> {
        let (executor, _) = create_process_chain_executor(
            &hook_point,
            env.global_process_chains.clone(),
            env.global_collection_manager.clone(),
            Some(get_external_commands(Arc::downgrade(&env.servers))),
        )
            .await
            .map_err(into_stack_err!(StackErrorCode::ProcessChainError))?;
        Ok(Self { env, executor })
    }

    async fn handle_tcp_stream(
        &self,
        mut stream: StatStream<IpStackTcpStream>,
        stat: MutComposedSpeedStatRef,
    ) -> StackResult<()> {
        let executor = self.executor.fork();
        let servers = self.env.servers.clone();
        let remote_addr = stream.raw_stream().local_addr();
        let dest_addr = stream.raw_stream().peer_addr();
        let mut request = StreamRequest::new(Box::new(stream), dest_addr);
        request.source_addr = Some(remote_addr);
        request.dest_port = dest_addr.port();
        request.app_protocol = Some("tcp".to_string());
        let chain_env = executor.chain_env().clone();
        let (ret, stream) = execute_stream_chain(executor, request)
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

                    let (limiter_id, down_speed, up_speed) = get_limit_info(chain_env.clone()).await?;
                    let upper = if limiter_id.is_some() {
                        self.env.limiter_manager.get_limiter(limiter_id.unwrap())
                    } else {
                        None
                    };
                    let limiter = if down_speed.is_some() && up_speed.is_some() {
                        Some(Limiter::new(
                            upper,
                            Some(1),
                            down_speed.map(|v| v as u32),
                            up_speed.map(|v| v as u32),
                        ))
                    } else {
                        upper
                    };

                    let stat_group_ids = get_stat_info(chain_env).await?;
                    let speed_groups = self
                        .env
                        .stat_manager
                        .get_speed_stats(stat_group_ids.as_slice());
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
                                let (read_limit, write_limit) =
                                    limiter.as_ref().unwrap().new_limit_session();
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
                                let (read_limit, write_limit) =
                                    limiter.as_ref().unwrap().new_limit_session();
                                let limit_stream = LimitStream::new(stream, read_limit, write_limit);
                                Box::new(limit_stream)
                            } else {
                                stream
                            };

                            let server_name = list[1].as_str();
                            if let Some(server) = servers.get_server(server_name) {
                                match server {
                                    Server::Http(server) => {
                                        hyper_serve_http(
                                            stream,
                                            server,
                                            StreamInfo::new(remote_addr.to_string()),
                                        )
                                            .await
                                            .map_err(into_stack_err!(
                                                StackErrorCode::ServerError,
                                                "server {server_name}"
                                            ))?;
                                    }
                                    Server::Stream(server) => {
                                        server
                                            .serve_connection(
                                                stream,
                                                StreamInfo::new(remote_addr.to_string()),
                                            )
                                            .await
                                            .map_err(into_stack_err!(
                                                StackErrorCode::ServerError,
                                                "server {server_name}"
                                            ))?;
                                    }
                                    Server::QA(server) => {
                                        serve_qa_from_stream(
                                            Box::new(stream),
                                            server,
                                            StreamInfo::new(remote_addr.to_string()),
                                        )
                                            .await
                                            .map_err(into_stack_err!(
                                                StackErrorCode::ServerError,
                                                "server {server_name}"
                                            ))?;
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

    async fn handle_udp_stream(
        &self,
        mut stream: StatStream<IpStackUdpStream>,
        stat: MutComposedSpeedStatRef,
    ) -> StackResult<()> {
        let executor = self.executor.fork();
        let servers = self.env.servers.clone();
        let remote_addr = stream.raw_stream().local_addr();
        let dest_addr = stream.raw_stream().peer_addr();

        let map = MemoryMapCollection::new_ref();
        map.insert("dest_addr", CollectionValue::String(dest_addr.to_string()))
            .await
            .map_err(|e| stack_err!(StackErrorCode::ProcessChainError, "{e}"))?;
        map.insert("dest_port", CollectionValue::String(dest_addr.port().to_string()))
            .await
            .map_err(|e| stack_err!(StackErrorCode::ProcessChainError, "{e}"))?;
        map.insert("source_addr", CollectionValue::String(remote_addr.to_string()))
            .await
            .map_err(|e| stack_err!(StackErrorCode::ProcessChainError, "{e}"))?;
        map.insert("app_protocol", CollectionValue::String("udp".to_string()))
            .await
            .map_err(|e| stack_err!(StackErrorCode::ProcessChainError, "{e}"))?;

        let chain_env = executor.chain_env().clone();
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

                    let (limiter_id, down_speed, up_speed) = get_limit_info(chain_env.clone()).await?;
                    let upper = if limiter_id.is_some() {
                        self.env.limiter_manager.get_limiter(limiter_id.unwrap())
                    } else {
                        None
                    };
                    let limiter = if down_speed.is_some() && up_speed.is_some() {
                        Some(Limiter::new(
                            upper,
                            Some(1),
                            down_speed.map(|v| v as u32),
                            up_speed.map(|v| v as u32),
                        ))
                    } else {
                        upper
                    };

                    let stat_group_ids = get_stat_info(chain_env).await?;
                    let speed_groups = self
                        .env
                        .stat_manager
                        .get_speed_stats(stat_group_ids.as_slice());
                    stat.set_external_stats(speed_groups);

                    let (read, send) = tokio::io::split(Box::new(stream) as Box<dyn AsyncStream>);
                    let datagram_stream: Box<dyn DatagramClientBox> = if limiter.is_some() {
                        let (read_limit, write_limit) =
                            limiter.as_ref().unwrap().new_limit_session();
                        Box::new(TunDatagramClient::new(
                            LimitDatagramRecv::new(TunDatagramRecv::new(read), read_limit),
                            LimitDatagramSend::new(TunDatagramSend::new(send), write_limit),
                        ))
                    } else {
                        Box::new(TunDatagramClient::new(
                            TunDatagramRecv::new(read),
                            TunDatagramSend::new(send),
                        ))
                    };

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
                            datagram_forward(datagram_stream, target, &self.env.tunnel_manager)
                                .await?;
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
                                        let mut buf = vec![0; 4096];
                                        loop {
                                            let len = datagram_stream
                                                .recv_datagram(&mut buf)
                                                .await
                                                .map_err(into_stack_err!(
                                                    StackErrorCode::IoError,
                                                    "recv datagram error"
                                                ))?;
                                            let resp = server
                                                .serve_datagram(
                                                    &buf[..len],
                                                    DatagramInfo::new(Some(dest_addr.to_string())),
                                                )
                                                .await
                                                .map_err(into_stack_err!(
                                                    StackErrorCode::ServerError,
                                                    "serve datagram error"
                                                ))?;
                                            datagram_stream
                                                .send_datagram(resp.as_slice())
                                                .await
                                                .map_err(into_stack_err!(
                                                    StackErrorCode::IoError,
                                                    "send datagram error"
                                                ))?;
                                        }
                                    }
                                    _ => {
                                        return Err(stack_err!(
                                            StackErrorCode::InvalidConfig,
                                            "Unsupport server type"
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

pub struct TunDatagramSend {
    send: WriteHalf<Box<dyn AsyncStream>>,
}

impl TunDatagramSend {
    fn new(send: WriteHalf<Box<dyn AsyncStream>>) -> Self {
        Self {
            send,
        }
    }
}

#[async_trait::async_trait]
impl sfo_io::DatagramSend for TunDatagramSend {
    type Error = Error;
    async fn send_to(&mut self, buffer: &[u8]) -> Result<usize, Error> {
        let n = self.send.write(buffer).await?;
        Ok(n)
    }
}

pub struct TunDatagramRecv {
    recv: ReadHalf<Box<dyn AsyncStream>>,
}

impl TunDatagramRecv {
    fn new(recv: ReadHalf<Box<dyn AsyncStream>>) -> Self {
        Self {
            recv,
        }
    }
}

#[async_trait::async_trait]
impl sfo_io::DatagramRecv for TunDatagramRecv {
    type Error = Error;
    async fn recv_from(&mut self, buffer: &mut [u8]) -> Result<usize, Self::Error> {
        let n = self.recv.read(buffer).await?;
        Ok(n)
    }
}

struct TunDatagramClient<R: sfo_io::DatagramRecv, S: sfo_io::DatagramSend> {
    send: Arc<tokio::sync::Mutex<S>>,
    recv: Arc<tokio::sync::Mutex<R>>,
}

impl<R: sfo_io::DatagramRecv, S: sfo_io::DatagramSend> Clone for TunDatagramClient<R, S> {
    fn clone(&self) -> Self {
        Self {
            send: self.send.clone(),
            recv: self.recv.clone(),
        }
    }
}

impl<R: sfo_io::DatagramRecv, S: sfo_io::DatagramSend> TunDatagramClient<R, S> {
    fn new(recv: R, send: S) -> Self {
        Self {
            send: Arc::new(tokio::sync::Mutex::new(send)),
            recv: Arc::new(tokio::sync::Mutex::new(recv)),
        }
    }
}

#[async_trait::async_trait]
impl<R: sfo_io::DatagramRecv<Error=Error>, S: sfo_io::DatagramSend<Error=Error>> DatagramClient for TunDatagramClient<R, S> {
    async fn recv_datagram(&self, buffer: &mut [u8]) -> Result<usize, Error> {
        let mut recv = self.recv.lock().await;
        let n = recv.recv_from(buffer).await?;
        Ok(n)
    }

    async fn send_datagram(&self, buffer: &[u8]) -> Result<usize, Error> {
        let mut send = self.send.lock().await;
        let n = send.send_to(buffer).await?;
        Ok(n)
    }
}

pub struct TunStack {
    inner: Arc<TunStackInner>,
    handle: Mutex<Option<JoinHandle<()>>>,
}

impl Drop for TunStack {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.lock().unwrap().take() {
            handle.abort();
        }
    }
}

impl TunStack {
    pub fn builder() -> TunStackBuilder {
        TunStackBuilder::new()
    }
    async fn create(builder: TunStackBuilder) -> StackResult<Self> {
        let inner = TunStackInner::create(builder).await?;
        Ok(Self {
            inner: Arc::new(inner),
            handle: Mutex::new(None),
        })
    }
}

#[async_trait::async_trait]
impl Stack for TunStack {
    fn id(&self) -> String {
        self.inner.id.clone()
    }

    fn stack_protocol(&self) -> StackProtocol {
        StackProtocol::Extension("tun".to_string())
    }

    fn get_bind_addr(&self) -> String {
        self.inner.ip.to_string()
    }

    async fn start(&self) -> StackResult<()> {
        {
            if self.handle.lock().unwrap().is_some() {
                return Ok(());
            }
        }
        let handle = self.inner.start().await?;
        *self.handle.lock().unwrap() = Some(handle);
        Ok(())
    }

    async fn prepare_update(
        &self,
        config: Arc<dyn StackConfig>,
        context: Option<Arc<dyn StackContext>>,
    ) -> StackResult<()> {
        let config = config
            .as_ref()
            .as_any()
            .downcast_ref::<TunStackConfig>()
            .ok_or(stack_err!(
                StackErrorCode::InvalidConfig,
                "invalid tun stack config"
            ))?;

        if config.id != self.inner.id {
            return Err(stack_err!(StackErrorCode::InvalidConfig, "id unmatch"));
        }

        if config.bind != self.inner.ip {
            return Err(stack_err!(StackErrorCode::BindUnmatched, "bind unmatch"));
        }

        let env = match context {
            Some(context) => {
                let tun_context = context
                    .as_ref()
                    .as_any()
                    .downcast_ref::<TunStackContext>()
                    .ok_or(stack_err!(
                        StackErrorCode::InvalidConfig,
                        "invalid tun stack context"
                    ))?;
                Arc::new(tun_context.clone())
            }
            None => self.inner.handler.read().unwrap().env.clone(),
        };

        let new_handler = TunConnectionHandler::create(config.hook_point.clone(), env).await?;
        *self.inner.prepare_handler.write().unwrap() = Some(Arc::new(new_handler));
        Ok(())
    }

    async fn commit_update(&self) {
        if let Some(handler) = self.inner.prepare_handler.write().unwrap().take() {
            *self.inner.handler.write().unwrap() = handler;
        }
    }

    async fn rollback_update(&self) {
        self.inner.prepare_handler.write().unwrap().take();
    }
}

struct TunStackInner {
    id: String,
    ip: IpAddr,
    mask: IpAddr,
    mtu: u16,
    tcp_timeout: u64,
    udp_timeout: u64,
    handler: Arc<RwLock<Arc<TunConnectionHandler>>>,
    prepare_handler: Arc<RwLock<Option<Arc<TunConnectionHandler>>>>,
    connection_manager: Option<ConnectionManagerRef>,
}

impl TunStackInner {
    async fn create(builder: TunStackBuilder) -> StackResult<Self> {
        if builder.id.is_none() {
            return Err(stack_err!(
                StackErrorCode::InvalidConfig,
                "id is required"
            ));
        }
        if builder.ip.is_none() {
            return Err(stack_err!(
                StackErrorCode::InvalidConfig,
                "ip is required"
            ));
        }
        if builder.mask.is_none() {
            return Err(stack_err!(
                StackErrorCode::InvalidConfig,
                "mask is required"
            ));
        }
        if builder.hook_point.is_none() {
            return Err(stack_err!(
                StackErrorCode::InvalidConfig,
                "hook_point is required"
            ));
        }
        if builder.stack_context.is_none() {
            return Err(stack_err!(StackErrorCode::InvalidConfig, "stack_context is required"));
        }

        let env = builder.stack_context.unwrap();
        let handler = TunConnectionHandler::create(builder.hook_point.as_ref().unwrap().clone(), env)
            .await?;

        Ok(Self {
            id: builder.id.unwrap(),
            ip: builder.ip.unwrap(),
            mask: builder.mask.unwrap(),
            mtu: builder.mtu.unwrap_or(DEFAULT_MTU),
            tcp_timeout: builder.tcp_timeout,
            udp_timeout: builder.udp_timeout,
            handler: Arc::new(RwLock::new(Arc::new(handler))),
            prepare_handler: Arc::new(Default::default()),
            connection_manager: builder.connection_manager,
        })
    }

    async fn start(self: &Arc<Self>) -> StackResult<JoinHandle<()>> {
        let mut config = tun::Configuration::default();
        config.address(self.ip).netmask(self.mask);

        let truncated_name = if cfg!(target_os = "macos") {
            let name = format!("utun{}", self.id);
            // MacOS: 15 chars max
            name[..std::cmp::min(name.len(), 8)].to_string()
        } else if cfg!(target_os = "linux") {
            let name = format!("tun_{}", self.id);
            // Linux: 15 chars max
            name[..std::cmp::min(name.len(), 15)].to_string()
        } else if cfg!(windows) {
            let name = format!("tun_{}", self.id);
            // Windows: 32 chars max for compatibility (even though wintun allows 128)
            name[..std::cmp::min(name.len(), 32)].to_string()
        } else {
            let name = format!("tun_{}", self.id);
            name[..std::cmp::min(name.len(), 15)].to_string()
        };

        config.tun_name(truncated_name.clone());

        #[cfg(target_os = "linux")]
        config.platform_config(|cfg| {
            #[allow(deprecated)]
            cfg.packet_information(true);
            cfg.ensure_root_privileges(true);
        });


        #[cfg(any(target_os = "ios", target_os = "macos"))]
        config.platform_config(|cfg| {
            cfg.packet_information(true);
        });

        let dev = tun::create_as_async(&config)
            .map_err(into_stack_err!(StackErrorCode::Failed, "create tun device {} failed", self.id))?;

        let mut ipstack_config = ipstack::IpStackConfig::default();
        ipstack_config.mtu(self.mtu);
        let mut tcp_cfg = ipstack::TcpConfig::default();
        tcp_cfg.timeout = std::time::Duration::from_secs(self.tcp_timeout);
        ipstack_config.with_tcp_config(tcp_cfg);
        ipstack_config.udp_timeout(std::time::Duration::from_secs(self.udp_timeout));

        let this = self.clone();
        let mut ip_stack = ipstack::IpStack::new(ipstack_config, dev);
        let handle = tokio::spawn(async move {
            loop {
                match ip_stack.accept().await {
                    Ok(stream) => {
                        match stream {
                            IpStackStream::Tcp(stream) => {
                                let dest_addr = stream.peer_addr();
                                let src_addr = stream.local_addr();
                                let compose_stat = MutComposedSpeedStat::new();
                                let stat_stream = StatStream::new_with_tracker(stream, compose_stat.clone());
                                let speed = stat_stream.get_speed_stat();
                                let handler_snapshot = {
                                    let handler = this.handler.read().unwrap();
                                    handler.clone()
                                };
                                let handle = tokio::spawn(async move {
                                    if let Err(e) = handler_snapshot
                                        .handle_tcp_stream(stat_stream, compose_stat)
                                        .await
                                    {
                                        log::error!("handle tcp stream error: {}", e);
                                    }
                                });

                                if let Some(manager) = &this.connection_manager {
                                    let controller = HandleConnectionController::new(handle);
                                    manager.add_connection(ConnectionInfo::new(dest_addr.to_string(),
                                                                               src_addr.to_string(),
                                                                               StackProtocol::Tcp,
                                                                               speed, controller));
                                }
                            }
                            IpStackStream::Udp(stream) => {
                                let dest_addr = stream.peer_addr();
                                let src_addr = stream.local_addr();
                                let compose_stat = MutComposedSpeedStat::new();
                                let stat_stream = StatStream::new_with_tracker(stream, compose_stat.clone());
                                let speed = stat_stream.get_speed_stat();
                                let handler_snapshot = {
                                    let handler = this.handler.read().unwrap();
                                    handler.clone()
                                };
                                let handle = tokio::spawn(async move {
                                    if let Err(e) = handler_snapshot
                                        .handle_udp_stream(stat_stream, compose_stat)
                                        .await
                                    {
                                        log::error!("handle udp stream error: {}", e);
                                    }
                                });

                                if let Some(manager) = &this.connection_manager {
                                    let controller = HandleConnectionController::new(handle);
                                    manager.add_connection(ConnectionInfo::new(dest_addr.to_string(),
                                                                               src_addr.to_string(),
                                                                               StackProtocol::Udp,
                                                                               speed, controller));
                                }
                            }
                            IpStackStream::UnknownTransport(u) => {
                                let len = u.payload().len();
                                log::info!("#0 unhandled transport - Ip Protocol {:?}, length {}", u.ip_protocol(), len);
                                continue;
                            }
                            IpStackStream::UnknownNetwork(pkt) => {
                                log::info!("#0 unknown transport - {} bytes", pkt.len());
                                continue;
                            }
                        }
                    }
                    Err(err) => {
                        log::error!("accept error: {}", err);
                        break;
                    }
                }
            }
        });
        Ok(handle)
    }

}

pub struct TunStackBuilder {
    id: Option<String>,
    ip: Option<IpAddr>,
    mask: Option<IpAddr>,
    mtu: Option<u16>,
    tcp_timeout: u64,
    udp_timeout: u64,
    hook_point: Option<ProcessChainConfigs>,
    connection_manager: Option<ConnectionManagerRef>,
    stack_context: Option<Arc<TunStackContext>>,
}

impl TunStackBuilder {
    pub fn new() -> Self {
        TunStackBuilder {
            id: None,
            ip: None,
            mask: None,
            mtu: None,
            tcp_timeout: 60,
            udp_timeout: 60,
            hook_point: None,
            connection_manager: None,
            stack_context: None,
        }
    }

    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    pub fn ip(mut self, ip: IpAddr) -> Self {
        self.ip = Some(ip);
        self
    }

    pub fn mask(mut self, mask: IpAddr) -> Self {
        self.mask = Some(mask);
        self
    }

    pub fn mtu(mut self, mtu: u16) -> Self {
        self.mtu = Some(mtu);
        self
    }

    pub fn tcp_timeout(mut self, tcp_timeout: u64) -> Self {
        self.tcp_timeout = tcp_timeout;
        self
    }

    pub fn udp_timeout(mut self, udp_timeout: u64) -> Self {
        self.udp_timeout = udp_timeout;
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

    pub fn stack_context(mut self, stack_context: Arc<TunStackContext>) -> Self {
        self.stack_context = Some(stack_context);
        self
    }
    
    pub async fn build(self) -> StackResult<TunStack> {
        TunStack::create(self).await
    }
}
#[derive(Serialize, Deserialize, Clone)]
pub struct TunStackConfig {
    pub id: String,
    pub protocol: StackProtocol,
    pub bind: IpAddr,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mask: Option<IpAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp_timeout: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub udp_timeout: Option<u64>,
    pub hook_point: Vec<ProcessChainConfig>,
}

impl StackConfig for TunStackConfig {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn stack_protocol(&self) -> StackProtocol {
        self.protocol.clone()
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

pub struct TunStackFactory {
    connection_manager: ConnectionManagerRef,
}

impl TunStackFactory {
    pub fn new(
        connection_manager: ConnectionManagerRef,
    ) -> Self {
        TunStackFactory {
            connection_manager,
        }
    }
}

#[async_trait::async_trait]
impl StackFactory for TunStackFactory {
    async fn create(
        &self,
        config: Arc<dyn StackConfig>,
        context: Arc<dyn StackContext>,
    ) -> StackResult<StackRef> {
        let config = config
            .as_any()
            .downcast_ref::<TunStackConfig>()
            .ok_or(stack_err!(StackErrorCode::InvalidConfig, "invalid tun stack config"))?;

        let stack_context = context
            .as_ref()
            .as_any()
            .downcast_ref::<TunStackContext>()
            .ok_or(stack_err!(StackErrorCode::InvalidConfig, "invalid tun stack context"))?;
        let stack_context = Arc::new(stack_context.clone());

        let stack = TunStack::builder()
            .id(config.id.clone())
            .ip(config.bind)
            .mask(config.mask.unwrap_or(IpAddr::from([255, 255, 255, 0])))
            .mtu(config.mtu.unwrap_or(1500))
            .tcp_timeout(config.tcp_timeout.unwrap_or(60))
            .udp_timeout(config.udp_timeout.unwrap_or(60))
            .hook_point(config.hook_point.clone())
            .connection_manager(self.connection_manager.clone())
            .stack_context(stack_context)
            .build().await?;
        Ok(Arc::new(stack))
    }
}
