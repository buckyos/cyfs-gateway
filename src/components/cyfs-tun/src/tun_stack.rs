use std::io::Error;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use buckyos_kit::AsyncStream;
use ipstack::{IpStackStream, IpStackTcpStream, IpStackUdpStream};
use serde::{Deserialize, Serialize};
use sfo_io::{LimitStream, StatStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::task::JoinHandle;
use cyfs_gateway_lib::*;
use cyfs_process_chain::{CollectionValue, CommandControl, MemoryMapCollection, ProcessChainLibExecutor, StreamRequest};

pub const DEFAULT_MTU: u16 = 1500;

#[derive(Clone)]
struct TunDatagramClient {
    send: Arc<tokio::sync::Mutex<WriteHalf<Box<dyn AsyncStream>>>>,
    recv: Arc<tokio::sync::Mutex<ReadHalf<Box<dyn AsyncStream>>>>,
}

impl TunDatagramClient {
    fn new(stream: Box<dyn AsyncStream>) -> Self {
        let (recv, send) = tokio::io::split(stream);
        Self {
            send: Arc::new(tokio::sync::Mutex::new(send)),
            recv: Arc::new(tokio::sync::Mutex::new(recv)),
        }
    }
}

#[async_trait::async_trait]
impl DatagramClient for TunDatagramClient {
    async fn recv_datagram(&self, buffer: &mut [u8]) -> Result<usize, Error> {
        let mut recv = self.recv.lock().await;
        let n = recv.read(buffer).await?;
        Ok(n)
    }

    async fn send_datagram(&self, buffer: &[u8]) -> Result<usize, Error> {
        let mut send = self.send.lock().await;
        let n = send.write(buffer).await?;
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
        let handle = self.inner.start().await?;
        *self.handle.lock().unwrap() = Some(handle);
        Ok(())
    }

    async fn update_config(&self, config: Arc<dyn StackConfig>) -> StackResult<()> {
        let config = config.as_ref().as_any().downcast_ref::<TunStackConfig>()
            .ok_or(stack_err!(StackErrorCode::InvalidConfig, "invalid config"))?;

        if config.id != self.inner.id {
            return Err(stack_err!(StackErrorCode::InvalidConfig, "id unmatch"));
        }

        if config.bind != self.inner.ip {
            return Err(stack_err!(StackErrorCode::BindUnmatched, "bind unmatch"));
        }

        let (executor, _) = create_process_chain_executor(&config.hook_point,
                                                          self.inner.global_process_chains.clone(),
                                                          Some(get_stream_external_commands())).await
            .map_err(into_stack_err!(StackErrorCode::ProcessChainError))?;
        *self.inner.executor.lock().unwrap() = executor;
        Ok(())
    }
}

struct TunStackInner {
    id: String,
    ip: IpAddr,
    mask: IpAddr,
    mtu: u16,
    tcp_timeout: u64,
    udp_timeout: u64,
    servers: ServerManagerRef,
    executor: Arc<Mutex<ProcessChainLibExecutor>>,
    connection_manager: Option<ConnectionManagerRef>,
    tunnel_manager: TunnelManager,
    global_process_chains: Option<GlobalProcessChainsRef>,
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
        if builder.servers.is_none() {
            return Err(stack_err!(StackErrorCode::InvalidConfig, "servers is required"));
        }
        if builder.tunnel_manager.is_none() {
            return Err(stack_err!(StackErrorCode::InvalidConfig, "tunnel_manager is required"));
        }

        let (executor, _) = create_process_chain_executor(builder.hook_point.as_ref().unwrap(),
                                                          builder.global_process_chains.clone(),
                                                          Some(get_stream_external_commands())).await
            .map_err(into_stack_err!(StackErrorCode::ProcessChainError))?;

        Ok(Self {
            id: builder.id.unwrap(),
            ip: builder.ip.unwrap(),
            mask: builder.mask.unwrap(),
            mtu: builder.mtu.unwrap_or(DEFAULT_MTU),
            tcp_timeout: 0,
            udp_timeout: 0,
            servers: builder.servers.unwrap(),
            executor: Arc::new(Mutex::new(executor)),
            connection_manager: builder.connection_manager,
            tunnel_manager: builder.tunnel_manager.unwrap(),
            global_process_chains: builder.global_process_chains,
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
                                let src_addr = stream.peer_addr();
                                let dest_addr = stream.local_addr();
                                let stat_stream = StatStream::new(stream);
                                let speed = stat_stream.get_speed_stat();
                                let stack = this.clone();
                                let handle = tokio::spawn(async move {
                                    if let Err(e) = stack.on_new_tcp_stream(stat_stream).await {
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
                                let src_addr = stream.peer_addr();
                                let dest_addr = stream.local_addr();
                                let stat_stream = StatStream::new(stream);
                                let speed = stat_stream.get_speed_stat();
                                let stack = this.clone();
                                let handle = tokio::spawn(async move {
                                    if let Err(e) = stack.on_new_udp_stream(stat_stream).await {
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

    async fn on_new_tcp_stream(&self, mut stream: StatStream<IpStackTcpStream>) -> StackResult<()> {
        let executor = {
            self.executor.lock().unwrap().fork()
        };
        let servers = self.servers.clone();
        let remote_addr = stream.raw_stream().peer_addr();
        let dest_addr = stream.raw_stream().local_addr();
        let mut request = StreamRequest::new(Box::new(stream), dest_addr);
        request.source_addr = Some(remote_addr);
        request.app_protocol = Some("tcp".to_string());
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
                    if list.len() == 0 {
                        return Ok(());
                    }

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
                            let limiter = Limiter::new(None, None);
                            let stream = Box::new(LimitStream::new(stream, Arc::new(limiter)));
                            stream_forward(stream, target, &self.tunnel_manager).await?;
                        }
                        "server" => {
                            if list.len() < 2 {
                                return Err(stack_err!(
                                    StackErrorCode::InvalidConfig,
                                    "invalid server command"
                                ));
                            }
                            let limiter = Limiter::new(None, None);
                            let stream = Box::new(LimitStream::new(stream, Arc::new(limiter)));

                            let server_name = list[1].as_str();
                            if let Some(server) = servers.get_server(server_name) {
                                match server {
                                    Server::Http(server) => {
                                        hyper_serve_http(stream, server, StreamInfo::new(remote_addr.to_string())).await
                                            .map_err(into_stack_err!(StackErrorCode::ServerError, "server {server_name}"))?;
                                    }
                                    Server::Stream(server) => {
                                        server
                                            .serve_connection(stream, StreamInfo::new(remote_addr.to_string()))
                                            .await
                                            .map_err(into_stack_err!(StackErrorCode::ServerError, "server {server_name}"))?;
                                    }
                                    Server::Datagram(_) => {
                                        return Err(stack_err!(
                                            StackErrorCode::InvalidConfig,
                                            "datagram server {server_name} not support"
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

    async fn on_new_udp_stream(&self, mut stream: StatStream<IpStackUdpStream>) -> StackResult<()> {
        let executor = {
            self.executor.lock().unwrap().fork()
        };
        let servers = self.servers.clone();
        let remote_addr = stream.raw_stream().peer_addr();
        let dest_addr = stream.raw_stream().local_addr();

        let map = MemoryMapCollection::new_ref();
        map.insert("dest_addr", CollectionValue::String(dest_addr.to_string())).await
            .map_err(|e| stack_err!(StackErrorCode::ProcessChainError, "{e}"))?;
        map.insert("source_addr", CollectionValue::String(remote_addr.to_string())).await
            .map_err(|e| stack_err!(StackErrorCode::ProcessChainError, "{e}"))?;
        map.insert("app_protocol", CollectionValue::String("udp".to_string())).await
            .map_err(|e| stack_err!(StackErrorCode::ProcessChainError, "{e}"))?;

        let ret = execute_chain(executor, map).await
            .map_err(into_stack_err!(StackErrorCode::ProcessChainError))?;

        if ret.is_control() {
            if ret.is_drop() {
                return Ok(());
            } else if ret.is_reject() {
                return Ok(());
            }

            if let Some(CommandControl::Return(ret)) = ret.as_control() {
                if let Some(list) = shlex::split(ret.value.as_str()) {
                    if list.len() == 0 {
                        return Ok(());
                    }

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
                            let limiter = Limiter::new(None, None);
                            let stream = Box::new(LimitStream::new(stream, Arc::new(limiter)));
                            let datagram_stream = Box::new(TunDatagramClient::new(stream));
                            datagram_forward(datagram_stream, target, &self.tunnel_manager).await?;
                        }
                        "server" => {
                            if list.len() < 2 {
                                return Err(stack_err!(
                                    StackErrorCode::InvalidConfig,
                                    "invalid server command"
                                ));
                            }
                            let limiter = Limiter::new(None, None);
                            let stream = Box::new(LimitStream::new(stream, Arc::new(limiter)));

                            let server_name = list[1].as_str();
                            if let Some(server) = servers.get_server(server_name) {
                                match server {
                                    Server::Http(_) => {
                                        return Err(stack_err!(
                                            StackErrorCode::InvalidConfig,
                                            "http server {server_name} not support"
                                        ));
                                    }
                                    Server::Stream(_) => {
                                        return Err(stack_err!(
                                            StackErrorCode::InvalidConfig,
                                            "stream server {server_name} not support"
                                        ));
                                    }
                                    Server::Datagram(server) => {
                                        let datagram_stream = TunDatagramClient::new(stream);
                                        let mut buf = vec![0; 4096];
                                        loop {
                                            let len = datagram_stream.recv_datagram(&mut buf).await
                                                .map_err(into_stack_err!(StackErrorCode::IoError, "recv datagram error"))?;
                                            let resp = server.serve_datagram(&buf[..len], DatagramInfo::new(Some(dest_addr.to_string()))).await
                                                .map_err(into_stack_err!(StackErrorCode::ServerError, "serve datagram error"))?;
                                            datagram_stream.send_datagram(resp.as_slice()).await
                                                .map_err(into_stack_err!(StackErrorCode::IoError, "send datagram error"))?;
                                        }
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

pub struct TunStackBuilder {
    id: Option<String>,
    ip: Option<IpAddr>,
    mask: Option<IpAddr>,
    mtu: Option<u16>,
    tcp_timeout: u64,
    udp_timeout: u64,
    hook_point: Option<ProcessChainConfigs>,
    servers: Option<ServerManagerRef>,
    global_process_chains: Option<GlobalProcessChainsRef>,
    connection_manager: Option<ConnectionManagerRef>,
    tunnel_manager: Option<TunnelManager>,
}

impl TunStackBuilder {
    pub fn new() -> Self {
        TunStackBuilder {
            id: None,
            ip: None,
            mask: None,
            mtu: None,
            tcp_timeout: 30,
            udp_timeout: 30,
            hook_point: None,
            servers: None,
            global_process_chains: None,
            connection_manager: None,
            tunnel_manager: None,
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

    pub fn servers(mut self, servers: ServerManagerRef) -> Self {
        self.servers = Some(servers);
        self
    }

    pub fn global_process_chains(mut self, global_process_chains: GlobalProcessChainsRef) -> Self {
        self.global_process_chains = Some(global_process_chains);
        self
    }

    pub fn connection_manager(mut self, connection_manager: ConnectionManagerRef) -> Self {
        self.connection_manager = Some(connection_manager);
        self
    }

    pub fn tunnel_manager(mut self, tunnel_manager: TunnelManager) -> Self {
        self.tunnel_manager = Some(tunnel_manager);
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
    servers: ServerManagerRef,
    global_process_chains: GlobalProcessChainsRef,
    connection_manager: ConnectionManagerRef,
    tunnel_manager: TunnelManager,
}

impl TunStackFactory {
    pub fn new(
        servers: ServerManagerRef,
        global_process_chains: GlobalProcessChainsRef,
        connection_manager: ConnectionManagerRef,
        tunnel_manager: TunnelManager,
    ) -> Self {
        TunStackFactory {
            servers,
            global_process_chains,
            connection_manager,
            tunnel_manager,
        }
    }
}

#[async_trait::async_trait]
impl StackFactory for TunStackFactory {
    async fn create(&self, config: Arc<dyn StackConfig>) -> StackResult<StackRef> {
        let config = config
            .as_any()
            .downcast_ref::<TunStackConfig>()
            .ok_or(stack_err!(StackErrorCode::InvalidConfig, "invalid config"))?;

        let stack = TunStack::builder()
            .id(config.id.clone())
            .ip(config.bind)
            .mask(config.mask.unwrap_or(IpAddr::from([255, 255, 255, 0])))
            .mtu(config.mtu.unwrap_or(1500))
            .tcp_timeout(config.tcp_timeout.unwrap_or(30))
            .udp_timeout(config.udp_timeout.unwrap_or(30))
            .hook_point(config.hook_point.clone())
            .servers(self.servers.clone())
            .global_process_chains(self.global_process_chains.clone())
            .connection_manager(self.connection_manager.clone())
            .tunnel_manager(self.tunnel_manager.clone())
            .build().await?;
        Ok(Arc::new(stack))
    }
}