#[cfg(unix)]
use super::{get_socket_opt, has_root_privileges, set_socket_opt, sockaddr_to_socket_addr, stream_forward, Stack};
#[cfg(windows)]
use super::{stream_forward, Stack};

use super::StackResult;
use crate::global_process_chains::{
    create_process_chain_executor, execute_stream_chain, GlobalProcessChainsRef,
};
use crate::{into_stack_err, stack_err, ProcessChainConfigs, StackErrorCode, StackProtocol, ServerManagerRef, Server, hyper_serve_http, ConnectionManagerRef, ConnectionInfo, HandleConnectionController, TunnelManager, StackConfig, StackFactory, ProcessChainConfig, StackRef, StreamInfo, get_min_priority};
use cyfs_process_chain::{CommandControl, ProcessChainLibExecutor, StreamRequest};
use std::net::SocketAddr;
#[cfg(unix)]
use std::os::fd::{FromRawFd, IntoRawFd};
#[cfg(windows)]
use std::os::windows::io::{FromRawSocket, IntoRawSocket};
use std::sync::{Arc, Mutex};
use serde::{Deserialize, Serialize};
use sfo_io::{LimitStream, StatStream};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use crate::stack::limiter::Limiter;

struct TcpStackInner {
    id: String,
    bind_addr: String,
    servers: ServerManagerRef,
    executor: Arc<Mutex<ProcessChainLibExecutor>>,
    connection_manager: Option<ConnectionManagerRef>,
    tunnel_manager: TunnelManager,
    global_process_chains: Option<GlobalProcessChainsRef>,
    transparent: bool,
}


impl TcpStackInner {
    async fn create(config: TcpStackBuilder) -> StackResult<Self> {
        if config.id.is_none() {
            return Err(stack_err!(
                StackErrorCode::InvalidConfig,
                "id is required"
            ));
        }
        if config.bind.is_none() {
            return Err(stack_err!(
                StackErrorCode::InvalidConfig,
                "bind is required"
            ));
        }
        if config.hook_point.is_none() {
            return Err(stack_err!(
                StackErrorCode::InvalidConfig,
                "hook_point is required"
            ));
        }
        if config.servers.is_none() {
            return Err(stack_err!(
                StackErrorCode::InvalidConfig,
                "servers is required"
            ));
        }
        if config.tunnel_manager.is_none() {
            return Err(stack_err!(
                StackErrorCode::InvalidConfig,
                "tunnel_manager is required"
            ));
        }

        let (executor, _) = create_process_chain_executor(config.hook_point.as_ref().unwrap(),
                                                          config.global_process_chains.clone()).await
            .map_err(into_stack_err!(StackErrorCode::ProcessChainError))?;
        Ok(Self {
            id: config.id.unwrap(),
            bind_addr: config.bind.unwrap(),
            servers: config.servers.unwrap(),
            executor: Arc::new(Mutex::new(executor)),
            connection_manager: config.connection_manager,
            tunnel_manager: config.tunnel_manager.unwrap(),
            global_process_chains: config.global_process_chains,
            transparent: config.transparent,
        })
    }

    pub async fn start(self: &Arc<Self>) -> StackResult<JoinHandle<()>> {
        let addr: SocketAddr = self.bind_addr.parse()
            .map_err(into_stack_err!(StackErrorCode::InvalidConfig, "invalid bind address"))?;
        let sockaddr: socket2::SockAddr = addr.into();

        // 2. 创建原始套接字
        // 根据目标地址的IP版本选择域 (Domain::IPV4 或 Domain::IPV6)
        let domain = match addr {
            std::net::SocketAddr::V4(_) => socket2::Domain::IPV4,
            std::net::SocketAddr::V6(_) => socket2::Domain::IPV6,
        };
        // 创建数据报 (DGRAM) 套接字，对应 UDP
        let socket = socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))
            .map_err(into_stack_err!(StackErrorCode::IoError, "create socket error"))?;

        socket.set_nonblocking(true).map_err(into_stack_err!(StackErrorCode::IoError, "set nonblocking error"))?;
        #[cfg(unix)]
        {
            if self.transparent {
                if !has_root_privileges() {
                    return Err(stack_err!(
                        StackErrorCode::PermissionDenied,
                        "transparent mode requires root privileges"
                    ));
                }
                socket.set_reuse_address(true)
                    .map_err(into_stack_err!(StackErrorCode::IoError, "set reuse address error"))?;
                socket.set_ip_transparent_v4(true)
                    .map_err(into_stack_err!(StackErrorCode::IoError, "set ip transparent error"))?;

                unsafe {
                    if domain == socket2::Domain::IPV4 {
                        set_socket_opt(&socket,
                                       libc::SOL_IP,
                                       libc::IP_TRANSPARENT,
                                       libc::c_int::from(1))?;
                    } else if domain == socket2::Domain::IPV6 {
                        set_socket_opt(&socket,
                                       libc::SOL_IPV6,
                                       libc::IP_TRANSPARENT,
                                       libc::c_int::from(1))?;
                    }
                }
            }
        }
        socket.bind(&sockaddr).map_err(into_stack_err!(StackErrorCode::BindFailed, "bind error"))?;
        socket.listen(1024).map_err(into_stack_err!(StackErrorCode::ListenFailed, "listen error"))?;
        #[cfg(unix)]
        let std_listener = unsafe {
            std::net::TcpListener::from_raw_fd(socket.into_raw_fd())
        };
        #[cfg(windows)]
        let std_listener = unsafe {
            std::net::TcpListener::from_raw_socket(socket.into_raw_socket())
        };
        let listener = tokio::net::TcpListener::from_std(std_listener)
            .map_err(into_stack_err!(StackErrorCode::BindFailed))?;
        let this = self.clone();
        let handle = tokio::spawn(async move {
            loop {
                let (stream, remote_addr) = match listener.accept().await {
                    Ok(s) => s,
                    Err(e) => {
                        log::error!("accept tcp stream failed: {}", e);
                        continue;
                    }
                };

                let dest_addr = match Self::get_dest_addr(&stream) {
                    Ok(addr) => addr,
                    Err(e) => {
                        log::error!("get dest addr failed: {}", e);
                        continue;
                    }
                };
                log::info!("accept tcp stream from {} to {}", remote_addr, dest_addr);
                let this_tmp = this.clone();
                let stat_stream = StatStream::new(stream);
                let speed = stat_stream.get_speed_stat();
                let handle = tokio::spawn(async move {
                    if let Err(e) =
                        this_tmp.handle_connect(stat_stream, dest_addr).await
                    {
                        log::error!("handle tcp stream failed: {}", e);
                    }
                });
                if let Some(manager) = &this.connection_manager {
                    let controller = HandleConnectionController::new(handle);
                    manager.add_connection(ConnectionInfo::new(remote_addr.to_string(), dest_addr.to_string(), StackProtocol::Tcp, speed, controller));
                }
            }
        });
        Ok(handle)
    }

    fn get_dest_addr(stream: &TcpStream) -> StackResult<SocketAddr> {
        #[cfg(unix)] {
            let mut addr: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            let ret = crate::stack::get_socket_opt(
                stream,
                libc::SOL_IPV6,
                libc::IP6T_SO_ORIGINAL_DST,
                &mut addr,
            );
            if ret.is_ok() {
                return crate::stack::sockaddr_to_socket_addr(&addr)
                    .map_err(into_stack_err!(StackErrorCode::InvalidData, "read dest addr failed"));
            }

            let ret = crate::stack::get_socket_opt(
                stream,
                libc::SOL_IP,
                libc::SO_ORIGINAL_DST,
                &mut addr,
            );
            if ret.is_ok() {
                return crate::stack::sockaddr_to_socket_addr(&addr)
                    .map_err(into_stack_err!(StackErrorCode::InvalidData, "read dest addr failed"));
            }
        }

        stream.local_addr().map_err(into_stack_err!(StackErrorCode::ServerError, "read dest addr failed"))
    }

    async fn handle_connect(
        &self,
        mut stream: StatStream<TcpStream>,
        dest_addr: SocketAddr,
    ) -> StackResult<()> {
        let executor = {
            self.executor.lock().unwrap().fork()
        };
        let servers = self.servers.clone();
        let remote_addr = stream.raw_stream().peer_addr().map_err(into_stack_err!(StackErrorCode::ServerError, "read remote addr failed"))?;
        let mut request = StreamRequest::new(Box::new(stream), dest_addr);
        request.source_addr = Some(remote_addr);
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
                                        hyper_serve_http(stream, server).await
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

    pub async fn update_hook_point(&mut self, _config: ProcessChainConfigs) -> StackResult<()> {
        Ok(())
    }
}

pub struct TcpStack {
    inner: Arc<TcpStackInner>,
    handle: Mutex<Option<JoinHandle<()>>>,
}

impl TcpStack {
    pub fn builder() -> TcpStackBuilder {
        TcpStackBuilder {
            id: None,
            bind: None,
            hook_point: None,
            servers: None,
            global_process_chains: None,
            connection_manager: None,
            tunnel_manager: None,
            transparent: false,
        }
    }

    async fn create(config: TcpStackBuilder) -> StackResult<Self> {
        let inner = TcpStackInner::create(config).await?;
        Ok(Self {
            inner: Arc::new(inner),
            handle: Mutex::new(None),
        })
    }
}

impl Drop for TcpStack {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.lock().unwrap().take() {
            handle.abort();
        }
    }
}

#[async_trait::async_trait]
impl Stack for TcpStack {
    fn id(&self) -> String {
        self.inner.id.clone()
    }

    fn stack_protocol(&self) -> StackProtocol {
        StackProtocol::Tcp
    }

    fn get_bind_addr(&self) -> String {
        self.inner.bind_addr.clone()
    }

    async fn start(&self) -> StackResult<()> {
        let handle = self.inner.start().await?;
        *self.handle.lock().unwrap() = Some(handle);
        Ok(())
    }

    async fn update_config(&self, config: Arc<dyn StackConfig>) -> StackResult<()> {
        let config = config.as_ref().as_any().downcast_ref::<TcpStackConfig>()
            .ok_or(stack_err!(StackErrorCode::InvalidConfig, "invalid config"))?;

        if config.id != self.inner.id {
            return Err(stack_err!(StackErrorCode::InvalidConfig, "id unmatch"));
        }

        if config.bind.to_string() != self.inner.bind_addr {
            return Err(stack_err!(StackErrorCode::InvalidConfig, "bind unmatch"));
        }

        let (executor, _) = create_process_chain_executor(&config.hook_point,
                                                          self.inner.global_process_chains.clone()).await
            .map_err(into_stack_err!(StackErrorCode::ProcessChainError))?;
        *self.inner.executor.lock().unwrap() = executor;
        Ok(())
    }
}


pub struct TcpStackBuilder {
    id: Option<String>,
    bind: Option<String>,
    hook_point: Option<ProcessChainConfigs>,
    servers: Option<ServerManagerRef>,
    global_process_chains: Option<GlobalProcessChainsRef>,
    connection_manager: Option<ConnectionManagerRef>,
    tunnel_manager: Option<TunnelManager>,
    transparent: bool,
}

impl TcpStackBuilder {
    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    pub fn bind(mut self, bind: impl Into<String>) -> Self {
        self.bind = Some(bind.into());
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

    pub fn transparent(mut self, transparent: bool) -> Self {
        self.transparent = transparent;
        self
    }

    pub async fn build(self) -> StackResult<TcpStack> {
        let stack = TcpStack::create(self).await?;
        Ok(stack)
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct TcpStackConfig {
    pub id: String,
    pub protocol: StackProtocol,
    pub bind: SocketAddr,
    pub transparent: Option<bool>,
    pub hook_point: Vec<ProcessChainConfig>,
}

impl StackConfig for TcpStackConfig {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn stack_protocol(&self) -> StackProtocol {
        StackProtocol::Tcp
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

pub struct TcpStackFactory {
    servers: ServerManagerRef,
    global_process_chains: GlobalProcessChainsRef,
    connection_manager: ConnectionManagerRef,
    tunnel_manager: TunnelManager,
}

impl TcpStackFactory {
    pub fn new(
        servers: ServerManagerRef,
        global_process_chains: GlobalProcessChainsRef,
        connection_manager: ConnectionManagerRef,
        tunnel_manager: TunnelManager,
    ) -> Self {
        Self {
            servers,
            global_process_chains,
            connection_manager,
            tunnel_manager,
        }
    }
}

#[async_trait::async_trait]
impl StackFactory for TcpStackFactory {
    async fn create(
        &self,
        config: Arc<dyn StackConfig>,
    ) -> StackResult<StackRef> {
        let config = config.as_ref().as_any().downcast_ref::<TcpStackConfig>()
            .ok_or(stack_err!(StackErrorCode::InvalidConfig, "invalid config"))?;
        let stack = TcpStack::builder()
            .id(config.id.clone())
            .bind(config.bind.to_string())
            .tunnel_manager(self.tunnel_manager.clone())
            .connection_manager(self.connection_manager.clone())
            .global_process_chains(self.global_process_chains.clone())
            .servers(self.servers.clone())
            .transparent(config.transparent.unwrap_or(false))
            .hook_point(config.hook_point.clone())
            .build().await?;
        Ok(Arc::new(stack))
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use crate::global_process_chains::GlobalProcessChains;
    use crate::{GatewayDevice, ProcessChainConfigs, ServerResult, StreamServer, ServerManager, TcpStack, TunnelManager, GATEWAY_TUNNEL_MANAGER, Server, ConnectionManager, Stack, TcpStackFactory, TcpStackConfig, StackProtocol, StackFactory, ServerConfig, StreamInfo};
    use buckyos_kit::AsyncStream;
    use name_lib::{encode_ed25519_sk_to_pk_jwk, generate_ed25519_key, DeviceConfig};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    #[tokio::test]
    async fn test_tcp_stack_creation() {
        let result = TcpStack::builder().build().await;
        assert!(result.is_err());
        let result = TcpStack::builder().bind("127.0.0.1:8080").build().await;
        assert!(result.is_err());
        let result = TcpStack::builder()
            .id("test")
            .bind("127.0.0.1:8080")
            .servers(Arc::new(ServerManager::new()))
            .build()
            .await;
        assert!(result.is_err());
        let result = TcpStack::builder()
            .id("test")
            .bind("127.0.0.1:8080")
            .servers(Arc::new(ServerManager::new()))
            .hook_point(vec![])
            .build()
            .await;
        assert!(result.is_err());
        let result = TcpStack::builder()
            .id("test")
            .bind("127.0.0.1:8080")
            .servers(Arc::new(ServerManager::new()))
            .tunnel_manager(TunnelManager::new())
            .hook_point(vec![])
            .build()
            .await;
        assert!(result.is_ok());
        let result = TcpStack::builder()
            .id("test")
            .bind("127.0.0.1:8080")
            .servers(Arc::new(ServerManager::new()))
            .hook_point(vec![])
            .tunnel_manager(TunnelManager::new())
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .build()
            .await;
        assert!(result.is_ok());
        let result = TcpStack::builder()
            .id("test")
            .bind("127.0.0.1:8080")
            .servers(Arc::new(ServerManager::new()))
            .hook_point(vec![])
            .tunnel_manager(TunnelManager::new())
            .connection_manager(ConnectionManager::new())
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .build()
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_tcp_stack_reject() {
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        reject;
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let connection_manager = ConnectionManager::new();
        let result = TcpStack::builder()
            .id("test")
            .bind("127.0.0.1:8080")
            .servers(Arc::new(ServerManager::new()))
            .hook_point(chains)
            .tunnel_manager(TunnelManager::new())
            .connection_manager(connection_manager.clone())
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .build()
            .await;
        assert!(result.is_ok());
        let mut stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());

        {
            let mut stream = TcpStream::connect("127.0.0.1:8080").await.unwrap();
            let result = stream
                .write_all(b"GET / HTTP/1.1\r\nHost: httpbin.org\r\n\r\n")
                .await;
            assert!(result.is_ok());
            let ret = stream.read(&mut [0; 1024]).await;
            assert!(ret.is_err());
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
        assert_eq!(connection_manager.get_all_connection_info().len(), 0);
    }

    #[tokio::test]
    async fn test_tcp_stack_drop() {
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        drop;
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let result = TcpStack::builder()
            .id("test")
            .bind("127.0.0.1:8081")
            .servers(Arc::new(ServerManager::new()))
            .hook_point(chains)
            .tunnel_manager(TunnelManager::new())
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .build()
            .await;
        assert!(result.is_ok());
        let mut stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());

        let mut stream = TcpStream::connect("127.0.0.1:8081").await.unwrap();
        let result = stream
            .write_all(b"GET / HTTP/1.1\r\nHost: httpbin.org\r\n\r\n")
            .await;
        assert!(result.is_ok());
        let ret = stream.read(&mut [0; 1024]).await;
        assert!(ret.is_err());
    }

    #[tokio::test]
    async fn test_tcp_stack_forward() {
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "forward tcp:///127.0.0.1:8083";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let connection_manager = ConnectionManager::new();
        let result = TcpStack::builder()
            .id("test")
            .bind("127.0.0.1:8082")
            .servers(Arc::new(ServerManager::new()))
            .hook_point(chains)
            .tunnel_manager(TunnelManager::new())
            .connection_manager(connection_manager.clone())
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .build()
            .await;
        assert!(result.is_ok());
        let mut stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());

        tokio::spawn(async move {
            let tcp_listener = TcpListener::bind("127.0.0.1:8083").await.unwrap();
            if let Ok((mut tcp_stream, _)) = tcp_listener.accept().await {
                let mut buf = [0u8; 4];
                tcp_stream.read_exact(&mut buf).await.unwrap();
                assert_eq!(&buf, b"test");
                tcp_stream.write_all("recv".as_bytes()).await.unwrap();
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        });

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let start = std::time::SystemTime::now();
        {
            let mut stream = TcpStream::connect("127.0.0.1:8082").await.unwrap();
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            assert_eq!(connection_manager.get_all_connection_info().len(), 1);
            let result = stream.write_all(b"test").await;
            assert!(result.is_ok());

            let mut buf = [0u8; 4];
            let ret = stream.read_exact(&mut buf).await;

            assert!(ret.is_ok());
            assert_eq!(&buf, b"recv");
            stream.shutdown().await.unwrap();
        }
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        assert_eq!(connection_manager.get_all_connection_info().len(), 0);
    }

    #[tokio::test]
    async fn test_tcp_stack_forward_err() {
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "forward tcp:///127.0.0.1:8086";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let result = TcpStack::builder()
            .id("test")
            .bind("127.0.0.1:8084")
            .servers(Arc::new(ServerManager::new()))
            .hook_point(chains)
            .tunnel_manager(TunnelManager::new())
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .build()
            .await;
        assert!(result.is_ok());
        let mut stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let mut stream = TcpStream::connect("127.0.0.1:8084").await.unwrap();
        let result = stream.write_all(b"test").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 4];
        let ret = stream.read_exact(&mut buf).await;
        assert!(ret.is_err());
    }

    pub struct MockServer;

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
            todo!()
        }

        async fn update_config(&self, config: Arc<dyn ServerConfig>) -> ServerResult<()> {
            todo!()
        }
    }
    #[tokio::test]
    async fn test_tcp_stack_server() {
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
        server_manager.add_server("www.buckyos.com".to_string(), Server::Stream(Arc::new(MockServer)));
        let result = TcpStack::builder()
            .id("test")
            .bind("127.0.0.1:8085")
            .servers(server_manager)
            .hook_point(chains)
            .tunnel_manager(TunnelManager::new())
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .build()
            .await;
        assert!(result.is_ok());
        let mut stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let mut stream = TcpStream::connect("127.0.0.1:8085").await.unwrap();
        let result = stream.write_all(b"test").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 4];
        let ret = stream.read_exact(&mut buf).await;
        assert!(ret.is_ok());
        assert_eq!(&buf, b"recv");
    }

    #[tokio::test]
    async fn test_factory() {
        let tcp_factory = TcpStackFactory::new(Arc::new(ServerManager::new()),
                                               Arc::new(GlobalProcessChains::new()),
                                               ConnectionManager::new(),
                                               TunnelManager::new());
        let config = TcpStackConfig {
            id: "test".to_string(),
            protocol: StackProtocol::Tcp,
            bind: "127.0.0.1:3345".parse().unwrap(),
            transparent: None,
            hook_point: vec![],
        };

        let ret = tcp_factory.create(Arc::new(config)).await;
        assert!(ret.is_ok());
    }
}
