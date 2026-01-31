use super::{get_limit_info, stream_forward, Stack};

#[cfg(target_os = "linux")]
use super::{has_root_privileges, set_socket_opt};

use super::StackResult;
use crate::global_process_chains::{
    create_process_chain_executor, execute_stream_chain, GlobalProcessChainsRef,
};
use crate::{into_stack_err, stack_err, ProcessChainConfigs, StackErrorCode, StackProtocol, ServerManagerRef, Server, hyper_serve_http, ConnectionManagerRef, ConnectionInfo, HandleConnectionController, TunnelManager, StackConfig, StackFactory, ProcessChainConfig, StackRef, StreamInfo, get_min_priority, get_external_commands, LimiterManagerRef, StatManagerRef, get_stat_info, MutComposedSpeedStat, MutComposedSpeedStatRef, GlobalCollectionManagerRef, StackContext};
use cyfs_process_chain::{CommandControl, ProcessChainLibExecutor, StreamRequest};
use std::net::SocketAddr;
#[cfg(unix)]
use std::os::fd::{FromRawFd, IntoRawFd};
#[cfg(windows)]
use std::os::windows::io::{FromRawSocket, IntoRawSocket};
use std::sync::{Arc, Mutex, RwLock};
use serde::{Deserialize, Serialize};
use sfo_io::{LimitStream, StatStream};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use crate::stack::limiter::Limiter;

#[derive(Clone)]
pub struct TcpStackContext {
    pub servers: ServerManagerRef,
    pub tunnel_manager: TunnelManager,
    pub limiter_manager: LimiterManagerRef,
    pub stat_manager: StatManagerRef,
    pub global_process_chains: Option<GlobalProcessChainsRef>,
    pub global_collection_manager: Option<GlobalCollectionManagerRef>,
}

impl TcpStackContext {
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

impl StackContext for TcpStackContext {
    fn stack_protocol(&self) -> StackProtocol {
        StackProtocol::Tcp
    }
}

struct TcpConnectionHandler {
    env: Arc<TcpStackContext>,
    executor: ProcessChainLibExecutor,
}

impl TcpConnectionHandler {
    async fn create(
        hook_point: ProcessChainConfigs,
        env: Arc<TcpStackContext>,
    ) -> StackResult<Self> {
        let (executor, _) = create_process_chain_executor(
            &hook_point,
            env.global_process_chains.clone(),
            env.global_collection_manager.clone(),
            Some(get_external_commands(env.servers.clone())),
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
    ) -> StackResult<Self> {
        let (executor, _) = create_process_chain_executor(
            &hook_point,
            self.env.global_process_chains.clone(),
            self.env.global_collection_manager.clone(),
            Some(get_external_commands(self.env.servers.clone())),
        )
            .await
            .map_err(into_stack_err!(StackErrorCode::ProcessChainError))?;
        Ok(Self {
            env: self.env.clone(),
            executor,
        })
    }

    async fn handle_connect(
        &self,
        mut stream: StatStream<TcpStream>,
        dest_addr: SocketAddr,
        compose_stat: MutComposedSpeedStatRef,
    ) -> StackResult<()> {
        let executor = self.executor.fork();
        let servers = self.env.servers.clone();
        let remote_addr = stream.raw_stream().peer_addr().map_err(into_stack_err!(StackErrorCode::ServerError, "read remote addr failed"))?;
        let mut request = StreamRequest::new(Box::new(stream), dest_addr);
        request.source_addr = Some(remote_addr);
        let global_env = executor.global_env().clone();
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
                    compose_stat.set_external_stats(speed_groups);

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
                                        hyper_serve_http(stream, server, StreamInfo::new(remote_addr.to_string())).await
                                            .map_err(into_stack_err!(StackErrorCode::ServerError, "server {server_name}"))?;
                                    }
                                    Server::Stream(server) => {
                                        server
                                            .serve_connection(stream, StreamInfo::new(remote_addr.to_string()))
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
}

fn get_dest_addr(stream: &TcpStream) -> StackResult<SocketAddr> {
    #[cfg(target_os = "linux")]
    {
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

pub struct TcpStack {
    id: String,
    bind_addr: String,
    connection_manager: Option<ConnectionManagerRef>,
    handler: Arc<RwLock<Arc<TcpConnectionHandler>>>,
    prepare_handler: Arc<RwLock<Option<Arc<TcpConnectionHandler>>>>,
    transparent: bool,
    handle: Mutex<Option<JoinHandle<()>>>,
}

impl TcpStack {
    pub fn builder() -> TcpStackBuilder {
        TcpStackBuilder {
            id: None,
            bind: None,
            hook_point: None,
            connection_manager: None,
            stack_context: None,
            transparent: false,
        }
    }

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
        if config.stack_context.is_none() {
            return Err(stack_err!(
                StackErrorCode::InvalidConfig,
                "handler_env is required"
            ));
        }

        let id = config.id.unwrap();
        let bind_addr = config.bind.unwrap();
        let env = config.stack_context.unwrap();
        let handler = TcpConnectionHandler::create(
            config.hook_point.unwrap(),
            env,
        )
            .await?;

        Ok(Self {
            id,
            bind_addr,
            connection_manager: config.connection_manager,
            handler: Arc::new(RwLock::new(Arc::new(handler))),
            prepare_handler: Arc::new(Default::default()),
            transparent: config.transparent,
            handle: Mutex::new(None),
        })
    }

    async fn start_listener(&self) -> StackResult<JoinHandle<()>> {
        let addr: SocketAddr = self.bind_addr.parse()
            .map_err(into_stack_err!(StackErrorCode::InvalidConfig, "invalid bind address {}", self.bind_addr))?;
        let sockaddr: socket2::SockAddr = addr.into();

        let domain = match addr {
            std::net::SocketAddr::V4(_) => socket2::Domain::IPV4,
            std::net::SocketAddr::V6(_) => socket2::Domain::IPV6,
        };
        let socket = socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))
            .map_err(into_stack_err!(StackErrorCode::IoError, "create socket error"))?;

        socket.set_nonblocking(true).map_err(into_stack_err!(StackErrorCode::IoError, "set nonblocking error"))?;
        #[cfg(target_os = "linux")]
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
        socket.bind(&sockaddr).map_err(into_stack_err!(StackErrorCode::BindFailed, "bind {} error", self.bind_addr))?;
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
        let handler = self.handler.clone();
        let connection_manager = self.connection_manager.clone();
        let handle = tokio::spawn(async move {
            loop {
                let (stream, remote_addr) = match listener.accept().await {
                    Ok(s) => s,
                    Err(e) => {
                        log::error!("{:?} accept tcp stream failed: {}", sockaddr, e);
                        continue;
                    }
                };

                let dest_addr = match get_dest_addr(&stream) {
                    Ok(addr) => addr,
                    Err(e) => {
                        log::error!("get dest addr failed: {}", e);
                        continue;
                    }
                };
                log::info!("accept tcp stream from {} to {}", remote_addr, dest_addr);
                let compose_stat = MutComposedSpeedStat::new();
                let stat_stream = StatStream::new_with_tracker(stream, compose_stat.clone());
                let speed = stat_stream.get_speed_stat();
                let handler_snapshot = {
                    let handler = handler.read().unwrap();
                    handler.clone()
                };
                let handle = tokio::spawn(async move {
                    if let Err(e) =
                        handler_snapshot.handle_connect(stat_stream, dest_addr, compose_stat).await
                    {
                        log::error!("handle tcp stream failed: {}", e);
                    }
                });
                if let Some(manager) = &connection_manager {
                    let controller = HandleConnectionController::new(handle);
                    manager.add_connection(ConnectionInfo::new(remote_addr.to_string(), dest_addr.to_string(), StackProtocol::Tcp, speed, controller));
                }
            }
        });
        Ok(handle)
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
        self.id.clone()
    }

    fn stack_protocol(&self) -> StackProtocol {
        StackProtocol::Tcp
    }

    fn get_bind_addr(&self) -> String {
        self.bind_addr.clone()
    }

    async fn start(&self) -> StackResult<()> {
        {
            if self.handle.lock().unwrap().is_some() {
                return Ok(());
            }
        }
        let handle = self.start_listener().await?;
        *self.handle.lock().unwrap() = Some(handle);
        Ok(())
    }

    async fn prepare_update(&self, config: Arc<dyn StackConfig>, context: Option<Arc<dyn StackContext>>) -> StackResult<()> {
        let config = config.as_ref().as_any().downcast_ref::<TcpStackConfig>()
            .ok_or(stack_err!(StackErrorCode::InvalidConfig, "invalid tcp stack config"))?;

        if config.id != self.id {
            return Err(stack_err!(StackErrorCode::InvalidConfig, "id unmatch"));
        }

        if config.bind.to_string() != self.bind_addr {
            return Err(stack_err!(StackErrorCode::BindUnmatched, "bind unmatch"));
        }

        if config.transparent.unwrap_or(false) != self.transparent {
            return Err(stack_err!(StackErrorCode::InvalidConfig, "transparent unmatch"));
        }

        let env = match context {
            Some(context) => {
                let tcp_context = context.as_ref().as_any().downcast_ref::<TcpStackContext>()
                    .ok_or(stack_err!(StackErrorCode::InvalidConfig, "invalid tcp stack context"))?;
                Arc::new(tcp_context.clone())
            }
            None => self.handler.read().unwrap().env.clone(),
        };

        let new_handler = TcpConnectionHandler::create(config.hook_point.clone(), env).await?;

        *self.prepare_handler.write().unwrap() = Some(Arc::new(new_handler));
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


pub struct TcpStackBuilder {
    id: Option<String>,
    bind: Option<String>,
    hook_point: Option<ProcessChainConfigs>,
    connection_manager: Option<ConnectionManagerRef>,
    stack_context: Option<Arc<TcpStackContext>>,
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

    pub fn connection_manager(mut self, connection_manager: ConnectionManagerRef) -> Self {
        self.connection_manager = Some(connection_manager);
        self
    }

    pub fn transparent(mut self, transparent: bool) -> Self {
        self.transparent = transparent;
        self
    }

    pub fn stack_context(mut self, handler_env: Arc<TcpStackContext>) -> Self {
        self.stack_context = Some(handler_env);
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
    #[serde(skip_serializing_if = "Option::is_none")]
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
    connection_manager: ConnectionManagerRef,
}

impl TcpStackFactory {
    pub fn new(
        connection_manager: ConnectionManagerRef,
    ) -> Self {
        Self {
            connection_manager,
        }
    }
}

#[async_trait::async_trait]
impl StackFactory for TcpStackFactory {
    async fn create(
        &self,
        config: Arc<dyn StackConfig>,
        context: Arc<dyn StackContext>,
    ) -> StackResult<StackRef> {
        let config = config.as_ref().as_any().downcast_ref::<TcpStackConfig>()
            .ok_or(stack_err!(StackErrorCode::InvalidConfig, "invalid tcp stack config"))?;
        let handler_env = context
            .as_ref()
            .as_any()
            .downcast_ref::<TcpStackContext>()
            .ok_or(stack_err!(StackErrorCode::InvalidConfig, "invalid tcp stack context"))?;
        let handler_env = Arc::new(handler_env.clone());
        let stack = TcpStack::builder()
            .id(config.id.clone())
            .bind(config.bind.to_string())
            .connection_manager(self.connection_manager.clone())
            .transparent(config.transparent.unwrap_or(false))
            .hook_point(config.hook_point.clone())
            .stack_context(handler_env)
            .build().await?;
        Ok(Arc::new(stack))
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use crate::global_process_chains::GlobalProcessChains;
    use crate::{ProcessChainConfigs, ServerResult, StreamServer, ServerManager, TcpStack, TunnelManager, Server, ConnectionManager, Stack, TcpStackFactory, TcpStackConfig, StackProtocol, StackFactory, StreamInfo, DefaultLimiterManager, StatManager, GlobalCollectionManager, TcpStackContext, ServerManagerRef, LimiterManagerRef, StatManagerRef};
    use buckyos_kit::{AsyncStream};
    use std::sync::Arc;
    use std::time::Instant;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    fn build_handler_env(
        servers: ServerManagerRef,
        tunnel_manager: TunnelManager,
        limiter_manager: LimiterManagerRef,
        stat_manager: StatManagerRef,
        global_process_chains: Option<Arc<GlobalProcessChains>>,
    ) -> Arc<TcpStackContext> {
        Arc::new(TcpStackContext::new(
            servers,
            tunnel_manager,
            limiter_manager,
            stat_manager,
            global_process_chains,
            None,
        ))
    }

    fn default_handler_env() -> Arc<TcpStackContext> {
        build_handler_env(
            Arc::new(ServerManager::new()),
            TunnelManager::new(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            None,
        )
    }

    fn handler_env_with_process_chains() -> Arc<TcpStackContext> {
        build_handler_env(
            Arc::new(ServerManager::new()),
            TunnelManager::new(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        )
    }

    #[tokio::test]
    async fn test_tcp_stack_creation() {
        let result = TcpStack::builder().build().await;
        assert!(result.is_err());
        let result = TcpStack::builder().bind("127.0.0.1:8080").build().await;
        assert!(result.is_err());
        let result = TcpStack::builder()
            .id("test")
            .bind("127.0.0.1:8080")
            .build()
            .await;
        assert!(result.is_err());
        let result = TcpStack::builder()
            .id("test")
            .bind("127.0.0.1:8080")
            .hook_point(vec![])
            .build()
            .await;
        assert!(result.is_err());
        let result = TcpStack::builder()
            .id("test")
            .bind("127.0.0.1:8080")
            .hook_point(vec![])
            .stack_context(default_handler_env())
            .build()
            .await;
        assert!(result.is_ok());
        let result = TcpStack::builder()
            .id("test")
            .bind("127.0.0.1:8080")
            .hook_point(vec![])
            .stack_context(handler_env_with_process_chains())
            .build()
            .await;
        assert!(result.is_ok());
        let result = TcpStack::builder()
            .id("test")
            .bind("127.0.0.1:8080")
            .hook_point(vec![])
            .connection_manager(ConnectionManager::new())
            .stack_context(handler_env_with_process_chains())
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
        let handler_env = build_handler_env(
            Arc::new(ServerManager::new()),
            TunnelManager::new(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = TcpStack::builder()
            .id("test")
            .bind("127.0.0.1:8080")
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(handler_env)
            .build()
            .await;
        assert!(result.is_ok());
        let stack = result.unwrap();
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

        let handler_env = build_handler_env(
            Arc::new(ServerManager::new()),
            TunnelManager::new(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = TcpStack::builder()
            .id("test")
            .bind("127.0.0.1:8081")
            .hook_point(chains)
            .stack_context(handler_env)
            .build()
            .await;
        assert!(result.is_ok());
        let stack = result.unwrap();
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
        forward tcp:///127.0.0.1:8083;
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let connection_manager = ConnectionManager::new();
        let handler_env = build_handler_env(
            Arc::new(ServerManager::new()),
            TunnelManager::new(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = TcpStack::builder()
            .id("test")
            .bind("127.0.0.1:8082")
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(handler_env)
            .build()
            .await;
        assert!(result.is_ok());
        let stack = result.unwrap();
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
        return "forward tcp:///127.0.0.1:18086";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let handler_env = build_handler_env(
            Arc::new(ServerManager::new()),
            TunnelManager::new(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = TcpStack::builder()
            .id("test")
            .bind("127.0.0.1:8084")
            .hook_point(chains)
            .stack_context(handler_env)
            .build()
            .await;
        assert!(result.is_ok());
        let stack = result.unwrap();
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

    pub struct MockServer {
        id: String,
    }

    impl MockServer {
        pub fn new(id: String) -> Self {
            Self { id }
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
        server_manager.add_server(Server::Stream(Arc::new(MockServer::new("www.buckyos.com".to_string())))).unwrap();
        let handler_env = build_handler_env(
            server_manager,
            TunnelManager::new(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = TcpStack::builder()
            .id("test")
            .bind("127.0.0.1:8085")
            .hook_point(chains)
            .stack_context(handler_env)
            .build()
            .await;
        assert!(result.is_ok());
        let stack = result.unwrap();
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
    async fn test_tcp_stack_stat_server() {
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

        let stat_manager = StatManager::new();
        let server_manager = Arc::new(ServerManager::new());
        server_manager.add_server(Server::Stream(Arc::new(MockServer::new("www.buckyos.com".to_string())))).unwrap();
        let handler_env = build_handler_env(
            server_manager,
            TunnelManager::new(),
            Arc::new(DefaultLimiterManager::new()),
            stat_manager.clone(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = TcpStack::builder()
            .id("test")
            .bind("127.0.0.1:8086")
            .hook_point(chains)
            .stack_context(handler_env)
            .build()
            .await;
        assert!(result.is_ok());
        let stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let mut stream = TcpStream::connect("127.0.0.1:8086").await.unwrap();
        let result = stream.write_all(b"test").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 4];
        let ret = stream.read_exact(&mut buf).await;
        assert!(ret.is_ok());
        assert_eq!(&buf, b"recv");
        let test_stat = stat_manager.get_speed_stat("test");
        assert!(test_stat.is_some());
        let test_stat = test_stat.unwrap();
        assert_eq!(test_stat.get_read_sum_size(), 4);
        assert_eq!(test_stat.get_write_sum_size(), 4);
    }

    #[tokio::test]
    async fn test_tcp_stack_stat_limiter_server() {
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

        let stat_manager = StatManager::new();
        let server_manager = Arc::new(ServerManager::new());
        server_manager.add_server(Server::Stream(Arc::new(MockServer::new("www.buckyos.com".to_string())))).unwrap();
        let handler_env = build_handler_env(
            server_manager,
            TunnelManager::new(),
            Arc::new(DefaultLimiterManager::new()),
            stat_manager.clone(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = TcpStack::builder()
            .id("test")
            .bind("127.0.0.1:8087")
            .hook_point(chains)
            .stack_context(handler_env)
            .build()
            .await;
        assert!(result.is_ok());
        let stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let mut stream = TcpStream::connect("127.0.0.1:8087").await.unwrap();
        let start = Instant::now();
        let result = stream.write_all(b"test").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 4];
        let ret = stream.read_exact(&mut buf).await;
        assert!(ret.is_ok());
        assert_eq!(&buf, b"recv");
        let test_stat = stat_manager.get_speed_stat("test");
        assert!(test_stat.is_some());
        let test_stat = test_stat.unwrap();
        assert_eq!(test_stat.get_read_sum_size(), 4);
        assert_eq!(test_stat.get_write_sum_size(), 4);
        assert!(start.elapsed().as_millis() > 1800);
        assert!(start.elapsed().as_millis() < 2500);
    }

    #[tokio::test]
    async fn test_tcp_stack_stat_group_limiter_server() {
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

        let stat_manager = StatManager::new();
        let mut limiter_manager = DefaultLimiterManager::new();
        let _ = limiter_manager.new_limiter("test".to_string(), None::<String>, Some(1), Some(2), Some(2));
        let limiter_manager = Arc::new(limiter_manager);
        let server_manager = Arc::new(ServerManager::new());
        server_manager.add_server(Server::Stream(Arc::new(MockServer::new("www.buckyos.com".to_string())))).unwrap();
        let handler_env = build_handler_env(
            server_manager,
            TunnelManager::new(),
            limiter_manager,
            stat_manager.clone(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = TcpStack::builder()
            .id("test")
            .bind("127.0.0.1:8088")
            .hook_point(chains)
            .stack_context(handler_env)
            .build()
            .await;
        assert!(result.is_ok());
        let stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let mut stream = TcpStream::connect("127.0.0.1:8088").await.unwrap();
        let start = Instant::now();
        let result = stream.write_all(b"test").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 4];
        let ret = stream.read_exact(&mut buf).await;
        assert!(ret.is_ok());
        assert_eq!(&buf, b"recv");
        let test_stat = stat_manager.get_speed_stat("test");
        assert!(test_stat.is_some());
        let test_stat = test_stat.unwrap();
        assert_eq!(test_stat.get_read_sum_size(), 4);
        assert_eq!(test_stat.get_write_sum_size(), 4);
        assert!(start.elapsed().as_millis() > 1800);
        assert!(start.elapsed().as_millis() < 2500);
    }

    #[tokio::test]
    async fn test_tcp_stack_stat_group_limiter_server2() {
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        set-stat test;
        set-limit test 10KB/s 10KB/s;
        return "server www.buckyos.com";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let stat_manager = StatManager::new();
        let mut limiter_manager = DefaultLimiterManager::new();
        let _ = limiter_manager.new_limiter("test".to_string(), None::<String>, Some(1), Some(2), Some(2));
        let limiter_manager = Arc::new(limiter_manager);
        let server_manager = Arc::new(ServerManager::new());
        server_manager.add_server(Server::Stream(Arc::new(MockServer::new("www.buckyos.com".to_string())))).unwrap();
        let handler_env = build_handler_env(
            server_manager,
            TunnelManager::new(),
            limiter_manager,
            stat_manager.clone(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = TcpStack::builder()
            .id("test")
            .bind("127.0.0.1:8089")
            .hook_point(chains)
            .stack_context(handler_env)
            .build()
            .await;
        assert!(result.is_ok());
        let stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let mut stream = TcpStream::connect("127.0.0.1:8089").await.unwrap();
        let start = Instant::now();
        let result = stream.write_all(b"test").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 4];
        let ret = stream.read_exact(&mut buf).await;
        assert!(ret.is_ok());
        assert_eq!(&buf, b"recv");
        let test_stat = stat_manager.get_speed_stat("test");
        assert!(test_stat.is_some());
        let test_stat = test_stat.unwrap();
        assert_eq!(test_stat.get_read_sum_size(), 4);
        assert_eq!(test_stat.get_write_sum_size(), 4);
        assert!(start.elapsed().as_millis() > 1800);
        assert!(start.elapsed().as_millis() < 2500);
    }

    #[tokio::test]
    async fn test_factory() {
        let server_manager = Arc::new(ServerManager::new());
        let global_process_chains = Arc::new(GlobalProcessChains::new());
        let tunnel_manager = TunnelManager::new();
        let limiter_manager = Arc::new(DefaultLimiterManager::new());
        let stat_manager = StatManager::new();
        let collection_manager = GlobalCollectionManager::create(vec![]).await.unwrap();
        let tcp_factory = TcpStackFactory::new(ConnectionManager::new());
        let config = TcpStackConfig {
            id: "test".to_string(),
            protocol: StackProtocol::Tcp,
            bind: "127.0.0.1:3345".parse().unwrap(),
            transparent: None,
            hook_point: vec![],
        };

        let stack_context = Arc::new(TcpStackContext::new(
            server_manager,
            tunnel_manager,
            limiter_manager,
            stat_manager,
            Some(global_process_chains),
            Some(collection_manager),
        ));
        let ret = tcp_factory.create(Arc::new(config), stack_context).await;
        assert!(ret.is_ok());
    }
}
