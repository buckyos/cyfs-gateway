use std::any::Any;
use super::{stream_forward, Stack};
use super::StackResult;
use crate::global_process_chains::{
    create_process_chain_executor, execute_stream_chain, GlobalProcessChainsRef,
};
use crate::{into_stack_err, stack_err, ProcessChainConfigs, StackErrorCode, StackProtocol, ServerManagerRef, Server, hyper_serve_http, ConnectionManagerRef, ConnectionInfo, HandleConnectionController, TunnelManager, StackConfig, StackFactory, ProcessChainConfig};
use cyfs_process_chain::{CommandControl, ProcessChainLibExecutor, StreamRequest};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use as_any::AsAny;
use serde::{Deserialize, Serialize};
use sfo_io::{LimitStream, StatStream};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use crate::stack::limiter::Limiter;

struct TcpStackInner {
    bind_addr: String,
    servers: ServerManagerRef,
    executor: Arc<Mutex<ProcessChainLibExecutor>>,
    connection_manager: Option<ConnectionManagerRef>,
    tunnel_manager: TunnelManager,
}


impl TcpStackInner {
    async fn create(config: TcpStackBuilder) -> StackResult<Self> {
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
                                                          config.global_process_chains).await
            .map_err(into_stack_err!(StackErrorCode::ProcessChainError))?;
        Ok(Self {
            bind_addr: config.bind.unwrap(),
            servers: config.servers.unwrap(),
            executor: Arc::new(Mutex::new(executor)),
            connection_manager: config.connection_manager,
            tunnel_manager: config.tunnel_manager.unwrap(),
        })
    }

    pub async fn start(self: &Arc<Self>) -> StackResult<JoinHandle<()>> {
        let bind_addr = self.bind_addr.clone();
        let listener = tokio::net::TcpListener::bind(bind_addr.as_str())
            .await
            .map_err(into_stack_err!(StackErrorCode::BindFailed))?;
        let this = self.clone();
        let handle = tokio::spawn(async move {
            loop {
                let (stream, local_addr) = match listener.accept().await {
                    Ok(s) => s,
                    Err(e) => {
                        log::error!("accept tcp stream failed: {}", e);
                        continue;
                    }
                };

                let remote_addr = match stream.peer_addr() {
                    Ok(addr) => addr,
                    Err(e) => {
                        log::error!("get remote addr failed: {}", e);
                        continue;
                    }
                };

                let this_tmp = this.clone();
                let stat_stream = StatStream::new(stream);
                let speed = stat_stream.get_speed_stat();
                let handle = tokio::spawn(async move {
                    if let Err(e) =
                        this_tmp.handle_connect(stat_stream, local_addr).await
                    {
                        log::error!("handle tcp stream failed: {}", e);
                    }
                });
                if let Some(manager) = &this.connection_manager {
                    let controller = HandleConnectionController::new(handle);
                    manager.add_connection(ConnectionInfo::new(remote_addr.to_string(), local_addr.to_string(), StackProtocol::Tcp, speed, controller));
                }
            }
        });
        Ok(handle)
    }

    async fn handle_connect(
        &self,
        mut stream: StatStream<TcpStream>,
        local_addr: SocketAddr,
    ) -> StackResult<()> {
        let executor = {
            self.executor.lock().unwrap().fork()
        };
        let servers = self.servers.clone();
        let remote_addr = stream.raw_stream().peer_addr().map_err(into_stack_err!(StackErrorCode::ServerError, "read remote addr failed"))?;
        let mut request = StreamRequest::new(Box::new(stream), local_addr);
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
                            let limiter = Limiter::new(Some(1), Some(1));
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
                            let limiter = Limiter::new(Some(1), Some(1));
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
                                            .serve_connection(stream)
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
    handle: Option<JoinHandle<()>>,
}

impl TcpStack {
    pub fn builder() -> TcpStackBuilder {
        TcpStackBuilder {
            bind: None,
            hook_point: None,
            servers: None,
            global_process_chains: None,
            connection_manager: None,
            tunnel_manager: None,
        }
    }

    async fn create(config: TcpStackBuilder) -> StackResult<Self> {
        let inner = TcpStackInner::create(config).await?;
        Ok(Self {
            inner: Arc::new(inner),
            handle: None,
        })
    }
}

impl Drop for TcpStack {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

#[async_trait::async_trait]
impl Stack for TcpStack {
    fn stack_protocol(&self) -> StackProtocol {
        StackProtocol::Tcp
    }

    fn get_bind_addr(&self) -> String {
        self.inner.bind_addr.clone()
    }

    async fn start(&mut self) -> StackResult<()> {
        let handle = self.inner.start().await?;
        self.handle = Some(handle);
        Ok(())
    }

    async fn update_config(&mut self, config: Arc<dyn StackConfig>) -> StackResult<()> {
        todo!()
    }
}


pub struct TcpStackBuilder {
    bind: Option<String>,
    hook_point: Option<ProcessChainConfigs>,
    servers: Option<ServerManagerRef>,
    global_process_chains: Option<GlobalProcessChainsRef>,
    connection_manager: Option<ConnectionManagerRef>,
    tunnel_manager: Option<TunnelManager>,
}

impl TcpStackBuilder {
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

    pub async fn build(self) -> StackResult<TcpStack> {
        let stack = TcpStack::create(self).await?;
        Ok(stack)
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct TcpStackConfig {
    pub protocol: StackProtocol,
    pub bind: SocketAddr,
    pub hook_point: Vec<ProcessChainConfig>,
}

impl StackConfig for TcpStackConfig {
    fn stack_protocol(&self) -> StackProtocol {
        StackProtocol::Tcp
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
        config: Box<dyn StackConfig>,
    ) -> StackResult<Box<dyn Stack>> {
        let config = config.as_ref().as_any().downcast_ref::<TcpStackConfig>()
            .ok_or(stack_err!(StackErrorCode::InvalidConfig, "invalid config"))?;
        let stack = TcpStack::builder()
            .bind(config.bind.to_string())
            .tunnel_manager(self.tunnel_manager.clone())
            .connection_manager(self.connection_manager.clone())
            .global_process_chains(self.global_process_chains.clone())
            .servers(self.servers.clone())
            .hook_point(config.hook_point.clone())
            .build().await?;
        Ok(Box::new(stack))
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use crate::global_process_chains::GlobalProcessChains;
    use crate::{GatewayDevice, ProcessChainConfigs, ServerResult, StreamServer, ServerManager, TcpStack, TunnelManager, GATEWAY_TUNNEL_MANAGER, Server, ConnectionManager, Stack, TcpStackFactory, TcpStackConfig, StackProtocol, StackFactory};
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
            .bind("127.0.0.1:8080")
            .servers(Arc::new(ServerManager::new()))
            .build()
            .await;
        assert!(result.is_err());
        let result = TcpStack::builder()
            .bind("127.0.0.1:8080")
            .servers(Arc::new(ServerManager::new()))
            .hook_point(vec![])
            .build()
            .await;
        assert!(result.is_err());
        let result = TcpStack::builder()
            .bind("127.0.0.1:8080")
            .servers(Arc::new(ServerManager::new()))
            .tunnel_manager(TunnelManager::new())
            .hook_point(vec![])
            .build()
            .await;
        assert!(result.is_ok());
        let result = TcpStack::builder()
            .bind("127.0.0.1:8080")
            .servers(Arc::new(ServerManager::new()))
            .hook_point(vec![])
            .tunnel_manager(TunnelManager::new())
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .build()
            .await;
        assert!(result.is_ok());
        let result = TcpStack::builder()
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
        async fn serve_connection(&self, mut stream: Box<dyn AsyncStream>) -> ServerResult<()> {
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"test");
            stream.write_all("recv".as_bytes()).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            Ok(())
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
            protocol: StackProtocol::Tcp,
            bind: "127.0.0.1:3345".parse().unwrap(),
            hook_point: vec![],
        };

        let ret = tcp_factory.create(Box::new(config)).await;
        assert!(ret.is_ok());
    }
}
