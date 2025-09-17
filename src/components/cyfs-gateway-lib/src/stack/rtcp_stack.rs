use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use buckyos_kit::AsyncStream;
use name_lib::DeviceConfig;
use sfo_io::{LimitStream, StatStream};
use cyfs_process_chain::{CollectionValue, CommandControl, MemoryMapCollection, ProcessChainLibExecutor, StreamRequest};
use crate::{hyper_serve_http, into_stack_err, stack_err, ConnectionInfo, ConnectionManagerRef, HandleConnectionController, ProcessChainConfigs, RTcp, RTcpListener, Server, ServerManagerRef, Stack, StackErrorCode, StackProtocol, StackResult, TunnelEndpoint, TunnelError, TunnelManager, TunnelResult};
use crate::global_process_chains::{create_process_chain_executor, execute_chain, execute_stream_chain, GlobalProcessChainsRef};
use crate::rtcp::{AsyncStreamWithDatagram, DatagramForwarder};
use crate::stack::limiter::Limiter;
use crate::stack::stream_forward;

struct Listener {
    inner: Arc<RtcpStackInner>,
}

impl Listener {
    pub fn new(inner: Arc<RtcpStackInner>) -> Self {
        Self {
            inner
        }
    }
}

#[async_trait::async_trait]
impl RTcpListener for Listener {
    async fn on_new_stream(&self, stream: Box<dyn AsyncStream>, dest_host: Option<String>, dest_port: u16, endpoint: TunnelEndpoint) -> TunnelResult<()> {
        let inner = self.inner.clone();
        tokio::spawn(async move {
            if let Err(e) = inner.on_new_stream(stream, dest_host, dest_port, endpoint).await {
                error!("on_new_stream error: {}", e);
            }
        });
        Ok(())
    }

    async fn on_new_datagram(&self, stream: Box<dyn AsyncStream>, dest_host: Option<String>, dest_port: u16, endpoint: TunnelEndpoint) -> TunnelResult<()> {
        let inner = self.inner.clone();
        let stat_stream = Box::new(StatStream::new(stream));
        let remote_addr = match dest_host.clone() {
            Some(host) => format!("{}:{}", host, dest_port),
            None => format!("{}:{}", endpoint.device_id, dest_port),
        };

        let speed = stat_stream.get_speed_stat();
        let handle = tokio::spawn(async move {
            if let Err(e) = inner.on_new_datagram(stat_stream, dest_host, dest_port, endpoint).await {
                error!("on_new_stream error: {}", e);
            }
        });

        if let Some(manager) = &self.inner.connection_manager {
            let controller = HandleConnectionController::new(handle);
            manager.add_connection(ConnectionInfo::new(remote_addr, self.inner.bind_addr.clone(), StackProtocol::Rtcp, speed, controller))
        }
        Ok(())
    }
}

struct RtcpStackInner {
    bind_addr: String,
    servers: ServerManagerRef,
    executor: Arc<Mutex<ProcessChainLibExecutor>>,
    connection_manager: Option<ConnectionManagerRef>,
    tunnel_manager: TunnelManager,
}

impl RtcpStackInner {
    async fn create(builder: RtcpStackBuilder) -> StackResult<Self> {
        if builder.servers.is_none() {
            return Err(stack_err!(StackErrorCode::InvalidConfig, "servers is required"));
        }
        if builder.tunnel_manager.is_none() {
            return Err(stack_err!(StackErrorCode::InvalidConfig, "tunnel_manager is required"));
        }

        let (executor, _) = create_process_chain_executor(builder.hook_point.as_ref().unwrap(),
                                                          builder.global_process_chains).await
            .map_err(into_stack_err!(StackErrorCode::ProcessChainError))?;
        Ok(Self {
            bind_addr: builder.bind_addr.unwrap(),
            servers: builder.servers.unwrap(),
            executor: Arc::new(Mutex::new(executor)),
            connection_manager: builder.connection_manager,
            tunnel_manager: builder.tunnel_manager.unwrap(),
        })
    }

    async fn on_new_stream(&self, stream: Box<dyn AsyncStream>, dest_host: Option<String>, dest_port: u16, endpoint: TunnelEndpoint) -> StackResult<()> {
        let executor = {
            self.executor.lock().unwrap().fork()
        };
        let servers = self.servers.clone();
        let remote_addr = match dest_host.clone() {
            Some(host) => format!("{}:{}", host, dest_port),
            None => format!("{}:{}", endpoint.device_id, dest_port),
        };
        let map = MemoryMapCollection::new_ref();
        map.insert("dest_port", CollectionValue::String(dest_port.to_string())).await
            .map_err(|e| stack_err!(StackErrorCode::ProcessChainError, "{e}"))?;
        map.insert("dest_host", CollectionValue::String(dest_host.unwrap_or_default())).await
            .map_err(|e| stack_err!(StackErrorCode::ProcessChainError, "{e}"))?;
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

    async fn on_new_datagram(&self, datagram: Box<dyn AsyncStream>, dest_host: Option<String>, dest_port: u16, endpoint: TunnelEndpoint) -> StackResult<()> {
        let executor = {
            self.executor.lock().unwrap().fork()
        };
        let servers = self.servers.clone();
        let remote_addr = match dest_host.clone() {
            Some(host) => format!("{}:{}", host, dest_port),
            None => format!("127.0.0.1:{}", dest_port),
        };
        let map = MemoryMapCollection::new_ref();
        map.insert("dest_port", CollectionValue::String(dest_port.to_string())).await
            .map_err(|e| stack_err!(StackErrorCode::ProcessChainError, "{e}"))?;
        map.insert("dest_host", CollectionValue::String(dest_host.unwrap_or_default())).await
            .map_err(|e| stack_err!(StackErrorCode::ProcessChainError, "{e}"))?;
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
                            let stream = Box::new(LimitStream::new(datagram, Arc::new(limiter)));
                            let forwarder = DatagramForwarder::new(target, "0.0.0.0:0", stream).await
                                .map_err(into_stack_err!(StackErrorCode::IoError))?;
                            forwarder.run().await
                                .map_err(into_stack_err!(StackErrorCode::IoError))?;
                        }
                        "server" => {
                            if list.len() < 2 {
                                return Err(stack_err!(
                                    StackErrorCode::InvalidConfig,
                                    "invalid server command"
                                ));
                            }
                            let limiter = Limiter::new(Some(1), Some(1));
                            let stream = Box::new(LimitStream::new(datagram, Arc::new(limiter)));

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
                                        let datagram_stream = AsyncStreamWithDatagram::new(stream);
                                        let mut buf = vec![0; 4096];
                                        loop {
                                            datagram_stream.recv_datagram(&mut buf).await
                                                .map_err(into_stack_err!(StackErrorCode::IoError, "recv datagram error"))?;
                                            let resp = server.serve_datagram(buf.as_slice()).await
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

pub struct RtcpStack {
    bind_addr: String,
    rtcp: RTcp,
    inner: Arc<RtcpStackInner>,
}

impl RtcpStack {
    pub fn builder() -> RtcpStackBuilder {
        RtcpStackBuilder::new()
    }

    async fn create(mut builder: RtcpStackBuilder) -> StackResult<Self> {
        if builder.bind_addr.is_none() {
            return Err(stack_err!(StackErrorCode::InvalidConfig, "bind is required"));
        }
        if builder.device_config.is_none() {
            return Err(stack_err!(StackErrorCode::InvalidConfig, "device_config is required"));
        }
        if builder.private_key.is_none() {
            return Err(stack_err!(StackErrorCode::InvalidConfig, "private_key is required"));
        }

        let bind_addr = builder.bind_addr.clone().unwrap();
        let device_config = builder.device_config.take().unwrap();
        let private_key = builder.private_key.take();
        let inner = Arc::new(RtcpStackInner::create(builder).await?);

        let rtcp = RTcp::new(device_config.id.clone(), bind_addr.clone(), private_key, Arc::new(Listener::new(inner.clone())));
        Ok(Self {
            bind_addr,
            rtcp,
            inner,
        })
    }
    
    pub async fn start(&mut self) -> StackResult<()> {
        self.rtcp.start().await.map_err(|e| stack_err!(StackErrorCode::IoError, "start rtcp failed: {:?}", e))?;
        Ok(())
    }
}

impl Stack for RtcpStack {
    fn stack_protocol(&self) -> StackProtocol {
        StackProtocol::Rtcp
    }

    fn get_bind_addr(&self) -> String {
        self.bind_addr.clone()
    }
}

pub struct RtcpStackBuilder {
    bind_addr: Option<String>,
    device_config: Option<DeviceConfig>,
    private_key: Option<[u8; 48]>,
    hook_point: Option<ProcessChainConfigs>,
    servers: Option<ServerManagerRef>,
    global_process_chains: Option<GlobalProcessChainsRef>,
    connection_manager: Option<ConnectionManagerRef>,
    tunnel_manager: Option<TunnelManager>,
}

impl RtcpStackBuilder {
    fn new() -> Self {
        Self {
            bind_addr: None,
            device_config: None,
            private_key: None,
            hook_point: None,
            servers: None,
            global_process_chains: None,
            connection_manager: None,
            tunnel_manager: None,
        }
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

    pub async fn build(self) -> StackResult<RtcpStack> {
        RtcpStack::create(self).await
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use crate::global_process_chains::GlobalProcessChains;
    use crate::{GatewayDevice, ProcessChainConfigs, ServerResult, StreamServer, ServerManager, RtcpStack, TunnelManager, Server, ConnectionManager};
    use buckyos_kit::AsyncStream;
    use name_lib::{encode_ed25519_sk_to_pk_jwk, generate_ed25519_key, DeviceConfig};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
            .bind("127.0.0.1:2980".to_string())
            .device_config(device_config.clone())
            .build()
            .await;
        assert!(result.is_err());
        let result = RtcpStack::builder()
            .bind("127.0.0.1:2980".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .build()
            .await;
        assert!(result.is_err());
        let result = RtcpStack::builder()
            .bind("127.0.0.1:2980".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .servers(Arc::new(ServerManager::new()))
            .build()
            .await;
        assert!(result.is_err());
        let result = RtcpStack::builder()
            .bind("127.0.0.1:2980".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .servers(Arc::new(ServerManager::new()))
            .hook_point(vec![])
            .build()
            .await;
        assert!(result.is_err());
        let result = RtcpStack::builder()
            .bind("127.0.0.1:2980".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .servers(Arc::new(ServerManager::new()))
            .tunnel_manager(TunnelManager::new())
            .hook_point(vec![])
            .build()
            .await;
        assert!(result.is_ok());
        let result = RtcpStack::builder()
            .bind("127.0.0.1:2980".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .servers(Arc::new(ServerManager::new()))
            .hook_point(vec![])
            .tunnel_manager(TunnelManager::new())
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .build()
            .await;
        assert!(result.is_ok());
        let result = RtcpStack::builder()
            .bind("127.0.0.1:2980".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
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
    async fn test_rtcp_stack_reject() {
        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test", serde_json::from_value(jwk).unwrap());

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
        let result = RtcpStack::builder()
            .bind("127.0.0.1:2981".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
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

        // TODO: Add actual connection test when RTcp client is available
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        assert_eq!(connection_manager.get_all_connection_info().len(), 0);
    }

    #[tokio::test]
    async fn test_rtcp_stack_drop() {
        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test", serde_json::from_value(jwk).unwrap());

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        drop;
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let result = RtcpStack::builder()
            .bind("127.0.0.1:2982".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
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

        // TODO: Add actual connection test when RTcp client is available
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
    async fn test_rtcp_stack_server() {
        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test", serde_json::from_value(jwk).unwrap());

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
        let result = RtcpStack::builder()
            .bind("127.0.0.1:2983".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
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

        // TODO: Add actual connection test when RTcp client is available
    }
}