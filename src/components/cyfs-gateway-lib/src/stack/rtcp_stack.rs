use std::path::Path;
use std::sync::{Arc, Mutex};
use buckyos_kit::AsyncStream;
use name_lib::{encode_ed25519_pkcs8_sk_to_pk, get_x_from_jwk, load_raw_private_key, DeviceConfig};
use sfo_io::{LimitStream, StatStream};
use url::Url;
use cyfs_process_chain::{CollectionValue, CommandControl, MemoryMapCollection, ProcessChainLibExecutor};
use crate::{hyper_serve_http, into_stack_err, stack_err, ConnectionInfo, ConnectionManagerRef, DatagramServerBox, HandleConnectionController, ProcessChainConfigs, RTcp, RTcpListener, Server, ServerManagerRef, Stack, StackRef, StackConfig, StackErrorCode, StackFactory, StackProtocol, StackResult, StreamListener, TunnelBox, TunnelBuilder, TunnelEndpoint, TunnelManager, TunnelResult, StreamInfo, ProcessChainConfig, get_min_priority, get_stream_external_commands, DatagramInfo};
use crate::global_process_chains::{create_process_chain_executor, execute_chain, GlobalProcessChainsRef};
use crate::rtcp::{AsyncStreamWithDatagram, RTcpTunnelDatagramClient};
use crate::stack::limiter::Limiter;
use crate::stack::{datagram_forward, stream_forward};
use serde::{Deserialize, Serialize};

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
        let stat_stream = Box::new(StatStream::new(stream));
        let remote_addr = match dest_host.clone() {
            Some(host) => format!("{}:{}", host, dest_port),
            None => format!("{}:{}", endpoint.device_id, dest_port),
        };

        let speed = stat_stream.get_speed_stat();
        let handle = tokio::spawn(async move {
            if let Err(e) = inner.on_new_stream(stat_stream, dest_host, dest_port, endpoint).await {
                error!("on_new_stream error: {}", e);
            }
        });
        if let Some(manager) = &self.inner.connection_manager {
            let controller = HandleConnectionController::new(handle);
            manager.add_connection(ConnectionInfo::new(remote_addr, self.inner.bind_addr.clone(), StackProtocol::Rtcp, speed, controller))
        }
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
    global_process_chains: Option<GlobalProcessChainsRef>,
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
                                                          builder.global_process_chains.clone(),
                                                          Some(get_stream_external_commands())).await
            .map_err(into_stack_err!(StackErrorCode::ProcessChainError))?;
        Ok(Self {
            bind_addr: builder.bind_addr.unwrap(),
            servers: builder.servers.unwrap(),
            executor: Arc::new(Mutex::new(executor)),
            connection_manager: builder.connection_manager,
            tunnel_manager: builder.tunnel_manager.unwrap(),
            global_process_chains: builder.global_process_chains,
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

    async fn on_new_datagram(&self, datagram: Box<dyn AsyncStream>, dest_host: Option<String>, dest_port: u16, _endpoint: TunnelEndpoint) -> StackResult<()> {
        let executor = {
            self.executor.lock().unwrap().fork()
        };
        let servers = self.servers.clone();
        let _remote_addr = match dest_host.clone() {
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
                            let limiter = Limiter::new(None, None);
                            let stream = Box::new(LimitStream::new(datagram, Arc::new(limiter)));
                            let datagram_stream = Box::new(RTcpTunnelDatagramClient::new(stream));
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
                                            let len = datagram_stream.recv_datagram(&mut buf).await
                                                .map_err(into_stack_err!(StackErrorCode::IoError, "recv datagram error"))?;
                                            let resp = server.serve_datagram(&buf[..len], DatagramInfo::new(Some(_remote_addr.clone()))).await
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

    async fn create_stream_listener(&self, _bind_stream_id: &Url) -> TunnelResult<Box<dyn StreamListener>> {
        todo!()
    }

    async fn create_datagram_server(&self, _bind_session_id: &Url) -> TunnelResult<Box<dyn DatagramServerBox>> {
        todo!()
    }
}

pub struct RtcpStack {
    id: String,
    bind_addr: String,
    rtcp: Mutex<Option<RTcp>>,
    rtcp_ref: Mutex<Option<Arc<RTcp>>>,
    inner: Arc<RtcpStackInner>,
}

impl Drop for RtcpStack {
    fn drop(&mut self) {
        self.inner.tunnel_manager.remove_tunnel_builder("rtcp");
        self.inner.tunnel_manager.remove_tunnel_builder("rudp");
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

        let id = builder.id.take().unwrap();
        let bind_addr = builder.bind_addr.clone().unwrap();
        let device_config = builder.device_config.take().unwrap();
        let private_key = builder.private_key.take();
        let inner = Arc::new(RtcpStackInner::create(builder).await?);

        let rtcp = RTcp::new(device_config.id.clone(), bind_addr.clone(), private_key, Arc::new(Listener::new(inner.clone())));
        Ok(Self {
            id,
            bind_addr,
            rtcp: Mutex::new(Some(rtcp)),
            rtcp_ref: Mutex::new(None),
            inner,
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
        self.inner.tunnel_manager.register_tunnel_builder("rtcp", tunnel_builder.clone());
        self.inner.tunnel_manager.register_tunnel_builder("rudp", tunnel_builder);
        *self.rtcp_ref.lock().unwrap() = Some(rtcp);
        Ok(())
    }

    async fn update_config(&self, config: Arc<dyn StackConfig>) -> StackResult<()> {
        let config = config.as_ref().as_any().downcast_ref::<RtcpStackConfig>()
            .ok_or(stack_err!(StackErrorCode::InvalidConfig, "invalid config"))?;

        if config.id != self.id {
            return Err(stack_err!(StackErrorCode::InvalidConfig, "id unmatch"));
        }

        if config.bind != self.inner.bind_addr {
            return Err(stack_err!(StackErrorCode::InvalidConfig, "bind unmatch"));
        }

        let (executor, _) = create_process_chain_executor(&config.hook_point,
                                                          self.inner.global_process_chains.clone(),
                                                          Some(get_stream_external_commands())).await
            .map_err(into_stack_err!(StackErrorCode::ProcessChainError))?;
        *self.inner.executor.lock().unwrap() = executor;
        Ok(())
    }
}

pub struct RtcpStackBuilder {
    id: Option<String>,
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
            id: None,
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
    servers: ServerManagerRef,
    global_process_chains: GlobalProcessChainsRef,
    connection_manager: ConnectionManagerRef,
    tunnel_manager: TunnelManager,
}

impl RtcpStackFactory {
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
impl StackFactory for RtcpStackFactory {
    async fn create(&self, config: Arc<dyn StackConfig>) -> StackResult<StackRef> {
        let config = config
            .as_any()
            .downcast_ref::<RtcpStackConfig>()
            .ok_or(stack_err!(StackErrorCode::InvalidConfig, "invalid config"))?;

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
        let stack = RtcpStack::builder()
            .id(config.id.clone())
            .bind(config.bind.clone())
            .tunnel_manager(self.tunnel_manager.clone())
            .connection_manager(self.connection_manager.clone())
            .global_process_chains(self.global_process_chains.clone())
            .servers(self.servers.clone())
            .device_config(device_config)
            .private_key(private_key)
            .hook_point(config.hook_point.clone())
            .build().await?;
        Ok(Arc::new(stack))
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::collections::HashMap;
    use crate::global_process_chains::GlobalProcessChains;
    use crate::{ProcessChainConfigs, ServerResult, StreamServer, ServerManager, TunnelManager, Server, ConnectionManager, Stack, RtcpStack, RtcpStackFactory, RtcpStackConfig, StackProtocol, StackFactory, ServerConfig, StreamInfo, DatagramInfo};
    use buckyos_kit::{AsyncStream};
    use name_lib::{encode_ed25519_sk_to_pk_jwk, generate_ed25519_key, generate_ed25519_key_pair, DeviceConfig, EncodedDocument};
    use std::sync::Arc;
    use std::time::Duration;
    use name_client::{init_name_lib, NameInfo, GLOBAL_NAME_CLIENT};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, UdpSocket};
    use url::Url;

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
            .servers(Arc::new(ServerManager::new()))
            .build()
            .await;
        assert!(result.is_err());
        let result = RtcpStack::builder()
            .id("test")
            .bind("127.0.0.1:2980".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .servers(Arc::new(ServerManager::new()))
            .hook_point(vec![])
            .build()
            .await;
        assert!(result.is_err());
        let result = RtcpStack::builder()
            .id("test")
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
            .id("test")
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
            .id("test")
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
        let _ = init_name_lib(&HashMap::new()).await;
        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let id1 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        GLOBAL_NAME_CLIENT.get().unwrap().add_did_cache(device_config.id.clone(), encoded_doc).unwrap();
        GLOBAL_NAME_CLIENT.get().unwrap().add_nameinfo_cache(device_config.id.to_string().as_str(),
                                                             NameInfo::from_address(device_config.id.to_string().as_str(), "127.0.0.1".parse().unwrap())).unwrap();

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
        let result = RtcpStack::builder()
            .id("test")
            .bind("127.0.0.1:2981".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .servers(Arc::new(ServerManager::new()))
            .hook_point(chains)
            .tunnel_manager(tunnel_manager1.clone())
            .connection_manager(connection_manager.clone())
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .build()
            .await;
        assert!(result.is_ok());

        let mut stack1 = result.unwrap();
        let result = stack1.start().await;
        assert!(result.is_ok());

        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let id2 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        GLOBAL_NAME_CLIENT.get().unwrap().add_did_cache(device_config.id.clone(), encoded_doc).unwrap();
        GLOBAL_NAME_CLIENT.get().unwrap().add_nameinfo_cache(device_config.id.to_string().as_str(),
                                                             NameInfo::from_address(device_config.id.to_string().as_str(), "127.0.0.1".parse().unwrap())).unwrap();

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
        let result = RtcpStack::builder()
            .id("test2")
            .bind("127.0.0.1:2982".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .servers(Arc::new(ServerManager::new()))
            .hook_point(chains)
            .tunnel_manager(tunnel_manager2.clone())
            .connection_manager(connection_manager.clone())
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .build()
            .await;
        assert!(result.is_ok());

        let mut stack2 = result.unwrap();
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
        let _ = init_name_lib(&HashMap::new()).await;
        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let id1 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        GLOBAL_NAME_CLIENT.get().unwrap().add_did_cache(device_config.id.clone(), encoded_doc).unwrap();
        GLOBAL_NAME_CLIENT.get().unwrap().add_nameinfo_cache(device_config.id.to_string().as_str(),
                                                             NameInfo::from_address(device_config.id.to_string().as_str(), "127.0.0.1".parse().unwrap())).unwrap();

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
        let result = RtcpStack::builder()
            .id("test")
            .bind("127.0.0.1:2983".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .servers(Arc::new(ServerManager::new()))
            .hook_point(chains)
            .tunnel_manager(tunnel_manager1.clone())
            .connection_manager(connection_manager.clone())
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .build()
            .await;
        assert!(result.is_ok());

        let mut stack1 = result.unwrap();
        let result = stack1.start().await;
        assert!(result.is_ok());

        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let id2 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        GLOBAL_NAME_CLIENT.get().unwrap().add_did_cache(device_config.id.clone(), encoded_doc).unwrap();
        GLOBAL_NAME_CLIENT.get().unwrap().add_nameinfo_cache(device_config.id.to_string().as_str(),
                                                             NameInfo::from_address(device_config.id.to_string().as_str(), "127.0.0.1".parse().unwrap())).unwrap();

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
        let result = RtcpStack::builder()
            .id("test2")
            .bind("127.0.0.1:2984".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .servers(Arc::new(ServerManager::new()))
            .hook_point(chains)
            .tunnel_manager(tunnel_manager2.clone())
            .connection_manager(connection_manager.clone())
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .build()
            .await;
        assert!(result.is_ok());

        let mut stack2 = result.unwrap();
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
        let _ = init_name_lib(&HashMap::new()).await;
        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let id1 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        GLOBAL_NAME_CLIENT.get().unwrap().add_did_cache(device_config.id.clone(), encoded_doc).unwrap();
        GLOBAL_NAME_CLIENT.get().unwrap().add_nameinfo_cache(device_config.id.to_string().as_str(),
                                                             NameInfo::from_address(device_config.id.to_string().as_str(), "127.0.0.1".parse().unwrap())).unwrap();

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
        let result = RtcpStack::builder()
            .id("test")
            .bind("127.0.0.1:2985".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .servers(Arc::new(ServerManager::new()))
            .hook_point(chains)
            .tunnel_manager(tunnel_manager1.clone())
            .connection_manager(connection_manager.clone())
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .build()
            .await;
        assert!(result.is_ok());

        let mut stack1 = result.unwrap();
        let result = stack1.start().await;
        assert!(result.is_ok());

        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let id2 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        GLOBAL_NAME_CLIENT.get().unwrap().add_did_cache(device_config.id.clone(), encoded_doc).unwrap();
        GLOBAL_NAME_CLIENT.get().unwrap().add_nameinfo_cache(device_config.id.to_string().as_str(),
                                                             NameInfo::from_address(device_config.id.to_string().as_str(), "127.0.0.1".parse().unwrap())).unwrap();

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
        let result = RtcpStack::builder()
            .id("test2")
            .bind("127.0.0.1:2986".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .servers(Arc::new(ServerManager::new()))
            .hook_point(chains)
            .tunnel_manager(tunnel_manager2.clone())
            .connection_manager(connection_manager.clone())
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .build()
            .await;
        assert!(result.is_ok());

        let mut stack2 = result.unwrap();
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
        let _ = init_name_lib(&HashMap::new()).await;
        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let id1 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        GLOBAL_NAME_CLIENT.get().unwrap().add_did_cache(device_config.id.clone(), encoded_doc).unwrap();
        GLOBAL_NAME_CLIENT.get().unwrap().add_nameinfo_cache(device_config.id.to_string().as_str(),
                                                             NameInfo::from_address(device_config.id.to_string().as_str(), "127.0.0.1".parse().unwrap())).unwrap();

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
        let result = RtcpStack::builder()
            .id("test")
            .bind("127.0.0.1:2988".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .servers(Arc::new(ServerManager::new()))
            .hook_point(chains)
            .tunnel_manager(tunnel_manager1.clone())
            .connection_manager(connection_manager.clone())
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .build()
            .await;
        assert!(result.is_ok());

        let mut stack1 = result.unwrap();
        let result = stack1.start().await;
        assert!(result.is_ok());

        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let id2 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        GLOBAL_NAME_CLIENT.get().unwrap().add_did_cache(device_config.id.clone(), encoded_doc).unwrap();
        GLOBAL_NAME_CLIENT.get().unwrap().add_nameinfo_cache(device_config.id.to_string().as_str(),
                                                             NameInfo::from_address(device_config.id.to_string().as_str(), "127.0.0.1".parse().unwrap())).unwrap();

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
        let result = RtcpStack::builder()
            .id("test2")
            .bind("127.0.0.1:2989".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .servers(Arc::new(ServerManager::new()))
            .hook_point(chains)
            .tunnel_manager(tunnel_manager2.clone())
            .connection_manager(connection_manager.clone())
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .build()
            .await;
        assert!(result.is_ok());

        let mut stack2 = result.unwrap();
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

        async fn update_config(&self, config: Arc<dyn ServerConfig>) -> ServerResult<()> {
            todo!()
        }
    }

    #[tokio::test]
    async fn test_rtcp_stack_server() {
        let _ = init_name_lib(&HashMap::new()).await;
        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let id1 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        GLOBAL_NAME_CLIENT.get().unwrap().add_did_cache(device_config.id.clone(), encoded_doc).unwrap();
        GLOBAL_NAME_CLIENT.get().unwrap().add_nameinfo_cache(device_config.id.to_string().as_str(),
                                                             NameInfo::from_address(device_config.id.to_string().as_str(), "127.0.0.1".parse().unwrap())).unwrap();

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
        server_manager.add_server(Server::Stream(Arc::new(MockServer::new("www.buckyos.com".to_string()))));
        let tunnel_manager1 = TunnelManager::new();
        let connection_manager = ConnectionManager::new();
        let result = RtcpStack::builder()
            .id("test")
            .bind("127.0.0.1:2990".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .servers(server_manager)
            .hook_point(chains)
            .tunnel_manager(tunnel_manager1.clone())
            .connection_manager(connection_manager.clone())
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .build()
            .await;
        assert!(result.is_ok());

        let mut stack1 = result.unwrap();
        let result = stack1.start().await;
        assert!(result.is_ok());

        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let id2 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        GLOBAL_NAME_CLIENT.get().unwrap().add_did_cache(device_config.id.clone(), encoded_doc).unwrap();
        GLOBAL_NAME_CLIENT.get().unwrap().add_nameinfo_cache(device_config.id.to_string().as_str(),
                                                             NameInfo::from_address(device_config.id.to_string().as_str(), "127.0.0.1".parse().unwrap())).unwrap();

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
        server_manager.add_server(Server::Stream(Arc::new(MockServer::new("www.buckyos.com".to_string()))));
        let tunnel_manager2 = TunnelManager::new();
        let result = RtcpStack::builder()
            .id("test2")
            .bind("127.0.0.1:2991".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .servers(server_manager)
            .hook_point(chains)
            .tunnel_manager(tunnel_manager2.clone())
            .connection_manager(connection_manager.clone())
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .build()
            .await;
        assert!(result.is_ok());

        let mut stack2 = result.unwrap();
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
        assert!(ret.is_ok());
        assert_eq!(&buf, b"recv");
    }


    #[tokio::test]
    async fn test_rudp_stack_reject() {
        let _ = init_name_lib(&HashMap::new()).await;
        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let id1 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        GLOBAL_NAME_CLIENT.get().unwrap().add_did_cache(device_config.id.clone(), encoded_doc).unwrap();
        GLOBAL_NAME_CLIENT.get().unwrap().add_nameinfo_cache(device_config.id.to_string().as_str(),
                                                             NameInfo::from_address(device_config.id.to_string().as_str(), "127.0.0.1".parse().unwrap())).unwrap();

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
        let result = RtcpStack::builder()
            .id("test")
            .bind("127.0.0.1:2995".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .servers(Arc::new(ServerManager::new()))
            .hook_point(chains)
            .tunnel_manager(tunnel_manager1.clone())
            .connection_manager(connection_manager.clone())
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .build()
            .await;
        assert!(result.is_ok());

        let mut stack1 = result.unwrap();
        let result = stack1.start().await;
        assert!(result.is_ok());

        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let id2 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        GLOBAL_NAME_CLIENT.get().unwrap().add_did_cache(device_config.id.clone(), encoded_doc).unwrap();
        GLOBAL_NAME_CLIENT.get().unwrap().add_nameinfo_cache(device_config.id.to_string().as_str(),
                                                             NameInfo::from_address(device_config.id.to_string().as_str(), "127.0.0.1".parse().unwrap())).unwrap();

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
        let result = RtcpStack::builder()
            .id("test2")
            .bind("127.0.0.1:2996".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .servers(Arc::new(ServerManager::new()))
            .hook_point(chains)
            .tunnel_manager(tunnel_manager2.clone())
            .connection_manager(connection_manager.clone())
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .build()
            .await;
        assert!(result.is_ok());

        let mut stack2 = result.unwrap();
        let result = stack2.start().await;
        assert!(result.is_ok());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let url = Url::parse(format!("rudp://{}:2995/test:80", id1.to_host_name()).as_str()).unwrap();
        let ret = tunnel_manager2.create_datagram_client_by_url(&url).await;
        assert!(ret.is_ok());
        let mut stream = ret.unwrap();
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
        let _ = init_name_lib(&HashMap::new()).await;
        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let id1 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        GLOBAL_NAME_CLIENT.get().unwrap().add_did_cache(device_config.id.clone(), encoded_doc).unwrap();
        GLOBAL_NAME_CLIENT.get().unwrap().add_nameinfo_cache(device_config.id.to_string().as_str(),
                                                             NameInfo::from_address(device_config.id.to_string().as_str(), "127.0.0.1".parse().unwrap())).unwrap();

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
        let result = RtcpStack::builder()
            .id("test")
            .bind("127.0.0.1:2997".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .servers(Arc::new(ServerManager::new()))
            .hook_point(chains)
            .tunnel_manager(tunnel_manager1.clone())
            .connection_manager(connection_manager.clone())
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .build()
            .await;
        assert!(result.is_ok());

        let mut stack1 = result.unwrap();
        let result = stack1.start().await;
        assert!(result.is_ok());

        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let id2 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        GLOBAL_NAME_CLIENT.get().unwrap().add_did_cache(device_config.id.clone(), encoded_doc).unwrap();
        GLOBAL_NAME_CLIENT.get().unwrap().add_nameinfo_cache(device_config.id.to_string().as_str(),
                                                             NameInfo::from_address(device_config.id.to_string().as_str(), "127.0.0.1".parse().unwrap())).unwrap();

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
        let result = RtcpStack::builder()
            .id("test2")
            .bind("127.0.0.1:2313".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .servers(Arc::new(ServerManager::new()))
            .hook_point(chains)
            .tunnel_manager(tunnel_manager2.clone())
            .connection_manager(connection_manager.clone())
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .build()
            .await;
        assert!(result.is_ok());

        let mut stack2 = result.unwrap();
        let result = stack2.start().await;
        assert!(result.is_ok());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let url = Url::parse(format!("rudp://{}:2997/test:80", id1.to_host_name()).as_str()).unwrap();
        let ret = tunnel_manager2.create_datagram_client_by_url(&url).await;
        assert!(ret.is_ok());
        let mut stream = ret.unwrap();
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
        let _ = init_name_lib(&HashMap::new()).await;
        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let id1 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        GLOBAL_NAME_CLIENT.get().unwrap().add_did_cache(device_config.id.clone(), encoded_doc).unwrap();
        GLOBAL_NAME_CLIENT.get().unwrap().add_nameinfo_cache(device_config.id.to_string().as_str(),
                                                             NameInfo::from_address(device_config.id.to_string().as_str(), "127.0.0.1".parse().unwrap())).unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "forward udp:///127.0.0.1:2300";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let tunnel_manager1 = TunnelManager::new();
        let connection_manager = ConnectionManager::new();
        let result = RtcpStack::builder()
            .id("test")
            .bind("127.0.0.1:2998".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .servers(Arc::new(ServerManager::new()))
            .hook_point(chains)
            .tunnel_manager(tunnel_manager1.clone())
            .connection_manager(connection_manager.clone())
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .build()
            .await;
        assert!(result.is_ok());

        let mut stack1 = result.unwrap();
        let result = stack1.start().await;
        assert!(result.is_ok());

        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let id2 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        GLOBAL_NAME_CLIENT.get().unwrap().add_did_cache(device_config.id.clone(), encoded_doc).unwrap();
        GLOBAL_NAME_CLIENT.get().unwrap().add_nameinfo_cache(device_config.id.to_string().as_str(),
                                                             NameInfo::from_address(device_config.id.to_string().as_str(), "127.0.0.1".parse().unwrap())).unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "forward udp:///127.0.0.1:2300";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let tunnel_manager2 = TunnelManager::new();
        let result = RtcpStack::builder()
            .id("test2")
            .bind("127.0.0.1:2999".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .servers(Arc::new(ServerManager::new()))
            .hook_point(chains)
            .tunnel_manager(tunnel_manager2.clone())
            .connection_manager(connection_manager.clone())
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .build()
            .await;
        assert!(result.is_ok());

        let mut stack2 = result.unwrap();
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
        let mut stream = ret.unwrap();
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
        let _ = init_name_lib(&HashMap::new()).await;
        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let id1 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        GLOBAL_NAME_CLIENT.get().unwrap().add_did_cache(device_config.id.clone(), encoded_doc).unwrap();
        GLOBAL_NAME_CLIENT.get().unwrap().add_nameinfo_cache(device_config.id.to_string().as_str(),
                                                             NameInfo::from_address(device_config.id.to_string().as_str(), "127.0.0.1".parse().unwrap())).unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "forward udp:///127.0.0.1:22987";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let tunnel_manager1 = TunnelManager::new();
        let connection_manager = ConnectionManager::new();
        let result = RtcpStack::builder()
            .id("test")
            .bind("127.0.0.1:2301".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .servers(Arc::new(ServerManager::new()))
            .hook_point(chains)
            .tunnel_manager(tunnel_manager1.clone())
            .connection_manager(connection_manager.clone())
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .build()
            .await;
        assert!(result.is_ok());

        let mut stack1 = result.unwrap();
        let result = stack1.start().await;
        assert!(result.is_ok());

        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let id2 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        GLOBAL_NAME_CLIENT.get().unwrap().add_did_cache(device_config.id.clone(), encoded_doc).unwrap();
        GLOBAL_NAME_CLIENT.get().unwrap().add_nameinfo_cache(device_config.id.to_string().as_str(),
                                                             NameInfo::from_address(device_config.id.to_string().as_str(), "127.0.0.1".parse().unwrap())).unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "forward udp:///127.0.0.1:22987";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let tunnel_manager2 = TunnelManager::new();
        let result = RtcpStack::builder()
            .id("test2")
            .bind("127.0.0.1:2302".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .servers(Arc::new(ServerManager::new()))
            .hook_point(chains)
            .tunnel_manager(tunnel_manager2.clone())
            .connection_manager(connection_manager.clone())
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .build()
            .await;
        assert!(result.is_ok());

        let mut stack2 = result.unwrap();
        let result = stack2.start().await;
        assert!(result.is_ok());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let url = Url::parse(format!("rudp://{}:2301/test:80", id1.to_host_name()).as_str()).unwrap();
        let ret = tunnel_manager2.create_datagram_client_by_url(&url).await;
        assert!(ret.is_ok());
        let mut stream = ret.unwrap();
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        assert_eq!(connection_manager.get_all_connection_info().len(), 1);
        let result = stream.send_datagram(b"test").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 4];
        let ret = tokio::time::timeout(Duration::from_secs(5),
                                       stream.recv_datagram(&mut buf)).await;

        assert!(ret.is_err() || ret.unwrap().is_err());
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

        async fn update_config(&self, config: Arc<dyn ServerConfig>) -> ServerResult<()> {
            todo!()
        }
    }

    #[tokio::test]
    async fn test_rudp_stack_server() {
        let _ = init_name_lib(&HashMap::new()).await;
        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let id1 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        GLOBAL_NAME_CLIENT.get().unwrap().add_did_cache(device_config.id.clone(), encoded_doc).unwrap();
        GLOBAL_NAME_CLIENT.get().unwrap().add_nameinfo_cache(device_config.id.to_string().as_str(),
                                                             NameInfo::from_address(device_config.id.to_string().as_str(), "127.0.0.1".parse().unwrap())).unwrap();

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
        server_manager.add_server(Server::Datagram(Arc::new(MockDatagramServer::new("www.buckyos.com".to_string()))));
        let tunnel_manager1 = TunnelManager::new();
        let connection_manager = ConnectionManager::new();
        let result = RtcpStack::builder()
            .id("test")
            .bind("127.0.0.1:2310".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .servers(server_manager)
            .hook_point(chains)
            .tunnel_manager(tunnel_manager1.clone())
            .connection_manager(connection_manager.clone())
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .build()
            .await;
        assert!(result.is_ok());

        let mut stack1 = result.unwrap();
        let result = stack1.start().await;
        assert!(result.is_ok());

        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let id2 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        GLOBAL_NAME_CLIENT.get().unwrap().add_did_cache(device_config.id.clone(), encoded_doc).unwrap();
        GLOBAL_NAME_CLIENT.get().unwrap().add_nameinfo_cache(device_config.id.to_string().as_str(),
                                                             NameInfo::from_address(device_config.id.to_string().as_str(), "127.0.0.1".parse().unwrap())).unwrap();

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
        server_manager.add_server(Server::Datagram(Arc::new(MockDatagramServer::new("www.buckyos.com".to_string()))));
        let tunnel_manager2 = TunnelManager::new();
        let result = RtcpStack::builder()
            .id("test2")
            .bind("127.0.0.1:2311".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .servers(server_manager)
            .hook_point(chains)
            .tunnel_manager(tunnel_manager2.clone())
            .connection_manager(connection_manager.clone())
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .build()
            .await;
        assert!(result.is_ok());

        let mut stack2 = result.unwrap();
        let result = stack2.start().await;
        assert!(result.is_ok());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let url = Url::parse(format!("rudp://{}:2310/test:80", id1.to_host_name()).as_str()).unwrap();
        let ret = tunnel_manager2.create_datagram_client_by_url(&url).await;
        assert!(ret.is_ok());
        let mut stream = ret.unwrap();
        let result = stream.send_datagram(b"test_server").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 8];
        let ret = stream.recv_datagram(&mut buf).await;
        assert!(ret.is_ok());
        assert_eq!(&buf, b"datagram");
    }

    #[tokio::test]
    async fn test_factory() {
        let factory = RtcpStackFactory::new(
            Arc::new(ServerManager::new()),
            Arc::new(GlobalProcessChains::new()),
            ConnectionManager::new(),
            TunnelManager::new(),
        );

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

        let ret = factory.create(Arc::new(config)).await;
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

        let ret = factory.create(Arc::new(config)).await;
        assert!(ret.is_ok());
    }
}
