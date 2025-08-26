use std::collections::{BTreeMap};
use std::net::SocketAddr;
use std::ops::Div;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use url::Url;
use cyfs_process_chain::{CollectionValue, CommandControl, ProcessChainLibExecutor};
use crate::{into_stack_err, stack_err, DatagramClientBox, DatagramServerManagerRef, ProcessChainConfigs, Stack, StackErrorCode, StackProtocol, StackResult, GATEWAY_TUNNEL_MANAGER};
use crate::global_process_chains::{create_process_chain_executor, GlobalProcessChainsRef};

struct DatagramForwardSession {
    client: Box<dyn DatagramClientBox>,
    latest_time: u64,
    receive_handle: Option<JoinHandle<()>>,
}

impl Drop for DatagramForwardSession {
    fn drop(&mut self) {
        if let Some(handle) = self.receive_handle.take() {
            handle.abort();
        }
    }
}

struct DatagramServerSession {
    server: String,
    latest_time: u64,
}

enum DatagramSession {
    Forward(DatagramForwardSession),
    Server(DatagramServerSession),
}

type DatagramClientSessionMap = Arc<Mutex<BTreeMap<SocketAddr, Arc<tokio::sync::Mutex<Option<DatagramSession>>>>>>;

struct UdpStackInner {
    bind_addr: String,
    concurrency: u32,
    session_idle_time: Duration,
    servers: DatagramServerManagerRef,
    executor: Arc<Mutex<ProcessChainLibExecutor>>,
    all_client_session: DatagramClientSessionMap,
}

impl UdpStackInner {
    async fn create(builder: UdpStackBuilder) -> StackResult<Self> {
        if builder.bind.is_none() {
            return Err(stack_err!(StackErrorCode::InvalidConfig, "bind is required"));
        }
        if builder.servers.is_none() {
            return Err(stack_err!(StackErrorCode::InvalidConfig, "servers is required"));
        }
        if builder.hook_point.is_none() {
            return Err(stack_err!(StackErrorCode::InvalidConfig, "hook_point is required"));
        }

        let (executor, _) = create_process_chain_executor(&builder.hook_point.unwrap(), builder.
            global_process_chains).await
            .map_err(|e| stack_err!(StackErrorCode::InvalidConfig, "create process chain executor error: {}", e))?;
        Ok(Self {
            bind_addr: builder.bind.unwrap(),
            concurrency: builder.concurrency,
            session_idle_time: builder.session_idle_time,
            servers: builder.servers.unwrap(),
            executor: Arc::new(Mutex::new(executor)),
            all_client_session: Arc::new(Mutex::new(BTreeMap::new())),
        })
    }

    async fn handle_datagram(&self, udp_socket: Arc<UdpSocket>, addr: SocketAddr, data: &[u8]) -> StackResult<()> {
        let client_session = {
            let mut all_sessions = self.all_client_session.lock().unwrap();
            let client_session = all_sessions.get(&addr);
            if client_session.is_none() {
                let client_session = Arc::new(tokio::sync::Mutex::new(None));
                all_sessions.insert(addr, client_session.clone());
            }
            let client_session = all_sessions.get(&addr);
            let client_session = client_session.unwrap();
            client_session.clone()
        };

        let mut session_guard = client_session.lock().await;
        if session_guard.is_some() {
            let client_session = session_guard.as_mut().unwrap();
            match client_session {
                DatagramSession::Forward(forward_session) => {
                    if let Err(e) = forward_session.client.send_datagram(data).await {
                        log::error!("send datagram error: {}", e);
                        *session_guard = None;
                    } else {
                        forward_session.latest_time = chrono::Utc::now().timestamp() as u64;
                    }
                }
                DatagramSession::Server(server_session) => {
                    if let Some(server) = self.servers.get_server(&server_session.server) {
                        match server.serve_datagram(data).await {
                            Ok(resp) => {
                                if let Err(e) = udp_socket.send_to(resp.as_slice(), &addr).await {
                                    log::error!("send datagram error: {}", e);
                                    *session_guard = None;
                                } else {
                                    server_session.latest_time = chrono::Utc::now().timestamp() as u64;
                                }
                            }
                            Err(e) => {
                                log::error!("send datagram error: {}", e);
                                *session_guard = None;
                            }
                        }
                    }
                }
            }
            return Ok(());
        }

        let executor = { self.executor.lock().unwrap().fork() };
        let chain_env = executor.chain_env();
        chain_env.create("src_ip", CollectionValue::String(addr.to_string())).await
            .map_err(|e| stack_err!(StackErrorCode::InvalidConfig, "create chain env error: {}", e))?;
        chain_env.create(
            "src_port",
            CollectionValue::String(format!("{}", addr.port())),
        ).await.map_err(|e| stack_err!(StackErrorCode::InvalidConfig, "create chain env error: {}", e))?;

        let ret = executor.execute_lib().await
            .map_err(|e| stack_err!(StackErrorCode::InvalidConfig, "execute chain error: {}", e))?;
        if ret.is_control() {
            if ret.is_drop() {
                return Ok(());
            } else if ret.is_reject() {
                return Ok(());
            }
            if let Some(CommandControl::Return(ret)) = ret.as_control() {
                if let Some(list) = shlex::split(ret.value.as_str()) {
                    if list.len() == 0 {
                        return Err(stack_err!(
                                    StackErrorCode::InvalidConfig,
                                    "invalid forward command"
                                ));
                    }

                    let cmd = list[0].as_str();
                    match cmd {
                        "forward" => {
                            if list.len() < 2 {
                                return Err(stack_err!(
                                    StackErrorCode::InvalidConfig,
                                    "invalid server command"
                                ));
                            }

                            let target = list[1].as_str();
                            if let Some(tunnel_manager) = GATEWAY_TUNNEL_MANAGER.get() {
                                let url = Url::parse(target).map_err(into_stack_err!(
                                    StackErrorCode::InvalidConfig,
                                    "invalid forward url {}",
                                    target
                                ))?;
                                let forward = tunnel_manager
                                    .create_datagram_client_by_url(&url)
                                    .await.map_err(into_stack_err!(StackErrorCode::TunnelError))?;
                                // forward.send_datagram(data).await.map_err(into_stack_err!(StackErrorCode::TunnelError))?;
                                forward.send_datagram(data).await.map_err(|e| {
                                    println!("send datagram error: {}", e);
                                    stack_err!(StackErrorCode::TunnelError)
                                })?;

                                let forward_recv = forward.clone();
                                let back_socket = udp_socket.clone();
                                let handle = tokio::spawn(async move {
                                    let mut buffer = vec![0u8; 1024 * 4];
                                    loop {
                                        let len = match forward_recv
                                            .recv_datagram(&mut buffer)
                                            .await
                                        {
                                            Ok(pair) => pair,
                                            Err(err) => {
                                                log::error!("accept error: {}", err);
                                                break;
                                            }
                                        };
                                        if let Err(e) = back_socket
                                            .send_to(&buffer[0..len], addr)
                                            .await
                                        {
                                            log::error!("send datagram error: {}", e);
                                            break;
                                        }
                                    }
                                });
                                *session_guard = Some(DatagramSession::Forward(DatagramForwardSession {
                                    client: forward,
                                    latest_time: chrono::Utc::now().timestamp() as u64,
                                    receive_handle: Some(handle),
                                }));
                            } else {
                                log::error!("tunnel manager not found");
                            }
                        }
                        "server" => {
                            if list.len() < 2 {
                                return Err(stack_err!(
                                    StackErrorCode::InvalidConfig,
                                    "invalid server command"
                                ));
                            }
                            let server_name = list[1].as_str();
                            if let Some(server) = self.servers.get_server(server_name) {
                                let buf = server.serve_datagram(data).await.map_err(into_stack_err!(StackErrorCode::ServerError, ""))?;
                                udp_socket.send_to(buf.as_slice(), addr).await.map_err(into_stack_err!(StackErrorCode::IoError, "send error"))?;

                                *session_guard = Some(DatagramSession::Server(DatagramServerSession {
                                    server: server_name.to_string(),
                                    latest_time: chrono::Utc::now().timestamp() as u64,
                                }));
                            }
                        }
                        v => {
                            log::error!("invalid command: {}", v);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    pub async fn start(self: &Arc<Self>) -> StackResult<JoinHandle<()>> {
        let udp_socket = tokio::net::UdpSocket::bind(self.bind_addr.as_str())
            .await
            .map_err(into_stack_err!(StackErrorCode::BindFailed))?;
        let udp_socket = Arc::new(udp_socket);

        let this = self.clone();
        let concurrency = self.concurrency;
        let handle = tokio::spawn(async move {
            let semaphore = Arc::new(Semaphore::new(concurrency as usize));
            loop {
                let mut buffer = vec![0u8; 1024 * 2];
                let permit = semaphore.clone().acquire_owned().await.unwrap();
                let (len, addr) = match udp_socket.recv_from(&mut buffer).await {
                    Ok(pair) => pair,
                    Err(err) => {
                        log::error!("accept error: {}", err);
                        break;
                    }
                };
                let this = this.clone();
                let socket = udp_socket.clone();
                tokio::spawn(async move {
                    let result = this.handle_datagram(socket, addr, &buffer[0..len]).await;
                    if let Err(e) = result {
                        log::error!("handle datagram error: {}", e);
                    }
                    drop(permit);
                });
            }
        });
        Ok(handle)
    }

    async fn clear_idle_sessions(&self, latest_key: Option<SocketAddr>) -> Option<SocketAddr> {
        let mut sessions = self.all_client_session.lock().unwrap();
        let now = chrono::Utc::now().timestamp() as u64;
        let timeout = self.session_idle_time.as_secs();

        const MAX_CLEAN_PER_CYCLE: usize = 500;
        let mut count = 0;
        let mut deletes = Vec::new();
        if latest_key.is_some() {
            for (k, session) in sessions.range(latest_key.unwrap()..) {
                count += 1;
                if count > MAX_CLEAN_PER_CYCLE {
                    return Some(k.clone());
                }
                let remove = if let Ok(mut guard) = session.try_lock() {
                    if let Some(datagram_session) = guard.as_mut() {
                        let latest_time = match datagram_session {
                            DatagramSession::Forward(f) => f.latest_time,
                            DatagramSession::Server(s) => s.latest_time,
                        };

                        if now - latest_time > timeout {
                            false
                        } else {
                            true
                        }
                    } else {
                        false
                    }
                } else {
                    true
                };
                if remove {
                    deletes.push(k.clone());
                }
            }
        } else {
            for (k, session) in sessions.iter() {
                count += 1;
                if count > MAX_CLEAN_PER_CYCLE {
                    return Some(k.clone());
                }
                let remove = if let Ok(mut guard) = session.try_lock() {
                    if let Some(datagram_session) = guard.as_mut() {
                        let latest_time = match datagram_session {
                            DatagramSession::Forward(f) => f.latest_time,
                            DatagramSession::Server(s) => s.latest_time,
                        };

                        if now - latest_time > timeout {
                            false
                        } else {
                            true
                        }
                    } else {
                        false
                    }
                } else {
                    true
                };
                if remove {
                    deletes.push(k.clone());
                }
            }
        }
        for k in deletes {
            sessions.remove(&k);
        }
        None
    }
}

pub struct UdpStack {
    inner: Arc<UdpStackInner>,
    handle: Option<JoinHandle<()>>,
    clear_handle: Option<JoinHandle<()>>,
}

impl Drop for UdpStack {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
        if let Some(handle) = self.clear_handle.take() {
            handle.abort();
        }
    }
}

impl UdpStack {
    pub fn builder() -> UdpStackBuilder {
        UdpStackBuilder::new()
    }

    async fn create(builder: UdpStackBuilder) -> StackResult<Self> {
        let inner = UdpStackInner::create(builder).await?;
        Ok(Self {
            inner: Arc::new(inner),
            handle: None,
            clear_handle: None,
        })
    }

    pub async fn start(&mut self) -> StackResult<()> {
        let handle = self.inner.start().await?;
        let inner = self.inner.clone();
        self.clear_handle = Some(tokio::spawn(async move {
            let mut latest_key = None;
            loop {
                latest_key = inner.clear_idle_sessions(latest_key).await;
                tokio::time::sleep(inner.session_idle_time.div(2)).await;
            }
        }));
        self.handle = Some(handle);
        Ok(())
    }

    #[cfg(test)]
    fn get_session_count(&self) -> usize {
        self.inner.all_client_session.lock().unwrap().len()
    }
}

impl Stack for UdpStack {
    fn stack_protocol(&self) -> StackProtocol {
        StackProtocol::Udp
    }
    fn get_bind_addr(&self) -> String {
        self.inner.bind_addr.clone()
    }
}

pub struct UdpStackBuilder {
    bind: Option<String>,
    concurrency: u32,
    session_idle_time: Duration,
    hook_point: Option<ProcessChainConfigs>,
    servers: Option<DatagramServerManagerRef>,
    global_process_chains: Option<GlobalProcessChainsRef>,
}

impl UdpStackBuilder {
    fn new() -> Self {
        Self {
            bind: None,
            concurrency: 200,
            session_idle_time: Duration::from_secs(120),
            hook_point: None,
            servers: None,
            global_process_chains: None,
        }
    }
    pub fn bind(mut self, bind: impl Into<String>) -> Self {
        self.bind = Some(bind.into());
        self
    }
    pub fn hook_point(mut self, hook_point: ProcessChainConfigs) -> Self {
        self.hook_point = Some(hook_point);
        self
    }

    pub fn servers(mut self, servers: DatagramServerManagerRef) -> Self {
        self.servers = Some(servers);
        self
    }

    pub fn global_process_chains(mut self, global_process_chains: GlobalProcessChainsRef) -> Self {
        self.global_process_chains = Some(global_process_chains);
        self
    }

    pub fn concurrency(mut self, concurrency: u32) -> Self {
        self.concurrency = concurrency;
        self
    }

    pub fn session_idle_time(mut self, session_idle_time: Duration) -> Self {
        self.session_idle_time = session_idle_time;
        self
    }

    pub async fn build(self) -> StackResult<UdpStack> {
        UdpStack::create(self).await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;
    use name_lib::{encode_ed25519_sk_to_pk_jwk, generate_ed25519_key, DeviceConfig};
    use tokio::net::UdpSocket;
    use crate::{DatagramServerManager, GatewayDevice, ProcessChainConfigs, ServerResult, TunnelManager, UdpStack, GATEWAY_TUNNEL_MANAGER};
    use crate::global_process_chains::GlobalProcessChains;
    use crate::server::{DatagramServer};

    #[tokio::test]
    async fn test_udp_stack_creation() {
        let result = UdpStack::builder()
            .build()
            .await;
        assert!(result.is_err());
        let result = UdpStack::builder()
            .bind("0.0.0.0:8930")
            .build()
            .await;
        assert!(result.is_err());
        let result = UdpStack::builder()
            .bind("0.0.0.0:8930")
            .servers(Arc::new(DatagramServerManager::new()))
            .build()
            .await;
        assert!(result.is_err());
        let result = UdpStack::builder()
            .bind("0.0.0.0:8930")
            .hook_point(vec![])
            .servers(Arc::new(DatagramServerManager::new()))
            .build()
            .await;
        assert!(result.is_ok());
        let result = UdpStack::builder()
            .bind("0.0.0.0:8930")
            .hook_point(vec![])
            .servers(Arc::new(DatagramServerManager::new()))
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .build()
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_udp_stack_forward() {
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "forward udp:///127.0.0.1:8933";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let result = UdpStack::builder()
            .bind("0.0.0.0:8930")
            .hook_point(chains)
            .servers(Arc::new(DatagramServerManager::new()))
            .session_idle_time(Duration::from_secs(5))
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .build()
            .await;
        assert!(result.is_ok());
        let mut stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());

        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test", serde_json::from_value(jwk).unwrap());

        let tunnel_manager = TunnelManager::new(Arc::new(GatewayDevice {
            config: device_config,
            private_key: pkcs8_bytes,
        }));
        let _ = GATEWAY_TUNNEL_MANAGER.set(tunnel_manager);

        tokio::spawn(async move {
            let udp_socket = UdpSocket::bind("127.0.0.1:8933").await.unwrap();
            loop {
                let mut buf = [0; 1024];
                let (n, addr) = udp_socket.recv_from(&mut buf).await.unwrap();
                assert_eq!(&buf[..n], b"test");
                let _ = udp_socket.send_to(b"recv", addr).await;
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                break;
            }
        });

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let udp_client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ret = udp_client.send_to(b"test", "127.0.0.1:8930").await;
        assert!(ret.is_ok());

        let mut buf = [0; 1024];
        let (n, _) = tokio::time::timeout(Duration::from_secs(10), udp_client.recv_from(&mut buf)).await.unwrap().unwrap();
        assert_eq!(&buf[..n], b"recv");

        assert!(stack.get_session_count() > 0);
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        assert_eq!(stack.get_session_count(), 0);
    }
    #[tokio::test]
    async fn test_udp_stack_forward_err() {
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "forward udp:///127.0.0.1:8934";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let result = UdpStack::builder()
            .bind("0.0.0.0:8931")
            .hook_point(chains)
            .session_idle_time(Duration::from_secs(5))
            .servers(Arc::new(DatagramServerManager::new()))
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .build()
            .await;
        assert!(result.is_ok());
        let mut stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());

        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test", serde_json::from_value(jwk).unwrap());

        let tunnel_manager = TunnelManager::new(Arc::new(GatewayDevice {
            config: device_config,
            private_key: pkcs8_bytes,
        }));
        let _ = GATEWAY_TUNNEL_MANAGER.set(tunnel_manager);

        let udp_client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ret = udp_client.send_to(b"test", "127.0.0.1:8931").await;
        assert!(ret.is_ok());

        let mut buf = [0; 1024];
        let ret = tokio::time::timeout(Duration::from_secs(1), udp_client.recv_from(&mut buf)).await;
        assert!(ret.is_err());

        assert!(stack.get_session_count() > 0);
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        assert_eq!(stack.get_session_count(), 0);
    }

    struct MockServer;

    #[async_trait::async_trait]
    impl DatagramServer for MockServer {
        async fn serve_datagram(&self, buf: &[u8]) -> ServerResult<Vec<u8>> {
            assert_eq!(buf, b"test_server");
            Ok("datagram".as_bytes().to_vec())
        }
    }

    #[tokio::test]
    async fn test_udp_stack_serve() {
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "server mock";
        "#;
        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let datagram_server_manager = Arc::new(DatagramServerManager::new());
        datagram_server_manager.add_server("mock".to_string(), Arc::new(MockServer));
        let result = UdpStack::builder()
            .bind("0.0.0.0:8938")
            .hook_point(chains)
            .session_idle_time(Duration::from_secs(5))
            .servers(datagram_server_manager)
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .build()
            .await;
        assert!(result.is_ok());
        let mut stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());

        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test", serde_json::from_value(jwk).unwrap());

        let tunnel_manager = TunnelManager::new(Arc::new(GatewayDevice {
            config: device_config,
            private_key: pkcs8_bytes,
        }));
        let _ = GATEWAY_TUNNEL_MANAGER.set(tunnel_manager);

        let udp_client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ret = udp_client.send_to(b"test_server", "127.0.0.1:8938").await;
        assert!(ret.is_ok());

        let mut buf = [0; 1024];
        let (n, _) = tokio::time::timeout(Duration::from_secs(10), udp_client.recv_from(&mut buf)).await.unwrap().unwrap();
        assert_eq!(&buf[..n], b"datagram");

        assert!(stack.get_session_count() > 0);
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        assert_eq!(stack.get_session_count(), 0);
    }
}
