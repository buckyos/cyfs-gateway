use std::collections::{BTreeMap};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use url::Url;
use cyfs_process_chain::{CollectionValue, CommandControl, ProcessChainListExecutor};
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
    servers: DatagramServerManagerRef,
    executor: Arc<Mutex<ProcessChainListExecutor>>,
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

        let (executor, _) = create_process_chain_executor(&builder.hook_point.unwrap()).await
            .map_err(|e| stack_err!(StackErrorCode::InvalidConfig, "create process chain executor error: {}", e))?;
        Ok(Self {
            bind_addr: builder.bind.unwrap(),
            concurrency: builder.concurrency,
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

        let ret = executor.execute_all().await
            .map_err(|e| stack_err!(StackErrorCode::InvalidConfig, "execute chain error: {}", e))?;
        if ret.is_control() {
            if ret.is_drop() {
                return Ok(());
            } else if ret.is_reject() {
                return Ok(());
            }
            if let Some(CommandControl::Return(ret)) = ret.as_control() {
                if let Some(list) = shlex::split(ret) {
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
                                forward.send_datagram(data).await.map_err(into_stack_err!(StackErrorCode::TunnelError))?;

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
        let timeout = 120;

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
                tokio::time::sleep(Duration::from_secs(60)).await;
            }
        }));
        self.handle = Some(handle);
        Ok(())
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
    hook_point: Option<ProcessChainConfigs>,
    servers: Option<DatagramServerManagerRef>,
    global_process_chains: Option<GlobalProcessChainsRef>,
}

impl UdpStackBuilder {
    fn new() -> Self {
        Self {
            bind: None,
            concurrency: 200,
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

    pub async fn build(self) -> StackResult<UdpStack> {
        UdpStack::create(self).await
    }
}
