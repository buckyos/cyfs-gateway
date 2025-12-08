use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::ops::Div;
#[cfg(unix)]
use std::os::fd::{FromRawFd, IntoRawFd};
#[cfg(windows)]
use std::os::windows::io::{FromRawSocket, IntoRawSocket};
use std::sync::{Arc, Mutex};
use std::time::{Duration};
use local_ip_address::list_afinet_netifas;
use serde::{Deserialize, Serialize};
use sfo_io::{Datagram, LimitDatagram, SpeedTracker};
use tokio::net::{UdpSocket};
use tokio::sync::{Notify, Semaphore};
use tokio::task::JoinHandle;
use url::Url;
use cyfs_process_chain::{CollectionValue, CommandControl, MemoryMapCollection, ProcessChainLibExecutor};
use crate::{into_stack_err, stack_err, DatagramClientBox, ServerManagerRef, ProcessChainConfigs, Stack, StackErrorCode, StackProtocol, StackResult, Server, ConnectionManagerRef, ConnectionController, ConnectionInfo, StackError, StackConfig, ProcessChainConfig, TunnelManager, StackFactory, StackRef, get_min_priority, DatagramInfo, LimiterManagerRef, StatManagerRef, get_stat_info, ComposedSpeedStat, get_datagram_external_commands};
use crate::global_process_chains::{create_process_chain_executor, GlobalProcessChainsRef};
use crate::stack::limiter::Limiter;
#[cfg(target_os = "linux")]
use crate::stack::{has_root_privileges, recv_from, set_socket_opt};
use crate::stack::get_limit_info;

pub struct UdpSendDatagram {
    socket: Arc<UdpSocket>,
    addr: SocketAddr,
}

impl UdpSendDatagram {
    pub fn new(socket: Arc<UdpSocket>, addr: SocketAddr) -> Self {
        Self {
            socket,
            addr,
        }
    }
}

#[async_trait::async_trait]
impl Datagram for UdpSendDatagram {
    type Error = StackError;

    async fn send_to(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        self.socket.send_to(buf, self.addr).await.map_err(into_stack_err!(StackErrorCode::IoError))
    }

    async fn recv_from(&mut self, _buf: &mut [u8]) -> Result<usize, Self::Error> {
        unreachable!()
    }
}

pub struct UdpDatagram {
    socket: Arc<UdpSocket>,
    dest: SocketAddr,
    recv_channel: tokio::sync::mpsc::Receiver<Vec<u8>>,
}

impl UdpDatagram {
    fn new(socket: Arc<UdpSocket>, dest: SocketAddr, recv_channel: tokio::sync::mpsc::Receiver<Vec<u8>>) -> Self {
        Self {
            socket,
            dest,
            recv_channel,
        }
    }
}

#[async_trait::async_trait]
impl Datagram for UdpDatagram {
    type Error = StackError;

    async fn send_to(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        self.socket.send_to(buf, self.dest).await.map_err(into_stack_err!(StackErrorCode::IoError))
    }

    async fn recv_from(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        if let Some(data) = self.recv_channel.recv().await {
            if buf.len() >= data.len() {
                buf[..data.len()].copy_from_slice(&data);
                Ok(data.len())
            } else {
                buf.copy_from_slice(&data[..buf.len()]);
                Ok(buf.len())
            }
        } else {
            Err(stack_err!(StackErrorCode::IoError, "no data"))
        }
    }
}

pub struct ClientDatagram {
    client: Box<dyn DatagramClientBox>,
}

impl ClientDatagram {
    pub fn new(client: Box<dyn DatagramClientBox>) -> Self {
        Self {
            client,
        }
    }
}

#[async_trait::async_trait]
impl Datagram for ClientDatagram {
    type Error = StackError;

    async fn send_to(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        self.client.send_datagram(buf).await.map_err(into_stack_err!(StackErrorCode::IoError))
    }

    async fn recv_from(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        self.client.recv_datagram(buf).await.map_err(into_stack_err!(StackErrorCode::IoError))
    }
}

pub struct ChannelDatagram {
    sender: tokio::sync::mpsc::Sender<Vec<u8>>,
}

impl ChannelDatagram {
    pub fn new(sender: tokio::sync::mpsc::Sender<Vec<u8>>) -> Self {
        Self {
            sender,
        }
    }
}

#[async_trait::async_trait]
impl Datagram for ChannelDatagram {
    type Error = StackError;

    async fn send_to(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        let _ = self.sender.try_send(buf.to_vec());
        Ok(buf.len())
    }

    async fn recv_from(&mut self, _buf: &mut [u8]) -> Result<usize, Self::Error> {
        unreachable!()
    }
}

#[derive(Hash, Eq, PartialEq, Debug, Clone, Copy, Ord, PartialOrd)]
struct SessionKey {
    pub src_addr: SocketAddr,
    pub dest_addr: SocketAddr,
}

impl SessionKey {
    pub fn new(src_addr: SocketAddr, dest_addr: SocketAddr) -> Self {
        Self {
            src_addr,
            dest_addr,
        }
    }
}

struct UdpSessionController {
    session_key: SessionKey,
    client_session: DatagramClientSessionMap,
    notify: Arc<Notify>,
}

impl UdpSessionController {
    fn new(session_key: SessionKey, client_session: DatagramClientSessionMap, notify: Arc<Notify>) -> Arc<Self> {
        Arc::new(Self {
            session_key,
            client_session,
            notify,
        })
    }
}

#[async_trait::async_trait]
impl ConnectionController for UdpSessionController {
    fn stop_connection(&self) {
        let mut all_sessions = self.client_session.lock().unwrap();
        all_sessions.remove(&self.session_key);
    }

    async fn wait_stop(&self) {
        self.notify.notified().await;
    }

    fn is_stopped(&self) -> bool {
        let all_sessions = self.client_session.lock().unwrap();
        !all_sessions.contains_key(&self.session_key)
    }
}


struct DatagramForwardSession {
    client: Box<dyn Datagram<Error=StackError>>,
    latest_time: u64,
    receive_handle: Option<JoinHandle<()>>,
    notify: Arc<Notify>,
    speed_stat: Arc<dyn SpeedTracker>,
    send_handle: Option<JoinHandle<()>>,
}

impl Drop for DatagramForwardSession {
    fn drop(&mut self) {
        if let Some(handle) = self.receive_handle.take() {
            handle.abort();
        }
        if let Some(handle) = self.send_handle.take() {
            handle.abort();
        }
        self.notify.notify_waiters();
    }
}

struct DatagramServerSession {
    server: String,
    latest_time: u64,
    notify: Arc<Notify>,
    speed_stat: Arc<dyn SpeedTracker>,
    send_handle: Option<JoinHandle<()>>,
    send_datagram: Option<Box<dyn Datagram<Error=StackError>>>,
}

impl Drop for DatagramServerSession {
    fn drop(&mut self) {
        if let Some(handle) = self.send_handle.take() {
            handle.abort();
        }
        self.notify.notify_waiters();
    }
}

enum DatagramSession {
    Forward(DatagramForwardSession),
    Server(DatagramServerSession),
}

type DatagramClientSessionMap = Arc<Mutex<BTreeMap<SessionKey, Arc<tokio::sync::Mutex<Option<DatagramSession>>>>>>;


#[cfg(unix)]
fn recv_message(fd: std::os::unix::io::RawFd, buffer: &mut [u8]) -> Result<usize, std::io::Error> {
    let mut iov = libc::iovec {
        iov_base: buffer.as_mut_ptr() as *mut libc::c_void,
        iov_len: buffer.len(),
    };

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = std::ptr::null_mut();
    msg.msg_namelen = 0;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = std::ptr::null_mut();
    msg.msg_controllen = 0;
    msg.msg_flags = 0;

    let result = unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_WAITALL) };

    if result < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(result as usize)
    }
}

struct SocketCache {
    socket_cache: Arc<tokio::sync::Mutex<HashMap<SocketAddr, Arc<UdpSocket>>>>,
}

impl SocketCache {
    pub fn new() -> Self {
        Self {
            socket_cache: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        }
    }

    pub async fn get_socket(&self, addr: SocketAddr) -> StackResult<Arc<UdpSocket>> {
        let mut cache = self.socket_cache.lock().await;
        if let Some(socket) = cache.get(&addr) {
            Ok(socket.clone())
        } else {
            let std_addr = addr;
            let domain = match addr {
                std::net::SocketAddr::V4(_) => socket2::Domain::IPV4,
                std::net::SocketAddr::V6(_) => socket2::Domain::IPV6,
            };
            let addr: socket2::SockAddr = addr.into();
            // 创建数据报 (DGRAM) 套接字，对应 UDP
            let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))
                .map_err(into_stack_err!(StackErrorCode::IoError, "create socket error"))?;

            socket.set_nonblocking(true).map_err(into_stack_err!(StackErrorCode::IoError, "set nonblocking error"))?;
            #[cfg(target_os = "linux")]
            {
                socket.set_reuse_address(true)
                    .map_err(into_stack_err!(StackErrorCode::IoError, "set reuse address error"))?;
                socket.set_ip_transparent_v4(true)
                    .map_err(into_stack_err!(StackErrorCode::IoError, "set ip transparent error"))?;

                unsafe {
                    if domain == socket2::Domain::IPV4 {
                        crate::stack::set_socket_opt(&socket,
                                                     libc::SOL_IP,
                                                     libc::IP_TRANSPARENT,
                                                     libc::c_int::from(1))?;
                        crate::stack::set_socket_opt(&socket,
                                                     libc::SOL_IP,
                                                     libc::IP_ORIGDSTADDR,
                                                     libc::c_int::from(1))?;
                        crate::stack::set_socket_opt(&socket,
                                                     libc::SOL_IP,
                                                     libc::IP_FREEBIND,
                                                     libc::c_int::from(1))?;
                    } else if domain == socket2::Domain::IPV6 {
                        crate::stack::set_socket_opt(&socket,
                                                     libc::SOL_IPV6,
                                                     libc::IP_TRANSPARENT,
                                                     libc::c_int::from(1))?;
                        crate::stack::set_socket_opt(&socket,
                                                     libc::SOL_IPV6,
                                                     libc::IPV6_RECVORIGDSTADDR,
                                                     libc::c_int::from(1))?;
                        crate::stack::set_socket_opt(&socket,
                                                     libc::SOL_IPV6,
                                                     libc::IP_FREEBIND,
                                                     libc::c_int::from(1))?;
                    }
                }

            }
            socket.bind(&addr).map_err(into_stack_err!(StackErrorCode::BindFailed, "bind error"))?;
            #[cfg(unix)]
            let socket = unsafe {
                std::net::UdpSocket::from_raw_fd(socket.into_raw_fd())
            };
            #[cfg(windows)]
            let socket = unsafe {
                std::net::UdpSocket::from_raw_socket(socket.into_raw_socket())
            };
            let udp_socket = tokio::net::UdpSocket::from_std(socket).map_err(into_stack_err!(StackErrorCode::IoError))?;
            let udp_socket = Arc::new(udp_socket);

            cache.insert(std_addr, udp_socket.clone());
            Ok(udp_socket)
        }
    }

    pub async fn clear_socket(&self) {
        let mut cache = self.socket_cache.lock().await;
        let mut list = Vec::new();
        for (addr, socket) in cache.iter() {
            if Arc::strong_count(socket) == 1 {
                list.push(addr.clone());
            }
        }

        for addr in list {
            cache.remove(&addr);
        }
    }
}

struct UdpStackInner {
    id: String,
    bind_addr: String,
    concurrency: u32,
    session_idle_time: Duration,
    servers: ServerManagerRef,
    executor: Arc<Mutex<ProcessChainLibExecutor>>,
    all_client_session: DatagramClientSessionMap,
    connection_manager: Option<ConnectionManagerRef>,
    tunnel_manager: TunnelManager,
    global_process_chains: Option<GlobalProcessChainsRef>,
    limiter_manager: LimiterManagerRef,
    stat_manager: StatManagerRef,
    transparent: bool,
    local_ips: Vec<IpAddr>,
    socket_cache: SocketCache,
}

impl UdpStackInner {
    async fn create(builder: UdpStackBuilder) -> StackResult<Self> {
        if builder.id.is_none() {
            return Err(stack_err!(StackErrorCode::InvalidConfig, "id is required"));
        }
        if builder.bind.is_none() {
            return Err(stack_err!(StackErrorCode::InvalidConfig, "bind is required"));
        }
        if builder.servers.is_none() {
            return Err(stack_err!(StackErrorCode::InvalidConfig, "servers is required"));
        }
        if builder.hook_point.is_none() {
            return Err(stack_err!(StackErrorCode::InvalidConfig, "hook_point is required"));
        }
        if builder.tunnel_manager.is_none() {
            return Err(stack_err!(StackErrorCode::InvalidConfig, "tunnel_manager is required"));
        }
        if builder.limiter_manager.is_none() {
            return Err(stack_err!(StackErrorCode::InvalidConfig, "limiter_manager is required"));
        }
        if builder.stat_manager.is_none() {
            return Err(stack_err!(StackErrorCode::InvalidConfig, "stat_manager is required"));
        }

        let (executor, _) = create_process_chain_executor(&builder.hook_point.unwrap(),
                                                          builder.global_process_chains.clone(),
                                                          Some(get_datagram_external_commands())).await
            .map_err(|e| stack_err!(StackErrorCode::InvalidConfig, "create process chain executor error: {}", e))?;
        let local_ips = Self::local_ips()?;
        Ok(Self {
            id: builder.id.unwrap(),
            bind_addr: builder.bind.unwrap(),
            concurrency: builder.concurrency,
            session_idle_time: builder.session_idle_time,
            servers: builder.servers.unwrap(),
            executor: Arc::new(Mutex::new(executor)),
            all_client_session: Arc::new(Mutex::new(BTreeMap::new())),
            connection_manager: builder.connection_manager,
            tunnel_manager: builder.tunnel_manager.unwrap(),
            global_process_chains: builder.global_process_chains,
            limiter_manager: builder.limiter_manager.unwrap(),
            stat_manager: builder.stat_manager.unwrap(),
            transparent: builder.transparent,
            local_ips,
            socket_cache: SocketCache::new(),
        })
    }

    fn local_ips() -> StackResult<Vec<IpAddr>> {
        let mut list = vec![];

        let interfaces = list_afinet_netifas()
            .map_err(|e| stack_err!(StackErrorCode::InvalidConfig, "list local ip error: {}", e))?;
        for (_, ip) in interfaces {
            list.push(ip);
        }
        Ok(list)
    }

    fn is_local_ip(&self, ip: &IpAddr) -> bool {
        if ip.is_loopback() || ip.is_unspecified() {
            return true;
        }
        self.local_ips.contains(ip)
    }

    async fn handle_datagram(&self, udp_socket: Arc<UdpSocket>, src_addr: SocketAddr, dest_addr: SocketAddr, data: Vec<u8>, len: usize) -> StackResult<()> {
        let session_key = SessionKey::new(src_addr, dest_addr);
        let client_session = {
            let mut all_sessions = self.all_client_session.lock().unwrap();
            let client_session = all_sessions.get(&session_key);
            if client_session.is_none() {
                let client_session = Arc::new(tokio::sync::Mutex::new(None));
                all_sessions.insert(session_key, client_session.clone());
            }
            let client_session = all_sessions.get(&session_key);
            let client_session = client_session.unwrap();
            client_session.clone()
        };

        let mut session_guard = client_session.lock().await;
        if session_guard.is_some() {
            let client_session = session_guard.as_mut().unwrap();
            match client_session {
                DatagramSession::Forward(forward_session) => {
                    if let Err(e) = forward_session.client.send_to(&data[..len]).await {
                        log::error!("send datagram error: {}", e);
                        *session_guard = None;
                    } else {
                        forward_session.latest_time = chrono::Utc::now().timestamp() as u64;
                        forward_session.speed_stat.add_read_data_size(len as u64);
                    }
                }
                DatagramSession::Server(server_session) => {
                    if server_session.send_handle.is_some() {
                        let is_finished = server_session.send_handle.as_ref().unwrap().is_finished();
                        if is_finished {
                            *session_guard = None;
                        } else {
                            match server_session.send_datagram.as_mut().unwrap().send_to(&data[..len]).await {
                                Ok(_) => {
                                    server_session.latest_time = chrono::Utc::now().timestamp() as u64;
                                }
                                Err(e) => {
                                    log::error!("send datagram error: {}", e);
                                    *session_guard = None;
                                }
                            }
                        }
                    } else {
                        if let Some(server) = self.servers.get_server(&server_session.server) {
                            if let Server::Datagram(server) = server {
                                match server.serve_datagram(&data[..len], DatagramInfo::new(Some(src_addr.to_string()))).await {
                                    Ok(resp) => {
                                        if let Err(e) = udp_socket.send_to(resp.as_slice(), &src_addr).await {
                                            log::error!("send datagram error: {}", e);
                                            *session_guard = None;
                                        } else {
                                            server_session.latest_time = chrono::Utc::now().timestamp() as u64;
                                            server_session.speed_stat.add_read_data_size(len as u64);
                                            server_session.speed_stat.add_write_data_size(resp.len() as u64);
                                        }
                                    }
                                    Err(e) => {
                                        log::error!("send datagram error: {}", e);
                                        *session_guard = None;
                                    }
                                }
                            } else {
                                return Err(stack_err!(StackErrorCode::InvalidConfig, "Unsupport server type"));
                            }
                        }
                    }
                }
            }
            return Ok(());
        }

        let executor = { self.executor.lock().unwrap().fork() };
        let global_env = executor.global_env();
        let map = MemoryMapCollection::new_ref();
        map.insert("source_addr", CollectionValue::String(src_addr.to_string())).await
            .map_err(|e| stack_err!(StackErrorCode::InvalidConfig, "insert source_addr error: {}", e))?;

        map.insert("dest_addr", CollectionValue::String(dest_addr.to_string())).await
            .map_err(|e| stack_err!(StackErrorCode::InvalidConfig, "insert source_addr error: {}", e))?;

        global_env.create("REQ", CollectionValue::Map(map)).await
            .map_err(|e| stack_err!(StackErrorCode::InvalidConfig, "create chain env error: {}", e))?;

        let chain_env = global_env.clone();
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

                    let udp_socket = if self.is_local_ip(&dest_addr.ip()) {
                        udp_socket.clone()
                    } else {
                        self.socket_cache.get_socket(dest_addr).await?
                    };

                    let (limiter_id, down_speed, up_speed) = get_limit_info(chain_env.clone()).await?;
                    let upper = if limiter_id.is_some() {
                        self.limiter_manager.get_limiter(limiter_id.unwrap())
                    } else {
                        None
                    };
                    let limiter = if down_speed.is_some() && up_speed.is_some() {
                        Some(Limiter::new(upper, Some(1), down_speed.map(|v| v as u32), up_speed.map(|v| v as u32)))
                    } else {
                        upper
                    };

                    let stat_group_ids = get_stat_info(chain_env).await?;
                    let speed_groups = self.stat_manager.get_speed_stats(stat_group_ids.as_slice());
                    let speed_stat = ComposedSpeedStat::new(speed_groups);

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
                            let url = Url::parse(target).map_err(into_stack_err!(
                                    StackErrorCode::InvalidConfig,
                                    "invalid forward url {}",
                                    target
                                ))?;
                            let forward = self.tunnel_manager
                                .create_datagram_client_by_url(&url)
                                .await.map_err(into_stack_err!(StackErrorCode::TunnelError))?;
                            // forward.send_datagram(data).await.map_err(into_stack_err!(StackErrorCode::TunnelError))?;
                            forward.send_datagram(&data[..len]).await.map_err(|e| {
                                println!("send datagram error: {}", e);
                                stack_err!(StackErrorCode::TunnelError)
                            })?;
                            speed_stat.add_read_data_size(len as u64);

                            let forward_recv = forward.clone();
                            let stat = speed_stat.clone();
                            let notify = Arc::new(Notify::new());
                            let is_limit = true;
                            if is_limit {
                                let (sender, receive) = tokio::sync::mpsc::channel::<Vec<u8>>(512);
                                let send_datagram = Box::new(ChannelDatagram::new(sender));
                                let mut receive_datagram: Box<dyn Datagram<Error=StackError>> = if limiter.is_some() {
                                    let (read_limit, write_limit) = limiter.as_ref().unwrap().new_limit_session();
                                    let receive_datagram = LimitDatagram::new(UdpDatagram::new(udp_socket.clone(), src_addr, receive), read_limit, write_limit);
                                    Box::new(receive_datagram)
                                } else {
                                    Box::new(UdpDatagram::new(udp_socket.clone(), src_addr, receive))
                                };
                                let stat = speed_stat.clone();
                                let send_handle = tokio::spawn(async move {
                                    let mut buffer = vec![0u8; 1024 * 4];
                                    loop {
                                        match receive_datagram.recv_from(&mut buffer).await {
                                            Ok(len) => {
                                                match forward.send_datagram(&buffer[0..len]).await {
                                                    Ok(_) => {
                                                        stat.add_read_data_size(len as u64);
                                                    }
                                                    Err(e) => {
                                                        log::error!("send datagram error: {}", e);
                                                        break;
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                log::error!("accept error: {}", e);
                                                break;
                                            }
                                        }
                                    }
                                });

                                let stat = speed_stat.clone();
                                let mut receive_forward_datagram: Box<dyn Datagram<Error=StackError>> = if limiter.is_some() {
                                    let (read_limit, write_limit) = limiter.as_ref().unwrap().new_limit_session();
                                    let datagram = LimitDatagram::new(UdpSendDatagram::new(udp_socket.clone(), src_addr), read_limit, write_limit);
                                    Box::new(datagram)
                                } else {
                                    Box::new(UdpSendDatagram::new(udp_socket.clone(), src_addr))
                                };
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
                                        if let Err(e) = receive_forward_datagram
                                            .send_to(&buffer[0..len])
                                            .await
                                        {
                                            log::error!("send datagram error: {}", e);
                                            break;
                                        }
                                        stat.add_write_data_size(len as u64);
                                    }
                                });

                                *session_guard = Some(DatagramSession::Forward(DatagramForwardSession {
                                    client: send_datagram,
                                    latest_time: chrono::Utc::now().timestamp() as u64,
                                    receive_handle: Some(handle),
                                    notify: notify.clone(),
                                    speed_stat: speed_stat.clone(),
                                    send_handle: Some(send_handle),
                                }));
                            } else {
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
                                        if let Err(e) = udp_socket
                                            .send_to(&buffer[0..len], src_addr)
                                            .await
                                        {
                                            log::error!("send datagram error: {}", e);
                                            break;
                                        }
                                        stat.add_write_data_size(len as u64);
                                    }
                                });

                                *session_guard = Some(DatagramSession::Forward(DatagramForwardSession {
                                    client: Box::new(ClientDatagram::new(forward)),
                                    latest_time: chrono::Utc::now().timestamp() as u64,
                                    receive_handle: Some(handle),
                                    notify: notify.clone(),
                                    speed_stat: speed_stat.clone(),
                                    send_handle: None,
                                }));
                            }
                            if let Some(connection_manager) = self.connection_manager.as_ref() {
                                let controller = UdpSessionController::new(session_key, self.all_client_session.clone(), notify);
                                connection_manager.add_connection(ConnectionInfo::new(src_addr.to_string(), target.to_string(), StackProtocol::Udp, speed_stat, controller));
                            }
                        }
                        "server" => {
                            if list.len() < 2 {
                                return Err(stack_err!(
                                    StackErrorCode::InvalidConfig,
                                    "invalid server command"
                                ));
                            }
                            let server_name = list[1].to_string();
                            if let Some(server) = self.servers.get_server(server_name.as_str()) {
                                if let Server::Datagram(server) = server {
                                    let notify = Arc::new(Notify::new());
                                    let is_limit = true;
                                    let name = server_name.clone();
                                    if is_limit {
                                        let (sender, receive) = tokio::sync::mpsc::channel::<Vec<u8>>(512);
                                        let mut send_datagram = Box::new(ChannelDatagram::new(sender));
                                        let mut receive_datagram: Box<dyn Datagram<Error=StackError>> = if limiter.is_some() {
                                            let (read_limit, write_limit) = limiter.as_ref().unwrap().new_limit_session();
                                            Box::new(LimitDatagram::new(UdpDatagram::new(udp_socket.clone(), src_addr, receive), read_limit, write_limit))
                                        } else {
                                            Box::new(UdpDatagram::new(udp_socket.clone(), src_addr, receive))
                                        };
                                        let stat = speed_stat.clone();
                                        let servers = self.servers.clone();
                                        let handle = tokio::spawn(async move {
                                            let mut buffer = vec![0u8; 1024 * 4];
                                            loop {
                                                match receive_datagram.recv_from(&mut buffer).await {
                                                    Ok(len) => {
                                                        if let Some(server) = servers.get_server(name.as_str()) {
                                                            if let Server::Datagram(server) = server {
                                                                let buf = match server.serve_datagram(&buffer[0..len],
                                                                                                      DatagramInfo::new(Some(src_addr.to_string()))).await {
                                                                    Ok(buf) => buf,
                                                                    Err(e) => {
                                                                        log::error!("server error: {}", e);
                                                                        break;
                                                                    }
                                                                };
                                                                if let Err(e) = udp_socket.send_to(buf.as_slice(), src_addr).await {
                                                                    log::error!("send datagram error: {}", e);
                                                                    break;
                                                                }
                                                                stat.add_read_data_size(len as u64);
                                                                stat.add_write_data_size(buf.len() as u64);
                                                            }
                                                        }
                                                    }
                                                    Err(e) => {
                                                        log::error!("accept error: {}", e);
                                                        break;
                                                    }
                                                }
                                            }
                                        });
                                        send_datagram.send_to(&data[..len]).await?;

                                        *session_guard = Some(DatagramSession::Server(DatagramServerSession {
                                            server: server_name.clone(),
                                            latest_time: chrono::Utc::now().timestamp() as u64,
                                            notify: notify.clone(),
                                            speed_stat: speed_stat.clone(),
                                            send_handle: Some(handle),
                                            send_datagram: Some(send_datagram),
                                        }));
                                    } else {
                                        let buf = server.serve_datagram(&data[..len],
                                                                        DatagramInfo::new(Some(src_addr.to_string()))).await
                                            .map_err(into_stack_err!(StackErrorCode::ServerError, ""))?;
                                        udp_socket.send_to(buf.as_slice(), src_addr).await.map_err(into_stack_err!(StackErrorCode::IoError, "send error"))?;

                                        speed_stat.add_read_data_size(len as u64);
                                        speed_stat.add_write_data_size(buf.len() as u64);

                                        *session_guard = Some(DatagramSession::Server(DatagramServerSession {
                                            server: server_name.clone(),
                                            latest_time: chrono::Utc::now().timestamp() as u64,
                                            notify: notify.clone(),
                                            speed_stat: speed_stat.clone(),
                                            send_handle: None,
                                            send_datagram: None,
                                        }));
                                    }
                                    if let Some(connection_manager) = self.connection_manager.as_ref() {
                                        let controller = UdpSessionController::new(session_key, self.all_client_session.clone(), notify);
                                        connection_manager.add_connection(ConnectionInfo::new(src_addr.to_string(), server_name.to_string(), StackProtocol::Udp, speed_stat, controller));
                                    }
                                } else {
                                    return Err(stack_err!(
                                        StackErrorCode::InvalidConfig,
                                        "invalid server command"
                                    ));
                                }
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
        let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))
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

                unsafe {
                    if domain == socket2::Domain::IPV4 {
                        set_socket_opt(&socket,
                                       libc::SOL_IP,
                                       libc::IP_TRANSPARENT,
                                       libc::c_int::from(1))?;
                        set_socket_opt(&socket,
                                       libc::SOL_IP,
                                       libc::IP_ORIGDSTADDR,
                                       libc::c_int::from(1))?;
                        set_socket_opt(&socket,
                                       libc::SOL_IP,
                                       libc::IP_FREEBIND,
                                       libc::c_int::from(1))?;
                    } else if domain == socket2::Domain::IPV6 {
                        set_socket_opt(&socket,
                                       libc::SOL_IPV6,
                                       libc::IP_TRANSPARENT,
                                       libc::c_int::from(1))?;
                        set_socket_opt(&socket,
                                       libc::SOL_IPV6,
                                       libc::IPV6_RECVORIGDSTADDR,
                                       libc::c_int::from(1))?;
                        set_socket_opt(&socket,
                                       libc::SOL_IPV6,
                                       libc::IP_FREEBIND,
                                       libc::c_int::from(1))?;
                    }
                }
            }
        }
        // 4. 绑定套接字到指定地址
        socket.bind(&sockaddr).map_err(into_stack_err!(StackErrorCode::BindFailed, "bind error"))?;
        #[cfg(unix)]
        let socket = unsafe {
            std::net::UdpSocket::from_raw_fd(socket.into_raw_fd())
        };
        #[cfg(windows)]
        let socket = unsafe {
            std::net::UdpSocket::from_raw_socket(socket.into_raw_socket())
        };
        let udp_socket = tokio::net::UdpSocket::from_std(socket).map_err(into_stack_err!(StackErrorCode::IoError))?;
        let udp_socket = Arc::new(udp_socket);

        let this = self.clone();
        let concurrency = self.concurrency;
        let handle = tokio::spawn(async move {
            let semaphore = Arc::new(Semaphore::new(concurrency as usize));
            loop {
                let permit = semaphore.clone().acquire_owned().await.unwrap();
                let mut buffer = vec![0u8; 1024 * 2];
                #[cfg(target_os = "linux")]
                let (len, src_addr, dest_addr) =
                    if this.transparent {
                        match udp_socket.async_io(tokio::io::Interest::READABLE, || {
                            recv_from(&udp_socket, &mut buffer)
                        }).await {
                            Ok(ret) => ret,
                            Err(e) => {
                                log::error!("accept error: {}", e);
                                break;
                            }
                        }
                    } else {
                        let (len, addr) = match udp_socket.recv_from(&mut buffer).await {
                            Ok(pair) => pair,
                            Err(err) => {
                                log::error!("accept error: {}", err);
                                break;
                            }
                        };
                        let dest_addr = match udp_socket.local_addr() {
                            Ok(addr) => addr,
                            Err(err) => {
                                log::error!("get local addr error: {}", err);
                                break;
                            }
                        };
                        (len, addr, dest_addr)
                    };
                #[cfg(not(target_os = "linux"))]
                let (len, src_addr, dest_addr) = {
                    let (len, addr) = match udp_socket.recv_from(&mut buffer).await {
                        Ok(pair) => pair,
                        Err(err) => {
                            if let Some(err) = err.raw_os_error() {
                                if err == 10054 {
                                    continue;
                                }
                            }
                            log::error!("accept error: {}", err);
                            break;
                        }
                    };
                    let dest_addr = match udp_socket.local_addr() {
                        Ok(addr) => addr,
                        Err(err) => {
                            log::error!("get local addr error: {}", err);
                            break;
                        }
                    };
                    (len, addr, dest_addr)
                };
                let this = this.clone();
                let socket = udp_socket.clone();
                tokio::spawn(async move {
                    let result = this.handle_datagram(socket, src_addr, dest_addr, buffer, len).await;
                    if let Err(e) = result {
                        log::error!("handle datagram error: {}", e);
                    }
                    drop(permit);
                });
            }
        });
        Ok(handle)
    }

    async fn clear_idle_sessions(&self, latest_key: Option<SessionKey>) -> Option<SessionKey> {
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

    async fn clear_socket(&self) {
        self.socket_cache.clear_socket().await;
    }
}

pub struct UdpStack {
    inner: Arc<UdpStackInner>,
    handle: Mutex<Option<JoinHandle<()>>>,
    clear_handle: Mutex<Option<JoinHandle<()>>>,
}

impl Drop for UdpStack {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.lock().unwrap().take() {
            handle.abort();
        }
        if let Some(handle) = self.clear_handle.lock().unwrap().take() {
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
            handle: Mutex::new(None),
            clear_handle: Mutex::new(None),
        })
    }

    #[cfg(test)]
    fn get_session_count(&self) -> usize {
        self.inner.all_client_session.lock().unwrap().len()
    }
}

#[async_trait::async_trait]
impl Stack for UdpStack {
    fn id(&self) -> String {
        self.inner.id.clone()
    }

    fn stack_protocol(&self) -> StackProtocol {
        StackProtocol::Udp
    }
    fn get_bind_addr(&self) -> String {
        self.inner.bind_addr.clone()
    }

    async fn start(&self) -> StackResult<()> {
        let handle = self.inner.start().await?;
        let inner = self.inner.clone();
        *self.clear_handle.lock().unwrap() = Some(tokio::spawn(async move {
            let mut latest_key = None;
            loop {
                latest_key = inner.clear_idle_sessions(latest_key).await;
                inner.clear_socket().await;
                tokio::time::sleep(inner.session_idle_time.div(2)).await;
            }
        }));
        *self.handle.lock().unwrap() = Some(handle);
        Ok(())
    }

    async fn update_config(&self, config: Arc<dyn StackConfig>) -> StackResult<()> {
        let config = config.as_ref().as_any().downcast_ref::<UdpStackConfig>()
            .ok_or(stack_err!(StackErrorCode::InvalidConfig, "invalid udp stack config"))?;

        if config.id != self.inner.id {
            return Err(stack_err!(StackErrorCode::InvalidConfig, "id unmatch"));
        }

        if config.bind.to_string() != self.inner.bind_addr {
            return Err(stack_err!(StackErrorCode::BindUnmatched, "bind unmatch"));
        }

        let (executor, _) = create_process_chain_executor(&config.hook_point,
                                                          self.inner.global_process_chains.clone(),
                                                          Some(get_datagram_external_commands())).await
            .map_err(into_stack_err!(StackErrorCode::ProcessChainError))?;
        *self.inner.executor.lock().unwrap() = executor;
        Ok(())
    }
}

pub struct UdpStackBuilder {
    id: Option<String>,
    bind: Option<String>,
    concurrency: u32,
    session_idle_time: Duration,
    hook_point: Option<ProcessChainConfigs>,
    servers: Option<ServerManagerRef>,
    global_process_chains: Option<GlobalProcessChainsRef>,
    connection_manager: Option<ConnectionManagerRef>,
    tunnel_manager: Option<TunnelManager>,
    limiter_manager: Option<LimiterManagerRef>,
    stat_manager: Option<StatManagerRef>,
    transparent: bool,
}

impl UdpStackBuilder {
    fn new() -> Self {
        Self {
            id: None,
            bind: None,
            concurrency: 200,
            session_idle_time: Duration::from_secs(120),
            hook_point: None,
            servers: None,
            global_process_chains: None,
            connection_manager: None,
            tunnel_manager: None,
            limiter_manager: None,
            stat_manager: None,
            transparent: false,
        }
    }

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

    pub fn concurrency(mut self, concurrency: u32) -> Self {
        self.concurrency = concurrency;
        self
    }

    pub fn session_idle_time(mut self, session_idle_time: Duration) -> Self {
        self.session_idle_time = session_idle_time;
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

    pub fn limiter_manager(mut self, limiter_manager: LimiterManagerRef) -> Self {
        self.limiter_manager = Some(limiter_manager);
        self
    }

    pub fn stat_manager(mut self, stat_manager: StatManagerRef) -> Self {
        self.stat_manager = Some(stat_manager);
        self
    }

    pub async fn build(self) -> StackResult<UdpStack> {
        UdpStack::create(self).await
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct UdpStackConfig {
    pub id: String,
    pub protocol: StackProtocol,
    pub bind: SocketAddr,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub concurrency: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_idle_time: Option<u64>,
    pub hook_point: Vec<ProcessChainConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transparent: Option<bool>,
}

impl StackConfig for UdpStackConfig {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn stack_protocol(&self) -> StackProtocol {
        StackProtocol::Udp
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

pub struct UdpStackFactory {
    servers: ServerManagerRef,
    global_process_chains: GlobalProcessChainsRef,
    connection_manager: ConnectionManagerRef,
    tunnel_manager: TunnelManager,
    limiter_manager: LimiterManagerRef,
    stat_manager: StatManagerRef,
}

impl UdpStackFactory {
    pub fn new(
        servers: ServerManagerRef,
        global_process_chains: GlobalProcessChainsRef,
        connection_manager: ConnectionManagerRef,
        tunnel_manager: TunnelManager,
        limiter_manager: LimiterManagerRef,
        stat_manager: StatManagerRef,
    ) -> Self {
        Self {
            servers,
            global_process_chains,
            connection_manager,
            tunnel_manager,
            limiter_manager,
            stat_manager,
        }
    }
}

#[async_trait::async_trait]
impl StackFactory for UdpStackFactory {
    async fn create(&self, config: Arc<dyn StackConfig>) -> StackResult<StackRef> {
        let config = config
            .as_any()
            .downcast_ref::<UdpStackConfig>()
            .ok_or(stack_err!(StackErrorCode::InvalidConfig, "invalid udp stack config"))?;
        let stack = UdpStack::builder()
            .id(config.id.clone())
            .bind(config.bind.to_string())
            .tunnel_manager(self.tunnel_manager.clone())
            .connection_manager(self.connection_manager.clone())
            .global_process_chains(self.global_process_chains.clone())
            .servers(self.servers.clone())
            .hook_point(config.hook_point.clone())
            .concurrency(config.concurrency.unwrap_or(200))
            .session_idle_time(Duration::from_secs(config.session_idle_time.unwrap_or(120)))
            .transparent(config.transparent.unwrap_or(false))
            .limiter_manager(self.limiter_manager.clone())
            .stat_manager(self.stat_manager.clone())
            .build().await?;
        Ok(Arc::new(stack))
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use tokio::net::UdpSocket;
    use crate::{ConnectionManager, DatagramInfo, LimiterManager, ProcessChainConfigs, Server, ServerManager, ServerResult, Stack, StackFactory, StackProtocol, StatManager, TunnelManager, UdpStack, UdpStackConfig, UdpStackFactory};
    use crate::global_process_chains::GlobalProcessChains;
    use crate::server::{DatagramServer};

    #[tokio::test]
    async fn test_udp_stack_creation() {
        let result = UdpStack::builder()
            .id("test")
            .build()
            .await;
        assert!(result.is_err());
        let result = UdpStack::builder()
            .id("test")
            .bind("0.0.0.0:8930")
            .build()
            .await;
        assert!(result.is_err());
        let result = UdpStack::builder()
            .id("test")
            .bind("0.0.0.0:8930")
            .servers(Arc::new(ServerManager::new()))
            .build()
            .await;
        assert!(result.is_err());
        let result = UdpStack::builder()
            .id("test")
            .bind("0.0.0.0:8930")
            .hook_point(vec![])
            .servers(Arc::new(ServerManager::new()))
            .tunnel_manager(TunnelManager::new())
            .limiter_manager(LimiterManager::new())
            .stat_manager(StatManager::new())
            .build()
            .await;
        assert!(result.is_ok());
        let result = UdpStack::builder()
            .id("test")
            .bind("0.0.0.0:8930")
            .hook_point(vec![])
            .servers(Arc::new(ServerManager::new()))
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .tunnel_manager(TunnelManager::new())
            .limiter_manager(LimiterManager::new())
            .stat_manager(StatManager::new())
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

        let tunnel_manager = TunnelManager::new();
        let result = UdpStack::builder()
            .id("test")
            .bind("0.0.0.0:8930")
            .hook_point(chains)
            .servers(Arc::new(ServerManager::new()))
            .session_idle_time(Duration::from_secs(5))
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .tunnel_manager(tunnel_manager)
            .limiter_manager(LimiterManager::new())
            .stat_manager(StatManager::new())
            .transparent(true)
            .build()
            .await;
        assert!(result.is_ok());
        let stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());


        tokio::spawn(async move {
            let udp_socket = UdpSocket::bind("127.0.0.1:8933").await.unwrap();
            let mut buf = [0; 1024];
            let (n, addr) = udp_socket.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"test");
            let _ = udp_socket.send_to(b"recv", addr).await;
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
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

        let tunnel_manager = TunnelManager::new();
        let result = UdpStack::builder()
            .id("test")
            .bind("0.0.0.0:8931")
            .hook_point(chains)
            .session_idle_time(Duration::from_secs(5))
            .servers(Arc::new(ServerManager::new()))
            .tunnel_manager(tunnel_manager)
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .limiter_manager(LimiterManager::new())
            .stat_manager(StatManager::new())
            .build()
            .await;
        assert!(result.is_ok());
        let stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());


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

    struct MockServer {
        id: String,
    }

    impl MockServer {
        fn new(id: String) -> Self {
            Self {
                id,
            }
        }
    }

    #[async_trait::async_trait]
    impl DatagramServer for MockServer {
        async fn serve_datagram(&self, buf: &[u8], _info: DatagramInfo) -> ServerResult<Vec<u8>> {
            assert_eq!(buf, b"test_server");
            Ok("datagram".as_bytes().to_vec())
        }

        fn id(&self) -> String {
            self.id.clone()
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


        let tunnel_manager = TunnelManager::new();
        let datagram_server_manager = Arc::new(ServerManager::new());
        let _ = datagram_server_manager.add_server(Server::Datagram(Arc::new(MockServer::new("mock".to_string())))).unwrap();
        let result = UdpStack::builder()
            .id("test")
            .bind("0.0.0.0:8938")
            .hook_point(chains)
            .session_idle_time(Duration::from_secs(5))
            .servers(datagram_server_manager)
            .tunnel_manager(tunnel_manager)
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .limiter_manager(LimiterManager::new())
            .stat_manager(StatManager::new())
            .build()
            .await;
        assert!(result.is_ok());
        let stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());

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

    #[tokio::test]
    async fn test_udp_stack_stat_serve() {
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        set-stat test;
        return "server mock";
        "#;
        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();


        let tunnel_manager = TunnelManager::new();
        let stat_manager = StatManager::new();
        let datagram_server_manager = Arc::new(ServerManager::new());
        let _ = datagram_server_manager.add_server(Server::Datagram(Arc::new(MockServer::new("mock".to_string())))).unwrap();
        let result = UdpStack::builder()
            .id("test")
            .bind("0.0.0.0:8939")
            .hook_point(chains)
            .session_idle_time(Duration::from_secs(5))
            .servers(datagram_server_manager)
            .tunnel_manager(tunnel_manager)
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .limiter_manager(LimiterManager::new())
            .stat_manager(stat_manager.clone())
            .build()
            .await;
        assert!(result.is_ok());
        let stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());

        let udp_client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ret = udp_client.send_to(b"test_server", "127.0.0.1:8939").await;
        assert!(ret.is_ok());

        let mut buf = [0; 1024];
        let (n, _) = tokio::time::timeout(Duration::from_secs(10), udp_client.recv_from(&mut buf)).await.unwrap().unwrap();
        assert_eq!(&buf[..n], b"datagram");

        let test_stat = stat_manager.get_speed_stat("test");
        assert!(test_stat.is_some());
        let test_stat = test_stat.unwrap();
        assert_eq!(test_stat.get_read_sum_size(), 11);
        assert_eq!(test_stat.get_write_sum_size(), 8);

        assert!(stack.get_session_count() > 0);
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        assert_eq!(stack.get_session_count(), 0);
    }

    #[tokio::test]
    async fn test_udp_stack_stat_limiter_serve() {
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        set-stat test;
        set-limit "1B/s" "1B/s";
        return "server mock";
        "#;
        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();


        let tunnel_manager = TunnelManager::new();
        let stat_manager = StatManager::new();
        let datagram_server_manager = Arc::new(ServerManager::new());
        let _ = datagram_server_manager.add_server(Server::Datagram(Arc::new(MockServer::new("mock".to_string())))).unwrap();
        let result = UdpStack::builder()
            .id("test")
            .bind("0.0.0.0:8940")
            .hook_point(chains)
            .session_idle_time(Duration::from_secs(5))
            .servers(datagram_server_manager)
            .tunnel_manager(tunnel_manager)
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .limiter_manager(LimiterManager::new())
            .stat_manager(stat_manager.clone())
            .build()
            .await;
        assert!(result.is_ok());
        let stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());

        let udp_client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let start = Instant::now();
        let ret = udp_client.send_to(b"test_server", "127.0.0.1:8940").await;
        assert!(ret.is_ok());

        let mut buf = [0; 1024];
        let (n, _) = tokio::time::timeout(Duration::from_secs(10), udp_client.recv_from(&mut buf)).await.unwrap().unwrap();
        assert_eq!(&buf[..n], b"datagram");

        let ret = udp_client.send_to(b"test_server", "127.0.0.1:8940").await;
        assert!(ret.is_ok());

        let mut buf = [0; 1024];
        let (n, _) = tokio::time::timeout(Duration::from_secs(10), udp_client.recv_from(&mut buf)).await.unwrap().unwrap();
        assert_eq!(&buf[..n], b"datagram");

        let test_stat = stat_manager.get_speed_stat("test");
        assert!(test_stat.is_some());
        let test_stat = test_stat.unwrap();
        assert_eq!(test_stat.get_read_sum_size(), 22);
        assert_eq!(test_stat.get_write_sum_size(), 16);
        println!("{}", start.elapsed().as_millis());
        assert!(start.elapsed().as_millis() > 800);
        assert!(start.elapsed().as_millis() < 1400);

        assert!(stack.get_session_count() > 0);
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        assert_eq!(stack.get_session_count(), 0);
    }

    #[tokio::test]
    async fn test_udp_factory() {
        let udp_factory = UdpStackFactory::new(Arc::new(ServerManager::new()),
                                               Arc::new(GlobalProcessChains::new()),
                                               ConnectionManager::new(),
                                               TunnelManager::new(),
                                               LimiterManager::new(),
                                               StatManager::new(),
        );

        let config = UdpStackConfig {
            id: "test".to_string(),
            protocol: StackProtocol::Udp,
            bind: "127.0.0.1:334".parse().unwrap(),
            concurrency: None,
            session_idle_time: None,
            hook_point: vec![],
            transparent: None,
        };
        let ret = udp_factory.create(Arc::new(config)).await;
        assert!(ret.is_ok());
    }
}
