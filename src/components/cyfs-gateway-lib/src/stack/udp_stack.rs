use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::ops::Div;
#[cfg(unix)]
use std::os::fd::{FromRawFd, IntoRawFd};
#[cfg(windows)]
use std::os::windows::io::{FromRawSocket, IntoRawSocket};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration};
use local_ip_address::list_afinet_netifas;
use serde::{Deserialize, Serialize};
use sfo_io::{Datagram, LimitDatagram, SpeedTracker};
use tokio::net::{UdpSocket};
use tokio::sync::{Notify, Semaphore};
use tokio::task::JoinHandle;
use url::Url;
use cyfs_process_chain::{CollectionValue, CommandControl, MemoryMapCollection, ProcessChainLibExecutor};
use crate::{create_io_dump_stack_config, dump_single_datagram, into_stack_err, stack_err, DatagramClientBox, IoDumpStackConfig, ServerManagerRef, ProcessChainConfigs, Stack, StackContext, StackErrorCode, StackProtocol, StackResult, Server, ConnectionManagerRef, ConnectionController, ConnectionInfo, StackError, StackConfig, ProcessChainConfig, TunnelManager, StackFactory, StackRef, DatagramInfo, LimiterManagerRef, StatManagerRef, get_stat_info, ComposedSpeedStat, SpeedStatRef, get_external_commands, GlobalCollectionManagerRef, JsExternalsManagerRef};
use crate::global_process_chains::{create_process_chain_executor, GlobalProcessChainsRef};
use crate::stack::limiter::Limiter;
#[cfg(target_os = "linux")]
use crate::stack::{has_root_privileges, recv_from, set_socket_opt};
use crate::stack::get_limit_info;

#[derive(Clone)]
pub struct UdpStackContext {
    pub servers: ServerManagerRef,
    pub tunnel_manager: TunnelManager,
    pub limiter_manager: LimiterManagerRef,
    pub stat_manager: StatManagerRef,
    pub global_process_chains: Option<GlobalProcessChainsRef>,
    pub global_collection_manager: Option<GlobalCollectionManagerRef>,
    pub js_externals: Option<JsExternalsManagerRef>,
}

impl UdpStackContext {
    pub fn new(
        servers: ServerManagerRef,
        tunnel_manager: TunnelManager,
        limiter_manager: LimiterManagerRef,
        stat_manager: StatManagerRef,
        global_process_chains: Option<GlobalProcessChainsRef>,
        global_collection_manager: Option<GlobalCollectionManagerRef>,
        js_externals: Option<JsExternalsManagerRef>,
    ) -> Self {
        Self {
            servers,
            tunnel_manager,
            limiter_manager,
            stat_manager,
            global_process_chains,
            global_collection_manager,
            js_externals,
        }
    }
}

impl StackContext for UdpStackContext {
    fn stack_protocol(&self) -> StackProtocol {
        StackProtocol::Udp
    }
}

struct UdpDatagramHandler {
    env: Arc<UdpStackContext>,
    executor: ProcessChainLibExecutor,
    io_dump: Option<IoDumpStackConfig>,
}

impl UdpDatagramHandler {
    async fn create(
        hook_point: ProcessChainConfigs,
        env: Arc<UdpStackContext>,
        io_dump: Option<IoDumpStackConfig>,
    ) -> StackResult<Self> {
        let (executor, _) = create_process_chain_executor(
            &hook_point,
            env.global_process_chains.clone(),
            env.global_collection_manager.clone(),
            Some(get_external_commands(Arc::downgrade(&env.servers))),
            env.js_externals.clone(),
        )
            .await
            .map_err(|e| stack_err!(StackErrorCode::InvalidConfig, "create process chain executor error: {}", e))?;
        Ok(Self {
            env,
            executor,
            io_dump,
        })
    }

    async fn handle_datagram(
        &self,
        state: &UdpStackInner,
        udp_socket: Arc<UdpSocket>,
        src_addr: SocketAddr,
        dest_addr: SocketAddr,
        data: Vec<u8>,
        len: usize,
    ) -> StackResult<Option<NewDatagramSession>> {
        log::info!("new udp session: {} -> {}", src_addr, dest_addr);
        let executor = self.executor.fork();
        let global_env = executor.global_env();
        let map = MemoryMapCollection::new_ref();
        map.insert("source_addr", CollectionValue::String(src_addr.to_string())).await
            .map_err(|e| stack_err!(StackErrorCode::InvalidConfig, "insert source_addr error: {}", e))?;

        if let Some(device_info) = state
            .connection_manager
            .as_ref()
            .and_then(|manager| manager.get_device_info_by_source(src_addr.ip()))
        {
            if let Some(mac) = device_info.mac() {
                map.insert("source_mac", CollectionValue::String(mac.to_string())).await
                    .map_err(|e| stack_err!(StackErrorCode::InvalidConfig, "insert source_mac error: {}", e))?;
            }
            if let Some(host_name) = device_info.hostname() {
                map.insert("source_hostname", CollectionValue::String(host_name.to_string())).await
                    .map_err(|e| stack_err!(StackErrorCode::InvalidConfig, "insert source_hostname error: {}", e))?;
            }
        }

        map.insert("dest_addr", CollectionValue::String(dest_addr.to_string())).await
            .map_err(|e| stack_err!(StackErrorCode::InvalidConfig, "insert source_addr error: {}", e))?;

        global_env.create("REQ", CollectionValue::Map(map)).await
            .map_err(|e| stack_err!(StackErrorCode::InvalidConfig, "create chain env error: {}", e))?;

        let chain_env = global_env.clone();
        let ret = executor.execute_lib().await
            .map_err(|e| stack_err!(StackErrorCode::InvalidConfig, "execute chain error: {}", e))?;
        let mut new_session = None;
        if ret.is_control() {
            if ret.is_drop() {
                return Ok(None);
            } else if ret.is_reject() {
                return Ok(None);
            }
            if let Some(CommandControl::Return(ret)) = ret.as_control() {
                if let Some(list) = shlex::split(ret.value.as_str()) {
                    if list.is_empty() {
                        return Err(stack_err!(
                                    StackErrorCode::InvalidConfig,
                                    "invalid forward command"
                                ));
                    }

                    let udp_socket = if state.is_local_ip(&dest_addr.ip()) {
                        udp_socket.clone()
                    } else {
                        state.socket_cache.get_socket(dest_addr).await?
                    };

                    let (limiter_id, down_speed, up_speed) = get_limit_info(chain_env.clone()).await?;
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

                    let stat_group_ids = get_stat_info(chain_env).await?;
                    let speed_groups = self.env.stat_manager.get_speed_stats(stat_group_ids.as_slice());
                    let speed_stat = ComposedSpeedStat::new(speed_groups);
                    let speed_stat_ref: SpeedStatRef = speed_stat.clone();

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
                            let forward = self.env.tunnel_manager
                                .create_datagram_client_by_url(&url)
                                .await.map_err(into_stack_err!(StackErrorCode::TunnelError))?;
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
                                let io_dump = self.io_dump.clone();
                                let src_addr_copy = src_addr;
                                let dest_addr_copy = dest_addr;
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
                                        if let Some(io_dump) = io_dump.as_ref() {
                                            dump_single_datagram(
                                                io_dump,
                                                src_addr_copy.to_string(),
                                                dest_addr_copy.to_string(),
                                                Vec::new(),
                                                buffer[0..len].to_vec(),
                                            );
                                        }
                                        stat.add_write_data_size(len as u64);
                                    }
                                });

                                new_session = Some(NewDatagramSession {
                                    session: DatagramSession::Forward(DatagramForwardSession {
                                        client: send_datagram,
                                        latest_time: chrono::Utc::now().timestamp() as u64,
                                        receive_handle: Some(handle),
                                        notify: notify.clone(),
                                        speed_stat: speed_stat.clone(),
                                        send_handle: Some(send_handle),
                                    }),
                                    connection_target: target.to_string(),
                                    speed_stat: speed_stat_ref.clone(),
                                });
                            } else {
                                let io_dump = self.io_dump.clone();
                                let src_addr_copy = src_addr;
                                let dest_addr_copy = dest_addr;
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
                                        if let Some(io_dump) = io_dump.as_ref() {
                                            dump_single_datagram(
                                                io_dump,
                                                src_addr_copy.to_string(),
                                                dest_addr_copy.to_string(),
                                                Vec::new(),
                                                buffer[0..len].to_vec(),
                                            );
                                        }
                                        stat.add_write_data_size(len as u64);
                                    }
                                });

                                new_session = Some(NewDatagramSession {
                                    session: DatagramSession::Forward(DatagramForwardSession {
                                        client: Box::new(ClientDatagram::new(forward)),
                                        latest_time: chrono::Utc::now().timestamp() as u64,
                                        receive_handle: Some(handle),
                                        notify: notify.clone(),
                                        speed_stat: speed_stat.clone(),
                                        send_handle: None,
                                    }),
                                    connection_target: target.to_string(),
                                    speed_stat: speed_stat_ref.clone(),
                                });
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
                            if let Some(server) = self.env.servers.get_server(server_name.as_str()) {
                                if let Server::Datagram(datagram_server) = &server {
                                    let notify = Arc::new(Notify::new());
                                    let is_limit = true;
                                    let session_server = server.clone();
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
                                        let io_dump = self.io_dump.clone();
                                        let src_addr_copy = src_addr;
                                        let dest_addr_copy = dest_addr;
                                        let datagram_server = datagram_server.clone();
                                        let handle = tokio::spawn(async move {
                                            let mut buffer = vec![0u8; 1024 * 4];
                                            loop {
                                                match receive_datagram.recv_from(&mut buffer).await {
                                                    Ok(len) => {
                                                        let buf = match datagram_server.serve_datagram(&buffer[0..len],
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
                                                        if let Some(io_dump) = io_dump.as_ref() {
                                                            dump_single_datagram(
                                                                io_dump,
                                                                src_addr_copy.to_string(),
                                                                dest_addr_copy.to_string(),
                                                                Vec::new(),
                                                                buf.clone(),
                                                            );
                                                        }
                                                        stat.add_read_data_size(len as u64);
                                                        stat.add_write_data_size(buf.len() as u64);
                                                    }
                                                    Err(e) => {
                                                        log::error!("accept error: {}", e);
                                                        break;
                                                    }
                                                }
                                            }
                                        });
                                        send_datagram.send_to(&data[..len]).await?;

                                        new_session = Some(NewDatagramSession {
                                            session: DatagramSession::Server(DatagramServerSession {
                                                server: session_server,
                                                latest_time: chrono::Utc::now().timestamp() as u64,
                                                notify: notify.clone(),
                                                speed_stat: speed_stat.clone(),
                                                send_handle: Some(handle),
                                                send_datagram: Some(send_datagram),
                                            }),
                                            connection_target: server_name.clone(),
                                            speed_stat: speed_stat_ref.clone(),
                                        });
                                    }
                                } else {
                                    return Err(stack_err!(StackErrorCode::InvalidConfig, "invalid server command"));
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
        Ok(new_session)
    }
}

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
    server: Server,
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

struct NewDatagramSession {
    session: DatagramSession,
    connection_target: String,
    speed_stat: SpeedStatRef,
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
            let addr_str = std_addr.to_string();
            socket.bind(&addr).map_err(into_stack_err!(StackErrorCode::BindFailed, "bind error, address:{}", addr_str))?;
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
    all_client_session: DatagramClientSessionMap,
    connection_manager: Option<ConnectionManagerRef>,
    transparent: bool,
    local_ips: Vec<IpAddr>,
    socket_cache: SocketCache,
    handler: Arc<RwLock<Arc<UdpDatagramHandler>>>,
    io_dump: Arc<RwLock<Option<IoDumpStackConfig>>>,
}

impl UdpStackInner {
    async fn create(builder: UdpStackBuilder, handler: Arc<RwLock<Arc<UdpDatagramHandler>>>) -> StackResult<Self> {
        if builder.id.is_none() {
            return Err(stack_err!(StackErrorCode::InvalidConfig, "id is required"));
        }
        if builder.bind.is_none() {
            return Err(stack_err!(StackErrorCode::InvalidConfig, "bind is required"));
        }

        let local_ips = Self::local_ips()?;
        let io_dump = handler.read().unwrap().io_dump.clone();
        Ok(Self {
            id: builder.id.unwrap(),
            bind_addr: builder.bind.unwrap(),
            concurrency: builder.concurrency,
            session_idle_time: builder.session_idle_time,
            all_client_session: Arc::new(Mutex::new(BTreeMap::new())),
            connection_manager: builder.connection_manager,
            transparent: builder.transparent,
            local_ips,
            socket_cache: SocketCache::new(),
            io_dump: Arc::new(RwLock::new(io_dump)),
            handler,
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
        if let Some(io_dump) = self.io_dump.read().unwrap().clone() {
            dump_single_datagram(
                &io_dump,
                src_addr.to_string(),
                dest_addr.to_string(),
                data[..len].to_vec(),
                Vec::new(),
            );
        }
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
                        match &server_session.server {
                            Server::Datagram(server) => {
                                match server.serve_datagram(&data[..len], DatagramInfo::new(Some(src_addr.to_string()))).await {
                                    Ok(resp) => {
                                        if let Err(e) = udp_socket.send_to(resp.as_slice(), &src_addr).await {
                                            log::error!("send datagram error: {}", e);
                                            *session_guard = None;
                                        } else {
                                            if let Some(io_dump) = self.io_dump.read().unwrap().clone() {
                                                dump_single_datagram(
                                                    &io_dump,
                                                    src_addr.to_string(),
                                                    dest_addr.to_string(),
                                                    Vec::new(),
                                                    resp.clone(),
                                                );
                                            }
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
                            }
                            _ => {
                                return Err(stack_err!(StackErrorCode::InvalidConfig, "Unsupport server type"));
                            }
                        }
                    }
                }
            }
            return Ok(());
        }

        let handler_snapshot = {
            let handler = self.handler.read().unwrap();
            handler.clone()
        };
        if let Some(new_session) = handler_snapshot
            .handle_datagram(self, udp_socket, src_addr, dest_addr, data, len)
            .await?
        {
            let NewDatagramSession {
                session,
                connection_target,
                speed_stat,
            } = new_session;
            let notify = match &session {
                DatagramSession::Forward(session) => session.notify.clone(),
                DatagramSession::Server(session) => session.notify.clone(),
            };
            *session_guard = Some(session);
            if let Some(connection_manager) = self.connection_manager.as_ref() {
                let controller = UdpSessionController::new(session_key, self.all_client_session.clone(), notify);
                connection_manager.add_connection(ConnectionInfo::new(
                    src_addr.to_string(),
                    connection_target,
                    StackProtocol::Udp,
                    speed_stat,
                    controller,
                ));
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
        let sockaddr_str = addr.to_string();
        socket.bind(&sockaddr).map_err(into_stack_err!(StackErrorCode::BindFailed, "bind error, address:{}", sockaddr_str))?;
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
    prepare_handler: Arc<RwLock<Option<Arc<UdpDatagramHandler>>>>,
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

    async fn create(mut builder: UdpStackBuilder) -> StackResult<Self> {
        if builder.hook_point.is_none() {
            return Err(stack_err!(StackErrorCode::InvalidConfig, "hook_point is required"));
        }
        if builder.stack_context.is_none() {
            return Err(stack_err!(StackErrorCode::InvalidConfig, "stack_context is required"));
        }
        let stack_context = builder.stack_context.clone().unwrap();

        let handler = UdpDatagramHandler::create(
            builder.hook_point.take().unwrap(),
            stack_context,
            builder.io_dump.clone(),
        )
            .await?;
        let handler = Arc::new(RwLock::new(Arc::new(handler)));
        let inner = UdpStackInner::create(builder, handler).await?;
        Ok(Self {
            inner: Arc::new(inner),
            prepare_handler: Arc::new(Default::default()),
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
        {
            if self.handle.lock().unwrap().is_some() {
                return Ok(());
            }
        }
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

    async fn prepare_update(&self, config: Arc<dyn StackConfig>, context: Option<Arc<dyn StackContext>>) -> StackResult<()> {
        let config = config.as_ref().as_any().downcast_ref::<UdpStackConfig>()
            .ok_or(stack_err!(StackErrorCode::InvalidConfig, "invalid udp stack config"))?;

        if config.id != self.inner.id {
            return Err(stack_err!(StackErrorCode::InvalidConfig, "id unmatch"));
        }

        if config.bind.to_string() != self.inner.bind_addr {
            return Err(stack_err!(StackErrorCode::BindUnmatched, "bind unmatch"));
        }

        if config.transparent.unwrap_or(false) != self.inner.transparent {
            return Err(stack_err!(StackErrorCode::InvalidConfig, "transparent unmatch"));
        }

        let env = match context {
            Some(context) => {
                let udp_context = context.as_ref().as_any().downcast_ref::<UdpStackContext>()
                    .ok_or(stack_err!(StackErrorCode::InvalidConfig, "invalid udp stack context"))?;
                Arc::new(udp_context.clone())
            }
            None => self.inner.handler.read().unwrap().env.clone(),
        };

        let new_handler = UdpDatagramHandler::create(
            config.hook_point.clone(),
            env,
            create_io_dump_stack_config(
                &config.id,
                config.io_dump_file.as_deref(),
                config.io_dump_rotate_size.as_deref(),
                config.io_dump_rotate_max_files,
                config.io_dump_max_upload_bytes_per_conn.as_deref(),
                config.io_dump_max_download_bytes_per_conn.as_deref(),
            )
            .await
            .map_err(|e| stack_err!(StackErrorCode::InvalidConfig, "{e}"))?,
        ).await?;
        *self.prepare_handler.write().unwrap() = Some(Arc::new(new_handler));
        Ok(())
    }

    async fn commit_update(&self) {
        if let Some(handler) = self.prepare_handler.write().unwrap().take() {
            *self.inner.io_dump.write().unwrap() = handler.io_dump.clone();
            *self.inner.handler.write().unwrap() = handler;
        }
    }

    async fn rollback_update(&self) {
        self.prepare_handler.write().unwrap().take();
    }
}

pub struct UdpStackBuilder {
    id: Option<String>,
    bind: Option<String>,
    concurrency: u32,
    session_idle_time: Duration,
    hook_point: Option<ProcessChainConfigs>,
    connection_manager: Option<ConnectionManagerRef>,
    transparent: bool,
    stack_context: Option<Arc<UdpStackContext>>,
    io_dump: Option<IoDumpStackConfig>,
}

impl UdpStackBuilder {
    fn new() -> Self {
        Self {
            id: None,
            bind: None,
            concurrency: 200,
            session_idle_time: Duration::from_secs(120),
            hook_point: None,
            connection_manager: None,
            transparent: false,
            stack_context: None,
            io_dump: None,
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

    pub fn transparent(mut self, transparent: bool) -> Self {
        self.transparent = transparent;
        self
    }

    pub fn stack_context(mut self, stack_context: Arc<UdpStackContext>) -> Self {
        self.stack_context = Some(stack_context);
        self
    }

    pub fn io_dump(mut self, io_dump: Option<IoDumpStackConfig>) -> Self {
        self.io_dump = io_dump;
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub io_dump_file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub io_dump_rotate_size: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub io_dump_rotate_max_files: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub io_dump_max_upload_bytes_per_conn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub io_dump_max_download_bytes_per_conn: Option<String>,
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
}

pub struct UdpStackFactory {
    connection_manager: ConnectionManagerRef,
}

impl UdpStackFactory {
    pub fn new(
        connection_manager: ConnectionManagerRef,
    ) -> Self {
        Self {
            connection_manager,
        }
    }
}

#[async_trait::async_trait]
impl StackFactory for UdpStackFactory {
    async fn create(
        &self,
        config: Arc<dyn StackConfig>,
        context: Arc<dyn StackContext>,
    ) -> StackResult<StackRef> {
        let config = config
            .as_any()
            .downcast_ref::<UdpStackConfig>()
            .ok_or(stack_err!(StackErrorCode::InvalidConfig, "invalid udp stack config"))?;
        let stack_context = context
            .as_ref()
            .as_any()
            .downcast_ref::<UdpStackContext>()
            .ok_or(stack_err!(StackErrorCode::InvalidConfig, "invalid udp stack context"))?;
        let stack_context = Arc::new(stack_context.clone());
        let io_dump = create_io_dump_stack_config(
            &config.id,
            config.io_dump_file.as_deref(),
            config.io_dump_rotate_size.as_deref(),
            config.io_dump_rotate_max_files,
            config.io_dump_max_upload_bytes_per_conn.as_deref(),
            config.io_dump_max_download_bytes_per_conn.as_deref(),
        )
        .await
        .map_err(|e| stack_err!(StackErrorCode::InvalidConfig, "{e}"))?;
        let stack = UdpStack::builder()
            .id(config.id.clone())
            .bind(config.bind.to_string())
            .connection_manager(self.connection_manager.clone())
            .hook_point(config.hook_point.clone())
            .concurrency(config.concurrency.unwrap_or(200))
            .session_idle_time(Duration::from_secs(config.session_idle_time.unwrap_or(120)))
            .transparent(config.transparent.unwrap_or(false))
            .stack_context(stack_context.clone())
            .io_dump(io_dump)
            .build().await?;
        Ok(Arc::new(stack))
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::path::Path;
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use buckyos_kit::init_logging;
    use tokio::net::UdpSocket;
    use crate::{create_io_dump_stack_config, decode_io_dump_frames, ConnectionManager, DatagramInfo, DefaultLimiterManager, GlobalCollectionManager, GlobalCollectionManagerRef, LimiterManagerRef, ProcessChainConfigs, Server, ServerManager, ServerManagerRef, ServerResult, Stack, StackFactory, StackProtocol, StatManager, StatManagerRef, TunnelManager, UdpStack, UdpStackConfig, UdpStackContext, UdpStackFactory};
    use crate::global_process_chains::{GlobalProcessChains, GlobalProcessChainsRef};
    use crate::server::{DatagramServer};

    fn build_udp_context(
        servers: ServerManagerRef,
        tunnel_manager: TunnelManager,
        limiter_manager: LimiterManagerRef,
        stat_manager: StatManagerRef,
        global_process_chains: Option<GlobalProcessChainsRef>,
        global_collection_manager: Option<GlobalCollectionManagerRef>,
    ) -> Arc<UdpStackContext> {
        Arc::new(UdpStackContext::new(
            servers,
            tunnel_manager,
            limiter_manager,
            stat_manager,
            global_process_chains,
            global_collection_manager,
            None,
        ))
    }

    async fn wait_dump_frames(file: &Path, min_frames: usize) -> Vec<crate::DecodedIoDumpFrame> {
        for _ in 0..50 {
            if let Ok(data) = std::fs::read(file)
                && !data.is_empty()
                && let Ok(frames) = decode_io_dump_frames(&data)
                && frames.len() >= min_frames
            {
                return frames;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("dump frames not ready");
    }

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
            .build()
            .await;
        assert!(result.is_err());
        let stack_context = build_udp_context(
            Arc::new(ServerManager::new()),
            TunnelManager::new(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            None,
            None,
        );
        let result = UdpStack::builder()
            .id("test")
            .bind("0.0.0.0:8930")
            .hook_point(vec![])
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());
        let stack_context = build_udp_context(
            Arc::new(ServerManager::new()),
            TunnelManager::new(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
            None,
        );
        let result = UdpStack::builder()
            .id("test")
            .bind("0.0.0.0:8930")
            .hook_point(vec![])
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_udp_stack_forward() {
        init_logging("test", false);
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "forward udp:///127.0.0.1:8933";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let stack_context = build_udp_context(
            Arc::new(ServerManager::new()),
            TunnelManager::new(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
            None,
        );
        let result = UdpStack::builder()
            .id("test")
            .bind("0.0.0.0:8932")
            .hook_point(chains)
            .session_idle_time(Duration::from_secs(5))
            .transparent(false)
            .stack_context(stack_context)
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
        let ret = udp_client.send_to(b"test", "127.0.0.1:8932").await;
        assert!(ret.is_ok());

        let mut buf = [0; 1024];
        let (n, _) = tokio::time::timeout(Duration::from_secs(10), udp_client.recv_from(&mut buf)).await.unwrap().unwrap();
        assert_eq!(&buf[..n], b"recv");

        assert!(stack.get_session_count() > 0);
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        assert_eq!(stack.get_session_count(), 0);
    }

    #[tokio::test]
    async fn test_udp_io_dump_forward_single_roundtrip() {
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "forward udp:///127.0.0.1:8942";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();
        let stack_context = build_udp_context(
            Arc::new(ServerManager::new()),
            TunnelManager::new(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
            None,
        );
        let dir = tempfile::tempdir().unwrap();
        let dump = dir.path().join("udp_forward.dump");
        let io_dump = create_io_dump_stack_config(
            "udp_forward",
            Some(dump.to_string_lossy().as_ref()),
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        let stack = UdpStack::builder()
            .id("udp-dump-forward")
            .bind("0.0.0.0:8941")
            .hook_point(chains)
            .session_idle_time(Duration::from_secs(5))
            .stack_context(stack_context)
            .io_dump(io_dump)
            .build()
            .await
            .unwrap();
        stack.start().await.unwrap();

        tokio::spawn(async move {
            let udp_socket = UdpSocket::bind("127.0.0.1:8942").await.unwrap();
            let mut buf = [0; 1024];
            let (n, addr) = udp_socket.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"test");
            let _ = udp_socket.send_to(b"recv", addr).await;
        });

        tokio::time::sleep(Duration::from_millis(200)).await;
        let udp_client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        udp_client.send_to(b"test", "127.0.0.1:8941").await.unwrap();
        let mut buf = [0; 1024];
        let (n, _) = tokio::time::timeout(Duration::from_secs(10), udp_client.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], b"recv");

        let frames = wait_dump_frames(&dump, 2).await;
        assert!(frames.iter().any(|f| f.upload == b"test" && f.download.is_empty()));
        assert!(frames.iter().any(|f| f.upload.is_empty() && f.download == b"recv"));
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

        let stack_context = build_udp_context(
            Arc::new(ServerManager::new()),
            TunnelManager::new(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
            None,
        );
        let result = UdpStack::builder()
            .id("test")
            .bind("0.0.0.0:8931")
            .hook_point(chains)
            .session_idle_time(Duration::from_secs(5))
            .stack_context(stack_context)
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
        let limiter_manager = Arc::new(DefaultLimiterManager::new());
        let stat_manager = StatManager::new();
        let datagram_server_manager = Arc::new(ServerManager::new());
        let _ = datagram_server_manager.add_server(Server::Datagram(Arc::new(MockServer::new("mock".to_string())))).unwrap();
        let stack_context = build_udp_context(
            datagram_server_manager.clone(),
            tunnel_manager,
            limiter_manager,
            stat_manager,
            Some(Arc::new(GlobalProcessChains::new())),
            None,
        );
        let result = UdpStack::builder()
            .id("test")
            .bind("0.0.0.0:8938")
            .hook_point(chains)
            .session_idle_time(Duration::from_secs(5))
            .stack_context(stack_context)
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
    async fn test_udp_io_dump_server_single_roundtrip() {
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
        let limiter_manager = Arc::new(DefaultLimiterManager::new());
        let stat_manager = StatManager::new();
        let datagram_server_manager = Arc::new(ServerManager::new());
        datagram_server_manager
            .add_server(Server::Datagram(Arc::new(MockServer::new("mock".to_string()))))
            .unwrap();
        let stack_context = build_udp_context(
            datagram_server_manager,
            tunnel_manager,
            limiter_manager,
            stat_manager,
            Some(Arc::new(GlobalProcessChains::new())),
            None,
        );
        let dir = tempfile::tempdir().unwrap();
        let dump = dir.path().join("udp_server.dump");
        let io_dump = create_io_dump_stack_config(
            "udp_server",
            Some(dump.to_string_lossy().as_ref()),
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        let stack = UdpStack::builder()
            .id("udp-dump-server")
            .bind("0.0.0.0:8943")
            .hook_point(chains)
            .session_idle_time(Duration::from_secs(5))
            .stack_context(stack_context)
            .io_dump(io_dump)
            .build()
            .await
            .unwrap();
        stack.start().await.unwrap();

        let udp_client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        udp_client.send_to(b"test_server", "127.0.0.1:8943").await.unwrap();
        let mut buf = [0; 1024];
        let (n, _) = tokio::time::timeout(Duration::from_secs(10), udp_client.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], b"datagram");

        let frames = wait_dump_frames(&dump, 2).await;
        assert!(frames.iter().any(|f| f.upload == b"test_server" && f.download.is_empty()));
        assert!(frames.iter().any(|f| f.upload.is_empty() && f.download == b"datagram"));
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
        let limiter_manager = Arc::new(DefaultLimiterManager::new());
        let stat_manager = StatManager::new();
        let datagram_server_manager = Arc::new(ServerManager::new());
        let _ = datagram_server_manager.add_server(Server::Datagram(Arc::new(MockServer::new("mock".to_string())))).unwrap();
        let stack_context = build_udp_context(
            datagram_server_manager.clone(),
            tunnel_manager,
            limiter_manager,
            stat_manager.clone(),
            Some(Arc::new(GlobalProcessChains::new())),
            None,
        );
        let result = UdpStack::builder()
            .id("test")
            .bind("0.0.0.0:8939")
            .hook_point(chains)
            .session_idle_time(Duration::from_secs(5))
            .stack_context(stack_context)
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
        let limiter_manager = Arc::new(DefaultLimiterManager::new());
        let stat_manager = StatManager::new();
        let datagram_server_manager = Arc::new(ServerManager::new());
        let _ = datagram_server_manager.add_server(Server::Datagram(Arc::new(MockServer::new("mock".to_string())))).unwrap();
        let stack_context = build_udp_context(
            datagram_server_manager.clone(),
            tunnel_manager,
            limiter_manager,
            stat_manager.clone(),
            Some(Arc::new(GlobalProcessChains::new())),
            None,
        );
        let result = UdpStack::builder()
            .id("test")
            .bind("0.0.0.0:8940")
            .hook_point(chains)
            .session_idle_time(Duration::from_secs(5))
            .stack_context(stack_context)
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
        let server_manager = Arc::new(ServerManager::new());
        let global_process_chains = Arc::new(GlobalProcessChains::new());
        let tunnel_manager = TunnelManager::new();
        let limiter_manager = Arc::new(DefaultLimiterManager::new());
        let stat_manager = StatManager::new();
        let collection_manager = GlobalCollectionManager::create(vec![]).await.unwrap();
        let udp_factory = UdpStackFactory::new(ConnectionManager::new());

        let config = UdpStackConfig {
            id: "test".to_string(),
            protocol: StackProtocol::Udp,
            bind: "127.0.0.1:334".parse().unwrap(),
            concurrency: None,
            session_idle_time: None,
            hook_point: vec![],
            transparent: None,
            io_dump_file: None,
            io_dump_rotate_size: None,
            io_dump_rotate_max_files: None,
            io_dump_max_upload_bytes_per_conn: None,
            io_dump_max_download_bytes_per_conn: None,
        };
        let stack_context = Arc::new(UdpStackContext::new(
            server_manager,
            tunnel_manager,
            limiter_manager,
            stat_manager,
            Some(global_process_chains),
            Some(collection_manager),
            None,
        ));
        let ret = udp_factory.create(Arc::new(config), stack_context).await;
        assert!(ret.is_ok());
    }
}
