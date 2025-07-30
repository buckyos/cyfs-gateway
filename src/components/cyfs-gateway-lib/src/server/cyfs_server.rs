use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use crate::{CyfsServerConfig, CyfsServerProtocol, DatagramClientBox, TunnelEndpoint, GATEWAY_TUNNEL_MANAGER};

#[derive(Debug, Copy, Clone)]
pub enum ServerErrorCode {
    BindFailed,
    InvalidConfig,
    ProcessChainError,
    StreamError,
    TunnelError,
}
pub type ServerResult<T> = sfo_result::Result<T, ServerErrorCode>;
pub type ServerError = sfo_result::Error<ServerErrorCode>;
use sfo_result::err as server_err;
use sfo_result::into_err as into_server_err;
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use url::Url;
use cyfs_process_chain::{CollectionValue, CommandControl, HookPoint, HookPointEnv, ProcessChainListExecutor};

pub struct CyfsTcpServer {
    executor: Arc<Mutex<ProcessChainListExecutor>>,
    hook_point: Mutex<HookPoint>,
    server_handle: JoinHandle<()>,
}

impl Drop for CyfsTcpServer {
    fn drop(&mut self) {
        self.server_handle.abort();
    }
}

impl CyfsTcpServer {
    async fn create_server(config: CyfsServerConfig) -> ServerResult<Self> {
        let hook_point = HookPoint::new("cyfs_server_hook_point");
        for chain_config in config.get_process_chains().iter() {
            hook_point.add_process_chain(chain_config.create_process_chain()
                .map_err(into_server_err!(ServerErrorCode::InvalidConfig))?)
                .map_err(|e| server_err!(ServerErrorCode::InvalidConfig, "{}", e))?;
        }
        let hook_point_env = HookPointEnv::new("cyfs_server_hook_point_env", PathBuf::new());
        let executor = hook_point_env.prepare_exec_list(&hook_point).await
            .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{}", e))?;
        let executor = Arc::new(Mutex::new(executor));

        let listener = tokio::net::TcpListener::bind(
            format!("{}:{}", config.get_bind().to_string(), config.get_port())).await
            .map_err(into_server_err!(ServerErrorCode::BindFailed))?;

        let locked_executor = executor.clone();
        let handle = tokio::spawn(async move {
            loop {
                let (socket, _) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(err) => {
                        log::error!("accept error: {}", err);
                        break;
                    }
                };

                let executor = {
                    locked_executor.lock().unwrap().fork()
                };

                tokio::spawn(async move {
                    if let Err(e) = Self::handle_connect(socket, executor).await {
                        log::error!("handle connect error: {}", e);
                    }
                });
            }
        });
        Ok(Self {
            server_handle: handle,
            executor,
            hook_point: Mutex::new(hook_point),
        })
    }

    async fn handle_connect(mut socket: TcpStream, executor: ProcessChainListExecutor) -> ServerResult<()> {
        let chain_env = executor.chain_env();
        let addr = socket.peer_addr().map_err(into_server_err!(ServerErrorCode::StreamError))?;
        chain_env.create("src_ip", CollectionValue::String(addr.to_string())).await
            .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{}", e))?;
        chain_env.create("src_port", CollectionValue::String(format!("{}", addr.port()))).await
            .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{}", e))?;

        let ret = executor.execute_all().await.map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{}", e))?;
        if ret.is_control() {
            if ret.is_drop() {
                return Ok(())
            } else if ret.is_reject() {
                return Ok(());
            }
            if let Some(CommandControl::Return(ret)) = ret.as_control() {
                if let Some((cmd, param)) = ret.split_once(" ") {
                    match cmd {
                        "forward" => {
                            if let Some(tunnel_manager) = GATEWAY_TUNNEL_MANAGER.get() {
                                let url = Url::parse(param).map_err(into_server_err!(ServerErrorCode::InvalidConfig, "invalid forward url {}", param))?;
                                let mut forward_stream = tunnel_manager.open_stream_by_url(&url).await
                                    .map_err(into_server_err!(ServerErrorCode::TunnelError))?;

                                tokio::io::copy_bidirectional(
                                    &mut socket,
                                    forward_stream.as_mut(),
                                ).await.map_err(into_server_err!(ServerErrorCode::StreamError))?;
                            } else {
                                log::error!("tunnel manager not found");
                            }
                        }
                        _ => {

                        }
                    }
                }
            }
        }
        Ok(())
    }
    pub fn update_server(&self, config: CyfsServerConfig) -> ServerResult<()> {
        todo!();
    }
}

type DatagramClientSession = Box<dyn DatagramClientBox>;
type DatagramClientSessionMap = Arc<tokio::sync::Mutex<HashMap<SocketAddr, DatagramClientSession>>>;
pub struct CyfsUdpServer {
    executor: Arc<Mutex<ProcessChainListExecutor>>,
    hook_point: Mutex<HookPoint>,
    server_handle: JoinHandle<()>,
    all_client_sessions: DatagramClientSessionMap,
}

impl Drop for CyfsUdpServer {
    fn drop(&mut self) {
        self.server_handle.abort();
    }
}

impl CyfsUdpServer {
    async fn create_server(config: CyfsServerConfig) -> ServerResult<Self> {
        let hook_point = HookPoint::new("cyfs_server_hook_point");
        for chain_config in config.get_process_chains().iter() {
            hook_point.add_process_chain(chain_config.create_process_chain()
                .map_err(into_server_err!(ServerErrorCode::InvalidConfig))?)
                .map_err(|e| server_err!(ServerErrorCode::InvalidConfig, "{}", e))?;
        }
        let hook_point_env = HookPointEnv::new("cyfs_server_hook_point_env", PathBuf::new());
        let executor = hook_point_env.prepare_exec_list(&hook_point).await
            .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{}", e))?;
        let executor = Arc::new(Mutex::new(executor));


        let udp_socket = tokio::net::UdpSocket::bind(
            format!("{}:{}", config.get_bind().to_string(), config.get_port())).await
            .map_err(into_server_err!(ServerErrorCode::BindFailed))?;
        let udp_socket = Arc::new(udp_socket);

        let all_client_session: DatagramClientSessionMap =
            Arc::new(tokio::sync::Mutex::new(HashMap::new()));
        let locked_executor = executor.clone();
        let handle = tokio::spawn(async move {
            let mut buffer = vec![0u8; 1024 * 4];
            loop {
                let (len, addr) = match udp_socket.recv_from(&mut buffer).await {
                    Ok(pair) => pair,
                    Err(err) => {
                        log::error!("accept error: {}", err);
                        break;
                    }
                };

                let mut all_sessions = all_client_session.lock().await;
                let client_session = all_sessions.get(&addr);
                if client_session.is_some() {
                    let client_session = client_session.unwrap();
                    if let Err(e) = client_session.send_datagram(&buffer[0..len]).await {
                        log::error!("send datagram error: {}", e);
                        all_sessions.remove(&addr);
                        continue;
                    };
                } else {
                    let executor = {
                        locked_executor.lock().unwrap().fork()
                    };
                    let chain_env = executor.chain_env();
                    if let Err(e) = chain_env.create("src_ip", CollectionValue::String(addr.to_string())).await {
                        log::error!("create src_ip error: {}", e);
                        continue;
                    };
                    if let Err(e) = chain_env.create("src_port", CollectionValue::String(format!("{}", addr.port()))).await {
                        log::error!("create src_port error: {}", e);
                    }

                    let ret = match executor.execute_all().await {
                        Ok(ret) => ret,
                        Err(e) => {
                            log::error!("execute all error: {}", e);
                            continue;
                        }
                    };
                    if ret.is_control() {
                        if ret.is_drop() {
                            continue;
                        } else if ret.is_reject() {
                            continue;
                        }
                        if let Some(CommandControl::Return(ret)) = ret.as_control() {
                            if let Some((cmd, param)) = ret.split_once(" ") {
                                match cmd {
                                    "forward" => {
                                        if let Some(tunnel_manager) = GATEWAY_TUNNEL_MANAGER.get() {
                                            let url = match Url::parse(param) {
                                                Ok(url) => url,
                                                Err(err) => {
                                                    log::error!("parse url {} error: {}", param, err);
                                                    continue;
                                                }
                                            };
                                            let forward = match tunnel_manager.create_datagram_client_by_url(&url).await {
                                                Ok(forward) => forward,
                                                Err(err) => {
                                                    log::error!("create datagram client error: {}", err);
                                                    continue;
                                                }
                                            };
                                            if let Err(e) = forward.send_datagram(&buffer[0..len]).await {
                                                log::error!("send datagram error: {}", e);
                                                continue;
                                            }
                                            let forward_recv = forward.clone();
                                            let back_socket = udp_socket.clone();
                                            all_sessions.insert(addr, forward);
                                            tokio::spawn(async move {
                                                let mut buffer = vec![0u8; 1024 * 4];
                                                loop {
                                                    let len = match forward_recv.recv_datagram(&mut buffer).await {
                                                        Ok(pair) => pair,
                                                        Err(err) => {
                                                            log::error!("accept error: {}", err);
                                                            break;
                                                        }
                                                    };
                                                    if let Err(e) = back_socket.send_to(&buffer[0..len], addr).await {
                                                        log::error!("send datagram error: {}", e);
                                                        break;
                                                    }
                                                }
                                            });
                                        } else {
                                            log::error!("tunnel manager not found");
                                        }
                                    }
                                    _ => {

                                    }
                                }
                            }
                        }
                    }
                }
            }
        });

        Ok(Self {
            server_handle: handle,
            executor,
            hook_point: Mutex::new(hook_point),
            all_client_sessions: Arc::new(Default::default()),
        })
    }
}

pub enum CyfsServer {
    TcpServer(CyfsTcpServer),
    UdpServer(CyfsUdpServer),
}

impl CyfsServer {
    pub async fn create_server(config: CyfsServerConfig) -> ServerResult<Self> {
        match config.get_protocol() {
            CyfsServerProtocol::TCP => {
                let tcp_server = CyfsTcpServer::create_server(config).await?;
                Ok(CyfsServer::TcpServer(tcp_server))
            }
            CyfsServerProtocol::UDP => {
                let udp_server = CyfsUdpServer::create_server(config).await?;
                Ok(CyfsServer::UdpServer(udp_server))
            }
        }
    }
}
