use crate::{CyfsServerConfig, StackProtocol, RTcpStack, GATEWAY_TUNNEL_MANAGER, DatagramClientBox, ServerError};
use buckyos_kit::AsyncStream;
use hyper::{Request, Response, StatusCode};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::collections::HashMap;
use std::io::{BufReader, Cursor};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper_util::rt::{TokioExecutor, TokioIo};
use name_lib::{encode_ed25519_pkcs8_sk_to_pk, load_raw_private_key, DeviceConfig};

use cyfs_process_chain::{CollectionValue, CommandControl, CommandResult, HookPoint, HookPointEnv, HyperHttpRequestHeaderMap, MapCollection, ProcessChainListExecutor, StreamRequest, StreamRequestMap};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use url::Url;
use crate::global_process_chains::create_process_chain_executor;
use super::{server_err, into_server_err, ServerResult, ServerErrorCode};

type GenericError = Box<dyn std::error::Error + Send + Sync>;
type Result<T> = std::result::Result<T, GenericError>;
type BoxBody = http_body_util::combinators::BoxBody<Bytes, hyper::Error>;
fn full<T: Into<Bytes>>(chunk: T) -> BoxBody {
    Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}

pub struct CyfsHttpService {
    pub executor: ProcessChainListExecutor,
}

pub struct CyfsRTcpService {
    pub stack: RTcpStack,
    pub executor: ProcessChainListExecutor,
}

struct CyfsTcpServerState {
    executor: Arc<ProcessChainListExecutor>,
    rtcp_service: Option<Arc<CyfsRTcpService>>,
    http_services: HashMap<String, Arc<CyfsHttpService>>,
}
type CyfsTcpServerStateRef = Arc<Mutex<CyfsTcpServerState>>;

pub struct CyfsTcpServer {
    state: CyfsTcpServerStateRef,
    server_handle: JoinHandle<()>,
}

impl Drop for CyfsTcpServer {
    fn drop(&mut self) {
        self.server_handle.abort();
    }
}

async fn execute_chain(executor: ProcessChainListExecutor, stream: Box<dyn AsyncStream>, local_addr: SocketAddr) -> ServerResult<(CommandResult, Box<dyn AsyncStream>)> {
    let request = StreamRequest::new(stream, local_addr);
    let request_map = StreamRequestMap::new(request);
    let chain_env = executor.chain_env();
    request_map
        .register(&chain_env)
        .await
        .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{}", e))?;

    let ret = executor
        .execute_all()
        .await
        .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{}", e))?;
    drop(executor);

    let request = request_map
        .into_request()
        .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{}", e))?;
    let socket = request.incoming_stream.lock().unwrap().take();
    if socket.is_none() {
        return Err(server_err!(
                ServerErrorCode::ProcessChainError,
                "socket is none"
            ));
    }
    let socket = socket.unwrap();
    Ok((ret, socket))
}

impl CyfsTcpServer {
    async fn create_server(config: CyfsServerConfig) -> ServerResult<Self> {
        let (executor, _) = create_process_chain_executor(config.get_process_chains()).await
            .map_err(into_server_err!(ServerErrorCode::ProcessChainError))?;

        let listener = tokio::net::TcpListener::bind(format!(
            "{}:{}",
            config.get_bind().to_string(),
            config.get_port()
        ))
        .await
        .map_err(into_server_err!(ServerErrorCode::BindFailed))?;

        let rtcp_service = if config.get_rtcp_service().is_some() {
            let rtcp_config = config.get_rtcp_service().as_ref().unwrap();
            let private_key = load_raw_private_key(Path::new(rtcp_config.device_key.as_str()))
                .map_err(into_server_err!(ServerErrorCode::InvalidConfig, "Invalid device key file {}", rtcp_config.device_key))?;
            let public_key = encode_ed25519_pkcs8_sk_to_pk(&private_key);

            let device_config = DeviceConfig::new(rtcp_config.device_name.as_str(), public_key);

            let rtcp_stack = RTcpStack::new(device_config.id.clone(), config.get_port(), Some(private_key));
            let (executor, _) = create_process_chain_executor(&rtcp_config.process_chains).await
                .map_err(into_server_err!(ServerErrorCode::ProcessChainError))?;
            Some(Arc::new(CyfsRTcpService {
                stack: rtcp_stack,
                executor,
            }))
        } else {
            None
        };

        let mut http_services = HashMap::new();
        if config.get_http_services().is_some() {
            let http_services_config = config.get_http_services().as_ref().unwrap();
            for (id, service_config) in http_services_config.iter() {
                let (executor, _) = create_process_chain_executor(&service_config.process_chains).await
                    .map_err(into_server_err!(ServerErrorCode::ProcessChainError))?;
                http_services.insert(id.clone(), Arc::new(CyfsHttpService {
                    executor,
                }));
            }
        }
        let state = CyfsTcpServerState {
            executor: Arc::new(executor),
            rtcp_service,
            http_services,
        };

        let state_ref = Arc::new(Mutex::new(state));
        let state =state_ref.clone();
        let handle = tokio::spawn(async move {
            loop {
                let (socket, local_addr) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(err) => {
                        log::error!("accept error: {}", err);
                        break;
                    }
                };

                let state = state_ref.clone();
                tokio::spawn(async move {
                    if let Err(e) = Self::handle_connect(state, socket, local_addr).await {
                        log::error!("handle connect error: {}", e);
                    }
                });
            }
        });
        Ok(Self {
            server_handle: handle,
            state,
        })
    }

    async fn load_certs(path: &str) -> ServerResult<Vec<CertificateDer<'static>>> {
        let file_content = tokio::fs::read(path)
            .await
            .map_err(into_server_err!(ServerErrorCode::InvalidConfig))?;
        let mut reader = BufReader::new(Cursor::new(file_content));
        Ok(certs(&mut reader)
            .map_err(|_| {
                server_err!(
                    ServerErrorCode::InvalidTlsCert,
                    "failed to parse certificates"
                )
            })?
            .into_iter()
            .map(|v| CertificateDer::from(v))
            .collect())
    }

    async fn load_key(path: &str) -> ServerResult<PrivateKeyDer<'static>> {
        let file_content = tokio::fs::read(path).await.map_err(into_server_err!(
            ServerErrorCode::InvalidTlsKey,
            "file:{}",
            path
        ))?;
        let mut reader = BufReader::new(Cursor::new(file_content));
        let keys = pkcs8_private_keys(&mut reader).map_err(|_| {
            server_err!(
                ServerErrorCode::InvalidTlsKey,
                "failed to parse private key, file:{}",
                path
            )
        })?;

        if keys.is_empty() {
            return Err(server_err!(
                ServerErrorCode::InvalidTlsKey,
                "no private key found, file:{}",
                path
            ));
        }

        Ok(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            keys.into_iter().next().unwrap(),
        )))
    }
    async fn create_server_config(
        cert_path: &str,
        key_path: &str,
    ) -> ServerResult<Arc<ServerConfig>> {
        let certs = Self::load_certs(cert_path).await?;
        let key = Self::load_key(key_path).await?;
        Ok(Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .map_err(|e| server_err!(ServerErrorCode::InvalidTlsCert, "{}", e))?,
        ))
    }

    async fn handle_connect(
        state: CyfsTcpServerStateRef,
        socket: TcpStream,
        local_addr: SocketAddr,
    ) -> ServerResult<()> {
        let executor = {
            state.lock().unwrap().executor.fork()
        };
        let (ret, socket) = execute_chain(executor, Box::new(socket), local_addr).await?;
        if ret.is_control() {
            if ret.is_drop() {
                return Ok(());
            } else if ret.is_reject() {
                return Ok(());
            }
            if let Some(CommandControl::Return(ret)) = ret.as_control() {
                if let Some(list) = shlex::split(ret) {
                    if list.len() == 0 {
                        return Ok(());
                    }
                    let cmd = list[0].as_str();
                    match cmd {
                        "forward" => {
                            if list.len() < 2 {
                                return Err(server_err!(
                                    ServerErrorCode::InvalidConfig,
                                    "invalid forward command"
                                ));
                            }
                            let target = list[1].as_str();
                            Self::forward(socket, target).await?;
                        }
                        "http" => {
                            if list.len() < 2 {
                                return Err(server_err!(
                                    ServerErrorCode::InvalidConfig,
                                    "invalid http command"
                                ));
                            }
                            let domain = list[1].as_str();
                            Self::http_server(state, socket, domain).await?;
                        }
                        "http2" => {
                            if list.len() < 2 {
                                return Err(server_err!(
                                    ServerErrorCode::InvalidConfig,
                                    "invalid http command"
                                ));
                            }
                            let domain = list[1].as_str();
                            Self::http2_server(state, socket, domain).await?;
                        }
                        "https" => {
                            if list.len() < 4 {
                                return Err(server_err!(
                                    ServerErrorCode::InvalidConfig,
                                    "invalid https command"
                                ));
                            }
                            let cert_path = list[1].as_str();
                            let key_path = list[2].as_str();
                            let domain = list[3].as_str();
                            Self::https_server(state, socket, cert_path, key_path, domain)
                                .await?;
                        }
                        "https2" => {
                            if list.len() < 4 {
                                return Err(server_err!(
                                    ServerErrorCode::InvalidConfig,
                                    "invalid https command"
                                ));
                            }
                            let cert_path = list[1].as_str();
                            let key_path = list[2].as_str();
                            let domain = list[3].as_str();
                            Self::https2_server(state, socket, cert_path, key_path, domain)
                                .await?;
                        }
                        _ => {}
                    }
                }
            }
        }
        Ok(())
    }

    async fn forward(mut socket: Box<dyn AsyncStream>, target: &str) -> ServerResult<()> {
        if let Some(tunnel_manager) = GATEWAY_TUNNEL_MANAGER.get() {
            let url = Url::parse(target).map_err(into_server_err!(
                ServerErrorCode::InvalidConfig,
                "invalid forward url {}",
                target
            ))?;
            let mut forward_stream = tunnel_manager
                .open_stream_by_url(&url)
                .await
                .map_err(into_server_err!(ServerErrorCode::TunnelError))?;

            tokio::io::copy_bidirectional(&mut socket, forward_stream.as_mut())
                .await
                .map_err(into_server_err!(ServerErrorCode::StreamError))?;
        } else {
            log::error!("tunnel manager not found");
        }
        Ok(())
    }

    async fn http_server(
        state: CyfsTcpServerStateRef,
        socket: Box<dyn AsyncStream>,
        domain: &str,
    ) -> ServerResult<()> {
        let http_service = {
            state.lock().unwrap().http_services.get(domain).map(|service| {
                service.clone()
            })
        };
        hyper::server::conn::http1::Builder::new()
            .serve_connection(
                TokioIo::new(socket),
                hyper::service::service_fn(move |req| {
                    let http_service = http_service.clone();
                    async move {
                        if let Some(http_service) = http_service {
                            match Self::handle_http_request(req, http_service.executor.fork()).await {
                                Ok(res) => Ok(res),
                                Err(e) => {
                                    log::error!("handle http request error: {}", e);
                                    Ok::<_, hyper::Error>(Response::builder()
                                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                                        .body(full(Bytes::new()))
                                        .unwrap())
                                }
                            }
                        } else {
                            Ok::<_, hyper::Error>(Response::builder()
                                .status(StatusCode::NOT_FOUND)
                                .body(full(Bytes::new())).unwrap()
                            )
                        }
                    }
                }),
            )
            .await
            .map_err(into_server_err!(ServerErrorCode::StreamError))?;
        Ok(())
    }

    async fn http2_server(
        state: CyfsTcpServerStateRef,
        socket: Box<dyn AsyncStream>,
        domain: &str,
    ) -> ServerResult<()> {
        let http_service = {
            state.lock().unwrap().http_services.get(domain).map(|service| {
                service.clone()
            })
        };
        hyper::server::conn::http2::Builder::new(TokioExecutor::new())
            .serve_connection(
                TokioIo::new(socket),
                hyper::service::service_fn(move |req| {
                    let http_service = http_service.clone();
                    async move {
                        if let Some(http_service) = http_service {
                            match Self::handle_http_request(req, http_service.executor.fork()).await {
                                Ok(res) => Ok(res),
                                Err(e) => {
                                    log::error!("handle http request error: {}", e);
                                    Ok::<_, hyper::Error>(Response::builder()
                                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                                        .body(full(Bytes::new()))
                                        .unwrap())
                                }
                            }
                        } else {
                            Ok::<_, hyper::Error>(Response::builder()
                                .status(StatusCode::NOT_FOUND)
                                .body(full(Bytes::new())).unwrap()
                            )
                        }
                    }
                }),
            )
            .await
            .map_err(into_server_err!(ServerErrorCode::StreamError))?;
        Ok(())
    }

    async fn https_server(
        state: CyfsTcpServerStateRef,
        socket: Box<dyn AsyncStream>,
        cert_path: &str,
        key_path: &str,
        domain: &str,
    ) -> ServerResult<()> {
        let http_service = {
            state.lock().unwrap().http_services.get(domain).map(|service| {
                service.clone()
            })
        };
        let config = Self::create_server_config(cert_path, key_path).await?;
        let tls_acceptor = TlsAcceptor::from(config);
        let tls_stream = tls_acceptor
            .accept(socket)
            .await
            .map_err(into_server_err!(ServerErrorCode::StreamError))?;
        hyper::server::conn::http1::Builder::new()
            .serve_connection(
                TokioIo::new(tls_stream),
                hyper::service::service_fn(move |req| {
                    let http_service = http_service.clone();
                    async move {
                        if let Some(http_service) = http_service {
                            match Self::handle_http_request(req, http_service.executor.fork()).await {
                                Ok(res) => Ok(res),
                                Err(e) => {
                                    log::error!("handle http request error: {}", e);
                                    Ok::<_, hyper::Error>(Response::builder()
                                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                                        .body(full(Bytes::new()))
                                        .unwrap())
                                }
                            }
                        } else {
                            Ok::<_, hyper::Error>(Response::builder()
                                .status(StatusCode::NOT_FOUND)
                                .body(full(Bytes::new())).unwrap()
                            )
                        }
                    }
                }),
            )
            .await
            .map_err(into_server_err!(ServerErrorCode::StreamError))?;
        Ok(())
    }

    async fn https2_server(
        state: CyfsTcpServerStateRef,
        socket: Box<dyn AsyncStream>,
        cert_path: &str,
        key_path: &str,
        domain: &str,
    ) -> ServerResult<()> {
        let http_service = {
            state.lock().unwrap().http_services.get(domain).map(|service| {
                service.clone()
            })
        };
        let config = Self::create_server_config(cert_path, key_path).await?;
        let tls_acceptor = TlsAcceptor::from(config);
        let tls_stream = tls_acceptor
            .accept(socket)
            .await
            .map_err(into_server_err!(ServerErrorCode::StreamError))?;
        hyper::server::conn::http2::Builder::new(TokioExecutor::new())
            .serve_connection(
                TokioIo::new(tls_stream),
                hyper::service::service_fn(move |req| {
                    let http_service = http_service.clone();
                    async move {
                        if let Some(http_service) = http_service {
                            match Self::handle_http_request(req, http_service.executor.fork()).await {
                                Ok(res) => Ok(res),
                                Err(e) => {
                                    log::error!("handle http request error: {}", e);
                                    Ok::<_, hyper::Error>(Response::builder()
                                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                                        .body(full(Bytes::new()))
                                        .unwrap())
                                }
                            }
                        } else {
                            Ok::<_, hyper::Error>(Response::builder()
                                .status(StatusCode::NOT_FOUND)
                                 .body(full(Bytes::new())).unwrap()
                            )
                        }
                    }
                }),
            )
            .await
            .map_err(into_server_err!(ServerErrorCode::StreamError))?;
        Ok(())
    }

    async fn handle_http_request(
        request: Request<Incoming>,
        executor: ProcessChainListExecutor,
    ) -> ServerResult<Response<BoxBody>> {
        let req_map = HyperHttpRequestHeaderMap::new(request);
        let chain_env = executor.chain_env();
        req_map.register_visitors(&chain_env).await.map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{}", e))?;

        let req_collection = Arc::new(Box::new(req_map.clone()) as Box<dyn MapCollection>);
        chain_env.create("REQ", CollectionValue::Map(req_collection)).await.map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{}", e))?;

        let ret = executor.execute_all().await.map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{}", e))?;
        if ret.is_control() {
            if ret.is_drop() {
                info!("Request dropped by the process chain");
                return Ok(Response::new(Full::new(Bytes::from("Request dropped")).map_err(|e| match e {}).boxed()));
            } else if ret.is_reject() {
                info!("Request rejected by the process chain");
                let mut response = Response::new(Full::new(Bytes::new()).map_err(|e| match e {}).boxed());
                *response.status_mut() = StatusCode::FORBIDDEN;
                return Ok(response);
            } else {
                info!("Request accepted by the process chain");
            }
        }
        drop(executor);

        Ok(hyper::Response::new(Full::new(Bytes::from(
            "Hello, World!",
        )).map_err(|e| match e {}).boxed()))
    }

    async fn rtcp_server(
        state: CyfsTcpServerStateRef,
        stream: TcpStream,
        addr: SocketAddr,
    ) -> ServerResult<()> {
        let rtcp_service = {
            let state = state.lock().unwrap();
            if state.rtcp_service.is_none() {
                return Ok(());
            }
            state.rtcp_service.as_ref().unwrap().clone()
        };

        rtcp_service.stack.serve_connection(stream, addr).await;

        Ok(())
    }

    pub fn update_server(&self, _config: CyfsServerConfig) -> ServerResult<()> {
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
            hook_point
                .add_process_chain(
                    chain_config
                        .create_process_chain()
                        .map_err(into_server_err!(ServerErrorCode::InvalidConfig))?,
                )
                .map_err(|e| server_err!(ServerErrorCode::InvalidConfig, "{}", e))?;
        }
        let hook_point_env = HookPointEnv::new("cyfs_server_hook_point_env", PathBuf::new());
        let executor = hook_point_env
            .prepare_exec_list(&hook_point)
            .await
            .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{}", e))?;
        let executor = Arc::new(Mutex::new(executor));

        let udp_socket = tokio::net::UdpSocket::bind(format!(
            "{}:{}",
            config.get_bind().to_string(),
            config.get_port()
        ))
        .await
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
                    let executor = { locked_executor.lock().unwrap().fork() };
                    let chain_env = executor.chain_env();
                    if let Err(e) = chain_env
                        .create("src_ip", CollectionValue::String(addr.to_string()))
                        .await
                    {
                        log::error!("create src_ip error: {}", e);
                        continue;
                    };
                    if let Err(e) = chain_env
                        .create(
                            "src_port",
                            CollectionValue::String(format!("{}", addr.port())),
                        )
                        .await
                    {
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
                                                    log::error!(
                                                        "parse url {} error: {}",
                                                        param,
                                                        err
                                                    );
                                                    continue;
                                                }
                                            };
                                            let forward = match tunnel_manager
                                                .create_datagram_client_by_url(&url)
                                                .await
                                            {
                                                Ok(forward) => forward,
                                                Err(err) => {
                                                    log::error!(
                                                        "create datagram client error: {}",
                                                        err
                                                    );
                                                    continue;
                                                }
                                            };
                                            if let Err(e) =
                                                forward.send_datagram(&buffer[0..len]).await
                                            {
                                                log::error!("send datagram error: {}", e);
                                                continue;
                                            }
                                            let forward_recv = forward.clone();
                                            let back_socket = udp_socket.clone();
                                            all_sessions.insert(addr, forward);
                                            tokio::spawn(async move {
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
                                        } else {
                                            log::error!("tunnel manager not found");
                                        }
                                    }
                                    _ => {}
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
            StackProtocol::Tcp => {
                let tcp_server = CyfsTcpServer::create_server(config).await?;
                Ok(CyfsServer::TcpServer(tcp_server))
            }
            StackProtocol::Udp => {
                let udp_server = CyfsUdpServer::create_server(config).await?;
                Ok(CyfsServer::UdpServer(udp_server))
            }
            _ => {
                return Err(ServerError::new(
                    ServerErrorCode::InvalidConfig,
                    format!("invalid protocol: {:?}", config.get_protocol()),
                ));
            }
        }
    }
}
