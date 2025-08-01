use std::collections::HashMap;
use std::io::{BufReader, Cursor};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use buckyos_kit::AsyncStream;
use hyper::{Request};
use rustls::{ServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls_pemfile::{certs, pkcs8_private_keys};
use crate::{CyfsServerConfig, CyfsServerProtocol, DatagramClientBox, GATEWAY_TUNNEL_MANAGER};

#[derive(Debug, Copy, Clone)]
pub enum ServerErrorCode {
    BindFailed,
    InvalidConfig,
    ProcessChainError,
    StreamError,
    TunnelError,
    InvalidTlsKey,
    InvalidTlsCert,
}
pub type ServerResult<T> = sfo_result::Result<T, ServerErrorCode>;
pub type ServerError = sfo_result::Error<ServerErrorCode>;
use sfo_result::err as server_err;
use sfo_result::into_err as into_server_err;
use tokio::net::{TcpStream};
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use url::Url;
use cyfs_process_chain::{CollectionValue, CommandControl, ExternalCommand, HookPoint, HookPointEnv, HttpsSniProbeCommand, ProcessChainListExecutor, StreamRequest, StreamRequestMap};

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
#[derive(Clone)]
// An Executor that uses the tokio runtime.
pub struct TokioExecutor;

// Implement the `hyper::rt::Executor` trait for `TokioExecutor` so that it can be used to spawn
// tasks in the hyper runtime.
// An Executor allows us to manage execution of tasks which can help us improve the efficiency and
// scalability of the server.
impl<F> hyper::rt::Executor<F> for TokioExecutor
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    fn execute(&self, fut: F) {
        tokio::task::spawn(fut);
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

        let https_sni_probe_command = HttpsSniProbeCommand::new();
        let name = https_sni_probe_command.name().to_owned();
        hook_point_env
            .register_external_command(
                &name,
                Arc::new(Box::new(https_sni_probe_command) as Box<dyn ExternalCommand>),
            )
            .unwrap();

        let executor = hook_point_env.prepare_exec_list(&hook_point).await
            .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{}", e))?;
        let executor = Arc::new(Mutex::new(executor));

        let listener = tokio::net::TcpListener::bind(
            format!("{}:{}", config.get_bind().to_string(), config.get_port())).await
            .map_err(into_server_err!(ServerErrorCode::BindFailed))?;

        let locked_executor = executor.clone();
        let handle = tokio::spawn(async move {
            loop {
                let (socket, local_addr) = match listener.accept().await {
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
                    if let Err(e) = Self::handle_connect(socket, local_addr, executor).await {
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

    async fn load_certs(path: &str) -> ServerResult<Vec<CertificateDer<'static>>> {
        let file_content = tokio::fs::read(path).await.map_err(into_server_err!(ServerErrorCode::InvalidConfig))?;
        let mut reader = BufReader::new(Cursor::new(file_content));
        Ok(certs(&mut reader)
            .map_err(|_| server_err!(ServerErrorCode::InvalidTlsCert, "failed to parse certificates"))?
            .into_iter()
            .map(|v| CertificateDer::from(v))
            .collect())
    }

    async fn load_key(path: &str) -> ServerResult<PrivateKeyDer<'static>> {
        let file_content = tokio::fs::read(path).await.map_err(into_server_err!(ServerErrorCode::InvalidTlsKey, "file:{}", path))?;
        let mut reader = BufReader::new(Cursor::new(file_content));
        let keys = pkcs8_private_keys(&mut reader)
            .map_err(|_| server_err!(ServerErrorCode::InvalidTlsKey, "failed to parse private key, file:{}", path))?;

        if keys.is_empty() {
            return Err(server_err!(ServerErrorCode::InvalidTlsKey, "no private key found, file:{}", path));
        }

        Ok(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(keys.into_iter().next().unwrap())))
    }
    async fn create_server_config(cert_path: &str, key_path: &str) -> ServerResult<Arc<ServerConfig>> {
        let certs = Self::load_certs(cert_path).await?;
        let key = Self::load_key(key_path).await?;
        Ok(Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .map_err(|e| server_err!(ServerErrorCode::InvalidTlsCert, "{}", e))?),
        )
    }

    async fn handle_connect(socket: TcpStream, local_addr: SocketAddr, executor: ProcessChainListExecutor) -> ServerResult<()> {
        let request = StreamRequest::new(Box::new(socket), local_addr);
        let request_map = StreamRequestMap::new(request);
        let chain_env = executor.chain_env();
        request_map.register(&chain_env).await.map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{}", e))?;

        let ret = executor.execute_all().await.map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{}", e))?;
        let executor = {
            let exe = executor.fork();
            drop(executor);
            exe
        };
        let request = request_map.into_request().map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{}", e))?;
        let socket = request.incoming_stream.lock().unwrap().take();
        if socket.is_none() {
            return Err(server_err!(ServerErrorCode::ProcessChainError, "socket is none"))
        }
        let socket = socket.unwrap();

        if ret.is_control() {
            if ret.is_drop() {
                return Ok(())
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
                                return Err(server_err!(ServerErrorCode::InvalidConfig, "invalid forward command"));
                            }
                            let target = list[1].as_str();
                            Self::forward(socket, target).await?;
                        }
                        "http" => {
                            if list.len() < 2 {
                                return Err(server_err!(ServerErrorCode::InvalidConfig, "invalid http command"));
                            }
                            let domain = list[1].as_str();
                            Self::http_server(socket, executor, domain).await?;
                        }
                        "http2" => {
                            if list.len() < 2 {
                                return Err(server_err!(ServerErrorCode::InvalidConfig, "invalid http command"));
                            }
                            let domain = list[1].as_str();
                            Self::http2_server(socket, executor, domain).await?;
                        }
                        "https" => {
                            if list.len() < 4 {
                                return Err(server_err!(ServerErrorCode::InvalidConfig, "invalid https command"));
                            }
                            let cert_path = list[1].as_str();
                            let key_path = list[2].as_str();
                            let domain = list[3].as_str();
                            Self::https_server(socket, executor, cert_path, key_path, domain).await?;
                        }
                        "https2" => {
                            if list.len() < 4 {
                                return Err(server_err!(ServerErrorCode::InvalidConfig, "invalid https command"));
                            }
                            let cert_path = list[1].as_str();
                            let key_path = list[2].as_str();
                            let domain = list[3].as_str();
                            Self::https2_server(socket, executor, cert_path, key_path, domain).await?;
                        }
                        _ => {

                        }
                    }
                }
            }
        }
        Ok(())
    }

    async fn forward(mut socket: Box<dyn AsyncStream>, target: &str) -> ServerResult<()> {
        if let Some(tunnel_manager) = GATEWAY_TUNNEL_MANAGER.get() {
            let url = Url::parse(target).map_err(into_server_err!(ServerErrorCode::InvalidConfig, "invalid forward url {}", target))?;
            let mut forward_stream = tunnel_manager.open_stream_by_url(&url).await
                .map_err(into_server_err!(ServerErrorCode::TunnelError))?;

            tokio::io::copy_bidirectional(
                &mut socket,
                forward_stream.as_mut(),
            ).await.map_err(into_server_err!(ServerErrorCode::StreamError))?;
        } else {
            log::error!("tunnel manager not found");
        }
        Ok(())
    }

    async fn http_server(socket: Box<dyn AsyncStream>, executor: ProcessChainListExecutor, domain: &str) -> ServerResult<()> {
        hyper::server::conn::http1::Builder::new().serve_connection(
            socket,
            hyper::service::service_fn(move |_req| {
                let executor = executor.fork();
                async move {
                    if let Some((_, chain)) = executor.get_chain(domain) {
                        match chain.execute(executor.context()).await {
                            Ok(_) => {}
                            Err(_) => {}
                        };
                    }
                    Ok::<_, hyper::Error>(hyper::Response::new(hyper::Body::from("Hello, World!")))
                }
            }),
        ).await.map_err(into_server_err!(ServerErrorCode::StreamError))?;
        Ok(())
    }

    async fn http2_server(socket: Box<dyn AsyncStream>, executor: ProcessChainListExecutor, domain: &str) -> ServerResult<()> {
        let domain = domain.to_string();
        hyper::server::conn::http2::Builder::new(TokioExecutor)
            .serve_connection(socket, hyper::service::service_fn(move |_req: Request<hyper::body::Body>| {
                let executor = executor.fork();
                let domain = domain.clone();
                async move {
                    if let Some((_, chain)) = executor.get_chain(domain.as_str()) {
                        match chain.execute(executor.context()).await {
                            Ok(_) => {}
                            Err(_) => {}
                        };
                    }
                    Ok::<_, hyper::Error>(hyper::Response::new(hyper::Body::from("Hello, World!")))
                }
            }),
        ).await.map_err(into_server_err!(ServerErrorCode::StreamError))?;
        Ok(())
    }

    async fn https_server(socket: Box<dyn AsyncStream>, executor: ProcessChainListExecutor, cert_path: &str, key_path: &str, domain: &str) -> ServerResult<()> {
        let config = Self::create_server_config(cert_path, key_path).await?;
        let tls_acceptor = TlsAcceptor::from(config);
        let tls_stream = tls_acceptor.accept(socket).await.map_err(into_server_err!(ServerErrorCode::StreamError))?;
        hyper::server::conn::http1::Builder::new().serve_connection(
            tls_stream,
            hyper::service::service_fn(move |_req| {
                let executor = executor.fork();
                async move {
                    if let Some((_, chain)) = executor.get_chain(domain) {
                        match chain.execute(executor.context()).await {
                            Ok(_) => {}
                            Err(_) => {}
                        };
                    }
                    Ok::<_, hyper::Error>(hyper::Response::new(hyper::Body::from("Hello, World!")))
                }
            }),
        ).await.map_err(into_server_err!(ServerErrorCode::StreamError))?;
        Ok(())
    }

    async fn https2_server(socket: Box<dyn AsyncStream>, executor: ProcessChainListExecutor, cert_path: &str, key_path: &str, domain: &str) -> ServerResult<()> {
        let config = Self::create_server_config(cert_path, key_path).await?;
        let tls_acceptor = TlsAcceptor::from(config);
        let tls_stream = tls_acceptor.accept(socket).await.map_err(into_server_err!(ServerErrorCode::StreamError))?;
        let domain = domain.to_string();
        hyper::server::conn::http2::Builder::new(TokioExecutor).serve_connection(
            tls_stream,
            hyper::service::service_fn(move |_req| {
                let executor = executor.fork();
                let domain = domain.clone();
                async move {
                    if let Some((_, chain)) = executor.get_chain(domain.as_str()) {
                        match chain.execute(executor.context()).await {
                            Ok(_) => {}
                            Err(_) => {}
                        };
                    }
                    Ok::<_, hyper::Error>(hyper::Response::new(hyper::Body::from("Hello, World!")))
                }
            }),
        ).await.map_err(into_server_err!(ServerErrorCode::StreamError))?;
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
