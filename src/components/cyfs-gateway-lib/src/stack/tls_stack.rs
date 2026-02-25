use crate::global_process_chains::{
    create_process_chain_executor, execute_stream_chain, GlobalProcessChainsRef,
};
use crate::{
    create_io_dump_stack_config,
    get_external_commands, get_stat_info, hyper_serve_http, into_stack_err, stack_err,
    DumpStream, IoDumpStackConfig,
    ConnectionInfo, ConnectionManagerRef, HandleConnectionController, LimiterManagerRef, StatManagerRef,
    MutComposedSpeedStat, MutComposedSpeedStatRef, ProcessChainConfigs,
    Server, ServerManagerRef, Stack, StackCertConfig, StackConfig, StackContext, StackErrorCode,
    StackProtocol, StackResult, StreamInfo, TunnelManager, GlobalCollectionManagerRef,
    JsExternalsManagerRef,
};
use cyfs_process_chain::{CommandControl, ProcessChainLibExecutor, StreamRequest};
pub use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, RwLock};
use rustls::pki_types::pem::PemObject;
use rustls::server::ResolvesServerCert;
use rustls::sign::CertifiedKey;
use sfo_io::{LimitStream, StatStream};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use crate::stack::{get_limit_info, get_source_addr_from_req_env, stream_forward, TlsCertResolver};
use serde::{Deserialize, Serialize};
use cyfs_acme::{AcmeCertManagerRef, AcmeItem, ChallengeType, ACME_TLS_ALPN_NAME};
use crate::self_cert_mgr::SelfCertMgrRef;
use crate::stack::limiter::Limiter;
use crate::stack::tls_cert_resolver::ResolvesServerCertUsingSni;

pub async fn load_certs(path: &str) -> StackResult<Vec<CertificateDer<'static>>> {
    let certs = CertificateDer::pem_file_iter(path).map_err(
        into_stack_err!(
            StackErrorCode::InvalidTlsCert,
            "failed to parse certificate, file:{}",
            path
        )
    )?.filter(|item| item.is_ok())
        .map(|item| item.unwrap()).collect();
    Ok(certs)
}

pub async fn load_key(path: &str) -> StackResult<PrivateKeyDer<'static>> {
    PrivateKeyDer::from_pem_file(path).map_err(
        into_stack_err!(
            StackErrorCode::InvalidTlsKey,
            "failed to parse private key, file:{}",
            path
        )
    )
}
pub async fn create_server_config(
    cert_path: &str,
    key_path: &str,
) -> StackResult<Arc<ServerConfig>> {
    let certs = load_certs(cert_path).await?;
    let key = load_key(key_path).await?;
    Ok(Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| stack_err!(StackErrorCode::InvalidTlsCert, "{}", e))?,
    ))
}

async fn build_tls_domain_configs(
    certs: &[StackCertConfig],
) -> StackResult<Vec<TlsDomainConfig>> {
    let mut cert_list = Vec::with_capacity(certs.len());
    for cert_config in certs.iter() {
        if cert_config.cert_path.is_some() && cert_config.key_path.is_some() {
            let certs = load_certs(cert_config.cert_path.as_deref().unwrap()).await?;
            let key = load_key(cert_config.key_path.as_deref().unwrap()).await?;
            cert_list.push(TlsDomainConfig {
                domain: cert_config.domain.clone(),
                acme_type: None,
                certs: Some(certs),
                key: Some(key),
                data: None,
            });
        } else {
            cert_list.push(TlsDomainConfig {
                domain: cert_config.domain.clone(),
                acme_type: cert_config.acme_type,
                certs: None,
                key: None,
                data: cert_config.data.clone(),
            });
        }
    }
    Ok(cert_list)
}

#[derive(Clone)]
pub struct TlsStackContext {
    pub servers: ServerManagerRef,
    pub tunnel_manager: TunnelManager,
    pub limiter_manager: LimiterManagerRef,
    pub stat_manager: StatManagerRef,
    pub acme_manager: AcmeCertManagerRef,
    pub self_cert_mgr: SelfCertMgrRef,
    pub global_process_chains: Option<GlobalProcessChainsRef>,
    pub global_collection_manager: Option<GlobalCollectionManagerRef>,
    pub js_externals: Option<JsExternalsManagerRef>,
}

impl TlsStackContext {
    pub fn new(
        servers: ServerManagerRef,
        tunnel_manager: TunnelManager,
        limiter_manager: LimiterManagerRef,
        stat_manager: StatManagerRef,
        acme_manager: AcmeCertManagerRef,
        self_cert_mgr: SelfCertMgrRef,
        global_process_chains: Option<GlobalProcessChainsRef>,
        global_collection_manager: Option<GlobalCollectionManagerRef>,
        js_externals: Option<JsExternalsManagerRef>,
    ) -> Self {
        Self {
            servers,
            tunnel_manager,
            limiter_manager,
            stat_manager,
            acme_manager,
            self_cert_mgr,
            global_process_chains,
            global_collection_manager,
            js_externals,
        }
    }
}

impl StackContext for TlsStackContext {
    fn stack_protocol(&self) -> StackProtocol {
        StackProtocol::Tls
    }
}

struct TlsConnectionHandler {
    env: Arc<TlsStackContext>,
    executor: ProcessChainLibExecutor,
    connection_manager: Option<ConnectionManagerRef>,
    certs: Arc<dyn ResolvesServerCert>,
    alpn_protocols: Vec<Vec<u8>>,
    io_dump: Option<IoDumpStackConfig>,
}

impl TlsConnectionHandler {
    async fn create(
        hook_point: ProcessChainConfigs,
        certs: Vec<TlsDomainConfig>,
        alpn_protocols: Vec<Vec<u8>>,
        env: Arc<TlsStackContext>,
        connection_manager: Option<ConnectionManagerRef>,
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
            .map_err(into_stack_err!(StackErrorCode::ProcessChainError))?;
        let certs = Self::build_cert_resolver(certs, env.as_ref())?;
        Ok(Self {
            env,
            executor,
            connection_manager,
            certs,
            alpn_protocols,
            io_dump,
        })
    }

    async fn rebuild_with_hook_point(
        &self,
        hook_point: ProcessChainConfigs,
    ) -> StackResult<Self> {
        let (executor, _) = create_process_chain_executor(
            &hook_point,
            self.env.global_process_chains.clone(),
            self.env.global_collection_manager.clone(),
            Some(get_external_commands(Arc::downgrade(&self.env.servers))),
            self.env.js_externals.clone(),
        )
            .await
            .map_err(into_stack_err!(StackErrorCode::ProcessChainError))?;
        Ok(Self {
            env: self.env.clone(),
            executor,
            connection_manager: self.connection_manager.clone(),
            certs: self.certs.clone(),
            alpn_protocols: self.alpn_protocols.clone(),
            io_dump: self.io_dump.clone(),
        })
    }

    fn build_cert_resolver(
        certs: Vec<TlsDomainConfig>,
        env: &TlsStackContext,
    ) -> StackResult<Arc<dyn ResolvesServerCert>> {
        let crypto_provider = rustls::crypto::ring::default_provider();
        let external_resolver = Some(env.acme_manager.clone() as Arc<dyn ResolvesServerCert>);
        let cert_resolver = Arc::new(ResolvesServerCertUsingSni::new(external_resolver));
        let mut self_cert = false;
        for cert_config in certs.into_iter() {
            if cert_config.domain == "*" {
                self_cert = true;
                continue;
            }
            if let (Some(certs), Some(key)) = (cert_config.certs, cert_config.key) {
                let cert_key = CertifiedKey::from_der(certs, key, &crypto_provider)
                    .map_err(into_stack_err!(StackErrorCode::InvalidTlsCert, "parse {} cert failed", cert_config.domain))?;
                cert_resolver
                    .add(&cert_config.domain, cert_key)
                    .map_err(|e| stack_err!(StackErrorCode::InvalidConfig, "add {} cert failed.err {}", cert_config.domain, e))?;
            } else {
                env.acme_manager
                    .add_acme_item(AcmeItem::new(
                        cert_config.domain,
                        cert_config.acme_type.unwrap_or(ChallengeType::TlsAlpn01),
                        cert_config.data,
                    ))
                    .map_err(|e| stack_err!(StackErrorCode::InvalidConfig, "{e}"))?;
            }
        }
        let cert: Arc<dyn ResolvesServerCert> = if self_cert {
            Arc::new(TlsCertResolver::new(cert_resolver, Some(env.self_cert_mgr.clone())))
        } else {
            cert_resolver
        };
        Ok(cert)
    }

    async fn handle_connect(
        &self,
        mut stream: StatStream<TcpStream>,
        local_addr: SocketAddr,
        compose_stat: MutComposedSpeedStatRef,
    ) -> StackResult<()> {
        let servers = self.env.servers.clone();
        let executor = self.executor.fork();
        let remote_addr = stream
            .raw_stream()
            .peer_addr()
            .map_err(into_stack_err!(StackErrorCode::ServerError, "read remote addr failed"))?;

        let mut server_config = ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
            .with_protocol_versions(rustls::DEFAULT_VERSIONS)
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(self.certs.clone());
        server_config.alpn_protocols = self.alpn_protocols.clone();
        server_config.alpn_protocols.push(ACME_TLS_ALPN_NAME.to_vec());

        let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));
        let tls_stream = tls_acceptor
            .accept(stream)
            .await
            .map_err(into_stack_err!(StackErrorCode::StreamError))?;
        {
            let (_, conn) = tls_stream.get_ref();
            if let Some(alpn) = conn.alpn_protocol() {
                if alpn == ACME_TLS_ALPN_NAME {
                    return Ok(());
                }
            }
        }
        let server_name = {
            let (_, conn) = tls_stream.get_ref();
            conn.server_name().map(|s| s.to_string())
        };
        if server_name.is_none() {
            return Ok(());
        }
        log::info!("accept tls stream from {} to {} name {}", remote_addr, local_addr, server_name.as_ref().unwrap_or(&"".to_string()));
        let request_stream: Box<dyn buckyos_kit::AsyncStream> = if let Some(io_dump) = self.io_dump.clone() {
            Box::new(DumpStream::new(
                tls_stream,
                io_dump,
                remote_addr.to_string(),
                local_addr.to_string(),
            ))
        } else {
            Box::new(tls_stream)
        };
        let mut request = StreamRequest::new(request_stream, local_addr);
        request.source_addr = Some(remote_addr);
        request.dest_host = server_name;
        if let Some(device_info) = self
            .connection_manager
            .as_ref()
            .and_then(|manager| manager.get_device_info_by_source(remote_addr.ip()))
        {
            request.source_mac = device_info.mac().map(|v| v.to_string());
            request.source_hostname = device_info.hostname().map(|v| v.to_string());
        }
        let global_env = executor.global_env().clone();
        let (ret, stream) = execute_stream_chain(executor, request)
            .await
            .map_err(into_stack_err!(StackErrorCode::ProcessChainError))?;
        let conn_src_addr = Some(remote_addr.to_string());
        let real_src_addr = get_source_addr_from_req_env(&global_env)
            .await
            .and_then(|addr| addr.parse::<SocketAddr>().ok().map(|_| addr));
        let mut stream_info = StreamInfo::with_addrs(conn_src_addr, real_src_addr);
        if let Some(device_info) = self
            .connection_manager
            .as_ref()
            .and_then(|manager| manager.get_device_info_by_source(remote_addr.ip()))
        {
            stream_info = stream_info.with_device_info(
                device_info.mac().map(|v| v.to_string()),
                device_info.hostname().map(|v| v.to_string()),
            );
        }
        if ret.is_control() {
            if ret.is_drop() {
                return Ok(());
            } else if ret.is_reject() {
                return Ok(());
            }

            if let Some(CommandControl::Return(ret)) = ret.as_control() {
                if let Some(list) = shlex::split(ret.value.as_str()) {
                    if list.is_empty() {
                        return Ok(());
                    }

                    let (limiter_id, down_speed, up_speed) = get_limit_info(global_env.clone()).await?;
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

                    let stat_group_ids = get_stat_info(global_env).await?;
                    let speed_groups = self.env.stat_manager.get_speed_stats(stat_group_ids.as_slice());
                    compose_stat.set_external_stats(speed_groups);

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
                            let stream = if limiter.is_some() {
                                let (read_limit, write_limit) = limiter.as_ref().unwrap().new_limit_session();
                                let limit_stream = LimitStream::new(stream, read_limit, write_limit);
                                Box::new(limit_stream)
                            } else {
                                stream
                            };
                            stream_forward(stream, target, &self.env.tunnel_manager).await?;
                        }
                        "server" => {
                            if list.len() < 2 {
                                return Err(stack_err!(
                                    StackErrorCode::InvalidConfig,
                                    "invalid server command"
                                ));
                            }
                            let server_name = list[1].as_str();

                            let stream = if limiter.is_some() {
                                let (read_limit, write_limit) = limiter.as_ref().unwrap().new_limit_session();
                                let limit_stream = LimitStream::new(stream, read_limit, write_limit);
                                Box::new(limit_stream)
                            } else {
                                stream
                            };

                            if let Some(server) = servers.get_server(server_name) {
                                match server {
                                    Server::Http(http_server) => {
                                        if let Err(e) = hyper_serve_http(stream,
                                                                         http_server,
                                                                         stream_info.clone()).await {
                                            log::error!("hyper serve http failed: {}", e);
                                        }
                                    }
                                    Server::Stream(server) => {
                                        server
                                            .serve_connection(stream, stream_info.clone())
                                            .await
                                            .map_err(into_stack_err!(StackErrorCode::InvalidConfig))?;
                                    }
                                    _ => {
                                        return Err(stack_err!(StackErrorCode::InvalidConfig, "unsupported server type"));
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

pub struct TlsStack {
    id: String,
    bind_addr: String,
    connection_manager: Option<ConnectionManagerRef>,
    handler: Arc<RwLock<Arc<TlsConnectionHandler>>>,
    prepare_handler: Arc<RwLock<Option<Arc<TlsConnectionHandler>>>>,
    handle: Mutex<Option<JoinHandle<()>>>,
}

impl Drop for TlsStack {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.lock().unwrap().take() {
            handle.abort();
        }
    }
}

impl TlsStack {
    pub fn builder() -> TlsStackBuilder {
        TlsStackBuilder::new()
    }

    async fn create(config: TlsStackBuilder) -> StackResult<Self> {
        if config.id.is_none() {
            return Err(stack_err!(
                StackErrorCode::InvalidConfig,
                "id is required"
            ));
        }
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
        if config.stack_context.is_none() {
            return Err(stack_err!(
                StackErrorCode::InvalidConfig,
                "stack_context is required"
            ));
        }

        let id = config.id.unwrap();
        let bind_addr = config.bind.unwrap();
        let env = config.stack_context.unwrap();
        let handler = TlsConnectionHandler::create(
            config.hook_point.unwrap(),
            config.certs,
            config.alpn_protocols,
            env,
            config.connection_manager.clone(),
            config.io_dump,
        )
            .await?;

        Ok(Self {
            id,
            bind_addr,
            connection_manager: config.connection_manager,
            handler: Arc::new(RwLock::new(Arc::new(handler))),
            prepare_handler: Arc::new(Default::default()),
            handle: Mutex::new(None),
        })
    }

    async fn start_listener(&self) -> StackResult<JoinHandle<()>> {
        let bind_addr = self.bind_addr.clone();
        let listener = tokio::net::TcpListener::bind(bind_addr.as_str())
            .await
            .map_err(into_stack_err!(StackErrorCode::BindFailed, "bind address:{}", bind_addr))?;
        let handler = self.handler.clone();
        let connection_manager = self.connection_manager.clone();
        let handle = tokio::spawn(async move {
            loop {
                let (stream, remote_addr) = match listener.accept().await {
                    Ok(s) => s,
                    Err(e) => {
                        log::error!("accept tcp stream failed: {}", e);
                        continue;
                    }
                };

                let local_addr = match stream.local_addr() {
                    Ok(addr) => addr,
                    Err(e) => {
                        log::error!("get remote addr failed: {}", e);
                        continue;
                    }
                };

                log::info!("accept tcp stream from {} to {}", remote_addr, local_addr);
                let compose_stat = MutComposedSpeedStat::new();
                let stat_stream = StatStream::new_with_tracker(stream, compose_stat.clone());
                let speed = stat_stream.get_speed_stat();
                let handler_snapshot = {
                    let handler = handler.read().unwrap();
                    handler.clone()
                };
                let handle = tokio::spawn(async move {
                    if let Err(e) =
                        handler_snapshot.handle_connect(stat_stream, local_addr, compose_stat).await
                    {
                        log::error!("handle tcp stream failed: {}", e);
                    }
                });

                if let Some(connection_manager) = &connection_manager {
                    let controller = HandleConnectionController::new(handle);
                    connection_manager.add_connection(ConnectionInfo::new(remote_addr.to_string(), local_addr.to_string(), StackProtocol::Tls, speed, controller));
                }
            }
        });
        Ok(handle)
    }
}

#[async_trait::async_trait]
impl Stack for TlsStack {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn stack_protocol(&self) -> StackProtocol {
        StackProtocol::Tls
    }

    fn get_bind_addr(&self) -> String {
        self.bind_addr.clone()
    }

    async fn start(&self) -> StackResult<()> {
        {
            if self.handle.lock().unwrap().is_some() {
                return Ok(());
            }
        }
        let handle = self.start_listener().await?;
        *self.handle.lock().unwrap() = Some(handle);
        Ok(())
    }

    async fn prepare_update(&self, config: Arc<dyn StackConfig>, context: Option<Arc<dyn StackContext>>) -> StackResult<()> {
        let config = config.as_ref().as_any().downcast_ref::<TlsStackConfig>()
            .ok_or(stack_err!(StackErrorCode::InvalidConfig, "invalid tls stack config"))?;
        if config.id != self.id {
            return Err(stack_err!(StackErrorCode::InvalidConfig, "id unmatch"));
        }
        if config.bind.to_string() != self.bind_addr {
            return Err(stack_err!(StackErrorCode::BindUnmatched, "bind unmatch"));
        }

        let env = match context {
            Some(context) => {
                let tls_context = context.as_ref().as_any().downcast_ref::<TlsStackContext>()
                    .ok_or(stack_err!(StackErrorCode::InvalidConfig, "invalid tls stack context"))?;
                Arc::new(tls_context.clone())
            }
            None => self.handler.read().unwrap().env.clone(),
        };

        let certs = build_tls_domain_configs(&config.certs).await?;
        let alpn_protocols = config
            .alpn_protocols
            .clone()
            .unwrap_or_else(|| vec!["http/1.1".to_string()])
            .iter()
            .map(|s| s.as_bytes().to_vec())
            .collect();

        let new_handler = TlsConnectionHandler::create(
            config.hook_point.clone(),
            certs,
            alpn_protocols,
            env,
            self.connection_manager.clone(),
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
        )
            .await?;

        *self.prepare_handler.write().unwrap() = Some(Arc::new(new_handler));
        Ok(())
    }

    async fn commit_update(&self) {
        if let Some(handler) = self.prepare_handler.write().unwrap().take() {
            *self.handler.write().unwrap() = handler;
        }
    }

    async fn rollback_update(&self) {
        self.prepare_handler.write().unwrap().take();
    }
}

pub struct TlsDomainConfig {
    pub domain: String,
    pub acme_type: Option<ChallengeType>,
    pub certs: Option<Vec<CertificateDer<'static>>>,
    pub key: Option<PrivateKeyDer<'static>>,
    pub data: Option<serde_json::Value>,
}

// 为TlsDomainConfig实现Clone trait
impl Clone for TlsDomainConfig {
    fn clone(&self) -> Self {
        Self {
            domain: self.domain.clone(),
            acme_type: self.acme_type.clone(),
            certs: self.certs.clone(),
            key: match &self.key {
                None => None,
                Some(PrivateKeyDer::Pkcs8(key)) => Some(PrivateKeyDer::Pkcs8(key.clone_key())),
                Some(PrivateKeyDer::Pkcs1(key)) => Some(PrivateKeyDer::Pkcs1(key.clone_key())),
                Some(PrivateKeyDer::Sec1(key)) => Some(PrivateKeyDer::Sec1(key.clone_key())),
                Some(_) => panic!("Unsupported key type"),
            },
            data: self.data.clone(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct TlsStackConfig {
    pub id: String,
    pub protocol: StackProtocol,
    pub bind: std::net::SocketAddr,
    pub hook_point: Vec<crate::ProcessChainConfig>,
    pub certs: Vec<StackCertConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub concurrency: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alpn_protocols: Option<Vec<String>>,
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

impl crate::StackConfig for TlsStackConfig {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn stack_protocol(&self) -> StackProtocol {
        StackProtocol::Tls
    }

    fn get_config_json(&self) -> String {
        serde_json::to_string(self).unwrap()
    }
}

pub struct TlsStackFactory {
    connection_manager: ConnectionManagerRef,
}

impl TlsStackFactory {
    pub fn new(
        connection_manager: ConnectionManagerRef,
    ) -> Self {
        Self {
            connection_manager,
        }
    }
}

#[async_trait::async_trait]
impl crate::StackFactory for TlsStackFactory {
    async fn create(
        &self,
        config: Arc<dyn crate::StackConfig>,
        context: Arc<dyn crate::StackContext>,
    ) -> crate::StackResult<crate::StackRef> {
        let config = config
            .as_any()
            .downcast_ref::<TlsStackConfig>()
            .ok_or(stack_err!(StackErrorCode::InvalidConfig, "invalid tls stack config"))?;

        let cert_list = build_tls_domain_configs(&config.certs).await?;

        let stack_context = context
            .as_ref()
            .as_any()
            .downcast_ref::<TlsStackContext>()
            .ok_or(stack_err!(StackErrorCode::InvalidConfig, "invalid tls stack context"))?;
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

        let stack = TlsStack::builder()
            .id(config.id.clone())
            .bind(config.bind.to_string())
            .connection_manager(self.connection_manager.clone())
            .hook_point(config.hook_point.clone())
            .add_certs(cert_list)
            .concurrency(config.concurrency.unwrap_or(0))
            .alpn_protocols(config.alpn_protocols.clone().unwrap_or(vec!["http/1.1".to_string()]).iter().map(|s| s.as_bytes().to_vec()).collect())
            .stack_context(stack_context)
            .io_dump(io_dump)
            .build()
            .await?;
        Ok(Arc::new(stack))
    }
}

pub struct TlsStackBuilder {
    id: Option<String>,
    bind: Option<String>,
    hook_point: Option<ProcessChainConfigs>,
    certs: Vec<TlsDomainConfig>,
    concurrency: u32,
    connection_manager: Option<ConnectionManagerRef>,
    alpn_protocols: Vec<Vec<u8>>,
    stack_context: Option<Arc<TlsStackContext>>,
    io_dump: Option<IoDumpStackConfig>,
}

impl TlsStackBuilder {
    fn new() -> Self {
        Self {
            id: None,
            bind: None,
            hook_point: None,
            certs: vec![],
            concurrency: 0,
            connection_manager: None,
            alpn_protocols: vec![],
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

    pub fn add_certs(mut self, certs: Vec<TlsDomainConfig>) -> Self {
        self.certs.extend(certs);
        self
    }

    pub fn hook_point(mut self, hook_point: ProcessChainConfigs) -> Self {
        self.hook_point = Some(hook_point);
        self
    }

    pub fn connection_manager(mut self, connection_manager: ConnectionManagerRef) -> Self {
        self.connection_manager = Some(connection_manager);
        self
    }

    pub fn stack_context(mut self, stack_context: Arc<TlsStackContext>) -> Self {
        self.stack_context = Some(stack_context);
        self
    }

    pub fn concurrency(mut self, concurrency: u32) -> Self {
        if concurrency == 0 {
            self.concurrency = u32::MAX;
        } else {
            self.concurrency = concurrency;
        }
        self
    }

    pub fn alpn_protocols(mut self, alpn_protocols: Vec<Vec<u8>>) -> Self {
        self.alpn_protocols = alpn_protocols;
        self
    }

    pub fn io_dump(mut self, io_dump: Option<IoDumpStackConfig>) -> Self {
        self.io_dump = io_dump;
        self
    }

    pub async fn build(self) -> StackResult<TlsStack> {
        let stack = TlsStack::create(self).await?;
        Ok(stack)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{load_certs, load_key};
    use crate::global_process_chains::GlobalProcessChains;
    use crate::{create_io_dump_stack_config, decode_io_dump_frames, ProcessChainConfigs, ServerResult, StreamServer, ServerManager, TunnelManager, Server, ProcessChainHttpServer, Stack, TlsStackFactory, ConnectionManager, TlsStackConfig, StackProtocol, StackFactory, StreamInfo, DefaultLimiterManager, StatManager, GlobalCollectionManager};
    use crate::{LimiterManagerRef, ServerManagerRef, StackContext, StatManagerRef, TlsDomainConfig, TlsStack, TlsStackContext};
    use buckyos_kit::{init_logging, AsyncStream};
    use name_lib::{encode_ed25519_sk_to_pk_jwk, generate_ed25519_key, DeviceConfig};
    use rcgen::{generate_simple_self_signed, BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{
        CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime,
    };
    use rustls::{ClientConfig, DigitallySignedStruct, Error, RootCertStore, ServerConfig, SignatureScheme};
    use std::sync::Arc;
    use std::time::Duration;
    use http_body_util::Full;
    use hyper::body::Bytes;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use tempfile::tempdir;
    use tokio::fs;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::{TlsAcceptor, TlsConnector};
    use cyfs_acme::{AcmeCertManager, AcmeCertManagerRef, CertManagerConfig};
    use crate::self_cert_mgr::{SelfCertConfig, SelfCertMgr, SelfCertMgrRef};

    async fn wait_dump_frames(file: &std::path::Path, min_frames: usize) -> Vec<crate::DecodedIoDumpFrame> {
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

    fn build_stack_context(
        servers: ServerManagerRef,
        tunnel_manager: TunnelManager,
        limiter_manager: LimiterManagerRef,
        stat_manager: StatManagerRef,
        acme_manager: AcmeCertManagerRef,
        self_cert_mgr: SelfCertMgrRef,
        global_process_chains: Option<Arc<GlobalProcessChains>>,
    ) -> Arc<TlsStackContext> {
        Arc::new(TlsStackContext::new(
            servers,
            tunnel_manager,
            limiter_manager,
            stat_manager,
            acme_manager,
            self_cert_mgr,
            global_process_chains,
            None,
            None,
        ))
    }

    #[tokio::test]
    async fn test_tls_stack_creation() {
        let subject_alt_names = vec!["www.buckyos.com".to_string(), "127.0.0.1".to_string()];
        let cert_key = generate_simple_self_signed(subject_alt_names).unwrap();
        let result = TlsStack::builder().build().await;
        assert!(result.is_err());
        let result = TlsStack::builder().bind("127.0.0.1:9080").build().await;
        assert!(result.is_err());
        let result = TlsStack::builder()
            .id("test")
            .bind("127.0.0.1:9080")
            .stack_context(build_stack_context(
                Arc::new(ServerManager::new()),
                TunnelManager::new(),
                Arc::new(DefaultLimiterManager::new()),
                StatManager::new(),
                AcmeCertManager::create(CertManagerConfig::default()).await.unwrap(),
                SelfCertMgr::create(SelfCertConfig::default()).await.unwrap(),
                None,
            ))
            .build()
            .await;
        assert!(result.is_err());
        let result = TlsStack::builder()
            .id("test")
            .bind("127.0.0.1:9080")
            .hook_point(vec![])
            .stack_context(build_stack_context(
                Arc::new(ServerManager::new()),
                TunnelManager::new(),
                Arc::new(DefaultLimiterManager::new()),
                StatManager::new(),
                AcmeCertManager::create(CertManagerConfig::default()).await.unwrap(),
                SelfCertMgr::create(SelfCertConfig::default()).await.unwrap(),
                None,
            ))
            .build()
            .await;
        assert!(result.is_ok());
        let result = TlsStack::builder()
            .id("test")
            .bind("127.0.0.1:9080")
            .hook_point(vec![])
            .add_certs(vec![TlsDomainConfig {
                domain: "www.buckyos.com".to_string(),
                acme_type: None,
                certs: Some(vec![cert_key.cert.der().clone()]),
                key: Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    cert_key.signing_key.serialize_der()),
                )),
                data: None,
            }])
            .stack_context(build_stack_context(
                Arc::new(ServerManager::new()),
                TunnelManager::new(),
                Arc::new(DefaultLimiterManager::new()),
                StatManager::new(),
                AcmeCertManager::create(CertManagerConfig::default()).await.unwrap(),
                SelfCertMgr::create(SelfCertConfig::default()).await.unwrap(),
                Some(Arc::new(GlobalProcessChains::new())),
            ))
            .build()
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_tls_stack_reject() {
        let subject_alt_names = vec!["www.buckyos.com".to_string(), "127.0.0.1".to_string()];
        let cert_key = generate_simple_self_signed(subject_alt_names).unwrap();
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        reject;
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let result = TlsStack::builder()
            .id("test")
            .bind("127.0.0.1:9080")
            .hook_point(chains)
            .add_certs(vec![TlsDomainConfig {
                domain: "www.buckyos.com".to_string(),
                acme_type: None,
                certs: Some(vec![cert_key.cert.der().clone()]),
                key: Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    cert_key.signing_key.serialize_der()),
                )),
                data: None,
            }])
            .alpn_protocols(vec![b"http/1.1".to_vec(), b"h2".to_vec(), b"h3".to_vec()])
            .stack_context(build_stack_context(
                Arc::new(ServerManager::new()),
                TunnelManager::new(),
                Arc::new(DefaultLimiterManager::new()),
                StatManager::new(),
                AcmeCertManager::create(CertManagerConfig::default()).await.unwrap(),
                SelfCertMgr::create(SelfCertConfig::default()).await.unwrap(),
                Some(Arc::new(GlobalProcessChains::new())),
            ))
            .build()
            .await;
        assert!(result.is_ok());
        let stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());

        let config = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(rustls::DEFAULT_VERSIONS).unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();

        let stream = TcpStream::connect("127.0.0.1:9080").await.unwrap();
        let connector = TlsConnector::from(Arc::new(config));
        let mut stream = connector
            .connect(ServerName::try_from("www.buckyos.com").unwrap(), stream)
            .await
            .unwrap();
        let result = stream
            .write_all(b"GET / HTTP/1.1\r\nHost: httpbin.org\r\n\r\n")
            .await;
        assert!(result.is_ok());
        let ret = stream.read(&mut [0; 1024]).await;
        assert!(ret.is_err());
    }

    #[tokio::test]
    async fn test_tls_stack_drop() {
        let subject_alt_names = vec!["www.buckyos.com".to_string(), "127.0.0.1".to_string()];
        let cert_key = generate_simple_self_signed(subject_alt_names).unwrap();
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        drop;
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let result = TlsStack::builder()
            .id("test")
            .bind("127.0.0.1:9081")
            .hook_point(chains)
            .add_certs(vec![TlsDomainConfig {
                domain: "www.buckyos.com".to_string(),
                acme_type: None,
                certs: Some(vec![cert_key.cert.der().clone()]),
                key: Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    cert_key.signing_key.serialize_der()),
                )),
                data: None,
            }])
            .alpn_protocols(vec![b"http/1.1".to_vec(), b"h2".to_vec(), b"h3".to_vec()])
            .stack_context(build_stack_context(
                Arc::new(ServerManager::new()),
                TunnelManager::new(),
                Arc::new(DefaultLimiterManager::new()),
                StatManager::new(),
                AcmeCertManager::create(CertManagerConfig::default()).await.unwrap(),
                SelfCertMgr::create(SelfCertConfig::default()).await.unwrap(),
                Some(Arc::new(GlobalProcessChains::new())),
            ))
            .build()
            .await;
        assert!(result.is_ok());
        let stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());

        let config = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(rustls::DEFAULT_VERSIONS).unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();

        let stream = TcpStream::connect("127.0.0.1:9081").await.unwrap();
        let connector = TlsConnector::from(Arc::new(config));
        let mut stream = connector
            .connect(ServerName::try_from("www.buckyos.com").unwrap(), stream)
            .await
            .unwrap();
        let result = stream
            .write_all(b"GET / HTTP/1.1\r\nHost: httpbin.org\r\n\r\n")
            .await;
        assert!(result.is_ok());
        let ret = stream.read(&mut [0; 1024]).await;
        assert!(ret.is_err());
    }

    #[tokio::test]
    async fn test_tls_stack_forward() {
        let subject_alt_names = vec!["www.buckyos.com".to_string(), "127.0.0.1".to_string()];
        let cert_key = generate_simple_self_signed(subject_alt_names).unwrap();
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "forward tcp:///127.0.0.1:9083";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let connection_manager = ConnectionManager::new();
        let result = TlsStack::builder()
            .id("test")
            .bind("127.0.0.1:9091")
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .add_certs(vec![TlsDomainConfig {
                domain: "www.buckyos.com".to_string(),
                acme_type: None,
                certs: Some(vec![cert_key.cert.der().clone()]),
                key: Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    cert_key.signing_key.serialize_der()),
                )),
                data: None,
            }])
            .alpn_protocols(vec![b"http/1.1".to_vec(), b"h2".to_vec(), b"h3".to_vec()])
            .stack_context(build_stack_context(
                Arc::new(ServerManager::new()),
                TunnelManager::new(),
                Arc::new(DefaultLimiterManager::new()),
                StatManager::new(),
                AcmeCertManager::create(CertManagerConfig::default()).await.unwrap(),
                SelfCertMgr::create(SelfCertConfig::default()).await.unwrap(),
                Some(Arc::new(GlobalProcessChains::new())),
            ))
            .build()
            .await;
        assert!(result.is_ok());
        let stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());

        tokio::spawn(async move {
            let tcp_listener = TcpListener::bind("127.0.0.1:9083").await.unwrap();
            if let Ok((mut tcp_stream, _)) = tcp_listener.accept().await {
                let mut buf = [0u8; 4];
                tcp_stream.read_exact(&mut buf).await.unwrap();
                assert_eq!(&buf, b"test");
                tcp_stream.write_all("recv".as_bytes()).await.unwrap();
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        });

        tokio::time::sleep(Duration::from_secs(1)).await;

        let config = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(rustls::DEFAULT_VERSIONS).unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();

        {
            let stream = TcpStream::connect("127.0.0.1:9091").await.unwrap();
            let connector = TlsConnector::from(Arc::new(config));
            let mut stream = connector
                .connect(ServerName::try_from("www.buckyos.com").unwrap(), stream)
                .await
                .unwrap();
            let result = stream
                .write_all(b"test")
                .await;
            assert_eq!(connection_manager.get_all_connection_info().len(), 1);
            assert!(result.is_ok());
            let mut buf = [0u8; 4];
            let ret = stream.read_exact(&mut buf).await;
            assert!(ret.is_ok());
            assert_eq!(b"recv", &buf[..ret.unwrap()]);
            stream.shutdown().await.unwrap();
        }
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        assert_eq!(connection_manager.get_all_connection_info().len(), 0);
    }

    #[tokio::test]
    async fn test_tls_stack_forward_err() {
        let subject_alt_names = vec!["www.buckyos.com".to_string(), "127.0.0.1".to_string()];
        let cert_key = generate_simple_self_signed(subject_alt_names).unwrap();
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "forward tcp:///127.0.0.1:19083";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let connection_manager = ConnectionManager::new();
        let result = TlsStack::builder()
            .id("test")
            .bind("127.0.0.1:9093")
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .add_certs(vec![TlsDomainConfig {
                domain: "www.buckyos.com".to_string(),
                acme_type: None,
                certs: Some(vec![cert_key.cert.der().clone()]),
                key: Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    cert_key.signing_key.serialize_der()),
                )),
                data: None,
            }])
            .alpn_protocols(vec![b"http/1.1".to_vec(), b"h2".to_vec(), b"h3".to_vec()])
            .stack_context(build_stack_context(
                Arc::new(ServerManager::new()),
                TunnelManager::new(),
                Arc::new(DefaultLimiterManager::new()),
                StatManager::new(),
                AcmeCertManager::create(CertManagerConfig::default()).await.unwrap(),
                SelfCertMgr::create(SelfCertConfig::default()).await.unwrap(),
                Some(Arc::new(GlobalProcessChains::new())),
            ))
            .build()
            .await;
        assert!(result.is_ok());
        let stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());

        tokio::time::sleep(Duration::from_secs(1)).await;

        let config = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(rustls::DEFAULT_VERSIONS).unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();

        let stream = TcpStream::connect("127.0.0.1:9093").await.unwrap();
        let connector = TlsConnector::from(Arc::new(config));
        let mut stream = connector
            .connect(ServerName::try_from("www.buckyos.com").unwrap(), stream)
            .await
            .unwrap();
        let result = stream
            .write_all(b"test")
            .await;
        assert!(result.is_ok());
        let mut buf = [0u8; 4];
        let ret = stream.read_exact(&mut buf).await;
        assert!(ret.is_err());
    }

    #[tokio::test]
    async fn test_tls_stack_self_cert() {
        init_logging("test", false);
        let _subject_alt_names = vec!["www.buckyos.com".to_string(), "127.0.0.1".to_string()];
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "forward tcp:///127.0.0.1:9088";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let tls_self_certs_path = tempfile::env::temp_dir().join("tls_self_certs").to_string_lossy().to_string();
        let mut self_cert_config = SelfCertConfig::default();
        self_cert_config.store_path = tls_self_certs_path.clone();
        let connection_manager = ConnectionManager::new();
        let result = TlsStack::builder()
            .id("test")
            .bind("127.0.0.1:9096")
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .add_certs(vec![TlsDomainConfig {
                domain: "*".to_string(),
                acme_type: None,
                certs: None,
                key: None,
                data: None,
            }])
            .alpn_protocols(vec![b"http/1.1".to_vec(), b"h2".to_vec(), b"h3".to_vec()])
            .stack_context(build_stack_context(
                Arc::new(ServerManager::new()),
                TunnelManager::new(),
                Arc::new(DefaultLimiterManager::new()),
                StatManager::new(),
                AcmeCertManager::create(CertManagerConfig::default()).await.unwrap(),
                SelfCertMgr::create(self_cert_config).await.unwrap(),
                Some(Arc::new(GlobalProcessChains::new())),
            ))
            .build()
            .await;
        assert!(result.is_ok());
        let stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());

        tokio::spawn(async move {
            let tcp_listener = TcpListener::bind("127.0.0.1:9088").await.unwrap();
            if let Ok((mut tcp_stream, _)) = tcp_listener.accept().await {
                let mut buf = [0u8; 4];
                tcp_stream.read_exact(&mut buf).await.unwrap();
                assert_eq!(&buf, b"test");
                tcp_stream.write_all("recv".as_bytes()).await.unwrap();
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        });

        tokio::time::sleep(Duration::from_secs(1)).await;

        let config = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(rustls::DEFAULT_VERSIONS).unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();

        {
            let stream = TcpStream::connect("127.0.0.1:9096").await.unwrap();
            let connector = TlsConnector::from(Arc::new(config));
            let mut stream = connector
                .connect(ServerName::try_from("www.buckyos.com").unwrap(), stream)
                .await
                .unwrap();
            let result = stream
                .write_all(b"test")
                .await;
            assert_eq!(connection_manager.get_all_connection_info().len(), 1);
            assert!(result.is_ok());
            let mut buf = [0u8; 4];
            let ret = stream.read_exact(&mut buf).await;
            assert!(ret.is_ok());
            assert_eq!(b"recv", &buf[..ret.unwrap()]);
            stream.shutdown().await.unwrap();
        }
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        assert_eq!(connection_manager.get_all_connection_info().len(), 0);

        tokio::fs::remove_dir_all(tls_self_certs_path).await.unwrap();
    }

    pub struct MockServer {
        id: String,
    }

    impl MockServer {
        pub fn new(id: String) -> Self {
            Self { id }
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
    }
    #[derive(Debug)]
    struct NoVerifier;

    impl ServerCertVerifier for NoVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer,
            _intermediates: &[CertificateDer],
            _server_name: &ServerName,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::RSA_PKCS1_SHA1,
                SignatureScheme::ECDSA_SHA1_Legacy,
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::RSA_PKCS1_SHA512,
                SignatureScheme::ECDSA_NISTP521_SHA512,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
                SignatureScheme::ED25519,
                SignatureScheme::ED448,
            ]
        }
    }

    #[tokio::test]
    async fn test_tls_stack_server() {
        let subject_alt_names = vec!["www.buckyos.com".to_string(), "127.0.0.1".to_string()];
        let cert_key = generate_simple_self_signed(subject_alt_names).unwrap();
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
        let _ = server_manager.add_server(Server::Stream(Arc::new(MockServer::new("www.buckyos.com".to_string()))));
        let result = TlsStack::builder()
            .id("test")
            .bind("127.0.0.1:9085")
            .hook_point(chains)
            .add_certs(vec![TlsDomainConfig {
                domain: "www.buckyos.com".to_string(),
                acme_type: None,
                certs: Some(vec![cert_key.cert.der().clone()]),
                key: Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    cert_key.signing_key.serialize_der()),
                )),
                data: None,
            }])
            .alpn_protocols(vec![b"http/1.1".to_vec(), b"h2".to_vec(), b"h3".to_vec()])
            .stack_context(build_stack_context(
                server_manager,
                TunnelManager::new(),
                Arc::new(DefaultLimiterManager::new()),
                StatManager::new(),
                AcmeCertManager::create(CertManagerConfig::default()).await.unwrap(),
                SelfCertMgr::create(SelfCertConfig::default()).await.unwrap(),
                Some(Arc::new(GlobalProcessChains::new())),
            ))
            .build()
            .await;
        assert!(result.is_ok());
        let stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let config = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(rustls::DEFAULT_VERSIONS).unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();
        let stream = TcpStream::connect("127.0.0.1:9085").await.unwrap();
        let connector = TlsConnector::from(Arc::new(config));
        let mut stream = connector
            .connect(ServerName::try_from("www.buckyos.com").unwrap(), stream)
            .await
            .unwrap();
        let result = stream.write_all(b"test").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 4];
        let ret = stream.read_exact(&mut buf).await;
        assert!(ret.is_ok());
        assert_eq!(&buf, b"recv");
    }

    #[tokio::test]
    async fn test_tls_http1() {
        let subject_alt_names = vec!["www.buckyos.com".to_string(), "127.0.0.1".to_string()];
        let cert_key = generate_simple_self_signed(subject_alt_names).unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        reject;
        "#;
        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let server_mgr = Arc::new(ServerManager::new());
        let http_server = ProcessChainHttpServer::builder()
            .id("www.buckyos.com")
            .version("HTTP/3")
            .h3_port(9186)
            .hook_point(chains)
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .server_mgr(Arc::downgrade(&server_mgr))
            .tunnel_manager(TunnelManager::new())
            .build().await.unwrap();

        let server_manager = Arc::new(ServerManager::new());
        let _ = server_manager.add_server(Server::Http(Arc::new(http_server)));


        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "server www.buckyos.com";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let result = TlsStack::builder()
            .id("test")
            .bind("127.0.0.1:9087")
            .hook_point(chains)
            .add_certs(vec![TlsDomainConfig {
                domain: "www.buckyos.com".to_string(),
                acme_type: None,
                certs: Some(vec![cert_key.cert.der().clone()]),
                key: Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    cert_key.signing_key.serialize_der()),
                )),
                data: None,
            }])
            .alpn_protocols(vec![b"http/1.1".to_vec(), b"h2".to_vec(), b"h3".to_vec()])
            .stack_context(build_stack_context(
                server_manager,
                TunnelManager::new(),
                Arc::new(DefaultLimiterManager::new()),
                StatManager::new(),
                AcmeCertManager::create(CertManagerConfig::default()).await.unwrap(),
                SelfCertMgr::create(SelfCertConfig::default()).await.unwrap(),
                Some(Arc::new(GlobalProcessChains::new())),
            ))
            .build()
            .await;
        assert!(result.is_ok());
        let stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());


        let (signing_key, _pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let _device_config = DeviceConfig::new_by_jwk("test", serde_json::from_value(jwk).unwrap());

        let config = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(rustls::DEFAULT_VERSIONS).unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();
        let stream = TcpStream::connect("127.0.0.1:9087").await.unwrap();
        let connector = TlsConnector::from(Arc::new(config));
        let stream = connector
            .connect(ServerName::try_from("www.buckyos.com").unwrap(), stream)
            .await
            .unwrap();
        let (mut send, conn) = hyper::client::conn::http1::Builder::new()
            .handshake(TokioIo::new(stream)).await.unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });

        let request = http::Request::builder()
            .version(http::Version::HTTP_11)
            .method("GET")
            .uri("https://www.buckyos.com/")
            .body(Full::new(Bytes::new()))
            .unwrap();

        let result = send.send_request(request).await;
        assert!(result.is_ok());
        let resp = result.unwrap();
        assert_eq!(resp.version(), http::Version::HTTP_11);
        let header = resp.headers().get(http::header::ALT_SVC);
        assert!(header.is_some());
        assert_eq!(header.unwrap(), "h3=\":9186\"; ma=86400");
    }

    #[tokio::test]
    async fn test_tls_http2() {
        let subject_alt_names = vec!["www.buckyos.com".to_string(), "127.0.0.1".to_string()];
        let cert_key = generate_simple_self_signed(subject_alt_names).unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        reject;
        "#;
        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let server_mgr = Arc::new(ServerManager::new());
        let http_server = ProcessChainHttpServer::builder()
            .id("www.buckyos.com")
            .version("HTTP/3")
            .h3_port(9186)
            .hook_point(chains)
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .server_mgr(Arc::downgrade(&server_mgr))
            .tunnel_manager(TunnelManager::new())
            .build().await.unwrap();

        let server_manager = Arc::new(ServerManager::new());
        let _ = server_manager.add_server(Server::Http(Arc::new(http_server)));


        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "server www.buckyos.com";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let result = TlsStack::builder()
            .id("test")
            .bind("127.0.0.1:9086")
            .hook_point(chains)
            .add_certs(vec![TlsDomainConfig {
                domain: "www.buckyos.com".to_string(),
                acme_type: None,
                certs: Some(vec![cert_key.cert.der().clone()]),
                key: Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    cert_key.signing_key.serialize_der()),
                )),
                data: None,
            }])
            .alpn_protocols(vec![b"http/1.1".to_vec(), b"h2".to_vec(), b"h3".to_vec()])
            .stack_context(build_stack_context(
                server_manager,
                TunnelManager::new(),
                Arc::new(DefaultLimiterManager::new()),
                StatManager::new(),
                AcmeCertManager::create(CertManagerConfig::default()).await.unwrap(),
                SelfCertMgr::create(SelfCertConfig::default()).await.unwrap(),
                Some(Arc::new(GlobalProcessChains::new())),
            ))
            .build()
            .await;
        assert!(result.is_ok());
        let stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());


        let (signing_key, _pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let _device_config = DeviceConfig::new_by_jwk("test", serde_json::from_value(jwk).unwrap());

        let config = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(rustls::DEFAULT_VERSIONS).unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();
        let stream = TcpStream::connect("127.0.0.1:9086").await.unwrap();
        let connector = TlsConnector::from(Arc::new(config));
        let stream = connector
            .connect(ServerName::try_from("www.buckyos.com").unwrap(), stream)
            .await
            .unwrap();
        let (mut send, conn) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
            .handshake(TokioIo::new(stream)).await.unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });

        let request = http::Request::builder()
            .version(http::Version::HTTP_2)
            .method("GET")
            .uri("https://www.buckyos.com/")
            .body(Full::new(Bytes::new()))
            .unwrap();

        let result = send.send_request(request).await;
        assert!(result.is_ok());
        let resp = result.unwrap();
        assert_eq!(resp.version(), http::Version::HTTP_2);
        let header = resp.headers().get(http::header::ALT_SVC);
        assert!(header.is_some());
        assert_eq!(header.unwrap(), "h3=\":9186\"; ma=86400");
    }

    #[tokio::test]
    async fn test_tls_io_dump_raw_single_roundtrip() {
        let subject_alt_names = vec!["www.buckyos.com".to_string(), "127.0.0.1".to_string()];
        let cert_key = generate_simple_self_signed(subject_alt_names).unwrap();
        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(
            "- id: main\n  priority: 1\n  blocks:\n    - id: main\n      block: |\n        return \"server www.buckyos.com\";\n",
        )
            .unwrap();
        let server_manager = Arc::new(ServerManager::new());
        server_manager
            .add_server(Server::Stream(Arc::new(MockServer::new("www.buckyos.com".to_string()))))
            .unwrap();
        let dir = tempdir().unwrap();
        let dump = dir.path().join("tls_raw.dump");
        let io_dump = create_io_dump_stack_config(
            "tls_raw",
            Some(dump.to_string_lossy().as_ref()),
            None,
            None,
            None,
            None,
        )
            .await
            .unwrap();

        let stack = TlsStack::builder()
            .id("tls-raw")
            .bind("127.0.0.1:9093")
            .hook_point(chains)
            .add_certs(vec![TlsDomainConfig {
                domain: "www.buckyos.com".to_string(),
                acme_type: None,
                certs: Some(vec![cert_key.cert.der().clone()]),
                key: Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    cert_key.signing_key.serialize_der(),
                ))),
                data: None,
            }])
            .stack_context(build_stack_context(
                server_manager,
                TunnelManager::new(),
                Arc::new(DefaultLimiterManager::new()),
                StatManager::new(),
                AcmeCertManager::create(CertManagerConfig::default()).await.unwrap(),
                SelfCertMgr::create(SelfCertConfig::default()).await.unwrap(),
                Some(Arc::new(GlobalProcessChains::new())),
            ))
            .io_dump(io_dump)
            .build()
            .await
            .unwrap();
        stack.start().await.unwrap();

        let config = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(rustls::DEFAULT_VERSIONS)
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();
        let stream = TcpStream::connect("127.0.0.1:9093").await.unwrap();
        let connector = TlsConnector::from(Arc::new(config));
        let mut stream = connector
            .connect(ServerName::try_from("www.buckyos.com").unwrap(), stream)
            .await
            .unwrap();
        stream.write_all(b"test").await.unwrap();
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"recv");
        drop(stream);

        let frames = wait_dump_frames(&dump, 1).await;
        assert!(frames.iter().any(|f| f.upload == b"test" && f.download == b"recv"));
    }

    #[tokio::test]
    async fn test_tls_io_dump_raw_flush_on_upload_limit() {
        let subject_alt_names = vec!["www.buckyos.com".to_string(), "127.0.0.1".to_string()];
        let cert_key = generate_simple_self_signed(subject_alt_names).unwrap();
        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(
            "- id: main\n  priority: 1\n  blocks:\n    - id: main\n      block: |\n        return \"server www.buckyos.com\";\n",
        )
            .unwrap();
        let server_manager = Arc::new(ServerManager::new());
        server_manager
            .add_server(Server::Stream(Arc::new(MockServer::new("www.buckyos.com".to_string()))))
            .unwrap();
        let dir = tempdir().unwrap();
        let dump = dir.path().join("tls_raw_limit.dump");
        let io_dump = create_io_dump_stack_config(
            "tls_raw_limit",
            Some(dump.to_string_lossy().as_ref()),
            None,
            None,
            Some("2B"),
            None,
        )
            .await
            .unwrap();

        let stack = TlsStack::builder()
            .id("tls-raw-limit")
            .bind("127.0.0.1:9095")
            .hook_point(chains)
            .add_certs(vec![TlsDomainConfig {
                domain: "www.buckyos.com".to_string(),
                acme_type: None,
                certs: Some(vec![cert_key.cert.der().clone()]),
                key: Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    cert_key.signing_key.serialize_der(),
                ))),
                data: None,
            }])
            .stack_context(build_stack_context(
                server_manager,
                TunnelManager::new(),
                Arc::new(DefaultLimiterManager::new()),
                StatManager::new(),
                AcmeCertManager::create(CertManagerConfig::default()).await.unwrap(),
                SelfCertMgr::create(SelfCertConfig::default()).await.unwrap(),
                Some(Arc::new(GlobalProcessChains::new())),
            ))
            .io_dump(io_dump)
            .build()
            .await
            .unwrap();
        stack.start().await.unwrap();

        let config = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(rustls::DEFAULT_VERSIONS)
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();
        let stream = TcpStream::connect("127.0.0.1:9095").await.unwrap();
        let connector = TlsConnector::from(Arc::new(config));
        let mut stream = connector
            .connect(ServerName::try_from("www.buckyos.com").unwrap(), stream)
            .await
            .unwrap();
        stream.write_all(b"test").await.unwrap();
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"recv");

        let frames = wait_dump_frames(&dump, 1).await;
        assert!(frames.iter().any(|f| f.upload == b"te" && f.download.is_empty()));
    }

    #[tokio::test]
    async fn test_tls_io_dump_http1_multi_requests_same_connection() {
        let subject_alt_names = vec!["www.buckyos.com".to_string(), "127.0.0.1".to_string()];
        let cert_key = generate_simple_self_signed(subject_alt_names).unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        reject;
        "#;
        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let server_mgr = Arc::new(ServerManager::new());
        let http_server = ProcessChainHttpServer::builder()
            .id("www.buckyos.com")
            .version("HTTP/3")
            .h3_port(9196)
            .hook_point(chains)
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .server_mgr(Arc::downgrade(&server_mgr))
            .tunnel_manager(TunnelManager::new())
            .build().await.unwrap();

        let server_manager = Arc::new(ServerManager::new());
        let _ = server_manager.add_server(Server::Http(Arc::new(http_server)));

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(
            "- id: main\n  priority: 1\n  blocks:\n    - id: main\n      block: |\n        return \"server www.buckyos.com\";\n",
        )
            .unwrap();
        let dir = tempdir().unwrap();
        let dump = dir.path().join("tls_http.dump");
        let io_dump = create_io_dump_stack_config(
            "tls_http",
            Some(dump.to_string_lossy().as_ref()),
            None,
            None,
            None,
            None,
        )
            .await
            .unwrap();
        let stack = TlsStack::builder()
            .id("tls-http")
            .bind("127.0.0.1:9094")
            .hook_point(chains)
            .add_certs(vec![TlsDomainConfig {
                domain: "www.buckyos.com".to_string(),
                acme_type: None,
                certs: Some(vec![cert_key.cert.der().clone()]),
                key: Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    cert_key.signing_key.serialize_der(),
                ))),
                data: None,
            }])
            .alpn_protocols(vec![b"http/1.1".to_vec()])
            .stack_context(build_stack_context(
                server_manager,
                TunnelManager::new(),
                Arc::new(DefaultLimiterManager::new()),
                StatManager::new(),
                AcmeCertManager::create(CertManagerConfig::default()).await.unwrap(),
                SelfCertMgr::create(SelfCertConfig::default()).await.unwrap(),
                Some(Arc::new(GlobalProcessChains::new())),
            ))
            .io_dump(io_dump)
            .build()
            .await
            .unwrap();
        stack.start().await.unwrap();

        let config = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(rustls::DEFAULT_VERSIONS)
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();
        let stream = TcpStream::connect("127.0.0.1:9094").await.unwrap();
        let connector = TlsConnector::from(Arc::new(config));
        let stream = connector
            .connect(ServerName::try_from("www.buckyos.com").unwrap(), stream)
            .await
            .unwrap();
        let (mut send, conn) = hyper::client::conn::http1::Builder::new()
            .handshake(TokioIo::new(stream))
            .await
            .unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });

        for path in ["/a", "/b"] {
            let req = http::Request::builder()
                .version(http::Version::HTTP_11)
                .method("GET")
                .uri(format!("https://www.buckyos.com{path}"))
                .body(Full::new(Bytes::new()))
                .unwrap();
            let resp = send.send_request(req).await.unwrap();
            assert_eq!(resp.version(), http::Version::HTTP_11);
        }

        let frames = wait_dump_frames(&dump, 2).await;
        assert!(frames.iter().any(|f| {
            f.upload.starts_with(b"GET ")
                && f.upload.windows(2).any(|w| w == b"/a")
                && f.download.starts_with(b"HTTP/1.1")
        }));
        assert!(frames.iter().any(|f| {
            f.upload.starts_with(b"GET ")
                && f.upload.windows(2).any(|w| w == b"/b")
                && f.download.starts_with(b"HTTP/1.1")
        }));
    }

    #[tokio::test]
    async fn test_tls_io_dump_http_flush_on_upload_limit() {
        let subject_alt_names = vec!["www.buckyos.com".to_string(), "127.0.0.1".to_string()];
        let cert_key = generate_simple_self_signed(subject_alt_names).unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        reject;
        "#;
        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let server_mgr = Arc::new(ServerManager::new());
        let http_server = ProcessChainHttpServer::builder()
            .id("www.buckyos.com")
            .version("HTTP/3")
            .h3_port(9196)
            .hook_point(chains)
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .server_mgr(Arc::downgrade(&server_mgr))
            .tunnel_manager(TunnelManager::new())
            .build().await.unwrap();

        let server_manager = Arc::new(ServerManager::new());
        let _ = server_manager.add_server(Server::Http(Arc::new(http_server)));

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(
            "- id: main\n  priority: 1\n  blocks:\n    - id: main\n      block: |\n        return \"server www.buckyos.com\";\n",
        )
            .unwrap();
        let dir = tempdir().unwrap();
        let dump = dir.path().join("tls_http_limit.dump");
        let io_dump = create_io_dump_stack_config(
            "tls_http_limit",
            Some(dump.to_string_lossy().as_ref()),
            None,
            None,
            Some("4B"),
            None,
        )
            .await
            .unwrap();
        let stack = TlsStack::builder()
            .id("tls-http-limit")
            .bind("127.0.0.1:9096")
            .hook_point(chains)
            .add_certs(vec![TlsDomainConfig {
                domain: "www.buckyos.com".to_string(),
                acme_type: None,
                certs: Some(vec![cert_key.cert.der().clone()]),
                key: Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    cert_key.signing_key.serialize_der(),
                ))),
                data: None,
            }])
            .alpn_protocols(vec![b"http/1.1".to_vec()])
            .stack_context(build_stack_context(
                server_manager,
                TunnelManager::new(),
                Arc::new(DefaultLimiterManager::new()),
                StatManager::new(),
                AcmeCertManager::create(CertManagerConfig::default()).await.unwrap(),
                SelfCertMgr::create(SelfCertConfig::default()).await.unwrap(),
                Some(Arc::new(GlobalProcessChains::new())),
            ))
            .io_dump(io_dump)
            .build()
            .await
            .unwrap();
        stack.start().await.unwrap();

        let config = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(rustls::DEFAULT_VERSIONS)
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();
        let stream = TcpStream::connect("127.0.0.1:9096").await.unwrap();
        let connector = TlsConnector::from(Arc::new(config));
        let stream = connector
            .connect(ServerName::try_from("www.buckyos.com").unwrap(), stream)
            .await
            .unwrap();
        let (mut send, conn) = hyper::client::conn::http1::Builder::new()
            .handshake(TokioIo::new(stream))
            .await
            .unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });

        let req = http::Request::builder()
            .version(http::Version::HTTP_11)
            .method("GET")
            .uri("https://www.buckyos.com/a")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let resp = send.send_request(req).await.unwrap();
        assert_eq!(resp.version(), http::Version::HTTP_11);

        let frames = wait_dump_frames(&dump, 1).await;
        assert!(frames.iter().any(|f| f.upload == b"GET " && f.download.is_empty()));
    }

    #[tokio::test]
    async fn test_factory() {
        let mut cert_config = CertManagerConfig::default();
        let data_dir = tempfile::tempdir().unwrap();
        cert_config.keystore_path = data_dir.path().to_string_lossy().to_string();
        let cert_manager = AcmeCertManager::create(cert_config).await.unwrap();
        let self_cert_mgr = SelfCertMgr::create(SelfCertConfig::default()).await.unwrap();
        let server_manager = Arc::new(ServerManager::new());
        let global_process_chains = Arc::new(GlobalProcessChains::new());
        let tunnel_manager = TunnelManager::new();
        let limiter_manager = Arc::new(DefaultLimiterManager::new());
        let stat_manager = StatManager::new();
        let collection_manager = GlobalCollectionManager::create(vec![]).await.unwrap();
        let factory = TlsStackFactory::new(ConnectionManager::new());

        let config = TlsStackConfig {
            id: "test".to_string(),
            protocol: StackProtocol::Tls,
            bind: "127.0.0.1:343".parse().unwrap(),
            hook_point: vec![],
            certs: vec![],
            concurrency: None,
            alpn_protocols: None,
            io_dump_file: None,
            io_dump_rotate_size: None,
            io_dump_rotate_max_files: None,
            io_dump_max_upload_bytes_per_conn: None,
            io_dump_max_download_bytes_per_conn: None,
        };
        let stack_context: Arc<dyn StackContext> = Arc::new(TlsStackContext::new(
            server_manager,
            tunnel_manager,
            limiter_manager,
            stat_manager,
            cert_manager,
            self_cert_mgr,
            Some(global_process_chains),
            Some(collection_manager),
            None,
        ));
        let ret = factory.create(Arc::new(config), stack_context).await;
        assert!(ret.is_ok());
    }

    #[tokio::test]
    async fn test_tls_stack_stat_server() {
        let subject_alt_names = vec!["www.buckyos.com".to_string(), "127.0.0.1".to_string()];
        let cert_key = generate_simple_self_signed(subject_alt_names).unwrap();
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        set-stat test;
        return "server www.buckyos.com";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let stat_manager = StatManager::new();
        let server_manager = Arc::new(ServerManager::new());
        server_manager.add_server(Server::Stream(Arc::new(MockServer::new("www.buckyos.com".to_string())))).unwrap();
        let result = TlsStack::builder()
            .id("test")
            .bind("127.0.0.1:9185")
            .hook_point(chains)
            .add_certs(vec![TlsDomainConfig {
                domain: "www.buckyos.com".to_string(),
                acme_type: None,
                certs: Some(vec![cert_key.cert.der().clone()]),
                key: Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    cert_key.signing_key.serialize_der()),
                )),
                data: None,
            }])
            .alpn_protocols(vec![b"http/1.1".to_vec(), b"h2".to_vec(), b"h3".to_vec()])
            .stack_context(build_stack_context(
                server_manager,
                TunnelManager::new(),
                Arc::new(DefaultLimiterManager::new()),
                stat_manager.clone(),
                AcmeCertManager::create(CertManagerConfig::default()).await.unwrap(),
                SelfCertMgr::create(SelfCertConfig::default()).await.unwrap(),
                Some(Arc::new(GlobalProcessChains::new())),
            ))
            .build()
            .await;
        assert!(result.is_ok());
        let stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let config = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(rustls::DEFAULT_VERSIONS).unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();
        let stream = TcpStream::connect("127.0.0.1:9185").await.unwrap();
        let connector = TlsConnector::from(Arc::new(config));
        let mut stream = connector
            .connect(ServerName::try_from("www.buckyos.com").unwrap(), stream)
            .await
            .unwrap();
        let result = stream.write_all(b"test").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 4];
        let ret = stream.read_exact(&mut buf).await;
        assert!(ret.is_ok());
        assert_eq!(&buf, b"recv");

        let test_stat = stat_manager.get_speed_stat("test");
        assert!(test_stat.is_some());
        let test_stat = test_stat.unwrap();
        assert!(test_stat.get_read_sum_size() > 350);
        assert!(test_stat.get_write_sum_size() > 880);
    }

    #[tokio::test]
    async fn test_tls_stack_stat_limiter_server() {
        let subject_alt_names = vec!["www.buckyos.com".to_string(), "127.0.0.1".to_string()];
        let cert_key = generate_simple_self_signed(subject_alt_names).unwrap();
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        set-stat test;
        set-limit "2B/s" "2B/s";
        return "server www.buckyos.com";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let stat_manager = StatManager::new();
        let server_manager = Arc::new(ServerManager::new());
        server_manager.add_server(Server::Stream(Arc::new(MockServer::new("www.buckyos.com".to_string())))).unwrap();
        let result = TlsStack::builder()
            .id("test")
            .bind("127.0.0.1:9186")
            .hook_point(chains)
            .add_certs(vec![TlsDomainConfig {
                domain: "www.buckyos.com".to_string(),
                acme_type: None,
                certs: Some(vec![cert_key.cert.der().clone()]),
                key: Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    cert_key.signing_key.serialize_der()),
                )),
                data: None,
            }])
            .alpn_protocols(vec![b"http/1.1".to_vec(), b"h2".to_vec(), b"h3".to_vec()])
            .stack_context(build_stack_context(
                server_manager,
                TunnelManager::new(),
                Arc::new(DefaultLimiterManager::new()),
                stat_manager.clone(),
                AcmeCertManager::create(CertManagerConfig::default()).await.unwrap(),
                SelfCertMgr::create(SelfCertConfig::default()).await.unwrap(),
                Some(Arc::new(GlobalProcessChains::new())),
            ))
            .build()
            .await;
        assert!(result.is_ok());
        let stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let config = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(rustls::DEFAULT_VERSIONS).unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();
        let stream = TcpStream::connect("127.0.0.1:9186").await.unwrap();
        let start = std::time::Instant::now();
        let connector = TlsConnector::from(Arc::new(config));
        let mut stream = connector
            .connect(ServerName::try_from("www.buckyos.com").unwrap(), stream)
            .await
            .unwrap();
        let result = stream.write_all(b"test").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 4];
        let ret = stream.read_exact(&mut buf).await;
        assert!(ret.is_ok());
        assert_eq!(&buf, b"recv");

        let test_stat = stat_manager.get_speed_stat("test");
        assert!(test_stat.is_some());
        let test_stat = test_stat.unwrap();
        assert!(test_stat.get_read_sum_size() > 350);
        assert!(test_stat.get_write_sum_size() > 880);
        assert!(start.elapsed().as_millis() > 1800);
        assert!(start.elapsed().as_millis() < 3000);
    }

    #[tokio::test]
    async fn test_tls_stack_stat_group_limiter_server() {
        let subject_alt_names = vec!["www.buckyos.com".to_string(), "127.0.0.1".to_string()];
        let cert_key = generate_simple_self_signed(subject_alt_names).unwrap();
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        set-stat test;
        set-limit test;
        return "server www.buckyos.com";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let stat_manager = StatManager::new();
        let mut limiter_manager = DefaultLimiterManager::new();
        let _ = limiter_manager.new_limiter("test".to_string(), None::<String>, Some(1), Some(2), Some(2));
        let limiter_manager = Arc::new(limiter_manager);
        let server_manager = Arc::new(ServerManager::new());
        server_manager.add_server(Server::Stream(Arc::new(MockServer::new("www.buckyos.com".to_string())))).unwrap();
        let result = TlsStack::builder()
            .id("test")
            .bind("127.0.0.1:9187")
            .hook_point(chains)
            .add_certs(vec![TlsDomainConfig {
                domain: "www.buckyos.com".to_string(),
                acme_type: None,
                certs: Some(vec![cert_key.cert.der().clone()]),
                key: Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    cert_key.signing_key.serialize_der()),
                )),
                data: None,
            }])
            .alpn_protocols(vec![b"http/1.1".to_vec(), b"h2".to_vec(), b"h3".to_vec()])
            .stack_context(build_stack_context(
                server_manager,
                TunnelManager::new(),
                limiter_manager,
                stat_manager.clone(),
                AcmeCertManager::create(CertManagerConfig::default()).await.unwrap(),
                SelfCertMgr::create(SelfCertConfig::default()).await.unwrap(),
                Some(Arc::new(GlobalProcessChains::new())),
            ))
            .build()
            .await;
        assert!(result.is_ok());
        let stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let config = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(rustls::DEFAULT_VERSIONS).unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();
        let stream = TcpStream::connect("127.0.0.1:9187").await.unwrap();
        let start = std::time::Instant::now();
        let connector = TlsConnector::from(Arc::new(config));
        let mut stream = connector
            .connect(ServerName::try_from("www.buckyos.com").unwrap(), stream)
            .await
            .unwrap();
        let result = stream.write_all(b"test").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 4];
        let ret = stream.read_exact(&mut buf).await;
        assert!(ret.is_ok());
        assert_eq!(&buf, b"recv");

        let test_stat = stat_manager.get_speed_stat("test");
        assert!(test_stat.is_some());
        let test_stat = test_stat.unwrap();
        assert!(test_stat.get_read_sum_size() > 350);
        assert!(test_stat.get_write_sum_size() > 880);
        assert!(start.elapsed().as_millis() > 1800);
        assert!(start.elapsed().as_millis() < 2500);
    }

    #[tokio::test]
    async fn test_tls_stack_stat_group_limiter_server2() {
        let subject_alt_names = vec!["www.buckyos.com".to_string(), "127.0.0.1".to_string()];
        let cert_key = generate_simple_self_signed(subject_alt_names).unwrap();
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        set-stat test;
        set-limit test "10KB/s" "10KB/s";
        return "server www.buckyos.com";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let stat_manager = StatManager::new();
        let mut limiter_manager = DefaultLimiterManager::new();
        let _ = limiter_manager.new_limiter("test".to_string(), None::<String>, Some(1), Some(2), Some(2));
        let limiter_manager = Arc::new(limiter_manager);
        let server_manager = Arc::new(ServerManager::new());
        server_manager.add_server(Server::Stream(Arc::new(MockServer::new("www.buckyos.com".to_string())))).unwrap();
        let result = TlsStack::builder()
            .id("test")
            .bind("127.0.0.1:9188")
            .hook_point(chains)
            .add_certs(vec![TlsDomainConfig {
                domain: "www.buckyos.com".to_string(),
                acme_type: None,
                certs: Some(vec![cert_key.cert.der().clone()]),
                key: Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    cert_key.signing_key.serialize_der()),
                )),
                data: None,
            }])
            .alpn_protocols(vec![b"http/1.1".to_vec(), b"h2".to_vec(), b"h3".to_vec()])
            .stack_context(build_stack_context(
                server_manager,
                TunnelManager::new(),
                limiter_manager,
                stat_manager.clone(),
                AcmeCertManager::create(CertManagerConfig::default()).await.unwrap(),
                SelfCertMgr::create(SelfCertConfig::default()).await.unwrap(),
                Some(Arc::new(GlobalProcessChains::new())),
            ))
            .build()
            .await;
        assert!(result.is_ok());
        let stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let config = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(rustls::DEFAULT_VERSIONS).unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();
        let stream = TcpStream::connect("127.0.0.1:9188").await.unwrap();
        let start = std::time::Instant::now();
        let connector = TlsConnector::from(Arc::new(config));
        let mut stream = connector
            .connect(ServerName::try_from("www.buckyos.com").unwrap(), stream)
            .await
            .unwrap();
        let result = stream.write_all(b"test").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 4];
        let ret = stream.read_exact(&mut buf).await;
        assert!(ret.is_ok());
        assert_eq!(&buf, b"recv");

        let test_stat = stat_manager.get_speed_stat("test");
        assert!(test_stat.is_some());
        let test_stat = test_stat.unwrap();
        assert!(test_stat.get_read_sum_size() > 350);
        assert!(test_stat.get_write_sum_size() > 880);
        assert!(start.elapsed().as_millis() > 1800);
        assert!(start.elapsed().as_millis() < 2500);
    }

    fn ensure_crypto_provider() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    fn build_test_chain() -> (String, String, String, CertificateDer<'static>) {
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(vec!["Test Root CA".to_string()]).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let intermediate_key = KeyPair::generate().unwrap();
        let mut intermediate_params =
            CertificateParams::new(vec!["Test Intermediate CA".to_string()]).unwrap();
        intermediate_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_issuer = Issuer::from_params(&ca_params, &ca_key);
        let intermediate_cert = intermediate_params
            .signed_by(&intermediate_key, &ca_issuer)
            .unwrap();

        let leaf_key = KeyPair::generate().unwrap();
        let leaf_params = CertificateParams::new(vec!["sn.buckyos.ai".to_string()]).unwrap();
        let intermediate_issuer = Issuer::from_params(&intermediate_params, &intermediate_key);
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &intermediate_issuer)
            .unwrap();

        let intermediate_pem = intermediate_cert.pem();
        let leaf_pem = leaf_cert.pem();
        let leaf_key_pem = leaf_key.serialize_pem();
        let root_der = CertificateDer::from(ca_cert.clone());

        let fullchain_pem = format!("{leaf_pem}\n{intermediate_pem}");
        (fullchain_pem, leaf_pem, leaf_key_pem, root_der)
    }

    #[tokio::test]
    async fn test_tls_fullchain_allows_client_verify() {
        ensure_crypto_provider();
        let (fullchain_pem, _leaf_pem, leaf_key_pem, root_der) = build_test_chain();
        let tmp_dir = tempdir().unwrap();
        let cert_path = tmp_dir.path().join("fullchain.pem");
        let key_path = tmp_dir.path().join("leaf.key");
        fs::write(&cert_path, fullchain_pem).await.unwrap();
        fs::write(&key_path, leaf_key_pem).await.unwrap();

        let certs = load_certs(cert_path.to_str().unwrap()).await.unwrap();
        let key = load_key(key_path.to_str().unwrap()).await.unwrap();
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let server_handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = acceptor.accept(stream).await;
        });

        let mut roots = RootCertStore::empty();
        roots.add(root_der).unwrap();
        let client_config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(client_config));
        let stream = TcpStream::connect(addr).await.unwrap();
        let result = connector
            .connect(ServerName::try_from("sn.buckyos.ai").unwrap(), stream)
            .await;
        assert!(result.is_ok());

        server_handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_tls_missing_intermediate_fails_client_verify() {
        ensure_crypto_provider();
        let (_fullchain_pem, leaf_pem, leaf_key_pem, root_der) = build_test_chain();
        let tmp_dir = tempdir().unwrap();
        let cert_path = tmp_dir.path().join("leaf.pem");
        let key_path = tmp_dir.path().join("leaf.key");
        fs::write(&cert_path, leaf_pem).await.unwrap();
        fs::write(&key_path, leaf_key_pem).await.unwrap();

        let certs = load_certs(cert_path.to_str().unwrap()).await.unwrap();
        let key = load_key(key_path.to_str().unwrap()).await.unwrap();
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let server_handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = acceptor.accept(stream).await;
        });

        let mut roots = RootCertStore::empty();
        roots.add(root_der).unwrap();
        let client_config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(client_config));
        let stream = TcpStream::connect(addr).await.unwrap();
        let result = connector
            .connect(ServerName::try_from("sn.buckyos.ai").unwrap(), stream)
            .await;
        assert!(result.is_err());

        server_handle.await.unwrap();
    }
}
