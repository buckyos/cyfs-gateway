use crate::global_process_chains::{
    create_process_chain_executor, execute_stream_chain, GlobalProcessChainsRef,
};
use crate::{into_stack_err, stack_err, ProcessChainConfigs, Stack, StackErrorCode, StackProtocol, StackResult, ServerManagerRef, Server, hyper_serve_http, ConnectionManagerRef, ConnectionInfo, HandleConnectionController, StackConfig, TunnelManager, StackCertConfig, StreamInfo, ProcessChainConfig, get_min_priority, get_stream_external_commands, LimiterManagerRef, StatManagerRef, get_stat_info, MutComposedSpeedStat, MutComposedSpeedStatRef};
use cyfs_process_chain::{CommandControl, ProcessChainLibExecutor, StreamRequest};
pub use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use std::io::{BufReader, Cursor};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use rustls::server::ResolvesServerCert;
use rustls::sign::CertifiedKey;
use sfo_io::{LimitStream, StatStream};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use crate::stack::{get_limit_info, stream_forward};
use serde::{Deserialize, Serialize};
use cyfs_acme::{AcmeCertManagerRef, AcmeItem, ChallengeType, ACME_TLS_ALPN_NAME};
use crate::stack::limiter::Limiter;
use crate::stack::tls_cert_resolver::ResolvesServerCertUsingSni;

pub async fn load_certs(path: &str) -> StackResult<Vec<CertificateDer<'static>>> {
    let file_content = tokio::fs::read(path)
        .await
        .map_err(into_stack_err!(StackErrorCode::InvalidConfig))?;
    let mut reader = BufReader::new(Cursor::new(file_content));
    let mut certs = vec![];
    for cert in rustls_pemfile::certs(&mut reader) {
        certs.push(cert.map_err(|_| {
            stack_err!(
                StackErrorCode::InvalidTlsCert,
                "failed to parse certificates"
            )
        })?);
    }
    Ok(certs)
}

pub async fn load_key(path: &str) -> StackResult<PrivateKeyDer<'static>> {
    let file_content = tokio::fs::read(path).await.map_err(into_stack_err!(
        StackErrorCode::InvalidTlsKey,
        "file:{}",
        path
    ))?;
    let mut reader = BufReader::new(Cursor::new(file_content));
    let mut keys = vec![];
    for key in rustls_pemfile::pkcs8_private_keys(&mut reader) {
        keys.push(key.map_err(|_| {
            stack_err!(
            StackErrorCode::InvalidTlsKey,
            "failed to parse private key, file:{}",
            path
        )
        })?);
    }

    if keys.is_empty() {
        return Err(stack_err!(
            StackErrorCode::InvalidTlsKey,
            "no private key found, file:{}",
            path
        ));
    }

    Ok(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        keys.into_iter().next().unwrap(),
    )))
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

struct TlsStackInner {
    id: String,
    bind_addr: String,
    certs: Arc<ResolvesServerCertUsingSni>,
    servers: ServerManagerRef,
    executor: Arc<Mutex<ProcessChainLibExecutor>>,
    connection_manager: Option<ConnectionManagerRef>,
    global_process_chains: Option<GlobalProcessChainsRef>,
    tunnel_manager: TunnelManager,
    limiter_manager: LimiterManagerRef,
    stat_manager: StatManagerRef,
    alpn_protocols: Vec<Vec<u8>>,
}

impl TlsStackInner {
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
        if config.servers.is_none() {
            return Err(stack_err!(
                StackErrorCode::InvalidConfig,
                "servers is required"
            ));
        }
        if config.tunnel_manager.is_none() {
            return Err(stack_err!(
                StackErrorCode::InvalidConfig,
                "tunnel_manager is required"
            ));
        }
        if config.limiter_manager.is_none() {
            return Err(stack_err!(
                StackErrorCode::InvalidConfig,
                "limiter_manager is required"
            ));
        }
        if config.stat_manager.is_none() {
            return Err(stack_err!(
                StackErrorCode::InvalidConfig,
                "stat_manager is required"
            ));
        }
        let (executor, _) = create_process_chain_executor(config.hook_point.as_ref().unwrap(),
                                                          config.global_process_chains.clone(),
                                                          Some(get_stream_external_commands())).await
            .map_err(into_stack_err!(StackErrorCode::ProcessChainError))?;
        let crypto_provider = rustls::crypto::ring::default_provider();
        let external_resolver = config.acme_manager.clone().map(|v| v.clone() as Arc<dyn ResolvesServerCert>);
        let cert_resolver = Arc::new(ResolvesServerCertUsingSni::new(external_resolver));
        for cert_config in config.certs.into_iter() {
            if cert_config.certs.is_some() && cert_config.key.is_some() {
                let cert_key = CertifiedKey::from_der(cert_config.certs.unwrap(), cert_config.key.unwrap(), &crypto_provider)
                    .map_err(into_stack_err!(StackErrorCode::InvalidTlsCert))?;
                cert_resolver.add(&cert_config.domain, cert_key)
                    .map_err(into_stack_err!(StackErrorCode::InvalidConfig, "add cert failed"))?;
            } else {
                if config.acme_manager.is_some() {
                    config.acme_manager.as_ref().unwrap()
                        .add_acme_item(AcmeItem::new(cert_config.domain,
                                                     cert_config.acme_type.unwrap_or(ChallengeType::TlsAlpn01),
                                                     cert_config.data))
                        .map_err(|e| stack_err!(StackErrorCode::InvalidConfig, "{e}"))?;
                }
            }
        }

        Ok(Self {
            id: config.id.unwrap(),
            bind_addr: config.bind.unwrap(),
            certs: cert_resolver.clone(),
            servers: config.servers.unwrap(),
            executor: Arc::new(Mutex::new(executor)),
            connection_manager: config.connection_manager,
            global_process_chains: config.global_process_chains,
            tunnel_manager: config.tunnel_manager.unwrap(),
            limiter_manager: config.limiter_manager.unwrap(),
            stat_manager: config.stat_manager.unwrap(),
            alpn_protocols: config.alpn_protocols,
        })
    }

    pub async fn start(self: &Arc<Self>) -> StackResult<JoinHandle<()>> {
        let bind_addr = self.bind_addr.clone();
        let listener = tokio::net::TcpListener::bind(bind_addr.as_str())
            .await
            .map_err(into_stack_err!(StackErrorCode::BindFailed))?;
        let this = self.clone();
        let handle = tokio::spawn(async move {
            loop {
                let (stream, local_addr) = match listener.accept().await {
                    Ok(s) => s,
                    Err(e) => {
                        log::error!("accept tcp stream failed: {}", e);
                        continue;
                    }
                };

                let remote_addr = match stream.peer_addr() {
                    Ok(addr) => addr,
                    Err(e) => {
                        log::error!("get remote addr failed: {}", e);
                        continue;
                    }
                };

                let this_tmp = this.clone();
                let compose_stat = MutComposedSpeedStat::new();
                let stat_stream = StatStream::new_with_tracker(stream, compose_stat.clone());
                let speed = stat_stream.get_speed_stat();
                let handle = tokio::spawn(async move {
                    if let Err(e) =
                        this_tmp.handle_connect(stat_stream, local_addr, compose_stat).await
                    {
                        log::error!("handle tcp stream failed: {}", e);
                    }
                });

                if let Some(connection_manager) = &this.connection_manager {
                    let controller = HandleConnectionController::new(handle);
                    connection_manager.add_connection(ConnectionInfo::new(remote_addr.to_string(), local_addr.to_string(), StackProtocol::Tls, speed, controller));
                }
            }
        });
        Ok(handle)
    }

    async fn handle_connect(
        &self,
        mut stream: StatStream<TcpStream>,
        local_addr: SocketAddr,
        compose_stat: MutComposedSpeedStatRef,
    ) -> StackResult<()> {
        let servers = self.servers.clone();
        let executor = {
            self.executor.lock().unwrap().fork()
        };
        let remote_addr = stream.raw_stream().peer_addr().map_err(into_stack_err!(StackErrorCode::ServerError, "read remote addr failed"))?;

        let mut server_config = ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
            .with_protocol_versions(rustls::DEFAULT_VERSIONS)
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(self.certs.clone());
        // server_config.alpn_protocols = vec![b"http/1.1".to_vec(), b"h2".to_vec(), b"h3".to_vec()];
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
        let mut request = StreamRequest::new(Box::new(tls_stream), local_addr);
        request.source_addr = Some(remote_addr);
        request.dest_host = server_name;
        let chain_env = executor.chain_env().clone();
        let (ret, stream) = execute_stream_chain(executor, request)
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
                            stream_forward(stream, target, &self.tunnel_manager).await?;
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
                                                                         StreamInfo::new(local_addr.to_string())).await {
                                            log::error!("hyper serve http failed: {}", e);
                                        }
                                    }
                                    Server::Stream(server) => {
                                        server
                                            .serve_connection(stream, StreamInfo::new(local_addr.to_string()))
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
    inner: Arc<TlsStackInner>,
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
        let inner = TlsStackInner::create(config).await?;

        Ok(Self {
            inner: Arc::new(inner),
            handle: Mutex::new(None),
        })
    }
}

#[async_trait::async_trait]
impl Stack for TlsStack {
    fn id(&self) -> String {
        self.inner.id.clone()
    }

    fn stack_protocol(&self) -> StackProtocol {
        StackProtocol::Tls
    }

    fn get_bind_addr(&self) -> String {
        self.inner.bind_addr.clone()
    }

    async fn start(&self) -> StackResult<()> {
        let handle = self.inner.start().await?;
        *self.handle.lock().unwrap() = Some(handle);
        Ok(())
    }

    async fn update_config(&self, config: Arc<dyn StackConfig>) -> StackResult<()> {
        let config = config.as_ref().as_any().downcast_ref::<TlsStackConfig>()
            .ok_or(stack_err!(StackErrorCode::InvalidConfig, "invalid config"))?;
        if config.id != self.inner.id {
            return Err(stack_err!(StackErrorCode::InvalidConfig, "id unmatch"));
        }
        if config.bind.to_string() != self.inner.bind_addr {
            return Err(stack_err!(StackErrorCode::BindUnmatched, "bind unmatch"));
        }

        let (executor, _) = create_process_chain_executor(&config.hook_point,
                                                          self.inner.global_process_chains.clone(),
                                                          Some(get_stream_external_commands())).await
            .map_err(into_stack_err!(StackErrorCode::ProcessChainError))?;
        *self.inner.executor.lock().unwrap() = executor;
        Ok(())
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

pub struct TlsStackFactory {
    servers: ServerManagerRef,
    global_process_chains: GlobalProcessChainsRef,
    connection_manager: ConnectionManagerRef,
    tunnel_manager: TunnelManager,
    acme_manager: AcmeCertManagerRef,
    limiter_manager: LimiterManagerRef,
    stat_manager: StatManagerRef,
}

impl TlsStackFactory {
    pub fn new(
        servers: ServerManagerRef,
        global_process_chains: GlobalProcessChainsRef,
        connection_manager: ConnectionManagerRef,
        tunnel_manager: TunnelManager,
        acme_manager: AcmeCertManagerRef,
        limiter_manager: LimiterManagerRef,
        stat_manager: StatManagerRef,
    ) -> Self {
        Self {
            servers,
            global_process_chains,
            connection_manager,
            tunnel_manager,
            acme_manager,
            limiter_manager,
            stat_manager,
        }
    }
}

#[async_trait::async_trait]
impl crate::StackFactory for TlsStackFactory {
    async fn create(&self, config: Arc<dyn crate::StackConfig>) -> crate::StackResult<crate::StackRef> {
        let config = config
            .as_any()
            .downcast_ref::<TlsStackConfig>()
            .ok_or(stack_err!(StackErrorCode::InvalidConfig, "invalid config"))?;

        let mut cert_list = vec![];
        for cert_config in config.certs.iter() {
            if cert_config.cert_file.is_some() && cert_config.key_file.is_some() {
                let certs = load_certs(cert_config.cert_file.as_ref().unwrap().as_str()).await?;
                let key = load_key(cert_config.key_file.as_ref().unwrap().as_str()).await?;
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

        let stack = TlsStack::builder()
            .id(config.id.clone())
            .bind(config.bind.to_string())
            .connection_manager(self.connection_manager.clone())
            .global_process_chains(self.global_process_chains.clone())
            .servers(self.servers.clone())
            .hook_point(config.hook_point.clone())
            .add_certs(cert_list)
            .concurrency(config.concurrency.unwrap_or(0))
            .tunnel_manager(self.tunnel_manager.clone())
            .alpn_protocols(config.alpn_protocols.clone().unwrap_or(vec!["http/1.1".to_string()]).iter().map(|s| s.as_bytes().to_vec()).collect())
            .acme_manager(self.acme_manager.clone())
            .limiter_manager(self.limiter_manager.clone())
            .stat_manager(self.stat_manager.clone())
            .build()
            .await?;
        Ok(Arc::new(stack))
    }
}

pub struct TlsStackBuilder {
    id: Option<String>,
    bind: Option<String>,
    hook_point: Option<ProcessChainConfigs>,
    servers: Option<ServerManagerRef>,
    global_process_chains: Option<GlobalProcessChainsRef>,
    certs: Vec<TlsDomainConfig>,
    concurrency: u32,
    connection_manager: Option<ConnectionManagerRef>,
    tunnel_manager: Option<TunnelManager>,
    alpn_protocols: Vec<Vec<u8>>,
    acme_manager: Option<AcmeCertManagerRef>,
    limiter_manager: Option<LimiterManagerRef>,
    stat_manager: Option<StatManagerRef>,
}

impl TlsStackBuilder {
    fn new() -> Self {
        Self {
            id: None,
            bind: None,
            hook_point: None,
            servers: None,
            global_process_chains: None,
            certs: vec![],
            concurrency: 0,
            connection_manager: None,
            tunnel_manager: None,
            alpn_protocols: vec![],
            acme_manager: None,
            limiter_manager: None,
            stat_manager: None,
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

    pub fn concurrency(mut self, concurrency: u32) -> Self {
        if concurrency == 0 {
            self.concurrency = u32::MAX;
        } else {
            self.concurrency = concurrency;
        }
        self
    }

    pub fn tunnel_manager(mut self, tunnel_manager: TunnelManager) -> Self {
        self.tunnel_manager = Some(tunnel_manager);
        self
    }

    pub fn alpn_protocols(mut self, alpn_protocols: Vec<Vec<u8>>) -> Self {
        self.alpn_protocols = alpn_protocols;
        self
    }

    pub fn acme_manager(mut self, acme_resolver: AcmeCertManagerRef) -> Self {
        self.acme_manager = Some(acme_resolver);
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

    pub async fn build(self) -> StackResult<TlsStack> {
        let stack = TlsStack::create(self).await?;
        Ok(stack)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use crate::global_process_chains::GlobalProcessChains;
    use crate::{ProcessChainConfigs, ServerResult, StreamServer, ServerManager, TunnelManager, Server, ProcessChainHttpServer, Stack, TlsStackFactory, ConnectionManager, TlsStackConfig, StackProtocol, StackFactory, StreamInfo, LimiterManager, StatManager};
    use crate::{TlsDomainConfig, TlsStack};
    use buckyos_kit::{AsyncStream};
    use name_lib::{encode_ed25519_sk_to_pk_jwk, generate_ed25519_key, DeviceConfig};
    use rcgen::generate_simple_self_signed;
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{
        CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime,
    };
    use rustls::{ClientConfig, DigitallySignedStruct, Error, SignatureScheme};
    use std::sync::Arc;
    use std::time::Duration;
    use http_body_util::Full;
    use hyper::body::Bytes;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::TlsConnector;
    use cyfs_acme::{AcmeCertManager, CertManagerConfig};

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
            .servers(Arc::new(ServerManager::new()))
            .build()
            .await;
        assert!(result.is_err());
        let result = TlsStack::builder()
            .id("test")
            .bind("127.0.0.1:9080")
            .servers(Arc::new(ServerManager::new()))
            .hook_point(vec![])
            .tunnel_manager(TunnelManager::new())
            .limiter_manager(LimiterManager::new())
            .stat_manager(StatManager::new()) // 添加stat_manager
            .build()
            .await;
        assert!(result.is_ok());
        let result = TlsStack::builder()
            .id("test")
            .bind("127.0.0.1:9080")
            .servers(Arc::new(ServerManager::new()))
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
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .tunnel_manager(TunnelManager::new())
            .limiter_manager(LimiterManager::new())
            .stat_manager(StatManager::new()) // 添加stat_manager
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
            .servers(Arc::new(ServerManager::new()))
            .hook_point(chains)
            .tunnel_manager(TunnelManager::new())
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
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .limiter_manager(LimiterManager::new())
            .stat_manager(StatManager::new()) // 添加stat_manager
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
            .servers(Arc::new(ServerManager::new()))
            .hook_point(chains)
            .tunnel_manager(TunnelManager::new())
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
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .limiter_manager(LimiterManager::new())
            .stat_manager(StatManager::new()) // 添加stat_manager
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
            .servers(Arc::new(ServerManager::new()))
            .hook_point(chains)
            .tunnel_manager(TunnelManager::new())
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
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .limiter_manager(LimiterManager::new())
            .stat_manager(StatManager::new()) // 添加stat_manager
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
            .servers(Arc::new(ServerManager::new()))
            .hook_point(chains)
            .tunnel_manager(TunnelManager::new())
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
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .limiter_manager(LimiterManager::new())
            .stat_manager(StatManager::new())
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
            .servers(server_manager)
            .hook_point(chains)
            .tunnel_manager(TunnelManager::new())
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
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .limiter_manager(LimiterManager::new())
            .stat_manager(StatManager::new()) // 添加stat_manager
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

        let http_server = ProcessChainHttpServer::builder()
            .id("www.buckyos.com")
            .version("HTTP/3")
            .h3_port(9186)
            .hook_point(chains)
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .server_mgr(Arc::new(ServerManager::new()))
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
            .servers(server_manager)
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
            .tunnel_manager(TunnelManager::new())
            .alpn_protocols(vec![b"http/1.1".to_vec(), b"h2".to_vec(), b"h3".to_vec()])
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .limiter_manager(LimiterManager::new())
            .stat_manager(StatManager::new()) // 添加stat_manager
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

        let http_server = ProcessChainHttpServer::builder()
            .id("www.buckyos.com")
            .version("HTTP/3")
            .h3_port(9186)
            .hook_point(chains)
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .server_mgr(Arc::new(ServerManager::new()))
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
            .servers(server_manager)
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
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .tunnel_manager(TunnelManager::new())
            .limiter_manager(LimiterManager::new())
            .alpn_protocols(vec![b"http/1.1".to_vec(), b"h2".to_vec(), b"h3".to_vec()])
            .stat_manager(StatManager::new()) // 添加stat_manager
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
    async fn test_factory() {
        let mut cert_config = CertManagerConfig::default();
        let data_dir = tempfile::tempdir().unwrap();
        cert_config.keystore_path = data_dir.path().to_string_lossy().to_string();
        let cert_manager = AcmeCertManager::create(cert_config).await.unwrap();

        let factory = TlsStackFactory::new(
            Arc::new(ServerManager::new()),
            Arc::new(GlobalProcessChains::new()),
            ConnectionManager::new(),
            TunnelManager::new(),
            cert_manager,
            LimiterManager::new(),
            StatManager::new(),
        );

        let config = TlsStackConfig {
            id: "test".to_string(),
            protocol: StackProtocol::Tls,
            bind: "127.0.0.1:343".parse().unwrap(),
            hook_point: vec![],
            certs: vec![],
            concurrency: None,
            alpn_protocols: None,
        };
        let ret = factory.create(Arc::new(config)).await;
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
            .servers(server_manager)
            .hook_point(chains)
            .tunnel_manager(TunnelManager::new())
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
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .limiter_manager(LimiterManager::new())
            .stat_manager(stat_manager.clone())
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
            .servers(server_manager)
            .hook_point(chains)
            .tunnel_manager(TunnelManager::new())
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
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .limiter_manager(LimiterManager::new())
            .stat_manager(stat_manager.clone())
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
        assert!(start.elapsed().as_millis() < 2500);
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
        let limiter_manager = LimiterManager::new();
        let _ = limiter_manager.new_limiter("test", None::<String>, Some(1), Some(2), Some(2));
        let server_manager = Arc::new(ServerManager::new());
        server_manager.add_server(Server::Stream(Arc::new(MockServer::new("www.buckyos.com".to_string())))).unwrap();
        let result = TlsStack::builder()
            .id("test")
            .bind("127.0.0.1:9187")
            .servers(server_manager)
            .hook_point(chains)
            .tunnel_manager(TunnelManager::new())
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
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .limiter_manager(limiter_manager)
            .stat_manager(stat_manager.clone())
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
        let limiter_manager = LimiterManager::new();
        let _ = limiter_manager.new_limiter("test", None::<String>, Some(1), Some(2), Some(2));
        let server_manager = Arc::new(ServerManager::new());
        server_manager.add_server(Server::Stream(Arc::new(MockServer::new("www.buckyos.com".to_string())))).unwrap();
        let result = TlsStack::builder()
            .id("test")
            .bind("127.0.0.1:9188")
            .servers(server_manager)
            .hook_point(chains)
            .tunnel_manager(TunnelManager::new())
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
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .limiter_manager(limiter_manager)
            .stat_manager(stat_manager.clone())
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
}
