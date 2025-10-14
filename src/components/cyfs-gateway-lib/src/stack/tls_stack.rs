use crate::global_process_chains::{
    create_process_chain_executor, execute_stream_chain, GlobalProcessChainsRef,
};
use crate::{into_stack_err, stack_err, ProcessChainConfigs, Stack, StackErrorCode, StackProtocol, StackResult, ServerManagerRef, Server, hyper_serve_http, ConnectionManagerRef, ConnectionInfo, HandleConnectionController, StackConfig, TunnelManager, StackCertConfig, StreamInfo, ProcessChainConfig, get_min_priority, get_stream_external_commands};
use cyfs_process_chain::{CommandControl, ProcessChainLibExecutor, StreamRequest};
pub use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::io::{BufReader, Cursor};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use rustls::sign::CertifiedKey;
use sfo_io::{LimitStream, StatStream};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use crate::stack::{stream_forward, ResolvesServerCertUsingSni};
use serde::{Deserialize, Serialize};
use crate::stack::limiter::Limiter;

pub async fn load_certs(path: &str) -> StackResult<Vec<CertificateDer<'static>>> {
    let file_content = tokio::fs::read(path)
        .await
        .map_err(into_stack_err!(StackErrorCode::InvalidConfig))?;
    let mut reader = BufReader::new(Cursor::new(file_content));
    Ok(certs(&mut reader)
        .map_err(|_| {
            stack_err!(
                StackErrorCode::InvalidTlsCert,
                "failed to parse certificates"
            )
        })?
        .into_iter()
        .map(|v| CertificateDer::from(v))
        .collect())
}

pub async fn load_key(path: &str) -> StackResult<PrivateKeyDer<'static>> {
    let file_content = tokio::fs::read(path).await.map_err(into_stack_err!(
        StackErrorCode::InvalidTlsKey,
        "file:{}",
        path
    ))?;
    let mut reader = BufReader::new(Cursor::new(file_content));
    let keys = pkcs8_private_keys(&mut reader).map_err(|_| {
        stack_err!(
            StackErrorCode::InvalidTlsKey,
            "failed to parse private key, file:{}",
            path
        )
    })?;

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
        let (executor, _) = create_process_chain_executor(config.hook_point.as_ref().unwrap(),
                                                          config.global_process_chains.clone(),
                                                          Some(get_stream_external_commands())).await
            .map_err(into_stack_err!(StackErrorCode::ProcessChainError))?;
        let crypto_provider = rustls::crypto::ring::default_provider();
        let cert_resolver = Arc::new(ResolvesServerCertUsingSni::new());
        for cert_config in config.certs.into_iter() {
            let cert_key = CertifiedKey::from_der(cert_config.certs, cert_config.key, &crypto_provider)
                .map_err(into_stack_err!(StackErrorCode::InvalidTlsCert))?;
            cert_resolver.add(&cert_config.domain, cert_key)
                .map_err(into_stack_err!(StackErrorCode::InvalidConfig, "add cert failed"))?;
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
                let stat_stream = StatStream::new(stream);
                let speed = stat_stream.get_speed_stat();
                let handle = tokio::spawn(async move {
                    if let Err(e) =
                        this_tmp.handle_connect(stat_stream, local_addr).await
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

        let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));
        let tls_stream = tls_acceptor
            .accept(stream)
            .await
            .map_err(into_stack_err!(StackErrorCode::StreamError))?;

        let mut request = StreamRequest::new(Box::new(tls_stream), local_addr);
        request.source_addr = Some(remote_addr);
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
                            let server_name = list[1].as_str();

                            if let Some(server) = servers.get_server(server_name) {
                                match server {
                                    Server::Http(http_server) => {
                                        if let Err(e) = hyper_serve_http(Box::new(stream), http_server).await {
                                            log::error!("hyper serve http failed: {}", e);
                                        }
                                    }
                                    Server::Stream(server) => {
                                        server
                                            .serve_connection(Box::new(stream), StreamInfo::new(remote_addr.to_string()))
                                            .await
                                            .map_err(into_stack_err!(StackErrorCode::InvalidConfig))?;
                                    }
                                    Server::Datagram(_) => {
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

pub struct TlsDomainConfig {
    pub domain: String,
    pub certs: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
}

// 为TlsDomainConfig实现Clone trait
impl Clone for TlsDomainConfig {
    fn clone(&self) -> Self {
        Self {
            domain: self.domain.clone(),
            certs: self.certs.clone(),
            key: match &self.key {
                PrivateKeyDer::Pkcs8(key) => PrivateKeyDer::Pkcs8(key.clone_key()),
                PrivateKeyDer::Pkcs1(key) => PrivateKeyDer::Pkcs1(key.clone_key()),
                PrivateKeyDer::Sec1(key) => PrivateKeyDer::Sec1(key.clone_key()),
                _ => panic!("Unsupported key type"),
            },
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
}

impl TlsStackFactory {
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
impl crate::StackFactory for TlsStackFactory {
    async fn create(&self, config: Arc<dyn crate::StackConfig>) -> crate::StackResult<crate::StackRef> {
        let config = config
            .as_any()
            .downcast_ref::<TlsStackConfig>()
            .ok_or(stack_err!(StackErrorCode::InvalidConfig, "invalid config"))?;

        let mut cert_list = vec![];
        for cert_config in config.certs.iter() {
            let certs = load_certs(cert_config.cert_file.as_str()).await?;
            let key = load_key(cert_config.key_file.as_str()).await?;
            cert_list.push(TlsDomainConfig {
                domain: cert_config.domain.clone(),
                certs,
                key,
            });
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
            .alpn_protocols(config.alpn_protocols.clone().unwrap_or(vec![]).iter().map(|s| s.as_bytes().to_vec()).collect())
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

    pub async fn build(self) -> StackResult<TlsStack> {
        let stack = TlsStack::create(self).await?;
        Ok(stack)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use crate::global_process_chains::GlobalProcessChains;
    use crate::{GatewayDevice, ProcessChainConfigs, ServerResult, StreamServer, ServerManager, TunnelManager, GATEWAY_TUNNEL_MANAGER, Server, ProcessChainHttpServer, InnerServiceManager, Stack, TlsStackFactory, ConnectionManager, TlsStackConfig, StackProtocol, StackFactory, ServerConfig, StreamInfo};
    use crate::{TlsDomainConfig, TlsStack};
    use buckyos_kit::AsyncStream;
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
                certs: vec![cert_key.cert.der().clone()],
                key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    cert_key.signing_key.serialize_der(),
                )),
            }])
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .tunnel_manager(TunnelManager::new())
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
                certs: vec![cert_key.cert.der().clone()],
                key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    cert_key.signing_key.serialize_der(),
                )),
            }])
            .alpn_protocols(vec![b"http/1.1".to_vec(), b"h2".to_vec(), b"h3".to_vec()])
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .build()
            .await;
        assert!(result.is_ok());
        let mut stack = result.unwrap();
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
                certs: vec![cert_key.cert.der().clone()],
                key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    cert_key.signing_key.serialize_der(),
                )),
            }])
            .alpn_protocols(vec![b"http/1.1".to_vec(), b"h2".to_vec(), b"h3".to_vec()])
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .build()
            .await;
        assert!(result.is_ok());
        let mut stack = result.unwrap();
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
                certs: vec![cert_key.cert.der().clone()],
                key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    cert_key.signing_key.serialize_der(),
                )),
            }])
            .alpn_protocols(vec![b"http/1.1".to_vec(), b"h2".to_vec(), b"h3".to_vec()])
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .build()
            .await;
        assert!(result.is_ok());
        let mut stack = result.unwrap();
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

        let start = std::time::SystemTime::now();
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
                certs: vec![cert_key.cert.der().clone()],
                key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    cert_key.signing_key.serialize_der(),
                )),
            }])
            .alpn_protocols(vec![b"http/1.1".to_vec(), b"h2".to_vec(), b"h3".to_vec()])
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .build()
            .await;
        assert!(result.is_ok());
        let mut stack = result.unwrap();
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

    pub struct MockServer;

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
            todo!()
        }

        async fn update_config(&self, config: Arc<dyn ServerConfig>) -> ServerResult<()> {
            todo!()
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
        server_manager.add_server("www.buckyos.com".to_string(), Server::Stream(Arc::new(MockServer)));
        let result = TlsStack::builder()
            .id("test")
            .bind("127.0.0.1:9085")
            .servers(server_manager)
            .hook_point(chains)
            .tunnel_manager(TunnelManager::new())
            .add_certs(vec![TlsDomainConfig {
                domain: "www.buckyos.com".to_string(),
                certs: vec![cert_key.cert.der().clone()],
                key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    cert_key.signing_key.serialize_der(),
                )),
            }])
            .alpn_protocols(vec![b"http/1.1".to_vec(), b"h2".to_vec(), b"h3".to_vec()])
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .build()
            .await;
        assert!(result.is_ok());
        let mut stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());

        let tunnel_manager = TunnelManager::new();

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
            .id("1")
            .version("HTTP/3")
            .h3_port(9186)
            .hook_point(chains)
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .inner_services(Arc::new(InnerServiceManager::new()))
            .build().await.unwrap();

        let server_manager = Arc::new(ServerManager::new());
        server_manager.add_server("www.buckyos.com".to_string(), Server::Http(Arc::new(http_server)));


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
                certs: vec![cert_key.cert.der().clone()],
                key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    cert_key.signing_key.serialize_der(),
                )),
            }])
            .tunnel_manager(TunnelManager::new())
            .alpn_protocols(vec![b"http/1.1".to_vec(), b"h2".to_vec(), b"h3".to_vec()])
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
            .id("1")
            .version("HTTP/3")
            .h3_port(9186)
            .hook_point(chains)
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .inner_services(Arc::new(InnerServiceManager::new()))
            .build().await.unwrap();

        let server_manager = Arc::new(ServerManager::new());
        server_manager.add_server("www.buckyos.com".to_string(), Server::Http(Arc::new(http_server)));


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
                certs: vec![cert_key.cert.der().clone()],
                key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    cert_key.signing_key.serialize_der(),
                )),
            }])
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .tunnel_manager(TunnelManager::new())
            .alpn_protocols(vec![b"http/1.1".to_vec(), b"h2".to_vec(), b"h3".to_vec()])
            .build()
            .await;
        assert!(result.is_ok());
        let mut stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());


        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config = DeviceConfig::new_by_jwk("test", serde_json::from_value(jwk).unwrap());

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
        let factory = TlsStackFactory::new(
            Arc::new(ServerManager::new()),
            Arc::new(GlobalProcessChains::new()),
            ConnectionManager::new(),
            TunnelManager::new(),
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
}
