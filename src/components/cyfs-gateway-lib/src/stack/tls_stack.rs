use crate::global_process_chains::{
    create_process_chain_executor, execute_chain, GlobalProcessChainsRef,
};
use crate::{
    into_stack_err, stack_err, ProcessChainConfigs, Stack, StackErrorCode, StackProtocol,
    StackResult, StreamServerManagerRef,
};
use cyfs_process_chain::{CommandControl, ProcessChainListExecutor};
use rustls::crypto::CryptoProvider;
pub use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::collections::HashMap;
use std::io::{BufReader, Cursor};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

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

pub struct TlsStack {
    bind_addr: String,
    certs: Arc<Mutex<HashMap<String, Arc<ServerConfig>>>>,
    servers: StreamServerManagerRef,
    executor: Arc<Mutex<ProcessChainListExecutor>>,
    handle: Option<JoinHandle<()>>,
}

impl Drop for TlsStack {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

impl TlsStack {
    pub fn builder() -> TlsStackBuilder {
        TlsStackBuilder {
            bind: None,
            hook_point: None,
            servers: None,
            global_process_chains: None,
            certs: Default::default(),
        }
    }

    async fn create(config: TlsStackBuilder) -> StackResult<Self> {
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
        let (executor, _) = create_process_chain_executor(config.hook_point.as_ref().unwrap())
            .await
            .map_err(into_stack_err!(StackErrorCode::ProcessChainError))?;
        let mut certs = HashMap::new();
        for cert_config in config.certs.into_iter() {
            certs.insert(
                cert_config.domain.clone(),
                Arc::new(
                    ServerConfig::builder_with_provider(Arc::new(
                        rustls::crypto::ring::default_provider(),
                    ))
                        .with_protocol_versions(rustls::DEFAULT_VERSIONS)
                        .unwrap()
                        .with_no_client_auth()
                        .with_single_cert(cert_config.certs, cert_config.key)
                        .map_err(|e| stack_err!(StackErrorCode::InvalidTlsCert, "{}", e))?,
                ),
            );
        }

        Ok(Self {
            bind_addr: config.bind.unwrap(),
            certs: Arc::new(Mutex::new(certs)),
            servers: config.servers.unwrap(),
            executor: Arc::new(Mutex::new(executor)),
            handle: None,
        })
    }

    pub async fn start(&mut self) -> StackResult<()> {
        let bind_addr = self.bind_addr.clone();
        let servers = self.servers.clone();
        let executor = self.executor.clone();
        let certs = self.certs.clone();
        let listener = tokio::net::TcpListener::bind(bind_addr.as_str())
            .await
            .map_err(into_stack_err!(StackErrorCode::BindFailed))?;
        let handle = tokio::spawn(async move {
            loop {
                let (stream, local_addr) = match listener.accept().await {
                    Ok(s) => s,
                    Err(e) => {
                        log::error!("accept tcp stream failed: {}", e);
                        continue;
                    }
                };
                let servers = servers.clone();
                let executor = executor.lock().unwrap().fork();
                let certs = certs.clone();
                tokio::spawn(async move {
                    if let Err(e) =
                        Self::handle_connect(stream, local_addr, servers, executor, certs).await
                    {
                        log::error!("handle tcp stream failed: {}", e);
                    }
                });
            }
        });
        self.handle = Some(handle);
        Ok(())
    }

    async fn handle_connect(
        stream: TcpStream,
        local_addr: SocketAddr,
        servers: StreamServerManagerRef,
        executor: ProcessChainListExecutor,
        certs: Arc<Mutex<HashMap<String, Arc<ServerConfig>>>>,
    ) -> StackResult<()> {
        let (ret, stream) = execute_chain(executor, Box::new(stream), local_addr)
            .await
            .map_err(into_stack_err!(StackErrorCode::ProcessChainError))?;
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
                        "server" => {
                            if list.len() < 2 {
                                return Err(stack_err!(
                                    StackErrorCode::InvalidConfig,
                                    "invalid server command"
                                ));
                            }
                            let server_name = list[1].as_str();

                            let tls_config = {
                                let certs = certs.lock().unwrap();
                                if let Some(cert) = certs.get(server_name) {
                                    cert.clone()
                                } else {
                                    return Ok(());
                                }
                            };

                            let tls_acceptor = TlsAcceptor::from(tls_config);
                            let tls_stream = tls_acceptor
                                .accept(stream)
                                .await
                                .map_err(into_stack_err!(StackErrorCode::StreamError))?;

                            if let Some(server) = servers.get_server(server_name) {
                                server
                                    .serve_connection(Box::new(tls_stream))
                                    .await
                                    .map_err(into_stack_err!(StackErrorCode::InvalidConfig))?;
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

impl Stack for TlsStack {
    fn stack_protocol(&self) -> StackProtocol {
        StackProtocol::Tls
    }

    fn get_bind_addr(&self) -> String {
        self.bind_addr.clone()
    }
}

pub struct TlsDomainConfig {
    pub domain: String,
    pub certs: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
}

pub struct TlsStackBuilder {
    bind: Option<String>,
    hook_point: Option<ProcessChainConfigs>,
    servers: Option<StreamServerManagerRef>,
    global_process_chains: Option<GlobalProcessChainsRef>,
    certs: Vec<TlsDomainConfig>,
}

impl TlsStackBuilder {
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
    pub fn servers(mut self, servers: StreamServerManagerRef) -> Self {
        self.servers = Some(servers);
        self
    }
    pub fn global_process_chains(mut self, global_process_chains: GlobalProcessChainsRef) -> Self {
        self.global_process_chains = Some(global_process_chains);
        self
    }
    pub async fn build(self) -> StackResult<TlsStack> {
        let stack = TlsStack::create(self).await?;
        Ok(stack)
    }
}

#[cfg(test)]
mod tests {
    use crate::global_process_chains::GlobalProcessChains;
    use crate::{
        GatewayDevice, ProcessChainConfigs, ServerResult, StreamServer, StreamServerManager,
        TunnelManager, GATEWAY_TUNNEL_MANAGER,
    };
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::TlsConnector;

    #[tokio::test]
    async fn test_tls_stack_creation() {
        let subject_alt_names = vec!["localhost".to_string(), "127.0.0.1".to_string()];
        let cert_key = generate_simple_self_signed(subject_alt_names).unwrap();
        let result = TlsStack::builder().build().await;
        assert!(result.is_err());
        let result = TlsStack::builder().bind("127.0.0.1:9080").build().await;
        assert!(result.is_err());
        let result = TlsStack::builder()
            .bind("127.0.0.1:9080")
            .servers(Arc::new(StreamServerManager::new()))
            .build()
            .await;
        assert!(result.is_err());
        let result = TlsStack::builder()
            .bind("127.0.0.1:9080")
            .servers(Arc::new(StreamServerManager::new()))
            .hook_point(vec![])
            .build()
            .await;
        assert!(result.is_ok());
        let result = TlsStack::builder()
            .bind("127.0.0.1:9080")
            .servers(Arc::new(StreamServerManager::new()))
            .hook_point(vec![])
            .add_certs(vec![TlsDomainConfig {
                domain: "localhost".to_string(),
                certs: vec![cert_key.cert.der().clone()],
                key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    cert_key.signing_key.serialize_der(),
                )),
            }])
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .build()
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_tls_stack_reject() {
        let subject_alt_names = vec!["localhost".to_string(), "127.0.0.1".to_string()];
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
            .bind("127.0.0.1:9080")
            .servers(Arc::new(StreamServerManager::new()))
            .hook_point(chains)
            .add_certs(vec![TlsDomainConfig {
                domain: "localhost".to_string(),
                certs: vec![cert_key.cert.der().clone()],
                key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    cert_key.signing_key.serialize_der(),
                )),
            }])
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .build()
            .await;
        assert!(result.is_ok());
        let mut stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());

        let mut stream = TcpStream::connect("127.0.0.1:9080").await.unwrap();
        let result = stream
            .write_all(b"GET / HTTP/1.1\r\nHost: httpbin.org\r\n\r\n")
            .await;
        assert!(result.is_ok());
        let ret = stream.read(&mut [0; 1024]).await;
        assert!(ret.is_err());
    }

    #[tokio::test]
    async fn test_tls_stack_drop() {
        let subject_alt_names = vec!["localhost".to_string(), "127.0.0.1".to_string()];
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
            .bind("127.0.0.1:9081")
            .servers(Arc::new(StreamServerManager::new()))
            .hook_point(chains)
            .add_certs(vec![TlsDomainConfig {
                domain: "localhost".to_string(),
                certs: vec![cert_key.cert.der().clone()],
                key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    cert_key.signing_key.serialize_der(),
                )),
            }])
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .build()
            .await;
        assert!(result.is_ok());
        let mut stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());

        let mut stream = TcpStream::connect("127.0.0.1:9081").await.unwrap();
        let result = stream
            .write_all(b"GET / HTTP/1.1\r\nHost: httpbin.org\r\n\r\n")
            .await;
        assert!(result.is_ok());
        let ret = stream.read(&mut [0; 1024]).await;
        assert!(ret.is_err());
    }

    pub struct MockServer;

    #[async_trait::async_trait]
    impl StreamServer for MockServer {
        async fn serve_connection(&self, mut stream: Box<dyn AsyncStream>) -> ServerResult<()> {
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"test");
            stream.write_all("recv".as_bytes()).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            Ok(())
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

        let server_manager = Arc::new(StreamServerManager::new());
        server_manager.add_server("www.buckyos.com".to_string(), Arc::new(MockServer));
        let result = TlsStack::builder()
            .bind("127.0.0.1:9085")
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
}
