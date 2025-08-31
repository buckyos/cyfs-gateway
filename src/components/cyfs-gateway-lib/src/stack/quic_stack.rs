use std::collections::HashMap;
use std::future::poll_fn;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use h3::quic;
use h3::server::{RequestResolver, RequestStream};
use http_body_util::combinators::BoxBody;
use hyper::body::{Body, Buf, Bytes, Frame};
use quinn::crypto::rustls::{HandshakeData, QuicServerConfig};
use quinn::Incoming;
use rustls::{server, sign, Error, ServerConfig};
use rustls::client::verify_server_name;
use rustls::pki_types::{DnsName, ServerName};
use rustls::server::{ClientHello, ParsedCertificate};
use rustls::sign::CertifiedKey;
use tokio::task::JoinHandle;
use cyfs_process_chain::{CollectionValue, CommandControl, MemoryMapCollection, ProcessChainLibExecutor};
use crate::{into_stack_err, stack_err, ProcessChainConfigs, Stack, StackErrorCode, StackProtocol, StackResult, ServerManagerRef, TlsDomainConfig, Server, server_err, ServerErrorCode, ServerError};
use crate::global_process_chains::{create_process_chain_executor, execute_chain, GlobalProcessChainsRef};
use crate::stack::stream_forward;

pub struct Http3Body<S, B> {
    stream: RequestStream<S, B>,
}

impl<S, B> Http3Body<S, B> {
    pub fn new(stream: RequestStream<S, B>) -> Self {
        Self {
            stream,
        }
    }
}

impl<S, B> Body for Http3Body<S, B>
where
    S: quic::RecvStream + 'static,
    B: Buf + 'static,
{
    type Data = Bytes;
    type Error = ServerError;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.stream.poll_recv_data(cx) {
            Poll::Ready(ret) => {
                match ret {
                    Ok(Some(mut ret)) => {
                        Poll::Ready(Some(Ok(Frame::data(ret.copy_to_bytes(ret.remaining())))))
                    }
                    Ok(None) => {
                        Poll::Ready(None)
                    }
                    Err(e) => {
                        Poll::Ready(Some(Err(server_err!(ServerErrorCode::IOError, "{}", e))))
                    }
                }
            }
            Poll::Pending => {
                Poll::Pending
            }
        }
    }
}
#[derive(Debug)]
struct ResolvesServerCertUsingSni {
    by_name: Mutex<HashMap<String, Arc<sign::CertifiedKey>>>,
}

impl ResolvesServerCertUsingSni {
    pub fn new() -> Self {
        Self {
            by_name: Mutex::new(HashMap::new()),
        }
    }

    pub fn add(&self, name: &str, ck: sign::CertifiedKey) -> Result<(), Error> {
        let server_name = {
            let checked_name = DnsName::try_from(name)
                .map_err(|_| Error::General("Bad DNS name".into()))
                .map(|name| name.to_lowercase_owned())?;
            ServerName::DnsName(checked_name)
        };

        ck.end_entity_cert()
            .and_then(ParsedCertificate::try_from)
            .and_then(|cert| verify_server_name(&cert, &server_name))?;

        if let ServerName::DnsName(name) = server_name {
            self.by_name.lock().unwrap()
                .insert(name.as_ref().to_string(), Arc::new(ck));
        }
        Ok(())
    }
}

impl server::ResolvesServerCert for ResolvesServerCertUsingSni {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<sign::CertifiedKey>> {
        if let Some(name) = client_hello.server_name() {
            self.by_name.lock().unwrap().get(name).cloned()
        } else {
            None
        }
    }
}

struct QuicStackInner {
    bind_addr: String,
    concurrency: u32,
    certs: Arc<ResolvesServerCertUsingSni>,
    alpn_protocols: Vec<Vec<u8>>,
    servers: ServerManagerRef,
    executor: Arc<Mutex<ProcessChainLibExecutor>>,
}

impl QuicStackInner {
    async fn start(self: &Arc<Self>) -> StackResult<JoinHandle<()>> {
        let mut server_config = ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
            .with_protocol_versions(rustls::DEFAULT_VERSIONS)
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(self.certs.clone());
        server_config.alpn_protocols = self.alpn_protocols.clone();
        server_config.max_early_data_size = u32::MAX;
        let server_config = quinn::ServerConfig::with_crypto(
            Arc::new(QuicServerConfig::try_from(server_config)

                .map_err(into_stack_err!(StackErrorCode::InvalidConfig))?));
        let endpoint = quinn::Endpoint::server(server_config,
                                               self.bind_addr.parse()
                                                   .map_err(into_stack_err!(StackErrorCode::InvalidConfig))?)
            .map_err(|e| {
                println!("{}", e);
                into_stack_err!(StackErrorCode::InvalidConfig)(e)
            })?;

        let this = self.clone();
        let handle = tokio::spawn(async move {
            loop {
                match endpoint.accept().await {
                    None => {
                        log::error!("quic endpoint accept error");
                        break;
                    }
                    Some(conn) => {
                        if endpoint.open_connections() > this.concurrency as usize {
                            conn.refuse();
                            continue;
                        }
                        let this = this.clone();
                        tokio::spawn(async move {
                            if let Err(e) = this.accept(conn).await {
                                log::error!("quic accept error: {}", e);
                            }
                        });
                    }
                }
            }
        });
        Ok(handle)
    }

    async fn accept(self: &Arc<Self>, conn: Incoming) -> StackResult<()> {
        let connection = conn.await.map_err(into_stack_err!(StackErrorCode::QuicError))?;
        let server_name = {
            let handshake_data = connection.handshake_data();
            if handshake_data.is_none() {
                return Err(stack_err!(StackErrorCode::QuicError, "handshake data is None"));
            }
            let handshake_data = handshake_data.as_ref().unwrap().as_ref().downcast_ref::<HandshakeData>();
            if handshake_data.is_none() {
                return Err(stack_err!(StackErrorCode::QuicError, "handshake data is None"));
            }

            let server_name = handshake_data.unwrap().server_name.as_ref();
            if server_name.is_none() {
                return Err(stack_err!(StackErrorCode::QuicError, "server name is None"));
            }
            server_name.unwrap().to_string()
        };

        let remote_addr = connection.remote_address();
        let map = MemoryMapCollection::new_ref();
        map.insert("dest_host", CollectionValue::String(server_name)).await.map_err(|e| stack_err!(StackErrorCode::ProcessChainError, "{e}"))?;
        map.insert("source_addr", CollectionValue::String(remote_addr.ip().to_string())).await.map_err(|e| stack_err!(StackErrorCode::ProcessChainError, "{e}"))?;
        map.insert("source_port", CollectionValue::String(remote_addr.port().to_string())).await.map_err(|e| stack_err!(StackErrorCode::ProcessChainError, "{e}"))?;

        let executor = {
            self.executor.lock().unwrap().fork()
        };
        let ret = execute_chain(executor, map)
            .await
            .map_err(into_stack_err!(StackErrorCode::ProcessChainError))?;
        if ret.is_control() {
            if ret.is_drop() {
                connection.close(0u32.into(), "".as_bytes());
                return Ok(());
            } else if ret.is_reject() {
                connection.close(0u32.into(), "".as_bytes());
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
                            loop {
                                let (send, recv) = connection.accept_bi().await.map_err(into_stack_err!(StackErrorCode::QuicError))?;
                                let stream = sfo_split::Splittable::new(recv, send);
                                let target = list[1].clone();
                                tokio::spawn(async move {
                                    if let Err(e) = stream_forward(Box::new(stream), target.as_str()).await {
                                        log::error!("stream forward error: {}", e);
                                    }
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
                            let server_name = list[1].as_str();
                            if let Some(server) = self.servers.get_server(server_name) {
                                match server {
                                    Server::Http(server) => {
                                        let mut h3_conn = match h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(connection))
                                            .await {
                                            Ok(h3_conn) => h3_conn,
                                            Err(e) => {
                                                return if e.is_h3_no_error() {
                                                    Ok(())
                                                } else {
                                                    Err(stack_err!(StackErrorCode::QuicError, "h3 new error: {e}"))
                                                }
                                            }
                                        };
                                        loop {
                                            let resolver = match h3_conn.accept().await {
                                                Ok(resolver) => resolver,
                                                Err(e) => {
                                                    if e.is_h3_no_error() {
                                                        break;
                                                    } else {
                                                        return Err(stack_err!(StackErrorCode::QuicError, "h3 accept error: {e}"))
                                                    }
                                                }
                                            };
                                            if resolver.is_none() {
                                                break;
                                            }
                                            let server = server.clone();
                                            tokio::spawn(async move {
                                                let ret: StackResult<()> = async move {
                                                    let (req, stream) = resolver.unwrap().resolve_request().await
                                                        .map_err(into_stack_err!(StackErrorCode::QuicError, "h3 resolve request error"))?;
                                                    let (parts, _) = req.into_parts();
                                                    let (mut send, recv) = stream.split();
                                                    let req = http::Request::from_parts(parts, BoxBody::new(Http3Body::new(recv)));
                                                    let resp = server
                                                        .serve_request(req)
                                                        .await
                                                        .map_err(into_stack_err!(StackErrorCode::InvalidConfig))?;
                                                    let (parts, mut body) = resp.into_parts();
                                                    let resp = http::Response::from_parts(parts, ());
                                                    send.send_response(resp)
                                                        .await
                                                        .map_err(into_stack_err!(StackErrorCode::QuicError, "h3 send response error"))?;
                                                    loop {
                                                        let mut pin_body = Pin::new(&mut body);
                                                        let data = poll_fn(move |cx| {
                                                            pin_body.as_mut().poll_frame(cx)
                                                        }).await;
                                                        match data {
                                                            Some(data) => {
                                                                let data = data.map_err(into_stack_err!(StackErrorCode::QuicError, "h3 map error"))?;
                                                                send.send_data(data.into_data()
                                                                    .map_err(|_e| stack_err!(StackErrorCode::QuicError, "h3 data error"))?).await
                                                                    .map_err(into_stack_err!(StackErrorCode::QuicError, "h3 send data error"))?;
                                                            }
                                                            None => {
                                                                break;
                                                            }
                                                        }
                                                    }
                                                    send.finish().await
                                                        .map_err(into_stack_err!(StackErrorCode::QuicError, "h3 finish error"))?;
                                                    Ok(())
                                                }.await;
                                                if let Err(e) = ret {
                                                    log::error!("server error: {}", e);
                                                }
                                            });
                                        }
                                    }
                                    Server::Stream(server) => {
                                        loop {
                                            let (send, recv) = connection.accept_bi().await.map_err(into_stack_err!(StackErrorCode::QuicError))?;
                                            let server = server.clone();
                                            tokio::spawn(async move {
                                                let stream = sfo_split::Splittable::new(recv, send);
                                                if let Err(e) = server.serve_connection(Box::new(stream)).await {
                                                    log::error!("server error: {}", e);
                                                }
                                            });
                                        }
                                    }
                                    Server::Datagram(_) => {
                                        return Err(stack_err!(
                                            StackErrorCode::InvalidConfig,
                                            "Unsupport server type"
                                        ));
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

pub struct QuicStack {
    inner: Arc<QuicStackInner>,
    handle: Option<JoinHandle<()>>,
}

impl QuicStack {
    pub fn builder() -> QuicStackBuilder {
        QuicStackBuilder::new()
    }

    async fn create(builder: QuicStackBuilder) -> StackResult<Self> {
        if builder.bind.is_none() {
            return Err(stack_err!(StackErrorCode::InvalidConfig, "bind is required"));
        }
        if builder.hook_point.is_none() {
            return Err(stack_err!(StackErrorCode::InvalidConfig, "hook_point is required"));
        }
        if builder.servers.is_none() {
            return Err(stack_err!(StackErrorCode::InvalidConfig, "servers is required"));
        }

        let (executor, _) = create_process_chain_executor(builder.hook_point.as_ref().unwrap(),
                                                          builder.global_process_chains).await
            .map_err(into_stack_err!(StackErrorCode::InvalidConfig))?;

        let crypto_provider = rustls::crypto::ring::default_provider();
        let cert_resolver = Arc::new(ResolvesServerCertUsingSni::new());
        for cert_config in builder.certs.into_iter() {
            let cert_key = CertifiedKey::from_der(cert_config.certs, cert_config.key, &crypto_provider)
                .map_err(into_stack_err!(StackErrorCode::InvalidTlsCert))?;
            cert_resolver.add(&cert_config.domain, cert_key)
                .map_err(into_stack_err!(StackErrorCode::InvalidConfig, "add cert failed"))?;
        }

        Ok(QuicStack {
            inner: Arc::new(QuicStackInner {
                bind_addr: builder.bind.unwrap(),
                concurrency: builder.concurrency,
                certs: cert_resolver,
                alpn_protocols: builder.alpn_protocols,
                servers: builder.servers.unwrap(),
                executor: Arc::new(Mutex::new(executor)),
            }),
            handle: None,
        })
    }

    pub async fn start(&mut self) -> StackResult<()> {
        let handle = self.inner.start().await?;
        self.handle = Some(handle);
        Ok(())
    }
}

impl Stack for QuicStack {
    fn stack_protocol(&self) -> StackProtocol {
        StackProtocol::Quic
    }

    fn get_bind_addr(&self) -> String {
        self.inner.bind_addr.clone()
    }
}

pub struct QuicStackBuilder {
    bind: Option<String>,
    hook_point: Option<ProcessChainConfigs>,
    servers: Option<ServerManagerRef>,
    global_process_chains: Option<GlobalProcessChainsRef>,
    certs: Vec<TlsDomainConfig>,
    alpn_protocols: Vec<Vec<u8>>,
    concurrency: u32,
}

impl QuicStackBuilder {
    fn new() -> Self {
        QuicStackBuilder {
            bind: None,
            hook_point: None,
            servers: None,
            global_process_chains: None,
            certs: vec![],
            concurrency: 1024,
            alpn_protocols: vec![],
        }
    }
    pub fn bind(mut self, bind: &str) -> Self {
        self.bind = Some(bind.to_string());
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

    pub fn add_certs(mut self, certs: Vec<TlsDomainConfig>) -> Self {
        self.certs = certs;
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

    pub fn alpn_protocols(mut self, alpn: Vec<Vec<u8>>) -> Self {
        self.alpn_protocols = alpn;
        self
    }

    pub async fn build(self) -> StackResult<QuicStack> {
        QuicStack::create(self).await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use buckyos_kit::AsyncStream;
    use h3::error::{ConnectionError, StreamError};
    use name_lib::{encode_ed25519_sk_to_pk_jwk, generate_ed25519_key, DeviceConfig};
    use quinn::crypto::rustls::QuicClientConfig;
    use quinn::Endpoint;
    use rcgen::generate_simple_self_signed;
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::{ClientConfig, DigitallySignedStruct, Error, SignatureScheme};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use crate::{GatewayDevice, ProcessChainConfigs, QuicStack, ServerResult, StreamServer, ServerManager, TlsDomainConfig, TunnelManager, GATEWAY_TUNNEL_MANAGER, Server, ProcessChainHttpServer, InnerHttpServiceManager};
    use crate::global_process_chains::GlobalProcessChains;

    #[tokio::test]
    async fn test_quic_stack_creation() {
        let subject_alt_names = vec!["www.buckyos.com".to_string(), "127.0.0.1".to_string()];
        let cert_key = generate_simple_self_signed(subject_alt_names).unwrap();
        let result = QuicStack::builder().build().await;
        assert!(result.is_err());
        let result = QuicStack::builder().bind("127.0.0.1:9080").build().await;
        assert!(result.is_err());
        let result = QuicStack::builder()
            .bind("127.0.0.1:9080")
            .servers(Arc::new(ServerManager::new()))
            .build()
            .await;
        assert!(result.is_err());
        let result = QuicStack::builder()
            .bind("127.0.0.1:9080")
            .servers(Arc::new(ServerManager::new()))
            .hook_point(vec![])
            .build()
            .await;
        assert!(result.is_ok());
        let result = QuicStack::builder()
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
            .build()
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_quic_stack_reject() {
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

        let result = QuicStack::builder()
            .bind("127.0.0.1:9180")
            .servers(Arc::new(ServerManager::new()))
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

        let mut config = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(rustls::DEFAULT_VERSIONS).unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();
        config.enable_early_data = true;
        // config.alpn_protocols = vec![b"h3".to_vec()];
        let client_config =
            quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(config).unwrap()));
        let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(client_config);
        let ret = endpoint.connect("127.0.0.1:9180".parse().unwrap(), "www.buckyos.com").unwrap();
        let ret = ret.await.unwrap();
        let (mut send, mut recv) = ret.open_bi().await.unwrap();
        let result = send
            .write_all(b"GET / HTTP/1.1\r\nHost: httpbin.org\r\n\r\n")
            .await;
        assert!(result.is_ok());
        let ret = recv.read(&mut [0; 1024]).await;
        assert!(ret.is_err());
    }

    #[tokio::test]
    async fn test_quic_stack_drop() {
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

        let result = QuicStack::builder()
            .bind("127.0.0.1:9181")
            .servers(Arc::new(ServerManager::new()))
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

        let mut config = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(rustls::DEFAULT_VERSIONS).unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();
        config.enable_early_data = true;
        // config.alpn_protocols = vec![b"h3".to_vec()];
        let client_config =
            quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(config).unwrap()));
        let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(client_config);
        let ret = endpoint.connect("127.0.0.1:9181".parse().unwrap(), "www.buckyos.com").unwrap();
        let ret = ret.await.unwrap();
        let (mut send, mut recv) = ret.open_bi().await.unwrap();
        let result = send
            .write_all(b"GET / HTTP/1.1\r\nHost: httpbin.org\r\n\r\n")
            .await;
        assert!(result.is_ok());
        let ret = recv.read(&mut [0; 1024]).await;
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
    async fn test_quic_stack_server() {
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
        let result = QuicStack::builder()
            .bind("127.0.0.1:9185")
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

        let mut config = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(rustls::DEFAULT_VERSIONS).unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();
        config.enable_early_data = true;
        // config.alpn_protocols = vec![b"h3".to_vec()];
        let client_config =
            quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(config).unwrap()));
        let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(client_config);
        let ret = endpoint.connect("127.0.0.1:9185".parse().unwrap(), "www.buckyos.com").unwrap();
        let ret = ret.await.unwrap();
        let (mut send, mut recv) = ret.open_bi().await.unwrap();
        let result = send.write_all(b"test").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 4];
        let ret = recv.read_exact(&mut buf).await;
        assert!(ret.is_ok());
        assert_eq!(&buf, b"recv");

        let ret = endpoint.connect("127.0.0.1:9185".parse().unwrap(), "www.buckyos.com").unwrap();
        let ret = ret.await.unwrap();
        let (mut send, mut recv) = ret.open_bi().await.unwrap();
        let result = send.write_all(b"test").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 4];
        let ret = recv.read_exact(&mut buf).await;
        assert!(ret.is_ok());
        assert_eq!(&buf, b"recv");
    }

    #[tokio::test]
    async fn test_http3_server() {
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
            .version("HTTP/3")
            .h3_port(9186)
            .hook_point(chains)
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .inner_services(Arc::new(InnerHttpServiceManager::new()))
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

        let result = QuicStack::builder()
            .bind("127.0.0.1:9186")
            .servers(server_manager)
            .hook_point(chains)
            .add_certs(vec![TlsDomainConfig {
                domain: "www.buckyos.com".to_string(),
                certs: vec![cert_key.cert.der().clone()],
                key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    cert_key.signing_key.serialize_der(),
                )),
            }])
            .alpn_protocols(vec![b"h2".to_vec(), b"h3".to_vec()])
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

        let mut config = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(rustls::DEFAULT_VERSIONS).unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();
        config.alpn_protocols = vec![b"h3".to_vec()];
        let client_config =
            quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(config).unwrap()));
        let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(client_config);
        let ret = endpoint.connect("127.0.0.1:9186".parse().unwrap(), "www.buckyos.com").unwrap();
        let ret = ret.await.unwrap();
        let quinn_conn = h3_quinn::Connection::new(ret);
        let (mut driver, mut send_request) = h3::client::new(quinn_conn).await.unwrap();
        let drive = async move {
            return Err::<(), ConnectionError>(std::future::poll_fn(|cx| driver.poll_close(cx)).await);
        };

        let request = async move {
            let req = http::Request::builder().uri("https://www.buckyos.com/").body(()).unwrap();
            let mut stream = send_request.send_request(req).await?;

            stream.finish().await?;
            let resp = stream.recv_response().await?;

            assert_eq!(resp.status(), http::StatusCode::FORBIDDEN);
            assert_eq!(resp.version(), http::Version::HTTP_3);

            Ok::<_, StreamError>(())
        };

        let (req_res, drive_res) = tokio::join!(request, drive);

        assert!(req_res.is_ok());


        let ret = endpoint.connect("127.0.0.1:9186".parse().unwrap(), "www.buckyos.com").unwrap();
        let ret = ret.await.unwrap();
        let quinn_conn = h3_quinn::Connection::new(ret);
        let (mut driver, mut send_request) = h3::client::new(quinn_conn).await.unwrap();
        let drive = async move {
            return Err::<(), ConnectionError>(std::future::poll_fn(|cx| driver.poll_close(cx)).await);
        };

        let request = async move {
            let req = http::Request::builder().uri("https://www.buckyos.com/").body(()).unwrap();
            let mut stream = send_request.send_request(req).await?;

            stream.finish().await?;
            let resp = stream.recv_response().await?;

            assert_eq!(resp.status(), http::StatusCode::FORBIDDEN);
            assert_eq!(resp.version(), http::Version::HTTP_3);

            Ok::<_, StreamError>(())
        };

        let (req_res, drive_res) = tokio::join!(request, drive);

        assert!(req_res.is_ok());
    }

    #[tokio::test]
    async fn test_quic_server_forward() {
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "forward tcp:///127.0.0.1:9183";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let subject_alt_names = vec!["www.buckyos.com".to_string(), "127.0.0.1".to_string()];
        let cert_key = generate_simple_self_signed(subject_alt_names).unwrap();
        let server_manager = Arc::new(ServerManager::new());
        let result = QuicStack::builder()
            .bind("127.0.0.1:9188")
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

        tokio::spawn(async move {
            let tcp_listener = TcpListener::bind("127.0.0.1:9183").await.unwrap();
            if let Ok((mut tcp_stream, _)) = tcp_listener.accept().await {
                let mut buf = [0u8; 4];
                tcp_stream.read_exact(&mut buf).await.unwrap();
                assert_eq!(&buf, b"test");
                tcp_stream.write_all("recv".as_bytes()).await.unwrap();
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        });

        let mut config = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(rustls::DEFAULT_VERSIONS).unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();
        config.enable_early_data = true;
        let client_config =
            quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(config).unwrap()));
        let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(client_config);
        let ret = endpoint.connect("127.0.0.1:9188".parse().unwrap(), "www.buckyos.com").unwrap();
        let ret = ret.await.unwrap();
        let (mut send, mut recv) = ret.open_bi().await.unwrap();
        let result = send.write_all(b"test").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 4];
        let ret = recv.read_exact(&mut buf).await;
        assert!(ret.is_ok());
        assert_eq!(&buf, b"recv");
    }
}
