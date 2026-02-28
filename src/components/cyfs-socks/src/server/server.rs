use super::config::SocksServerConfig;
use crate::{Socks5Proxy, SocksDataTunnelProviderRef, SocksHookManager, SocksProxyAuth, SocksProxyConfig};
use buckyos_kit::AsyncStream;
use cyfs_gateway_lib::{server_err, GlobalProcessChainsRef, JsExternalsManagerRef, Server, ServerConfig, ServerContext, ServerContextRef, ServerErrorCode, ServerFactory, ServerResult, StreamServer, StreamInfo, GlobalCollectionManagerRef};
use std::sync::Arc;

pub struct SocksServer {
    proxy: Socks5Proxy,
}

impl SocksServer {
    pub fn new(proxy: Socks5Proxy) -> Self {
        Self { proxy }
    }
}

#[async_trait::async_trait]
impl StreamServer for SocksServer {
    async fn serve_connection(&self, stream: Box<dyn AsyncStream>, info: StreamInfo) -> ServerResult<()> {
        self.proxy
            .handle_new_connection(stream, info)
            .await
            .map_err(|e| {
                server_err!(
                    ServerErrorCode::StreamError,
                    "socks5 proxy handle connection failed: {}",
                    e
                )
            })?;

        Ok(())
    }

    fn id(&self) -> String {
        self.proxy.id().to_string()
    }
}

#[derive(Clone)]
pub struct SocksServerContext {
    pub global_process_chains: GlobalProcessChainsRef,
    pub js_externals: JsExternalsManagerRef,
    pub global_collection_manager: GlobalCollectionManagerRef,
    pub tunnel_provider: SocksDataTunnelProviderRef,
}

impl SocksServerContext {
    pub fn new(
        global_process_chains: GlobalProcessChainsRef,
        js_externals: JsExternalsManagerRef,
        global_collection_manager: GlobalCollectionManagerRef,
        tunnel_provider: SocksDataTunnelProviderRef,
    ) -> Self {
        Self {
            global_process_chains,
            js_externals,
            global_collection_manager,
            tunnel_provider,
        }
    }
}

impl ServerContext for SocksServerContext {
    fn get_server_type(&self) -> String {
        "socks".to_string()
    }
}

pub struct SocksServerFactory;

impl SocksServerFactory {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl ServerFactory for SocksServerFactory {
    async fn create(
        &self,
        config: Arc<dyn ServerConfig>,
        context: Option<ServerContextRef>,
    ) -> ServerResult<Vec<Server>> {
        let config = config
            .as_any()
            .downcast_ref::<SocksServerConfig>()
            .ok_or(server_err!(
                ServerErrorCode::InvalidConfig,
                "invalid socks server config"
            ))?;

        // Load the hook point
        let process_chain_lib = config.parse_process_chain().map_err(|e| {
            server_err!(
                ServerErrorCode::InvalidConfig,
                "parse process chain failed: {}",
                e
            )
        })?;

        let context = context.ok_or(server_err!(
            ServerErrorCode::InvalidConfig,
            "socks server context is required"
        ))?;
        let context = context
            .as_ref()
            .as_any()
            .downcast_ref::<SocksServerContext>()
            .ok_or(server_err!(
                ServerErrorCode::InvalidConfig,
                "invalid socks server context"
            ))?;

        let global_process_chains = context.global_process_chains.get_process_chains();
        let hook_point = SocksHookManager::create(process_chain_lib,
                                                   global_process_chains,
                                                   context.global_collection_manager.clone())
            .await
            .map_err(|e| {
                server_err!(
                    ServerErrorCode::InvalidConfig,
                    "create socks hook manager failed: {}",
                    e
                )
            })?;
        let hook_point = Arc::new(hook_point);

        let auth = if config.username.is_some() && config.password.is_some() {
            SocksProxyAuth::Password(config.username.clone().unwrap(), config.password.clone().unwrap())
        } else {
            SocksProxyAuth::None
        };
        let proxy_config = SocksProxyConfig {
            id: config.id.clone(),
            target: config.target.clone(),
            enable_tunnel: config.enable_tunnel.clone(),
            auth,
            rule_config: config.rule_config.clone(),
            rule_engine: None,
        };

        let socks_server = Socks5Proxy::new(proxy_config, hook_point.clone());
        socks_server.set_data_tunnel_provider(context.tunnel_provider.clone());
        let server = SocksServer::new(socks_server);
        let server = Server::Stream(Arc::new(server) as Arc<dyn StreamServer>);

        Ok(vec![server])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SocksDataTunnelProvider, SocksError, SocksResult};
    use buckyos_kit::AsyncStream;
    use cyfs_gateway_lib::{BlockConfig, GlobalCollectionManager, GlobalProcessChains, ProcessChainConfig};
    use fast_socks5::consts;
    use fast_socks5::util::target_addr::TargetAddr;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex, Once};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
    use tokio::net::{TcpListener, TcpStream};
    use url::Url;

    #[derive(Clone, Default)]
    struct MockTunnelProvider {
        call_count: Arc<AtomicUsize>,
        last_proxy_target: Arc<Mutex<Option<String>>>,
    }

    impl MockTunnelProvider {
        fn calls(&self) -> usize {
            self.call_count.load(Ordering::SeqCst)
        }

        fn last_proxy_target(&self) -> Option<String> {
            self.last_proxy_target.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl SocksDataTunnelProvider for MockTunnelProvider {
        async fn build(
            &self,
            target: &TargetAddr,
            proxy_target: &Url,
            _enable_tunnel: &Option<Vec<String>>,
        ) -> SocksResult<Box<dyn AsyncStream>> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            *self.last_proxy_target.lock().unwrap() = Some(proxy_target.to_string());

            let addr = match target {
                TargetAddr::Ip(addr) => *addr,
                TargetAddr::Domain(domain, port) => {
                    let mut resolved = tokio::net::lookup_host((domain.as_str(), *port))
                        .await
                        .map_err(|e| SocksError::IoError(format!("resolve domain failed: {}", e)))?;
                    resolved.next().ok_or_else(|| {
                        SocksError::InvalidAddress(format!("resolve domain {} failed", domain))
                    })?
                }
            };

            let stream = TcpStream::connect(addr)
                .await
                .map_err(|e| SocksError::IoError(format!("connect target failed: {}", e)))?;

            Ok(Box::new(stream))
        }
    }

    fn ensure_test_root() {
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let root = std::env::temp_dir().join(format!(
                "cyfs-socks-tests-{}-{}",
                std::process::id(),
                nanos
            ));
            std::fs::create_dir_all(&root).unwrap();
            unsafe {
                std::env::set_var("BUCKYOS_ROOT", root.as_os_str());
            }
        });
    }

    fn provider_ref(provider: MockTunnelProvider) -> SocksDataTunnelProviderRef {
        Arc::new(Box::new(provider) as Box<dyn SocksDataTunnelProvider>)
    }

    async fn create_socks_stream_server(
        block: &str,
        provider: SocksDataTunnelProviderRef,
    ) -> Arc<dyn StreamServer> {
        ensure_test_root();

        let config = SocksServerConfig {
            id: "test-socks".to_string(),
            username: None,
            password: None,
            target: Url::parse("socks5://127.0.0.1:1080").unwrap(),
            enable_tunnel: None,
            rule_config: None,
            hook_point: vec![ProcessChainConfig {
                id: "main".to_string(),
                priority: 1,
                blocks: vec![BlockConfig {
                    id: "main".to_string(),
                    priority: 1,
                    block: block.to_string(),
                }],
            }],
        };

        let context = SocksServerContext::new(
            Arc::new(GlobalProcessChains::new()),
            GlobalCollectionManager::create(vec![]).await.unwrap(),
            provider,
        );
        let factory = SocksServerFactory::new();
        let servers = factory
            .create(Arc::new(config), Some(Arc::new(context)))
            .await
            .unwrap();

        assert_eq!(servers.len(), 1);
        match servers.into_iter().next().unwrap() {
            Server::Stream(server) => server,
            _ => panic!("expect stream server"),
        }
    }

    async fn start_echo_server() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let n = socket.read(&mut buf).await.unwrap();
            if n > 0 {
                socket.write_all(&buf[..n]).await.unwrap();
            }
        });

        addr
    }

    async fn socks5_connect_ipv4(client: &mut DuplexStream, target: SocketAddrV4) -> u8 {
        client
            .write_all(&[consts::SOCKS5_VERSION, 1, consts::SOCKS5_AUTH_METHOD_NONE])
            .await
            .unwrap();

        let mut auth_reply = [0u8; 2];
        client.read_exact(&mut auth_reply).await.unwrap();
        assert_eq!(auth_reply, [consts::SOCKS5_VERSION, consts::SOCKS5_AUTH_METHOD_NONE]);

        let mut req = vec![
            consts::SOCKS5_VERSION,
            consts::SOCKS5_CMD_TCP_CONNECT,
            0x00,
            consts::SOCKS5_ADDR_TYPE_IPV4,
        ];
        req.extend_from_slice(&target.ip().octets());
        req.extend_from_slice(&target.port().to_be_bytes());

        client.write_all(&req).await.unwrap();

        let mut reply_head = [0u8; 4];
        client.read_exact(&mut reply_head).await.unwrap();
        let atyp = reply_head[3];
        match atyp {
            consts::SOCKS5_ADDR_TYPE_IPV4 => {
                let mut rest = [0u8; 6];
                client.read_exact(&mut rest).await.unwrap();
            }
            consts::SOCKS5_ADDR_TYPE_DOMAIN_NAME => {
                let mut len_buf = [0u8; 1];
                client.read_exact(&mut len_buf).await.unwrap();
                let mut rest = vec![0u8; len_buf[0] as usize + 2];
                client.read_exact(&mut rest).await.unwrap();
            }
            consts::SOCKS5_ADDR_TYPE_IPV6 => {
                let mut rest = [0u8; 18];
                client.read_exact(&mut rest).await.unwrap();
            }
            _ => panic!("unknown atyp {}", atyp),
        }

        reply_head[1]
    }

    #[tokio::test]
    async fn test_socks_server_reject_connection() {
        let provider = MockTunnelProvider::default();
        let socks_server =
            create_socks_stream_server("reject;", provider_ref(provider.clone())).await;

        let (mut client, server_stream) = tokio::io::duplex(1024);
        let task = tokio::spawn(async move {
            socks_server
                .serve_connection(Box::new(server_stream), StreamInfo::default())
                .await
        });

        let target = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 10080);
        let rep = socks5_connect_ipv4(&mut client, target).await;
        assert_eq!(rep, fast_socks5::ReplyError::HostUnreachable.as_u8());
        assert_eq!(provider.calls(), 0);

        drop(client);
        let ret = tokio::time::timeout(std::time::Duration::from_secs(3), task)
            .await
            .unwrap()
            .unwrap();
        assert!(ret.is_ok());
    }

    #[tokio::test]
    async fn test_socks_server_accept_direct_connection() {
        let provider = MockTunnelProvider::default();
        let socks_server =
            create_socks_stream_server("return \"DIRECT\";", provider_ref(provider.clone()))
                .await;

        let target_addr = start_echo_server().await;
        let (mut client, server_stream) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            socks_server
                .serve_connection(Box::new(server_stream), StreamInfo::default())
                .await
        });

        let target = SocketAddrV4::new(Ipv4Addr::LOCALHOST, target_addr.port());
        let rep = socks5_connect_ipv4(&mut client, target).await;
        assert_eq!(rep, fast_socks5::ReplyError::Succeeded.as_u8());

        let payload = b"direct-path-ok";
        client.write_all(payload).await.unwrap();
        let mut recv = vec![0u8; payload.len()];
        client.read_exact(&mut recv).await.unwrap();
        assert_eq!(recv, payload);
        assert_eq!(provider.calls(), 0);

        drop(client);
        let ret = tokio::time::timeout(std::time::Duration::from_secs(3), task)
            .await
            .unwrap()
            .unwrap();
        assert!(ret.is_ok());
    }

    #[tokio::test]
    async fn test_socks_server_proxy_connection() {
        let provider = MockTunnelProvider::default();
        let socks_server = create_socks_stream_server(
            "return \"PROXY socks://proxy.example:1080\";",
            provider_ref(provider.clone()),
        )
            .await;

        let target_addr = start_echo_server().await;
        let (mut client, server_stream) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            socks_server
                .serve_connection(Box::new(server_stream), StreamInfo::default())
                .await
        });

        let target = SocketAddrV4::new(Ipv4Addr::LOCALHOST, target_addr.port());
        let rep = socks5_connect_ipv4(&mut client, target).await;
        assert_eq!(rep, fast_socks5::ReplyError::Succeeded.as_u8());

        let payload = b"proxy-path-ok";
        client.write_all(payload).await.unwrap();
        let mut recv = vec![0u8; payload.len()];
        client.read_exact(&mut recv).await.unwrap();
        assert_eq!(recv, payload);

        assert_eq!(provider.calls(), 1);
        assert_eq!(
            provider.last_proxy_target().as_deref(),
            Some("socks://proxy.example:1080")
        );

        drop(client);
        let ret = tokio::time::timeout(std::time::Duration::from_secs(3), task)
            .await
            .unwrap()
            .unwrap();
        assert!(ret.is_ok());
    }
}
