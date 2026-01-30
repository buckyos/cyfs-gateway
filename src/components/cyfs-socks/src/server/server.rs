use super::config::SocksServerConfig;
use crate::{Socks5Proxy, SocksDataTunnelProviderRef, SocksHookManager, SocksProxyAuth, SocksProxyConfig};
use buckyos_kit::AsyncStream;
use cyfs_gateway_lib::{server_err, GlobalProcessChainsRef, Server, ServerConfig, ServerContext, ServerContextRef, ServerErrorCode, ServerFactory, ServerResult, StreamServer, StreamInfo, GlobalCollectionManagerRef};
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
    pub global_collection_manager: GlobalCollectionManagerRef,
    pub tunnel_provider: SocksDataTunnelProviderRef,
}

impl SocksServerContext {
    pub fn new(
        global_process_chains: GlobalProcessChainsRef,
        global_collection_manager: GlobalCollectionManagerRef,
        tunnel_provider: SocksDataTunnelProviderRef,
    ) -> Self {
        Self {
            global_process_chains,
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
