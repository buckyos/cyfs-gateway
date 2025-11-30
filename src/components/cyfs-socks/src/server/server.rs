use super::config::SocksServerConfig;
use crate::{Socks5Proxy, SocksHookManager, SocksProxyConfig};
use buckyos_kit::AsyncStream;
use cyfs_gateway_lib::{
    server_err, GlobalProcessChainsRef, Server, ServerConfig, ServerErrorCode, ServerFactory,
    ServerResult, StreamServer, StreamInfo,
};
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

pub struct SocksServerFactory {
    global_process_chains: GlobalProcessChainsRef,
}

impl SocksServerFactory {
    pub fn new(global_process_chains: GlobalProcessChainsRef) -> Self {
        Self {
            global_process_chains,
        }
    }
}

#[async_trait::async_trait]
impl ServerFactory for SocksServerFactory {
    async fn create(&self, config: Arc<dyn ServerConfig>) -> ServerResult<Vec<Server>> {
        let config = config
            .as_any()
            .downcast_ref::<SocksServerConfig>()
            .ok_or(server_err!(
                ServerErrorCode::InvalidConfig,
                "invalid config"
            ))?;

        // Load the hook point
        let process_chain_lib = config.parse_process_chain().map_err(|e| {
            server_err!(
                ServerErrorCode::InvalidConfig,
                "parse process chain failed: {}",
                e
            )
        })?;

        let global_process_chains = self.global_process_chains.get_process_chains();
        let hook_point = SocksHookManager::create(process_chain_lib, global_process_chains)
            .await
            .map_err(|e| {
                server_err!(
                    ServerErrorCode::InvalidConfig,
                    "create socks hook manager failed: {}",
                    e
                )
            })?;
        let hook_point = Arc::new(hook_point);

        let proxy_config = SocksProxyConfig {
            id: config.id.clone(),
            target: config.target.clone(),
            enable_tunnel: config.enable_tunnel.clone(),
            auth: config.auth.clone(),
            rule_config: config.rule_config.clone(),
            rule_engine: None,
        };

        let socks_server = Socks5Proxy::new(proxy_config, hook_point.clone());
        let server = SocksServer::new(socks_server);
        let server = Server::Stream(Arc::new(server) as Arc<dyn StreamServer>);

        Ok(vec![server])
    }
}
