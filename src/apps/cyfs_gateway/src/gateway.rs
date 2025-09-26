use std::path::PathBuf;
use std::sync::Arc;
use super::config_loader::GatewayConfig;
use super::dispatcher::ServiceDispatcher;
use cyfs_dns::start_cyfs_dns_server;
use cyfs_dns::DNSServer;
use cyfs_gateway_lib::{ConnectionManager, ConnectionManagerRef, CyfsInnerServiceFactory, CyfsServerFactory, CyfsStackFactory, GlobalProcessChains, GlobalProcessChainsRef, InnerServiceFactory, InnerServiceManager, InnerServiceManagerRef, ProcessChainConfigs, QuicStackFactory, RtcpStackFactory, ServerConfig, ServerFactory, ServerManager, ServerManagerRef, StackFactory, StackManager, StackProtocol, TcpStackFactory, TlsStackFactory, UdpStackFactory};
use cyfs_gateway_lib::{GatewayDevice, GatewayDeviceRef, TunnelManager};
use cyfs_socks::Socks5Proxy;
use cyfs_warp::start_cyfs_warp_server;
use cyfs_warp::CyfsWarpServer;
use name_client::*;
use name_lib::*;
use buckyos_kit::*;
use once_cell::sync::OnceCell;
use tokio::sync::Mutex;
use url::Url;
use anyhow::Result;
//use buckyos_api::{*};
pub struct GatewayParams {
    pub keep_tunnel: Vec<String>,
}

pub struct GatewayFactory {
    servers: ServerManagerRef,
    global_process_chains: GlobalProcessChainsRef,
    connection_manager: ConnectionManagerRef,
    tunnel_manager: TunnelManager,
    inner_service_manager: InnerServiceManagerRef,
    stack_factory: CyfsStackFactory,
    server_factory: CyfsServerFactory,
    inner_service_factory: CyfsInnerServiceFactory,
}
impl GatewayFactory {
    pub fn new(
        servers: ServerManagerRef,
        global_process_chains: GlobalProcessChainsRef,
        connection_manager: ConnectionManagerRef,
        tunnel_manager: TunnelManager,
        inner_service_manager: InnerServiceManagerRef) -> Self {
        Self {
            servers,
            global_process_chains,
            connection_manager,
            tunnel_manager,
            inner_service_manager,
            stack_factory: CyfsStackFactory::new(),
            server_factory: CyfsServerFactory::new(),
            inner_service_factory: CyfsInnerServiceFactory::new(),
        }
    }

    pub fn register_stack_factory(&self, protocol: StackProtocol, factory: Arc<dyn StackFactory>) {
        self.stack_factory.register(protocol, factory);
    }

    pub fn register_server_factory<T: Into<String>>(&self, server_type: T, factory: Arc<dyn ServerFactory>) {
        self.server_factory.register(server_type.into(), factory);
    }

    pub fn register_inner_service_factory<T: Into<String>>(
        &self,
        service_type: T,
        factory: Arc<dyn InnerServiceFactory>,
    ) {
        self.inner_service_factory.register(service_type.into(), factory);
    }

    pub async fn create_gateway(
        &self,
        config: GatewayConfig,
    ) -> Result<Gateway> {
        let mut stack_manager = StackManager::new();
        for stack_config in config.stacks.iter() {
            let stack = self.stack_factory.create(stack_config.clone()).await?;
            stack_manager.add_stack(stack);
        }

        for server_config in config.servers.iter() {
            let server = self.server_factory.create(server_config.clone()).await?;
            self.servers.add_server(server.id(), server);
        }

        for inner_service_config in config.inner_services.iter() {
            let service = self.inner_service_factory.create(inner_service_config.clone()).await?;
            self.inner_service_manager.add_service(service.id(), service);
        }

        for process_chain_config in config.global_process_chains.iter() {
            let process_chain = process_chain_config.create_process_chain()?;
            self.global_process_chains.add_process_chain(Arc::new(process_chain));
        }
        
        Ok(Gateway {
            config,
            stack_manager,
            tunnel_manager: self.tunnel_manager.clone(),
            server_manager: self.servers.clone(),
            inner_service_factory: self.inner_service_manager.clone(),
            global_process_chains: self.global_process_chains.clone(),
        })
    }
}

pub struct Gateway {
    config: GatewayConfig,
    stack_manager: StackManager,
    tunnel_manager: TunnelManager,
    server_manager: ServerManagerRef,
    inner_service_factory: InnerServiceManagerRef,
    global_process_chains: GlobalProcessChainsRef,
}

impl Gateway {
    pub fn tunnel_manager(&self) -> &TunnelManager {
        &self.tunnel_manager
    }

    pub async fn start(&mut self, params: GatewayParams) {
        let mut real_machine_config = BuckyOSMachineConfig::default();
        let machine_config = BuckyOSMachineConfig::load_machine_config();
        if machine_config.is_some() {
            real_machine_config = machine_config.unwrap();
        }
        let init_result = init_name_lib(&real_machine_config.web3_bridge).await;
        if init_result.is_err() {
            error!("init default name client failed, err:{}", init_result.err().unwrap());
            return;
        }
        info!("init default name client OK!");

        if !params.keep_tunnel.is_empty() {
            self.keep_tunnels(params.keep_tunnel).await;
        }

        if let Err(e) = self.stack_manager.start().await {
            error!("start stack manager failed, err:{}", e);
        }
    }
    async fn keep_tunnels(&self, keep_tunnel: Vec<String>) {
        for tunnel in keep_tunnel {
            self.keep_tunnel(tunnel.as_str()).await;
        }
    }

    async fn keep_tunnel(&self, tunnel: &str) {
        let tunnel_url = format!("rtcp://{}", tunnel);
        info!("Will keep tunnel: {}", tunnel_url);
        let tunnel_url = Url::parse(tunnel_url.as_str());
        if tunnel_url.is_err() {
            warn!("Invalid tunnel url: {}", tunnel_url.err().unwrap());
            return;
        }

        let tunnel_manager = self.tunnel_manager().clone();
        tokio::task::spawn(async move {
            let tunnel_url = tunnel_url.unwrap();
            loop {
                let last_ok;
                let tunnel = tunnel_manager.get_tunnel(&tunnel_url, None).await;
                if tunnel.is_err() {
                    warn!("Error getting tunnel: {}", tunnel.err().unwrap());
                    last_ok = false;
                } else {
                    let tunnel = tunnel.unwrap();
                    let ping_result = tunnel.ping().await;
                    if ping_result.is_err() {
                        warn!("Error pinging tunnel: {}", ping_result.err().unwrap());
                        last_ok = false;
                    } else {
                        last_ok = true;
                    }
                }

                if last_ok {
                    tokio::time::sleep(std::time::Duration::from_secs(60 * 2)).await;
                } else {
                    tokio::time::sleep(std::time::Duration::from_secs(15)).await;
                }
            }
        });
    }
}
