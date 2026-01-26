use super::config::{SocksProxyAuth, SocksProxyConfig};
use super::util::{parse_hook_point_return_value, ProxyAccessMethod, Socks5Util};
use crate::error::{SocksError, SocksResult};
use crate::hook::*;
use buckyos_kit::AsyncStream;
use cyfs_gateway_lib::StreamInfo;
use cyfs_process_chain::{CommandResult, EnvExternal};
use fast_socks5::{
    server::{Config, SimpleUserPassword},
    util::target_addr::TargetAddr,
    Socks5Command,
};
use once_cell::sync::OnceCell;
use std::sync::{Arc, Mutex};
use fast_socks5::server::Socks5Socket;
use tokio::{net::TcpStream, task::JoinHandle};
use url::Url;

#[async_trait::async_trait]
pub trait SocksDataTunnelProvider: Send + Sync {
    async fn build(
        &self,
        target: &TargetAddr,
        proxy_target: &Url,
        enable_tunnel: &Option<Vec<String>>,
    ) -> SocksResult<Box<dyn AsyncStream>>;
}

pub type SocksDataTunnelProviderRef = Arc<Box<dyn SocksDataTunnelProvider>>;

#[derive(Clone)]
pub struct Socks5Proxy {
    config: Arc<SocksProxyConfig>,
    socks5_config: Arc<Config<SimpleUserPassword>>,

    hook_point: SocksHookManagerRef,

    // Use to stop the proxy
    task: Arc<Mutex<Option<JoinHandle<()>>>>,

    // The data tunnel provider
    data_tunnel_provider: Arc<OnceCell<SocksDataTunnelProviderRef>>,
}

impl Socks5Proxy {
    pub fn new(config: SocksProxyConfig, hook_point: SocksHookManagerRef) -> Self {
        let mut socks5_config = Config::default();

        // We should process the command and dns resolve by ourselves
        socks5_config.set_dns_resolve(false);
        socks5_config.set_execute_command(false);

        let socks5_config = match config.auth {
            SocksProxyAuth::None => socks5_config,
            SocksProxyAuth::Password(ref username, ref password) => socks5_config
                .with_authentication(SimpleUserPassword {
                    username: username.clone(),
                    password: password.clone(),
                }),
        };

        Self {
            config: Arc::new(config),
            socks5_config: Arc::new(socks5_config),
            task: Arc::new(Mutex::new(None)),
            data_tunnel_provider: Arc::new(OnceCell::new()),
            hook_point,
        }
    }

    pub fn id(&self) -> &str {
        &self.config.id
    }

    // Should only call once
    pub fn set_data_tunnel_provider(&self, provider: SocksDataTunnelProviderRef) {
        if let Err(_) = self.data_tunnel_provider.set(provider) {
            unreachable!(
                "Data tunnel provider already set for socks5 proxy: {}",
                self.config.id
            );
        }
    }

    pub async fn handle_new_connection(
        &self,
        conn: Box<dyn AsyncStream>,
        addr: StreamInfo,
    ) -> SocksResult<()> {
        debug!("Socks5 connection from {:?}", addr);
        let socket = Socks5Socket::new(conn, self.socks5_config.clone());

        match socket.upgrade_to_socks5().await {
            Ok(mut socket) => {
                let target = match socket.target_addr() {
                    Some(target) => {
                        info!("Recv socks5 connection from {:?} to {}", addr, target);
                        target.to_owned()
                    }
                    None => {
                        let msg =
                            format!("Error getting socks5 connection target address: {:?}", addr,);
                        error!("{}", msg);
                        return Err(SocksError::InvalidParam(msg));
                    }
                };

                let cmd = socket.cmd().as_ref().unwrap();
                match cmd {
                    Socks5Command::TCPConnect => {
                        self.process_socket(socket, addr, target.clone()).await
                    }
                    _ => {
                        let msg = format!("Unsupported socks5 command: {:?}", cmd);
                        error!("{}", msg);
                        Socks5Util::reply_error(
                            &mut socket,
                            fast_socks5::ReplyError::CommandNotSupported,
                        )
                        .await
                    }
                }
            }
            Err(err) => {
                let msg = format!("Upgrade to socks5 error: {:?}, {}", addr, err);
                error!("{}", msg);
                Err(SocksError::SocksError(msg))
            }
        }
    }

    async fn build_data_tunnel(&self, target: &TargetAddr) -> SocksResult<Box<dyn AsyncStream>> {
        debug!("Will build tunnel for {}", target);

        if let Some(builder) = self.data_tunnel_provider.get() {
            builder
                .build(target, &self.config.target, &self.config.enable_tunnel)
                .await
        } else {
            let msg = format!(
                "Data tunnel provider not set for socks5 proxy: {}",
                self.config.id
            );
            error!("{}", msg);
            Err(SocksError::InvalidState(msg))
        }
    }

    async fn process_socket(
        &self,
        mut socket: fast_socks5::server::Socks5Socket<Box<dyn AsyncStream>, SimpleUserPassword>,
        addr: StreamInfo,
        target: TargetAddr,
    ) -> SocksResult<()> {
        let hook_point = self.hook_point.get_socks_lib_executor()?;
        let env = hook_point.chain_env();

        let socks_req = SocksRequestMap::new(addr.src_addr, target.clone());
        let ext_env = SocksRequestEnv::new(socks_req);
        let ext_env = Arc::new(Box::new(ext_env) as Box<dyn EnvExternal>);
        env.env_external_manager()
            .add_external("socks", ext_env)
            .await
            .map_err(|e| {
                let msg = format!("Add socks request env to external failed: {}", e);
                error!("{}", msg);
                SocksError::HookPointError(msg)
            })?;

        let ret = hook_point.execute_lib().await.map_err(|e| {
            let msg = format!("Execute socks hook point failed: {}", e);
            error!("{}", msg);
            SocksError::HookPointError(msg)
        })?;

        let hook_point_ret = match ret {
            CommandResult::Success(value) => value,
            CommandResult::Error(value) => value,
            CommandResult::Control(ctrl) => {
                let msg = format!(
                    "Socks hook point returned control, will use direct {:?}",
                    ctrl
                );
                warn!("{}", msg);
                "DIRECT".to_string()
            }
        };

        let access_method = match parse_hook_point_return_value(&hook_point_ret) {
            Ok(m) => {
                debug!(
                    "Socks hook point return value: {}, access method: {:?}",
                    hook_point_ret, m
                );
                if m.is_empty() {
                    vec![ProxyAccessMethod::Direct]
                } else {
                    m
                }
            }
            Err(e) => {
                let msg = format!(
                    "Error parsing socks hook point return value: {}, will use direct",
                    e
                );
                warn!("{}", msg);
                vec![ProxyAccessMethod::Direct]
            }
        };

        // TODO now just use the first one, and will support multiple later?
        let access_method = &access_method[0];
        match access_method {
            ProxyAccessMethod::Direct => {
                info!("Will process socks5 connection to {} directly", target);
                self.process_socket_direct(socket, target).await
            }
            ProxyAccessMethod::Proxy(proxy_target) => {
                // TODO now always use the proxy in config
                info!(
                    "Will process socks5 connection to {} via proxy {:?}",
                    target, proxy_target
                );
                self.process_socket_via_proxy(socket, target).await
            }
            ProxyAccessMethod::Reject => {
                let msg = format!("Rule engine blocked connection to {}", target);
                error!("{}", msg);
                Socks5Util::reply_error(&mut socket, fast_socks5::ReplyError::HostUnreachable).await
            }
        }
    }

    async fn process_socket_direct(
        &self,
        mut socket: fast_socks5::server::Socks5Socket<Box<dyn AsyncStream>, SimpleUserPassword>,
        target: TargetAddr,
    ) -> SocksResult<()> {
        // Connect to target directly
        let mut stream = match &target {
            TargetAddr::Ip(ip) => TcpStream::connect(ip).await.map_err(|e| {
                let msg = format!("Error connecting to target with ip: {}, {}", ip, e);
                error!("{}", msg);
                SocksError::IoError(msg)
            })?,
            TargetAddr::Domain(domain, port) => {
                // Resolve domain

                let addr = format!("{}:{}", domain, port);
                TcpStream::connect(&addr).await.map_err(|e| {
                    let msg = format!("Error connecting to target with domain: {}, {}", addr, e);
                    error!("{}", msg);
                    SocksError::IoError(msg)
                })?
            }
        };

        // Reply success after connected
        Socks5Util::reply_error(&mut socket, fast_socks5::ReplyError::Succeeded).await?;

        let (read, write) = tokio::io::copy_bidirectional(&mut stream, &mut socket)
            .await
            .map_err(|e| {
                let msg = format!("Error copying data on socks connection: {}, {}", target, e);
                error!("{}", msg);
                SocksError::IoError(msg)
            })?;

        info!(
            "socks5 connection to {} closed, {} bytes read, {} bytes written",
            target, read, write
        );

        Ok(())
    }

    async fn process_socket_via_proxy(
        &self,
        mut socket: fast_socks5::server::Socks5Socket<Box<dyn AsyncStream>, SimpleUserPassword>,
        target: TargetAddr,
    ) -> SocksResult<()> {
        let mut tunnel = match self.build_data_tunnel(&target).await {
            Ok(tunnel) => {
                // Reply success after data tunnel connected
                Socks5Util::reply_error(&mut socket, fast_socks5::ReplyError::Succeeded).await?;
                tunnel
            }
            Err(e) => {
                error!("Error building data tunnel: {}", e);
                return Socks5Util::reply_error(
                    &mut socket,
                    fast_socks5::ReplyError::GeneralFailure,
                )
                .await;
            }
        };

        let (read, write) = tokio::io::copy_bidirectional(&mut tunnel, &mut socket)
            .await
            .map_err(|e| {
                let msg = format!("Error copying data on socks connection: {}, {}", target, e);
                error!("{}", msg);
                SocksError::IoError(msg)
            })?;

        info!(
            "socks5 connection to {} closed, {} bytes read, {} bytes written",
            target, read, write
        );

        Ok(())
    }
}
