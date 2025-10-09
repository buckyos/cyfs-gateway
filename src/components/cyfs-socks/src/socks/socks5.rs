use super::config::{SocksProxyAuth, SocksProxyConfig};
use super::util::Socks5Util;
use crate::error::{SocksError, SocksResult};
use crate::hook::SocksHookManagerRef;
use crate::rule::{RuleAction, RuleInput};
use buckyos_kit::AsyncStream;
use fast_socks5::{
    server::{Config, SimpleUserPassword, Socks5Socket},
    util::target_addr::TargetAddr,
    Socks5Command,
};
use once_cell::sync::OnceCell;
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
};
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
        addr: SocketAddr,
    ) -> SocksResult<()> {
        // info!("Socks5 connection from {}", addr);
        let socket = Socks5Socket::new(conn, self.socks5_config.clone());

        match socket.upgrade_to_socks5().await {
            Ok(mut socket) => {
                let target = match socket.target_addr() {
                    Some(target) => {
                        info!("Recv socks5 connection from {} to {}", addr, target);
                        target.to_owned()
                    }
                    None => {
                        let msg =
                            format!("Error getting socks5 connection target address: {},", addr,);
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
                let msg = format!("Upgrade to socks5 error: {}", err);
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
        addr: SocketAddr,
        target: TargetAddr,
    ) -> SocksResult<()> {
        // Select by rule engine
        if let Some(ref rule_engine) = self.config.rule_engine {
            let input = RuleInput::new_socks_request(&addr, &target);
            match rule_engine.select(input).await {
                Ok(action) => match action {
                    RuleAction::Direct | RuleAction::Pass => {
                        info!("Will process socks5 connection to {} directly", target);
                        self.process_socket_direct(socket, target).await
                    }
                    RuleAction::Proxy(proxy_target) => {
                        info!(
                            "Will process socks5 connection to {} via proxy {}",
                            target, proxy_target
                        );
                        self.process_socket_via_proxy(socket, target).await
                    }
                    RuleAction::Reject => {
                        let msg = format!("Rule engine blocked connection to {}", target);
                        error!("{}", msg);
                        Socks5Util::reply_error(
                            &mut socket,
                            fast_socks5::ReplyError::HostUnreachable,
                        )
                        .await
                    }
                },
                Err(e) => {
                    let msg = format!("Error selecting rule, now will use direct: {}", e);
                    warn!("{}", msg);
                    // Socks5Util::reply_error(&mut socket, fast_socks5::ReplyError::GeneralFailure)
                    //    .await
                    self.process_socket_direct(socket, target).await
                }
            }
        } else {
            warn!(
                "Rule engine is not set, now Will process socks5 connection to {} directly",
                target
            );
            self.process_socket_direct(socket, target).await
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
