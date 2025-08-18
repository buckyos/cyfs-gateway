use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use url::Url;
use cyfs_process_chain::{CommandControl, ProcessChainListExecutor};
use super::{Stack};
use crate::{into_stack_err, stack_err, ProcessChainConfigs, StackErrorCode, StackProtocol, StreamServerManagerRef, GATEWAY_TUNNEL_MANAGER};
use crate::global_process_chains::{create_process_chain_executor, execute_chain, GlobalProcessChainsRef};
use super::StackResult;

pub struct TcpStack {
    bind_addr: String,
    servers: StreamServerManagerRef,
    handle: Option<JoinHandle<()>>,
    executor: Arc<Mutex<ProcessChainListExecutor>>,
}

impl Drop for TcpStack {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

impl TcpStack {
    pub fn builder() -> TcpStackBuilder {
        TcpStackBuilder {
            bind: None,
            hook_point: None,
            servers: None,
            global_process_chains: None,
        }
    }

    async fn create(config: TcpStackBuilder) -> StackResult<Self> {
        if config.bind.is_none() {
            return Err(stack_err!(StackErrorCode::InvalidConfig, "bind is required"));
        }
        if config.hook_point.is_none() {
            return Err(stack_err!(StackErrorCode::InvalidConfig, "hook_point is required"));
        }
        if config.servers.is_none() {
            return Err(stack_err!(StackErrorCode::InvalidConfig, "servers is required"));
        }
        let (executor, _) = create_process_chain_executor(config.hook_point.as_ref().unwrap()).await
            .map_err(into_stack_err!(StackErrorCode::ProcessChainError))?;
        Ok(Self {
            bind_addr: config.bind.unwrap(),
            servers: config.servers.unwrap(),
            handle: None,
            executor: Arc::new(Mutex::new(executor)),
        })
    }

    pub async fn start(&mut self) -> StackResult<()> {
        let bind_addr = self.bind_addr.clone();
        let servers = self.servers.clone();
        let executor = self.executor.clone();
        let listener = tokio::net::TcpListener::bind(bind_addr.as_str()).await
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
                tokio::spawn(async move {
                    if let Err(e) = Self::handle_connect(stream, local_addr, servers, executor).await {
                        log::error!("handle tcp stream failed: {}", e);
                    }
                });
            }
        });
        self.handle = Some(handle);
        Ok(())
    }

    async fn handle_connect(stream: TcpStream, local_addr: SocketAddr, servers: StreamServerManagerRef, executor: ProcessChainListExecutor) -> StackResult<()> {
        let (ret, mut stream) = execute_chain(executor, Box::new(stream), local_addr).await
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
                        "forward" => {
                            if list.len() < 2 {
                                return Err(stack_err!(
                                    StackErrorCode::InvalidConfig,
                                    "invalid forward command"
                                ));
                            }
                            let target = list[1].as_str();
                            if let Some(tunnel_manager) = GATEWAY_TUNNEL_MANAGER.get() {
                                let url = Url::parse(target).map_err(into_stack_err!(StackErrorCode::InvalidConfig, "invalid forward url {}", target))?;
                                let mut forward_stream = tunnel_manager
                                    .open_stream_by_url(&url)
                                    .await
                                    .map_err(into_stack_err!(StackErrorCode::TunnelError))?;

                                tokio::io::copy_bidirectional(&mut stream, forward_stream.as_mut())
                                    .await
                                    .map_err(into_stack_err!(StackErrorCode::StreamError))?;
                            } else {
                                log::error!("tunnel manager not found");
                            }
                        },
                        "server" => {
                            if list.len() < 2 {
                                return Err(stack_err!(StackErrorCode::InvalidConfig, "invalid server command"));
                            }
                            let server_name = list[1].as_str();
                            if let Some(server) = servers.get_server(server_name) {
                                server.serve_connection(stream).await
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

    pub async fn update_hook_point(&mut self, config: ProcessChainConfigs) -> StackResult<()> {
        Ok(())
    }
}

impl Stack for TcpStack {
    fn stack_protocol(&self) -> StackProtocol {
        StackProtocol::Tcp
    }

    fn get_bind_addr(&self) -> String {
        self.bind_addr.clone()
    }
}

pub struct TcpStackBuilder {
    bind: Option<String>,
    hook_point: Option<ProcessChainConfigs>,
    servers: Option<StreamServerManagerRef>,
    global_process_chains: Option<GlobalProcessChainsRef>,
}

impl TcpStackBuilder {
    pub fn bind(mut self, bind: impl Into<String>) -> Self {
        self.bind = Some(bind.into());
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

    pub async fn build(self) -> StackResult<TcpStack> {
        let stack = TcpStack::create(self).await?;
        Ok(stack)
    }
}
