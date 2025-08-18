use std::collections::HashMap;
use std::io::{BufReader, Cursor};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use rustls_pemfile::{certs, pkcs8_private_keys};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use cyfs_process_chain::{CommandControl, ProcessChainListExecutor};
use crate::{into_stack_err, stack_err, ProcessChainConfigs, Stack, StackCertConfig, StackErrorCode, StackProtocol, StackResult, StreamServerManagerRef};
use crate::global_process_chains::{create_process_chain_executor, execute_chain, GlobalProcessChainsRef};


async fn load_certs(path: &str) -> StackResult<Vec<CertificateDer<'static>>> {
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

async fn load_key(path: &str) -> StackResult<PrivateKeyDer<'static>> {
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
async fn create_server_config(
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
        let mut certs = HashMap::new();
        for cert_config in config.certs.iter() {
            certs.insert(cert_config.domain.clone(), create_server_config(cert_config.cert_file.as_str(), cert_config.key_file.as_str()).await?);
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
                let certs = certs.clone();
                tokio::spawn(async move {
                    if let Err(e) = Self::handle_connect(stream, local_addr, servers, executor, certs).await {
                        log::error!("handle tcp stream failed: {}", e);
                    }
                });
            }
        });
        self.handle = Some(handle);
        Ok(())
    }

    async fn handle_connect(stream: TcpStream, local_addr: SocketAddr, servers: StreamServerManagerRef, executor: ProcessChainListExecutor, certs: Arc<Mutex<HashMap<String, Arc<ServerConfig>>>>) -> StackResult<()> {
        let (ret, stream) = execute_chain(executor, Box::new(stream), local_addr).await
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
                                return Err(stack_err!(StackErrorCode::InvalidConfig, "invalid server command"));
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
                                server.serve_connection(Box::new(tls_stream)).await
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

pub struct TlsStackBuilder {
    bind: Option<String>,
    hook_point: Option<ProcessChainConfigs>,
    servers: Option<StreamServerManagerRef>,
    global_process_chains: Option<GlobalProcessChainsRef>,
    certs: Vec<StackCertConfig>,
}

impl TlsStackBuilder {
    pub fn bind(mut self, bind: impl Into<String>) -> Self {
        self.bind = Some(bind.into());
        self
    }

    pub fn add_certs(mut self, certs: Vec<StackCertConfig>) -> Self {
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
