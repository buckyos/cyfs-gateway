use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use buckyos_kit::AsyncStream;
use cyfs_process_chain::{CommandResult, ExternalCommand, HookPoint, HookPointEnv, HttpProbeCommand, HttpsSniProbeCommand, ProcessChainListExecutor, ProcessChainRef, StreamRequest, StreamRequestMap};
use crate::{config_err, ConfigErrorCode, ConfigResult, ProcessChainConfig};

pub struct GlobalProcessChains {
    process_chains: Mutex<Vec<ProcessChainRef>>,
}
pub type GlobalProcessChainsRef = Arc<GlobalProcessChains>;

impl GlobalProcessChains {
    pub fn new() -> Self {
        Self {
            process_chains: Mutex::new(vec![]),
        }
    }
    
    pub fn add_process_chain(&mut self, process_chain: ProcessChainRef) {
        self.process_chains.lock().unwrap().push(process_chain);
    }
    
    pub fn get_process_chains(&self) -> Vec<ProcessChainRef> {
        self.process_chains.lock().unwrap().clone()
    }
}


pub(crate) async fn create_process_chain_executor(
    chains: &Vec<ProcessChainConfig>,
) -> ConfigResult<(ProcessChainListExecutor, HookPointEnv)> {
    let hook_point = HookPoint::new("cyfs_server_hook_point");
    for chain_config in chains.iter() {
        hook_point
            .add_process_chain(
                chain_config
                    .create_process_chain()?,
            )
            .map_err(|e| config_err!(ConfigErrorCode::InvalidConfig, "{}", e))?;
    }
    let hook_point_env = HookPointEnv::new("cyfs_server_hook_point_env", PathBuf::new());

    let https_sni_probe_command = HttpsSniProbeCommand::new();
    let name = https_sni_probe_command.name().to_owned();
    hook_point_env
        .register_external_command(
            &name,
            Arc::new(Box::new(https_sni_probe_command) as Box<dyn ExternalCommand>),
        )
        .map_err(|e| config_err!(ConfigErrorCode::ProcessChainError, "{}", e))?;

    let http_probe_command = HttpProbeCommand::new();
    let name = http_probe_command.name().to_owned();
    hook_point_env
        .register_external_command(
            &name,
            Arc::new(Box::new(http_probe_command) as Box<dyn ExternalCommand>),
        )
        .unwrap();

    let executor = hook_point_env
        .prepare_exec_list(&hook_point)
        .await
        .map_err(|e| config_err!(ConfigErrorCode::ProcessChainError, "{}", e))?;
    Ok((executor, hook_point_env))
}


pub(crate) async fn execute_chain(executor: ProcessChainListExecutor, stream: Box<dyn AsyncStream>, local_addr: SocketAddr) -> ConfigResult<(CommandResult, Box<dyn AsyncStream>)> {
    let request = StreamRequest::new(stream, local_addr);
    let request_map = StreamRequestMap::new(request);
    let chain_env = executor.chain_env();
    request_map
        .register(&chain_env)
        .await
        .map_err(|e| config_err!(ConfigErrorCode::ProcessChainError, "{}", e))?;

    let ret = executor
        .execute_all()
        .await
        .map_err(|e| config_err!(ConfigErrorCode::ProcessChainError, "{}", e))?;
    drop(executor);

    let request = request_map
        .into_request()
        .map_err(|e| config_err!(ConfigErrorCode::ProcessChainError, "{}", e))?;
    let socket = request.incoming_stream.lock().unwrap().take();
    if socket.is_none() {
        return Err(config_err!(
                ConfigErrorCode::ProcessChainError,
                "socket is none"
            ));
    }
    let socket = socket.unwrap();
    Ok((ret, socket))
}