use super::cmd::ResolveDNSCommand;
use crate::error::{SocksError, SocksResult};
use buckyos_kit::get_buckyos_service_data_dir;
use cyfs_process_chain::*;
use std::sync::Arc;

pub struct SocksHookManager {
    hook_point: HookPoint,
    hook_point_env: HookPointEnv,
    exec: HookPointExecutorRef,
}

impl SocksHookManager {
    pub async fn create(process_chain: ProcessChainLibRef, global_process_chains: Vec<ProcessChainLibRef>) -> Result<Self, String> {
        // Create a hook point
        let hook_point = HookPoint::new("socks-hook-point");
        hook_point
            .add_process_chain_lib(process_chain)
            .map_err(|e| {
                let msg = format!("Load socks process chain lib failed! err={}", e);
                error!("{}", msg);
                msg
            })?;

        for lib in global_process_chains.iter() {
            hook_point.add_process_chain_lib(lib.clone()).map_err(|e| {
                let msg = format!("Load global process chain lib failed! err={}", e);
                error!("{}", msg);
                msg
            })?;
        }

        let data_dir = get_buckyos_service_data_dir("cyfs-gateway");
        if !data_dir.exists() {
            std::fs::create_dir_all(&data_dir).map_err(|e| {
                let msg = format!(
                    "create buckyos service data dir failed! dir={}, err={}",
                    data_dir.display(),
                    e
                );
                error!("{}", msg);
                msg
            })?;
        }

        std::fs::create_dir_all(&data_dir).unwrap();

        // Create env to execute the hook point
        let hook_point_env = HookPointEnv::new("socks-hook-point", data_dir);

        // Register external commands
        let cmd = Box::new(ResolveDNSCommand::new());
        let name = cmd.name().to_owned();

        let command = Arc::new(cmd as Box<dyn ExternalCommand>);
        hook_point_env.register_external_command(&name, command)?;

        // Link the hook point with the env
        let exec = hook_point_env.link_hook_point(&hook_point).await?;

        Ok(Self {
            hook_point,
            hook_point_env,
            exec,
        })
    }

    pub fn get_socks_lib_executor(&self) -> SocksResult<ProcessChainLibExecutor> {
        let lib_exec = self.exec.prepare_exec_lib("main").map_err(|e| {
            let msg = format!("Prepare socks lib executor failed! err={}", e);
            error!("{}", msg);
            SocksError::HookPointError(msg)
        })?;

        Ok(lib_exec)
    }
}

pub type SocksHookManagerRef = Arc<SocksHookManager>;