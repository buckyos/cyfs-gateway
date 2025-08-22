use super::loader::ProcessChainXMLLoader;
use crate::chain::EnvRef;
use crate::chain::{
    ProcessChainLib, ProcessChainLibExecutor, ProcessChainLibRef, ProcessChainLinkedManagerRef,
    ProcessChainListLib, ProcessChainManager,
};
use crate::cmd::CommandResult;
use crate::pipe::CommandPipe;
use std::sync::Arc;

pub struct HookPoint {
    id: String,
    process_chain_manager: Arc<ProcessChainManager>,
}

impl HookPoint {
    pub fn new(id: impl Into<String>) -> Self {
        let process_chain_manager = ProcessChainManager::new();
        let process_chain_manager = Arc::new(process_chain_manager);

        Self {
            id: id.into(),
            process_chain_manager,
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn process_chain_manager(&self) -> &Arc<ProcessChainManager> {
        &self.process_chain_manager
    }

    pub fn add_process_chain_lib(&self, lib: ProcessChainLibRef) -> Result<(), String> {
        self.process_chain_manager.add_lib(lib)
    }

    // Load process chain list as lib in xml format and manage it in the process chain manager
    pub async fn load_process_chain_lib(
        &self,
        lib_id: &str,
        priority: i32,
        content: &str,
    ) -> Result<ProcessChainLibRef, String> {
        let chains = ProcessChainXMLLoader::parse(content)?;
        let chains = chains
            .into_iter()
            .map(|chain| Arc::new(chain))
            .collect::<Vec<_>>();

        let lib = ProcessChainListLib::new(lib_id, priority, chains);
        let lib = Arc::new(Box::new(lib) as Box<dyn ProcessChainLib>);
        self.add_process_chain_lib(lib.clone())?;

        Ok(lib)
    }
}

pub type HookPointRef = Arc<HookPoint>;

pub struct HookPointExecutor {
    id: String,
    process_chain_manager: ProcessChainLinkedManagerRef,
    global_env: EnvRef,
    pipe: CommandPipe,
}

impl HookPointExecutor {
    pub(crate) fn new(
        id: impl Into<String>,
        process_chain_manager: ProcessChainLinkedManagerRef,
        global_env: EnvRef,
        pipe: CommandPipe,
    ) -> Self {
        Self {
            id: id.into(),
            process_chain_manager,
            global_env,
            pipe,
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn process_chain_manager(&self) -> &ProcessChainLinkedManagerRef {
        &self.process_chain_manager
    }

    pub fn prepare_exec_lib(&self, lib_id: &str) -> Result<ProcessChainLibExecutor, String> {
        let lib = self.process_chain_manager.get_lib(lib_id).ok_or_else(|| {
            let msg = format!("Process chain lib '{}' not found", lib_id);
            error!("{}", msg);
            msg
        })?;

        let process_chain_manager = self.process_chain_manager.clone();
        let exec = ProcessChainLibExecutor::new(
            lib,
            process_chain_manager,
            self.global_env.clone(),
            self.pipe.clone(),
        );

        Ok(exec)
    }

    pub async fn execute_lib(&self, lib_id: &str) -> Result<CommandResult, String> {
        let exec = self.prepare_exec_lib(lib_id)?;
        exec.execute_lib().await
    }

    pub async fn execute_chain(
        &self,
        lib_id: &str,
        chain_id: &str,
    ) -> Result<CommandResult, String> {
        let exec = self.prepare_exec_lib(lib_id)?;

        exec.execute_chain(chain_id).await
    }
}

pub type HookPointExecutorRef = Arc<HookPointExecutor>;
