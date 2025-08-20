use super::env::HookPointEnv;
use super::loader::ProcessChainXMLLoader;
use crate::chain::{
    ProcessChainLib, ProcessChainLibExecutor, ProcessChainLibRef, ProcessChainLinkedManagerRef,
    ProcessChainListLib, ProcessChainManager, ProcessChainsExecutor,
};
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

    // Load process chain list as lib in xml format
    pub async fn load_process_chain_lib(
        &self,
        id: &str,
        priority: i32,
        content: &str,
    ) -> Result<ProcessChainLibRef, String> {
        let chains = ProcessChainXMLLoader::parse(content)?;
        let chains = chains
            .into_iter()
            .map(|chain| Arc::new(chain))
            .collect::<Vec<_>>();

        let lib = ProcessChainListLib::new(id, priority, chains);

        Ok(Arc::new(Box::new(lib) as Box<dyn ProcessChainLib>))
    }
}

pub type HookPointRef = Arc<HookPoint>;

pub struct HookPointExecutor {
    id: String,
    process_chain_manager: ProcessChainLinkedManagerRef,
}

impl HookPointExecutor {
    pub(crate) fn new(
        id: impl Into<String>,
        process_chain_manager: ProcessChainLinkedManagerRef,
    ) -> Self {
        Self {
            id: id.into(),
            process_chain_manager,
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn process_chain_manager(&self) -> &ProcessChainLinkedManagerRef {
        &self.process_chain_manager
    }

    pub async fn prepare_exec_lib(
        &self,
        env: &HookPointEnv,
        id: &str,
    ) -> Result<ProcessChainLibExecutor, String> {
        let lib = self.process_chain_manager.get_lib(id).ok_or_else(|| {
            let msg = format!("Process chain lib '{}' not found", id);
            error!("{}", msg);
            msg
        })?;

        let process_chain_manager = self.process_chain_manager.clone();
        let exec = ProcessChainLibExecutor::new(
            lib,
            process_chain_manager,
            env.global_env().clone(),
            env.pipe().pipe().clone(),
        );

        Ok(exec)
    }

    pub async fn prepare_exec_chain(
        &self,
        env: &HookPointEnv,
    ) -> Result<ProcessChainsExecutor, String> {
        let process_chain_manager = self.process_chain_manager.clone();
        let exec = ProcessChainsExecutor::new(
            process_chain_manager,
            env.global_env().clone(),
            env.pipe().pipe().clone(),
        );

        Ok(exec)
    }
}

pub type HookPointExecutorRef = Arc<HookPointExecutor>;
