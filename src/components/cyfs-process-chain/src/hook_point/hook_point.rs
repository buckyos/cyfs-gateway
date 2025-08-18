use super::loader::ProcessChainXMLLoader;
use crate::chain::{ProcessChain, ProcessChainManager, ProcessChainListLib, ProcessChainLibRef};
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
    pub async fn load_process_chain_lib(&self, id: &str, priority: i32, content: &str) -> Result<(), String> {
        let chains = ProcessChainXMLLoader::parse(content)?;
        let chains = chains
            .into_iter()
            .map(|chain| Arc::new(chain))
            .collect::<Vec<_>>();

        let lib = ProcessChainListLib::new(
            id,
            priority,
            chains
        );

        Ok(())
    }
}

pub type HookPointRef = Arc<HookPoint>;
