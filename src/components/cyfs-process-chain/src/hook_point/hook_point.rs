use crate::chain::{ProcessChain, ProcessChainManager};
use std::sync::Arc;

pub struct HookPoint {
    id: String,
    process_chain_manager: Arc<ProcessChainManager>,
}

impl HookPoint {
    pub fn new(id: String) -> Self {
        let process_chain_manager = ProcessChainManager::new();
        let process_chain_manager = Arc::new(process_chain_manager);

        Self {
            id,
            process_chain_manager,
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn process_chain_manager(&self) -> &Arc<ProcessChainManager> {
        &self.process_chain_manager
    }

    pub fn add_process_chain(&self, chain: ProcessChain) -> Result<(), String> {
        self.process_chain_manager.add_chain(chain)
    }

    pub fn load_process_chain(
        &self,
        chain_id: &str,
        _content: &str,
    ) -> Result<ProcessChain, String> {
        todo!("Load process chain by ID: {}", chain_id);
    }
}
