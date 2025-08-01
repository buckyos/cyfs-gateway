use super::loader::ProcessChainXMLLoader;
use crate::chain::{ProcessChain, ProcessChainManager};
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

    pub fn add_process_chain(&self, chain: ProcessChain) -> Result<(), String> {
        self.process_chain_manager.add_chain(chain)
    }

    // Load process chain list in xml format
    pub async fn load_process_chain_list(&self, content: &str) -> Result<(), String> {
        let chains = ProcessChainXMLLoader::parse(content)?;

        // Append all chains to the manager
        for chain in chains {
            self.add_process_chain(chain)?;
        }

        Ok(())
    }
}

pub type HookPointRef = Arc<HookPoint>;
