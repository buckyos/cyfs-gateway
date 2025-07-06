use super::env::{Env, EnvLevel, EnvRef};
use crate::block::*;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

pub struct ProcessChain {
    id: String,
    blocks: Vec<Block>,
}

impl ProcessChain {
    pub fn new(id: String) -> Self {
        ProcessChain {
            id,
            blocks: Vec::new(),
        }
    }

    pub fn add_block(&mut self, block: Block) {
        self.blocks.push(block);
    }

    pub fn get_blocks(&self) -> &Vec<Block> {
        &self.blocks
    }

    // Execute the chain with multiple blocks
    pub async fn execute(&self, context: &Context) -> Result<BlockResult, String> {
        assert!(
            self.blocks.len() > 0,
            "Process chain must have at least one block"
        );
        let mut block_executer = BlockExecuter::new();

        for block in &self.blocks {
            let result = block_executer.execute_block(block, context).await?;
            if result != BlockResult::Ok {
                return Ok(result);
            }
        }

        Ok(BlockResult::Ok)
    }
}

pub type ProcessChainRef = Arc<ProcessChain>;

// Manager for process chain with ids
pub struct ProcessChainManager {
    chains: RwLock<HashMap<String, ProcessChainRef>>,
    env: EnvRef, // Environment manager for global environment
}

impl ProcessChainManager {
    pub fn new() -> Self {
        ProcessChainManager {
            chains: RwLock::new(HashMap::new()),
            env: Arc::new(Env::new(EnvLevel::Global, None)), // Initialize with a new environment
        }

        // TODO: We can load some existing env vars from a persistent storage if needed
    }

    pub fn get_global_env(&self) -> &EnvRef {
        &self.env
    }

    pub fn create_chain_env(&self) -> EnvRef {
        Arc::new(Env::new(EnvLevel::Chain, Some(self.env.clone())))
    }

    pub fn add_chain(&self, chain: ProcessChain) {
        let mut chains = self.chains.write().unwrap();
        chains.insert(chain.id.clone(), Arc::new(chain));
    }

    pub fn get_chain(&self, id: &str) -> Option<ProcessChainRef> {
        let chains = self.chains.read().unwrap();
        chains.get(id).cloned()
    }
}

pub type ProcessChainManagerRef = Arc<ProcessChainManager>;
