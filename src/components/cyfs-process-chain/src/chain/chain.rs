use super::env::{Env, EnvLevel, EnvRef};
use super::exec::ProcessChainExecutor;
use crate::block::*;
use crate::cmd::{CommandResult, COMMAND_PARSER_FACTORY};
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

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn add_block(&mut self, block: Block) -> Result<(), String> {
        // First check if the block id is unique
        if self.get_block(&block.id).is_some() {
            let msg = format!("Block with id '{}' already exists in the chain", block.id);
            error!("{}", msg);
            return Err(msg);
        }

        self.blocks.push(block);

        Ok(())
    }

    pub fn get_block(&self, id: &str) -> Option<&Block> {
        self.blocks.iter().find(|b| b.id == id)
    }

    pub fn get_block_index(&self, id: &str) -> Option<usize> {
        self.blocks.iter().position(|b| b.id == id)
    }

    pub fn get_blocks(&self) -> &Vec<Block> {
        &self.blocks
    }

    pub async fn translate(&mut self) -> Result<(), String> {
        let translator = BlockCommandTranslator::new(COMMAND_PARSER_FACTORY.clone());
        // Translate each block in the chain
        for block in &mut self.blocks {
            translator.translate(block).await?;
        }
        
        Ok(())
    }

    // Execute the chain with multiple blocks
    pub async fn execute(&self, context: &Context) -> Result<CommandResult, String> {
        let executor = ProcessChainExecutor::new();
        executor.execute_chain(self, context).await
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

    pub fn add_chain(&self, chain: ProcessChain) -> Result<(), String> {
        let mut chains = self.chains.write().unwrap();
        match chains.entry(chain.id().to_string()) {
            std::collections::hash_map::Entry::Occupied(_) => {
                let msg = format!("Process chain with id '{}' already exists", chain.id);
                error!("{}", msg);
                return Err(msg);
            }
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(Arc::new(chain));
            }
        }

        Ok(())
    }

    pub fn get_chain(&self, id: &str) -> Option<ProcessChainRef> {
        let chains = self.chains.read().unwrap();
        chains.get(id).cloned()
    }
}

pub type ProcessChainManagerRef = Arc<ProcessChainManager>;
