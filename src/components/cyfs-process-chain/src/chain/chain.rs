use super::context::Context;
use super::exec::ProcessChainExecutor;
use crate::block::*;
use crate::cmd::{COMMAND_PARSER_FACTORY, CommandResult};
use std::sync::{Arc, RwLock};

pub struct ProcessChain {
    id: String,
    priority: i32,
    blocks: Vec<Block>,
}

impl ProcessChain {
    pub fn new(id: String, priority: i32) -> Self {
        ProcessChain {
            id,
            priority,
            blocks: Vec::new(),
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn priority(&self) -> i32 {
        self.priority
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
    chains: RwLock<Vec<ProcessChainRef>>,
}

impl ProcessChainManager {
    pub fn new() -> Self {
        ProcessChainManager {
            chains: RwLock::new(Vec::new()),
        }
    }

    pub fn add_chain(&self, chain: ProcessChain) -> Result<(), String> {
        let mut chains = self.chains.write().unwrap();
        // Check if the chain id is unique
        if chains.iter().any(|c| c.id() == chain.id) {
            let msg = format!("Process chain with id '{}' already exists", chain.id);
            error!("{}", msg);
            return Err(msg);
        }

        info!("Added process chain with id '{}'", chain.id);

        // Create a reference counted version of the chain
        let chain_ref = Arc::new(chain);
        chains.push(chain_ref);

        Ok(())
    }

    pub fn get_chain(&self, id: &str) -> Option<ProcessChainRef> {
        let chains = self.chains.read().unwrap();
        chains.iter().find(|c| c.id() == id).cloned()
    }

    pub fn clone_process_chain_list(&self) -> Vec<ProcessChainRef> {
        let chains = self.chains.read().unwrap();
        chains.clone()
    }
}

pub type ProcessChainManagerRef = Arc<ProcessChainManager>;
