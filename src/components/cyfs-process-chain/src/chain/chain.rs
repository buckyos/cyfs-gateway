use std::collections::HashMap;
use crate::block::*;

pub struct ProcessChain {
    id: String,
    blocks: Vec<Block>,
}

impl ProcessChain {
    pub fn new(id: String) -> Self {
        ProcessChain { id, blocks: Vec::new() }
    }

    pub fn add_block(&mut self, block: Block) {
        self.blocks.push(block);
    }

    pub fn get_blocks(&self) -> &Vec<Block> {
        &self.blocks
    }

     // Execute the chain with multiple blocks
     pub async fn execute(&self, context: &mut Context) -> Result<BlockResult, String> {
        assert!(self.blocks.len() > 0, "Process chain must have at least one block");
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

// Manager for process chain with ids
pub struct ProcessChainManager {
    chains: HashMap<String, ProcessChain>,
}

impl ProcessChainManager {
    pub fn new() -> Self {
        ProcessChainManager { chains: HashMap::new() }
    }

    pub fn add_chain(&mut self, chain: ProcessChain) {
        self.chains.insert(chain.id.clone(), chain);
    }

    pub fn get_chain(&self, id: &str) -> Option<&ProcessChain> {
        self.chains.get(id)
    }
}