use super::context::Context;
use super::exec::ProcessChainExecutor;
use crate::block::*;
use crate::cmd::{COMMAND_PARSER_FACTORY, CommandResult};
use std::sync::{Arc, RwLock};

#[derive(Debug, Clone)]
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

    pub async fn translate(&mut self, context: &ParserContextRef) -> Result<(), String> {
        info!("Translating process chain: {}", self.id);

        let translator =
            BlockCommandTranslator::new(context.clone(), COMMAND_PARSER_FACTORY.clone());
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

use crate::cmd::{EXTERNAL_COMMAND_FACTORY, ExternalCommandFactory, ExternalCommandRef};

pub struct ParserContext {
    external_commands: ExternalCommandFactory,
}

impl ParserContext {
    pub fn new() -> Self {
        Self {
            external_commands: ExternalCommandFactory::new(),
        }
    }

    pub fn register_external_command(
        &self,
        name: &str,
        command: ExternalCommandRef,
    ) -> Result<(), String> {
        // First check if the command already exists in global factory
        if EXTERNAL_COMMAND_FACTORY.get_command(name).is_some() {
            let msg = format!("External command '{}' already exists in global", name);
            error!("{}", msg);
            return Err(msg);
        }

        self.external_commands.register(name, command)
    }

    pub fn get_external_command(&self, name: &str) -> Option<ExternalCommandRef> {
        if let Some(cmd) = self.external_commands.get_command(name) {
            return Some(cmd);
        }

        // If not found, check the global factory
        EXTERNAL_COMMAND_FACTORY.get_command(name)
    }

    pub fn get_external_command_list(&self) -> Vec<String> {
        self.external_commands.get_command_list()
    }
}

pub type ParserContextRef = Arc<ParserContext>;