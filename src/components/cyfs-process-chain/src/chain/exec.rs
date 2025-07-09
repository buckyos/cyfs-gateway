use super::chain::{ProcessChain, ProcessChainManagerRef, ProcessChainRef};
use super::context::Context;
use crate::GotoCounter;
use crate::block::BlockExecuter;
use crate::cmd::{CommandControl, CommandControlLevel, CommandResult};
use crate::collection::{CollectionManager, VariableVisitorManager};
use crate::pipe::CommandPipe;
use std::sync::Arc;

pub struct ProcessChainExecutor {}

impl ProcessChainExecutor {
    pub fn new() -> Self {
        Self {}
    }
}

impl ProcessChainExecutor {
    pub async fn execute_chain(
        &self,
        chain: &ProcessChain,
        context: &Context,
    ) -> Result<CommandResult, String> {
        let blocks = chain.get_blocks();
        if blocks.is_empty() {
            let msg = format!("Process chain '{}' has no blocks to execute", chain.id());
            warn!("{}", msg);
            return Ok(CommandResult::success());
        }

        let mut chain_result = CommandResult::success();

        let mut i = 0;
        while i < blocks.len() {
            let block = &blocks[i];

            let block_executer = BlockExecuter::new(&block.id);
            let block_context = context.fork_block();
            let result = block_executer.execute_block(block, &block_context).await?;
            if result.is_control() {
                // If the block execution result is a control action, we handle it immediately
                info!("Control action in block '{}': {:?}", block.id, result);
                let control = result.as_control().unwrap();
                match control {
                    CommandControl::Return(value) => {
                        info!("Returning from block '{}': {}", block.id, value);
                        chain_result = result;
                    }
                    CommandControl::Error(value) => {
                        warn!("Error return in block '{}': {}", block.id, value);
                        chain_result = result
                    }
                    CommandControl::Exit(value) => {
                        info!("Exiting chain from block '{}': {}", block.id, value);
                        chain_result = result;
                        break;
                    }
                    CommandControl::Goto((level, target)) => {
                        info!(
                            "Goto action in block '{}': level={:?}, target={}",
                            block.id, level, target
                        );
                        if *level == CommandControlLevel::Block {
                            // If it's a block-level goto, we can continue to the target block
                            let goto_index = chain.get_block_index(&target);
                            if goto_index.is_none() {
                                let msg = format!(
                                    "Goto target block '{}' not found in chain '{}'",
                                    target,
                                    chain.id()
                                );
                                warn!("{}", msg);
                                return Err(msg);
                            }

                            i = goto_index.unwrap();

                            context.counter().increment()?;

                            // TODO: What should the result be in this case?
                            // For now, we just set it to success and continue to the next block
                            chain_result = CommandResult::success();
                        } else if *level == CommandControlLevel::Chain {
                            // If it's a chain-level goto, we exit the chain execution
                            chain_result = result;
                            break;
                        }
                    }
                }
            } else {
                // If the block execution result is not a control action, we continue to the next block
                chain_result = result;
            }

            i += 1;
        }

        Ok(chain_result)
    }
}

pub struct ProcessChainsExecutor {
    process_chain_manager: ProcessChainManagerRef,
    collection_manager: CollectionManager,
    variable_visitor_manager: VariableVisitorManager,
    pipe: CommandPipe,
}

impl ProcessChainsExecutor {
    pub fn new(
        process_chain_manager: ProcessChainManagerRef,
        collection_manager: CollectionManager,
        variable_visitor_manager: VariableVisitorManager,
        pipe: CommandPipe,
    ) -> Self {
        Self {
            process_chain_manager,
            collection_manager,
            variable_visitor_manager,
            pipe,
        }
    }

    pub async fn execute_chain_by_id(&self, chain_id: &str) -> Result<CommandResult, String> {
        let chain = self.process_chain_manager.get_chain(chain_id);
        if chain.is_none() {
            let msg = format!("Process chain '{}' not found", chain_id);
            warn!("{}", msg);
            return Err(msg);
        }

        let chain = chain.unwrap();
        self.execute_chain(&chain).await
    }

    pub async fn execute_chain(&self, chain: &ProcessChainRef) -> Result<CommandResult, String> {
        let global_env = self.process_chain_manager.get_global_env().clone();
        let chain_env = self.process_chain_manager.create_chain_env();

        let counter = Arc::new(GotoCounter::new());
        let context = Context::new(
            chain.clone(),
            global_env,
            chain_env,
            self.process_chain_manager.clone(),
            self.collection_manager.clone(),
            self.variable_visitor_manager.clone(),
            counter,
            self.pipe.clone(),
        );

        self.execute_chain_loop(chain, &context).await
    }

    #[async_recursion::async_recursion]
    async fn execute_chain_inner(
        &self,
        chain: &ProcessChainRef,
        context: &Context,
    ) -> Result<CommandResult, String> {
        let ret = chain.execute(context).await?;
        if ret.is_control() {
            info!("Chain execution result is a control action: {:?}", ret);
            let control = ret.as_control().unwrap();
            if control.is_goto_chain() {
                let target_chain_id = control.as_goto_chain().unwrap();

                let chain = self.process_chain_manager.get_chain(target_chain_id);
                if chain.is_none() {
                    let msg = format!("Goto process chain '{}' not found", target_chain_id);
                    warn!("{}", msg);
                    return Err(msg);
                }

                context.counter().increment()?;

                let chain = chain.unwrap();
                let context = context.fork_chain(chain.clone());
                return self.execute_chain_inner(&chain, &context).await;
            }
        }

        Ok(ret)
    }

    async fn execute_chain_loop(
        &self,
        chain: &ProcessChainRef,
        context: &Context,
    ) -> Result<CommandResult, String> {
        let mut target_chain = None;
        let mut target_context = None;
        loop {
            let chain = if let Some(c) = target_chain.as_ref() {
                c
            } else {
                chain
            };

            let context = if let Some(c) = target_context.as_ref() {
                c
            } else {
                context
            };

            let ret = chain.execute(context).await?;
            if ret.is_control() {
                let control = ret.as_control().unwrap();
                if control.is_goto_chain() {
                    let target_chain_id = control.as_goto_chain().unwrap();

                    let target = self.process_chain_manager.get_chain(target_chain_id);
                    if target.is_none() {
                        let msg = format!("Goto process chain '{}' not found", target_chain_id);
                        warn!("{}", msg);
                        return Err(msg);
                    }

                    context.counter().increment()?;

                    let target = target.unwrap();
                    info!("Goto process chain '{}'", target_chain_id);
                    target_context = Some(context.fork_chain(target.clone()));
                    target_chain = Some(target);

                    continue;
                } else {
                    break Ok(ret);
                }
            } else {
                break Ok(ret);
            }
        }
    }
}
