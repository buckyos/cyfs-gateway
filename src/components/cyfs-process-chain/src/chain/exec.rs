use super::chain::ProcessChain;
use crate::block::{Context, BlockExecuter};
use crate::cmd::{CommandResult, CommandControl, CommandControlLevel};

pub struct ProcessChainExecutor {
}

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
                        info!("Goto action in block '{}': level={:?}, target={}", block.id, level, target);
                        if *level == CommandControlLevel::Block {
                            // If it's a block-level goto, we can continue to the target block
                            let goto_index = chain.get_block_index(&target);
                            if goto_index.is_none() {
                                let msg = format!("Goto target block '{}' not found in chain '{}'", target, chain.id());
                                warn!("{}", msg);
                                return Err(msg);
                            }

                            i = goto_index.unwrap();

                            // TODO: What should the result be in this case?
                            // For now, we just set it to success and continue to the next block
                            chain_result = CommandResult::success();
                            
                            continue;
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
        }

        Ok(chain_result)
    }
}
