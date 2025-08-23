use super::chain::ProcessChainRef;
use super::context::Context;
use super::env::EnvRef;
use super::manager::{ProcessChainLibRef, ProcessChainLinkedManagerRef};
use super::stack::{
    ExecPointerBlockGuard, ExecPointerChainGuard, ExecPointerLibGuard, GotoCounter,
};
use crate::block::BlockExecuter;
use crate::cmd::{CommandControl, CommandControlLevel, CommandResult};
use crate::pipe::CommandPipe;
use std::sync::Arc;

pub struct ProcessChainExecutor;

impl ProcessChainExecutor {
    pub async fn execute_block(
        chain: &ProcessChainRef,
        block_id: &str,
        context: &Context,
    ) -> Result<CommandResult, String> {
        // First get the block by ID
        let block = chain.get_block(block_id);
        if block.is_none() {
            let msg = format!(
                "Block with ID '{}' not found in chain '{}'",
                block_id,
                chain.id()
            );
            warn!("{}", msg);
            return Err(msg);
        }

        let _block_guard = ExecPointerBlockGuard::new(&context.current_pointer(), block_id)?;

        let block = block.unwrap();
        let block_executer = BlockExecuter::new(&block.id);
        let block_context = context.fork_block();
        let result = block_executer.execute_block(block, &block_context).await?;

        Ok(result)
    }

    pub async fn execute_chain(
        chain: &ProcessChainRef,
        context: &Context,
    ) -> Result<CommandResult, String> {
        let blocks = chain.get_blocks();
        if blocks.is_empty() {
            let msg = format!("Process chain '{}' has no blocks to execute", chain.id());
            warn!("{}", msg);
            return Ok(CommandResult::success());
        }

        let _chain_guard = ExecPointerChainGuard::new(&context.current_pointer(), chain.clone())?;

        let mut chain_result = CommandResult::success();

        for i in 0..blocks.len() {
            let block = &blocks[i];

            let _block_guard = ExecPointerBlockGuard::new(&context.current_pointer(), &block.id)?;

            let block_executer = BlockExecuter::new(&block.id);
            let block_context = context.fork_block();
            let result = block_executer.execute_block(block, &block_context).await?;
            if result.is_control() {
                // If the block execution result is a control action, we handle it immediately
                // info!("Control action in block '{}': {:?}", block.id, result);

                let control = result.as_control().unwrap();
                match control {
                    CommandControl::Return(value) => {
                        info!("Returning from block '{}': {:?}", block.id, value);

                        match value.level {
                            CommandControlLevel::Block => {
                                // Return from the block with a value, and will continue to the next block
                                chain_result = result;
                                continue;
                            }
                            CommandControlLevel::Chain | CommandControlLevel::Lib => {
                                // Return from the entire chain
                                chain_result = result;
                                break;
                            }
                        }
                    }
                    CommandControl::Error(value) => {
                        warn!("Error return in block '{}': {:?}", block.id, value);

                        match value.level {
                            CommandControlLevel::Block => {
                                // Error return from the block, continue to the next block
                                chain_result = result;
                                continue;
                            }
                            CommandControlLevel::Chain | CommandControlLevel::Lib => {
                                // Error return from the entire chain
                                chain_result = result;
                                break;
                            }
                        }
                    }
                    CommandControl::Exit(value) => {
                        info!("Exiting chain from block '{}': {}", block.id, value);
                        chain_result = result;
                        break;
                    }
                    CommandControl::Break(_value) => {
                        let msg = format!(
                            "break action only valid in map-reduce loop, found in block '{}'",
                            block.id
                        );
                        error!("{}", msg);
                        return Err(msg);
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

pub struct ProcessChainLibExecutor {
    process_chain_lib: ProcessChainLibRef,
    context: Context,
}

impl ProcessChainLibExecutor {
    pub fn new(
        process_chain_lib: ProcessChainLibRef,
        process_chain_manager: ProcessChainLinkedManagerRef,
        global_env: EnvRef,
        pipe: CommandPipe,
    ) -> Self {
        let counter = Arc::new(GotoCounter::new());
        let context = Context::new(
            process_chain_manager,
            global_env.clone(),
            counter,
            pipe.clone(),
        );

        Self {
            process_chain_lib,
            context,
        }
    }

    pub fn new_with_context(process_chain_lib: ProcessChainLibRef, context: Context) -> Self {
        Self {
            process_chain_lib,
            context,
        }
    }

    pub fn context(&self) -> &Context {
        &self.context
    }

    pub fn chain_env(&self) -> &EnvRef {
        self.context.chain_env()
    }

    pub fn global_env(&self) -> &EnvRef {
        self.context.global_env()
    }

    pub fn pipe(&self) -> &CommandPipe {
        self.context.pipe()
    }

    /// Fork the executor to create a new context to execute the process chain lib or chain.
    pub fn fork(&self) -> Self {
        let counter = Arc::new(GotoCounter::new());
        let context = Context::new(
            self.context.process_chain_manager().clone(),
            self.context.global_env().clone(),
            counter,
            self.context.pipe().clone(),
        );

        Self {
            process_chain_lib: self.process_chain_lib.clone(),
            context,
        }
    }

    // Consume the executor and execute the process chain lib
    pub async fn execute_lib(self) -> Result<CommandResult, String> {
        let mut final_result = CommandResult::success();

        let _lib_guard = ExecPointerLibGuard::new(
            &self.context.current_pointer(),
            self.process_chain_lib.clone(),
        )?;

        // We execute the first chain in the list
        let mut chain_index = 0;
        let len = self.process_chain_lib.get_len()?;
        while chain_index < len {
            let chain = self.process_chain_lib.get_chain_by_index(chain_index)?;
            info!(
                "Executing process chain: {}:{}, {}",
                chain_index,
                chain.priority(),
                chain.id()
            );

            let ret = ProcessChainExecutor::execute_chain(&chain, &self.context).await?;
            if ret.is_control() {
                let control = ret.as_control().unwrap();
                if control.is_exit() {
                    info!(
                        "Exiting process chain execution from chain '{}'",
                        chain.id(),
                    );
                    final_result = ret;
                    break;
                } else if control.is_return_from_lib() {
                    info!("Returning from process chain lib with value: {:?}", control,);
                    final_result = ret;
                    break;
                } else if control.is_error_from_lib() {
                    info!(
                        "Error return from process chain lib with value: {:?}",
                        control,
                    );
                    final_result = ret;
                    break;
                } else {
                    // For other control actions, we just return the result
                    final_result = ret;
                }
            } else {
                // For normal execution, we just continue to the next chain
                final_result = ret;
            }

            chain_index += 1;
        }

        Ok(final_result)
    }

    // Consume the executor and execute a specific chain in the process chain lib
    pub async fn execute_chain(self, chain_id: &str) -> Result<CommandResult, String> {
        let chain = self.process_chain_lib.get_chain(chain_id)?.ok_or_else(|| {
            let msg = format!("Process chain '{}' not found in lib", chain_id);
            error!("{}", msg);
            msg
        })?;

        let _lib_guard = ExecPointerLibGuard::new(
            &self.context.current_pointer(),
            self.process_chain_lib.clone(),
        )?;

        ProcessChainExecutor::execute_chain(&chain, &self.context).await
    }
}
