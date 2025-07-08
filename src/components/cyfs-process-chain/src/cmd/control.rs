use super::cmd::*;
use crate::block::{BlockType, Context, BlockExecuter};
use std::sync::Arc;

// exec command, like: EXEC block1
pub struct ExecCommandParser {}

impl ExecCommandParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl CommandParser for ExecCommandParser {
    fn check(&self, _block_type: BlockType) -> bool {
        true
    }

    fn parse(&self, args: &[&str]) -> Result<CommandExecutorRef, String> {
        if args.len() != 1 {
            let msg = format!("Invalid exec command: {:?}", args);
            error!("{}", msg);
            return Err(msg);
        }

        let cmd = ExecCommandExecutor::new(args[0]);
        Ok(Arc::new(Box::new(cmd)))
    }
}

// exec command executer
pub struct ExecCommandExecutor {
    pub block: String,
}

impl ExecCommandExecutor {
    pub fn new(block: &str) -> Self {
        ExecCommandExecutor {
            block: block.to_string(),
        }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for ExecCommandExecutor {
    async fn exec(&self, context: &Context) -> Result<CommandResult, String> {
        // Get target block from context
        let block = context.chain().get_block(&self.block);
        if block.is_none() {
            let msg = format!("Exec target block not found: {}", self.block);
            error!("{}", msg);
            return Err(msg);
        }

        let block = block.unwrap();
        let executor = BlockExecuter::new(&block.id);
        let context = context.fork_block();

        // Execute the block
        executor.execute_block(&block, &context).await
    }
}