use super::cmd::*;
use crate::block::{BlockExecuter, BlockType, Context};
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

enum GotoTarget {
    Block(String),
    Chain(String),
}

// goto command, like: goto block1; goto --chain chain1; goto --block block2;
pub struct GotoCommandParser {}

impl GotoCommandParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl CommandParser for GotoCommandParser {
    fn check(&self, _block_type: BlockType) -> bool {
        true
    }

    fn parse(&self, args: &[&str]) -> Result<CommandExecutorRef, String> {
        if args.len() < 1 || args.len() > 2 {
            let msg = format!("Invalid goto command: {:?}", args);
            error!("{}", msg);
            return Err(msg);
        }

        // Parse the command arguments
        // If only one argument is provided, it is considered a chain name
        // If two arguments are provided, the first one must be --chain or --block
        // and the second one is the target name
        let name = args.last().unwrap().to_string();
        let target = if args.len() == 2 {
            match args[0] {
                "--chain" => GotoTarget::Chain(name),
                "--block" => GotoTarget::Block(name),
                _ => {
                    let msg = format!(
                        "Invalid goto command: expected --chain or --block, got {}",
                        args[0]
                    );
                    error!("{}", msg);
                    return Err(msg);
                }
            }
        } else {
            GotoTarget::Chain(name)
        };

        let cmd = GotoCommandExecutor::new(target);
        Ok(Arc::new(Box::new(cmd)))
    }
}

// goto command executer
pub struct GotoCommandExecutor {
    target: GotoTarget,
}

impl GotoCommandExecutor {
    fn new(target: GotoTarget) -> Self {
        Self { target }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for GotoCommandExecutor {
    async fn exec(&self, _context: &Context) -> Result<CommandResult, String> {
        let ret = match &self.target {
            GotoTarget::Block(block) => CommandResult::goto_block(block),
            GotoTarget::Chain(chain) => CommandResult::goto_chain(chain),
        };

        Ok(ret)
    }
}
