use super::cmd::*;
use crate::block::{block::BlockType, context::Context};
use std::sync::Arc;

pub struct ActionCommandParser {
    action: CommandAction,
}

impl ActionCommandParser {
    pub fn new(action: CommandAction) -> Self {
        ActionCommandParser { action }
    }
}

impl CommandParser for ActionCommandParser {
    fn check(&self, _block_type: BlockType) -> bool {
        // Action command can be used in any block
        true
    }

    fn parse(&self,  args: &Vec<String>) -> Result<CommandExecutorRef, String> {
        // Args must be empty
        if !args.is_empty() {
            let msg = format!("Invalid action command: {:?}", args);
            error!("{}", msg);
            return Err(msg);
        }

        let cmd = ActionCommandExecutor {
            action: self.action.clone(),
        };
        Ok(Arc::new(Box::new(cmd)))
    }
}

// Drop & Pass command
pub struct ActionCommandExecutor {
    action: CommandAction,
}

impl ActionCommandExecutor {
    pub fn new(action: CommandAction) -> Self {
        ActionCommandExecutor { action }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for ActionCommandExecutor {
    async fn exec(&self, _context: &mut Context) -> Result<CommandResult, String> {
        Ok(CommandResult {
            success: true,
            action: self.action.clone(),
            error_code: 0,
        })
    }
}
