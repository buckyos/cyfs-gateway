use super::cmd::*;
use crate::block::CommandArgs;
use crate::chain::Context;
use std::sync::Arc;

// some action commands, DROP/ACCEPT/REJECT
pub struct ActionCommandParser {
    action: CommandAction,
}

impl ActionCommandParser {
    pub fn new(action: CommandAction) -> Self {
        Self { action }
    }
}

impl CommandParser for ActionCommandParser {
    fn check(&self, args: &CommandArgs) -> Result<(), String> {
        // Args must be empty
        if !args.is_empty() {
            let msg = format!("Invalid action command: {:?}", args);
            error!("{}", msg);
            return Err(msg);
        }

        Ok(())
    }

    fn parse(&self, args: Vec<String>, _origin_args: &CommandArgs) -> Result<CommandExecutorRef, String> {
        // Args must be empty
        assert!(args.is_empty(), "Action command should not have any args");

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
    async fn exec(&self, _context: &Context) -> Result<CommandResult, String> {
        let ret = match self.action {
            CommandAction::Drop => CommandResult::drop(),
            CommandAction::Accept => CommandResult::accept(),
            CommandAction::Reject => CommandResult::reject(),
        };

        Ok(ret)
    }
}
