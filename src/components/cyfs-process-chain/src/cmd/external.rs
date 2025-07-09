use super::cmd::*;
use crate::block::CommandArgs;
use crate::chain::Context;
use std::sync::Arc;

// EXEC command, like: EXEC app1
pub struct ExternalCommandParser {}

impl ExternalCommandParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl CommandParser for ExternalCommandParser {
    fn check(&self, args: &CommandArgs) -> Result<(), String> {
        // Args should not be empty
        if args.is_empty() {
            let msg = format!("Invalid exec command: {:?}", args);
            error!("{}", msg);
            return Err(msg);
        }

        Ok(())
    }

    fn parse(&self, args: &[&str]) -> Result<CommandExecutorRef, String> {
        // Args should not be empty
        assert!(!args.is_empty(), "Exec command should have at least 1 arg");

        let cmd = ExternalCommandExecutor::new(args);
        Ok(Arc::new(Box::new(cmd)))
    }
}

// EXEC command executer
pub struct ExternalCommandExecutor {
    pub command: String,
    pub args: Vec<String>,
}

impl ExternalCommandExecutor {
    pub fn new(args: &[&str]) -> Self {
        assert!(args.len() > 0);

        if args.len() == 1 {
            return Self {
                command: args[0].to_owned(),
                args: vec![],
            };
        }

        Self {
            command: args[0].to_owned(),
            args: args[1..].iter().map(|&s| s.to_owned()).collect(),
        }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for ExternalCommandExecutor {
    async fn exec(&self, _context: &Context) -> Result<CommandResult, String> {
        todo!("exec command not implemented yet");

        // Ok(CommandResult::success())
    }
}
