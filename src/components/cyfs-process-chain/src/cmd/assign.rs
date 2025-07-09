use super::cmd::*;
use crate::block::{AssignKind, CommandArgs, Context};
use crate::chain::EnvLevel;
use std::sync::Arc;

pub struct AssignCommandParser {}

impl AssignCommandParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl CommandParser for AssignCommandParser {
    // export KEY=VALUE or export KEY
    // The first param is the kind of assignment, which can be "block", "chain" or "global"
    // The second param is the key, and the third param is the value (optional)
    fn check(&self, args: &CommandArgs) -> Result<(), String> {
        // Args must not be empty
        if args.is_empty() {
            let msg = "Invalid assign command: args cannot be empty".to_string();
            error!("{}", msg);
            return Err(msg);
        }

        // Expect a single argument in the form of KEY=VALUE
        if args.len() < 2 || args.len() > 3 {
            let msg = format!("Invalid assign command: {:?}", args);
            error!("{}", msg);
            return Err(msg);
        }

        Ok(())
    }

    fn parse(&self, args: &[&str]) -> Result<CommandExecutorRef, String> {
        // Args must not be checked before calling parse
        assert!(
            args.len() >= 2 && args.len() <= 3,
            "Assign command should have 2 or 3 args"
        );

        // Expect a single argument in the form of KEY=VALUE
        let kind = args[0];
        let kind = AssignKind::from_str(kind)
            .map_err(|e| format!("Invalid assign kind: {}. Error: {}", kind, e))?;

        let key = args[1].to_string();
        let value = if args.len() > 2 {
            Some(args[2].to_string())
        } else {
            None
        };

        let cmd: AssignCommand = AssignCommand::new(kind, key, value);
        Ok(Arc::new(Box::new(cmd)))
    }
}

pub struct AssignCommand {
    kind: AssignKind,
    key: String,
    value: Option<String>,
}

impl AssignCommand {
    pub fn new(kind: AssignKind, key: String, value: Option<String>) -> Self {
        Self { kind, key, value }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for AssignCommand {
    async fn exec(&self, context: &Context) -> Result<CommandResult, String> {
        let env_level = match self.kind {
            AssignKind::Block => EnvLevel::Block,
            AssignKind::Chain => EnvLevel::Chain,
            AssignKind::Global => EnvLevel::Global,
        };

        match self.value {
            Some(ref value) => {
                // Handle assignment with value
                context
                    .set_env_value(self.key.as_str(), value, Some(env_level))
                    .await?;

                Ok(CommandResult::success_with_value(value))
            }
            None => {
                // Handle assignment without value, which will change the variable scope
                context
                    .env()
                    .change_var_level(self.key.as_str(), Some(env_level));
                Ok(CommandResult::success())
            }
        }
    }
}
