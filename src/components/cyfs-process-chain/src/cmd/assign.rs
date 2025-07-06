use super::cmd::*;
use crate::block::{AssignKind, BlockType, Context};
use crate::chain::EnvLevel;
use std::sync::Arc;

pub struct AssignCommandParser {}

impl AssignCommandParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl CommandParser for AssignCommandParser {
    fn check(&self, _block_type: BlockType) -> bool {
        true
    }

    fn parse(&self, args: &[&str]) -> Result<CommandExecutorRef, String> {
        // Args must not be empty
        if args.len() < 2 {
            let msg = format!("Invalid assign command: {:?}", args);
            error!("{}", msg);
            return Err(msg);
        }

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
    async fn exec(&self, context: &mut Context) -> Result<CommandResult, String> {
        match self.value {
            Some(ref value) => {
                // Handle assignment with value
                let env_level = match self.kind {
                    AssignKind::Block => EnvLevel::Block,
                    AssignKind::Chain => EnvLevel::Chain,
                    AssignKind::Global => EnvLevel::Global,
                };

                // Set the value in the context
                context.set_env_value(self.key.as_str(), value, Some(env_level)).await?;
            }
            None => {
                // Handle assignment without value
                todo!("Assign command without value not implemented yet");
            }
        }

        // Return success
        Ok(CommandResult::success())
    }
}
