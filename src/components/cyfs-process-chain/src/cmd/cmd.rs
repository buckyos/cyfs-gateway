use crate::block::{BlockType, Context, CommandArgs};
use std::sync::Arc;

pub type CommandParserRef = Arc<Box<dyn CommandParser>>;

pub trait CommandParser: Send + Sync {
    // To check if the command is valid in the block
    fn check(&self, block_type: BlockType) -> bool;

    fn parse_origin(&self, args: Vec<String>, _origin_args: &CommandArgs) -> Result<CommandExecutorRef, String> {
        let args = args
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<&str>>();
        self.parse(&args)
    }

    fn parse(&self, _args: &[&str]) -> Result<CommandExecutorRef, String> {
        unimplemented!("CommandParser::parse should be implemented by the command parser");
    }
}

#[derive(Debug, Clone)]
pub enum CommandAction {
    Ok,
    Drop,
    Pass,
    Goto(String),
    Value(String),
}

// The result of a command execution
#[derive(Debug)]
pub struct CommandResult {
    pub success: bool,
    pub action: CommandAction,
    pub error_code: i32,
}

impl CommandResult {
    pub fn success() -> Self {
        CommandResult {
            success: true,
            action: CommandAction::Ok,
            error_code: 0,
        }
    }

    pub fn failure(code: i32) -> Self {
        CommandResult {
            success: false,
            action: CommandAction::Ok,
            error_code: code,
        }
    }

    pub fn drop() -> Self {
        CommandResult {
            success: true,
            action: CommandAction::Drop,
            error_code: 0,
        }
    }

    pub fn pass() -> Self {
        CommandResult {
            success: true,
            action: CommandAction::Pass,
            error_code: 0,
        }
    }

    pub fn goto(target: impl Into<String>) -> Self {
        CommandResult {
            success: true,
            action: CommandAction::Goto(target.into()),
            error_code: 0,
        }
    }

    pub fn value(value: impl Into<String>) -> Self {
        CommandResult {
            success: true,
            action: CommandAction::Value(value.into()),
            error_code: 0,
        }
    }

    pub fn is_special_action(&self) -> bool {
        match self.action {
            CommandAction::Ok => false,
            CommandAction::Value(_) => false,
            _ => true,
        }
    }

    pub fn is_value(&self) -> bool {
        matches!(self.action, CommandAction::Value(_))
    }

    pub fn into_value(self) -> Option<String> {
        if let CommandAction::Value(value) = self.action {
            Some(value)
        } else {
            None
        }
    }
}

// CommandExecutor is the trait for executing a command
#[async_trait::async_trait]
pub trait CommandExecutor: Send + Sync {
    async fn exec(&self, context: &mut Context) -> Result<CommandResult, String>;
}

pub type CommandExecutorRef = Arc<Box<dyn CommandExecutor>>;
