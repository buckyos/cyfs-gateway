use crate::block::{BlockType, CommandArgs, Context};
use std::sync::Arc;

pub type CommandParserRef = Arc<Box<dyn CommandParser>>;

pub trait CommandParser: Send + Sync {
    // To check if the command is valid in the block
    fn check(&self, block_type: BlockType) -> bool;

    fn parse_origin(
        &self,
        args: Vec<String>,
        _origin_args: &CommandArgs,
    ) -> Result<CommandExecutorRef, String> {
        let args = args.iter().map(|s| s.as_str()).collect::<Vec<&str>>();
        self.parse(&args)
    }

    fn parse(&self, _args: &[&str]) -> Result<CommandExecutorRef, String> {
        unimplemented!("CommandParser::parse should be implemented by the command parser");
    }
}

#[derive(Debug, Clone)]
pub enum CommandAction {
    Drop,
    Accept,
    Reject,
}

impl CommandAction {
    pub fn as_str(&self) -> &str {
        match self {
            CommandAction::Drop => "drop",
            CommandAction::Accept => "accept",
            CommandAction::Reject => "reject",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandControlLevel {
    Block,
    Chain,
}

#[derive(Debug, Clone)]
pub enum CommandControl {
    Return(String),                      // Return to the block caller with ok
    Error(String),                       // Return to the block caller with error
    Exit(String),                        // Exit current chain with ok
    Goto((CommandControlLevel, String)), // Goto a specific block or chain
}

#[derive(Debug, Clone)]
pub enum CommandResult {
    Success(String),
    Error(String),
    Control(CommandControl),
}

impl CommandResult {
    pub fn success() -> Self {
        Self::Success("".to_string())
    }

    pub fn success_with_value(value: impl Into<String>) -> Self {
        Self::Success(value.into())
    }

    pub fn error() -> Self {
        Self::Error("".to_string())
    }

    pub fn error_with_value(value: impl Into<String>) -> Self {
        Self::Error(value.into())
    }

    pub fn control(action: CommandControl) -> Self {
        Self::Control(action)
    }

    pub fn return_to_block(value: impl Into<String>) -> Self {
        Self::Control(CommandControl::Return(value.into()))
    }

    pub fn error_to_block(value: impl Into<String>) -> Self {
        Self::Control(CommandControl::Error(value.into()))
    }

    pub fn exit_chain(value: impl Into<String>) -> Self {
        Self::Control(CommandControl::Exit(value.into()))
    }

    pub fn goto_block(block_id: impl Into<String>) -> Self {
        Self::Control(CommandControl::Goto((
            CommandControlLevel::Block,
            block_id.into(),
        )))
    }

    pub fn goto_chain(chain_id: impl Into<String>) -> Self {
        Self::Control(CommandControl::Goto((
            CommandControlLevel::Chain,
            chain_id.into(),
        )))
    }

    // drop is same as exit drop
    pub fn drop() -> Self {
        Self::exit_chain(CommandAction::Drop.as_str())
    }

    // Accept is same as exit success
    pub fn accept() -> Self {
        Self::exit_chain(CommandAction::Accept.as_str())
    }

    // Reject is same as exit reject
    pub fn reject() -> Self {
        Self::exit_chain(CommandAction::Reject.as_str())
    }

    // ret = !ret, but  is action, then will return error
    pub fn try_not(&self) -> Result<CommandResult, String> {
        match self {
            CommandResult::Success(value) => Ok(CommandResult::Error(value.clone())),
            CommandResult::Error(value) => Ok(CommandResult::Success(value.clone())),
            CommandResult::Control(action) => {
                let msg = format!("Cannot negate action result: {:?}", action);
                warn!("{}", msg);
                Err(msg)
            }
        }
    }

    pub fn is_success(&self) -> bool {
        matches!(self, CommandResult::Success(_))
    }

    pub fn is_error(&self) -> bool {
        matches!(self, CommandResult::Error(_))
    }

    pub fn is_control(&self) -> bool {
        matches!(self, CommandResult::Control(_))
    }

    pub fn into_control(self) -> Option<CommandControl> {
        if let CommandResult::Control(action) = self {
            Some(action)
        } else {
            None
        }
    }

    pub fn as_control(&self) -> Option<&CommandControl> {
        if let CommandResult::Control(action) = self {
            Some(action)
        } else {
            None
        }
    }

    pub fn is_substitution_value(&self) -> bool {
        matches!(self, CommandResult::Success(_))
    }

    pub fn into_substitution_value(self) -> Option<String> {
        if let CommandResult::Success(value) = self {
            Some(value)
        } else {
            None
        }
    }
}

// CommandExecutor is the trait for executing a command
#[async_trait::async_trait]
pub trait CommandExecutor: Send + Sync {
    async fn exec(&self, context: &Context) -> Result<CommandResult, String>;
}

pub type CommandExecutorRef = Arc<Box<dyn CommandExecutor>>;
