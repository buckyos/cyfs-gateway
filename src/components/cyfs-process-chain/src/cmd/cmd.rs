use crate::block::CommandArgs;
use crate::chain::{Context, ParserContext};
use std::sync::Arc;
use clap::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CommandGroup {
    Match,
    Control,
    String,
    Collection,
    Variable,
    Debug,
    External,
    MapReduce,
}

impl CommandGroup {
    pub fn as_str(&self) -> &'static str {
        match self {
            CommandGroup::Match => "match",
            CommandGroup::Control => "control",
            CommandGroup::String => "string",
            CommandGroup::Collection => "collection",
            CommandGroup::Variable => "variable",
            CommandGroup::Debug => "debug",
            CommandGroup::External => "external",
            CommandGroup::MapReduce => "map-reduce",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandHelpType {
    Usage,
    Short,
    Long,
}

impl CommandHelpType {
    pub fn as_str(&self) -> &'static str {
        match self {
            CommandHelpType::Usage => "usage",
            CommandHelpType::Short => "short",
            CommandHelpType::Long => "long",
        }
    }
}

pub type CommandParserRef = Arc<Box<dyn CommandParser>>;

pub fn command_help(help_type: CommandHelpType, cmd: &Command) -> String {
    let mut cmd = cmd.clone();
    match help_type {
        CommandHelpType::Usage => cmd.render_usage().to_string(),
        CommandHelpType::Short => cmd.render_help().to_string(),
        CommandHelpType::Long => cmd.render_long_help().to_string(),
    }
}

pub trait CommandParser: Send + Sync {
    /// Get the command group.
    fn group(&self) -> CommandGroup;

    /// Display command usage information.
    /// This is used to show help information for the command.
    fn help(&self, name: &str, _help_type: CommandHelpType) -> String {
        format!("Usage: {}", name)
    }

    /// Parse the command arguments if valid then return a CommandExecutor.
    fn parse_origin(
        &self,
        context: &ParserContext,
        args: &CommandArgs,
    ) -> Result<CommandExecutorRef, String> {
        let str_args = args
            .iter()
            .map(|value| value.as_str())
            .collect::<Vec<&str>>();

        self.parse(context, str_args, args)
    }

    fn parse(
        &self,
        _context: &ParserContext,
        _str_args: Vec<&str>,
        _args: &CommandArgs,
    ) -> Result<CommandExecutorRef, String> {
        unimplemented!("CommandParser::parse must be implemented by the parser");
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
    Break(String),                       // Break the map-reduce loop with a specific value
    Return(String),                      // Return to the block caller with ok
    Error(String),                       // Return to the block caller with error
    Exit(String),                        // Exit process chain list with value(string)
    Goto((CommandControlLevel, String)), // Goto a specific block or chain
}

impl CommandControl {
    pub fn is_goto_block(&self) -> bool {
        matches!(self, CommandControl::Goto((CommandControlLevel::Block, _)))
    }

    pub fn as_goto_block(&self) -> Option<&str> {
        if let CommandControl::Goto((CommandControlLevel::Block, block_id)) = self {
            Some(block_id)
        } else {
            None
        }
    }

    pub fn is_goto_chain(&self) -> bool {
        matches!(self, CommandControl::Goto((CommandControlLevel::Chain, _)))
    }

    pub fn as_goto_chain(&self) -> Option<&str> {
        if let CommandControl::Goto((CommandControlLevel::Chain, chain_id)) = self {
            Some(chain_id)
        } else {
            None
        }
    }

    pub fn is_return(&self) -> bool {
        matches!(self, CommandControl::Return(_))
    }

    pub fn is_error(&self) -> bool {
        matches!(self, CommandControl::Error(_))
    }

    pub fn is_exit(&self) -> bool {
        matches!(self, CommandControl::Exit(_))
    }

    pub fn is_break(&self) -> bool {
        matches!(self, CommandControl::Break(_))
    }

    pub fn as_break(&self) -> Option<&str> {
        if let CommandControl::Break(value) = self {
            Some(value)
        } else {
            None
        }
    }
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

    pub fn return_to_block() -> Self {
        Self::Control(CommandControl::Return("".to_string()))
    }

    pub fn return_to_block_with_value(value: impl Into<String>) -> Self {
        Self::Control(CommandControl::Return(value.into()))
    }

    pub fn error_to_block() -> Self {
        Self::Control(CommandControl::Error("".to_string()))
    }

    pub fn error_to_block_with_value(value: impl Into<String>) -> Self {
        Self::Control(CommandControl::Error(value.into()))
    }

    pub fn exit_chain() -> Self {
        Self::Control(CommandControl::Exit("".to_string()))
    }

    pub fn exit_chain_with_value(value: impl Into<String>) -> Self {
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

    pub fn _break() -> Self {
        Self::Control(CommandControl::Break("".to_string()))
    }

    pub fn break_with_value(value: impl Into<String>) -> Self {
        Self::Control(CommandControl::Break(value.into()))
    }

    // drop is same as exit drop
    pub fn drop() -> Self {
        Self::exit_chain_with_value(CommandAction::Drop.as_str())
    }

    // Accept is same as exit success
    pub fn accept() -> Self {
        Self::exit_chain_with_value(CommandAction::Accept.as_str())
    }

    // Reject is same as exit reject
    pub fn reject() -> Self {
        Self::exit_chain_with_value(CommandAction::Reject.as_str())
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

    pub fn is_accept(&self) -> bool {
        matches!(self, CommandResult::Control(CommandControl::Exit(value)) if value == CommandAction::Accept.as_str())
    }

    pub fn is_drop(&self) -> bool {
        matches!(self, CommandResult::Control(CommandControl::Exit(value)) if value == CommandAction::Drop.as_str())
    }

    pub fn is_reject(&self) -> bool {
        matches!(self, CommandResult::Control(CommandControl::Exit(value)) if value == CommandAction::Reject.as_str())
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
        matches!(self, CommandResult::Success(_) | CommandResult::Error(_))
    }

    pub fn into_substitution_value(self) -> Option<String> {
        if let CommandResult::Success(value) = self {
            Some(value)
        } else if let CommandResult::Error(value) = self {
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
