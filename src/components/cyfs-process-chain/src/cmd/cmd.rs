use crate::block::CommandArgs;
use crate::chain::{Context, ParserContext};
use crate::collection::CollectionValue;
use clap::Command;
use std::str::FromStr;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CommandGroup {
    Match,
    Control,
    String,
    Uri,
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
            CommandGroup::Uri => "uri",
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandControlLevel {
    Block,
    Chain,
    Lib,
}

impl CommandControlLevel {
    pub fn as_str(&self) -> &str {
        match self {
            CommandControlLevel::Block => "block",
            CommandControlLevel::Chain => "chain",
            CommandControlLevel::Lib => "lib",
        }
    }

    pub fn is_block(&self) -> bool {
        matches!(self, CommandControlLevel::Block)
    }

    pub fn is_chain(&self) -> bool {
        matches!(self, CommandControlLevel::Chain)
    }

    pub fn is_lib(&self) -> bool {
        matches!(self, CommandControlLevel::Lib)
    }
}

impl FromStr for CommandControlLevel {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "block" => Ok(CommandControlLevel::Block),
            "chain" => Ok(CommandControlLevel::Chain),
            "lib" => Ok(CommandControlLevel::Lib),
            _ => {
                let msg = format!("Invalid command control level: {}", s);
                error!("{}", msg);
                Err(msg)
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct CommandControlValue {
    pub level: CommandControlLevel,
    pub value: CollectionValue,
}

#[derive(Debug, Clone)]
pub enum CommandControl {
    Break(CollectionValue),      // Break the map-reduce loop with a specific value
    Return(CommandControlValue), // Return to caller with ok
    Error(CommandControlValue),  // Return to caller with error
    Exit(CollectionValue),       // Exit process chain list with value
}

impl CommandControl {
    pub fn is_return(&self) -> bool {
        matches!(self, CommandControl::Return(_))
    }

    pub fn is_return_from_lib(&self) -> bool {
        matches!(self, CommandControl::Return(value) if value.level == CommandControlLevel::Lib)
    }

    pub fn is_error(&self) -> bool {
        matches!(self, CommandControl::Error(_))
    }

    pub fn is_error_from_lib(&self) -> bool {
        matches!(self, CommandControl::Error(value) if value.level == CommandControlLevel::Lib)
    }

    pub fn is_exit(&self) -> bool {
        matches!(self, CommandControl::Exit(_))
    }

    pub fn is_break(&self) -> bool {
        matches!(self, CommandControl::Break(_))
    }

    pub fn as_break(&self) -> Option<&CollectionValue> {
        if let CommandControl::Break(value) = self {
            Some(value)
        } else {
            None
        }
    }

    pub fn value(&self) -> &CollectionValue {
        match self {
            CommandControl::Return(value) => &value.value,
            CommandControl::Error(value) => &value.value,
            CommandControl::Exit(value) => value,
            CommandControl::Break(value) => value,
        }
    }
}

#[derive(Debug, Clone)]
pub enum CommandResult {
    Success(CollectionValue),
    Error(CollectionValue),
    Control(CommandControl),
}

impl CommandResult {
    pub fn success() -> Self {
        Self::Success(CollectionValue::String("".to_string()))
    }

    pub fn success_with_string(value: impl Into<String>) -> Self {
        Self::Success(CollectionValue::String(value.into()))
    }

    pub fn success_with_value(value: CollectionValue) -> Self {
        Self::Success(value)
    }

    pub fn error() -> Self {
        Self::Error(CollectionValue::String("".to_string()))
    }

    pub fn error_with_string(value: impl Into<String>) -> Self {
        Self::Error(CollectionValue::String(value.into()))
    }

    pub fn error_with_value(value: CollectionValue) -> Self {
        Self::Error(value)
    }

    pub fn control(action: CommandControl) -> Self {
        Self::Control(action)
    }

    pub fn _return(level: CommandControlLevel) -> Self {
        Self::Control(CommandControl::Return(CommandControlValue {
            level,
            value: CollectionValue::String("".to_string()),
        }))
    }

    pub fn return_with_string(level: CommandControlLevel, value: impl Into<String>) -> Self {
        Self::return_with_value(level, CollectionValue::String(value.into()))
    }

    pub fn return_with_value(level: CommandControlLevel, value: CollectionValue) -> Self {
        Self::Control(CommandControl::Return(CommandControlValue { level, value }))
    }

    pub fn return_error(level: CommandControlLevel) -> Self {
        Self::Control(CommandControl::Error(CommandControlValue {
            level,
            value: CollectionValue::String("".to_string()),
        }))
    }

    pub fn return_error_with_string(level: CommandControlLevel, value: impl Into<String>) -> Self {
        Self::return_error_with_value(level, CollectionValue::String(value.into()))
    }

    pub fn return_error_with_value(level: CommandControlLevel, value: CollectionValue) -> Self {
        Self::Control(CommandControl::Error(CommandControlValue { level, value }))
    }

    pub fn exit_chain() -> Self {
        Self::Control(CommandControl::Exit(CollectionValue::String(
            "".to_string(),
        )))
    }

    pub fn exit_chain_with_string(value: impl Into<String>) -> Self {
        Self::exit_chain_with_value(CollectionValue::String(value.into()))
    }

    pub fn exit_chain_with_value(value: CollectionValue) -> Self {
        Self::Control(CommandControl::Exit(value))
    }

    pub fn _break() -> Self {
        Self::Control(CommandControl::Break(CollectionValue::String(
            "".to_string(),
        )))
    }

    pub fn break_with_string(value: impl Into<String>) -> Self {
        Self::break_with_value(CollectionValue::String(value.into()))
    }

    pub fn break_with_value(value: CollectionValue) -> Self {
        Self::Control(CommandControl::Break(value))
    }

    // drop is same as exit drop
    pub fn drop() -> Self {
        Self::exit_chain_with_string(CommandAction::Drop.as_str())
    }

    // Accept is same as exit success
    pub fn accept() -> Self {
        Self::exit_chain_with_string(CommandAction::Accept.as_str())
    }

    // Reject is same as exit reject
    pub fn reject() -> Self {
        Self::exit_chain_with_string(CommandAction::Reject.as_str())
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

    pub fn value_ref(&self) -> &CollectionValue {
        match self {
            CommandResult::Success(value) => value,
            CommandResult::Error(value) => value,
            CommandResult::Control(control) => control.value(),
        }
    }

    pub fn value(&self) -> String {
        self.value_ref().treat_as_str().to_owned()
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
        matches!(
            self,
            CommandResult::Control(CommandControl::Exit(value))
                if value.as_str() == Some(CommandAction::Accept.as_str())
        )
    }

    pub fn is_drop(&self) -> bool {
        matches!(
            self,
            CommandResult::Control(CommandControl::Exit(value))
                if value.as_str() == Some(CommandAction::Drop.as_str())
        )
    }

    pub fn is_reject(&self) -> bool {
        matches!(
            self,
            CommandResult::Control(CommandControl::Exit(value))
                if value.as_str() == Some(CommandAction::Reject.as_str())
        )
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

    pub fn into_substitution_value(self) -> Option<CollectionValue> {
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
