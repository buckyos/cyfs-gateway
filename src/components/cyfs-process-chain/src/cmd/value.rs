use super::cmd::*;
use crate::block::{CommandArg, CommandArgs};
use crate::chain::{Context, ParserContext};
use crate::collection::CollectionValue;
use clap::{Arg, Command};
use std::sync::Arc;

pub struct ToBoolCommandParser {
    cmd: Command,
}

impl ToBoolCommandParser {
    pub fn new() -> Self {
        let cmd = Command::new("to-bool")
            .about("Convert a value to bool according to execution coercion policy.")
            .arg(Arg::new("value").required(true).help("Value to convert"));
        Self { cmd }
    }
}

impl CommandParser for ToBoolCommandParser {
    fn group(&self) -> CommandGroup {
        CommandGroup::Variable
    }

    fn help(&self, _name: &str, help_type: CommandHelpType) -> String {
        command_help(help_type, &self.cmd)
    }

    fn parse_origin(
        &self,
        _context: &ParserContext,
        args: &CommandArgs,
    ) -> Result<CommandExecutorRef, String> {
        if args.len() != 2 {
            let msg = format!("Invalid to-bool command: {:?}", args);
            error!("{}", msg);
            return Err(msg);
        }

        let cmd = ToBoolCommandExecutor::new(args[1].clone());
        Ok(Arc::new(Box::new(cmd)))
    }
}

pub struct ToBoolCommandExecutor {
    value: CommandArg,
}

impl ToBoolCommandExecutor {
    pub fn new(value: CommandArg) -> Self {
        Self { value }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for ToBoolCommandExecutor {
    async fn exec(&self, context: &Context) -> Result<CommandResult, String> {
        match self.value.evaluate_bool(context).await {
            Ok(value) => Ok(CommandResult::success_with_string(value.to_string())),
            Err(e) => Ok(CommandResult::error_with_string(e)),
        }
    }
}

pub struct ToNumberCommandParser {
    cmd: Command,
}

impl ToNumberCommandParser {
    pub fn new() -> Self {
        let cmd = Command::new("to-number")
            .about("Convert a value to number according to execution coercion policy.")
            .arg(Arg::new("value").required(true).help("Value to convert"));
        Self { cmd }
    }
}

impl CommandParser for ToNumberCommandParser {
    fn group(&self) -> CommandGroup {
        CommandGroup::Variable
    }

    fn help(&self, _name: &str, help_type: CommandHelpType) -> String {
        command_help(help_type, &self.cmd)
    }

    fn parse_origin(
        &self,
        _context: &ParserContext,
        args: &CommandArgs,
    ) -> Result<CommandExecutorRef, String> {
        if args.len() != 2 {
            let msg = format!("Invalid to-number command: {:?}", args);
            error!("{}", msg);
            return Err(msg);
        }

        let cmd = ToNumberCommandExecutor::new(args[1].clone());
        Ok(Arc::new(Box::new(cmd)))
    }
}

pub struct ToNumberCommandExecutor {
    value: CommandArg,
}

impl ToNumberCommandExecutor {
    pub fn new(value: CommandArg) -> Self {
        Self { value }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for ToNumberCommandExecutor {
    async fn exec(&self, context: &Context) -> Result<CommandResult, String> {
        match self.value.evaluate_number(context).await {
            Ok(value) => Ok(CommandResult::success_with_string(value.to_string())),
            Err(e) => Ok(CommandResult::error_with_string(e)),
        }
    }
}

#[derive(Clone, Copy)]
enum ValuePredicateKind {
    Null,
    Bool,
    Number,
}

pub struct ValuePredicateCommandParser {
    cmd: Command,
    kind: ValuePredicateKind,
}

impl ValuePredicateCommandParser {
    fn new(name: &'static str, about: &'static str, kind: ValuePredicateKind) -> Self {
        let cmd = Command::new(name)
            .about(about)
            .arg(Arg::new("value").required(true).help("Value to inspect"));
        Self { cmd, kind }
    }
}

impl CommandParser for ValuePredicateCommandParser {
    fn group(&self) -> CommandGroup {
        CommandGroup::Variable
    }

    fn help(&self, _name: &str, help_type: CommandHelpType) -> String {
        command_help(help_type, &self.cmd)
    }

    fn parse_origin(
        &self,
        _context: &ParserContext,
        args: &CommandArgs,
    ) -> Result<CommandExecutorRef, String> {
        if args.len() != 2 {
            let msg = format!("Invalid {} command: {:?}", self.cmd.get_name(), args);
            error!("{}", msg);
            return Err(msg);
        }

        let cmd = ValuePredicateCommandExecutor::new(self.kind, args[1].clone());
        Ok(Arc::new(Box::new(cmd)))
    }
}

pub struct ValuePredicateCommandExecutor {
    kind: ValuePredicateKind,
    value: CommandArg,
}

impl ValuePredicateCommandExecutor {
    fn new(kind: ValuePredicateKind, value: CommandArg) -> Self {
        Self { kind, value }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for ValuePredicateCommandExecutor {
    async fn exec(&self, context: &Context) -> Result<CommandResult, String> {
        let value = self.value.evaluate(context).await?;

        let matched = match self.kind {
            ValuePredicateKind::Null => value.is_null(),
            ValuePredicateKind::Bool => value.is_bool(),
            ValuePredicateKind::Number => value.is_number(),
        };

        if matched {
            Ok(CommandResult::success_with_value(CollectionValue::Bool(true)))
        } else {
            Ok(CommandResult::error_with_value(CollectionValue::Bool(false)))
        }
    }
}

pub fn create_is_null_parser() -> ValuePredicateCommandParser {
    ValuePredicateCommandParser::new(
        "is-null",
        "Check whether a value is Null.",
        ValuePredicateKind::Null,
    )
}

pub fn create_is_bool_parser() -> ValuePredicateCommandParser {
    ValuePredicateCommandParser::new(
        "is-bool",
        "Check whether a value is Bool.",
        ValuePredicateKind::Bool,
    )
}

pub fn create_is_number_parser() -> ValuePredicateCommandParser {
    ValuePredicateCommandParser::new(
        "is-number",
        "Check whether a value is Number.",
        ValuePredicateKind::Number,
    )
}
