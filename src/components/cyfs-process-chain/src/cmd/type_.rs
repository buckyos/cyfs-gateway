use super::cmd::*;
use crate::block::CommandArgs;
use crate::chain::{Context, EnvLevel, ParserContext};
use clap::{Arg, ArgAction, Command};
use std::sync::Arc;

pub struct TypeCommandParser {
    cmd: Command,
}

/*
Get type of var:
type var
type $var
type map.key
*/
impl TypeCommandParser {
    pub fn new() -> Self {
        let cmd = Command::new("type")
            .about("Determine and display the type of the provided argument(s).")
            .after_help(
                r#"
Get the type of the given variable or collection value.

Scope Options:
  --export, --global   Global scope
  --chain              Chain scope
  --block, --local     Block scope

Behavior:
  - Evaluates argument and identifies its type.
  - If the target var exists, returns its success(type).
  - If the target var does not exist, returns error.
  - If scope is not specified, defaults to the variable's current scope, default is chain level

Examples:
    type my_var
    type --global $my_var
    type --block my_map.key
"#,
            )
            .arg(
                Arg::new("global")
                    .long("global")
                    .alias("export")
                    .help("Use global scope")
                    .action(ArgAction::SetTrue),
            )
            .arg(
                Arg::new("chain")
                    .long("chain")
                    .help("Use chain scope (default)")
                    .action(ArgAction::SetTrue),
            )
            .arg(
                Arg::new("block")
                    .long("block")
                    .alias("local")
                    .help("Use block (local) scope")
                    .action(ArgAction::SetTrue),
            )
            .arg(
                Arg::new("variable_name")
                    .help("The name of the variable to get type")
                    .required(true),
            );

        Self { cmd }
    }
}

impl CommandParser for TypeCommandParser {
    fn group(&self) -> CommandGroup {
        CommandGroup::Variable
    }

    fn help(&self, _name: &str, help_type: CommandHelpType) -> String {
        command_help(help_type, &self.cmd)
    }

    fn parse(
        &self,
        _context: &ParserContext,
        str_args: Vec<&str>,
        args: &CommandArgs,
    ) -> Result<CommandExecutorRef, String> {
        let matches = self
            .cmd
            .clone()
            .try_get_matches_from(&str_args)
            .map_err(|e| {
                let msg = format!("Invalid type command: {:?}, {}", str_args, e);
                error!("{}", msg);
                msg
            })?;

        // Determine the scope level based on the flags
        let level = if matches.get_flag("global") {
            Some(EnvLevel::Global)
        } else if matches.get_flag("chain") {
            Some(EnvLevel::Chain)
        } else if matches.get_flag("block") {
            Some(EnvLevel::Block)
        } else {
            // Default to current scope in env manager
            None
        };

        let var_index = matches.index_of("variable_name").ok_or_else(|| {
            let msg = "variable_name argument is required".to_string();
            error!("{}", msg);
            msg
        })?;

        let var = &args[var_index];
        if !var.is_literal() && !var.is_var() {
            let msg = format!("Invalid variable name: {:?}", var);
            error!("{}", msg);
            return Err(msg);
        }

        let cmd = TypeCommandExecutor::new(level, var.as_str().to_string());
        Ok(Arc::new(Box::new(cmd)))
    }
}

pub struct TypeCommandExecutor {
    level: Option<EnvLevel>,
    variable_name: String,
}

impl TypeCommandExecutor {
    pub fn new(level: Option<EnvLevel>, variable_name: String) -> Self {
        Self {
            level,
            variable_name,
        }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for TypeCommandExecutor {
    async fn exec(&self, context: &Context) -> Result<CommandResult, String> {
        match context.env().get(&self.variable_name, self.level).await? {
            Some(value) => Ok(CommandResult::success_with_value(value.get_type())),
            None => Ok(CommandResult::error_with_value("None")),
        }
    }
}
