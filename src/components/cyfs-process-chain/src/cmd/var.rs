use super::cmd::*;
use crate::block::{AssignKind, CommandArg, CommandArgs};
use crate::chain::EnvLevel;
use crate::chain::{Context, ParserContext};
use crate::collection::CollectionValue;
use clap::{Arg, ArgAction, Command};
use std::sync::Arc;

pub struct AssignCommandParser {
    cmd: Command,
}

impl AssignCommandParser {
    pub fn new() -> Self {
        let cmd = Command::new("assign")
            .about("Manage variable definitions and scope preferences.")
            .override_usage(
                r#"
    [SCOPE] VAR=VALUE     Define or update a variable in the specified scope.
    VAR=VALUE             Define a variable in the default (chain) scope.
    SCOPE VAR             Set the default scope for future references to VAR.
    "#,
            )
            .after_help(
                r#"
Scope:
    export, global        Global scope (shared across chains)
    chain                 Chain-level scope (default)
    block, local          Block-level scope

Notes:
    - If a variable already exists, its value will be overwritten.
    - When assigning (VAR=VALUE), scope defaults to 'chain' unless explicitly specified.
    - When only VAR is given after a scope, it sets default lookup scope for VAR.

Examples:
    my_var=123
    global my_var=456
    block my_var
"#,
            );
        Self { cmd }
    }
}

impl CommandParser for AssignCommandParser {
    fn group(&self) -> CommandGroup {
        CommandGroup::Variable
    }

    fn help(&self, _name: &str, help_type: CommandHelpType) -> String {
        command_help(help_type, &self.cmd)
    }

    // [export|global|chain|block|local] KEY=VALUE or [export|global|chain|block|local]  KEY
    // The first param is the kind of assignment, which can be "block", "chain" or "global"
    // The second param is the key, and the third param is the value (optional)
    fn parse_origin(
        &self,
        _context: &ParserContext,
        args: &CommandArgs,
    ) -> Result<CommandExecutorRef, String> {
        // Expect at least 2 arguments, and at most 3 arguments
        if args.len() < 2 || args.len() > 3 {
            let msg = format!("Invalid assign command: {:?}", args);
            error!("{}", msg);
            return Err(msg);
        }

        // Expect a single argument in the form of KEY=VALUE
        let kind = args[0].as_literal_str().ok_or_else(|| {
            let msg = format!("Invalid assign command kind: {:?}", args[0]);
            error!("{}", msg);
            msg
        })?;

        let kind = AssignKind::from_str(&kind).map_err(|e| {
            let msg = format!("Invalid assign command kind: {:?}, {}", args[0], e);
            error!("{}", msg);
            msg
        })?;

        let key = args[1]
            .as_literal_str()
            .ok_or_else(|| {
                let msg = format!("Invalid assign command key: {:?}", args[1]);
                error!("{}", msg);
                msg
            })?
            .to_string();

        let value = if args.len() > 2 {
            Some(args[2].clone())
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
    value: Option<CommandArg>,
}

impl AssignCommand {
    pub fn new(kind: AssignKind, key: String, value: Option<CommandArg>) -> Self {
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
                let value = value.evaluate_string(context).await?;

                // Handle assignment with value
                context
                    .env()
                    .set(
                        self.key.as_str(),
                        CollectionValue::String(value.clone()),
                        Some(env_level),
                    )
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

// delete [option] <variable_name>
// variable_name: The name of the variable to delete, maybe a env value or a collection value
pub struct DeleteCommandParser {
    cmd: Command,
}

impl DeleteCommandParser {
    pub fn new() -> Self {
        let cmd = Command::new("delete")
            .about("Delete a variable or collection value from a specified scope.")
            .override_usage("delete [--global|--chain|--block] <variable_name>")
            .after_help(
                r#"
Deletes a variable or collection value from the specified scope.

Scope Options:
  --export, --global   Global scope
  --chain              Chain scope
  --block, --local     Block scope

Variable Names:
  - Variable names can include dot-separated paths to access nested values,
    especially for structured collections like set/map/multimap.
  - For example: $REQ.header, $REQ.headers.Host, $USER.config.theme
  - If scope is not specified, defaults to the variable's current scope.

Delete Modes:
  - If the full name refers to a top-level variable (e.g., $REQ, $temp), the entire
    variable will be deleted from the given scope.
  - If the name includes a path (e.g., REQ.header1), the command attempts
    to remove the key `header1` from the container `REQ`.

Examples:
  delete my_var;
  delete --global user_token;
  delete --block tmp_value;
  delete $REQ.header1;
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
                    .help("The name of the variable to delete")
                    .required(true),
            );

        Self { cmd }
    }
}

impl CommandParser for DeleteCommandParser {
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
                let msg = format!("Invalid delete command: {:?}, {}", str_args, e);
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

        let cmd = DeleteCommand::new(level, var.as_str().to_string());
        Ok(Arc::new(Box::new(cmd)))
    }
}

struct DeleteCommand {
    level: Option<EnvLevel>,
    var: String,
}

impl DeleteCommand {
    pub fn new(level: Option<EnvLevel>, var: String) -> Self {
        Self { level, var }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for DeleteCommand {
    async fn exec(&self, context: &Context) -> Result<CommandResult, String> {
        // Attempt to delete the variable from the specified scope
        let result = context.env().remove(&self.var, self.level).await;

        match result {
            Ok(Some(ret)) => Ok(CommandResult::success_with_value(ret.to_string())),
            Ok(None) => {
                let msg = format!(
                    "Variable '{}' not found in scope {:?}",
                    self.var, self.level
                );
                warn!("{}", msg);
                Ok(CommandResult::error_with_value(msg))
            }
            Err(e) => {
                let msg = format!("Failed to delete variable '{}': {}", self.var, e);
                error!("{}", msg);
                Err(msg)
            }
        }
    }
}
