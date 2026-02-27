use super::cmd::*;
use crate::block::{BlockExecuter, CommandArgs, Expression};
use crate::chain::{Context, EnvLevel, ParserContext};
use crate::collection::CollectionValue;
use clap::{Arg, Command};
use std::sync::Arc;

pub struct CaptureCommandParser {
    cmd: Command,
}

impl CaptureCommandParser {
    pub fn new() -> Self {
        let cmd = Command::new("capture")
            .about("Execute a sub-command once, capture its result value/status into local variables, and return the original result.")
            .after_help(
                r#"
Examples:
  capture --value geo --status st $(lookup-geo $clientIp)
  capture --value out $(call check_something $arg)

Notes:
  - The sub-command must be provided as command substitution: $(...)
  - Captured variables are written to block(local) scope.
  - This command returns the original sub-command CommandResult unchanged.
"#,
            )
            .arg(
                Arg::new("value")
                    .long("value")
                    .value_name("VAR")
                    .help("Variable name to store CommandResult.value()")
                    .required(false),
            )
            .arg(
                Arg::new("status")
                    .long("status")
                    .value_name("VAR")
                    .help("Variable name to store status: success|error|control")
                    .required(false),
            )
            .arg(
                Arg::new("command")
                    .index(1)
                    .required(true)
                    .help("Sub-command in command substitution form: $(...)"),
            );

        Self { cmd }
    }
}

impl CommandParser for CaptureCommandParser {
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
                let msg = format!("Invalid capture command: {:?}, {}", str_args, e);
                error!("{}", msg);
                msg
            })?;

        let value_var = if let Some(index) = matches.index_of("value") {
            let arg = &args[index];
            if !arg.is_literal() && !arg.is_var() {
                let msg = format!("Invalid --value variable name: {:?}", arg);
                error!("{}", msg);
                return Err(msg);
            }
            Some(arg.as_str().to_string())
        } else {
            None
        };

        let status_var = if let Some(index) = matches.index_of("status") {
            let arg = &args[index];
            if !arg.is_literal() && !arg.is_var() {
                let msg = format!("Invalid --status variable name: {:?}", arg);
                error!("{}", msg);
                return Err(msg);
            }
            Some(arg.as_str().to_string())
        } else {
            None
        };

        if value_var.is_none() && status_var.is_none() {
            let msg = "capture command requires at least one target: --value or --status"
                .to_string();
            error!("{}", msg);
            return Err(msg);
        }

        let cmd_index = matches.index_of("command").ok_or_else(|| {
            let msg = "Sub-command argument is required for capture command".to_string();
            error!("{}", msg);
            msg
        })?;

        let cmd = &args[cmd_index];
        if !cmd.is_command_substitution() {
            let msg = format!(
                "capture command expects command substitution as argument, found: {:?}",
                cmd
            );
            error!("{}", msg);
            return Err(msg);
        }

        let sub_command = cmd.as_command_substitution().unwrap().clone();
        let executor = CaptureCommandExecutor::new(value_var, status_var, sub_command);
        Ok(Arc::new(Box::new(executor)))
    }
}

pub struct CaptureCommandExecutor {
    value_var: Option<String>,
    status_var: Option<String>,
    sub_command: Box<Expression>,
}

impl CaptureCommandExecutor {
    pub fn new(
        value_var: Option<String>,
        status_var: Option<String>,
        sub_command: Box<Expression>,
    ) -> Self {
        Self {
            value_var,
            status_var,
            sub_command,
        }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for CaptureCommandExecutor {
    async fn exec(&self, context: &Context) -> Result<CommandResult, String> {
        let ret = BlockExecuter::execute_expression(&self.sub_command, context).await?;

        if let Some(value_var) = &self.value_var {
            context
                .env()
                .set(
                    value_var,
                    CollectionValue::String(ret.value().clone()),
                    Some(EnvLevel::Block),
                )
                .await?;
        }

        if let Some(status_var) = &self.status_var {
            let status = if ret.is_success() {
                "success"
            } else if ret.is_error() {
                "error"
            } else {
                "control"
            };

            context
                .env()
                .set(
                    status_var,
                    CollectionValue::String(status.to_string()),
                    Some(EnvLevel::Block),
                )
                .await?;
        }

        Ok(ret)
    }
}
