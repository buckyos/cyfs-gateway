use super::types::*;
use crate::block::{BlockExecuter, CommandArgs, Expression};
use crate::chain::{Context, EnvLevel, EnvManager, ParserContext};
use crate::collection::CollectionValue;
use clap::{Arg, Command};
use std::sync::Arc;

struct CaptureTarget {
    key: String,
    simple_root: bool,
}

impl CaptureTarget {
    fn new(key: String) -> Self {
        let simple_root = EnvManager::is_simple_root_key(&key);
        Self { key, simple_root }
    }

    async fn set(&self, context: &Context, value: CollectionValue) -> Result<(), String> {
        if self.simple_root {
            context
                .env()
                .set_simple_root_at_explicit_level(&self.key, value, EnvLevel::Block)
                .await?;
        } else {
            context
                .env()
                .set(&self.key, value, Some(EnvLevel::Block))
                .await?;
        }

        Ok(())
    }
}

pub struct CaptureCommandParser {
    cmd: Command,
}

impl CaptureCommandParser {
    fn parse_target_var(
        matches: &clap::ArgMatches,
        args: &CommandArgs,
        name: &str,
    ) -> Result<Option<CaptureTarget>, String> {
        if let Some(index) = matches.index_of(name) {
            let arg = &args[index];
            if !arg.is_literal() && !arg.is_var() {
                let msg = format!("Invalid --{} variable name: {:?}", name, arg);
                error!("{}", msg);
                return Err(msg);
            }
            Ok(Some(CaptureTarget::new(arg.as_str().to_string())))
        } else {
            Ok(None)
        }
    }

    pub fn new() -> Self {
        let cmd = Command::new("capture")
            .about("Execute a sub-command once, capture its result value/status into local variables, and return the original result.")
            .after_help(
                r#"
Examples:
  capture --value geo --ok ok --status st $(lookup-geo $clientIp)
  capture --value out $(call check_something $arg)
  capture --status st --control ctl --control-kind kind --from from $(some-command)

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
                Arg::new("ok")
                    .long("ok")
                    .value_name("VAR")
                    .help("Variable name to store bool: result is success")
                    .required(false),
            )
            .arg(
                Arg::new("error")
                    .long("error")
                    .value_name("VAR")
                    .help("Variable name to store bool: result is error")
                    .required(false),
            )
            .arg(
                Arg::new("control")
                    .long("control")
                    .value_name("VAR")
                    .help("Variable name to store bool: result is control")
                    .required(false),
            )
            .arg(
                Arg::new("control_kind")
                    .long("control-kind")
                    .value_name("VAR")
                    .help("Variable name to store control kind: return|error|exit|break; Null if not control")
                    .required(false),
            )
            .arg(
                Arg::new("from")
                    .long("from")
                    .value_name("VAR")
                    .help("Variable name to store control level: block|chain|lib; Null if not return/error")
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

        let value_var = Self::parse_target_var(&matches, args, "value")?;
        let status_var = Self::parse_target_var(&matches, args, "status")?;
        let ok_var = Self::parse_target_var(&matches, args, "ok")?;
        let error_var = Self::parse_target_var(&matches, args, "error")?;
        let control_var = Self::parse_target_var(&matches, args, "control")?;
        let control_kind_var = Self::parse_target_var(&matches, args, "control_kind")?;
        let from_var = Self::parse_target_var(&matches, args, "from")?;

        if value_var.is_none()
            && status_var.is_none()
            && ok_var.is_none()
            && error_var.is_none()
            && control_var.is_none()
            && control_kind_var.is_none()
            && from_var.is_none()
        {
            let msg = "capture command requires at least one target option".to_string();
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

        let sub_command = Box::new(cmd.as_command_substitution().unwrap().clone());
        let executor = CaptureCommandExecutor {
            value_var,
            status_var,
            ok_var,
            error_var,
            control_var,
            control_kind_var,
            from_var,
            sub_command,
        };
        Ok(Arc::new(Box::new(executor)))
    }
}

pub struct CaptureCommandExecutor {
    value_var: Option<CaptureTarget>,
    status_var: Option<CaptureTarget>,
    ok_var: Option<CaptureTarget>,
    error_var: Option<CaptureTarget>,
    control_var: Option<CaptureTarget>,
    control_kind_var: Option<CaptureTarget>,
    from_var: Option<CaptureTarget>,
    sub_command: Box<Expression>,
}

#[async_trait::async_trait]
impl CommandExecutor for CaptureCommandExecutor {
    async fn exec(&self, context: &Context) -> Result<CommandResult, String> {
        let ret = BlockExecuter::execute_expression(&self.sub_command, context).await?;

        if let Some(value_var) = &self.value_var {
            value_var.set(context, ret.value_ref().clone()).await?;
        }

        if let Some(status_var) = &self.status_var {
            let status = if ret.is_success() {
                "success"
            } else if ret.is_error() {
                "error"
            } else {
                "control"
            };

            status_var
                .set(context, CollectionValue::String(status.to_string()))
                .await?;
        }

        if let Some(ok_var) = &self.ok_var {
            ok_var
                .set(context, CollectionValue::Bool(ret.is_success()))
                .await?;
        }

        if let Some(error_var) = &self.error_var {
            error_var
                .set(context, CollectionValue::Bool(ret.is_error()))
                .await?;
        }

        if let Some(control_var) = &self.control_var {
            control_var
                .set(context, CollectionValue::Bool(ret.is_control()))
                .await?;
        }

        if let Some(control_kind_var) = &self.control_kind_var {
            let control_kind = match ret.as_control() {
                Some(CommandControl::Return(_)) => CollectionValue::String("return".to_string()),
                Some(CommandControl::Error(_)) => CollectionValue::String("error".to_string()),
                Some(CommandControl::Exit(_)) => CollectionValue::String("exit".to_string()),
                Some(CommandControl::Break(_)) => CollectionValue::String("break".to_string()),
                None => CollectionValue::Null,
            };

            control_kind_var.set(context, control_kind).await?;
        }

        if let Some(from_var) = &self.from_var {
            let from = match ret.as_control() {
                Some(CommandControl::Return(v)) | Some(CommandControl::Error(v)) => {
                    CollectionValue::String(v.level.as_str().to_string())
                }
                _ => CollectionValue::Null,
            };

            from_var.set(context, from).await?;
        }

        Ok(ret)
    }
}
