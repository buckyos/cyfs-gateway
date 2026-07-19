use clap::{Arg, Command};
use cyfs_process_chain::*;

pub struct CallStack {
    name: String,
    cmd: Command,
}

impl CallStack {
    pub fn new() -> Self {
        let cmd = Command::new("call-stack")
            .about("Hand off the current ordered stream to a stack")
            .after_help(
                r#"
Examples:
    call-stack main_tls
"#,
            )
            .arg(
                Arg::new("stack_id")
                    .help("Target stack ID")
                    .index(1)
                    .required(true),
            );
        Self {
            name: "call-stack".to_string(),
            cmd,
        }
    }

    pub fn name(&self) -> &str {
        self.name.as_str()
    }
}

#[async_trait::async_trait]
impl ExternalCommand for CallStack {
    fn help(&self, name: &str, help_type: CommandHelpType) -> String {
        assert_eq!(self.cmd.get_name(), name);
        command_help(help_type, &self.cmd)
    }

    fn check(&self, args: &CommandArgs) -> Result<(), String> {
        self.cmd
            .clone()
            .try_get_matches_from(args.as_str_list())
            .map(|_| ())
            .map_err(|e| {
                let msg = format!("Invalid call-stack command: {:?}, {}", args, e);
                error!("{}", msg);
                msg
            })
    }

    async fn exec(
        &self,
        _context: &Context,
        args: &[CollectionValue],
        _origin_args: &CommandArgs,
    ) -> Result<CommandResult, String> {
        let mut str_args = Vec::with_capacity(args.len());
        for arg in args {
            if !arg.is_string() {
                return Err(format!(
                    "Invalid argument type: expected string, got {:?}",
                    arg
                ));
            }
            str_args.push(arg.as_str().unwrap());
        }
        let matches = self
            .cmd
            .clone()
            .try_get_matches_from(&str_args)
            .map_err(|e| format!("Invalid call-stack command: {:?}, {}", args, e))?;
        let stack_id = matches
            .get_one::<String>("stack_id")
            .ok_or_else(|| "stack_id is required".to_string())?;
        Ok(CommandResult::return_with_string(
            CommandControlLevel::Lib,
            format!("stack {}", stack_id),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn literal(value: &str) -> CommandArg {
        CommandArg::Literal(value.to_string())
    }

    #[test]
    fn test_call_stack_check_accepts_one_target() {
        let command = CallStack::new();
        let args = CommandArgs::new(vec![literal("call-stack"), literal("main_tls")]);
        command.check(&args).unwrap();
    }

    #[test]
    fn test_call_stack_check_rejects_missing_or_extra_target() {
        let command = CallStack::new();
        assert!(command
            .check(&CommandArgs::new(vec![literal("call-stack")]))
            .is_err());
        assert!(command
            .check(&CommandArgs::new(vec![
                literal("call-stack"),
                literal("main_tls"),
                literal("extra"),
            ]))
            .is_err());
    }
}
