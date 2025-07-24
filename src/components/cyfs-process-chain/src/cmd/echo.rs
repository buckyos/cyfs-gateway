use super::cmd::*;
use crate::block::CommandArgs;
use crate::chain::Context;
use clap::{Arg, ArgAction, Command};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;

// Echo command parser, which simply echoes the input arguments, such as: echo "Hello, World!"; echo -n "Hello," "World!"
// Echo command accepts any arguments and output them as a string with space concat.
pub struct EchoCommandParser {
    cmd: Command,
}

impl EchoCommandParser {
    pub fn new() -> Self {
        let cmd = Command::new("echo")
            .about("Display a line of text or output the given arguments.")
            .after_help(
                r#"
Options:
  -n          Do not print the trailing newline.

Behavior:
  - Joins all arguments with spaces and prints them.
  - By default, a newline is printed at the end.

Examples:
  echo "Hello, World!"
  echo -n "Hello," "World!"
"#,
            )
            .arg(
                Arg::new("no_newline")
                    .short('n')
                    .action(ArgAction::SetTrue)
                    .help("Do not print the trailing newline"),
            )
            .arg(
                Arg::new("args")
                    .help("Text arguments to display")
                    .num_args(0..)
                    .trailing_var_arg(true), // important: accepts any values
            );

        Self { cmd }
    }
}

impl CommandParser for EchoCommandParser {
    fn help(&self, _name: &str, help_type: CommandHelpType) -> String {
        command_help(help_type, &self.cmd)
    }

    fn check(&self, args: &CommandArgs) -> Result<(), String> {
        let arg_list = args.as_str_list();
        self.cmd
            .clone()
            .try_get_matches_from(&arg_list)
            .map_err(|e| e.to_string())?;

        Ok(())
    }

    fn parse(
        &self,
        args: Vec<String>,
        _origin_args: &CommandArgs,
    ) -> Result<CommandExecutorRef, String> {
        let matches = self.cmd.clone().try_get_matches_from(&args).map_err(|e| {
            let msg = format!("Invalid echo command: {:?}, {}", args, e);
            error!("{}", msg);
            msg
        })?;

        // Get the optional no_newline flag
        let suppress_newline = matches.get_flag("no_newline");

        // Get the arguments to echo
        let parts: Vec<&str> = matches
            .get_many::<String>("args")
            .map(|vals| vals.map(|v| v.as_str()).collect())
            .unwrap_or_else(Vec::new);

        let mut result = parts.join(" ");
        if suppress_newline {
            result.push('\n'); // Use '\n' to ensure the output is consistent with echo behavior
        }

        let cmd = EchoCommandExecutor::new(suppress_newline, result);
        Ok(Arc::new(Box::new(cmd)))
    }
}

// Echo command executor, which simply echoes the input arguments
pub struct EchoCommandExecutor {
    suppress_newline: bool,
    output: String,
}

impl EchoCommandExecutor {
    pub fn new(suppress_newline: bool, output: String) -> Self {
        Self {
            suppress_newline,
            output,
        }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for EchoCommandExecutor {
    async fn exec(&self, context: &Context) -> Result<CommandResult, String> {
        if !self.output.is_empty() {
            let mut stdout = context.pipe().stdout.lock().await;
            // Write the output to stdout
            if let Err(e) = stdout.write_all(self.output.as_bytes()).await {
                let msg = format!("Failed to write output to stdout: {}", e);
                error!("{}", msg);
                return Err(msg);
            }

            // Flush the output to ensure it is written immediately
            if let Err(e) = stdout.flush().await {
                let msg = format!("Failed to flush stdout: {}", e);
                error!("{}", msg);
                return Err(msg);
            }
        }

        Ok(CommandResult::success_with_value(self.output.as_str()))
    }
}
