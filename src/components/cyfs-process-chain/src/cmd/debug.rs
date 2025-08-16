use super::cmd::*;
use crate::CommandArgEvaluator;
use crate::block::{CommandArg, CommandArgs};
use crate::chain::{Context, ParserContext};
use crate::collection::CollectionValue;
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
  --verbose   Print additional information about the command execution, such as collections's contents.

Behavior:
  - Joins all arguments with spaces and prints them.
  - By default, a newline is printed at the end.

Examples:
  echo "Hello, World!";
  echo -n "Hello," "World!";
  echo --verbose $REQ;
"#,
            )
            .arg(
                Arg::new("no_newline")
                    .short('n')
                    .action(ArgAction::SetTrue)
                    .help("Do not print the trailing newline"),
            )
            .arg(
                Arg::new("verbose")
                    .long("verbose")
                    .short('v')
                    .action(ArgAction::SetTrue)
                    .help("Print additional information about the command execution, such as collections' contents"),
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
    fn group(&self) -> CommandGroup {
        CommandGroup::Debug
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
                let msg = format!("Invalid echo command: {:?}, {}", str_args, e);
                error!("{}", msg);
                msg
            })?;

        // Get the optional no_newline flag
        let suppress_newline = matches.get_flag("no_newline");
        let verbose = matches.get_flag("verbose");

        // Get the arguments to echo
        let output_args = match matches.indices_of("args") {
            Some(indices) => indices.map(|i| args[i].clone()).collect(),
            None => Vec::new(),
        };

        let cmd = EchoCommandExecutor::new(output_args, suppress_newline, verbose);
        Ok(Arc::new(Box::new(cmd)))
    }
}

// Echo command executor, which simply echoes the input arguments
pub struct EchoCommandExecutor {
    output_args: Vec<CommandArg>,
    suppress_newline: bool,
    verbose: bool,
}

impl EchoCommandExecutor {
    pub fn new(output_args: Vec<CommandArg>, suppress_newline: bool, verbose: bool) -> Self {
        Self {
            output_args,
            suppress_newline,
            verbose,
        }
    }

    async fn print_verbose_output(&self, value: &CollectionValue) -> Result<String, String> {
        let ret = match value {
            CollectionValue::String(s) => s.clone(),
            CollectionValue::Set(set) => {
                let values = set.dump().await?;
                format!("{{ {} }}", values.join(" "))
            }
            CollectionValue::Map(map) => {
                let values = map.dump().await?;
                values
                    .iter()
                    .map(|(k, v)| format!("{} = {}", k, v))
                    .collect::<Vec<_>>()
                    .join("\n")
            }
            CollectionValue::MultiMap(mmap) => {
                let values = mmap.dump().await?;
                values
                    .iter()
                    .map(|(k, v)| {
                        if v.len() == 1 {
                            format!("{} = {}", k, v.iter().next().unwrap())
                        } else {
                            format!(
                                "{} = {{ {} }}",
                                k,
                                v.iter().cloned().collect::<Vec<_>>().join(", ")
                            )
                        }
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            }
            CollectionValue::Visitor(_visitor) => {
                // TODO: Implement visitor output
                "[Visitor]".to_string()
            }
            CollectionValue::Any(any) => {
                // If it's an Any type, we can try to downcast it to a known type
                if let Some(s) = any.downcast_ref::<String>() {
                    s.clone()
                } else {
                    format!("[Any: {:?}]", any)
                }
            }
        };

        Ok(ret)
    }
}

#[async_trait::async_trait]
impl CommandExecutor for EchoCommandExecutor {
    async fn exec(&self, context: &Context) -> Result<CommandResult, String> {
        debug!("Executing echo command with args: {:?}", self.output_args);
        let output_str;
        if !self.output_args.is_empty() {
            let args = CommandArgEvaluator::evaluate_list(&self.output_args, context).await?;
            let mut output = Vec::with_capacity(args.len());
            for value in &args {
                if self.verbose {
                    let v = self.print_verbose_output(value).await?;
                    output.push(v);
                } else {
                    output.push(value.to_string());
                }
            }
            output_str = output.join(" ");

            debug!("Echo output: {}", output_str);
            let mut stdout = context.pipe().stdout.lock().await;
            debug!("Writing output to stdout: {}", output_str);
            // Write the output to stdout
            if let Err(e) = stdout.write_all(output_str.as_bytes()).await {
                let msg = format!("Failed to write output to stdout: {}", e);
                error!("{}", msg);
                return Err(msg);
            }

            // If suppress_newline is false, append a newline
            if !self.suppress_newline {
                if let Err(e) = stdout.write_all(b"\n").await {
                    let msg = format!("Failed to write newline to stdout: {}", e);
                    error!("{}", msg);
                    return Err(msg);
                }
            }

            // Flush the output to ensure it is written immediately
            if let Err(e) = stdout.flush().await {
                let msg = format!("Failed to flush stdout: {}", e);
                error!("{}", msg);
                return Err(msg);
            }
        } else {
            output_str = String::new();
        }

        Ok(CommandResult::success_with_value(output_str))
    }
}
