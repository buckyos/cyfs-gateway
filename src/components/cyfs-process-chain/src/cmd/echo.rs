use super::cmd::*;
use super::helper::CommandArgHelper;
use crate::block::CommandArgs;
use crate::chain::Context;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;

// Echo command parser, which simply echoes the input arguments, such as: echo "Hello, World!"; echo -n "Hello," "World!"
// Echo command accepts any arguments and output them as a string with space concat.
pub struct EchoCommandParser;

impl EchoCommandParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl CommandParser for EchoCommandParser {
    fn check(&self, args: &CommandArgs) -> Result<(), String> {
        // Accept any arguments, but we should check the options
        if !args.is_empty() {
            CommandArgHelper::check_origin_options(args, &[&["n"]])?;
        }

        Ok(())
    }

    fn parse(&self, args: &[&str]) -> Result<CommandExecutorRef, String> {
        // Check first argument is not empty
        let mut suppress_newline = true;
        let mut option_count = 0;
        if !args.is_empty() {
            let options = CommandArgHelper::parse_options(args, &[&["n"]])?;
            option_count = options.len();

            for option in options {
                if option == "n" {
                    suppress_newline = false;
                } else {
                    let msg = format!("Invalid option '{}', expected one of ['-n']", option);
                    error!("{}", msg);
                    return Err(msg);
                }
            }
        }

        // For better performance, we just join the rest of the arguments on parser
        let mut output = if option_count < args.len() {
            args[option_count..].join(" ")
        } else {
            String::from("")
        };

        if !suppress_newline {
            output.push('\n');
        }

        let cmd = EchoCommandExecutor::new(suppress_newline, output);
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
