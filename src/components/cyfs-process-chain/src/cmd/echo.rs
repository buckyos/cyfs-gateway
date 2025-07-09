use super::cmd::*;
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
    fn check(&self, _args: &CommandArgs) -> Result<(), String> {
        // Accept any arguments, so no specific check is needed

        Ok(())
    }

    fn parse(&self, args: &[&str]) -> Result<CommandExecutorRef, String> {
        // Check first argument is not empty
        let mut suppress_newline = true;
        let mut arg_index = 0;
        if !args.is_empty() {
            match args[0] {
                "-n" | "--n" => {
                    suppress_newline = false;
                    arg_index += 1;
                }
                _ => {}
            }
        }

        // For better performance, we just join the rest of the arguments on parser
        let mut output = args[arg_index..].join(" ");
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
