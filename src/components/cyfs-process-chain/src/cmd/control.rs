use super::cmd::*;
use crate::block::{BlockExecuter, CommandArg, CommandArgs};
use crate::chain::{Context, ParserContext, ProcessChainsExecutor};
use clap::{Arg, ArgAction, Command};
use std::str::FromStr;
use std::sync::Arc;

// exec command, exec a block by block_id, like: EXEC block1
pub struct ExecCommandParser {
    cmd: Command,
}

impl ExecCommandParser {
    pub fn new() -> Self {
        let cmd = Command::new("exec")
            .about("Execute a block by its identifier within the current process chain.")
            .after_help(
                r#"
Arguments:
  <block_id>    The ID of the block to execute.

Behavior:
  - The specified block must exist in the current process chain.
  - The block will be executed immediately, and its result is returned.
  - Execution then continues with the next command in the current block.
  - If the block does not exist, an error will occur.

Examples:
  exec verify_token
  exec block_login && drop
"#,
            )
            .arg(
                Arg::new("block_id")
                    .required(true)
                    .value_name("block_id")
                    .help("The ID of the block to execute"),
            );

        Self { cmd }
    }
}

impl CommandParser for ExecCommandParser {
    fn group(&self) -> CommandGroup {
        CommandGroup::Control
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
                let msg = format!("Invalid exec command: {:?}, {}", str_args, e);
                error!("{}", msg);
                msg
            })?;

        let block_index = matches.index_of("block_id").ok_or_else(|| {
            let msg = "block_id argument is required for exec command".to_string();
            error!("{}", msg);
            msg
        })?;

        let block = args[block_index].clone();

        let cmd = ExecCommandExecutor::new(block);
        Ok(Arc::new(Box::new(cmd)))
    }
}

// exec command executer
pub struct ExecCommandExecutor {
    pub block: CommandArg,
}

impl ExecCommandExecutor {
    pub fn new(block: CommandArg) -> Self {
        Self { block }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for ExecCommandExecutor {
    async fn exec(&self, context: &Context) -> Result<CommandResult, String> {
        let block_id = self.block.evaluate_string(context).await?;

        // Get target block from context
        let chain = context.chain().ok_or_else(|| {
            let msg = "Exec command requires a chain context".to_string();
            error!("{}", msg);
            msg
        })?;

        let exec = ProcessChainsExecutor::new(
            context.process_chain_manager().clone(),
            context.global_env().clone(),
            context.pipe().clone(),
        );
        let ret = exec
            .execute_block_by_id2(&chain, &block_id)
            .await
            .map_err(|e| {
                let msg = format!("Failed to execute block '{}': {}", block_id, e);
                error!("{}", msg);
                msg
            })?;

        Ok(ret)
    }
}

/*
enum GotoTarget {
    Block(String),
    Chain(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum GotoTargetLevel {
    Block,
    Chain,
}

// goto command goto [--chain|--block] <target>
// like: goto block1; goto --chain chain1; goto --block block2;
pub struct GotoCommandParser {
    cmd: Command,
}

impl GotoCommandParser {
    pub fn new() -> Self {
        let cmd = Command::new("goto")
            .about("Jump to a block or another chain within the process flow.")
            .after_help(
                r#"
Arguments:
  <target>     The name of the target block or chain.

Options:
  --chain      Jump to a chain by name (default).
  --block      Jump to a block in the current chain.

Behavior:
  - Without options, defaults to jumping to a chain.
  - When using `--chain`, execution switches to the specified chain.
  - When using `--block`, jumps to a block inside the current chain.
  - The next command of the current command will not be executed any more.
  - Fails if the target block/chain does not exist.

Examples:
  goto login_retry
  goto --block validate_input
  goto --chain fallback_chain
"#,
            )
            .arg(
                Arg::new("chain")
                    .long("chain")
                    .conflicts_with("block")
                    .help("Jump to another chain")
                    .action(ArgAction::SetTrue),
            )
            .arg(
                Arg::new("block")
                    .long("block")
                    .conflicts_with("chain")
                    .help("Jump to a block in the current chain (default)")
                    .action(ArgAction::SetTrue),
            )
            .arg(
                Arg::new("target")
                    .required(true)
                    .help("The name of the target block or chain"),
            );

        Self { cmd }
    }
}

impl CommandParser for GotoCommandParser {
    fn group(&self) -> CommandGroup {
        CommandGroup::Control
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
                let msg = format!("Invalid goto command: {:?}, {}", str_args, e);
                error!("{}", msg);
                msg
            })?;

        let target_level = if matches.get_flag("chain") {
            GotoTargetLevel::Chain
        } else if matches.get_flag("block") {
            GotoTargetLevel::Block
        } else {
            GotoTargetLevel::Chain // Default to chain if no option is provided
        };

        let target_index = matches.index_of("target").ok_or_else(|| {
            let msg = "target argument is required for goto command".to_string();
            error!("{}", msg);
            msg
        })?;
        let target = args[target_index].clone();

        let cmd = GotoCommandExecutor::new(target, target_level);
        Ok(Arc::new(Box::new(cmd)))
    }
}

// goto command executer
pub struct GotoCommandExecutor {
    target: CommandArg,
    target_level: GotoTargetLevel,
}

impl GotoCommandExecutor {
    fn new(target: CommandArg, target_level: GotoTargetLevel) -> Self {
        Self {
            target,
            target_level,
        }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for GotoCommandExecutor {
    async fn exec(&self, context: &Context) -> Result<CommandResult, String> {
        let target = self.target.evaluate_string(context).await?;

        let ret = match self.target_level {
            GotoTargetLevel::Block => CommandResult::goto_block(target),
            GotoTargetLevel::Chain => CommandResult::goto_chain(target),
        };

        Ok(ret)
    }
}
*/

// Return command to invoker, return from a specified scope (block, chain, or lib).
// Examples:
//   return;
//   return value;
//   return --from chain "result";
pub struct ReturnCommandParser {
    cmd: Command,
}

impl ReturnCommandParser {
    pub fn new() -> Self {
        let cmd = Command::new("return")
            .about("Return from the current caller with success, optionally with a value.")
            .arg(
                Arg::new("value")
                    .help("Optional return value")
                    .required(false)
                    .index(1)
            )
            .arg(
                Arg::new("from")
                    .long("from")
                    .help("Specifies the execution scope to return from.")
                    .value_name("LEVEL")
                    .value_parser(["block", "chain", "lib"]) // Enforce allowed values
                    .default_value("block"), // Set the default behavior
            )
            .after_help(
                r#"
DESCRIPTION:
  Terminates execution at a specified scope and returns control to the invoker,
  optionally passing a value. This is the primary mechanism for controlling
  exec/return flow.

SCOPE LEVELS (--from):
  block (default): Exits only the current block. Execution continues with the
                   next block in the process-chain. This is the most common use.

  chain: Exits the entire current process-chain. If the chain was invoked via
         `exec --chain`, control and the return value are passed back to the
         caller.

  lib:   Exits the entire current library, no matter how deeply nested the
         execution is. If the library was invoked via `exec --lib`, control
         returns to that caller. This is essential for handling early exits
         from complex, nested library calls.

EXAMPLES:
  # Return from the current block with no value (default scope)
  return

  # Return from the current block with the value "done"
  return done

  # A chain called by `exec --chain` returns its result to the caller
  return --from chain "authentication successful"

  # A block deep inside a library needs to terminate the entire library's execution
  return --from lib "FATAL: configuration missing"
"#,
            );

        Self { cmd }
    }
}

impl CommandParser for ReturnCommandParser {
    fn group(&self) -> CommandGroup {
        CommandGroup::Control
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
                let msg = format!("Invalid return command: {:?}, {}", str_args, e);
                error!("{}", msg);
                msg
            })?;

        // Get the optional return scope
        let from_level = matches
            .get_one::<String>("from")
            .map(|s| s.as_str())
            .unwrap_or("block");
        let from_level = CommandControlLevel::from_str(from_level).map_err(|e| {
            let msg = format!("Invalid return scope: {}, {}", from_level, e);
            error!("{}", msg);
            msg
        })?;

        // Get the optional return value
        let value_index = matches.index_of("value");
        let value = if let Some(index) = value_index {
            Some(args[index].clone())
        } else {
            None
        };

        let cmd = ReturnCommandExecutor::new(from_level, value);
        Ok(Arc::new(Box::new(cmd)))
    }
}

// Return command executer
pub struct ReturnCommandExecutor {
    from_level: CommandControlLevel,
    value: Option<CommandArg>,
}

impl ReturnCommandExecutor {
    pub fn new(from_level: CommandControlLevel, value: Option<CommandArg>) -> Self {
        Self { from_level, value }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for ReturnCommandExecutor {
    async fn exec(&self, _context: &Context) -> Result<CommandResult, String> {
        let value = match &self.value {
            Some(val) => Some(val.evaluate_string(_context).await?),
            None => None,
        };

        let ret = if let Some(value) = value {
            CommandResult::return_with_value(self.from_level, value)
        } else {
            CommandResult::_return(self.from_level)
        };

        Ok(ret)
    }
}

// Error command parser: return from a specified scope with an error value.
// Examples:
//   error;
//   error "a message";
//   error --from chain "critical failure";
pub struct ErrorCommandParser {
    cmd: Command,
}

impl ErrorCommandParser {
    pub fn new() -> Self {
        let cmd = Command::new("return")
            .about("Return from the current block with error, optionally with a value.")
            .arg(
                Arg::new("value")
                    .help("Optional return value")
                    .required(false)
                    .index(1)
            )
            .arg(
                Arg::new("from")
                    .long("from")
                    .help("Specifies the execution scope to exit from.")
                    .value_name("LEVEL")
                    .value_parser(["block", "chain", "lib"]) // Enforce allowed values
                    .default_value("block"), // Set the default behavior
            )
            .after_help(
                r#"
DESCRIPTION:
  Terminates execution at a specified scope with an error status, optionally
  passing a message. This is the primary mechanism for controlling
  exec/return flow.

SCOPE LEVELS (--from):
  block (default): Exits only the current block. Execution continues with the
                   next block in the process-chain. This is the most common use.

  chain: Exits the entire current process-chain. If the chain was invoked via
         `exec --chain`, control and the return value are passed back to the
         caller. If the chain was invoked via `exec --lib`, control returns to the 
         next chain in the library.

  lib:   Exits the entire current library, no matter how deeply nested the
         execution is. If the library was invoked via `exec --lib`, control
         returns to that caller. This is essential for handling early exits
         from complex, nested library calls.

EXAMPLES:
  # Error the current block with no message (default scope)
  error

  # Error the current block with a specific message
  error "invalid input provided"

  # Error the entire process-chain because a required resource is missing
  error --from chain "permission denied to access file"

  # A block deep inside a library needs to terminate the entire library's execution
  error --from lib "not found"
"#,
            );

        Self { cmd }
    }
}

impl CommandParser for ErrorCommandParser {
    fn group(&self) -> CommandGroup {
        CommandGroup::Control
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
                let msg = format!("Invalid error command: {:?}, {}", str_args, e);
                error!("{}", msg);
                msg
            })?;

        // Get the optional error scope
        let from_level = matches
            .get_one::<String>("from")
            .map(|s| s.as_str())
            .unwrap_or("block");
        let from_level = CommandControlLevel::from_str(from_level).map_err(|e| {
            let msg = format!("Invalid error scope: {}, {}", from_level, e);
            error!("{}", msg);
            msg
        })?;

        // Get the optional error value
        let value_index = matches.index_of("value");
        let value = if let Some(index) = value_index {
            Some(args[index].clone())
        } else {
            None
        };

        let cmd = ErrorCommandExecutor::new(from_lelvel, value);
        Ok(Arc::new(Box::new(cmd)))
    }
}

// Error command executer
pub struct ErrorCommandExecutor {
    from_level: CommandControlLevel,
    value: Option<CommandArg>,
}

impl ErrorCommandExecutor {
    pub fn new( from_level: CommandControlLevel, value: Option<CommandArg>) -> Self {
        Self { from_level, value }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for ErrorCommandExecutor {
    async fn exec(&self, _context: &Context) -> Result<CommandResult, String> {
        let value = match &self.value {
            Some(val) => Some(val.evaluate_string(_context).await?),
            None => None,
        };

        let ret = if let Some(value) = value {
            CommandResult::return_error_with_value(self.from_level, value)
        } else {
            CommandResult::return_error(self.from_level)
        };

        Ok(ret)
    }
}

// Exit command parser: like: exit; exit value;
pub struct ExitCommandParser {
    cmd: Command,
}

impl ExitCommandParser {
    pub fn new() -> Self {
        let cmd = Command::new("return")
            .about("Return from the current process chain list, optionally with a value.")
            .after_help(
                r#"
Usage:
  exit           Exit with no value.
  exit <value>   Exit with the specified string value.

Behavior:
  - Ends execution of the current process chain list to top caller.
  - The return value (if any) is passed to caller.

Examples:
  exit
  exit accept
  exit "invalid input"
"#,
            )
            .arg(
                Arg::new("value")
                    .help("Optional return value")
                    .required(false)
                    .num_args(0..=1),
            );

        Self { cmd }
    }
}

impl CommandParser for ExitCommandParser {
    fn group(&self) -> CommandGroup {
        CommandGroup::Control
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
                let msg = format!("Invalid exit command: {:?}, {}", str_args, e);
                error!("{}", msg);
                msg
            })?;

        // Get the optional exit value
        let value_index = matches.index_of("value");
        let value = if let Some(index) = value_index {
            Some(args[index].clone())
        } else {
            None
        };

        let cmd = ExitCommandExecutor::new(value);
        Ok(Arc::new(Box::new(cmd)))
    }
}

// Exit command executer
pub struct ExitCommandExecutor {
    value: Option<CommandArg>,
}

impl ExitCommandExecutor {
    pub fn new(value: Option<CommandArg>) -> Self {
        Self { value }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for ExitCommandExecutor {
    async fn exec(&self, _context: &Context) -> Result<CommandResult, String> {
        let value = match &self.value {
            Some(val) => Some(val.evaluate_string(_context).await?),
            None => None,
        };

        let ret = if let Some(value) = value {
            CommandResult::exit_chain_with_value(value)
        } else {
            CommandResult::exit_chain()
        };

        Ok(ret)
    }
}

// break command parser: like: break; break value; only use to break the current map-reduce command
pub struct BreakCommandParser {
    cmd: Command,
}

impl BreakCommandParser {
    pub fn new() -> Self {
        let cmd = Command::new("break")
            .about("Break the current map-reduce command, optionally with a value.")
            .after_help(
                r#"
Usage:
  break           Break with no value.
  break <value>   Break with the specified string value.

Behavior:
  - Ends execution of the current map-reduce command immediately.
  - Only used to break the current map-reduce command.
  - The return value (if any) is passed to the parent or caller.

Examples:
  break;
  break "map failed"
"#,
            )
            .arg(
                Arg::new("value")
                    .help("Optional break value")
                    .required(false)
                    .num_args(0..=1),
            );

        Self { cmd }
    }
}

impl CommandParser for BreakCommandParser {
    fn group(&self) -> CommandGroup {
        CommandGroup::Control
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
                let msg = format!("Invalid break command: {:?}, {}", str_args, e);
                error!("{}", msg);
                msg
            })?;

        // Get the optional break value
        let value_index = matches.index_of("value");
        let value = if let Some(index) = value_index {
            Some(args[index].clone())
        } else {
            None
        };

        let cmd = BreakCommandExecutor::new(value);
        Ok(Arc::new(Box::new(cmd)))
    }
}

// Break command executer
pub struct BreakCommandExecutor {
    value: Option<CommandArg>,
}

impl BreakCommandExecutor {
    pub fn new(value: Option<CommandArg>) -> Self {
        Self { value }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for BreakCommandExecutor {
    async fn exec(&self, _context: &Context) -> Result<CommandResult, String> {
        let value = match &self.value {
            Some(val) => Some(val.evaluate_string(_context).await?),
            None => None,
        };

        let ret = if let Some(value) = value {
            CommandResult::break_with_value(value)
        } else {
            CommandResult::_break()
        };

        Ok(ret)
    }
}
