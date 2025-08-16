use super::cmd::*;
use crate::block::{BlockExecuter, CommandArgs, CommandArg};
use crate::chain::{Context, ParserContext};
use clap::{Arg, Command, ArgAction};
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
        let matches = self.cmd.clone().try_get_matches_from(&str_args).map_err(|e| {
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
        ExecCommandExecutor { block }
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

        let block = chain.get_block(&block_id);
        if block.is_none() {
            let msg = format!("Exec target block not found: {:?}", self.block);
            error!("{}", msg);
            return Err(msg);
        }

        let block = block.unwrap();
        let executor = BlockExecuter::new(&block.id);
        let context = context.fork_block();

        // Execute the block
        executor.execute_block(&block, &context).await
    }
}

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
        let matches = self.cmd.clone().try_get_matches_from(&str_args).map_err(|e| {
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
            GotoTargetLevel::Block => {
                CommandResult::goto_block(target)
            }
            GotoTargetLevel::Chain => {
                CommandResult::goto_chain(target)
            }
        };

        Ok(ret)
    }
}

// Return command parser, return from current block, like: return; return value;
pub struct ReturnCommandParser {
    cmd: Command,
}

impl ReturnCommandParser {
    pub fn new() -> Self {
        let cmd = Command::new("return")
            .about("Return from the current block with success, optionally with a value.")
            .after_help(
                r#"
Usage:
  return           Return with no value.
  return <value>   Return the specified string value.

Behavior:
  - Ends execution of the current block immediately with success.
  - The return value (if any) is passed to the parent or caller.
  - Used for control flow inside process chain blocks.

Examples:
  return
  return ok
  return "user input accepted"
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
        let matches = self.cmd.clone().try_get_matches_from(&str_args).map_err(|e| {
            let msg = format!("Invalid return command: {:?}, {}", str_args, e);
            error!("{}", msg);
            msg
        })?;

        // Get the optional return value
        let value_index= matches.index_of("value");
        let value = if let Some(index) = value_index {
            Some(args[index].clone())
        } else {
            None
        };

        let cmd = ReturnCommandExecutor::new(value);
        Ok(Arc::new(Box::new(cmd)))
    }
}

// Return command executer
pub struct ReturnCommandExecutor {
    value: Option<CommandArg>,
}

impl ReturnCommandExecutor {
    pub fn new(value: Option<CommandArg>) -> Self {
        Self { value }
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
            CommandResult::return_to_block_with_value(value)
        } else {
            CommandResult::return_to_block()
        };

        Ok(ret)
    }
}

// Error command parser: like: error; error value;
pub struct ErrorCommandParser {
    cmd: Command,
}

impl ErrorCommandParser {
    pub fn new() -> Self {
        let cmd = Command::new("return")
            .about("Return from the current block with error, optionally with a value.")
            .after_help(
                r#"
Usage:
  error           Return with no value.
  error <value>   Return the specified string value.

Behavior:
  - Ends execution of the current block immediately with error.
  - The return value (if any) is passed to the parent or caller.
  - Used for control flow inside process chain blocks.

Examples:
  error
  error ok
  error "invalid input"
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
        let matches = self.cmd.clone().try_get_matches_from(&str_args).map_err(|e| {
            let msg = format!("Invalid error command: {:?}, {}", str_args, e);
            error!("{}", msg);
            msg
        })?;

        // Get the optional error value
        let value_index= matches.index_of("value");
        let value = if let Some(index) = value_index {
            Some(args[index].clone())
        } else {
            None
        };

        let cmd = ErrorCommandExecutor::new(value);
        Ok(Arc::new(Box::new(cmd)))
    }
}

// Error command executer
pub struct ErrorCommandExecutor {
    value: Option<CommandArg>,
}

impl ErrorCommandExecutor {
    pub fn new(value: Option<CommandArg>) -> Self {
        Self { value }
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
            CommandResult::error_to_block_with_value(value)
        } else {
            CommandResult::error_to_block()
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
        let matches = self.cmd.clone().try_get_matches_from(&str_args).map_err(|e| {
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
        let matches = self.cmd.clone().try_get_matches_from(&str_args).map_err(|e| {
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