use super::cmd::*;
use super::exec::{
    ExecScope, InvokeArgSpec, InvokeCommandExecutor, parse_exec_scope_and_target, parse_invoke_args,
};
use crate::block::{BlockExecuter, CommandArg, CommandArgs, Expression};
use crate::chain::{Context, ParserContext};
use clap::{Arg, ArgAction, ArgGroup, ArgMatches, Command};
use std::str::FromStr;
use std::sync::Arc;

fn default_goto_from_level() -> CommandControlLevel {
    // Keep goto default aligned with `return` / `error` default behavior.
    CommandControlLevel::Block
}

fn parse_goto_from_level(
    matches: &ArgMatches,
    option_name: &str,
) -> Result<Option<CommandControlLevel>, String> {
    matches
        .get_one::<String>(option_name)
        .map(|s| s.as_str())
        .map(CommandControlLevel::from_str)
        .transpose()
        .map_err(|e| {
            let msg = format!("Invalid goto scope for --{}: {}", option_name, e);
            error!("{}", msg);
            msg
        })
}

pub struct FirstOkCommandParser {
    cmd: Command,
}

impl FirstOkCommandParser {
    pub fn new() -> Self {
        let cmd = Command::new("first-ok")
            .about(
                "Try command substitutions left-to-right and return the first successful result.",
            )
            .after_help(
                r#"
DESCRIPTION:
  first-ok is a result-level fallback combinator. It executes each command
  substitution from left to right and returns the first `success(value)`.

BEHAVIOR:
  - `success(value)`    => stop immediately and return that success.
  - `error(value)`      => remember it and continue with the next candidate.
  - `control(...)`      => propagate immediately without swallowing it.
  - If all candidates return `error(value)`, the last error is returned.

NOTES:
  - All inputs must be command substitutions: `$(...)`.
  - This is intended for sequential fallback of parsing/lookup helpers,
    not for general branching logic.

EXAMPLES:
  first-ok $(strip-prefix $path $route_prefix) $(strip-prefix $path "/api")

  local target=$(first-ok
    $(parse-authority $REQ.host)
    $(parse-authority --default-port 3180 $REQ.dest_host)
  )
"#,
            )
            .arg(
                Arg::new("commands")
                    .required(true)
                    .num_args(2..)
                    .help("Candidate sub-commands in command substitution form: $(...)"),
            );

        Self { cmd }
    }
}

impl CommandParser for FirstOkCommandParser {
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
                let msg = format!("Invalid first-ok command: {:?}, {}", str_args, e);
                error!("{}", msg);
                msg
            })?;

        let command_indices = matches.indices_of("commands").ok_or_else(|| {
            let msg = "At least two command substitutions are required for first-ok".to_string();
            error!("{}", msg);
            msg
        })?;

        let mut commands = Vec::new();
        for index in command_indices {
            let arg = &args[index];
            if !arg.is_command_substitution() {
                let msg = format!(
                    "first-ok expects command substitution arguments, found: {:?}",
                    arg
                );
                error!("{}", msg);
                return Err(msg);
            }
            commands.push(arg.as_command_substitution().unwrap().clone());
        }

        Ok(Arc::new(Box::new(FirstOkCommandExecutor::new(commands))))
    }
}

pub struct FirstOkCommandExecutor {
    commands: Vec<Box<Expression>>,
}

impl FirstOkCommandExecutor {
    pub fn new(commands: Vec<Box<Expression>>) -> Self {
        Self { commands }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for FirstOkCommandExecutor {
    async fn exec(&self, context: &Context) -> Result<CommandResult, String> {
        let mut last_error = None;

        for command in &self.commands {
            let ret = BlockExecuter::execute_expression(command, context).await?;

            if ret.is_success() {
                return Ok(ret);
            }

            if ret.is_control() {
                return Ok(ret);
            }

            last_error = Some(ret);
        }

        Ok(last_error.unwrap_or_else(CommandResult::error))
    }
}

// goto command: tail-transfer style control command.
// It executes a target (same resolution as invoke/exec) and then returns/errors from the caller scope.
pub struct GotoCommandParser {
    cmd: Command,
}

impl GotoCommandParser {
    pub fn new() -> Self {
        let cmd = Command::new("goto")
            .about("Tail-transfer to a block/chain/lib and then return from a chosen scope.")
            .after_help(
                r#"
DESCRIPTION:
  goto is a structured tail-transfer command. It first executes the target
  (same semantics as invoke), then converts the result to return/error from
  the selected caller scope(s).

TARGET:
  Exactly one of --block/--chain/--lib must be provided.
  Target ID formats are the same as exec/invoke:
    --block: block | chain:block | lib:chain:block
    --chain: chain | lib:chain
    --lib:   lib

RETURN LEVEL:
  --from      Optional common default for success/error mapping.
  --ok-from   Optional success scope override.
  --err-from  Optional error scope override.
  If omitted, defaults to block (same as return/error without --from).

Examples:
  goto --chain fallback_chain
  goto --chain auth_flow --from lib
  goto --chain auth_flow --from chain --err-from lib
  goto --block helper --arg req $REQ
"#,
            )
            .arg(
                Arg::new("chain")
                    .long("chain")
                    .value_name("CHAIN_ID")
                    .help("Transfer to a process-chain by ID."),
            )
            .arg(
                Arg::new("block")
                    .long("block")
                    .value_name("BLOCK_ID")
                    .help("Transfer to a block by ID."),
            )
            .arg(
                Arg::new("lib")
                    .long("lib")
                    .value_name("LIB_ID")
                    .help("Transfer to a library by ID."),
            )
            .arg(
                Arg::new("from")
                    .long("from")
                    .help("Default return/error scope after target execution.")
                    .value_name("LEVEL")
                    .value_parser(["block", "chain", "lib"]),
            )
            .arg(
                Arg::new("ok-from")
                    .long("ok-from")
                    .help("Success return scope override after target execution.")
                    .value_name("LEVEL")
                    .value_parser(["block", "chain", "lib"]),
            )
            .arg(
                Arg::new("err-from")
                    .long("err-from")
                    .help("Error return scope override after target execution.")
                    .value_name("LEVEL")
                    .value_parser(["block", "chain", "lib"]),
            )
            .arg(
                Arg::new("arg")
                    .long("arg")
                    .value_names(["KEY", "VALUE"])
                    .num_args(2)
                    .action(ArgAction::Append)
                    .help("Named argument for target, can be repeated."),
            );
        let cmd = cmd.group(
            ArgGroup::new("target_by_id")
                .args(["block", "chain", "lib"])
                .required(true),
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

        let (scope, target) = parse_exec_scope_and_target(&matches, args, "goto")?;
        let goto_args = parse_invoke_args(&matches, args)?;
        let default_from_level = default_goto_from_level();

        let from_level = parse_goto_from_level(&matches, "from")?;
        let ok_from_level = parse_goto_from_level(&matches, "ok-from")?
            .or(from_level)
            .unwrap_or(default_from_level);
        let err_from_level = parse_goto_from_level(&matches, "err-from")?
            .or(from_level)
            .unwrap_or(default_from_level);

        let cmd = GotoCommandExecutor::new(scope, target, goto_args, ok_from_level, err_from_level);
        Ok(Arc::new(Box::new(cmd)))
    }
}

pub struct GotoCommandExecutor {
    scope: ExecScope,
    target: CommandArg,
    args: Vec<InvokeArgSpec>,
    ok_from_level: CommandControlLevel,
    err_from_level: CommandControlLevel,
}

impl GotoCommandExecutor {
    fn new(
        scope: ExecScope,
        target: CommandArg,
        args: Vec<InvokeArgSpec>,
        ok_from_level: CommandControlLevel,
        err_from_level: CommandControlLevel,
    ) -> Self {
        Self {
            scope,
            target,
            args,
            ok_from_level,
            err_from_level,
        }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for GotoCommandExecutor {
    async fn exec(&self, context: &Context) -> Result<CommandResult, String> {
        let invoke = InvokeCommandExecutor::new(self.scope, self.target.clone(), self.args.clone());
        let invoke_ret = invoke.exec(context).await?;

        if invoke_ret.is_success() {
            return Ok(CommandResult::return_with_value(
                self.ok_from_level,
                invoke_ret.value_ref().clone(),
            ));
        }

        if invoke_ret.is_error() {
            return Ok(CommandResult::return_error_with_value(
                self.err_from_level,
                invoke_ret.value_ref().clone(),
            ));
        }

        let msg = format!(
            "Unexpected control result in goto target execution: {:?}",
            invoke_ret
        );
        error!("{}", msg);
        Err(msg)
    }
}

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
                    .index(1),
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
    async fn exec(&self, context: &Context) -> Result<CommandResult, String> {
        let value = match &self.value {
            Some(val) => Some(val.evaluate(context).await?),
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
                    .index(1),
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

        let cmd = ErrorCommandExecutor::new(from_level, value);
        Ok(Arc::new(Box::new(cmd)))
    }
}

// Error command executer
pub struct ErrorCommandExecutor {
    from_level: CommandControlLevel,
    value: Option<CommandArg>,
}

impl ErrorCommandExecutor {
    pub fn new(from_level: CommandControlLevel, value: Option<CommandArg>) -> Self {
        Self { from_level, value }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for ErrorCommandExecutor {
    async fn exec(&self, context: &Context) -> Result<CommandResult, String> {
        let value = match &self.value {
            Some(val) => Some(val.evaluate(context).await?),
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
    async fn exec(&self, context: &Context) -> Result<CommandResult, String> {
        let value = match &self.value {
            Some(val) => Some(val.evaluate(context).await?),
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
    async fn exec(&self, context: &Context) -> Result<CommandResult, String> {
        let value = match &self.value {
            Some(val) => Some(val.evaluate(context).await?),
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
