use super::cmd::*;
use crate::ProcessChainExecutor;
use crate::block::{CommandArg, CommandArgs};
use crate::chain::{
    Context, ExecPointerChainGuard, ExecPointerLibGuard, ParserContext, ProcessChainLibExecutor,
};
use crate::{CollectionValue, EnvLevel, MapCollection, MapCollectionRef, MemoryMapCollection};
use clap::{Arg, ArgAction, ArgGroup, ArgMatches, Command};
use std::collections::HashSet;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExecScope {
    Block,
    Chain,
    Lib,
}

impl ExecScope {
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "block" => Ok(Self::Block),
            "chain" => Ok(Self::Chain),
            "lib" => Ok(Self::Lib),
            _ => Err(format!("Invalid exec scope: {}", s)),
        }
    }
}

pub(crate) fn parse_exec_scope_and_target(
    matches: &ArgMatches,
    args: &CommandArgs,
    cmd_name: &str,
) -> Result<(ExecScope, CommandArg), String> {
    // First determine the scope and the argument name to use for finding the index
    let (scope, arg_name) = if matches.contains_id("block") {
        (ExecScope::Block, "block")
    } else if matches.contains_id("chain") {
        (ExecScope::Chain, "chain")
    } else if matches.contains_id("lib") {
        (ExecScope::Lib, "lib")
    } else if matches.contains_id("default_block_id") {
        // If no scope is specified, use the default block ID
        (ExecScope::Block, "default_block_id")
    } else {
        let msg = format!(
            "Invalid {} command: must specify one of --block, --chain, --lib or default_block_id",
            cmd_name
        );
        error!("{}", msg);
        return Err(msg);
    };

    // Get the index of the argument based on the determined scope
    let target_index = matches.index_of(arg_name).ok_or_else(|| {
        let msg = format!(
            "Argument '{}' is required for {} command",
            arg_name, cmd_name
        );
        error!("{}", msg);
        msg
    })?;

    let target_arg = args[target_index].clone();
    Ok((scope, target_arg))
}

pub(crate) fn normalize_exec_result(
    command_name: &str,
    target_id: &str,
    cmd_ret: CommandResult,
) -> Result<CommandResult, String> {
    let ret = if cmd_ret.is_control() {
        // If the execution result is a control action, we handle it immediately
        info!("Control action in {} command: {:?}", command_name, cmd_ret);
        let control = cmd_ret.into_control().unwrap();
        match control {
            CommandControl::Return(value) => {
                info!("Returning value from {} command: {:?}", command_name, value);
                CommandResult::success_with_value(value.value)
            }
            CommandControl::Error(value) => {
                info!("Error control in {} command: {:?}", command_name, value);
                CommandResult::error_with_value(value.value)
            }
            CommandControl::Exit(_value) => {
                let msg = format!(
                    "Exit control action in {} command '{}' is not allowed",
                    command_name, target_id
                );
                error!("{}", msg);
                return Err(msg);
            }
            CommandControl::Break(_value) => {
                let msg = format!(
                    "break action only valid in map-reduce loop, found in {} target '{}'",
                    command_name, target_id
                );
                error!("{}", msg);
                return Err(msg);
            }
        }
    } else {
        // If the execution result is not a control action, we return it as is
        cmd_ret
    };

    Ok(ret)
}

pub(crate) struct ExecTarget {
    lib: Option<String>,
    chain: Option<String>,
    block: Option<String>,
}

impl ExecTarget {
    pub fn lib(&self) -> &str {
        self.lib.as_deref().unwrap()
    }

    pub fn chain(&self) -> &str {
        self.chain.as_deref().unwrap()
    }

    pub fn block(&self) -> &str {
        self.block.as_deref().unwrap()
    }

    pub(crate) fn parse(scope: ExecScope, target: &str) -> Result<Self, String> {
        let parts: Vec<&str> = target.split(':').collect();
        match scope {
            ExecScope::Block => {
                if parts.len() == 1 {
                    Ok(Self {
                        lib: None,
                        chain: None,
                        block: Some(parts[0].to_string()),
                    })
                } else if parts.len() == 2 {
                    Ok(Self {
                        lib: None,
                        chain: Some(parts[0].to_string()),
                        block: Some(parts[1].to_string()),
                    })
                } else if parts.len() == 3 {
                    Ok(Self {
                        lib: Some(parts[0].to_string()),
                        chain: Some(parts[1].to_string()),
                        block: Some(parts[2].to_string()),
                    })
                } else {
                    let msg = format!(
                        "Invalid block ID format '{}' expected 'lib:chain:block', 'chain:block' or 'block'",
                        target
                    );
                    error!("{}", msg);
                    Err(msg)
                }
            }
            ExecScope::Chain => {
                if parts.len() == 1 {
                    Ok(Self {
                        lib: None,
                        chain: Some(parts[0].to_string()),
                        block: None,
                    })
                } else if parts.len() == 2 {
                    Ok(Self {
                        lib: Some(parts[0].to_string()),
                        chain: Some(parts[1].to_string()),
                        block: None,
                    })
                } else {
                    let msg = format!(
                        "Invalid chain ID format '{}' expected 'lib:chain' or 'chain'",
                        target
                    );
                    error!("{}", msg);
                    Err(msg)
                }
            }
            ExecScope::Lib => {
                if parts.len() == 1 {
                    Ok(Self {
                        lib: Some(parts[0].to_string()),
                        chain: None,
                        block: None,
                    })
                } else {
                    let msg = format!("Invalid lib ID format '{}', expected 'lib'", target);
                    error!("{}", msg);
                    Err(msg)
                }
            }
        }
    }
}

// exec command, exec a block/chain/lib by its identifier
// exec --block lib_id:chain_id:block_id // Full id, will get the block from the specified chain in the library in process chain manager in global
// exec --block chain_id:block_id // First try to get the block from the current lib, then from the process chain manager in global
// exec --block block_id // Get the block from the current process chain in context
// exec --chain lib_id:chain_id  // Full id, will get the chain from the specified library in process chain manager in global
// exec --chain chain_id // First try to get the chain from the current lib, then from the process chain manager in global
// exec --lib lib_id // Full id, will get the library from the process chain manager in global
pub struct ExecCommandParser {
    cmd: Command,
}

impl ExecCommandParser {
    pub fn new() -> Self {
        let cmd = Command::new("exec")
            .about("Execute a block, process-chain, or library by its identifier.")
            .arg(
                Arg::new("block")
                    .long("block")
                    .value_name("BLOCK_ID")
                    .help("Execute a block by ID."),
            )
            .arg(
                Arg::new("chain")
                    .long("chain")
                    .value_name("CHAIN_ID")
                    .help("Execute a process-chain by ID."),
            )
            .arg(
                Arg::new("lib")
                    .long("lib")
                    .value_name("LIB_ID")
                    .help("Execute a library by ID."),
            )
            .arg(
                Arg::new("default_block_id")
                    .value_name("BLOCK_ID")
                    .help("Default: execute a block from the current chain.")
                    .index(1),
            )
            // GROUP 1: Makes the --block, --chain, and --lib flags mutually exclusive.
            .group(ArgGroup::new("target_by_id").args(["block", "chain", "lib"]))
            .group(
                ArgGroup::new("execution_mode")
                    .args(["block", "chain", "lib", "default_block_id"])
                    .required(true),
            )
            .after_help(
                r#"
DESCRIPTION:
  Calls a reusable execution unit (block, chain, or lib) and waits for it to
  complete before continuing. The execution unit is found based on its ID
  and the current context.

IDENTIFIER RESOLUTION:
  The ID format determines the search scope for the target unit.

  For --block <ID>:
    - `lib:chain:block`:  Fully qualified. Searches globally for the library,
                          then the chain, then the block.
    - `chain:block`:      Partially qualified. Searches for the chain within the
                          *current library* first, then searches globally.
    - `block`:            Local. Searches for the block within the *current
                          process-chain*.

  For --chain <ID>:
    - `lib:chain`:        Fully qualified. Searches globally for the library,
                          then the chain.
    - `chain`:            Local. Searches for the chain within the *current
                          library* first, then searches globally.

  For --lib <ID>:
    - `lib`:              Global. Searches for the library globally.

EXAMPLES:
  # Execute a block within the current process-chain
  exec --block verify_token

  # Execute a block from a specific chain (searched in the current lib first)
  exec --block auth_flow:get_user_info

  # Execute a block using a fully qualified global ID
  exec --block security_lib:sso_flow:validate_jwt

  # Execute a chain (searched in the current lib first)
  exec --chain user_login_flow

  # Execute a globally unique library
  exec --lib common_utils
"#,
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

        let (scope, target_arg) = parse_exec_scope_and_target(&matches, args, "exec")?;

        let cmd = ExecCommandExecutor::new(scope, target_arg);
        Ok(Arc::new(Box::new(cmd)))
    }
}

// exec command executer
struct ExecCommandExecutor {
    scope: ExecScope,
    target: CommandArg,
}

impl ExecCommandExecutor {
    pub fn new(scope: ExecScope, target: CommandArg) -> Self {
        Self { scope, target }
    }

    async fn execute_block(
        context: &Context,
        target_id: &str,
        target: ExecTarget,
    ) -> Result<CommandResult, String> {
        let ret = context.search_block(
            target.lib.as_deref(),
            target.chain.as_deref(),
            target.block.as_deref().unwrap(),
        )?;

        if ret.is_none() {
            let msg = format!("Block '{}' not found", target_id,);
            error!("{}", msg);
            return Err(msg);
        }

        let ret = ret.unwrap();
        let _lib_guard = if ret.same_lib {
            None
        } else {
            let target_lib = ret.lib.unwrap();
            Some(ExecPointerLibGuard::new(
                context.current_pointer(),
                target_lib,
            )?)
        };

        let _chain_guard = if ret.same_chain {
            assert!(
                ret.same_lib,
                "Chain must be in the same library if same_chain is true"
            );
            None
        } else {
            let target_chain = ret.chain.clone().unwrap();
            Some(ExecPointerChainGuard::new(
                context.current_pointer(),
                target_chain,
            )?)
        };

        use std::borrow::Cow;
        let context = if !ret.same_chain {
            let context = context.fork_chain();
            Cow::Owned(context)
        } else {
            Cow::Borrowed(context)
        };

        let chain = ret.chain.unwrap();
        ProcessChainExecutor::execute_block(&chain, target.block(), &context).await
    }

    async fn execute_chain(
        context: &Context,
        target_id: &str,
        target: ExecTarget,
    ) -> Result<CommandResult, String> {
        let ret = context.search_chain(target.lib.as_deref(), target.chain())?;

        if ret.is_none() {
            let msg = format!("Chain '{}' not found", target_id,);
            error!("{}", msg);
            return Err(msg);
        }

        let ret = ret.unwrap();
        let _lib_guard = if ret.same_lib {
            None
        } else {
            let target_lib = ret.lib.unwrap();
            Some(ExecPointerLibGuard::new(
                context.current_pointer(),
                target_lib,
            )?)
        };

        // Always fork new chain context for chain execution, even if the chain is in the same chain as current pointer
        let context = context.fork_chain();
        let chain = ret.chain.unwrap();
        ProcessChainExecutor::execute_chain(&chain, &context).await
    }

    async fn execute_lib(
        context: &Context,
        target_id: &str,
        target: ExecTarget,
    ) -> Result<CommandResult, String> {
        let ret = context.search_lib(target.lib())?;
        if ret.is_none() {
            let msg = format!("Process chain library '{}' not found", target_id,);
            error!("{}", msg);
            return Err(msg);
        }

        let ret = ret.unwrap();
        let lib = ret.lib.unwrap();

        let exec = ProcessChainLibExecutor::new_with_context(lib, context.fork_chain());

        exec.execute_lib().await
    }
}

#[async_trait::async_trait]
impl CommandExecutor for ExecCommandExecutor {
    async fn exec(&self, context: &Context) -> Result<CommandResult, String> {
        let target_id = self.target.evaluate_string(context).await?;

        let target = ExecTarget::parse(self.scope, &target_id).map_err(|e| {
            let msg = format!("Failed to parse exec target '{}': {}", target_id, e);
            error!("{}", msg);
            msg
        })?;

        let cmd_ret = match self.scope {
            ExecScope::Block => Self::execute_block(context, &target_id, target).await,
            ExecScope::Chain => Self::execute_chain(context, &target_id, target).await,
            ExecScope::Lib => Self::execute_lib(context, &target_id, target).await,
        }?;

        normalize_exec_result("exec", &target_id, cmd_ret)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct InvokeArgSpec {
    pub(crate) key: String,
    pub(crate) value: CommandArg,
}

fn validate_invoke_arg_key(key: &str) -> Result<(), String> {
    let mut chars = key.chars();
    let first = chars
        .next()
        .ok_or_else(|| "invoke arg key must not be empty".to_string())?;
    if !(first.is_ascii_alphabetic() || first == '_') {
        let msg = format!(
            "Invalid invoke arg key '{}': must start with letter or underscore",
            key
        );
        error!("{}", msg);
        return Err(msg);
    }

    if !chars.all(|c| c.is_ascii_alphanumeric() || c == '_') {
        let msg = format!(
            "Invalid invoke arg key '{}': only [A-Za-z0-9_] is allowed",
            key
        );
        error!("{}", msg);
        return Err(msg);
    }

    Ok(())
}

pub(crate) fn parse_invoke_args(
    matches: &ArgMatches,
    args: &CommandArgs,
) -> Result<Vec<InvokeArgSpec>, String> {
    let indices = matches
        .indices_of("arg")
        .map(|idx| idx.collect::<Vec<_>>())
        .unwrap_or_default();

    if indices.is_empty() {
        return Ok(Vec::new());
    }

    if indices.len() % 2 != 0 {
        let msg = format!(
            "Invalid invoke command: --arg expects key/value pairs, got {} values",
            indices.len()
        );
        error!("{}", msg);
        return Err(msg);
    }

    let mut seen = HashSet::new();
    let mut result = Vec::with_capacity(indices.len() / 2);
    for pair in indices.chunks_exact(2) {
        let key_arg = args.get(pair[0]).ok_or_else(|| {
            let msg = format!(
                "Invalid invoke command: missing arg key at index {}",
                pair[0]
            );
            error!("{}", msg);
            msg
        })?;
        let value_arg = args.get(pair[1]).ok_or_else(|| {
            let msg = format!(
                "Invalid invoke command: missing arg value at index {}",
                pair[1]
            );
            error!("{}", msg);
            msg
        })?;

        let key = key_arg.as_literal_str().ok_or_else(|| {
            let msg = format!(
                "Invalid invoke arg key: expected literal, got {:?}",
                key_arg
            );
            error!("{}", msg);
            msg
        })?;

        validate_invoke_arg_key(key)?;
        if !seen.insert(key.to_string()) {
            let msg = format!("Duplicate invoke arg key '{}'", key);
            error!("{}", msg);
            return Err(msg);
        }

        result.push(InvokeArgSpec {
            key: key.to_string(),
            value: value_arg.clone(),
        });
    }

    Ok(result)
}

pub struct InvokeCommandParser {
    cmd: Command,
}

impl InvokeCommandParser {
    pub fn new() -> Self {
        let cmd = Command::new("invoke")
            .about("Invoke a block, process-chain, or library with named arguments.")
            .arg(
                Arg::new("block")
                    .long("block")
                    .value_name("BLOCK_ID")
                    .help("Invoke a block by ID."),
            )
            .arg(
                Arg::new("chain")
                    .long("chain")
                    .value_name("CHAIN_ID")
                    .help("Invoke a process-chain by ID."),
            )
            .arg(
                Arg::new("lib")
                    .long("lib")
                    .value_name("LIB_ID")
                    .help("Invoke a library by ID."),
            )
            .arg(
                Arg::new("arg")
                    .long("arg")
                    .value_names(["KEY", "VALUE"])
                    .num_args(2)
                    .action(ArgAction::Append)
                    .help("Named argument for callee, can be repeated."),
            )
            .arg(
                Arg::new("default_block_id")
                    .value_name("BLOCK_ID")
                    .help("Default: invoke a block from the current chain.")
                    .index(1),
            )
            .group(ArgGroup::new("target_by_id").args(["block", "chain", "lib"]))
            .group(
                ArgGroup::new("execution_mode")
                    .args(["block", "chain", "lib", "default_block_id"])
                    .required(true),
            )
            .after_help(
                r#"
DESCRIPTION:
  invoke is similar to exec, but it passes named arguments to the callee
  through $__args.<key>.

ARGUMENT PASSING:
  --arg <key> <value> can be repeated.
  <value> can be literal, variable, command substitution, or collection reference.
  The callee reads arguments via $__args.<key>.

EXAMPLES:
  invoke --chain auth_flow --arg user $REQ.user --arg pass $REQ.pass
  invoke --block helper_block --arg req $REQ
"#,
            );

        Self { cmd }
    }
}

impl CommandParser for InvokeCommandParser {
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
                let msg = format!("Invalid invoke command: {:?}, {}", str_args, e);
                error!("{}", msg);
                msg
            })?;

        let (scope, target) = parse_exec_scope_and_target(&matches, args, "invoke")?;
        let invoke_args = parse_invoke_args(&matches, args)?;

        let cmd = InvokeCommandExecutor::new(scope, target, invoke_args);
        Ok(Arc::new(Box::new(cmd)))
    }
}

pub(crate) struct InvokeCommandExecutor {
    scope: ExecScope,
    target: CommandArg,
    args: Vec<InvokeArgSpec>,
}

impl InvokeCommandExecutor {
    pub(crate) fn new(scope: ExecScope, target: CommandArg, args: Vec<InvokeArgSpec>) -> Self {
        Self {
            scope,
            target,
            args,
        }
    }

    async fn build_args_map(&self, caller: &Context) -> Result<MapCollectionRef, String> {
        let map = Arc::new(Box::new(MemoryMapCollection::new()) as Box<dyn MapCollection>);
        for arg in &self.args {
            let value = arg.value.evaluate(caller).await?;
            map.insert(arg.key.as_str(), value).await?;
        }

        Ok(map)
    }

    async fn inject_args(context: &Context, args: MapCollectionRef) -> Result<(), String> {
        context
            .env()
            .set("__args", CollectionValue::Map(args), Some(EnvLevel::Chain))
            .await?;
        Ok(())
    }

    async fn execute_block(
        context: &Context,
        target_id: &str,
        target: ExecTarget,
        args: MapCollectionRef,
    ) -> Result<CommandResult, String> {
        let ret = context.search_block(
            target.lib.as_deref(),
            target.chain.as_deref(),
            target.block.as_deref().unwrap(),
        )?;

        if ret.is_none() {
            let msg = format!("Block '{}' not found", target_id,);
            error!("{}", msg);
            return Err(msg);
        }

        let ret = ret.unwrap();
        let _lib_guard = if ret.same_lib {
            None
        } else {
            let target_lib = ret.lib.unwrap();
            Some(ExecPointerLibGuard::new(
                context.current_pointer(),
                target_lib,
            )?)
        };

        let _chain_guard = if ret.same_chain {
            assert!(
                ret.same_lib,
                "Chain must be in the same library if same_chain is true"
            );
            None
        } else {
            assert!(
                !ret.same_lib,
                "Chain must not be in the same library if same_chain is false"
            );
            let target_chain = ret.chain.clone().unwrap();
            Some(ExecPointerChainGuard::new(
                context.current_pointer(),
                target_chain,
            )?)
        };

        let invoke_context = context.fork_chain();
        Self::inject_args(&invoke_context, args).await?;

        let chain = ret.chain.unwrap();
        ProcessChainExecutor::execute_block(&chain, target.block(), &invoke_context).await
    }

    async fn execute_chain(
        context: &Context,
        target_id: &str,
        target: ExecTarget,
        args: MapCollectionRef,
    ) -> Result<CommandResult, String> {
        let ret = context.search_chain(target.lib.as_deref(), target.chain())?;

        if ret.is_none() {
            let msg = format!("Chain '{}' not found", target_id,);
            error!("{}", msg);
            return Err(msg);
        }

        let ret = ret.unwrap();
        let _lib_guard = if ret.same_lib {
            None
        } else {
            let target_lib = ret.lib.unwrap();
            Some(ExecPointerLibGuard::new(
                context.current_pointer(),
                target_lib,
            )?)
        };

        let invoke_context = context.fork_chain();
        Self::inject_args(&invoke_context, args).await?;

        let chain = ret.chain.unwrap();
        ProcessChainExecutor::execute_chain(&chain, &invoke_context).await
    }

    async fn execute_lib(
        context: &Context,
        target_id: &str,
        target: ExecTarget,
        args: MapCollectionRef,
    ) -> Result<CommandResult, String> {
        let ret = context.search_lib(target.lib())?;
        if ret.is_none() {
            let msg = format!("Process chain library '{}' not found", target_id,);
            error!("{}", msg);
            return Err(msg);
        }

        let ret = ret.unwrap();
        let lib = ret.lib.unwrap();

        let invoke_context = context.fork_chain();
        Self::inject_args(&invoke_context, args).await?;

        let exec = ProcessChainLibExecutor::new_with_context(lib, invoke_context);
        exec.execute_lib().await
    }
}

#[async_trait::async_trait]
impl CommandExecutor for InvokeCommandExecutor {
    async fn exec(&self, context: &Context) -> Result<CommandResult, String> {
        let target_id = self.target.evaluate_string(context).await?;
        let target = ExecTarget::parse(self.scope, &target_id).map_err(|e| {
            let msg = format!("Failed to parse invoke target '{}': {}", target_id, e);
            error!("{}", msg);
            msg
        })?;

        let args_map = self.build_args_map(context).await?;
        let cmd_ret = match self.scope {
            ExecScope::Block => Self::execute_block(context, &target_id, target, args_map).await,
            ExecScope::Chain => Self::execute_chain(context, &target_id, target, args_map).await,
            ExecScope::Lib => Self::execute_lib(context, &target_id, target, args_map).await,
        }?;

        normalize_exec_result("invoke", &target_id, cmd_ret)
    }
}
