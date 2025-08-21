use super::cmd::*;
use crate::ProcessChainExecutor;
use crate::block::{CommandArg, CommandArgs};
use crate::chain::{
    Context, ExecPointerChainGuard, ExecPointerLibGuard, ParserContext, ProcessChainLibExecutor,
};
use clap::{Arg, ArgGroup, Command};
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExecScope {
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

struct ExecTarget {
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

    pub fn parse(scope: ExecScope, target: &str) -> Result<Self, String> {
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
            .group(
                ArgGroup::new("target_by_id")
                    .args(["block", "chain", "lib"])
                    .required(false),
            )
            .arg(
                Arg::new("default_block_id")
                    .value_name("BLOCK_ID")
                    .help("Default: execute a block from the current chain.")
                    .index(1) // This is the default block ID if no scope param is specified
                    .required(false),
            )
            .group(
                ArgGroup::new("execution_mode")
                    .args(["target_by_id", "default_block_id"])
                    .required(true), // Ensure one of these is always provided
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
            let msg = "Invalid exec command: must specify one of --block, --chain, --lib or default_block_id".to_string();
            error!("{}", msg);
            return Err(msg);
        };

        // Get the index of the argument based on the determined scope
        let target_index = matches.index_of(arg_name).ok_or_else(|| {
            let msg = format!("Argument '{}' is required for exec command", arg_name);
            error!("{}", msg);
            msg
        })?;

        let target_arg = args[target_index].clone();

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
            ))
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
            ))
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
            ))
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

        exec.execute().await
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

        match self.scope {
            ExecScope::Block => Self::execute_block(context, &target_id, target).await,
            ExecScope::Chain => Self::execute_chain(context, &target_id, target).await,
            ExecScope::Lib => Self::execute_lib(context, &target_id, target).await,
        }
    }
}
