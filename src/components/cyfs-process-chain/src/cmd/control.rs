use super::cmd::*;
use super::helper::CommandArgHelper;
use crate::block::{BlockExecuter, CommandArgs};
use crate::chain::Context;
use std::sync::Arc;

// exec command, like: EXEC block1
pub struct ExecCommandParser {}

impl ExecCommandParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl CommandParser for ExecCommandParser {
    fn check(&self, args: &CommandArgs) -> Result<(), String> {
        if args.len() != 1 {
            let msg = format!("Invalid exec command: {:?}", args);
            error!("{}", msg);
            return Err(msg);
        }

        Ok(())
    }

    fn parse(&self, args: &[&str]) -> Result<CommandExecutorRef, String> {
        assert!(args.len() == 1, "Exec command should have exactly 1 arg");

        let cmd = ExecCommandExecutor::new(args[0]);
        Ok(Arc::new(Box::new(cmd)))
    }
}

// exec command executer
pub struct ExecCommandExecutor {
    pub block: String,
}

impl ExecCommandExecutor {
    pub fn new(block: &str) -> Self {
        ExecCommandExecutor {
            block: block.to_string(),
        }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for ExecCommandExecutor {
    async fn exec(&self, context: &Context) -> Result<CommandResult, String> {
        // Get target block from context
        let chain = context.chain().ok_or_else(|| {
            let msg = "Exec command requires a chain context".to_string();
            error!("{}", msg);
            msg
        })?;

        let block = chain.get_block(&self.block);
        if block.is_none() {
            let msg = format!("Exec target block not found: {}", self.block);
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
pub struct GotoCommandParser {}

impl GotoCommandParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl CommandParser for GotoCommandParser {
    fn check(&self, args: &CommandArgs) -> Result<(), String> {
        // Args must be either one or two elements
        if args.len() < 1 {
            let msg = format!("Invalid goto command: {:?}", args);
            error!("{}", msg);
            return Err(msg);
        }
        
        // If there are options, they must be valid
        if args.len() >= 2 {
            let option_count =
                CommandArgHelper::check_origin_options(args, &[&["chain", "block"]])?;
            if option_count + 1 != args.len() {
                let msg = format!(
                    "Invalid goto command: expected 1 target after options, but found {} options",
                    option_count
                );
                error!("{}", msg);
                return Err(msg);
            }
        }

        Ok(())
    }

    fn parse(&self, args: &[&str]) -> Result<CommandExecutorRef, String> {
        assert!(args.len() >= 1, "Goto command should have at least 1 arg");

        // Parse the command arguments
        // If only one argument is provided, it is considered a chain name
        // If two arguments are provided, the first one must be --chain or --block
        // and the second one is the target name

        let mut target_level = GotoTargetLevel::Chain;
        let mut option_count = 0;
        if args.len() >= 2 {
            let options = CommandArgHelper::parse_options(args, &[&["chain", "block"]])?;
            option_count = options.len();

            for option in options {
                match option {
                    "block" => {
                        // Set target to Block
                        target_level = GotoTargetLevel::Block;
                    }
                    "chain" => {
                        // Set target to Chain
                        target_level = GotoTargetLevel::Chain;
                    }
                    _ => {
                        let msg = format!("Invalid option '{}' in goto command", option);
                        error!("{}", msg);
                        return Err(msg);
                    }
                }
            }
        };

        if option_count + 1 != args.len() {
            let msg = format!(
                "Invalid goto command: expected 1 target after options, but found {} options",
                option_count
            );
            error!("{}", msg);
            return Err(msg);
        }

        let name = args[option_count].to_string();
        let target = match target_level {
            GotoTargetLevel::Block => GotoTarget::Block(name),
            GotoTargetLevel::Chain => GotoTarget::Chain(name),
        };

        let cmd = GotoCommandExecutor::new(target);
        Ok(Arc::new(Box::new(cmd)))
    }
}

// goto command executer
pub struct GotoCommandExecutor {
    target: GotoTarget,
}

impl GotoCommandExecutor {
    fn new(target: GotoTarget) -> Self {
        Self { target }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for GotoCommandExecutor {
    async fn exec(&self, _context: &Context) -> Result<CommandResult, String> {
        let ret = match &self.target {
            GotoTarget::Block(block) => CommandResult::goto_block(block),
            GotoTarget::Chain(chain) => CommandResult::goto_chain(chain),
        };

        Ok(ret)
    }
}

// Return command parser: like: return; return value;
pub struct ReturnCommandParser {}

impl ReturnCommandParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl CommandParser for ReturnCommandParser {
    fn check(&self, args: &CommandArgs) -> Result<(), String> {
        // Args should be empty or have exactly one element
        if args.len() > 1 {
            let msg = format!("Invalid return command: {:?}", args);
            error!("{}", msg);
            return Err(msg);
        }

        Ok(())
    }

    fn parse(&self, args: &[&str]) -> Result<CommandExecutorRef, String> {
        assert!(args.len() <= 1, "Return command should have at most 1 arg");

        let cmd = ReturnCommandExecutor::new(args.get(0).cloned());
        Ok(Arc::new(Box::new(cmd)))
    }
}

// Return command executer
pub struct ReturnCommandExecutor {
    value: Option<String>,
}

impl ReturnCommandExecutor {
    pub fn new(value: Option<&str>) -> Self {
        Self {
            value: value.map(|s| s.to_string()),
        }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for ReturnCommandExecutor {
    async fn exec(&self, _context: &Context) -> Result<CommandResult, String> {
        let ret = if let Some(value) = &self.value {
            CommandResult::return_to_block_with_value(value)
        } else {
            CommandResult::return_to_block()
        };

        Ok(ret)
    }
}

// Error command parser: like: error; error value;
pub struct ErrorCommandParser {}

impl ErrorCommandParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl CommandParser for ErrorCommandParser {
    fn check(&self, args: &CommandArgs) -> Result<(), String> {
        // Args should be empty or have exactly one element
        if args.len() > 1 {
            let msg = format!("Invalid error command: {:?}", args);
            error!("{}", msg);
            return Err(msg);
        }

        Ok(())
    }

    fn parse(&self, args: &[&str]) -> Result<CommandExecutorRef, String> {
        assert!(args.len() <= 1, "Error command should have at most 1 arg");

        let cmd = ErrorCommandExecutor::new(args.get(0).cloned());
        Ok(Arc::new(Box::new(cmd)))
    }
}

// Error command executer
pub struct ErrorCommandExecutor {
    value: Option<String>,
}

impl ErrorCommandExecutor {
    pub fn new(value: Option<&str>) -> Self {
        Self {
            value: value.map(|s| s.to_string()),
        }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for ErrorCommandExecutor {
    async fn exec(&self, _context: &Context) -> Result<CommandResult, String> {
        let ret = if let Some(value) = &self.value {
            CommandResult::error_to_block_with_value(value)
        } else {
            CommandResult::error_to_block()
        };

        Ok(ret)
    }
}

// Exit command parser: like: exit; exit value;
pub struct ExitCommandParser {}

impl ExitCommandParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl CommandParser for ExitCommandParser {
    fn check(&self, args: &CommandArgs) -> Result<(), String> {
        // Args should be empty or have exactly one element
        if args.len() > 1 {
            let msg = format!("Invalid exit command: {:?}", args);
            error!("{}", msg);
            return Err(msg);
        }

        Ok(())
    }

    fn parse(&self, args: &[&str]) -> Result<CommandExecutorRef, String> {
        assert!(args.len() <= 1, "Exit command should have at most 1 arg");

        let cmd = ExitCommandExecutor::new(args.get(0).cloned());
        Ok(Arc::new(Box::new(cmd)))
    }
}

// Exit command executer
pub struct ExitCommandExecutor {
    value: Option<String>,
}

impl ExitCommandExecutor {
    pub fn new(value: Option<&str>) -> Self {
        Self {
            value: value.map(|s| s.to_string()),
        }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for ExitCommandExecutor {
    async fn exec(&self, _context: &Context) -> Result<CommandResult, String> {
        let ret = if let Some(value) = &self.value {
            CommandResult::exit_chain_with_value(value)
        } else {
            CommandResult::exit_chain()
        };

        Ok(ret)
    }
}
