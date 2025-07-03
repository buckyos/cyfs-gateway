use super::cmd::*;
use crate::block::{context::Context, block::BlockType};
use regex::Regex;
use std::sync::Arc;


// Match command, like: match REQ_HEADER.host "*.local"

pub struct MatchCommandParser {}

impl MatchCommandParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl CommandParser for MatchCommandParser {
    fn check(&self, _block_type: BlockType) -> bool {
        // Match cmd can be used in any block
        true
    }

    fn parse(&self, args: &Vec<String>) -> Result<CommandExecutorRef, String> {
        if args.len() != 2 {
            let msg = format!("Invalid match command: {:?}", args);
            error!("{}", msg);
            return Err(msg);
        }

        let key = args[0].clone();
        let pattern = Regex::new(args[1].as_str()).map_err(|e| {
            let msg = format!("Invalid match pattern: {:?}, {}", args, e);
            error!("{}", msg);
            msg
        })?;

        let cmd = MatchCommandExecutor { key, pattern };
        Ok(Arc::new(Box::new(cmd)))
    }
}

// Match command executer
pub struct MatchCommandExecutor {
    pub key: String,
    pub pattern: Regex,
}

#[async_trait::async_trait]
impl CommandExecutor for MatchCommandExecutor {
    async fn exec(&self, context: &mut Context) -> Result<CommandResult, String> {
        // First get the value
        let value = context.get_value(&self.key);
        if value.is_none() {
            return Ok(CommandResult::failure(1));
        }

        // Then match the value
        let value = value.unwrap();
        if self.pattern.is_match(&value) {
            Ok(CommandResult::success())
        } else {
            Ok(CommandResult::failure(2))
        }
    }
}
