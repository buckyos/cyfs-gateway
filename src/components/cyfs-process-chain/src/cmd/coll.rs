use super::cmd::{
    CommandExecutor, CommandExecutorRef, CommandParser, CommandResult,
};
use crate::block::{BlockType, CommandArgs, Context};
use std::sync::Arc;

// match_include <var> <collection_id>
// Check if the variable is included in the specified collection
pub struct MatchIncludeCommandParser {}

impl MatchIncludeCommandParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl CommandParser for MatchIncludeCommandParser {
    fn check(&self, block_type: BlockType) -> bool {
        match block_type {
            BlockType::Probe | BlockType::Process => true,
            _ => false,
        }
    }

    fn parse(&self, args: &[&str]) -> Result<CommandExecutorRef, String> {
        // Args should not be empty
        if args.is_empty() {
            let msg = format!("Invalid match_include command: {:?}", args);
            error!("{}", msg);
            return Err(msg);
        }

        // Args should have exactly two elements
        if args.len() != 2 {
            let msg = format!("Invalid match_include command: {:?}", args);
            error!("{}", msg);
            return Err(msg);
        }

        let cmd = MatchIncludeCommandExecutor::new(args[0], args[1]);
        Ok(Arc::new(Box::new(cmd)))
    }
}

// MatchIncludeCommandExecutor
pub struct MatchIncludeCommandExecutor {
    pub key: String,
    pub collection_id: String,
}

impl MatchIncludeCommandExecutor {
    pub fn new(key: &str, collection_id: &str) -> Self {
        Self {
            key: key.to_owned(),
            collection_id: collection_id.to_owned(),
        }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for MatchIncludeCommandExecutor {
    async fn exec(&self, context: &mut Context) -> Result<CommandResult, String> {
        // Get the collection from the context
        let contains = context
            .collection_manager()
            .is_include_key(&self.collection_id, &self.key)
            .await?;

        if contains {
            Ok(CommandResult::success())
        } else {
            Ok(CommandResult::failure(1))
        }
    }
}
