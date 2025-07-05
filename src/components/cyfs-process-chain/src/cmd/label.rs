use super::cmd::*;
use crate::block::{Context, BlockType};
use std::sync::Arc;

// CMD: set_label_by_host_db REQ_HEADER.host
pub struct SetLabelByHostDbCommandParser {}

impl SetLabelByHostDbCommandParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl CommandParser for SetLabelByHostDbCommandParser {
    fn check(&self, _block_type: BlockType) -> bool {
       true
    }

    fn parse(&self, args: &[&str]) -> Result<CommandExecutorRef, String> {
        // Args should not be empty
        if args.is_empty() {
            let msg = format!("Invalid set_label_by_host_db command: {:?}", args);
            error!("{}", msg);
            return Err(msg);
        }

        // Only accept one argument
        if args.len() != 1 {
            let msg = format!("Invalid set_label_by_host_db command: {:?}", args);
            error!("{}", msg);
            return Err(msg);
        }

        let cmd = SetLabelByHostDbCommandExecutor::new(args[0]);
        Ok(Arc::new(Box::new(cmd)))
    }
}

// Set label by host db command executer
pub struct SetLabelByHostDbCommandExecutor {
    pub key: String,
}

impl SetLabelByHostDbCommandExecutor {
    pub fn new(key: &str) -> Self {
        SetLabelByHostDbCommandExecutor {
            key: key.to_string(),
        }
    }
}


#[async_trait::async_trait]
impl CommandExecutor for SetLabelByHostDbCommandExecutor {
    async fn exec(&self, context: &mut Context) -> Result<CommandResult, String> {
        // First get value from context, then load label from host db, then set label to request header
        let value = context.get_value(self.key.as_str());
        if value.is_none() {
            return Ok(CommandResult::failure(1));
        }

        context.set_label_from_host_db(&value.unwrap());

        Ok(CommandResult::success())
    }
}

// CMD: have_label REQ_HEADER.label "xxx"
pub struct HaveLabelCommandParser {

}

impl HaveLabelCommandParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl CommandParser for HaveLabelCommandParser {
    fn check(&self, _block_type: BlockType) -> bool {
        // Have label command can be used in any block
        true
    }

    fn parse(&self, args: &[&str]) -> Result<CommandExecutorRef, String> {
        if args.len() != 2 {
            let msg = format!("Invalid have_label command: {:?}", args);
            error!("{}", msg);
            return Err(msg);
        }

        let cmd = HaveLabelCommandExecutor::new(args[0].to_owned(), args[1].to_owned());
        Ok(Arc::new(Box::new(cmd)))
    }
}

pub struct HaveLabelCommandExecutor {
    pub key: String,
    pub label: String,
}

impl HaveLabelCommandExecutor {
    pub fn new(key: String, label: String) -> Self {
        HaveLabelCommandExecutor {
            key,
            label,
        }
    }
}


#[async_trait::async_trait]
impl CommandExecutor for HaveLabelCommandExecutor {
    async fn exec(&self, context: &mut Context) -> Result<CommandResult, String> {
        // First get value from context, then check if the label exists
        let labels = context.get_value(self.key.as_str());
        if labels.is_none() {
            return Ok(CommandResult::failure(1));
        }

        // Parse the labels
        let labels = labels.unwrap();
        let labels: Vec<&str> = labels.split(',').collect();
        for label in labels {
            if label == self.label {
                return Ok(CommandResult::success());
            }
        }

        Ok(CommandResult::failure(2))
    }
}
