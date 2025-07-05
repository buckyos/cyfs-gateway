use super::cmd::*;
use crate::block::{BlockType, Context};
use std::sync::Arc;

// If key is "REQ_HEADER", "REQ_BODY", "RESP_HEADER", "RESP_BODY", then assign to request or response
const REQUEST_VARS: [&str; 4] = ["REQ_HEADER", "REQ_BODY", "RESP_HEADER", "RESP_BODY"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssignType {
    // Normal assignment, use KEY=VALUE
    Normal,
}

pub struct AssignCommandParser {}

impl AssignCommandParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl CommandParser for AssignCommandParser {
    fn check(&self, _block_type: BlockType) -> bool {
        // Assign cmd can be used in any block
        true
    }

    fn parse(&self, args: &[&str]) -> Result<CommandExecutorRef, String> {
        if args.len() != 3 {
            let msg = format!("Invalid assign command: {:?}", args);
            error!("{}", msg);
            return Err(msg);
        }

        let _type = match args[1] {
            "=" => AssignType::Normal,
            _ => {
                let msg = format!("Invalid assign type: {:?}", args);
                error!("{}", msg);
                return Err(msg);
            }
        };

        let key = args[0].to_owned();
        let value = args[2].to_owned();

        // Check is request assign or env assign
        if REQUEST_VARS.contains(&key.as_str()) {
            let cmd = RequestAssignCommand::new(_type, key, value);
            Ok(Arc::new(Box::new(cmd)))
        } else {

            let cmd = EnvAssignCommand::new(key, value);
            Ok(Arc::new(Box::new(cmd)))
        }
    }
}

pub struct EnvAssignCommand {
    key: String,
    value: String,
}

impl EnvAssignCommand {
    pub fn new(key: String, value: String) -> Self {
        Self { key, value }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for EnvAssignCommand {
    async fn exec(&self, _context: &mut Context) -> Result<CommandResult, String> {
        todo!("EnvAssignCommand not implemented yet");
    }
}

pub struct RequestAssignCommand {
    type_: AssignType,
    key: String,
    value: String,
}

impl RequestAssignCommand {
    pub fn new(type_: AssignType, key: String, value: String) -> Self {
        Self { type_, key, value }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for RequestAssignCommand {
    async fn exec(&self, _context: &mut Context) -> Result<CommandResult, String> {
        todo!("RequestAssignCommand not implemented yet");
    }
}
