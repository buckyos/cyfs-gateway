use super::cmd::*;
use crate::block::{Context, BlockType};
use std::sync::Arc;

// http-sni-probe command parser
pub struct HttpSniProbeCommandParser {}

impl HttpSniProbeCommandParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl CommandParser for HttpSniProbeCommandParser {
    fn check(&self, block_type: BlockType) -> bool {
        match block_type {
            BlockType::Probe => true,
            _ => false,
        }
    }

    fn parse(&self, args: &Vec<String>) -> Result<CommandExecutorRef, String> {
        // Args must be empty
        if !args.is_empty() {
            let msg = format!("Invalid http-sni-probe command: {:?}", args);
            error!("{}", msg);
            return Err(msg);
        }

        let cmd = HttpSniProbeCommandExecutor::new();
        Ok(Arc::new(Box::new(cmd)))
    }
}

// http-sni-probe command executer
pub struct HttpSniProbeCommandExecutor {}

impl HttpSniProbeCommandExecutor {
    pub fn new() -> Self {
        HttpSniProbeCommandExecutor {}
    }
}

#[async_trait::async_trait]
impl CommandExecutor for HttpSniProbeCommandExecutor {
    async fn exec(&self, _context: &mut Context) -> Result<CommandResult, String> {
        todo!("http-sni-probe not implemented yet");

        // context.set_value("REQ_HEADER.host", "");

        // Ok(CommandResult::success())
    }
}
