use super::cmd::*;
use crate::block::{BlockType, Context};
use globset::{GlobBuilder, GlobMatcher};
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

    fn parse(&self, args: &[&str]) -> Result<CommandExecutorRef, String> {
        if args.len() != 2 {
            let msg = format!("Invalid match command: {:?}", args);
            error!("{}", msg);
            return Err(msg);
        }

        let value = args[0].to_owned();

        let pattern = GlobBuilder::new(args[1])
            .case_insensitive(true)
            .build()
            .map_err(|e| {
                let msg = format!("Invalid glob pattern: {}: {}", args[1], e);
                error!("{}", msg);
                msg
            })?
            .compile_matcher();

        let cmd = MatchCommandExecutor { value, pattern };
        Ok(Arc::new(Box::new(cmd)))
    }
}

// Match command executer
pub struct MatchCommandExecutor {
    pub value: String,
    pub pattern: GlobMatcher,
}

#[async_trait::async_trait]
impl CommandExecutor for MatchCommandExecutor {
    async fn exec(&self, _context: &mut Context) -> Result<CommandResult, String> {
        if self.pattern.is_match(&self.value) {
            Ok(CommandResult::success())
        } else {
            Ok(CommandResult::failure(2))
        }
    }
}

pub struct MatchRegexCommandParser {}

impl MatchRegexCommandParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl CommandParser for MatchRegexCommandParser {
    fn check(&self, _block_type: BlockType) -> bool {
        // Match regex cmd can be used in any block
        true
    }

    fn parse(&self, args: &[&str]) -> Result<CommandExecutorRef, String> {
        if args.len() != 2 {
            let msg = format!("Invalid match_regex command: {:?}", args);
            error!("{}", msg);
            return Err(msg);
        }

        let value = args[0].to_owned();
        let pattern = Regex::new(args[1]).map_err(|e| {
            let msg = format!("Invalid regex pattern: {}: {}", args[1], e);
            error!("{}", msg);
            msg
        })?;

        let cmd = MatchRegexCommandExecutor { value, pattern };
        Ok(Arc::new(Box::new(cmd)))
    }
}

// Match regex command executer
pub struct MatchRegexCommandExecutor {
    pub value: String,
    pub pattern: Regex,
}

#[async_trait::async_trait]
impl CommandExecutor for MatchRegexCommandExecutor {
    async fn exec(&self, _context: &mut Context) -> Result<CommandResult, String> {
        // Match the value
        if self.pattern.is_match(&self.value) {
            Ok(CommandResult::success())
        } else {
            Ok(CommandResult::failure(2))
        }
    }
}

pub struct EQCommandParser {}

impl EQCommandParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl CommandParser for EQCommandParser {
    fn check(&self, _block_type: BlockType) -> bool {
        // EQ cmd can be used in any block
        true
    }

    fn parse(&self, args: &[&str]) -> Result<CommandExecutorRef, String> {
        // If there are 3 args, the first one must be --ignore-case
        let cmd = if args.len() == 2 {
            let value1 = args[0].to_owned();
            let value2 = args[1].to_owned();

            EQCommandExecutor {
                ignore_case: false,
                value1,
                value2,
            }
        } else if args.len() == 3 {
            if args[0] != "--ignore-case" {
                let msg = format!("Invalid eq command: {:?}", args);
                error!("{}", msg);
                return Err(msg);
            }

            let value1 = args[0].to_owned();
            let value2 = args[1].to_owned();

            EQCommandExecutor {
                ignore_case: true,
                value1,
                value2,
            }
        } else {
            let msg = format!("Invalid eq command: {:?}", args);
            error!("{}", msg);
            return Err(msg);
        };

        Ok(Arc::new(Box::new(cmd)))
    }
}

// EQ command executer
pub struct EQCommandExecutor {
    pub ignore_case: bool, // Whether to ignore case, default is false
    pub value1: String,
    pub value2: String,
}

#[async_trait::async_trait]
impl CommandExecutor for EQCommandExecutor {
    async fn exec(&self, _context: &mut Context) -> Result<CommandResult, String> {
        let is_eq = if self.ignore_case {
            self.value1.eq_ignore_ascii_case(&self.value2)
        } else {
            self.value1 == self.value2
        };

        if is_eq {
            Ok(CommandResult::success())
        } else {
            Ok(CommandResult::failure(2))
        }
    }
}


pub struct RangeCommandParser {}

impl RangeCommandParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl CommandParser for RangeCommandParser {
    fn check(&self, _block_type: BlockType) -> bool {
        // Range cmd can be used in any block
        true
    }

    fn parse(&self, args: &[&str]) -> Result<CommandExecutorRef, String> {
        if args.len() != 3 {
            let msg = format!("Invalid range command: {:?}", args);
            error!("{}", msg);
            return Err(msg);
        }

        let value = args[1].parse::<f64>().map_err(|e| {
            let msg = format!("Invalid range value: {}: {}", args[1], e);
            error!("{}", msg);
            msg
        })?;

        let min = args[1].parse::<f64>().map_err(|e| {
            let msg = format!("Invalid range min value: {}: {}", args[1], e);
            error!("{}", msg);
            msg
        })?;
        let max = args[2].parse::<f64>().map_err(|e| {
            let msg = format!("Invalid range max value: {}: {}", args[2], e);
            error!("{}", msg);
            msg
        })?;

        let cmd = RangeCommandExecutor { value, min, max };
        Ok(Arc::new(Box::new(cmd)))
    }
}

// Range command executer
pub struct RangeCommandExecutor {
    pub value: f64,
    pub min: f64,
    pub max: f64,
}

#[async_trait::async_trait]
impl CommandExecutor for RangeCommandExecutor {
    async fn exec(&self, _context: &mut Context) -> Result<CommandResult, String> {
        if self.value >= self.min && self.value <= self.max {
            Ok(CommandResult::success())
        } else {
            Ok(CommandResult::failure(2))
        }
    }
}