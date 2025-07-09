use super::cmd::*;
use crate::block::CommandArgs;
use crate::chain::Context;
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
    fn check(&self, args: &CommandArgs) -> Result<(), String> {
        // Args should have exactly two elements
        if args.len() != 2 {
            let msg = format!("Invalid match command: {:?}", args);
            error!("{}", msg);
            return Err(msg);
        }

        Ok(())
    }

    fn parse(&self, args: &[&str]) -> Result<CommandExecutorRef, String> {
        assert!(args.len() == 2, "Match command should have exactly 2 args");

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
    async fn exec(&self, _context: &Context) -> Result<CommandResult, String> {
        if self.pattern.is_match(&self.value) {
            Ok(CommandResult::success())
        } else {
            Ok(CommandResult::error())
        }
    }
}

// Match regex command, like: match-regex REQ_HEADER.host "^(.*)\.local$"
/*
* MATCH_REG some_input "^pattern$"
* MATCH_REG --capture name some_input "^pattern$"
*/
pub struct MatchRegexCommandParser {}

impl MatchRegexCommandParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl CommandParser for MatchRegexCommandParser {
    fn check(&self, args: &CommandArgs) -> Result<(), String> {
        // Args should have exactly two or four elements
        if args.len() != 2 || args.len() != 4 {
            let msg = format!("Invalid match_regex command: {:?}", args);
            error!("{}", msg);
            return Err(msg);
        }

        if args.len() == 4 {
            if !args[0].is_literal() {
                let msg = format!(
                    "Invalid match_regex command: --capture must be a literal: {:?}",
                    args
                );
                error!("{}", msg);
                return Err(msg);
            }

            let arg = args[0].as_literal_str().unwrap();
            if arg != "--capture" {
                let msg = format!(
                    "Invalid match_regex command: expected --capture, got: {:?}",
                    args
                );
                error!("{}", msg);
                return Err(msg);
            }
        }

        Ok(())
    }

    fn parse(&self, args: &[&str]) -> Result<CommandExecutorRef, String> {
        let mut i = 0;
        let mut capture = None;

        // Check if there is a --capture flag
        if args.get(i) == Some(&"--capture") {
            if let Some(name) = args.get(i + 1) {
                capture = Some(name.to_string());
                i += 2;
            } else {
                let msg = format!("Expected name after --capture: {:?}", args);
                error!("{}", msg);
                return Err(msg);
            }
        }

        let value = args.get(i).ok_or("Missing value argument")?.to_string();
        let pattern_str = args.get(i + 1).ok_or("Missing pattern argument")?;

        let pattern = Regex::new(pattern_str).map_err(|e| {
            let msg = format!("Invalid regex pattern: {}: {}", args[1], e);
            error!("{}", msg);
            msg
        })?;

        let cmd = MatchRegexCommandExecutor {
            capture,
            value,
            pattern,
        };
        Ok(Arc::new(Box::new(cmd)))
    }
}

// Match regex command executer
pub struct MatchRegexCommandExecutor {
    pub capture: Option<String>, // Optional capture group name
    pub value: String,
    pub pattern: Regex,
}

#[async_trait::async_trait]
impl CommandExecutor for MatchRegexCommandExecutor {
    async fn exec(&self, context: &Context) -> Result<CommandResult, String> {
        // Match the value
        if let Some(caps) = self.pattern.captures(&self.value) {
            if let Some(name) = &self.capture {
                for (i, cap) in caps.iter().enumerate() {
                    if let Some(m) = cap {
                        // TODO: Add env level support, such as --capture export/local name
                        context
                            .set_env_value(format!("{}[{}]", name, i).as_str(), m.as_str(), None)
                            .await?;
                    }
                }
            }

            Ok(CommandResult::success())
        } else {
            Ok(CommandResult::error())
        }
    }
}

// EQ command, like: eq REQ_HEADER.host "localhost"; eq --ignore-case REQ_HEADER.host "LOCALHOST"
pub struct EQCommandParser {}

impl EQCommandParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl CommandParser for EQCommandParser {
    fn check(&self, args: &CommandArgs) -> Result<(), String> {
        // Args should have exactly two or three elements
        if args.len() < 2 && args.len() > 3 {
            let msg = format!("Invalid eq command: {:?}", args);
            error!("{}", msg);
            return Err(msg);
        }
        // If there are 3 args, the first one must be --ignore-case
        if args.len() == 3 {
            if !args[0].is_literal() {
                let msg = format!("Invalid eq command: {:?}", args);
                error!("{}", msg);
                return Err(msg);
            }

            let arg = args[0].as_literal_str().unwrap();
            if arg != "--ignore-case" {
                let msg = format!(
                    "Invalid eq command: expected --ignore-case, got: {:?}",
                    args
                );
                error!("{}", msg);
                return Err(msg);
            }
        }

        Ok(())
    }

    fn parse(&self, args: &[&str]) -> Result<CommandExecutorRef, String> {
        assert!(
            args.len() == 2 || args.len() == 3,
            "EQ command should have 2 or 3 args"
        );

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
    async fn exec(&self, _context: &Context) -> Result<CommandResult, String> {
        let is_eq = if self.ignore_case {
            self.value1.eq_ignore_ascii_case(&self.value2)
        } else {
            self.value1 == self.value2
        };

        if is_eq {
            Ok(CommandResult::success())
        } else {
            Ok(CommandResult::error())
        }
    }
}

// Range command, like: range var range_begin range_end
pub struct RangeCommandParser {}

impl RangeCommandParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl CommandParser for RangeCommandParser {
    fn check(&self, args: &CommandArgs) -> Result<(), String> {
        // Args should have exactly three elements
        if args.len() != 3 {
            let msg = format!("Invalid range command: {:?}", args);
            error!("{}", msg);
            return Err(msg);
        }

        // If arg is literal, it must be a valid number
        for arg in args.iter() {
            if arg.is_literal() {
                if let Err(e) = arg.as_literal_str().unwrap().parse::<f64>() {
                    let msg = format!("Invalid range command value: {:?}: {}", arg, e);
                    error!("{}", msg);
                    return Err(msg);
                }
            }
        }

        Ok(())
    }

    fn parse(&self, args: &[&str]) -> Result<CommandExecutorRef, String> {
        assert!(args.len() == 3, "Range command should have exactly 3 args");

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
    async fn exec(&self, _context: &Context) -> Result<CommandResult, String> {
        if self.value >= self.min && self.value <= self.max {
            Ok(CommandResult::success())
        } else {
            Ok(CommandResult::error())
        }
    }
}
