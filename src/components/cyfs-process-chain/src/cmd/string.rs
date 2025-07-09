use super::cmd::{CommandExecutor, CommandExecutorRef, CommandParser, CommandResult};
use crate::block::{CommandArgs, Context};
use globset::{GlobBuilder, GlobMatcher};
use std::sync::Arc;

// rewrite <var> <pattern> <template>
// rewrite $REQ.url /kapi/my-service/* /kapi/*
pub struct RewriteCommandParser;

impl RewriteCommandParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl CommandParser for RewriteCommandParser {
    fn check(&self, args: &CommandArgs) -> Result<(), String> {
        // Args should have exactly three elements
        if args.len() != 3 {
            let msg = format!("Invalid rewrite command: {:?}", args);
            error!("{}", msg);
            return Err(msg);
        }

        // The first argument must be a variable
        if !args[0].is_var() {
            let msg = format!(
                "Invalid rewrite command: {:?}, the first argument must be a variable",
                args
            );
            error!("{}", msg);
            return Err(msg);
        }

        // The second argument must be a valid glob pattern if is literal
        if args[1].is_literal() {
            let pattern = args[1].as_literal_str().unwrap();
            if let Err(e) = GlobBuilder::new(pattern).case_insensitive(true).build() {
                let msg = format!("Invalid glob pattern: {}, {}", pattern, e);
                error!("{}", msg);
                return Err(msg);
            }
        }

        Ok(())
    }

    fn parse_origin(
        &self,
        args: Vec<String>,
        origin_args: &CommandArgs,
    ) -> Result<CommandExecutorRef, String> {
        assert!(
            args.len() == 3,
            "Rewrite command should have exactly 3 args"
        );

        let key_arg = &origin_args.as_slice()[0];
        if !key_arg.is_var() {
            let msg = format!(
                "Invalid rewrite command: {:?}, the first argument must be a variable",
                args
            );
            error!("{}", msg);
            return Err(msg);
        }
        let key = key_arg.as_var_str().unwrap();

        let pattern = GlobBuilder::new(&args[1])
            .case_insensitive(true)
            .build()
            .map_err(|e| {
                let msg = format!("Invalid glob pattern: {}: {}", args[1], e);
                error!("{}", msg);
                msg
            })?
            .compile_matcher();

        let cmd = RewriteCommand::new(key.to_string(), pattern, args);

        Ok(Arc::new(Box::new(cmd)))
    }
}

pub struct RewriteCommand {
    key: String,
    pattern: GlobMatcher,
    args: Vec<String>,
}

impl RewriteCommand {
    pub fn new(key: String, pattern: GlobMatcher, args: Vec<String>) -> Self {
        Self { key, pattern, args }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for RewriteCommand {
    async fn exec(&self, context: &Context) -> Result<super::CommandResult, String> {
        let key_value = self.args[0].as_str();
        let pattern_value = self.args[1].as_str();
        let template = self.args[2].as_str();

        if self.pattern.is_match(key_value) {
            if let Some(prefix) = pattern_value.strip_suffix("*") {
                if key_value.starts_with(prefix) && template.ends_with('*') {
                    let tail = &key_value[prefix.len()..];
                    let rewritten = format!("{}{}", &template[..template.len() - 1], tail);
                    context
                        .set_env_value(self.key.as_str(), &rewritten, None)
                        .await?;
                    Ok(CommandResult::success_with_value(rewritten))
                } else {
                    Ok(CommandResult::success())
                }
            } else {
                Ok(CommandResult::success())
            }
        } else {
            Ok(CommandResult::error())
        }
    }
}

// rewrite $var ^/test/(\w+)(?:/(\d+))? /new/$1/$2
pub struct RewriteRegexCommandParser;

impl RewriteRegexCommandParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl CommandParser for RewriteRegexCommandParser {
    fn check(&self, args: &CommandArgs) -> Result<(), String> {
        // Args should have exactly three elements
        if args.len() != 3 {
            let msg = format!("Invalid rewrite-regex command: {:?}", args);
            error!("{}", msg);
            return Err(msg);
        }

        // The first argument must be a variable
        if !args[0].is_var() {
            let msg = format!(
                "Invalid rewrite-regex command: {:?}, the first argument must be a variable",
                args
            );
            error!("{}", msg);
            return Err(msg);
        }

        // The second argument must be a valid regex pattern if is literal
        if args[1].is_literal() {
            let pattern = args[1].as_literal_str().unwrap();
            if let Err(e) = regex::Regex::new(pattern) {
                let msg = format!("Invalid regex pattern: {}, {}", pattern, e);
                error!("{}", msg);
                return Err(msg);
            }
        }

        Ok(())
    }

    fn parse_origin(
        &self,
        args: Vec<String>,
        origin_args: &CommandArgs,
    ) -> Result<CommandExecutorRef, String> {
        assert!(
            args.len() == 3,
            "Rewrite-regex command should have exactly 3 args"
        );

        let key_arg = &origin_args.as_slice()[0];
        if !key_arg.is_var() {
            let msg = format!(
                "Invalid rewrite-regex command: {:?}, the first argument must be a variable",
                args
            );
            error!("{}", msg);
            return Err(msg);
        }
        let key = key_arg.as_var_str().unwrap();

        let regex = regex::Regex::new(&args[1]).map_err(|e| {
            let msg = format!("Invalid regex pattern: {}: {}", args[1], e);
            error!("{}", msg);
            msg
        })?;

        let cmd = RewriteRegexCommand::new(key.to_string(), regex, args);

        Ok(Arc::new(Box::new(cmd)))
    }
}

pub struct RewriteRegexCommand {
    key: String,
    regex: regex::Regex,
    args: Vec<String>,
}

impl RewriteRegexCommand {
    pub fn new(key: String, regex: regex::Regex, args: Vec<String>) -> Self {
        Self { key, regex, args }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for RewriteRegexCommand {
    async fn exec(&self, context: &Context) -> Result<super::CommandResult, String> {
        let key_value = self.args[0].as_str();
        let template = self.args[2].as_str();

        if let Some(captures) = self.regex.captures(key_value) {
            // Replace template variables like $1, $2, etc. with captured groups
            let mut result = String::new();
            let mut chars = template.chars().peekable();

            while let Some(c) = chars.next() {
                if c == '$' {
                    if let Some(&next_c) = chars.peek() {
                        if next_c.is_ascii_digit() {
                            chars.next(); // consume digit
                            let idx = next_c.to_digit(10).ok_or_else(|| {
                                let msg =
                                    format!("Invalid digit after $ in template: {}", template);
                                error!("{}", msg);
                                msg
                            })? as usize;

                            if let Some(m) = captures.get(idx) {
                                result.push_str(m.as_str());
                            } else {
                                // if the capture group does not exist, we should skip it as empty
                            }

                            continue;
                        }
                    }

                    result.push('$'); // literal $
                } else {
                    result.push(c);
                }
            }

            context
                .set_env_value(self.key.as_str(), &result, None)
                .await?;
            info!("Rewritten value for {}: {}", self.key, result);

            Ok(CommandResult::success_with_value(result))
        } else {
            Ok(CommandResult::error())
        }
    }
}

// replace <target_var> <match_text> <new_text>
pub struct StringReplaceCommandParser;

impl StringReplaceCommandParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl CommandParser for StringReplaceCommandParser {
    fn check(&self, args: &CommandArgs) -> Result<(), String> {
        // Args should have exactly three elements
        if args.len() != 3 {
            let msg = format!("Invalid string replace command: {:?}", args);
            error!("{}", msg);
            return Err(msg);
        }

        // The first argument must be a variable
        if !args[0].is_var() {
            let msg = format!(
                "Invalid string replace command: {:?}, the first argument must be a variable",
                args
            );
            error!("{}", msg);
            return Err(msg);
        }

        Ok(())
    }

    fn parse_origin(
        &self,
        args: Vec<String>,
        origin_args: &CommandArgs,
    ) -> Result<CommandExecutorRef, String> {
        assert!(
            args.len() == 3,
            "String replace command should have exactly 3 args"
        );

        let key_arg = &origin_args.as_slice()[0];
        if !key_arg.is_var() {
            let msg = format!(
                "Invalid string-replace command: {:?}, the first argument must be a variable",
                args
            );
            error!("{}", msg);
            return Err(msg);
        }
        let key = key_arg.as_var_str().unwrap();

        let cmd = StringReplaceCommand::new(key.to_string(), args);

        Ok(Arc::new(Box::new(cmd)))
    }
}

pub struct StringReplaceCommand {
    key: String,
    args: Vec<String>,
}

impl StringReplaceCommand {
    pub fn new(key: String, args: Vec<String>) -> Self {
        Self { key, args }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for StringReplaceCommand {
    async fn exec(&self, context: &Context) -> Result<super::CommandResult, String> {
        let key_value = self.args[0].as_str();
        let match_text = &self.args[1];
        let new_text = &self.args[2];

        if key_value.contains(match_text) {
            let rewritten = key_value.replace(match_text, new_text);
            context
                .set_env_value(self.key.as_str(), &rewritten, None)
                .await?;
            info!("Replace value for {}: {}", self.key, rewritten);

            Ok(super::CommandResult::success_with_value(rewritten))
        } else {
            Ok(super::CommandResult::error())
        }
    }
}

// append param1 param2
// This command appends param2 to param1 and not effect the env, just return the result
pub struct StringAppendCommandParser;

impl StringAppendCommandParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl CommandParser for StringAppendCommandParser {
    fn check(&self, args: &CommandArgs) -> Result<(), String> {
        // Args should have exactly two elements
        if args.len() != 2 {
            let msg = format!("Invalid string append command: {:?}", args);
            error!("{}", msg);
            return Err(msg);
        }

        Ok(())
    }

    fn parse(&self, args: &[&str]) -> Result<CommandExecutorRef, String> {
        assert!(
            args.len() == 2,
            "String append command should have exactly 2 args"
        );

        let result = args[0].to_string() + args[1];
        info!("String append {} + {} = {}", args[0], args[1], result);

        let cmd = StringConstCommand::new(result);

        Ok(Arc::new(Box::new(cmd)))
    }
}

pub struct StringConstCommand {
    result: String,
}

impl StringConstCommand {
    pub fn new(result: String) -> Self {
        Self { result }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for StringConstCommand {
    async fn exec(&self, _context: &Context) -> Result<super::CommandResult, String> {
        // Just return the result without modifying the context

        Ok(super::CommandResult::success_with_value(&self.result))
    }
}

// slice <string> range_start:range_end
// This command slices a string from range_start to range_end and returns the result
pub struct StringSliceCommandParser;

impl StringSliceCommandParser {
    pub fn new() -> Self {
        Self {}
    }

    fn parse_range(range: &str) -> Result<(usize, usize), String> {
        let range_parts: Vec<&str> = range.split(':').collect();
        if range_parts.len() != 2 {
            let msg = format!("Invalid range format: {}", range);
            error!("{}", msg);
            return Err(msg);
        }

        let start: usize = range_parts[0].parse().map_err(|e| {
            let msg = format!("Invalid start index: {}: {}", range_parts[0], e);
            error!("{}", msg);
            msg
        })?;
        let end: usize = range_parts[1].parse().map_err(|e| {
            let msg = format!("Invalid end index: {}: {}", range_parts[1], e);
            error!("{}", msg);
            msg
        })?;

        Ok((start, end))
    }
}

impl CommandParser for StringSliceCommandParser {
    fn check(&self, args: &CommandArgs) -> Result<(), String> {
        // Args should have exactly two elements
        if args.len() != 2 {
            let msg = format!("Invalid string slice command: {:?}", args);
            error!("{}", msg);
            return Err(msg);
        }

        // The second argument must be a valid range format if is literal
        if args[1].is_literal() {
            let range = args[1].as_literal_str().unwrap();
            Self::parse_range(range)?;
        }

        Ok(())
    }

    fn parse(&self, args: &[&str]) -> Result<CommandExecutorRef, String> {
        assert!(
            args.len() == 2,
            "String slice command should have exactly 2 args"
        );

        let (start, end) = Self::parse_range(args[1])?;

        let ret =
            if start <= end && args[0].is_char_boundary(start) && args[1].is_char_boundary(end) {
                args[0].get(start..end)
            } else {
                None
            };

        let ret = ret.unwrap_or_default().to_string();
        info!("String slice {}[{}:{}] = {}", args[0], start, end, ret);

        let cmd = StringConstCommand::new(ret);

        Ok(Arc::new(Box::new(cmd)))
    }
}

// strlen <string>
// This command returns the length of a string
pub struct StringLengthCommandParser;

impl StringLengthCommandParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl CommandParser for StringLengthCommandParser {
    fn check(&self, args: &CommandArgs) -> Result<(), String> {
        // Args should have exactly one element
        if args.len() != 1 {
            let msg = format!("Invalid strlen command: {:?}", args);
            error!("{}", msg);
            return Err(msg);
        }

        Ok(())
    }

    fn parse(&self, args: &[&str]) -> Result<CommandExecutorRef, String> {
        assert!(args.len() == 1, "strlen command should have exactly 1 arg");

        let length = args[0].len();
        info!("String length of {} is {}", args[0], length);

        let cmd = StringConstCommand::new(length.to_string());

        Ok(Arc::new(Box::new(cmd)))
    }
}

// starts-with <string> <prefix>
// This command checks if a string starts with a given prefix

pub struct StringStartsWithCommandParser;

impl StringStartsWithCommandParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl CommandParser for StringStartsWithCommandParser {
    fn check(&self, args: &CommandArgs) -> Result<(), String> {
        // Args should have exactly two elements
        if args.len() != 2 {
            let msg = format!("Invalid string starts-with command: {:?}", args);
            error!("{}", msg);
            return Err(msg);
        }

        Ok(())
    }

    fn parse(&self, args: &[&str]) -> Result<CommandExecutorRef, String> {
        assert!(
            args.len() == 2,
            "String starts-with command should have exactly 2 args"
        );

        let starts_with = args[0].starts_with(args[1]);
        info!(
            "String '{}' starts with '{}': {}",
            args[0], args[1], starts_with
        );

        let cmd = StringConstCommand::new(starts_with.to_string());

        Ok(Arc::new(Box::new(cmd)))
    }
}

// ends-with <string> <suffix>
// This command checks if a string ends with a given suffix
pub struct StringEndsWithCommandParser;

impl StringEndsWithCommandParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl CommandParser for StringEndsWithCommandParser {
    fn check(&self, args: &CommandArgs) -> Result<(), String> {
        // Args should have exactly two elements
        if args.len() != 2 {
            let msg = format!("Invalid string ends-with command: {:?}", args);
            error!("{}", msg);
            return Err(msg);
        }

        Ok(())
    }

    fn parse(&self, args: &[&str]) -> Result<CommandExecutorRef, String> {
        assert!(
            args.len() == 2,
            "String ends-with command should have exactly 2 args"
        );

        let ends_with = args[0].ends_with(args[1]);
        info!(
            "String '{}' ends with '{}': {}",
            args[0], args[1], ends_with
        );

        let cmd = StringConstCommand::new(ends_with.to_string());

        Ok(Arc::new(Box::new(cmd)))
    }
}
