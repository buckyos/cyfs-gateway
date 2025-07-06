use super::cmd::{CommandExecutorRef, CommandParser, CommandResult};
use crate::block::{BlockType, CommandArgs, Context};
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
    fn check(&self, _block_type: BlockType) -> bool {
        true
    }

    fn parse_origin(
        &self,
        args: Vec<String>,
        origin_args: &CommandArgs,
    ) -> Result<CommandExecutorRef, String> {
        if args.len() != 3 {
            let msg = format!("Invalid rewrite command: {:?}", args);
            error!("{}", msg);
            return Err(msg);
        }

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
impl super::CommandExecutor for RewriteCommand {
    async fn exec(&self, context: &mut Context) -> Result<super::CommandResult, String> {
        let key_value = self.args[0].as_str();
        let pattern_value = self.args[1].as_str();
        let template = self.args[2].as_str();

        if self.pattern.is_match(key_value) {
            if let Some(prefix) = pattern_value.strip_suffix("*") {
                if key_value.starts_with(prefix) && template.ends_with('*') {
                    let tail = &key_value[prefix.len()..];
                    let rewritten = format!("{}{}", &template[..template.len() - 1], tail);
                    context.set_env_value(self.key.as_str(), &rewritten, None);
                }
            }
            Ok(CommandResult::success())
        } else {
            Ok(CommandResult::failure(2))
        }
    }
}

pub struct RewriteRegexCommandParser;

impl RewriteRegexCommandParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl CommandParser for RewriteRegexCommandParser {
    fn check(&self, _block_type: BlockType) -> bool {
        true
    }

    fn parse_origin(
        &self,
        args: Vec<String>,
        origin_args: &CommandArgs,
    ) -> Result<CommandExecutorRef, String> {
        if args.len() != 3 {
            let msg = format!("Invalid rewrite-reg command: {:?}", args);
            error!("{}", msg);
            return Err(msg);
        }

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
impl super::CommandExecutor for RewriteRegexCommand {
    async fn exec(&self, context: &mut Context) -> Result<super::CommandResult, String> {
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

            context.set_env_value(self.key.as_str(), &result, None);
            info!("Rewritten value for {}: {}", self.key, result);

            Ok(CommandResult::success())
        } else {
            Ok(CommandResult::failure(2))
        }
    }
}
