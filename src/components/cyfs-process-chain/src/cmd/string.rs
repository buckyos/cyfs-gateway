use super::cmd::{CommandExecutorRef, CommandParser, CommandResult};
use crate::block::{BlockType, CommandArgs, Context};
use globset::{GlobBuilder, GlobMatcher};
use std::sync::Arc;

// rewrite <var> <pattern> <template>
// rewrite $REQ.url /kapi/my-service/* /kapi/*
pub struct RewriteCommandParser;

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
