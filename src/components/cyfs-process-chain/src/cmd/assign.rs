use super::cmd::*;
use crate::block::{AssignKind, CommandArgs};
use crate::chain::Context;
use crate::chain::EnvLevel;
use crate::collection::CollectionValue;
use clap::Command;
use std::sync::Arc;

pub struct AssignCommandParser {
    cmd: Command,
}

impl AssignCommandParser {
    pub fn new() -> Self {
        let cmd = Command::new("assign")
            .about("Manage variable definitions and scope preferences.")
            .override_usage(
                r#"
    [SCOPE] VAR=VALUE     Define or update a variable in the specified scope.
    VAR=VALUE             Define a variable in the default (chain) scope.
    SCOPE VAR             Set the default scope for future references to VAR.
    "#,
            )
            .after_help(
                r#"
Scope:
    export, global        Global scope (shared across chains)
    chain                 Chain-level scope (default)
    block, local          Block-level scope

Notes:
    - If a variable already exists, its value will be overwritten.
    - When assigning (VAR=VALUE), scope defaults to 'chain' unless explicitly specified.
    - When only VAR is given after a scope, it sets default lookup scope for VAR.

Examples:
    my_var=123
    global my_var=456
    block my_var
"#,
            );
        Self { cmd }
    }
}

impl CommandParser for AssignCommandParser {
    fn help(&self, _name: &str, help_type: CommandHelpType) -> String {
        command_help(help_type, &self.cmd)
    }

    // [export|global|chain|block|local] KEY=VALUE or [export|global|chain|block|local]  KEY
    // The first param is the kind of assignment, which can be "block", "chain" or "global"
    // The second param is the key, and the third param is the value (optional)
    fn check(&self, args: &CommandArgs) -> Result<(), String> {
        // Args must not be empty
        if args.is_empty() {
            let msg = "Invalid assign command: args cannot be empty".to_string();
            error!("{}", msg);
            return Err(msg);
        }

        // Expect a single argument in the form of KEY=VALUE
        if args.len() < 2 || args.len() > 3 {
            let msg = format!("Invalid assign command: {:?}", args);
            error!("{}", msg);
            return Err(msg);
        }

        Ok(())
    }

    fn parse(
        &self,
        args: Vec<String>,
        _origin_args: &CommandArgs,
    ) -> Result<CommandExecutorRef, String> {
        // Args must not be checked before calling parse
        assert!(
            args.len() >= 2 && args.len() <= 3,
            "Assign command should have 2 or 3 args"
        );

        // Expect a single argument in the form of KEY=VALUE
        let kind = &args[0];
        let kind = AssignKind::from_str(&kind)
            .map_err(|e| format!("Invalid assign kind: {}. Error: {}", kind, e))?;

        let key = &args[1];
        let value = if args.len() > 2 {
            Some(args[2].clone())
        } else {
            None
        };

        let cmd: AssignCommand = AssignCommand::new(kind.to_owned(), key.to_owned(), value);
        Ok(Arc::new(Box::new(cmd)))
    }
}

pub struct AssignCommand {
    kind: AssignKind,
    key: String,
    value: Option<String>,
}

impl AssignCommand {
    pub fn new(kind: AssignKind, key: String, value: Option<String>) -> Self {
        Self { kind, key, value }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for AssignCommand {
    async fn exec(&self, context: &Context) -> Result<CommandResult, String> {
        let env_level = match self.kind {
            AssignKind::Block => EnvLevel::Block,
            AssignKind::Chain => EnvLevel::Chain,
            AssignKind::Global => EnvLevel::Global,
        };

        match self.value {
            Some(ref value) => {
                // Handle assignment with value
                context
                    .env()
                    .set(
                        self.key.as_str(),
                        CollectionValue::String(value.clone()),
                        Some(env_level),
                    )
                    .await?;

                Ok(CommandResult::success_with_value(value))
            }
            None => {
                // Handle assignment without value, which will change the variable scope
                context
                    .env()
                    .change_var_level(self.key.as_str(), Some(env_level));
                Ok(CommandResult::success())
            }
        }
    }
}
