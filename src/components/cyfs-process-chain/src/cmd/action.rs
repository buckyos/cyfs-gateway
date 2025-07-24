use super::cmd::*;
use crate::block::CommandArgs;
use crate::chain::Context;
use clap::Command;
use std::sync::Arc;
// some action commands, DROP/ACCEPT/REJECT
pub struct ActionCommandParser {
    action: CommandAction,
    cmd: Command,
}

impl ActionCommandParser {
    pub fn new(action: CommandAction) -> Self {
        let cmd = Command::new(action.as_str().to_owned())
            .about("Perform a control action that terminates the current process chain execution.")
            .override_usage(
                r#"
    [expression] && drop
    match $ip "192.168.0.*" && accept
    match $uid "blacklist" && reject
"#,
            )
            .after_help(
                r#"
Available Actions:
    drop      Equivalent to `exit drop`. Terminates with result 'drop'.
    accept    Equivalent to `exit accept`. Terminates with result 'accept'.
    reject    Equivalent to `exit reject`. Terminates with result 'reject'.

Notes:
    - All actions immediately stop the entire process chain list.
    - The return value is passed to the outer caller (e.g., dispatcher, protocol stack).
    - Actions are often used after condition expressions such as `match`, `eq`, or `range`.

Examples:
    match $user "admin" && accept
    match $ip "10.0.*.*" && drop
    range $port 1000 2000 && reject
"#,
            );
        Self { action, cmd }
    }
}

impl CommandParser for ActionCommandParser {
    fn help(&self, _name: &str, help_type: CommandHelpType) -> String {
        command_help(help_type, &self.cmd)
    }

    fn check(&self, args: &CommandArgs) -> Result<(), String> {
        self.cmd
            .clone()
            .try_get_matches_from(args.as_str_list())
            .map_err(|e| {
                let msg = format!("Invalid action command: {}", e);
                error!("{}", msg);
                msg
            })?;

        Ok(())
    }

    fn parse(
        &self,
        _args: Vec<String>,
        _origin_args: &CommandArgs,
    ) -> Result<CommandExecutorRef, String> {

        let cmd = ActionCommandExecutor {
            action: self.action.clone(),
        };

        Ok(Arc::new(Box::new(cmd)))
    }
}

// Drop & Pass command
pub struct ActionCommandExecutor {
    action: CommandAction,
}

impl ActionCommandExecutor {
    pub fn new(action: CommandAction) -> Self {
        ActionCommandExecutor { action }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for ActionCommandExecutor {
    async fn exec(&self, _context: &Context) -> Result<CommandResult, String> {
        let ret = match self.action {
            CommandAction::Drop => CommandResult::drop(),
            CommandAction::Accept => CommandResult::accept(),
            CommandAction::Reject => CommandResult::reject(),
        };

        Ok(ret)
    }
}
