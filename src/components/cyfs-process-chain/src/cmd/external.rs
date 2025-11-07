use super::cmd::*;
use crate::block::{CommandArg, CommandArgs};
use crate::chain::{Context, ParserContext};
use crate::collection::CollectionValue;
use crate::js::{AsyncJavaScriptCommandExecutor, AsyncJavaScriptCommandExecutorRef};
use clap::{Arg, Command};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[async_trait::async_trait]
pub trait ExternalCommand: Send + Sync {
    fn help(&self, name: &str, _help_type: CommandHelpType) -> String {
        format!("Usage: {}", name)
    }

    fn check(&self, args: &CommandArgs) -> Result<(), String>;

    async fn exec(
        &self,
        context: &Context,
        args: &[CollectionValue],
        origin_args: &CommandArgs,
    ) -> Result<CommandResult, String>;
}

pub type ExternalCommandRef = Arc<Box<dyn ExternalCommand>>;

#[derive(Clone)]
pub struct ExternalCommandFactory {
    commands: Arc<Mutex<HashMap<String, ExternalCommandRef>>>,
    js_command_executor: AsyncJavaScriptCommandExecutorRef,
}

impl ExternalCommandFactory {
    pub fn new() -> Self {
        Self {
            commands: Arc::new(Mutex::new(HashMap::new())),
            js_command_executor: Arc::new(AsyncJavaScriptCommandExecutor::new()),
        }
    }

    pub fn register(&self, name: &str, command: ExternalCommandRef) -> Result<(), String> {
        let mut commands = self.commands.lock().unwrap();
        if commands.contains_key(name) {
            let msg = format!("External command {} already exists, will be replaced", name);
            error!("{}", msg);
            return Err(msg);
        }

        commands.insert(name.to_string(), command);

        info!("Registered external command: {}", name);
        Ok(())
    }

    pub async fn register_js_external_command(
        &self,
        name: &str,
        source: String,
    ) -> Result<(), String> {
        let cmd = self
            .js_command_executor
            .load_command(name.to_owned(), source)
            .await
            .map_err(|e| {
                let msg = format!(
                    "Failed to register JavaScript external command '{}': {}",
                    name, e
                );
                error!("{}", msg);
                msg
            })?;

        self.register(name, Arc::new(Box::new(cmd) as Box<dyn ExternalCommand>))
    }

    pub fn get_command(&self, name: &str) -> Option<ExternalCommandRef> {
        let commands = self.commands.lock().unwrap();
        commands.get(name).cloned()
    }

    pub fn get_command_list(&self) -> Vec<String> {
        let commands = self.commands.lock().unwrap();
        commands.keys().cloned().collect()
    }

    pub fn finalize(&self) {
        self.js_command_executor.stop();

        // Clear all commands
        let mut commands = self.commands.lock().unwrap();
        info!(
            "Unregistering all external commands, count: {}",
            commands.len()
        );
        commands.clear();
    }
}

lazy_static::lazy_static! {
    // Global command parser factory instance
    pub static ref EXTERNAL_COMMAND_FACTORY: ExternalCommandFactory = {
        let factory = ExternalCommandFactory::new();
        factory
    };
}

// call <command> <args...>
pub struct ExternalCommandParser {
    cmd: Command,
}

impl ExternalCommandParser {
    pub fn new() -> Self {
        let cmd = Command::new("call")
            .about("Call an external or user-defined command with arguments")
            .after_help(
                r#"
Note:
  - All external commands must be registered with the runtime beforehand.
  - If the command is not found, an error will be returned.
  - This command is useful to invoke plugin-based or user-defined logic
    without polluting the internal command namespace.

Examples:
  call verify_token $REQ.token
  call user_lookup alice
  call plugin.process_json '{"key": "value"}'
"#,
            )
            .arg(
                Arg::new("command")
                    .help("The external command to execute")
                    .required(true),
            )
            .arg(
                Arg::new("args")
                    .help("Arguments for the external command")
                    .num_args(0..)
                    .trailing_var_arg(true),
            );

        Self { cmd }
    }
}

impl CommandParser for ExternalCommandParser {
    fn group(&self) -> CommandGroup {
        CommandGroup::External
    }

    fn help(&self, _name: &str, help_type: CommandHelpType) -> String {
        command_help(help_type, &self.cmd)
    }

    fn parse(
        &self,
        context: &ParserContext,
        str_args: Vec<&str>,
        args: &CommandArgs,
    ) -> Result<CommandExecutorRef, String> {
        let matches = self
            .cmd
            .clone()
            .try_get_matches_from(&str_args)
            .map_err(|e| {
                let msg = format!("Invalid external command: {:?}, {}", str_args, e);
                error!("{}", msg);
                msg
            })?;

        let cmd_index = matches.index_of("command").ok_or_else(|| {
            let msg = "Command argument 'command' is required".to_string();
            error!("{}", msg);
            msg
        })?;

        let cmd = &args[cmd_index];

        // Ensure the command argument is a literal string
        if !cmd.is_literal() {
            let msg = format!("Command must be a string, got: {:?}", cmd);
            error!("{}", msg);
            return Err(msg);
        }

        let cmd = cmd.as_literal_str().unwrap();
        let command = context.get_external_command(cmd).ok_or_else(|| {
            let msg = format!("External command '{}' not found", cmd);
            error!("{}", msg);
            msg
        })?;

        let args = match matches.index_of("command") {
            Some(index) => {
                let args = args.as_slice().get(index..).unwrap();
                CommandArgs::new(args.to_owned())
            }
            None => CommandArgs::new_empty(),
        };

        // Check the command arguments
        command.check(&args)?;

        let executor = ExternalCommandExecutor::new(cmd.to_owned(), command.clone(), args);
        Ok(Arc::new(Box::new(executor)))
    }
}

// EXEC command executer
pub struct ExternalCommandExecutor {
    name: String,
    command: ExternalCommandRef,
    args: CommandArgs,
}

impl ExternalCommandExecutor {
    pub fn new(name: String, command: ExternalCommandRef, args: CommandArgs) -> Self {
        Self {
            name,
            command,
            args,
        }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for ExternalCommandExecutor {
    async fn exec(&self, context: &Context) -> Result<CommandResult, String> {
        let args = CommandArg::evaluate_list(&self.args, context)
            .await
            .map_err(|e| {
                let msg = format!("Failed to evaluate command arguments: {}", e);
                error!("{}", msg);
                msg
            })?;

        // Execute the command with the provided arguments
        let ret = self
            .command
            .exec(context, &args, &self.args)
            .await
            .map_err(|e| {
                let msg = format!("Failed to execute external command: {}", e);
                error!("{}", msg);
                msg
            })?;

        info!(
            "Executed external command: {}, args: {:?}, result: {:?}",
            self.name, self.args, ret
        );

        Ok(ret)
    }
}
