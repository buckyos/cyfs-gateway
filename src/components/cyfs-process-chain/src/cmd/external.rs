use super::cmd::*;
use crate::block::CommandArgs;
use crate::chain::Context;
use crate::collection::CollectionValue;
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

pub struct ExternalCommandFactory {
    commands: Arc<Mutex<HashMap<String, ExternalCommandRef>>>,
}

impl ExternalCommandFactory {
    pub fn new() -> Self {
        Self {
            commands: Arc::new(Mutex::new(HashMap::new())),
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

    pub fn get_command(&self, name: &str) -> Option<ExternalCommandRef> {
        let commands = self.commands.lock().unwrap();
        commands.get(name).cloned()
    }

    pub fn get_command_list(&self) -> Vec<String> {
        let commands = self.commands.lock().unwrap();
        commands.keys().cloned().collect()
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

    fn check(&self, args: &CommandArgs) -> Result<(), String> {
        let matches = self
            .cmd
            .clone()
            .try_get_matches_from(args.as_str_list())
            .map_err(|e| {
                let msg = format!("Invalid external command: {:?}, {}", args, e);
                error!("{}", msg);
                msg
            })?;

        let cmd = matches.get_one::<String>("command").unwrap();
        let command = EXTERNAL_COMMAND_FACTORY.get_command(cmd).ok_or_else(|| {
            let msg = format!("External command '{}' not found", cmd);
            error!("{}", msg);
            msg
        })?;

        let command_args = match matches.index_of("command") {
            Some(index) => {
                let args = args.as_slice().get(index..).unwrap();
                CommandArgs::new(args.to_owned())
            }
            None => CommandArgs::new_empty(),
        };

        command.check(&command_args)?;

        Ok(())
    }

    fn parse_origin(
        &self,
        args: Vec<CollectionValue>,
        origin_args: &CommandArgs,
    ) -> Result<CommandExecutorRef, String> {
        let str_args = args
            .iter()
            .map(|value| value.to_string())
            .collect::<Vec<String>>();

        let matches = self
            .cmd
            .clone()
            .try_get_matches_from(&str_args)
            .map_err(|e| {
                let msg = format!("Invalid external command: {:?}, {}", origin_args, e);
                error!("{}", msg);
                msg
            })?;

        let cmd_index = matches.index_of("command").unwrap();
        if !args[cmd_index].is_string() {
            let msg = format!(
                "Command must be a string, got: {:?}",
                args[cmd_index].get_type()
            );
            error!("{}", msg);
            return Err(msg);
        }

        let cmd = matches.get_one::<String>("command").unwrap();
        let command = EXTERNAL_COMMAND_FACTORY.get_command(cmd).ok_or_else(|| {
            let msg = format!("External command '{}' not found", cmd);
            error!("{}", msg);
            msg
        })?;

        let (args, origin_args) = match matches.index_of("command") {
            Some(index) => {
                let args = args.as_slice().get(index..).unwrap();
                let origin_args = origin_args.as_slice().get(index..).unwrap();
                (args.to_owned(), CommandArgs::new(origin_args.to_owned()))
            }
            None => (vec![], CommandArgs::new_empty()),
        };

        let executor =
            ExternalCommandExecutor::new(cmd.clone(), command.clone(), args, origin_args);
        Ok(Arc::new(Box::new(executor)))
    }
}

// EXEC command executer
pub struct ExternalCommandExecutor {
    name: String,
    command: ExternalCommandRef,
    args: Vec<CollectionValue>,
    origin_args: CommandArgs,
}

impl ExternalCommandExecutor {
    pub fn new(
        name: String,
        command: ExternalCommandRef,
        args: Vec<CollectionValue>,
        origin_args: CommandArgs,
    ) -> Self {
        Self {
            name,
            command,
            args,
            origin_args,
        }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for ExternalCommandExecutor {
    async fn exec(&self, context: &Context) -> Result<CommandResult, String> {
        // Execute the command with the provided arguments
        let ret = self
            .command
            .exec(context, &self.args, &self.origin_args)
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
