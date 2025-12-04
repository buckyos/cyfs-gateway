use clap::{Arg, Command};
use cyfs_process_chain::*;

pub struct CallServer {
    name: String,
    cmd: Command,
}

impl CallServer {
    pub fn new() -> Self {
        let cmd = Command::new("call-server")
            .about("Call server with specified name to handle request")
            .after_help(
                r#"
Examples:
    call-server example-server
"#
            )
            .arg(
                Arg::new("server_name")
                    .help("Server name to call")
                    .index(1)
                    .required(true)
            );
        Self {
            name: "call-server".to_string(),
            cmd,
        }
    }

    pub fn name(&self) -> &str {
        self.name.as_str()
    }
}

#[async_trait::async_trait]
impl ExternalCommand for CallServer {
    fn help(&self, name: &str, help_type: CommandHelpType) -> String {
        assert_eq!(self.cmd.get_name(), name);
        command_help(help_type, &self.cmd)
    }

    fn check(&self, args: &CommandArgs) -> Result<(), String> {
        let matches = self.cmd
            .clone()
            .try_get_matches_from(args.as_str_list())
            .map_err(|e| {
                let msg = format!("Invalid server command: {:?}, {}", args, e);
                error!("{}", msg);
                msg
            })?;

        let servername = matches.get_one::<String>("server_name").map(|s| s.to_string());
        if servername.is_none() {
            return Err("server_name is required".to_string());
        }

        Ok(())
    }

    async fn exec(&self, _context: &Context, args: &[CollectionValue], _origin_args: &CommandArgs) -> Result<CommandResult, String> {
        let mut str_args = Vec::with_capacity(args.len());
        for arg in args.iter() {
            if !arg.is_string() {
                let msg = format!("Invalid argument type: expected string, got {:?}", arg);
                error!("{}", msg);
                return Err(msg);
            }
            str_args.push(arg.as_str().unwrap());
        }

        let matches = self.cmd
            .clone()
            .try_get_matches_from(&str_args)
            .map_err(|e| {
                let msg = format!("Invalid server command: {:?}, {}", args, e);
                error!("{}", msg);
                msg
            })?;

        let server_name = matches.get_one::<String>("server_name").map(|s| s.to_string());
        if server_name.is_none() {
            return Err("server_name is required".to_string());
        }

        Ok(CommandResult::return_with_value(CommandControlLevel::Lib,
                                            format!(r#"server {}"#, server_name.unwrap())))
    }
}
