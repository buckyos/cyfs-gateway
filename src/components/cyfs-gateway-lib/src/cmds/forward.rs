use clap::{Arg, Command};
use cyfs_process_chain::*;

pub struct Forward {
    name: String,
    cmd: Command,
}

impl Forward {
    pub fn new() -> Self {
        let cmd = Command::new("forward")
            .about("Set forward destination URL")
            .after_help(
                r#"
Examples:
    forward tcp:///127.0.0.1:80
    forward rtcp://remote_server/path
                "#
            )
            .arg(
                Arg::new("dest_url")
                    .help("Destination URL to forward to")
                    .index(1)
                    .required(true)
            );
        Self {
            name: "forward".to_string(),
            cmd,
        }
    }

    pub fn name(&self) -> &str {
        self.name.as_str()
    }
}

#[async_trait::async_trait]
impl ExternalCommand for Forward {
    fn help(&self, name: &str, help_type: CommandHelpType) -> String {
        assert_eq!(self.cmd.get_name(), name);
        command_help(help_type, &self.cmd)
    }

    fn check(&self, args: &CommandArgs) -> Result<(), String> {
        let matches = self.cmd
            .clone()
            .try_get_matches_from(args.as_str_list())
            .map_err(|e| {
                let msg = format!("Invalid forward command: {:?}, {}", args, e);
                error!("{}", msg);
                msg
            })?;

        let dest_url = matches.get_one::<String>("dest_url").map(|s| s.to_string());
        if dest_url.is_none() {
            return Err("dest_url is required".to_string());
        }

        // Check if dest_url is a valid URL
        if let Some(url) = dest_url {
            if url::Url::parse(&url).is_err() {
                return Err(format!("Invalid URL format: {}", url));
            }
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
                let msg = format!("Invalid forward command: {:?}, {}", args, e);
                error!("{}", msg);
                msg
            })?;

        let dest_url = matches.get_one::<String>("dest_url").map(|s| s.to_string());
        if dest_url.is_none() {
            return Err("dest_url is required".to_string());
        }

        Ok(CommandResult::return_with_value(CommandControlLevel::Chain,
                                            format!(r#"forward {}"#, dest_url.unwrap())))
    }
}
