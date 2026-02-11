use clap::{Arg, Command};
use cyfs_process_chain::*;

pub struct Redirect {
    name: String,
    cmd: Command,
}

impl Redirect {
    pub fn new() -> Self {
        let cmd = Command::new("redirect")
            .about("Return an HTTP redirect response")
            .after_help(
                r#"
Examples:
    redirect https://example.com
    redirect https://example.com/login 301
                "#,
            )
            .arg(
                Arg::new("location")
                    .help("Redirect location URL")
                    .index(1)
                    .required(true),
            )
            .arg(
                Arg::new("status")
                    .help("Redirect status code: 301, 302, 303, 307, 308")
                    .index(2)
                    .required(false),
            );
        Self {
            name: "redirect".to_string(),
            cmd,
        }
    }

    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    fn parse_status_code(status: Option<&String>) -> Result<Option<u16>, String> {
        let status = match status {
            Some(status) => status,
            None => return Ok(None),
        };
        let code = status
            .parse::<u16>()
            .map_err(|e| format!("invalid redirect status: {}, {}", status, e))?;
        match code {
            301 | 302 | 303 | 307 | 308 => Ok(Some(code)),
            _ => Err(format!(
                "invalid redirect status: {}, supported values are 301, 302, 303, 307, 308",
                code
            )),
        }
    }
}

#[async_trait::async_trait]
impl ExternalCommand for Redirect {
    fn help(&self, name: &str, help_type: CommandHelpType) -> String {
        assert_eq!(self.cmd.get_name(), name);
        command_help(help_type, &self.cmd)
    }

    fn check(&self, args: &CommandArgs) -> Result<(), String> {
        let matches = self
            .cmd
            .clone()
            .try_get_matches_from(args.as_str_list())
            .map_err(|e| {
                let msg = format!("Invalid redirect command: {:?}, {}", args, e);
                error!("{}", msg);
                msg
            })?;

        let location = matches.get_one::<String>("location").map(|s| s.to_string());
        if location.is_none() {
            return Err("location is required".to_string());
        }

        Self::parse_status_code(matches.get_one::<String>("status"))?;
        Ok(())
    }

    async fn exec(
        &self,
        _context: &Context,
        args: &[CollectionValue],
        _origin_args: &CommandArgs,
    ) -> Result<CommandResult, String> {
        let mut str_args = Vec::with_capacity(args.len());
        for arg in args.iter() {
            if !arg.is_string() {
                let msg = format!("Invalid argument type: expected string, got {:?}", arg);
                error!("{}", msg);
                return Err(msg);
            }
            str_args.push(arg.as_str().unwrap());
        }

        let matches = self.cmd.clone().try_get_matches_from(&str_args).map_err(|e| {
            let msg = format!("Invalid redirect command: {:?}, {}", args, e);
            error!("{}", msg);
            msg
        })?;

        let location = matches.get_one::<String>("location").map(|s| s.to_string());
        if location.is_none() {
            return Err("location is required".to_string());
        }

        let status = Self::parse_status_code(matches.get_one::<String>("status"))?;
        let location = location.unwrap();
        let command = match status {
            Some(status) => format!(r#"redirect "{}" {}"#, location, status),
            None => format!(r#"redirect "{}""#, location),
        };

        Ok(CommandResult::return_with_value(
            CommandControlLevel::Lib,
            command,
        ))
    }
}
