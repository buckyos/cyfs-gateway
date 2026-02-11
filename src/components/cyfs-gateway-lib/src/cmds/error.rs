use clap::{Arg, Command};
use cyfs_process_chain::*;

pub struct ErrorResponse {
    name: String,
    cmd: Command,
}

impl ErrorResponse {
    pub fn new() -> Self {
        let cmd = Command::new("error")
            .about("Return an HTTP error response")
            .after_help(
                r#"
Examples:
    error 404
    error 503 "upstream unavailable"
                "#,
            )
            .arg(
                Arg::new("status")
                    .help("HTTP error status code, range 400-599")
                    .index(1)
                    .required(true),
            )
            .arg(
                Arg::new("message")
                    .help("Optional error message body")
                    .index(2)
                    .required(false),
            );

        Self {
            name: "error".to_string(),
            cmd,
        }
    }

    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    fn parse_status_code(status: &str) -> Result<u16, String> {
        let code = status
            .parse::<u16>()
            .map_err(|e| format!("invalid error status: {}, {}", status, e))?;
        if (400..=599).contains(&code) {
            Ok(code)
        } else {
            Err(format!(
                "invalid error status: {}, supported range is 400..=599",
                code
            ))
        }
    }
}

#[async_trait::async_trait]
impl ExternalCommand for ErrorResponse {
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
                let msg = format!("Invalid error command: {:?}, {}", args, e);
                error!("{}", msg);
                msg
            })?;

        let status = matches
            .get_one::<String>("status")
            .ok_or_else(|| "status is required".to_string())?;
        Self::parse_status_code(status)?;

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
            let msg = format!("Invalid error command: {:?}, {}", args, e);
            error!("{}", msg);
            msg
        })?;

        let status = matches
            .get_one::<String>("status")
            .ok_or_else(|| "status is required".to_string())?;
        let status = Self::parse_status_code(status)?;
        let message = matches.get_one::<String>("message").map(|s| s.to_string());

        let command = match message {
            Some(message) => format!(r#"error {} "{}""#, status, message),
            None => format!("error {}", status),
        };

        Ok(CommandResult::return_with_value(
            CommandControlLevel::Lib,
            command,
        ))
    }
}
