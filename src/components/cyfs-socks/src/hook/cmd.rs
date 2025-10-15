use clap::{Arg, Command};
use cyfs_process_chain::*;

pub struct ResolveDNSCommand {
    name: String,
    cmd: Command,
}

impl ResolveDNSCommand {
    pub fn new() -> Self {
        let name = "resolve-dns".to_string();
        let cmd = Command::new(&name)
            .about("Resolve a domain name to an IP address")
            .after_help(
                r#"
Behavior:
  - Resolves the given domain name to its corresponding IP address(es).
  - Outputs the resolved IP addresses as a semicolon-separated string.
Examples:
    resolve-dns example.com;
    resolve-dns www.example.com;
"#,
            )
            .arg(
                Arg::new("domain")
                    .help("The domain name to resolve")
                    .required(true)
                    .index(1),
            );

        Self { cmd, name }
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

#[async_trait::async_trait]
impl ExternalCommand for ResolveDNSCommand {
    fn help(&self, name: &str, help_type: CommandHelpType) -> String {
        assert_eq!(self.cmd.get_name(), name);
        command_help(help_type, &self.cmd)
    }

    fn check(&self, args: &CommandArgs) -> Result<(), String> {
        self.cmd
            .clone()
            .try_get_matches_from(args.as_str_list())
            .map_err(|e| {
                let msg = format!("Invalid resolve-dns command: {:?}, {}", args, e);
                error!("{}", msg);
                msg
            })?;

        Ok(())
    }

    async fn exec(
        &self,
        _context: &Context,
        args: &[CollectionValue],
        _origin_args: &CommandArgs,
    ) -> Result<CommandResult, String> {
        let mut str_args = Vec::with_capacity(args.len());
        for arg in args {
            if !arg.is_string() {
                let msg = format!("Invalid argument type: expected string, got {:?}", arg);
                error!("{}", msg);
                return Err(msg);
            }

            str_args.push(arg.as_str().unwrap());
        }

        let matches = self
            .cmd
            .clone()
            .try_get_matches_from(&str_args)
            .map_err(|e| {
                let msg = format!("Invalid resolve-dns command: {:?}, {}", args, e);
                error!("{}", msg);
                msg
            })?;

        let domain_index = matches.index_of("domain").ok_or_else(|| {
            let msg = "Domain argument is required".to_string();
            error!("{}", msg);
            msg
        })?;

        // Domain arg must be a string
        if !args[domain_index].is_string() {
            let msg = format!(
                "Domain argument must be a string, got: {:?}",
                args[domain_index]
            );
            error!("{}", msg);
            return Err(msg);
        }

        let domain = matches.get_one::<String>("domain").unwrap();

        match tokio::net::lookup_host((domain.to_owned(), 0)).await {
            Ok(addr) => {
                let ips: Vec<String> = addr.map(|addr| addr.ip().to_string()).collect();
                let ip_string = ips.join(";");

                Ok(CommandResult::success_with_value(ip_string))
            }
            Err(e) => {
                let msg = format!("DNS resolution failed for '{}': {}", domain, e);
                warn!("{}", msg);
                Ok(CommandResult::error_with_value(msg))
            }
        }
    }
}
