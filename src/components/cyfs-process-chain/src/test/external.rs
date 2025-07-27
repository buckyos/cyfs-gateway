
use crate::cmd::*;
use clap::{Arg, Command};
use crate::collection::CollectionValue;
use crate::chain::Context;
use crate::block::CommandArgs;

pub struct AddCommand {
    name: String,
    cmd: Command,
}


impl AddCommand {
    pub fn new() -> Self {
        let name = "add".to_string();
        let cmd = Command::new(&name)
            .about("Add two numbers")
            .arg(
                Arg::new("a")
                    .help("First number")
                    .required(true)
                    .index(1),
            )
            .arg(
                Arg::new("b")
                    .help("Second number")
                    .required(true)
                    .index(2),
            );

        Self { cmd, name }
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

#[async_trait::async_trait]
impl ExternalCommand for AddCommand {
    fn help(&self, name: &str, help_type: CommandHelpType) -> String {
        assert_eq!(self.cmd.get_name(), name);
        command_help(help_type, &self.cmd)
    }

    fn check(&self, args: &CommandArgs) -> Result<(), String> {
        self.cmd.clone()
            .try_get_matches_from(args.as_str_list())
            .map_err(|e| {
                let msg = format!("Invalid add command: {:?}, {}", args, e);
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
        // All args should be string, then covert to f64
        let mut str_args = Vec::with_capacity(args.len());
        for arg in args {
            if !arg.is_string() {
                let msg = format!("Invalid argument type: expected string, got {:?}", arg);
                error!("{}", msg);
                return Err(msg);
            }

            str_args.push(arg.as_str().unwrap());
        }


        let matches = self.cmd.clone().try_get_matches_from(&str_args).map_err(|e| {
            let msg = format!("Invalid add command: {:?}, {}", str_args, e);
            error!("{}", msg);
            msg
        })?;

        let a = matches.get_one::<String>("a").unwrap().parse::<f64>().map_err(|e| {
            let msg = format!("Invalid first number: {}, error: {}", matches.get_one::<String>("a").unwrap(), e);
            error!("{}", msg);
            msg
        })?;

        let b = matches.get_one::<String>("b").unwrap().parse::<f64>().map_err(|e| {
            let msg = format!("Invalid second number: {}, error: {}", matches.get_one::<String>("b").unwrap(), e);
            error!("{}", msg);
            msg
        })?;
        
        let result = a + b;
        let ret = CommandResult::success_with_value(result.to_string());

        info!(
            "Executed add command: {}, args: {:?}, result: {:?}",
            self.cmd.get_name(),
            str_args,
            ret
        );

        Ok(ret)
    }
}
