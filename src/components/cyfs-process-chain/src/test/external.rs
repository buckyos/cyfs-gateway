use crate::block::CommandArgs;
use crate::chain::Context;
use crate::cmd::*;
use crate::collection::{CollectionValue, NumberValue};
use clap::{Arg, Command};

pub struct AddCommand {
    name: String,
    cmd: Command,
}

impl AddCommand {
    pub fn new() -> Self {
        let name = "add".to_string();
        let cmd = Command::new(&name)
            .about("Add two numbers")
            .arg(Arg::new("a").help("First number").required(true).index(1))
            .arg(Arg::new("b").help("Second number").required(true).index(2));

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
        self.cmd
            .clone()
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
        if args.len() < 3 {
            let msg = format!(
                "Invalid add command args length: expected at least 3, got {}",
                args.len()
            );
            error!("{}", msg);
            return Err(msg);
        }

        let parse_number = |arg: &CollectionValue, index: usize| -> Result<f64, String> {
            match arg {
                CollectionValue::Number(number) => Ok(number.as_f64()),
                _ => {
                    let msg = format!(
                        "Invalid argument type at position {}: expected Number, got {:?}",
                        index, arg
                    );
                    error!("{}", msg);
                    Err(msg)
                }
            }
        };

        let a = parse_number(&args[1], 1)?;
        let b = parse_number(&args[2], 2)?;

        let result = a + b;
        let ret = if result.fract() == 0.0 {
            CommandResult::success_with_value(CollectionValue::Number(NumberValue::Int(
                result as i64,
            )))
        } else {
            CommandResult::success_with_value(CollectionValue::Number(NumberValue::Float(result)))
        };

        info!(
            "Executed add command: {}, args: {:?}, result: {:?}",
            self.cmd.get_name(),
            args,
            ret
        );

        Ok(ret)
    }
}
