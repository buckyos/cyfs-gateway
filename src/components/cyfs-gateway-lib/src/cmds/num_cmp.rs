use clap::{Arg, Command};
use cyfs_process_chain::{
    CollectionValue, CommandArgs, CommandHelpType, CommandResult, Context, ExternalCommand,
    command_help,
};

pub struct NumCmp {
    name: String,
    cmd: Command,
}

impl NumCmp {
    pub fn new() -> Self {
        let cmd = Command::new("num-cmp")
            .about("Compare two numbers (eq/gt/lt/ge/le)")
            .after_help(
                r#"
Examples:
    num-cmp 10 gt 5
    num-cmp 3.14 eq 3.14
    num-cmp 2 < 7
    num-cmp 10 ge 10
    num-cmp 5 <= 7

Operators:
    eq or ==     equal
    gt or >      greater than
    lt or <      less than
    ge or >=     greater than or equal
    le or <=     less than or equal
                "#,
            )
            .arg(Arg::new("left").required(true).help("Left number"))
            .arg(
                Arg::new("op")
                    .required(true)
                    .help("Operator: eq|gt|lt|ge|le|==|>|<|>=|<="),
            )
            .arg(Arg::new("right").required(true).help("Right number"));

        Self {
            name: "num-cmp".to_string(),
            cmd,
        }
    }

    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    fn parse_number(value: &str, field: &str) -> Result<f64, String> {
        let num = value
            .parse::<f64>()
            .map_err(|e| format!("invalid {} number '{}': {}", field, value, e))?;
        if !num.is_finite() {
            return Err(format!("invalid {} number '{}': must be finite", field, value));
        }
        Ok(num)
    }

    fn eval(op: &str, left: f64, right: f64) -> Result<bool, String> {
        match op {
            "eq" | "==" => Ok(left == right),
            "gt" | ">" => Ok(left > right),
            "lt" | "<" => Ok(left < right),
            "ge" | ">=" => Ok(left >= right),
            "le" | "<=" => Ok(left <= right),
            _ => Err(format!(
                "invalid operator '{}', expected eq|gt|lt|ge|le|==|>|<|>=|<=",
                op
            )),
        }
    }

    fn parse_and_eval(matches: &clap::ArgMatches) -> Result<bool, String> {
        let left = matches
            .get_one::<String>("left")
            .ok_or_else(|| "left is required".to_string())?;
        let op = matches
            .get_one::<String>("op")
            .ok_or_else(|| "op is required".to_string())?;
        let right = matches
            .get_one::<String>("right")
            .ok_or_else(|| "right is required".to_string())?;

        let left = Self::parse_number(left, "left")?;
        let right = Self::parse_number(right, "right")?;
        Self::eval(op.trim(), left, right)
    }
}

#[async_trait::async_trait]
impl ExternalCommand for NumCmp {
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
                let msg = format!("Invalid num-cmp command: {:?}, {}", args, e);
                error!("{}", msg);
                msg
            })?;

        let _ = Self::parse_and_eval(&matches)?;
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

        let matches = self.cmd.clone().try_get_matches_from(&str_args).map_err(|e| {
            let msg = format!("Invalid num-cmp command: {:?}, {}", args, e);
            error!("{}", msg);
            msg
        })?;

        let result = Self::parse_and_eval(&matches)?;
        if result {
            Ok(CommandResult::success_with_value("true"))
        } else {
            Ok(CommandResult::error_with_value("false"))
        }
    }
}
