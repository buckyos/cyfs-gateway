use super::cmd::*;
use crate::block::CommandArgs;
use crate::chain::Context;
use crate::collection::CollectionValue;
use clap::{Arg, ArgAction, Command};
use globset::{GlobBuilder, GlobMatcher};
use regex::{Regex, RegexBuilder};
use std::sync::Arc;

// Match command use glob, like: match REQ_HEADER.host "*.local"

pub struct MatchCommandParser {
    cmd: Command,
}

impl MatchCommandParser {
    pub fn new() -> Self {
        let cmd = Command::new("match")
            .about("Match a value using glob pattern.")
            .override_usage("match <value> <pattern>")
            .after_help(
                r#"
Arguments:
  <value>     The string or variable to match.
  <pattern>   A glob pattern (e.g. *.domain.com, home.*.site.org)

Options:
  --no-ignore-case   Perform case-sensitive matching (default is case-insensitive)

Behavior:
  - Uses shell-style glob pattern matching.
  - Case-insensitive by default.
  - Pattern must follow shell glob syntax:
      *  — matches any number of characters
      ?  — matches a single character
      [...] — character class

Examples:
  match $REQ_HEADER.host "*.local"
  match username "admin*"
"#,
            )
            .arg(
                Arg::new("no_ignore_case")
                    .long("no-ignore-case")
                    .action(ArgAction::SetTrue)
                    .help("Perform case-sensitive matching (default is case-insensitive)"),
            )
            .arg(
                Arg::new("value")
                    .required(true)
                    .help("The input string or variable to match"),
            )
            .arg(
                Arg::new("pattern")
                    .required(true)
                    .help("The glob pattern to match against"),
            );

        Self { cmd }
    }
}

impl CommandParser for MatchCommandParser {
    fn help(&self, _name: &str, help_type: CommandHelpType) -> String {
        command_help(help_type, &self.cmd)
    }

    fn check(&self, args: &CommandArgs) -> Result<(), String> {
        self.cmd
            .clone()
            .try_get_matches_from(args.as_str_list())
            .map_err(|e| {
                let msg = format!("Invalid match command: {:?}, {}", args, e);
                error!("{}", msg);
                msg
            })?;

        Ok(())
    }

    fn parse(
        &self,
        args: Vec<String>,
        _origin_args: &CommandArgs,
    ) -> Result<CommandExecutorRef, String> {
        let matches = self.cmd.clone().try_get_matches_from(&args).map_err(|e| {
            let msg = format!("Invalid match command: {:?}, {}", args, e);
            error!("{}", msg);
            msg
        })?;

        let value = matches
            .get_one::<String>("value")
            .expect("Value argument is required");

        let pattern_str = matches
            .get_one::<String>("pattern")
            .expect("Pattern argument is required");

        let no_ignore_case = matches.get_flag("no_ignore_case");
        let pattern = GlobBuilder::new(pattern_str)
            .case_insensitive(!no_ignore_case)
            .build()
            .map_err(|e| {
                let msg = format!("Invalid glob pattern: {}: {}", args[1], e);
                error!("{}", msg);
                msg
            })?
            .compile_matcher();

        let cmd = MatchCommandExecutor {
            value: value.clone(),
            pattern,
        };
        Ok(Arc::new(Box::new(cmd)))
    }
}

// Match command executer
pub struct MatchCommandExecutor {
    pub value: String,
    pub pattern: GlobMatcher,
}

#[async_trait::async_trait]
impl CommandExecutor for MatchCommandExecutor {
    async fn exec(&self, _context: &Context) -> Result<CommandResult, String> {
        if self.pattern.is_match(&self.value) {
            Ok(CommandResult::success())
        } else {
            Ok(CommandResult::error())
        }
    }
}

// Match regex command, like: match-regex REQ_HEADER.host "^(.*)\.local$"
// If capture is provided, it will capture the matched groups into the environment with name `name[i]`
/*
* match-reg some_input "^pattern$"
* match-reg --capture name some_input "^pattern$"
*/
pub struct MatchRegexCommandParser {
    cmd: Command,
}

impl MatchRegexCommandParser {
    pub fn new() -> Self {
        let cmd = Command::new("match-regex")
            .about("Match a value against a regular expression. Supports optional named capture.")
            .after_help(
                r#"
Arguments:
  <value>      The string to match.
  <pattern>    The regular expression to match against.

Options:
  --capture name   Capture groups into environment variables like name[0], name[1], ...
  --no-ignore-case   Perform case-sensitive matching (default is case-insensitive)

Behavior:
  - Uses Rust-style regular expressions.
  - If the pattern matches, the command returns success, otherwise it returns error.
  - If --capture is provided, matched groups are saved into environment as:
      name[0] is the first capture group,
      name[1] is the second capture group, etc.
  - Default behavior is case-insensitive matching.

Examples:
  match-regex $REQ_HEADER.host "^(.*)\.local$"
  match-regex --capture parts $REQ_HEADER.host "^(.+)\.(local|dev)$"
"#,
            )
            .arg(
                Arg::new("no_ignore_case")
                    .long("no-ignore-case")
                    .action(ArgAction::SetTrue)
                    .help("Perform case-sensitive matching (default is case-insensitive)"),
            )
            .arg(
                Arg::new("capture")
                    .long("capture")
                    .value_name("name")
                    .help("Name to use when storing regex captures into the environment"),
            )
            .arg(
                Arg::new("value")
                    .required(true)
                    .help("The input string or variable to match"),
            )
            .arg(
                Arg::new("pattern")
                    .required(true)
                    .help("The regular expression pattern"),
            );

        Self { cmd }
    }
}

impl CommandParser for MatchRegexCommandParser {
    fn help(&self, _name: &str, help_type: CommandHelpType) -> String {
        command_help(help_type, &self.cmd)
    }

    fn check(&self, args: &CommandArgs) -> Result<(), String> {
        self.cmd
            .clone()
            .try_get_matches_from(args.as_str_list())
            .map_err(|e| {
                let msg = format!("Invalid match-regex command: {:?}, {}", args, e);
                error!("{}", msg);
                msg
            })?;

        Ok(())
    }

    fn parse(
        &self,
        args: Vec<String>,
        _origin_args: &CommandArgs,
    ) -> Result<CommandExecutorRef, String> {
        let matches = self.cmd.clone().try_get_matches_from(&args).map_err(|e| {
            let msg = format!("Invalid match-regex command: {:?}, {}", args, e);
            error!("{}", msg);
            msg
        })?;

        let capture = matches.get_one::<String>("capture").cloned();
        let value = matches
            .get_one::<String>("value")
            .expect("Value argument is required")
            .to_owned();

        let pattern_str = matches
            .get_one::<String>("pattern")
            .expect("Pattern argument is required");

        let no_ignore_case = matches.get_flag("no_ignore_case");
        let pattern = RegexBuilder::new(pattern_str)
            .case_insensitive(!no_ignore_case)
            .build()
            .map_err(|e| {
                let msg = format!("Invalid regex pattern: {}: {}", args[1], e);
                error!("{}", msg);
                msg
            })?;

        let cmd = MatchRegexCommandExecutor {
            capture,
            value,
            pattern,
        };

        Ok(Arc::new(Box::new(cmd)))
    }
}

// Match regex command executer
pub struct MatchRegexCommandExecutor {
    pub capture: Option<String>, // Optional capture group name
    pub value: String,
    pub pattern: Regex,
}

#[async_trait::async_trait]
impl CommandExecutor for MatchRegexCommandExecutor {
    async fn exec(&self, context: &Context) -> Result<CommandResult, String> {
        // Match the value
        if let Some(caps) = self.pattern.captures(&self.value) {
            if let Some(name) = &self.capture {
                for (i, cap) in caps.iter().enumerate() {
                    if let Some(m) = cap {
                        // TODO: Add env level support, such as --capture export/local name
                        context
                            .env()
                            .set(
                                format!("{}[{}]", name, i).as_str(),
                                CollectionValue::String(m.as_str().to_owned()),
                                None,
                            )
                            .await?;
                    }
                }
            }

            Ok(CommandResult::success())
        } else {
            Ok(CommandResult::error())
        }
    }
}

// EQ command, like: eq REQ_HEADER.host "localhost"; eq --ignore-case REQ_HEADER.host "LOCALHOST"
pub struct EQCommandParser {
    cmd: Command,
}

impl EQCommandParser {
    pub fn new() -> Self {
        let cmd = Command::new("eq")
        .about("Compare two strings for equality.")
        .after_help(
            r#"
Compare two strings for equality.

Arguments:
  <value1>        First value to compare
  <value2>        Second value to compare

Options:
  --ignore-case   Perform case-insensitive comparison

By default, the comparison is case-sensitive. Use --ignore-case to enable case-insensitive comparison.

Examples:
  eq "host" "host"
  eq --ignore-case "Host" "HOST"
"#,
        )
        .arg(
            Arg::new("ignore_case")
                .long("ignore-case")
                .short('i')
                .action(ArgAction::SetTrue)
                .help("Enable case-insensitive comparison"),
        )
        .arg(
            Arg::new("value1")
                .required(true)
                .help("The first value to compare"),
        )
        .arg(
            Arg::new("value2")
                .required(true)
                .help("The second value to compare"),
        );

        Self { cmd }
    }
}

impl CommandParser for EQCommandParser {
    fn help(&self, _name: &str, help_type: CommandHelpType) -> String {
        command_help(help_type, &self.cmd)
    }

    fn check(&self, args: &CommandArgs) -> Result<(), String> {
        let arg_list = args.as_str_list();
        self.cmd
            .clone()
            .try_get_matches_from(&arg_list)
            .map_err(|e| {
                let msg = format!("Invalid eq command: {:?}, {}", args, e);
                error!("{}", msg);
                msg
            })?;

        Ok(())
    }

    fn parse(
        &self,
        args: Vec<String>,
        _origin_args: &CommandArgs,
    ) -> Result<CommandExecutorRef, String> {
        let matches = self.cmd.clone().try_get_matches_from(&args).map_err(|e| {
            let msg = format!("Invalid eq command: {:?}, {}", args, e);
            error!("{}", msg);
            msg
        })?;

        let ignore_case = matches.get_flag("ignore_case");
        let value1 = matches
            .get_one::<String>("value1")
            .expect("Value1 argument is required")
            .to_owned();
        let value2 = matches
            .get_one::<String>("value2")
            .expect("Value2 argument is required")
            .to_owned();

        let cmd = EQCommandExecutor {
            ignore_case,
            value1,
            value2,
        };

        Ok(Arc::new(Box::new(cmd)))
    }
}

// EQ command executer
pub struct EQCommandExecutor {
    pub ignore_case: bool, // Whether to ignore case, default is false
    pub value1: String,
    pub value2: String,
}

#[async_trait::async_trait]
impl CommandExecutor for EQCommandExecutor {
    async fn exec(&self, _context: &Context) -> Result<CommandResult, String> {
        let is_eq = if self.ignore_case {
            self.value1.eq_ignore_ascii_case(&self.value2)
        } else {
            self.value1 == self.value2
        };

        if is_eq {
            Ok(CommandResult::success())
        } else {
            Ok(CommandResult::error())
        }
    }
}

// Range command, like: range <var> <range_begin> <range_end>
pub struct RangeCommandParser {
    cmd: Command,
}

impl RangeCommandParser {
    pub fn new() -> Self {
        let cmd = Command::new("range")
            .about("Check if a variable's value is within a numeric range.")
            .override_usage("range <value> <begin> <end>")
            .after_help(
                r#"
Arguments:
  <value>     The variable or value to test
  <begin>     Inclusive lower bound.
  <end>       Inclusive upper bound.

Behavior:
  - All values are parsed as integers or floats automatically.
  - Mixed types (e.g., int + float) are supported (converted to float).
  - Returns true if value ∈ [begin, end].

Examples:
  range 5 1 10
  range 3.14 0.0 3.15
  range $REQ.port 1000 2000
"#,
            )
            .arg(
                Arg::new("value")
                    .required(true)
                    .help("The variable or value to test"),
            )
            .arg(
                Arg::new("begin")
                    .required(true)
                    .help("Range start (inclusive)"),
            )
            .arg(Arg::new("end").required(true).help("Range end (inclusive)"));

        Self { cmd }
    }
}

impl CommandParser for RangeCommandParser {
    fn help(&self, _name: &str, help_type: CommandHelpType) -> String {
        command_help(help_type, &self.cmd)
    }

    fn check(&self, args: &CommandArgs) -> Result<(), String> {
        let matches = self
            .cmd
            .clone()
            .try_get_matches_from(args.as_str_list())
            .map_err(|e| {
                let msg = format!("Invalid range command: {:?}, {}", args, e);
                error!("{}", msg);
                msg
            })?;

        // Check begin and end are valid numbers
        for arg in ["value", "begin", "end"] {
            let index = matches.index_of(arg).unwrap();
            if args[index].is_literal() {
                if let Err(e) = args[index].as_literal_str().unwrap().parse::<f64>() {
                    let msg = format!("Invalid range command {}: {:?}: {}", arg, args[index], e);
                    error!("{}", msg);
                    return Err(msg);
                }
            }
        }

        Ok(())
    }

    fn parse(
        &self,
        args: Vec<String>,
        _origin_args: &CommandArgs,
    ) -> Result<CommandExecutorRef, String> {
        let matches = self.cmd.clone().try_get_matches_from(&args).map_err(|e| {
            let msg = format!("Invalid range command: {:?}, {}", args, e);
            error!("{}", msg);
            msg
        })?;

        let value = matches
            .get_one::<String>("value")
            .expect("Value argument is required");

        let value = value.parse::<f64>().map_err(|e| {
            let msg = format!("Invalid range value: {}: {}", args[1], e);
            error!("{}", msg);
            msg
        })?;

        // Get the range bounds
        let begin = matches
            .get_one::<String>("begin")
            .expect("Begin argument is required");
        let min = begin.parse::<f64>().map_err(|e| {
            let msg = format!("Invalid range min value: {}: {}", args[1], e);
            error!("{}", msg);
            msg
        })?;

        let end = matches
            .get_one::<String>("end")
            .expect("End argument is required");
        let max = end.parse::<f64>().map_err(|e| {
            let msg = format!("Invalid range max value: {}: {}", args[2], e);
            error!("{}", msg);
            msg
        })?;

        let cmd = RangeCommandExecutor { value, min, max };
        Ok(Arc::new(Box::new(cmd)))
    }
}

// Range command executer
pub struct RangeCommandExecutor {
    pub value: f64,
    pub min: f64,
    pub max: f64,
}

#[async_trait::async_trait]
impl CommandExecutor for RangeCommandExecutor {
    async fn exec(&self, _context: &Context) -> Result<CommandResult, String> {
        if self.value >= self.min && self.value <= self.max {
            Ok(CommandResult::success())
        } else {
            Ok(CommandResult::error())
        }
    }
}
