use super::cmd::*;
use crate::block::{CommandArgs, CommandArg};
use crate::chain::{Context, ParserContext};
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
    fn group(&self) -> CommandGroup {
        CommandGroup::Match
    }

    fn help(&self, _name: &str, help_type: CommandHelpType) -> String {
        command_help(help_type, &self.cmd)
    }


    fn parse(
        &self,
        _context: &ParserContext,
        str_args: Vec<&str>,
        args: &CommandArgs,
    ) -> Result<CommandExecutorRef, String> {
        let matches = self.cmd.clone().try_get_matches_from(&str_args).map_err(|e| {
            let msg = format!("Invalid match command: {:?}, {}", str_args, e);
            error!("{}", msg);
            msg
        })?;

        let value_index = matches.index_of("value").ok_or_else(|| {
            let msg = "Value argument is required for match command".to_string();
            error!("{}", msg);
            msg
        })?;
        let value = args[value_index].clone();

        let pattern_index = matches.index_of("pattern").ok_or_else(|| {
            let msg = "Pattern argument is required for match command".to_string();
            error!("{}", msg);
            msg
        })?;

        let pattern_str = args[pattern_index]
            .as_literal_str()
            .ok_or_else(|| {
                let msg = format!("Pattern argument must be a literal string: {:?}", args[pattern_index]);
                error!("{}", msg);
                msg
            })?;

        let no_ignore_case = matches.get_flag("no_ignore_case");
        let pattern = GlobBuilder::new(pattern_str)
            .case_insensitive(!no_ignore_case)
            .build()
            .map_err(|e| {
                let msg = format!("Invalid glob pattern: {}: {}", pattern_str, e);
                error!("{}", msg);
                msg
            })?
            .compile_matcher();

        let cmd = MatchCommandExecutor::new(value, pattern);
        Ok(Arc::new(Box::new(cmd)))
    }
}

// Match command executer
pub struct MatchCommandExecutor {
    pub value: CommandArg,
    pub pattern: GlobMatcher,
}

impl MatchCommandExecutor {
    pub fn new(value: CommandArg, pattern: GlobMatcher) -> Self {
        Self { value, pattern }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for MatchCommandExecutor {
    async fn exec(&self, context: &Context) -> Result<CommandResult, String> {
        // First evaluate the value
        let value = self.value.evaluate_string(context).await?;

        if self.pattern.is_match(&value) {
            Ok(CommandResult::success_with_value("true"))
        } else {
            Ok(CommandResult::error_with_value("false"))
        }
    }
}

// Match regex command, like: match-reg REQ_HEADER.host "^(.*)\.local$"
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
        let cmd = Command::new("match-reg")
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
  match-reg $REQ_HEADER.host "^(.*)\.local$"
  match-reg --capture parts $REQ_HEADER.host "^(.+)\.(local|dev)$"
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
    fn group(&self) -> CommandGroup {
        CommandGroup::Match
    }

    fn help(&self, _name: &str, help_type: CommandHelpType) -> String {
        command_help(help_type, &self.cmd)
    }

    fn parse(
        &self,
        _context: &ParserContext,
        str_args: Vec<&str>,
        args: &CommandArgs,
    ) -> Result<CommandExecutorRef, String> {
        let matches = self.cmd.clone().try_get_matches_from(&str_args).map_err(|e| {
            let msg = format!("Invalid match-reg command: {:?}, {}", str_args, e);
            error!("{}", msg);
            msg
        })?;

        let capture = match matches.index_of("capture") {
            Some(index) => {
                let name = args[index].as_literal_str().ok_or_else(|| {
                    let msg = format!("Capture name must be a literal string: {:?}", args[index]);
                    error!("{}", msg);
                    msg
                })?;
                Some(name.to_string())
            }
            None => None,
        };

        let value_index = matches.index_of("value").ok_or_else(|| {
            let msg = "Value argument is required for match-reg command".to_string();
            error!("{}", msg);
            msg
        })?;
        let value = args[value_index].clone();

        let pattern_index = matches.index_of("pattern").ok_or_else(|| {
            let msg = "Pattern argument is required for match-reg command".to_string();
            error!("{}", msg);
            msg
        })?;
        let pattern_str = args[pattern_index]
            .as_literal_str()
            .ok_or_else(|| {
                let msg = format!("Pattern argument must be a literal string: {:?}", args[pattern_index]);
                error!("{}", msg);
                msg
            })?;

        let no_ignore_case = matches.get_flag("no_ignore_case");
        let pattern = RegexBuilder::new(pattern_str)
            .case_insensitive(!no_ignore_case)
            .build()
            .map_err(|e| {
                let msg = format!("Invalid regex pattern: {}: {}", pattern_str, e);
                error!("{}", msg);
                msg
            })?;

        let cmd = MatchRegexCommandExecutor::new(value, pattern, capture);

        Ok(Arc::new(Box::new(cmd)))
    }
}

// Match regex command executer
pub struct MatchRegexCommandExecutor {
    pub capture: Option<String>, // Optional capture group name
    pub value: CommandArg,
    pub pattern: Regex,
}

impl MatchRegexCommandExecutor {
    pub fn new(value: CommandArg, pattern: Regex, capture: Option<String>) -> Self {
        Self {
            value,
            pattern,
            capture,
        }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for MatchRegexCommandExecutor {
    async fn exec(&self, context: &Context) -> Result<CommandResult, String> {
        // First evaluate the value
        let value = self.value.evaluate_string(context).await?;

        // Match the value
        if let Some(caps) = self.pattern.captures(&value) {
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

            Ok(CommandResult::success_with_value("true"))
        } else {
            Ok(CommandResult::error_with_value("false"))
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
    fn group(&self) -> CommandGroup {
        CommandGroup::Match
    }

    fn help(&self, _name: &str, help_type: CommandHelpType) -> String {
        command_help(help_type, &self.cmd)
    }

    fn parse(
        &self,
        _context: &ParserContext,
        str_args: Vec<&str>,
        args: &CommandArgs,
    ) -> Result<CommandExecutorRef, String> {
        let matches = self.cmd.clone().try_get_matches_from(&str_args).map_err(|e| {
            let msg = format!("Invalid eq command: {:?}, {}", str_args, e);
            error!("{}", msg);
            msg
        })?;

        let ignore_case = matches.get_flag("ignore_case");

        let value_index1 = matches.index_of("value1").ok_or_else(|| {
            let msg = "Value1 argument is required for eq command".to_string();
            error!("{}", msg);
            msg
        })?;
        let value1 = args[value_index1].clone();

        let value_index2 = matches.index_of("value2").ok_or_else(|| {
            let msg = "Value2 argument is required for eq command".to_string();
            error!("{}", msg);
            msg
        })?;
        let value2 = args[value_index2].clone();

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
    pub value1: CommandArg,
    pub value2: CommandArg,
}

#[async_trait::async_trait]
impl CommandExecutor for EQCommandExecutor {
    async fn exec(&self, context: &Context) -> Result<CommandResult, String> {
        // Evaluate both values
        let value1 = self.value1.evaluate_string(context).await?;
        let value2 = self.value2.evaluate_string(context).await?;

        let is_eq = if self.ignore_case {
            value1.eq_ignore_ascii_case(&value2)
        } else {
            value1 == value2
        };

        /*
        info!(
            "EQ command: comparing '{}' with '{}' (ignore_case: {})",
            value1, value2, self.ignore_case
        );
        */
        if is_eq {
            Ok(CommandResult::success_with_value("true"))
        } else {
            Ok(CommandResult::error_with_value("false"))
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
    fn group(&self) -> CommandGroup {
        CommandGroup::Match
    }

    fn help(&self, _name: &str, help_type: CommandHelpType) -> String {
        command_help(help_type, &self.cmd)
    }

    fn parse(
        &self,
        _context: &ParserContext,
        str_args: Vec<&str>,
        args: &CommandArgs,
    ) -> Result<CommandExecutorRef, String> {
        let matches = self.cmd.clone().try_get_matches_from(&str_args).map_err(|e| {
            let msg = format!("Invalid range command: {:?}, {}", str_args, e);
            error!("{}", msg);
            msg
        })?;

        let value_index = matches.index_of("value").ok_or_else(|| {
            let msg = "Value argument is required for range command".to_string();
            error!("{}", msg);
            msg
        })?;
        let value = args[value_index].clone();
        if value.is_literal() {
            if let Err(e) = value.as_literal_str().unwrap().parse::<f64>() {
                let msg = format!("Invalid range command value: {:?}: {}", value, e);
                error!("{}", msg);
                return Err(msg);
            }
        }
       
        // Get the range bounds and check they are valid numbers if is literal
        let begin_index = matches.index_of("begin").ok_or_else(|| {
            let msg = "Begin argument is required for range command".to_string();
            error!("{}", msg);
            msg
        })?;
        let begin = args[begin_index].clone();
        if begin.is_literal() {
            if let Err(e) = begin.as_literal_str().unwrap().parse::<f64>() {
                let msg = format!("Invalid range command begin value: {:?}: {}", begin, e);
                error!("{}", msg);
                return Err(msg);
            }
        }
        let end_index = matches.index_of("end").ok_or_else(|| {
            let msg = "End argument is required for range command".to_string();
            error!("{}", msg);
            msg
        })?;

        let end = args[end_index].clone();
        if end.is_literal() {
            if let Err(e) = end.as_literal_str().unwrap().parse::<f64>() {
                let msg = format!("Invalid range command end value: {:?}: {}", end, e);
                error!("{}", msg);
                return Err(msg);
            }
        }   

        let cmd = RangeCommandExecutor::new(
            value,
            begin,
            end,
        );
        Ok(Arc::new(Box::new(cmd)))
    }
}

// Range command executer
pub struct RangeCommandExecutor {
    pub value: CommandArg,
    pub min: CommandArg,
    pub max: CommandArg,
}

impl RangeCommandExecutor {
    pub fn new(value: CommandArg, min: CommandArg, max: CommandArg) -> Self {
        Self { value, min, max }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for RangeCommandExecutor {
    async fn exec(&self, _context: &Context) -> Result<CommandResult, String> {
        // First evaluate the value, min and max
        let value = self.value.evaluate_string(_context).await?;
        let min = self.min.evaluate_string(_context).await?;
        let max = self.max.evaluate_string(_context).await?;

        // Convert to f64 for comparison
        let value = value.parse::<f64>().map_err(|e| {
            let msg = format!("Invalid range value: {}: {}", value, e);
            error!("{}", msg);
            msg
        })?;

        let min = min.parse::<f64>().map_err(|e| {
            let msg = format!("Invalid range min value: {}: {}", min, e);
            error!("{}", msg);
            msg
        })?;

        let max = max.parse::<f64>().map_err(|e| {
            let msg = format!("Invalid range max value: {}: {}", max, e);
            error!("{}", msg);
            msg
        })?;

        if value >= min && value <= max {
            Ok(CommandResult::success_with_value("true"))
        } else {
            Ok(CommandResult::error_with_value("false"))
        }
    }
}