use super::cmd::*;
use crate::block::{CommandArg, CommandArgs};
use crate::chain::{Context, ParserContext};
use crate::collection::{CollectionValue, MemoryListCollection};
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
        let matches = self
            .cmd
            .clone()
            .try_get_matches_from(&str_args)
            .map_err(|e| {
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

        let pattern_str = args[pattern_index].as_literal_str().ok_or_else(|| {
            let msg = format!(
                "Pattern argument must be a literal string: {:?}",
                args[pattern_index]
            );
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
            Ok(CommandResult::success_with_value(CollectionValue::Bool(
                true,
            )))
        } else {
            Ok(CommandResult::error_with_value(CollectionValue::Bool(
                false,
            )))
        }
    }
}

// Match regex command, like: match-reg REQ_HEADER.host "^(.*)\.local$"
// If capture is provided, it stores match results in a fresh List accessible by `name[i]`
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
  --capture name   Store regex match results into a fresh List variable accessible as name[0], name[1], ...
  --no-ignore-case   Perform case-sensitive matching (default is case-insensitive)

Behavior:
  - Uses Rust-style regular expressions.
  - If the pattern matches, the command returns success, otherwise it returns error.
  - If --capture is provided, match results are saved into a fresh List as:
      name[0] is the full matched text,
      name[1] is the first capture group,
      name[2] is the second capture group, etc.
  - Unmatched optional capture groups are stored as Null to preserve indexes.
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
                    .help("Store regex match results into a fresh List variable"),
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
        let matches = self
            .cmd
            .clone()
            .try_get_matches_from(&str_args)
            .map_err(|e| {
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
        let pattern_str = args[pattern_index].as_literal_str().ok_or_else(|| {
            let msg = format!(
                "Pattern argument must be a literal string: {:?}",
                args[pattern_index]
            );
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
    pub capture: Option<String>, // Optional capture result list variable name
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

    async fn build_capture_list(caps: &regex::Captures<'_>) -> Result<CollectionValue, String> {
        let list = MemoryListCollection::new_ref();
        for cap in caps.iter() {
            let value = cap
                .map(|m| CollectionValue::String(m.as_str().to_owned()))
                .unwrap_or(CollectionValue::Null);
            list.push(value).await?;
        }

        Ok(CollectionValue::List(list))
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
                let capture_list = Self::build_capture_list(&caps).await?;
                // TODO: Add env level support, such as --capture export/local name
                context.env().set(name, capture_list, None).await?;
            }

            Ok(CommandResult::success_with_value(CollectionValue::Bool(
                true,
            )))
        } else {
            Ok(CommandResult::error_with_value(CollectionValue::Bool(
                false,
            )))
        }
    }
}

#[derive(Clone, Debug)]
enum TemplatePatternSegment {
    Template(Vec<TemplateFragment>),
    WildcardRest,
}

#[derive(Clone, Debug)]
enum TemplateFragment {
    Literal(String),
    Capture(String),
}

#[derive(Clone, Copy)]
struct TemplateMatchDefaults {
    separator: char,
    ignore_case: bool,
}

pub struct MatchPathCommandParser {
    cmd: Command,
}

impl MatchPathCommandParser {
    pub fn new() -> Self {
        let cmd = Command::new("match-path")
            .about("Match a path-like value using segment templates. Supports optional capture.")
            .after_help(
                r#"
Arguments:
  <value>      The path-like string to match.
  <pattern>    The template pattern to match against.

Options:
  --capture name   Store template match results into a fresh List variable accessible as name[0], name[1], ...
  --ignore-case    Perform case-insensitive matching (default is case-sensitive)

Behavior:
  - Uses '/' as the default segment separator.
  - Pattern is evaluated dynamically at runtime.
  - `{name}` captures text inside a single segment and never crosses '/'.
  - `**` matches the remaining segments and must appear as the last segment.
  - If --capture is provided, match results are saved into a fresh List as:
      name[0] is the full matched text,
      name[1] is the first template capture,
      name[2] is the second template capture, etc.
  - Matching is case-sensitive by default.

Examples:
  match-path $REQ.path "/kapi/{service_id}/**"
  match-path --capture parts $REQ.path "${route_prefix}/{node}/{plane}/**"
"#,
            )
            .arg(
                Arg::new("ignore_case")
                    .long("ignore-case")
                    .action(ArgAction::SetTrue)
                    .help("Perform case-insensitive matching (default is case-sensitive)"),
            )
            .arg(
                Arg::new("capture")
                    .long("capture")
                    .value_name("name")
                    .help("Store template match results into a fresh List variable"),
            )
            .arg(
                Arg::new("value")
                    .required(true)
                    .help("The input string or variable to match"),
            )
            .arg(
                Arg::new("pattern")
                    .required(true)
                    .help("The template pattern"),
            );

        Self { cmd }
    }
}

impl CommandParser for MatchPathCommandParser {
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
        parse_template_match_command(
            &self.cmd,
            "match-path",
            str_args,
            args,
            TemplateMatchDefaults {
                separator: '/',
                ignore_case: false,
            },
            Some("ignore_case"),
            None,
        )
    }
}

pub struct MatchHostCommandParser {
    cmd: Command,
}

impl MatchHostCommandParser {
    pub fn new() -> Self {
        let cmd = Command::new("match-host")
            .about("Match a host-like value using segment templates. Supports optional capture.")
            .after_help(
                r#"
Arguments:
  <value>      The host-like string to match.
  <pattern>    The template pattern to match against.

Options:
  --capture name     Store template match results into a fresh List variable accessible as name[0], name[1], ...
  --no-ignore-case   Perform case-sensitive matching (default is case-insensitive)

Behavior:
  - Uses '.' as the default segment separator.
  - Pattern is evaluated dynamically at runtime.
  - `{name}` captures text inside a single host label and never crosses '.'.
  - `**` matches the remaining labels and must appear as the last segment.
  - If --capture is provided, match results are saved into a fresh List as:
      name[0] is the full matched text,
      name[1] is the first template capture,
      name[2] is the second template capture, etc.
  - Matching is case-insensitive by default.

Examples:
  match-host $REQ.host "{app}.${THIS_ZONE_HOST}"
  match-host --capture host $REQ.host "{app}-${THIS_ZONE_HOST}"
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
                    .help("Store template match results into a fresh List variable"),
            )
            .arg(
                Arg::new("value")
                    .required(true)
                    .help("The input string or variable to match"),
            )
            .arg(
                Arg::new("pattern")
                    .required(true)
                    .help("The template pattern"),
            );

        Self { cmd }
    }
}

impl CommandParser for MatchHostCommandParser {
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
        parse_template_match_command(
            &self.cmd,
            "match-host",
            str_args,
            args,
            TemplateMatchDefaults {
                separator: '.',
                ignore_case: true,
            },
            None,
            Some("no_ignore_case"),
        )
    }
}

fn parse_template_match_command(
    cmd: &Command,
    command_name: &str,
    str_args: Vec<&str>,
    args: &CommandArgs,
    defaults: TemplateMatchDefaults,
    ignore_case_flag: Option<&str>,
    no_ignore_case_flag: Option<&str>,
) -> Result<CommandExecutorRef, String> {
    let matches = cmd.clone().try_get_matches_from(&str_args).map_err(|e| {
        let msg = format!("Invalid {} command: {:?}, {}", command_name, str_args, e);
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
        let msg = format!("Value argument is required for {} command", command_name);
        error!("{}", msg);
        msg
    })?;
    let value = args[value_index].clone();

    let pattern_index = matches.index_of("pattern").ok_or_else(|| {
        let msg = format!("Pattern argument is required for {} command", command_name);
        error!("{}", msg);
        msg
    })?;
    let pattern = args[pattern_index].clone();

    let ignore_case = if let Some(flag) = ignore_case_flag {
        matches.get_flag(flag)
    } else if let Some(flag) = no_ignore_case_flag {
        !matches.get_flag(flag)
    } else {
        defaults.ignore_case
    };

    let exec = TemplateMatchCommandExecutor::new(
        command_name.to_owned(),
        value,
        pattern,
        capture,
        defaults.separator,
        ignore_case,
    );
    Ok(Arc::new(Box::new(exec)))
}

pub struct TemplateMatchCommandExecutor {
    command_name: String,
    capture: Option<String>,
    value: CommandArg,
    pattern: CommandArg,
    separator: char,
    ignore_case: bool,
}

impl TemplateMatchCommandExecutor {
    pub fn new(
        command_name: String,
        value: CommandArg,
        pattern: CommandArg,
        capture: Option<String>,
        separator: char,
        ignore_case: bool,
    ) -> Self {
        Self {
            command_name,
            capture,
            value,
            pattern,
            separator,
            ignore_case,
        }
    }

    async fn build_capture_list(
        full_match: &str,
        captures: &[String],
    ) -> Result<CollectionValue, String> {
        let list = MemoryListCollection::new_ref();
        list.push(CollectionValue::String(full_match.to_owned()))
            .await?;
        for capture in captures {
            list.push(CollectionValue::String(capture.clone())).await?;
        }

        Ok(CollectionValue::List(list))
    }

    fn parse_pattern(&self, pattern: &str) -> Result<Vec<TemplatePatternSegment>, String> {
        let raw_segments: Vec<&str> = pattern.split(self.separator).collect();
        let mut segments = Vec::with_capacity(raw_segments.len());
        for (index, segment) in raw_segments.iter().enumerate() {
            if *segment == "**" {
                if index + 1 != raw_segments.len() {
                    let msg = format!(
                        "{} pattern '{}' contains '**' before the last segment",
                        self.command_name, pattern
                    );
                    error!("{}", msg);
                    return Err(msg);
                }
                segments.push(TemplatePatternSegment::WildcardRest);
                continue;
            }

            let fragments = self.parse_segment_template(pattern, segment)?;
            segments.push(TemplatePatternSegment::Template(fragments));
        }

        Ok(segments)
    }

    fn parse_segment_template(
        &self,
        pattern: &str,
        segment: &str,
    ) -> Result<Vec<TemplateFragment>, String> {
        let mut fragments = Vec::new();
        let mut literal_start = 0usize;
        let mut cursor = 0usize;

        while let Some(rel_open) = segment[cursor..].find('{') {
            let open = cursor + rel_open;
            if literal_start < open {
                fragments.push(TemplateFragment::Literal(
                    segment[literal_start..open].to_owned(),
                ));
            }

            let close = segment[open + 1..]
                .find('}')
                .map(|offset| open + 1 + offset)
                .ok_or_else(|| {
                    let msg = format!(
                        "Invalid {} pattern '{}': missing closing '}}' in segment '{}'",
                        self.command_name, pattern, segment
                    );
                    error!("{}", msg);
                    msg
                })?;

            let name = &segment[open + 1..close];
            if !is_valid_template_capture_name(name) {
                let msg = format!(
                    "Invalid {} pattern '{}': capture name '{}' must match [A-Za-z_][A-Za-z0-9_]*",
                    self.command_name, pattern, name
                );
                error!("{}", msg);
                return Err(msg);
            }

            fragments.push(TemplateFragment::Capture(name.to_owned()));
            cursor = close + 1;
            literal_start = cursor;
        }

        if literal_start < segment.len() {
            fragments.push(TemplateFragment::Literal(
                segment[literal_start..].to_owned(),
            ));
        }

        if fragments.is_empty() {
            fragments.push(TemplateFragment::Literal(String::new()));
        }

        Ok(fragments)
    }

    fn match_template(&self, value: &str, pattern: &str) -> Result<Option<Vec<String>>, String> {
        let pattern_segments = self.parse_pattern(pattern)?;
        let value_segments: Vec<&str> = value.split(self.separator).collect();
        let mut captures = Vec::new();
        let mut value_index = 0usize;

        for segment in pattern_segments.iter() {
            match segment {
                TemplatePatternSegment::WildcardRest => return Ok(Some(captures)),
                TemplatePatternSegment::Template(fragments) => {
                    if value_index >= value_segments.len() {
                        return Ok(None);
                    }
                    let segment_captures =
                        self.match_segment_template(fragments, value_segments[value_index])?;
                    let Some(segment_captures) = segment_captures else {
                        return Ok(None);
                    };
                    captures.extend(segment_captures);
                    value_index += 1;
                }
            }
        }

        if value_index == value_segments.len() {
            Ok(Some(captures))
        } else {
            Ok(None)
        }
    }

    fn match_segment_template(
        &self,
        fragments: &[TemplateFragment],
        value: &str,
    ) -> Result<Option<Vec<String>>, String> {
        self.match_segment_from(fragments, value, 0, 0)
    }

    fn match_segment_from(
        &self,
        fragments: &[TemplateFragment],
        value: &str,
        fragment_index: usize,
        offset: usize,
    ) -> Result<Option<Vec<String>>, String> {
        if fragment_index == fragments.len() {
            return Ok((offset == value.len()).then(Vec::new));
        }

        match &fragments[fragment_index] {
            TemplateFragment::Literal(literal) => {
                if !segment_starts_with(&value[offset..], literal, self.ignore_case) {
                    return Ok(None);
                }

                self.match_segment_from(
                    fragments,
                    value,
                    fragment_index + 1,
                    offset + literal.len(),
                )
            }
            TemplateFragment::Capture(_name) => {
                if fragment_index + 1 == fragments.len() {
                    return Ok(Some(vec![value[offset..].to_owned()]));
                }

                for end in candidate_segment_end_offsets(value, offset) {
                    if let Some(mut rest) =
                        self.match_segment_from(fragments, value, fragment_index + 1, end)?
                    {
                        let mut captures = vec![value[offset..end].to_owned()];
                        captures.append(&mut rest);
                        return Ok(Some(captures));
                    }
                }

                Ok(None)
            }
        }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for TemplateMatchCommandExecutor {
    async fn exec(&self, context: &Context) -> Result<CommandResult, String> {
        let value = self.value.evaluate_string(context).await?;
        let pattern = self.pattern.evaluate_string(context).await?;

        if let Some(captures) = self.match_template(&value, &pattern)? {
            if let Some(name) = &self.capture {
                let capture_list = Self::build_capture_list(&value, &captures).await?;
                context.env().set(name, capture_list, None).await?;
            }

            Ok(CommandResult::success_with_value(CollectionValue::Bool(
                true,
            )))
        } else {
            Ok(CommandResult::error_with_value(CollectionValue::Bool(
                false,
            )))
        }
    }
}

fn is_valid_template_capture_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }

    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn segment_starts_with(value: &str, prefix: &str, ignore_case: bool) -> bool {
    match value.get(..prefix.len()) {
        Some(candidate) => segment_text_eq(candidate, prefix, ignore_case),
        None => false,
    }
}

fn segment_text_eq(left: &str, right: &str, ignore_case: bool) -> bool {
    if ignore_case {
        left.eq_ignore_ascii_case(right)
    } else {
        left == right
    }
}

fn candidate_segment_end_offsets(value: &str, start: usize) -> Vec<usize> {
    let mut offsets = Vec::new();
    offsets.push(value.len());

    let tail = &value[start..];
    for (rel, _) in tail.char_indices() {
        if rel == 0 {
            continue;
        }
        offsets.push(start + rel);
    }

    offsets.sort_unstable();
    offsets.dedup();
    offsets.reverse();
    offsets
}

// EQ command, like: eq REQ_HEADER.host "localhost"; eq --ignore-case REQ_HEADER.host "LOCALHOST"; eq --loose 1 "1"
pub struct EQCommandParser {
    cmd: Command,
}

impl EQCommandParser {
    pub fn new() -> Self {
        let cmd = Command::new("eq")
            .about("Compare two values for equality (strict typed by default).")
            .after_help(
                r#"
Compare two values for equality.

Arguments:
  <value1>        First value to compare
  <value2>        Second value to compare

Options:
  --ignore-case   Perform case-insensitive comparison (string-string only)
  --loose         Enable loose comparison for string/number

By default, eq uses strict typed comparison:
  - Same-type scalar values are compared directly
  - Different types are not equal (e.g. Number(1) != String("1"))

Examples:
  eq 1 1
  eq 1 "1"              # false under strict mode
  eq --loose 1 "1"      # true under loose mode
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
                Arg::new("loose")
                    .long("loose")
                    .short('l')
                    .action(ArgAction::SetTrue)
                    .help("Enable loose comparison for string/number"),
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
        let matches = self
            .cmd
            .clone()
            .try_get_matches_from(&str_args)
            .map_err(|e| {
                let msg = format!("Invalid eq command: {:?}, {}", str_args, e);
                error!("{}", msg);
                msg
            })?;

        let ignore_case = matches.get_flag("ignore_case");
        let loose = matches.get_flag("loose");

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
            loose,
            value1,
            value2,
        };

        Ok(Arc::new(Box::new(cmd)))
    }
}

// EQ command executer
pub struct EQCommandExecutor {
    pub ignore_case: bool, // Whether to ignore case, default is false
    pub loose: bool,       // Whether to use loose comparison across scalar types
    pub value1: CommandArg,
    pub value2: CommandArg,
}

impl EQCommandExecutor {
    fn parse_number_literal(raw: &str) -> Option<f64> {
        let trimmed = raw.trim();
        if let Ok(v) = trimmed.parse::<i64>() {
            return Some(v as f64);
        }
        if let Ok(v) = trimmed.parse::<f64>() {
            return Some(v);
        }
        None
    }

    fn as_loose_number(value: &CollectionValue) -> Option<f64> {
        match value {
            CollectionValue::Number(v) => Some(v.as_f64()),
            CollectionValue::String(s) => Self::parse_number_literal(s),
            _ => None,
        }
    }

    fn compare_strict(&self, left: &CollectionValue, right: &CollectionValue) -> bool {
        if self.ignore_case {
            if let (CollectionValue::String(lhs), CollectionValue::String(rhs)) = (left, right) {
                return lhs.eq_ignore_ascii_case(rhs);
            }
        }

        left == right
    }

    fn compare_loose(&self, left: &CollectionValue, right: &CollectionValue) -> bool {
        if let (CollectionValue::String(lhs), CollectionValue::String(rhs)) = (left, right) {
            return if self.ignore_case {
                lhs.eq_ignore_ascii_case(rhs)
            } else {
                lhs == rhs
            };
        }

        if left.is_null() || right.is_null() {
            return left.is_null() && right.is_null();
        }

        if let (CollectionValue::Number(lhs), CollectionValue::Number(rhs)) = (left, right) {
            return lhs.as_f64() == rhs.as_f64();
        }

        if let (CollectionValue::Bool(lhs), CollectionValue::Bool(rhs)) = (left, right) {
            return lhs == rhs;
        }

        if let (CollectionValue::String(_), CollectionValue::Number(_))
        | (CollectionValue::Number(_), CollectionValue::String(_)) = (left, right)
        {
            if let (Some(lhs), Some(rhs)) =
                (Self::as_loose_number(left), Self::as_loose_number(right))
            {
                return lhs == rhs;
            }
        }

        left == right
    }
}

#[async_trait::async_trait]
impl CommandExecutor for EQCommandExecutor {
    async fn exec(&self, context: &Context) -> Result<CommandResult, String> {
        // Evaluate both values
        let value1 = self.value1.evaluate(context).await?;
        let value2 = self.value2.evaluate(context).await?;

        let is_eq = if self.loose {
            self.compare_loose(&value1, &value2)
        } else {
            self.compare_strict(&value1, &value2)
        };

        /*
        info!(
            "EQ command: comparing '{}' with '{}' (ignore_case: {})",
            value1, value2, self.ignore_case
        );
        */
        if is_eq {
            Ok(CommandResult::success_with_value(CollectionValue::Bool(
                true,
            )))
        } else {
            Ok(CommandResult::error_with_value(CollectionValue::Bool(
                false,
            )))
        }
    }
}

// NE command, like: ne REQ_HEADER.host "localhost"; ne --ignore-case REQ_HEADER.host "LOCALHOST"
pub struct NECommandParser {
    cmd: Command,
}

impl NECommandParser {
    pub fn new() -> Self {
        let cmd = Command::new("ne")
            .about("Compare two values for inequality (strict typed by default).")
            .after_help(
                r#"
Compare two values for inequality.

Arguments:
  <value1>        First value to compare
  <value2>        Second value to compare

Options:
  --ignore-case   Perform case-insensitive comparison (string-string only)
  --loose         Enable loose comparison for string/number

By default, ne uses strict typed comparison.
Use --loose to enable string/number loose comparison.
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
                Arg::new("loose")
                    .long("loose")
                    .short('l')
                    .action(ArgAction::SetTrue)
                    .help("Enable loose comparison for string/number"),
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

impl CommandParser for NECommandParser {
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
        let matches = self
            .cmd
            .clone()
            .try_get_matches_from(&str_args)
            .map_err(|e| {
                let msg = format!("Invalid ne command: {:?}, {}", str_args, e);
                error!("{}", msg);
                msg
            })?;

        let ignore_case = matches.get_flag("ignore_case");
        let loose = matches.get_flag("loose");

        let value_index1 = matches.index_of("value1").ok_or_else(|| {
            let msg = "Value1 argument is required for ne command".to_string();
            error!("{}", msg);
            msg
        })?;
        let value1 = args[value_index1].clone();

        let value_index2 = matches.index_of("value2").ok_or_else(|| {
            let msg = "Value2 argument is required for ne command".to_string();
            error!("{}", msg);
            msg
        })?;
        let value2 = args[value_index2].clone();

        let cmd = NECommandExecutor {
            ignore_case,
            loose,
            value1,
            value2,
        };

        Ok(Arc::new(Box::new(cmd)))
    }
}

pub struct NECommandExecutor {
    pub ignore_case: bool,
    pub loose: bool,
    pub value1: CommandArg,
    pub value2: CommandArg,
}

#[async_trait::async_trait]
impl CommandExecutor for NECommandExecutor {
    async fn exec(&self, context: &Context) -> Result<CommandResult, String> {
        let value1 = self.value1.evaluate(context).await?;
        let value2 = self.value2.evaluate(context).await?;

        let eq = if self.loose {
            EQCommandExecutor {
                ignore_case: self.ignore_case,
                loose: true,
                value1: self.value1.clone(),
                value2: self.value2.clone(),
            }
            .compare_loose(&value1, &value2)
        } else {
            EQCommandExecutor {
                ignore_case: self.ignore_case,
                loose: false,
                value1: self.value1.clone(),
                value2: self.value2.clone(),
            }
            .compare_strict(&value1, &value2)
        };

        if !eq {
            Ok(CommandResult::success_with_value(CollectionValue::Bool(
                true,
            )))
        } else {
            Ok(CommandResult::error_with_value(CollectionValue::Bool(
                false,
            )))
        }
    }
}

#[derive(Clone, Copy)]
enum NumberCompareOp {
    Gt,
    Ge,
    Lt,
    Le,
}

impl NumberCompareOp {
    fn compare(&self, left: f64, right: f64) -> bool {
        match self {
            NumberCompareOp::Gt => left > right,
            NumberCompareOp::Ge => left >= right,
            NumberCompareOp::Lt => left < right,
            NumberCompareOp::Le => left <= right,
        }
    }
}

pub struct NumberCompareCommandParser {
    cmd: Command,
    op: NumberCompareOp,
}

impl NumberCompareCommandParser {
    fn new(name: &'static str, about: &'static str, op: NumberCompareOp) -> Self {
        let cmd = Command::new(name)
            .about(about)
            .arg(
                Arg::new("loose")
                    .long("loose")
                    .short('l')
                    .action(ArgAction::SetTrue)
                    .help("Enable loose number parsing for string/number"),
            )
            .arg(Arg::new("value1").required(true).help("The left value"))
            .arg(Arg::new("value2").required(true).help("The right value"));
        Self { cmd, op }
    }
}

impl CommandParser for NumberCompareCommandParser {
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
        let matches = self
            .cmd
            .clone()
            .try_get_matches_from(&str_args)
            .map_err(|e| {
                let msg = format!(
                    "Invalid {} command: {:?}, {}",
                    self.cmd.get_name(),
                    str_args,
                    e
                );
                error!("{}", msg);
                msg
            })?;

        let loose = matches.get_flag("loose");

        let value_index1 = matches.index_of("value1").ok_or_else(|| {
            let msg = format!(
                "Value1 argument is required for {} command",
                self.cmd.get_name()
            );
            error!("{}", msg);
            msg
        })?;
        let value1 = args[value_index1].clone();

        let value_index2 = matches.index_of("value2").ok_or_else(|| {
            let msg = format!(
                "Value2 argument is required for {} command",
                self.cmd.get_name()
            );
            error!("{}", msg);
            msg
        })?;
        let value2 = args[value_index2].clone();

        let cmd = NumberCompareCommandExecutor::new(self.op, loose, value1, value2);
        Ok(Arc::new(Box::new(cmd)))
    }
}

pub struct NumberCompareCommandExecutor {
    op: NumberCompareOp,
    loose: bool,
    value1: CommandArg,
    value2: CommandArg,
}

impl NumberCompareCommandExecutor {
    fn new(op: NumberCompareOp, loose: bool, value1: CommandArg, value2: CommandArg) -> Self {
        Self {
            op,
            loose,
            value1,
            value2,
        }
    }

    fn parse_number(value: &CollectionValue, loose: bool) -> Option<f64> {
        match value {
            CollectionValue::Number(v) => Some(v.as_f64()),
            CollectionValue::String(s) if loose => EQCommandExecutor::parse_number_literal(s),
            _ => None,
        }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for NumberCompareCommandExecutor {
    async fn exec(&self, context: &Context) -> Result<CommandResult, String> {
        let value1 = self.value1.evaluate(context).await?;
        let value2 = self.value2.evaluate(context).await?;

        let matched = match (
            Self::parse_number(&value1, self.loose),
            Self::parse_number(&value2, self.loose),
        ) {
            (Some(left), Some(right)) => self.op.compare(left, right),
            _ => false,
        };

        if matched {
            Ok(CommandResult::success_with_value(CollectionValue::Bool(
                true,
            )))
        } else {
            Ok(CommandResult::error_with_value(CollectionValue::Bool(
                false,
            )))
        }
    }
}

pub fn create_gt_parser() -> NumberCompareCommandParser {
    NumberCompareCommandParser::new("gt", "Check whether value1 > value2.", NumberCompareOp::Gt)
}

pub fn create_ge_parser() -> NumberCompareCommandParser {
    NumberCompareCommandParser::new("ge", "Check whether value1 >= value2.", NumberCompareOp::Ge)
}

pub fn create_lt_parser() -> NumberCompareCommandParser {
    NumberCompareCommandParser::new("lt", "Check whether value1 < value2.", NumberCompareOp::Lt)
}

pub fn create_le_parser() -> NumberCompareCommandParser {
    NumberCompareCommandParser::new("le", "Check whether value1 <= value2.", NumberCompareOp::Le)
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
        let matches = self
            .cmd
            .clone()
            .try_get_matches_from(&str_args)
            .map_err(|e| {
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

        let cmd = RangeCommandExecutor::new(value, begin, end);
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
        let value = self.value.evaluate_number(_context).await?.as_f64();
        let min = self.min.evaluate_number(_context).await?.as_f64();
        let max = self.max.evaluate_number(_context).await?.as_f64();

        if value >= min && value <= max {
            Ok(CommandResult::success_with_value(CollectionValue::Bool(
                true,
            )))
        } else {
            Ok(CommandResult::error_with_value(CollectionValue::Bool(
                false,
            )))
        }
    }
}
