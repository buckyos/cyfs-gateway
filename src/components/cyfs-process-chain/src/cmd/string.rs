use super::cmd::*;
use crate::block::{CommandArg, CommandArgEvaluator, CommandArgs};
use crate::chain::{Context, ParserContext};
use crate::collection::CollectionValue;
use clap::{Arg, ArgAction, Command};
use globset::{GlobBuilder, GlobMatcher};
use regex::Regex;
use std::sync::Arc;

// rewrite <var> <pattern> <template>
// rewrite $REQ.url /kapi/my-service/* /kapi/*
pub struct RewriteCommandParser {
    cmd: Command,
}

impl RewriteCommandParser {
    pub fn new() -> Self {
        let cmd = Command::new("rewrite")
            .about("Rewrite the value of a variable using a glob pattern.")
            .after_help(
                r#"
Arguments:
  <var>       The variable to rewrite (e.g. $REQ.url)
  <pattern>   A glob-style pattern to match (e.g. /kapi/my-service/*)
  <template>  A replacement template using * wildcard (e.g. /kapi/*)

Behavior:
  - Performs case-insensitive glob pattern match.
  - Supports only a single '*' wildcard in pattern/template.
  - Rewrites the variable if pattern matches, replacing the '*' part.

Examples:
  rewrite $REQ.url "/kapi/my-service/*" "/kapi/*"
  rewrite host "api.*.domain.com" "svc-*.internal"
"#,
            )
            .arg(
                Arg::new("var")
                    .required(true)
                    .help("The name of the variable to rewrite"),
            )
            .arg(
                Arg::new("pattern")
                    .required(true)
                    .help("The glob pattern to match"),
            )
            .arg(
                Arg::new("template")
                    .required(true)
                    .help("The replacement template"),
            );

        Self { cmd }
    }
}

impl CommandParser for RewriteCommandParser {
    fn group(&self) -> CommandGroup {
        CommandGroup::String
    }

    fn help(&self, _name: &str, help_type: super::CommandHelpType) -> String {
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
                let msg = format!("Invalid rewrite command: {:?}, {}", str_args, e);
                error!("{}", msg);
                msg
            })?;

        let key_index = matches.index_of("var").ok_or_else(|| {
            let msg = format!("Variable name is required, but got: {:?}", args);
            error!("{}", msg);
            msg
        })?;
        let key = args[key_index].clone();
        if !key.is_var() {
            let msg = format!(
                "Invalid rewrite command: {:?}, the first argument must be a variable",
                args
            );
            error!("{}", msg);
            return Err(msg);
        }

        let pattern_index = matches.index_of("pattern").ok_or_else(|| {
            let msg = format!("Pattern is required, but got: {:?}", args);
            error!("{}", msg);
            msg
        })?;
        let pattern_value = args[pattern_index].as_literal_str().ok_or_else(|| {
            let msg = format!(
                "Pattern must be a literal string, got: {:?}",
                args[pattern_index]
            );
            error!("{}", msg);
            msg
        })?;

        let pattern = GlobBuilder::new(pattern_value)
            .case_insensitive(true)
            .build()
            .map_err(|e| {
                let msg = format!("Invalid glob pattern: {}: {}", pattern_value, e);
                error!("{}", msg);
                msg
            })?
            .compile_matcher();

        let template_index = matches.index_of("template").ok_or_else(|| {
            let msg = format!("Template is required, but got: {:?}", args);
            error!("{}", msg);
            msg
        })?;

        let template = args[template_index].clone();

        let cmd = RewriteCommand::new(key, pattern, pattern_value.to_string(), template);

        Ok(Arc::new(Box::new(cmd)))
    }
}

pub struct RewriteCommand {
    key: CommandArg,

    pattern: GlobMatcher,
    pattern_value: String,

    template: CommandArg,
}

impl RewriteCommand {
    pub fn new(
        key: CommandArg,
        pattern: GlobMatcher,
        pattern_value: String,
        template: CommandArg,
    ) -> Self {
        Self {
            key,
            pattern,
            pattern_value,
            template,
        }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for RewriteCommand {
    async fn exec(&self, context: &Context) -> Result<super::CommandResult, String> {
        let key_value = self.key.evaluate_string(context).await?;
        let template_value = self.template.evaluate_string(context).await?;

        if self.pattern.is_match(&key_value) {
            if let Some(prefix) = self.pattern_value.strip_suffix("*") {
                if key_value.starts_with(prefix) && template_value.ends_with('*') {
                    let tail = &key_value[prefix.len()..];
                    let rewritten =
                        format!("{}{}", &template_value[..template_value.len() - 1], tail);
                    context
                        .env()
                        .set(
                            self.key.as_str(),
                            CollectionValue::String(rewritten.clone()),
                            None,
                        )
                        .await?;
                    info!(
                        "Rewritten value for {}: {} -> {}",
                        self.key.as_str(),
                        key_value,
                        rewritten
                    );

                    Ok(CommandResult::success_with_value(rewritten))
                } else {
                    let msg = format!(
                        "Pattern '{}' did not match '{}', expected prefix '{}'",
                        self.pattern_value, key_value, prefix
                    );
                    info!("{}", msg);
                    Ok(CommandResult::success())
                }
            } else {
                info!(
                    "Pattern '{}' matched '{}', setting to template '{}'",
                    self.pattern_value, key_value, template_value
                );
                context
                    .env()
                    .set(
                        self.key.as_str(),
                        CollectionValue::String(template_value.to_owned()),
                        None,
                    )
                    .await?;

                Ok(CommandResult::success_with_value(template_value.to_owned()))
            }
        } else {
            info!(
                "Pattern '{}' did not match '{}'",
                self.pattern_value, key_value
            );
            Ok(CommandResult::error())
        }
    }
}

// rewrite $var ^/test/(\w+)(?:/(\d+))? /new/$1/$2
pub struct RewriteRegexCommandParser {
    cmd: Command,
}

impl RewriteRegexCommandParser {
    pub fn new() -> Self {
        let cmd = Command::new("rewrite-regex")
            .about("Rewrite a variable using a regular expression and a replacement template.")
            .after_help(
                r#"
Arguments:
  <var>        The name of the variable to rewrite (e.g. $REQ.url)
  <regex>      Regular expression pattern to match (with capture groups)
  <template>   Replacement string using $1, $2, ... for captured groups

Behavior:
  - If the regex matches, rewrites the variable with the template.
  - Unmatched captures are replaced with empty strings.
  - If the pattern does not match, the variable remains unchanged.

Examples:
  rewrite-regex $REQ.url "^/test/(\\w+)(?:/(\\d+))?" "/new/$1/$2"
"#,
            )
            .arg(
                Arg::new("var")
                    .required(true)
                    .help("The variable to rewrite"),
            )
            .arg(
                Arg::new("regex")
                    .required(true)
                    .help("The regular expression pattern"),
            )
            .arg(
                Arg::new("template")
                    .required(true)
                    .help("The replacement template"),
            );

        Self { cmd }
    }
}

impl CommandParser for RewriteRegexCommandParser {
    fn group(&self) -> CommandGroup {
        CommandGroup::String
    }

    fn help(&self, _name: &str, help_type: super::CommandHelpType) -> String {
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
                let msg = format!("Invalid rewrite-regex command: {:?}, {}", str_args, e);
                error!("{}", msg);
                msg
            })?;

        let key_index = matches.index_of("var").ok_or_else(|| {
            let msg = format!("Variable name is required, but got: {:?}", args);
            error!("{}", msg);
            msg
        })?;

        let key_value = args[key_index].clone();
        if !key_value.is_var() {
            let msg = format!(
                "Invalid rewrite-regex command: {:?}, the first argument must be a variable",
                args
            );
            error!("{}", msg);
            return Err(msg);
        }

        let regex_index = matches.index_of("regex").ok_or_else(|| {
            let msg = format!("Regex pattern is required, but got: {:?}", args);
            error!("{}", msg);
            msg
        })?;
        let regex = &args[regex_index];
        if !regex.is_literal() {
            let msg = format!("Regex pattern must be a literal string, got: {:?}", regex);
            error!("{}", msg);
            return Err(msg);
        }
        let regex = regex.as_literal_str().unwrap();

        let regex = regex::Regex::new(regex).map_err(|e| {
            let msg = format!("Invalid regex pattern: {}: {}", regex, e);
            error!("{}", msg);
            msg
        })?;

        let template_index = matches.index_of("template").ok_or_else(|| {
            let msg = format!("Template is required, but got: {:?}", args);
            error!("{}", msg);
            msg
        })?;
        let template = args[template_index].clone();

        let cmd = RewriteRegexCommand::new(key_value, regex, template);

        Ok(Arc::new(Box::new(cmd)))
    }
}

pub struct RewriteRegexCommand {
    key: CommandArg,
    regex: regex::Regex,
    template: CommandArg,
}

impl RewriteRegexCommand {
    pub fn new(key: CommandArg, regex: regex::Regex, template: CommandArg) -> Self {
        assert!(key.is_var(), "Key must be a variable");

        Self {
            key,
            regex,
            template,
        }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for RewriteRegexCommand {
    async fn exec(&self, context: &Context) -> Result<super::CommandResult, String> {
        let key_value = self.key.evaluate_string(context).await?;
        let template = self.template.evaluate_string(context).await?;

        if let Some(captures) = self.regex.captures(&key_value) {
            // Replace template variables like $1, $2, etc. with captured groups
            let mut result = String::new();
            let mut chars = template.chars().peekable();

            while let Some(c) = chars.next() {
                if c == '$' {
                    if let Some(&next_c) = chars.peek() {
                        if next_c.is_ascii_digit() {
                            chars.next(); // consume digit
                            let idx = next_c.to_digit(10).ok_or_else(|| {
                                let msg =
                                    format!("Invalid digit after $ in template: {}", template);
                                error!("{}", msg);
                                msg
                            })? as usize;

                            if let Some(m) = captures.get(idx) {
                                result.push_str(m.as_str());
                            } else {
                                // if the capture group does not exist, we should skip it as empty
                            }

                            continue;
                        }
                    }

                    result.push('$'); // literal $
                } else {
                    result.push(c);
                }
            }

            context
                .env()
                .set(
                    self.key.as_str(),
                    CollectionValue::String(result.clone()),
                    None,
                )
                .await?;
            info!("Rewritten value for {:?}: {}", self.key, result);

            Ok(CommandResult::success_with_value(result))
        } else {
            Ok(CommandResult::error())
        }
    }
}

// replace <target_var> <match_text> <new_text>
pub struct StringReplaceCommandParser {
    cmd: Command,
}

impl StringReplaceCommandParser {
    pub fn new() -> Self {
        let cmd = Command::new("replace")
            .about("Replace all occurrences of a substring in a variable’s value.")
            .after_help(
                r#"
Arguments:
  <var>         The name of the variable to modify (e.g. $REQ.host)
  <match>       The substring to search for
  <replacement> The string to replace it with

Options:
  --ignore-case,-i   Perform case-insensitive comparison

Behavior:
  - Replaces all (non-overlapping) occurrences of <match> with <replacement>.
  - Case-sensitive by default.
  - If <match> is not found, the variable remains unchanged.

Examples:
  replace $REQ.host "io" "ai"
  replace $PATH "/old/" "/new/"
"#,
            )
            .arg(
                Arg::new("ignore_case")
                    .long("ignore-case")
                    .short('i')
                    .action(ArgAction::SetTrue)
                    .help("Perform case-insensitive comparison"),
            )
            .arg(
                Arg::new("var")
                    .required(true)
                    .help("Variable name to modify"),
            )
            .arg(Arg::new("match").required(true).help("Text to search for"))
            .arg(
                Arg::new("replacement")
                    .required(true)
                    .help("Text to replace with"),
            );

        Self { cmd }
    }
}

impl CommandParser for StringReplaceCommandParser {
    fn group(&self) -> CommandGroup {
        CommandGroup::String
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
                let msg = format!("Invalid string replace command: {:?}, {}", str_args, e);
                error!("{}", msg);
                msg
            })?;

        let key_index = matches.index_of("var").ok_or_else(|| {
            let msg = format!("Variable name is required, but got: {:?}", args);
            error!("{}", msg);
            msg
        })?;
        let key = args[key_index].clone();
        if !key.is_var() {
            let msg = format!(
                "Invalid string replace command: {:?}, the first argument must be a variable",
                args
            );
            error!("{}", msg);
            return Err(msg);
        }

        let match_text_index = matches.index_of("match").ok_or_else(|| {
            let msg = format!("Match text is required, but got: {:?}", args);
            error!("{}", msg);
            msg
        })?;
        let match_text = args[match_text_index].clone();

        let new_text_index = matches.index_of("replacement").ok_or_else(|| {
            let msg = format!("Replacement text is required, but got: {:?}", args);
            error!("{}", msg);
            msg
        })?;
        let new_text = args[new_text_index].clone();

        let ignore_case = matches.get_flag("ignore_case");
        let cmd = StringReplaceCommand::new(ignore_case, key, match_text, new_text);

        Ok(Arc::new(Box::new(cmd)))
    }
}

pub struct StringReplaceCommand {
    ignore_case: bool,
    key: CommandArg,
    match_text: CommandArg,
    new_text: CommandArg,
}

impl StringReplaceCommand {
    pub fn new(
        ignore_case: bool,
        key: CommandArg,
        match_text: CommandArg,
        new_text: CommandArg,
    ) -> Self {
        Self {
            ignore_case,
            key,
            match_text,
            new_text,
        }
    }

    fn replace_case_insensitive(text: &str, match_text: &str, new_text: &str) -> String {
        let pattern = format!(r"(?i){}", regex::escape(match_text));
        let re = Regex::new(&pattern).unwrap();
        re.replace_all(text, new_text).into_owned()
    }

    fn replace_case_sensitive(text: &str, match_text: &str, new_text: &str) -> String {
        text.replace(match_text, new_text)
    }
}

#[async_trait::async_trait]
impl CommandExecutor for StringReplaceCommand {
    async fn exec(&self, context: &Context) -> Result<super::CommandResult, String> {
        // Evaluate the key, match_text, and new_text arguments
        let key_value = self.key.evaluate_string(context).await?;
        let match_text = self.match_text.evaluate_string(context).await?;
        let new_text = self.new_text.evaluate_string(context).await?;

        let rewritten = if self.ignore_case {
            if key_value
                .to_lowercase()
                .contains(&match_text.to_lowercase())
            {
                let rewritten = Self::replace_case_insensitive(&key_value, &match_text, &new_text);
                Some(rewritten)
            } else {
                None
            }
        } else {
            if key_value.contains(&match_text) {
                let rewritten = Self::replace_case_sensitive(&key_value, &match_text, &new_text);
                Some(rewritten)
            } else {
                None
            }
        };

        // If a rewritten value is found, set it in the environment
        if let Some(rewritten) = rewritten {
            context
                .env()
                .set(
                    self.key.as_str(),
                    CollectionValue::String(rewritten.clone()),
                    None,
                )
                .await?;
            info!("Replace value for {:?}: {}", self.key, rewritten);

            Ok(super::CommandResult::success_with_value(rewritten))
        } else {
            Ok(super::CommandResult::error())
        }
    }
}

// append <param1> <param2> ... <param_n>
// This command appends two or more string parameters and returns the result
pub struct StringAppendCommandParser {
    cmd: Command,
}

impl StringAppendCommandParser {
    pub fn new() -> Self {
        let cmd = Command::new("append")
            .about("Append two or more string parameters and return the result.")
            .after_help(
                r#"
Arguments:
  <params>...  Two or more strings or variables to append

Behavior:
  - Joins all parameters with no delimiter.
  - Output is returned with success.
  - The command will not modify any env variables unless specified.

Examples:
  append "abc" "123"
  append $REQ.host ".internal" ".com"
  append "prefix-" $VAR "-suffix"
"#,
            )
            .arg(
                Arg::new("params")
                    .required(true)
                    .num_args(2..) // Require at least two parameters
                    .help("Two or more values to append"),
            );

        Self { cmd }
    }
}

impl CommandParser for StringAppendCommandParser {
    fn group(&self) -> CommandGroup {
        CommandGroup::String
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
                let msg = format!("Invalid string append command: {:?}, {}", str_args, e);
                error!("{}", msg);
                msg
            })?;

        let params = match matches.indices_of("params") {
            Some(indices) => indices.map(|i| args[i].clone()).collect(),
            None => {
                vec![]
            }
        };

        // Check if we have at least two parameters
        if params.len() < 2 {
            let msg = format!(
                "At least two parameters are required, but got: {:?}",
                params
            );
            error!("{}", msg);
            return Err(msg);
        }

        let cmd = StringAppendCommand::new(params);

        Ok(Arc::new(Box::new(cmd)))
    }
}

pub struct StringAppendCommand {
    params: Vec<CommandArg>,
}

impl StringAppendCommand {
    pub fn new(params: Vec<CommandArg>) -> Self {
        Self { params }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for StringAppendCommand {
    async fn exec(&self, context: &Context) -> Result<super::CommandResult, String> {
        /*
        if let Some(var) = &self.var {
            // If a variable is specified, set it in the environment
            context
                .env()
                .set(var, CollectionValue::String(self.result.clone()), None)
                .await?;
            info!("Set variable {} to {}", var, self.result);
        }
        */

        let args = CommandArgEvaluator::evaluate_list(&self.params, context).await?;

        // TODO: for none string args, we should convert them to string or return an error? now we just treat them as strings
        // Concatenate all arguments into a single string
        let result = args
            .iter()
            .map(|arg| arg.treat_as_str())
            .collect::<Vec<&str>>()
            .join("");

        // Return the result as a command result
        Ok(super::CommandResult::success_with_value(&result))
    }
}

pub struct StringConstCommand {
    result: String,
}

impl StringConstCommand {
    pub fn new(result: String) -> Self {
        Self { result }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for StringConstCommand {
    async fn exec(&self, _context: &Context) -> Result<super::CommandResult, String> {
        // Just return the result without modifying the context
        Ok(super::CommandResult::success_with_value(&self.result))
    }
}

// slice <string> range_start:range_end
// This command slices a string from range_start to range_end and returns the result
pub struct StringSliceCommandParser {
    cmd: Command,
}

impl StringSliceCommandParser {
    pub fn new() -> Self {
        let cmd = Command::new("slice")
            .about("Slice a string by byte range and return the result.")
            .after_help(
                r#"
Arguments:
  <string>       The input string or variable to slice.
  <start:end>    Byte index range. End is exclusive.

Behavior:
  - Uses UTF-8-safe slicing based on byte indices.
  - Returns a substring starting at `start` and ending before `end`.
  - If end is less than or equal to start, returns an empty string.
  - Does not modify any variable or environment.

Examples:
  slice "abcdef" 1:4
  slice $REQ.url 0:10
"#,
            )
            .arg(Arg::new("string").required(true).help("String to slice"))
            .arg(
                Arg::new("range")
                    .required(true)
                    .help("Slice range in format start:end"),
            );

        Self { cmd }
    }

    fn parse_range(range: &str) -> Result<(usize, usize), String> {
        let range_parts: Vec<&str> = range.split(':').collect();
        if range_parts.len() != 2 {
            let msg = format!("Invalid range format: {}", range);
            error!("{}", msg);
            return Err(msg);
        }

        let start: usize = range_parts[0].parse().map_err(|e| {
            let msg = format!("Invalid start index: {}: {}", range_parts[0], e);
            error!("{}", msg);
            msg
        })?;
        let end: usize = range_parts[1].parse().map_err(|e| {
            let msg = format!("Invalid end index: {}: {}", range_parts[1], e);
            error!("{}", msg);
            msg
        })?;

        Ok((start, end))
    }
}

impl CommandParser for StringSliceCommandParser {
    fn group(&self) -> CommandGroup {
        CommandGroup::String
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
                let msg = format!("Invalid string slice command: {:?}, {}", str_args, e);
                error!("{}", msg);
                msg
            })?;

        let string_index = matches.index_of("string").ok_or_else(|| {
            let msg = format!("String value is required, but got: {:?}", args);
            error!("{}", msg);
            msg
        })?;
        let string_value = args[string_index].clone();

        let range_index = matches.index_of("range").ok_or_else(|| {
            let msg = format!("Range is required, but got: {:?}", args);
            error!("{}", msg);
            msg
        })?;

        let range = args[range_index].clone();

        let cmd = StringSliceCommand::new(string_value, range);

        Ok(Arc::new(Box::new(cmd)))
    }
}

pub struct StringSliceCommand {
    string: CommandArg,
    range: CommandArg,
}

impl StringSliceCommand {
    pub fn new(string: CommandArg, range: CommandArg) -> Self {
        Self { string, range }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for StringSliceCommand {
    async fn exec(&self, context: &Context) -> Result<super::CommandResult, String> {
        // Evaluate the string and range arguments
        let string_value = self.string.evaluate_string(context).await?;
        let range_value = self.range.evaluate_string(context).await?;

        // Parse the range
        let (start, end) = StringSliceCommandParser::parse_range(&range_value)?;

        let ret = if start <= end {
            if string_value.is_char_boundary(start) && string_value.is_char_boundary(end) {
                string_value.get(start..end)
            } else {
                let msg = format!(
                    "Invalid slice range {}:{} for string '{}'",
                    start, end, string_value
                );
                error!("{}", msg);
                None
            }
        } else {
            None
        };

        match ret {
            Some(sliced) => {
                info!(
                    "Sliced string: {}[{}:{}] = {}",
                    string_value, start, end, sliced
                );
                Ok(CommandResult::success_with_value(sliced))
            }
            None => {
                let msg = format!(
                    "Slice range {}:{} is invalid for string '{}'",
                    start, end, string_value
                );
                warn!("{}", msg);
                Ok(CommandResult::error())
            }
        }
    }
}

// strlen <string>
// This command returns the length of a string
pub struct StringLengthCommandParser {
    cmd: Command,
}

impl StringLengthCommandParser {
    pub fn new() -> Self {
        let cmd = Command::new("strlen")
            .about("Return the character length of a string.")
            .after_help(
                r#"
Arguments:
  <string>     The input string to measure.

Behavior:
  - Returns the number of bytes.
  - Does not modify environment or variables.

Examples:
  strlen "abc"
  strlen "你好"
  strlen $REQ.path
"#,
            )
            .arg(
                Arg::new("string")
                    .required(true)
                    .help("Input string to measure"),
            );

        Self { cmd }
    }
}

impl CommandParser for StringLengthCommandParser {
    fn group(&self) -> CommandGroup {
        CommandGroup::String
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
                let msg = format!("Invalid string length command: {:?}, {}", str_args, e);
                error!("{}", msg);
                msg
            })?;

        let string_index = matches.index_of("string").ok_or_else(|| {
            let msg = format!("String value is required, but got: {:?}", args);
            error!("{}", msg);
            msg
        })?;

        let string_value = args[string_index].clone();

        let cmd = StringLengthCommand::new(string_value);

        Ok(Arc::new(Box::new(cmd)))
    }
}

pub struct StringLengthCommand {
    string: CommandArg,
}

impl StringLengthCommand {
    pub fn new(string: CommandArg) -> Self {
        Self { string }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for StringLengthCommand {
    async fn exec(&self, context: &Context) -> Result<super::CommandResult, String> {
        // Evaluate the string argument
        let string_value = self.string.evaluate_string(context).await?;

        // Calculate the length
        let length = string_value.len();

        info!("String length of '{}': {}", string_value, length);

        // Return the length as a command result
        Ok(super::CommandResult::success_with_value(length.to_string()))
    }
}

// starts-with <string> <prefix>
// This command checks if a string starts with a given prefix

pub struct StringStartsWithCommandParser {
    cmd: Command,
}

impl StringStartsWithCommandParser {
    pub fn new() -> Self {
        let cmd = Command::new("starts-with")
            .about("Check if a string starts with the given prefix.")
            .after_help(
                r#"
Arguments:
  <string>     The full input string.
  <prefix>     The prefix to check.

Options:
  --ignore-case,-i   Perform case-insensitive comparison

Behavior:
  - Returns true if <string> begins with <prefix>.
  - Comparison is case-sensitive by default.
  - Does not modify any variable or environment.

Examples:
  starts-with "hello world" "hello"     → true
  starts-with $REQ.url "/api/"          → true
  starts-with "example.com" "test"      → false
"#,
            )
            .arg(
                Arg::new("ignore_case")
                    .long("ignore-case")
                    .short('i')
                    .action(ArgAction::SetTrue)
                    .help("Perform case-insensitive comparison"),
            )
            .arg(
                Arg::new("string")
                    .required(true)
                    .help("Input string to check"),
            )
            .arg(
                Arg::new("prefix")
                    .required(true)
                    .help("Prefix to test against"),
            );

        Self { cmd }
    }
}

impl CommandParser for StringStartsWithCommandParser {
    fn group(&self) -> CommandGroup {
        CommandGroup::String
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
                let msg = format!("Invalid string starts-with command: {:?}, {}", str_args, e);
                error!("{}", msg);
                msg
            })?;

        let ignore_case = matches.get_flag("ignore_case");

        let string_index = matches.index_of("string").ok_or_else(|| {
            let msg = format!("String value is required, but got: {:?}", args);
            error!("{}", msg);
            msg
        })?;
        let string_value = args[string_index].clone();

        let prefix_index = matches.index_of("prefix").ok_or_else(|| {
            let msg = format!("Prefix is required, but got: {:?}", args);
            error!("{}", msg);
            msg
        })?;
        let prefix = args[prefix_index].clone();

        let cmd = StringStartsWithCommand::new(string_value, prefix, ignore_case);

        Ok(Arc::new(Box::new(cmd)))
    }
}

pub struct StringStartsWithCommand {
    ignore_case: bool,
    string: CommandArg,
    prefix: CommandArg,
}

impl StringStartsWithCommand {
    pub fn new(string: CommandArg, prefix: CommandArg, ignore_case: bool) -> Self {
        Self {
            string,
            prefix,
            ignore_case,
        }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for StringStartsWithCommand {
    async fn exec(&self, context: &Context) -> Result<super::CommandResult, String> {
        // Evaluate the string and prefix arguments
        let string_value = self.string.evaluate_string(context).await?;
        let prefix = self.prefix.evaluate_string(context).await?;

        let starts_with = if self.ignore_case {
            string_value
                .to_lowercase()
                .starts_with(&prefix.to_lowercase())
        } else {
            string_value.starts_with(&prefix)
        };

        // This command is frequently used in routing rules; logging every false
        // predicate at INFO is noisy. Keep a single INFO line only on matches,
        // and leave the full trace at DEBUG when needed.
        if starts_with {
            info!("starts-with matched str='{}' prefix='{}'", string_value, prefix);
        } else {
            debug!("starts-with not-matched str='{}' prefix='{}'", string_value, prefix);
        }

        if starts_with {
            Ok(super::CommandResult::success_with_value("true"))
        } else {
            Ok(super::CommandResult::error_with_value("false"))
        }
    }
}

// ends-with <string> <suffix>
// This command checks if a string ends with a given suffix
pub struct StringEndsWithCommandParser {
    cmd: Command,
}

impl StringEndsWithCommandParser {
    pub fn new() -> Self {
        let cmd = Command::new("ends-with")
            .about("Check if a string ends with the given suffix.")
            .after_help(
                r#"
Arguments:
  <string>   The full input string.
  <suffix>   The suffix to check.

Options:
  --ignore-case,-i   Perform case-insensitive comparison

Behavior:

    - Returns true if <string> ends with <suffix>.
    - Comparison is case-sensitive by default.
    - Does not modify any variable or environment.

Examples:
  ends-with "hello world" "world"       → true
  ends-with $REQ.url ".html"            → false
  ends-with "example.com" ".com"        → true
"#,
            )
            .arg(
                Arg::new("ignore_case")
                    .long("ignore-case")
                    .short('i')
                    .action(ArgAction::SetTrue)
                    .help("Perform case-insensitive comparison"),
            )
            .arg(
                Arg::new("string")
                    .required(true)
                    .help("Input string to check"),
            )
            .arg(
                Arg::new("suffix")
                    .required(true)
                    .help("Suffix to test against"),
            );

        Self { cmd }
    }
}

impl CommandParser for StringEndsWithCommandParser {
    fn group(&self) -> CommandGroup {
        CommandGroup::String
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
                let msg = format!("Invalid string ends-with command: {:?}, {}", str_args, e);
                error!("{}", msg);
                msg
            })?;

        let ignore_case = matches.get_flag("ignore_case");

        let string_index = matches.index_of("string").ok_or_else(|| {
            let msg = format!("String value is required, but got: {:?}", args);
            error!("{}", msg);
            msg
        })?;
        let string_value = args[string_index].clone();

        let suffix_index = matches.index_of("suffix").ok_or_else(|| {
            let msg = format!("Suffix is required, but got: {:?}", args);
            error!("{}", msg);
            msg
        })?;
        let suffix = args[suffix_index].clone();

        let cmd = StringEndsWithCommand::new(string_value, suffix, ignore_case);

        Ok(Arc::new(Box::new(cmd)))
    }
}

pub struct StringEndsWithCommand {
    ignore_case: bool,
    string: CommandArg,
    suffix: CommandArg,
}

impl StringEndsWithCommand {
    pub fn new(string: CommandArg, suffix: CommandArg, ignore_case: bool) -> Self {
        Self {
            string,
            suffix,
            ignore_case,
        }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for StringEndsWithCommand {
    async fn exec(&self, context: &Context) -> Result<super::CommandResult, String> {
        // Evaluate the string and suffix arguments
        let string_value = self.string.evaluate_string(context).await?;
        let suffix = self.suffix.evaluate_string(context).await?;

        let ends_with = if self.ignore_case {
            string_value
                .to_lowercase()
                .ends_with(&suffix.to_lowercase())
        } else {
            string_value.ends_with(&suffix)
        };

        if ends_with {
            info!("ends-with matched str='{}' suffix='{}'", string_value, suffix);
        } else {
            debug!("ends-with not-matched str='{}' suffix='{}'", string_value, suffix);
        }

        if ends_with {
            Ok(super::CommandResult::success_with_value("true"))
        } else {
            Ok(super::CommandResult::error_with_value("false"))
        }
    }
}
