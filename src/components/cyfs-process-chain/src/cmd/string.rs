use super::cmd::*;
use crate::block::CommandArgs;
use crate::chain::Context;
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
    fn help(&self, _name: &str, help_type: super::CommandHelpType) -> String {
        command_help(help_type, &self.cmd)
    }

    fn check(&self, args: &CommandArgs) -> Result<(), String> {
        let matches = self
            .cmd
            .clone()
            .try_get_matches_from(args.as_str_list())
            .map_err(|e| {
                let msg = format!("Invalid rewrite command: {:?}, {}", args, e);
                error!("{}", msg);
                msg
            })?;

        // The var must be a variable
        let var_index = matches.index_of("var").unwrap();
        if !args[var_index].is_var() {
            let msg = format!(
                "Invalid rewrite command: {:?}, the var argument must be a variable",
                args
            );
            error!("{}", msg);
            return Err(msg);
        }

        // Check the pattern if is a valid glob
        let pattern_index = matches.index_of("pattern").unwrap();
        if args[pattern_index].is_literal() {
            let pattern = args[pattern_index].as_literal_str().unwrap();
            if let Err(e) = GlobBuilder::new(pattern).case_insensitive(true).build() {
                let msg = format!("Invalid glob pattern: {}, {}", pattern, e);
                error!("{}", msg);
                return Err(msg);
            }
        }

        Ok(())
    }

    fn parse(
        &self,
        args: Vec<String>,
        origin_args: &CommandArgs,
    ) -> Result<CommandExecutorRef, String> {
        let matches = self.cmd.clone().try_get_matches_from(&args).map_err(|e| {
            let msg = format!("Invalid rewrite command: {:?}, {}", args, e);
            error!("{}", msg);
            msg
        })?;

        let key_value = matches
            .get_one::<String>("var")
            .ok_or_else(|| {
                let msg = format!("Variable name is required, but got: {:?}", args);
                error!("{}", msg);
                msg
            })?
            .to_owned();

        let key_index = matches.index_of("var").unwrap();
        let key = &origin_args[key_index].as_var_str().unwrap();

        let pattern_value = matches
            .get_one::<String>("pattern")
            .ok_or_else(|| {
                let msg = format!("Pattern is required, but got: {:?}", args);
                error!("{}", msg);
                msg
            })?
            .to_owned();

        let pattern = GlobBuilder::new(&pattern_value)
            .case_insensitive(true)
            .build()
            .map_err(|e| {
                let msg = format!("Invalid glob pattern: {}: {}", pattern_value, e);
                error!("{}", msg);
                msg
            })?
            .compile_matcher();

        let template = matches
            .get_one::<String>("template")
            .ok_or_else(|| {
                let msg = format!("Template is required, but got: {:?}", args);
                error!("{}", msg);
                msg
            })?
            .to_owned();

        let cmd = RewriteCommand::new(
            key.to_string(),
            pattern,
            key_value,
            pattern_value.to_owned(),
            template,
        );

        Ok(Arc::new(Box::new(cmd)))
    }
}

pub struct RewriteCommand {
    key: String,
    pattern: GlobMatcher,

    key_value: String,
    pattern_value: String,
    template: String,
}

impl RewriteCommand {
    pub fn new(
        key: String,
        pattern: GlobMatcher,
        key_value: String,
        pattern_value: String,
        template: String,
    ) -> Self {
        Self {
            key,
            pattern,
            key_value,
            pattern_value,
            template,
        }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for RewriteCommand {
    async fn exec(&self, context: &Context) -> Result<super::CommandResult, String> {
        if self.pattern.is_match(&self.key_value) {
            if let Some(prefix) = self.pattern_value.strip_suffix("*") {
                if self.key_value.starts_with(prefix) && self.template.ends_with('*') {
                    let tail = &self.key_value[prefix.len()..];
                    let rewritten =
                        format!("{}{}", &self.template[..self.template.len() - 1], tail);
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
                        self.key, self.key_value, rewritten
                    );

                    Ok(CommandResult::success_with_value(rewritten))
                } else {
                    let msg = format!(
                        "Pattern '{}' did not match '{}', expected prefix '{}'",
                        self.pattern_value, self.key_value, prefix
                    );
                    info!("{}", msg);
                    Ok(CommandResult::success())
                }
            } else {
                info!(
                    "Pattern '{}' matched '{}', setting to template '{}'",
                    self.pattern_value, self.key_value, self.template
                );
                context
                    .env()
                    .set(
                        self.key.as_str(),
                        CollectionValue::String(self.template.clone()),
                        None,
                    )
                    .await?;

                Ok(CommandResult::success_with_value(self.template.clone()))
            }
        } else {
            info!(
                "Pattern '{}' did not match '{}'",
                self.pattern_value, self.key_value
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
    fn help(&self, _name: &str, help_type: super::CommandHelpType) -> String {
        command_help(help_type, &self.cmd)
    }

    fn check(&self, args: &CommandArgs) -> Result<(), String> {
        let matches = self
            .cmd
            .clone()
            .try_get_matches_from(args.as_str_list())
            .map_err(|e| {
                let msg = format!("Invalid rewrite-regex command: {:?}, {}", args, e);
                error!("{}", msg);
                msg
            })?;

        // The var argument must be a variable
        let var_index = matches.index_of("var").unwrap();
        if !args[var_index].is_var() {
            let msg = format!(
                "Invalid rewrite-regex command: {:?}, the first argument must be a variable",
                args
            );
            error!("{}", msg);
            return Err(msg);
        }

        // The regex argument must be a valid regex pattern if is literal
        let regex_index = matches.index_of("regex").unwrap();
        if args[regex_index].is_literal() {
            let pattern = args[regex_index].as_literal_str().unwrap();
            if let Err(e) = regex::Regex::new(pattern) {
                let msg = format!("Invalid regex pattern: {}, {}", pattern, e);
                error!("{}", msg);
                return Err(msg);
            }
        }

        Ok(())
    }

    fn parse(
        &self,
        args: Vec<String>,
        origin_args: &CommandArgs,
    ) -> Result<CommandExecutorRef, String> {
        let matches = self.cmd.clone().try_get_matches_from(&args).map_err(|e| {
            let msg = format!("Invalid rewrite-regex command: {:?}, {}", args, e);
            error!("{}", msg);
            msg
        })?;

        let key_value = matches
            .get_one::<String>("var")
            .ok_or_else(|| {
                let msg = format!("Variable name is required, but got: {:?}", args);
                error!("{}", msg);
                msg
            })?
            .to_owned();
        let key_index = matches.index_of("var").unwrap();
        let key_arg = &origin_args[key_index];
        if !key_arg.is_var() {
            let msg = format!(
                "Invalid rewrite-regex command: {:?}, the first argument must be a variable",
                args
            );
            error!("{}", msg);
            return Err(msg);
        }
        let key = key_arg.as_var_str().unwrap();

        let regex = matches.get_one::<String>("regex").ok_or_else(|| {
            let msg = format!("Regex pattern is required, but got: {:?}", args);
            error!("{}", msg);
            msg
        })?;

        let regex = regex::Regex::new(&regex).map_err(|e| {
            let msg = format!("Invalid regex pattern: {}: {}", regex, e);
            error!("{}", msg);
            msg
        })?;

        let template = matches
            .get_one::<String>("template")
            .ok_or_else(|| {
                let msg = format!("Template is required, but got: {:?}", args);
                error!("{}", msg);
                msg
            })?
            .to_owned();

        let cmd = RewriteRegexCommand::new(key.to_string(), key_value, regex, template);

        Ok(Arc::new(Box::new(cmd)))
    }
}

pub struct RewriteRegexCommand {
    key: String,
    key_value: String,
    regex: regex::Regex,
    template: String,
}

impl RewriteRegexCommand {
    pub fn new(key: String, key_value: String, regex: regex::Regex, template: String) -> Self {
        Self {
            key,
            key_value,
            regex,
            template,
        }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for RewriteRegexCommand {
    async fn exec(&self, context: &Context) -> Result<super::CommandResult, String> {
        let key_value = &self.key_value;
        let template = &self.template;

        if let Some(captures) = self.regex.captures(key_value) {
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
            info!("Rewritten value for {}: {}", self.key, result);

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
  --ignore-case   Perform case-insensitive comparison

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
    fn help(&self, _name: &str, help_type: CommandHelpType) -> String {
        command_help(help_type, &self.cmd)
    }

    fn check(&self, args: &CommandArgs) -> Result<(), String> {
        let matches = self
            .cmd
            .clone()
            .try_get_matches_from(args.as_str_list())
            .map_err(|e| {
                let msg = format!("Invalid string replace command: {:?}, {}", args, e);
                error!("{}", msg);
                msg
            })?;

        let var_index = matches.index_of("var").unwrap();

        // The var argument must be a variable
        if !args[var_index].is_var() {
            let msg = format!(
                "Invalid string replace command: {:?}, the first argument must be a variable",
                args
            );
            error!("{}", msg);
            return Err(msg);
        }

        Ok(())
    }

    fn parse(
        &self,
        args: Vec<String>,
        origin_args: &CommandArgs,
    ) -> Result<CommandExecutorRef, String> {
        let matches = self.cmd.clone().try_get_matches_from(&args).map_err(|e| {
            let msg = format!("Invalid string replace command: {:?}, {}", args, e);
            error!("{}", msg);
            msg
        })?;

        let key_value = matches
            .get_one::<String>("var")
            .ok_or_else(|| {
                let msg = format!("Variable name is required, but got: {:?}", args);
                error!("{}", msg);
                msg
            })?
            .to_owned();

        let key_index = matches.index_of("var").unwrap();
        let key_arg = &origin_args.as_slice()[key_index];
        if !key_arg.is_var() {
            let msg = format!(
                "Invalid string-replace command: {:?}, the first argument must be a variable",
                args
            );
            error!("{}", msg);
            return Err(msg);
        }
        let key = key_arg.as_var_str().unwrap();

        let match_text = matches
            .get_one::<String>("match")
            .ok_or_else(|| {
                let msg = format!("Match text is required, but got: {:?}", args);
                error!("{}", msg);
                msg
            })?
            .to_owned();

        let new_text = matches
            .get_one::<String>("replacement")
            .ok_or_else(|| {
                let msg = format!("Replacement text is required, but got: {:?}", args);
                error!("{}", msg);
                msg
            })?
            .to_owned();

        let ignore_case = matches.get_flag("ignore_case");
        let cmd = StringReplaceCommand::new(
            ignore_case,
            key.to_string(),
            key_value,
            match_text,
            new_text,
        );

        Ok(Arc::new(Box::new(cmd)))
    }
}

pub struct StringReplaceCommand {
    ignore_case: bool,
    key: String,
    key_value: String,
    match_text: String,
    new_text: String,
}

impl StringReplaceCommand {
    pub fn new(
        ignore_case: bool,
        key: String,
        key_value: String,
        match_text: String,
        new_text: String,
    ) -> Self {
        Self {
            ignore_case,
            key,
            key_value,
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
        let key_value = &self.key_value;
        let match_text = &self.match_text;
        let new_text = &self.new_text;

        let rewritten = if self.ignore_case {
            if key_value
                .to_lowercase()
                .contains(&match_text.to_lowercase())
            {
                let rewritten = Self::replace_case_insensitive(key_value, match_text, new_text);
                Some(rewritten)
            } else {
                None
            }
        } else {
            if key_value.contains(match_text) {
                let rewritten = Self::replace_case_sensitive(key_value, match_text, new_text);
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
            info!("Replace value for {}: {}", self.key, rewritten);

            Ok(super::CommandResult::success_with_value(rewritten))
        } else {
            Ok(super::CommandResult::error())
        }
    }
}

// append <param1> <param2>
// This command appends param2 to param1, and return the result
// If param1 is a variable, it will modify the variable to hold the new value
pub struct StringAppendCommandParser {
    cmd: Command,
}

impl StringAppendCommandParser {
    pub fn new() -> Self {
        let cmd = Command::new("append")
            .about("Append two string parameters and return the result.")
            .after_help(
                r#"
Arguments:
  <param1>     First string or variable
  <param2>     Second string to append

Behavior:
  - Joins param1 and param2 with no delimiter.
  - Output is returned with success.
  - If param1 is a variable, it will be modified to hold the new value.

Examples:
  append "abc" "123"
  append $REQ.host ".internal"
"#,
            )
            .arg(Arg::new("param1").required(true).help("First value"))
            .arg(
                Arg::new("param2")
                    .required(true)
                    .help("Second value to append"),
            );

        Self { cmd }
    }
}

impl CommandParser for StringAppendCommandParser {
    fn help(&self, _name: &str, help_type: CommandHelpType) -> String {
        command_help(help_type, &self.cmd)
    }

    fn check(&self, args: &CommandArgs) -> Result<(), String> {
        self.cmd
            .clone()
            .try_get_matches_from(args.as_str_list())
            .map_err(|e| {
                let msg = format!("Invalid string append command: {:?}, {}", args, e);
                error!("{}", msg);
                msg
            })?;

        Ok(())
    }

    fn parse(
        &self,
        args: Vec<String>,
        origin_args: &CommandArgs,
    ) -> Result<CommandExecutorRef, String> {
        let matches = self.cmd.clone().try_get_matches_from(&args).map_err(|e| {
            let msg = format!("Invalid string append command: {:?}, {}", args, e);
            error!("{}", msg);
            msg
        })?;

        let param1 = matches.get_one::<String>("param1").ok_or_else(|| {
            let msg = format!("First parameter is required, but got: {:?}", args);
            error!("{}", msg);
            msg
        })?;
        let param2 = matches.get_one::<String>("param2").ok_or_else(|| {
            let msg = format!("Second parameter is required, but got: {:?}", args);
            error!("{}", msg);
            msg
        })?;

        let param1_index = matches.index_of("param1").unwrap();
        let var = if origin_args[param1_index].is_var() {
            // If param1 is a variable, we should modify it
            Some(origin_args[param1_index].as_var_str().unwrap().to_owned())
        } else {
            None
        };

        let result = param1.to_string() + param2;
        info!("String append {} + {} = {}", param1, param2, result);

        let cmd = StringAppendCommand::new(var, result);

        Ok(Arc::new(Box::new(cmd)))
    }
}

pub struct StringAppendCommand {
    var: Option<String>,
    result: String,
}

impl StringAppendCommand {
    pub fn new(var: Option<String>, result: String) -> Self {
        Self { var, result }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for StringAppendCommand {
    async fn exec(&self, context: &Context) -> Result<super::CommandResult, String> {
        if let Some(var) = &self.var {
            // If a variable is specified, set it in the environment
            context
                .env()
                .set(var, CollectionValue::String(self.result.clone()), None)
                .await?;
            info!("Set variable {} to {}", var, self.result);
        }

        // Return the result as a command result
        Ok(super::CommandResult::success_with_value(&self.result))
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
    fn help(&self, _name: &str, help_type: CommandHelpType) -> String {
        command_help(help_type, &self.cmd)
    }

    fn check(&self, args: &CommandArgs) -> Result<(), String> {
        // Args should have exactly two elements
        let matches = self
            .cmd
            .clone()
            .try_get_matches_from(args.as_str_list())
            .map_err(|e| {
                let msg = format!("Invalid string slice command: {:?}, {}", args, e);
                error!("{}", msg);
                msg
            })?;

        // Check if range argument is literal and valid
        let range_index = matches.index_of("range").unwrap();
        if args[range_index].is_literal() {
            let range = args[range_index].as_literal_str().unwrap();
            Self::parse_range(range)?;
        }

        Ok(())
    }

    fn parse(
        &self,
        args: Vec<String>,
        _origin_args: &CommandArgs,
    ) -> Result<CommandExecutorRef, String> {
        let matches = self.cmd.clone().try_get_matches_from(&args).map_err(|e| {
            let msg = format!("Invalid string slice command: {:?}, {}", args, e);
            error!("{}", msg);
            msg
        })?;

        let string_value = matches
            .get_one::<String>("string")
            .ok_or_else(|| {
                let msg = format!("String value is required, but got: {:?}", args);
                error!("{}", msg);
                msg
            })?
            .to_owned();
        let range = matches.get_one::<String>("range").ok_or_else(|| {
            let msg = format!("Range is required, but got: {:?}", args);
            error!("{}", msg);
            msg
        })?;

        let (start, end) = Self::parse_range(&range)?;

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

        let ret = ret.unwrap_or_default().to_string();
        info!("String slice {}[{}:{}] = {}", string_value, start, end, ret);

        let cmd = StringConstCommand::new(ret);

        Ok(Arc::new(Box::new(cmd)))
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
    fn help(&self, _name: &str, help_type: CommandHelpType) -> String {
        command_help(help_type, &self.cmd)
    }

    fn check(&self, args: &CommandArgs) -> Result<(), String> {
        self.cmd
            .clone()
            .try_get_matches_from(args.as_str_list())
            .map_err(|e| {
                let msg = format!("Invalid string length command: {:?}, {}", args, e);
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
            let msg = format!("Invalid string length command: {:?}, {}", args, e);
            error!("{}", msg);
            msg
        })?;

        let string_value = matches.get_one::<String>("string").ok_or_else(|| {
            let msg = format!("String value is required, but got: {:?}", args);
            error!("{}", msg);
            msg
        })?;
        let length = string_value.len();

        let cmd = StringConstCommand::new(length.to_string());

        Ok(Arc::new(Box::new(cmd)))
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
    fn help(&self, _name: &str, help_type: CommandHelpType) -> String {
        command_help(help_type, &self.cmd)
    }

    fn check(&self, args: &CommandArgs) -> Result<(), String> {
        self.cmd
            .clone()
            .try_get_matches_from(args.as_str_list())
            .map_err(|e| {
                let msg = format!("Invalid string starts-with command: {:?}, {}", args, e);
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
            let msg = format!("Invalid string starts-with command: {:?}, {}", args, e);
            error!("{}", msg);
            msg
        })?;

        let string_value = matches.get_one::<String>("string").ok_or_else(|| {
            let msg = format!("String value is required, but got: {:?}", args);
            error!("{}", msg);
            msg
        })?;
        let prefix = matches.get_one::<String>("prefix").ok_or_else(|| {
            let msg = format!("Prefix is required, but got: {:?}", args);
            error!("{}", msg);
            msg
        })?;

        let starts_with = string_value.starts_with(prefix);
        info!(
            "String '{}' starts with '{}': {}",
            string_value, prefix, starts_with
        );

        let cmd = StringConstCommand::new(starts_with.to_string());

        Ok(Arc::new(Box::new(cmd)))
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
<suffix>     The suffix to check.
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
    fn help(&self, _name: &str, help_type: CommandHelpType) -> String {
        command_help(help_type, &self.cmd)
    }

    fn check(&self, args: &CommandArgs) -> Result<(), String> {
        self.cmd
            .clone()
            .try_get_matches_from(args.as_str_list())
            .map_err(|e| {
                let msg = format!("Invalid string ends-with command: {:?}, {}", args, e);
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
            let msg = format!("Invalid string ends-with command: {:?}, {}", args, e);
            error!("{}", msg);
            msg
        })?;

        let string_value = matches.get_one::<String>("string").ok_or_else(|| {
            let msg = format!("String value is required, but got: {:?}", args);
            error!("{}", msg);
            msg
        })?;
        let suffix = matches.get_one::<String>("suffix").ok_or_else(|| {
            let msg = format!("Suffix is required, but got: {:?}", args);
            error!("{}", msg);
            msg
        })?;

        let ends_with = string_value.ends_with(suffix);
        info!(
            "String '{}' ends with '{}': {}",
            string_value, suffix, ends_with
        );

        let cmd = StringConstCommand::new(ends_with.to_string());

        Ok(Arc::new(Box::new(cmd)))
    }
}
