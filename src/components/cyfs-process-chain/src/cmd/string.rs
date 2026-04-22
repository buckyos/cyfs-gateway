use super::cmd::*;
use super::template::TemplateMatcher;
use crate::block::{CommandArg, CommandArgEvaluator, CommandArgs};
use crate::chain::{Context, ParserContext};
use crate::collection::{CollectionValue, MemoryListCollection, NumberValue};
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
  <pattern>   A case-insensitive glob pattern to match
  <template>  The replacement string or trailing-* template

Behavior:
  - Performs case-insensitive glob pattern matching.
  - If <pattern> does not match, returns error and leaves the variable unchanged.
  - If <pattern> ends with '*' and <template> also ends with '*', preserves the
    matched suffix by appending it to <template> without its trailing '*'.
  - Otherwise, if <pattern> matches, rewrites the variable to <template> as-is.

Examples:
  rewrite $REQ.url "/kapi/my-service/*" "/kapi/*"
  rewrite $REQ.host "*.example.com" "backend.internal"
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

                    Ok(CommandResult::success_with_string(rewritten))
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

                Ok(CommandResult::success_with_string(
                    template_value.to_owned(),
                ))
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
        let cmd = Command::new("rewrite-reg")
            .about("Rewrite a variable using a regular expression and a replacement template.")
            .after_help(
                r#"
Arguments:
  <var>        The name of the variable to rewrite (e.g. $REQ.url)
  <regex>      Regular expression pattern to match (with capture groups)
  <template>   Replacement string using $1, $2, ... for captured groups

Behavior:
  - If the regex matches, rewrites the variable with the template.
  - Only '$' followed by one ASCII digit is treated as a capture reference.
    Other '$' characters are kept literally.
  - Unmatched captures are replaced with empty strings.
  - If the pattern does not match, returns error and leaves the variable unchanged.

Examples:
  rewrite-reg $REQ.url "^/test/(\\w+)(?:/(\\d+))?" "/new/$1/$2"
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

            Ok(CommandResult::success_with_string(result))
        } else {
            Ok(CommandResult::error())
        }
    }
}

#[derive(Clone, Copy)]
struct TemplateRewriteDefaults {
    separator: char,
    ignore_case: bool,
}

pub struct RewritePathCommandParser {
    cmd: Command,
}

impl RewritePathCommandParser {
    pub fn new() -> Self {
        let cmd = Command::new("rewrite-path")
            .about("Rewrite a path-like variable using segment templates.")
            .after_help(
                r#"
Arguments:
  <var>       The path-like variable to rewrite (e.g. $REQ.path)
  <pattern>   The template pattern to match against
  <template>  The rewrite template using {name} and optional ** rest splice

Options:
  --ignore-case   Perform case-insensitive matching (default is case-sensitive)

Behavior:
  - Uses '/' as the default segment separator.
  - <pattern> and <template> are evaluated dynamically at runtime.
  - <pattern> follows the same template rules as match-path:
      {name} captures one segment and ** matches the remaining segments at the end.
  - <template> can reference named captures using {name}.
  - If <pattern> contains **, <template> may include a segment ** to splice the matched remaining segments.
  - If <pattern> does not match, returns error and leaves the variable unchanged.

Examples:
  rewrite-path $REQ.path "/kapi/{service}/**" "/api/{service}/**"
  rewrite-path $REQ.path "${route_prefix}/{node}/{plane}/**" "/klog/{node}/{plane}/**"
"#,
            )
            .arg(
                Arg::new("ignore_case")
                    .long("ignore-case")
                    .action(ArgAction::SetTrue)
                    .help("Perform case-insensitive matching (default is case-sensitive)"),
            )
            .arg(Arg::new("var").required(true).help("The variable to rewrite"))
            .arg(
                Arg::new("pattern")
                    .required(true)
                    .help("The template pattern to match"),
            )
            .arg(
                Arg::new("template")
                    .required(true)
                    .help("The rewrite template"),
            );

        Self { cmd }
    }
}

impl CommandParser for RewritePathCommandParser {
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
        parse_template_rewrite_command(
            &self.cmd,
            "rewrite-path",
            str_args,
            args,
            TemplateRewriteDefaults {
                separator: '/',
                ignore_case: false,
            },
            Some("ignore_case"),
            None,
        )
    }
}

pub struct RewriteHostCommandParser {
    cmd: Command,
}

impl RewriteHostCommandParser {
    pub fn new() -> Self {
        let cmd = Command::new("rewrite-host")
            .about("Rewrite a host-like variable using segment templates.")
            .after_help(
                r#"
Arguments:
  <var>       The host-like variable to rewrite (e.g. $REQ.host)
  <pattern>   The template pattern to match against
  <template>  The rewrite template using {name} and optional ** rest splice

Options:
  --no-ignore-case   Perform case-sensitive matching (default is case-insensitive)

Behavior:
  - Uses '.' as the default segment separator.
  - <pattern> and <template> are evaluated dynamically at runtime.
  - <pattern> follows the same template rules as match-host:
      {name} captures one host label and ** matches the remaining labels at the end.
  - <template> can reference named captures using {name}.
  - If <pattern> contains **, <template> may include a segment ** to splice the matched remaining labels.
  - If <pattern> does not match, returns error and leaves the variable unchanged.

Examples:
  rewrite-host $REQ.host "{app}.${zone}" "{app}-internal.{zone}"
  rewrite-host $REQ.host "{app}.**" "{app}.internal.**"
"#,
            )
            .arg(
                Arg::new("no_ignore_case")
                    .long("no-ignore-case")
                    .action(ArgAction::SetTrue)
                    .help("Perform case-sensitive matching (default is case-insensitive)"),
            )
            .arg(Arg::new("var").required(true).help("The variable to rewrite"))
            .arg(
                Arg::new("pattern")
                    .required(true)
                    .help("The template pattern to match"),
            )
            .arg(
                Arg::new("template")
                    .required(true)
                    .help("The rewrite template"),
            );

        Self { cmd }
    }
}

impl CommandParser for RewriteHostCommandParser {
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
        parse_template_rewrite_command(
            &self.cmd,
            "rewrite-host",
            str_args,
            args,
            TemplateRewriteDefaults {
                separator: '.',
                ignore_case: true,
            },
            None,
            Some("no_ignore_case"),
        )
    }
}

fn parse_template_rewrite_command(
    cmd: &Command,
    command_name: &str,
    str_args: Vec<&str>,
    args: &CommandArgs,
    defaults: TemplateRewriteDefaults,
    ignore_case_flag: Option<&str>,
    no_ignore_case_flag: Option<&str>,
) -> Result<CommandExecutorRef, String> {
    let matches = cmd.clone().try_get_matches_from(&str_args).map_err(|e| {
        let msg = format!("Invalid {} command: {:?}, {}", command_name, str_args, e);
        error!("{}", msg);
        msg
    })?;

    let key_index = matches.index_of("var").ok_or_else(|| {
        let msg = format!("Variable name is required for {} command", command_name);
        error!("{}", msg);
        msg
    })?;
    let key = args[key_index].clone();
    if !key.is_var() {
        let msg = format!(
            "Invalid {} command: {:?}, the first argument must be a variable",
            command_name, args
        );
        error!("{}", msg);
        return Err(msg);
    }

    let pattern_index = matches.index_of("pattern").ok_or_else(|| {
        let msg = format!("Pattern is required for {} command", command_name);
        error!("{}", msg);
        msg
    })?;
    let pattern = args[pattern_index].clone();

    let template_index = matches.index_of("template").ok_or_else(|| {
        let msg = format!("Template is required for {} command", command_name);
        error!("{}", msg);
        msg
    })?;
    let template = args[template_index].clone();

    let ignore_case = if let Some(flag) = ignore_case_flag {
        matches.get_flag(flag)
    } else if let Some(flag) = no_ignore_case_flag {
        !matches.get_flag(flag)
    } else {
        defaults.ignore_case
    };

    let exec = TemplateRewriteCommand::new(
        command_name.to_owned(),
        key,
        pattern,
        template,
        defaults.separator,
        ignore_case,
    );
    Ok(Arc::new(Box::new(exec)))
}

pub struct TemplateRewriteCommand {
    command_name: String,
    key: CommandArg,
    pattern: CommandArg,
    template: CommandArg,
    separator: char,
    ignore_case: bool,
}

impl TemplateRewriteCommand {
    pub fn new(
        command_name: String,
        key: CommandArg,
        pattern: CommandArg,
        template: CommandArg,
        separator: char,
        ignore_case: bool,
    ) -> Self {
        Self {
            command_name,
            key,
            pattern,
            template,
            separator,
            ignore_case,
        }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for TemplateRewriteCommand {
    async fn exec(&self, context: &Context) -> Result<super::CommandResult, String> {
        let key_value = self.key.evaluate_string(context).await?;
        let pattern = self.pattern.evaluate_string(context).await?;
        let template = self.template.evaluate_string(context).await?;
        let matcher = TemplateMatcher::new(&self.command_name, self.separator, self.ignore_case);

        if let Some(rewritten) = matcher.rewrite(&key_value, &pattern, &template)? {
            context
                .env()
                .set(
                    self.key.as_str(),
                    CollectionValue::String(rewritten.clone()),
                    None,
                )
                .await?;
            info!(
                "Rewritten value for {} via {}: {} -> {}",
                self.key.as_str(),
                self.command_name,
                key_value,
                rewritten
            );

            Ok(CommandResult::success_with_string(rewritten))
        } else {
            info!(
                "{} pattern '{}' did not match '{}'",
                self.command_name, pattern, key_value
            );
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

            Ok(super::CommandResult::success_with_string(rewritten))
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
        Ok(super::CommandResult::success_with_string(&result))
    }
}

fn percent_encode_url_component(input: &str) -> String {
    let mut encoded = String::with_capacity(input.len());
    for byte in input.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push_str(&format!("{:02X}", byte));
        }
    }

    encoded
}

fn decode_hex_digit(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(format!(
            "Invalid percent-encoded byte: '{}'",
            char::from(byte)
        )),
    }
}

fn percent_decode_url_component(input: &str) -> Result<String, String> {
    let bytes = input.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;

    while index < bytes.len() {
        match bytes[index] {
            b'%' => {
                if index + 2 >= bytes.len() {
                    let msg = format!("Incomplete percent-encoded sequence in '{}'", input);
                    error!("{}", msg);
                    return Err(msg);
                }

                let high = decode_hex_digit(bytes[index + 1])?;
                let low = decode_hex_digit(bytes[index + 2])?;
                decoded.push((high << 4) | low);
                index += 3;
            }
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }

    String::from_utf8(decoded).map_err(|e| {
        let msg = format!("Decoded URL string is not valid UTF-8: {}", e);
        error!("{}", msg);
        msg
    })
}

pub struct UrlEncodeCommandParser {
    cmd: Command,
}

impl UrlEncodeCommandParser {
    pub fn new() -> Self {
        let cmd = Command::new("url_encode")
            .about("Percent-encode a string so it can be safely embedded in a URL.")
            .after_help(
                r#"
Arguments:
  <string>     The input string or variable to encode.

Behavior:
  - Encodes reserved URL characters using percent-encoding.
  - Leaves RFC 3986 unreserved characters unchanged.
  - Does not modify environment or variables.

Examples:
  url_encode "https://example.com/callback?a=1&b=2"
  url_encode $REQ.url
"#,
            )
            .arg(
                Arg::new("string")
                    .required(true)
                    .help("Input string to percent-encode"),
            );

        Self { cmd }
    }
}

impl CommandParser for UrlEncodeCommandParser {
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
                let msg = format!("Invalid url_encode command: {:?}, {}", str_args, e);
                error!("{}", msg);
                msg
            })?;

        let string_index = matches.index_of("string").ok_or_else(|| {
            let msg = format!("String value is required, but got: {:?}", args);
            error!("{}", msg);
            msg
        })?;

        let string_value = args[string_index].clone();
        Ok(Arc::new(Box::new(UrlEncodeCommand::new(string_value))))
    }
}

pub struct UrlEncodeCommand {
    string: CommandArg,
}

impl UrlEncodeCommand {
    pub fn new(string: CommandArg) -> Self {
        Self { string }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for UrlEncodeCommand {
    async fn exec(&self, context: &Context) -> Result<super::CommandResult, String> {
        let string_value = self.string.evaluate_string(context).await?;
        let encoded = percent_encode_url_component(&string_value);
        Ok(super::CommandResult::success_with_string(encoded))
    }
}

pub struct UrlDecodeCommandParser {
    cmd: Command,
}

impl UrlDecodeCommandParser {
    pub fn new() -> Self {
        let cmd = Command::new("url_decode")
            .about("Decode a percent-encoded URL string.")
            .after_help(
                r#"
Arguments:
  <string>     The input string or variable to decode.

Behavior:
  - Decodes `%XX` escape sequences.
  - Returns a runtime error for malformed escape sequences or invalid UTF-8.
  - Does not modify environment or variables.

Examples:
  url_decode "https%3A%2F%2Fexample.com%2Fcallback%3Fa%3D1%26b%3D2"
  url_decode $encoded_url
"#,
            )
            .arg(
                Arg::new("string")
                    .required(true)
                    .help("Input string to percent-decode"),
            );

        Self { cmd }
    }
}

impl CommandParser for UrlDecodeCommandParser {
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
                let msg = format!("Invalid url_decode command: {:?}, {}", str_args, e);
                error!("{}", msg);
                msg
            })?;

        let string_index = matches.index_of("string").ok_or_else(|| {
            let msg = format!("String value is required, but got: {:?}", args);
            error!("{}", msg);
            msg
        })?;

        let string_value = args[string_index].clone();
        Ok(Arc::new(Box::new(UrlDecodeCommand::new(string_value))))
    }
}

pub struct UrlDecodeCommand {
    string: CommandArg,
}

impl UrlDecodeCommand {
    pub fn new(string: CommandArg) -> Self {
        Self { string }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for UrlDecodeCommand {
    async fn exec(&self, context: &Context) -> Result<super::CommandResult, String> {
        let string_value = self.string.evaluate_string(context).await?;
        let decoded = percent_decode_url_component(&string_value)?;
        Ok(super::CommandResult::success_with_string(decoded))
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
        Ok(super::CommandResult::success_with_string(&self.result))
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
                Ok(CommandResult::success_with_string(sliced))
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

// split <value> <delimiter>
// This command splits a string into segments and optionally stores them in a fresh List capture.
pub struct StringSplitCommandParser {
    cmd: Command,
}

impl StringSplitCommandParser {
    pub fn new() -> Self {
        let cmd = Command::new("split")
            .about("Split a string into segments using a delimiter.")
            .after_help(
                r#"
Arguments:
  <value>       The input string or variable.
  <delimiter>   The delimiter string used to split the input.

Options:
  --capture <name>   Store segments into a fresh List variable accessible as name[0], name[1], ...
  --skip-empty       Drop empty segments from the result

Behavior:
  - Both arguments are evaluated dynamically at runtime.
  - Returns a List of string segments.
  - By default, empty segments are preserved, including leading or trailing ones.
  - If --skip-empty is set, empty segments are removed from both the returned list and captured slots.
  - If --capture is set, <name> is replaced with a fresh List containing the split segments.
  - <name> must be a literal variable name or path.
  - Empty delimiter is invalid and returns a runtime error.

Examples:
  split "/a/b/c" "/"
  split --skip-empty "/.cluster/klog/ood1/admin/" "/"
  split --capture parts $REQ.path $delimiter
"#,
            )
            .arg(
                Arg::new("capture")
                    .long("capture")
                    .value_name("name")
                    .help("Store split segments into a fresh List variable"),
            )
            .arg(
                Arg::new("skip_empty")
                    .long("skip-empty")
                    .action(ArgAction::SetTrue)
                    .help("Drop empty segments from the result"),
            )
            .arg(
                Arg::new("value")
                    .required(true)
                    .help("Input string to split"),
            )
            .arg(
                Arg::new("delimiter")
                    .required(true)
                    .help("Delimiter string used for splitting"),
            );

        Self { cmd }
    }
}

impl CommandParser for StringSplitCommandParser {
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
                let msg = format!("Invalid string split command: {:?}, {}", str_args, e);
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

        let skip_empty = matches.get_flag("skip_empty");

        let value_index = matches.index_of("value").ok_or_else(|| {
            let msg = format!("Value is required, but got: {:?}", args);
            error!("{}", msg);
            msg
        })?;
        let value = args[value_index].clone();

        let delimiter_index = matches.index_of("delimiter").ok_or_else(|| {
            let msg = format!("Delimiter is required, but got: {:?}", args);
            error!("{}", msg);
            msg
        })?;
        let delimiter = args[delimiter_index].clone();

        let cmd = StringSplitCommand::new(value, delimiter, capture, skip_empty);

        Ok(Arc::new(Box::new(cmd)))
    }
}

pub struct StringSplitCommand {
    value: CommandArg,
    delimiter: CommandArg,
    capture: Option<String>,
    skip_empty: bool,
}

impl StringSplitCommand {
    pub fn new(
        value: CommandArg,
        delimiter: CommandArg,
        capture: Option<String>,
        skip_empty: bool,
    ) -> Self {
        Self {
            value,
            delimiter,
            capture,
            skip_empty,
        }
    }

    fn split_segments(
        value: &str,
        delimiter: &str,
        skip_empty: bool,
    ) -> Result<Vec<String>, String> {
        if delimiter.is_empty() {
            let msg = "Delimiter for split command cannot be empty".to_string();
            error!("{}", msg);
            return Err(msg);
        }

        Ok(value
            .split(delimiter)
            .filter(|segment| !skip_empty || !segment.is_empty())
            .map(|segment| segment.to_owned())
            .collect())
    }

    async fn build_list(segments: &[String]) -> Result<CollectionValue, String> {
        let list = MemoryListCollection::new_ref();
        for segment in segments {
            list.push(CollectionValue::String(segment.clone())).await?;
        }

        Ok(CollectionValue::List(list))
    }
}

#[async_trait::async_trait]
impl CommandExecutor for StringSplitCommand {
    async fn exec(&self, context: &Context) -> Result<super::CommandResult, String> {
        let value = self.value.evaluate_string(context).await?;
        let delimiter = self.delimiter.evaluate_string(context).await?;
        let segments = Self::split_segments(&value, &delimiter, self.skip_empty)?;

        if let Some(name) = &self.capture {
            let capture_list = Self::build_list(&segments).await?;
            context.env().set(name, capture_list, None).await?;
        }

        debug!(
            "split value='{}' delimiter='{}' skip_empty={} segments={:?} capture={:?}",
            value, delimiter, self.skip_empty, segments, self.capture
        );

        Ok(super::CommandResult::success_with_value(
            Self::build_list(&segments).await?,
        ))
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

        // Return the length as typed number result
        Ok(super::CommandResult::success_with_value(
            CollectionValue::Number(NumberValue::Int(length as i64)),
        ))
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
            info!(
                "starts-with matched str='{}' prefix='{}'",
                string_value, prefix
            );
        } else {
            debug!(
                "starts-with not-matched str='{}' prefix='{}'",
                string_value, prefix
            );
        }

        if starts_with {
            Ok(super::CommandResult::success_with_value(
                CollectionValue::Bool(true),
            ))
        } else {
            Ok(super::CommandResult::error_with_value(
                CollectionValue::Bool(false),
            ))
        }
    }
}

// strip-prefix <value> <prefix>
// This command removes a dynamic prefix from a string and returns the remaining tail.
pub struct StringStripPrefixCommandParser {
    cmd: Command,
}

impl StringStripPrefixCommandParser {
    fn strip_prefix_ignore_case<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
        if !value.to_lowercase().starts_with(&prefix.to_lowercase()) {
            return None;
        }

        let prefix_char_count = prefix.chars().count();
        let split_index = value
            .char_indices()
            .nth(prefix_char_count)
            .map(|(index, _)| index)
            .unwrap_or(value.len());
        value.get(split_index..)
    }

    pub fn new() -> Self {
        let cmd = Command::new("strip-prefix")
            .about("Strip a prefix from a string and return the remaining tail.")
            .after_help(
                r#"
Arguments:
  <value>      The full input string or variable.
  <prefix>     The prefix to remove.

Options:
  --ignore-case,-i   Perform case-insensitive comparison

Behavior:
  - Both arguments are evaluated dynamically at runtime.
  - If <value> starts with <prefix>, returns success with the remaining tail.
  - If <value> equals <prefix>, returns success with an empty string.
  - Comparison is case-sensitive by default.
  - If <value> does not start with <prefix>, returns error and leaves the value unchanged.
  - Does not modify any variable or environment.

Examples:
  strip-prefix "/api/v1/users" "/api"
  strip-prefix --ignore-case "/API/v1/users" "/api"
  strip-prefix $REQ.url $route_prefix
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
                Arg::new("value")
                    .required(true)
                    .help("Input string to strip"),
            )
            .arg(Arg::new("prefix").required(true).help("Prefix to remove"));

        Self { cmd }
    }
}

impl CommandParser for StringStripPrefixCommandParser {
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
                let msg = format!("Invalid strip-prefix command: {:?}, {}", str_args, e);
                error!("{}", msg);
                msg
            })?;

        let ignore_case = matches.get_flag("ignore_case");

        let value_index = matches.index_of("value").ok_or_else(|| {
            let msg = format!("Value is required, but got: {:?}", args);
            error!("{}", msg);
            msg
        })?;
        let value = args[value_index].clone();

        let prefix_index = matches.index_of("prefix").ok_or_else(|| {
            let msg = format!("Prefix is required, but got: {:?}", args);
            error!("{}", msg);
            msg
        })?;
        let prefix = args[prefix_index].clone();

        let cmd = StringStripPrefixCommand::new(value, prefix, ignore_case);

        Ok(Arc::new(Box::new(cmd)))
    }
}

pub struct StringStripPrefixCommand {
    ignore_case: bool,
    value: CommandArg,
    prefix: CommandArg,
}

impl StringStripPrefixCommand {
    pub fn new(value: CommandArg, prefix: CommandArg, ignore_case: bool) -> Self {
        Self {
            ignore_case,
            value,
            prefix,
        }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for StringStripPrefixCommand {
    async fn exec(&self, context: &Context) -> Result<super::CommandResult, String> {
        let value = self.value.evaluate_string(context).await?;
        let prefix = self.prefix.evaluate_string(context).await?;

        let tail = if self.ignore_case {
            StringStripPrefixCommandParser::strip_prefix_ignore_case(&value, &prefix)
        } else {
            value.strip_prefix(prefix.as_str())
        };

        if let Some(tail) = tail {
            info!(
                "strip-prefix matched value='{}' prefix='{}' ignore_case={} tail='{}'",
                value, prefix, self.ignore_case, tail
            );
            Ok(super::CommandResult::success_with_string(tail))
        } else {
            debug!(
                "strip-prefix not-matched value='{}' prefix='{}' ignore_case={}",
                value, prefix, self.ignore_case
            );
            Ok(super::CommandResult::error())
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
            info!(
                "ends-with matched str='{}' suffix='{}'",
                string_value, suffix
            );
        } else {
            debug!(
                "ends-with not-matched str='{}' suffix='{}'",
                string_value, suffix
            );
        }

        if ends_with {
            Ok(super::CommandResult::success_with_value(
                CollectionValue::Bool(true),
            ))
        } else {
            Ok(super::CommandResult::error_with_value(
                CollectionValue::Bool(false),
            ))
        }
    }
}
