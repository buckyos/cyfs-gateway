use super::types::*;
use crate::block::{CommandArg, CommandArgs};
use crate::chain::{Context, ParserContext};
use crate::collection::{
    CollectionValue, MemoryListCollection, MemoryMapCollection, MemoryMultiMapCollection,
    MultiMapCollection, NumberValue,
};
use clap::{Arg, Command};
use http::uri::Authority;
use std::sync::Arc;
use url::{Position, Url, form_urlencoded};

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

fn percent_decode_query_component(input: &str) -> Result<String, String> {
    percent_decode_url_component(&input.replace('+', " "))
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
        CommandGroup::Uri
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
        CommandGroup::Uri
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

pub struct ParseAuthorityCommandParser {
    cmd: Command,
}

impl ParseAuthorityCommandParser {
    pub fn new(name: &'static str) -> Self {
        let cmd = Command::new(name)
            .about("Parse an authority string into a typed Map.")
            .after_help(
                r#"
Arguments:
  <value>     The authority-like string or variable to parse.

Options:
  --default-port <port>   Default port to use when the input has no explicit port

Behavior:
  - Accepts authority-like input such as `example.com`, `example.com:3180`, `user:pass@[::1]:8080`.
  - Returns a fresh Map with fields: `host`, `port`, `has_port`, `userinfo`.
  - `host` preserves IPv6 brackets when present.
  - `port` is Number when present or defaulted, otherwise Null.
  - `has_port` is true only when the input explicitly contains a port.
  - `userinfo` is returned as raw text before `@`, without percent-decoding.
  - Full URLs such as `https://example.com/path` are not accepted.
  - Returns error for invalid authority syntax or invalid default port.

Examples:
  parse-authority $REQ.host
  parse-authority --default-port 3180 $REQ.host
  parse-auth "user:pass@[::1]:8080"
"#,
            )
            .arg(
                Arg::new("default_port")
                    .long("default-port")
                    .value_name("port")
                    .help("Default port to use when the input has no explicit port"),
            )
            .arg(
                Arg::new("value")
                    .required(true)
                    .help("Input authority-like string to parse"),
            );

        Self { cmd }
    }
}

impl CommandParser for ParseAuthorityCommandParser {
    fn group(&self) -> CommandGroup {
        CommandGroup::Uri
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

        let default_port = matches
            .index_of("default_port")
            .map(|index| args[index].clone());

        let value_index = matches.index_of("value").ok_or_else(|| {
            let msg = format!("Value is required, but got: {:?}", args);
            error!("{}", msg);
            msg
        })?;
        let value = args[value_index].clone();

        Ok(Arc::new(Box::new(ParseAuthorityCommand::new(
            value,
            default_port,
        ))))
    }
}

pub struct ParseAuthorityCommand {
    value: CommandArg,
    default_port: Option<CommandArg>,
}

impl ParseAuthorityCommand {
    pub fn new(value: CommandArg, default_port: Option<CommandArg>) -> Self {
        Self {
            value,
            default_port,
        }
    }

    pub(crate) fn parse_port_arg(field: &str, value: &CollectionValue) -> Result<u16, String> {
        match value {
            CollectionValue::String(raw) => raw.parse::<u16>().map_err(|e| {
                let msg = format!("Invalid {} '{}': {}", field, raw, e);
                error!("{}", msg);
                msg
            }),
            CollectionValue::Number(NumberValue::Int(port)) => u16::try_from(*port).map_err(|_| {
                let msg = format!("Invalid {} '{}': expected 0..=65535", field, port);
                error!("{}", msg);
                msg
            }),
            CollectionValue::Number(NumberValue::Float(port)) => {
                let msg = format!(
                    "Invalid {} '{}': floating-point values are not supported",
                    field, port
                );
                error!("{}", msg);
                Err(msg)
            }
            _ => {
                let msg = format!(
                    "Invalid {} type '{}': expected String or integer Number",
                    field,
                    value.get_type()
                );
                error!("{}", msg);
                Err(msg)
            }
        }
    }

    async fn evaluate_default_port(&self, context: &Context) -> Result<Option<u16>, String> {
        let Some(default_port) = self.default_port.as_ref() else {
            return Ok(None);
        };

        let value = default_port.evaluate(context).await?;
        Ok(Some(Self::parse_port_arg("default port", &value)?))
    }

    fn userinfo_from_raw(raw: &str) -> Option<&str> {
        raw.rsplit_once('@').map(|(userinfo, _)| userinfo)
    }

    async fn build_map(
        authority: &Authority,
        has_port: bool,
        default_port: Option<u16>,
    ) -> Result<CollectionValue, String> {
        let map = MemoryMapCollection::new_ref();
        map.insert(
            "host",
            CollectionValue::String(authority.host().to_string()),
        )
        .await?;

        let port_value = if let Some(port) = authority.port_u16().or(default_port) {
            CollectionValue::Number(NumberValue::Int(port as i64))
        } else {
            CollectionValue::Null
        };
        map.insert("port", port_value).await?;
        map.insert("has_port", CollectionValue::Bool(has_port))
            .await?;

        let userinfo = Self::userinfo_from_raw(authority.as_str())
            .map(|value| CollectionValue::String(value.to_string()))
            .unwrap_or(CollectionValue::Null);
        map.insert("userinfo", userinfo).await?;

        Ok(CollectionValue::Map(map))
    }
}

#[async_trait::async_trait]
impl CommandExecutor for ParseAuthorityCommand {
    async fn exec(&self, context: &Context) -> Result<super::CommandResult, String> {
        let value = self.value.evaluate_string(context).await?;
        let default_port = self.evaluate_default_port(context).await?;

        let authority = Authority::from_maybe_shared(value.clone()).map_err(|e| {
            let msg = format!("Invalid authority '{}': {}", value, e);
            error!("{}", msg);
            msg
        })?;

        let has_port = authority.port().is_some();
        info!(
            "parse-authority parsed raw='{}' host='{}' has_port={} default_port={:?}",
            value,
            authority.host(),
            has_port,
            default_port
        );

        Ok(super::CommandResult::success_with_value(
            Self::build_map(&authority, has_port, default_port).await?,
        ))
    }
}

pub struct ParseUriCommandParser {
    cmd: Command,
}

impl ParseUriCommandParser {
    pub fn new() -> Self {
        let cmd = Command::new("parse-uri")
            .about("Parse an absolute URI string into a typed Map.")
            .after_help(
                r#"
Arguments:
  <value>     The absolute URI string or variable to parse.

Behavior:
  - Accepts absolute URI input and parses it with `url::Url`.
  - Returns a fresh Map with fields: `scheme`, `authority`, `host`, `port`,
    `effective_port`, `has_port`, `username`, `password`, `path`, `query`,
    `fragment`.
  - `authority` is Null when the URI has no authority component.
  - `host` preserves IPv6 brackets when present.
  - `port` reflects the normalized serialized port; known default ports are omitted.
  - `effective_port` includes known scheme defaults such as `https -> 443`.
  - `username` is always returned as a String and may be empty.
  - `password`, `query`, and `fragment` are Null when absent.
  - Relative references or invalid URI syntax return error.

Examples:
  parse-uri "https://user:pass@example.com:8443/api/v1?q=1#frag"
  parse-uri $REQ.ext.url
"#,
            )
            .arg(
                Arg::new("value")
                    .required(true)
                    .help("Input absolute URI string to parse"),
            );

        Self { cmd }
    }
}

impl CommandParser for ParseUriCommandParser {
    fn group(&self) -> CommandGroup {
        CommandGroup::Uri
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
                let msg = format!("Invalid parse-uri command: {:?}, {}", str_args, e);
                error!("{}", msg);
                msg
            })?;

        let value_index = matches.index_of("value").ok_or_else(|| {
            let msg = format!("Value is required, but got: {:?}", args);
            error!("{}", msg);
            msg
        })?;
        let value = args[value_index].clone();

        Ok(Arc::new(Box::new(ParseUriCommand::new(value))))
    }
}

pub struct ParseUriCommand {
    value: CommandArg,
}

impl ParseUriCommand {
    pub fn new(value: CommandArg) -> Self {
        Self { value }
    }

    fn authority_from_url(url: &Url) -> Option<String> {
        let authority = &url[Position::BeforeUsername..Position::AfterPort];
        if authority.is_empty() {
            None
        } else {
            Some(authority.to_string())
        }
    }

    async fn insert_string_or_null(
        map: &crate::collection::MapCollectionRef,
        key: &str,
        value: Option<&str>,
    ) -> Result<(), String> {
        let value = value
            .map(|value| CollectionValue::String(value.to_string()))
            .unwrap_or(CollectionValue::Null);
        map.insert(key, value).await?;
        Ok(())
    }

    async fn insert_port_or_null(
        map: &crate::collection::MapCollectionRef,
        key: &str,
        value: Option<u16>,
    ) -> Result<(), String> {
        let value = value
            .map(|value| CollectionValue::Number(NumberValue::Int(value as i64)))
            .unwrap_or(CollectionValue::Null);
        map.insert(key, value).await?;
        Ok(())
    }

    async fn build_map(url: &Url) -> Result<CollectionValue, String> {
        let map = MemoryMapCollection::new_ref();

        map.insert("scheme", CollectionValue::String(url.scheme().to_string()))
            .await?;
        Self::insert_string_or_null(&map, "authority", Self::authority_from_url(url).as_deref())
            .await?;
        Self::insert_string_or_null(&map, "host", url.host_str()).await?;
        Self::insert_port_or_null(&map, "port", url.port()).await?;
        Self::insert_port_or_null(&map, "effective_port", url.port_or_known_default()).await?;
        map.insert("has_port", CollectionValue::Bool(url.port().is_some()))
            .await?;
        map.insert(
            "username",
            CollectionValue::String(url.username().to_string()),
        )
        .await?;
        Self::insert_string_or_null(&map, "password", url.password()).await?;
        map.insert("path", CollectionValue::String(url.path().to_string()))
            .await?;
        Self::insert_string_or_null(&map, "query", url.query()).await?;
        Self::insert_string_or_null(&map, "fragment", url.fragment()).await?;

        Ok(CollectionValue::Map(map))
    }
}

#[async_trait::async_trait]
impl CommandExecutor for ParseUriCommand {
    async fn exec(&self, context: &Context) -> Result<super::CommandResult, String> {
        let value = self.value.evaluate_string(context).await?;
        let url = Url::parse(&value).map_err(|e| {
            let msg = format!("Invalid URI '{}': {}", value, e);
            error!("{}", msg);
            msg
        })?;

        info!(
            "parse-uri parsed raw='{}' scheme='{}' host={:?} port={:?}",
            value,
            url.scheme(),
            url.host_str(),
            url.port()
        );

        Ok(super::CommandResult::success_with_value(
            Self::build_map(&url).await?,
        ))
    }
}

pub struct ParseQueryCommandParser {
    cmd: Command,
}

impl ParseQueryCommandParser {
    pub fn new() -> Self {
        let cmd = Command::new("parse-query")
            .about("Parse a URL query string into a typed MultiMap.")
            .after_help(
                r#"
Arguments:
  <value>     The raw query string or variable to parse. A leading `?` is allowed.

Behavior:
  - Parses the input using `application/x-www-form-urlencoded` rules.
  - A leading `?` is ignored when present.
  - `+` is decoded as space.
  - Returns a fresh MultiMap whose keys and values are decoded strings.
  - Missing `=` is treated as an empty value.
  - Duplicate identical values under the same key are deduplicated by MultiMap set semantics.
  - Malformed percent-encoding or invalid UTF-8 returns error.

Examples:
  parse-query "redirect_url=%2Fdashboard&tag=alpha&tag=beta"
  parse-query $parsed.query
"#,
            )
            .arg(
                Arg::new("value")
                    .required(true)
                    .help("Input query string to parse"),
            );

        Self { cmd }
    }
}

impl CommandParser for ParseQueryCommandParser {
    fn group(&self) -> CommandGroup {
        CommandGroup::Uri
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
                let msg = format!("Invalid parse-query command: {:?}, {}", str_args, e);
                error!("{}", msg);
                msg
            })?;

        let value_index = matches.index_of("value").ok_or_else(|| {
            let msg = format!("Value is required, but got: {:?}", args);
            error!("{}", msg);
            msg
        })?;
        let value = args[value_index].clone();

        Ok(Arc::new(Box::new(ParseQueryCommand::new(value))))
    }
}

pub struct ParseQueryCommand {
    value: CommandArg,
}

impl ParseQueryCommand {
    pub fn new(value: CommandArg) -> Self {
        Self { value }
    }

    fn strip_prefix(raw: &str) -> &str {
        raw.strip_prefix('?').unwrap_or(raw)
    }

    async fn parse_query_to_multi_map(raw: &str) -> Result<CollectionValue, String> {
        let params =
            Arc::new(Box::new(MemoryMultiMapCollection::new()) as Box<dyn MultiMapCollection>);
        let query = Self::strip_prefix(raw);

        for pair in query.split('&') {
            if pair.is_empty() {
                continue;
            }

            let (raw_key, raw_value) = pair.split_once('=').unwrap_or((pair, ""));
            let key = percent_decode_query_component(raw_key)?;
            let value = percent_decode_query_component(raw_value)?;
            params.insert(&key, &value).await?;
        }

        Ok(CollectionValue::MultiMap(params))
    }
}

#[async_trait::async_trait]
impl CommandExecutor for ParseQueryCommand {
    async fn exec(&self, context: &Context) -> Result<super::CommandResult, String> {
        let value = self.value.evaluate_string(context).await?;
        let parsed = Self::parse_query_to_multi_map(&value).await?;
        info!("parse-query parsed raw='{}'", value);
        Ok(super::CommandResult::success_with_value(parsed))
    }
}

pub struct BuildUriCommandParser {
    cmd: Command,
}

impl BuildUriCommandParser {
    pub fn new() -> Self {
        let cmd = Command::new("build-uri")
            .about("Build an absolute URI string from a typed Map.")
            .after_help(
                r#"
Arguments:
  <parts>     A Map or map literal that describes the URI to build.

Behavior:
  - Expects a typed Map.
  - Supported input keys: `scheme`, `authority`, `host`, `port`, `username`,
    `password`, `path`, `query`, `fragment`.
  - `authority` is used only when `host` is absent.
  - Parsed-output helper keys `effective_port` and `has_port` are accepted and ignored.
  - Structured authority fields (`host`, `port`, `username`, `password`) take
    precedence over `authority`.
  - For `http`, `https`, `ws`, `wss`, and `ftp`, `host` or `authority` is required.
  - Returns a normalized absolute URI string.
  - Invalid field types or invalid URI components return error.

Examples:
  build-uri {
    "scheme": "https",
    "host": "example.com",
    "path": "/oauth/login",
    "query": "redirect_url=%2Fdashboard"
  }

  capture --value parsed $(parse-uri "https://user:pass@example.com:8443/api/v1?q=1#frag")
  build-uri $parsed
"#,
            )
            .arg(
                Arg::new("parts")
                    .required(true)
                    .help("Map or map literal describing the URI parts"),
            );

        Self { cmd }
    }
}

impl CommandParser for BuildUriCommandParser {
    fn group(&self) -> CommandGroup {
        CommandGroup::Uri
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
                let msg = format!("Invalid build-uri command: {:?}, {}", str_args, e);
                error!("{}", msg);
                msg
            })?;

        let parts_index = matches.index_of("parts").ok_or_else(|| {
            let msg = format!("URI parts map is required, but got: {:?}", args);
            error!("{}", msg);
            msg
        })?;
        let parts = args[parts_index].clone();

        Ok(Arc::new(Box::new(BuildUriCommand::new(parts))))
    }
}

pub struct BuildUriCommand {
    parts: CommandArg,
}

impl BuildUriCommand {
    pub fn new(parts: CommandArg) -> Self {
        Self { parts }
    }

    fn is_authority_required_scheme(scheme: &str) -> bool {
        matches!(scheme, "http" | "https" | "ws" | "wss" | "ftp")
    }

    async fn validate_supported_keys(
        map: &crate::collection::MapCollectionRef,
    ) -> Result<(), String> {
        let mut cursor = map.cursor_owned().await?;
        while let Some((key, _)) = cursor.next().await? {
            let supported = matches!(
                key.as_str(),
                "scheme"
                    | "authority"
                    | "host"
                    | "port"
                    | "effective_port"
                    | "has_port"
                    | "username"
                    | "password"
                    | "path"
                    | "query"
                    | "fragment"
            );
            if !supported {
                let msg = format!("Unsupported URI part key '{}'", key);
                error!("{}", msg);
                return Err(msg);
            }
        }

        Ok(())
    }

    async fn get_field(
        map: &crate::collection::MapCollectionRef,
        field: &str,
    ) -> Result<Option<CollectionValue>, String> {
        map.get(field).await
    }

    fn parse_optional_string(
        field: &str,
        value: Option<CollectionValue>,
    ) -> Result<Option<String>, String> {
        match value {
            None | Some(CollectionValue::Null) => Ok(None),
            Some(CollectionValue::String(value)) => Ok(Some(value)),
            Some(value) => {
                let msg = format!(
                    "Invalid URI part '{}' type '{}': expected String or Null",
                    field,
                    value.get_type()
                );
                error!("{}", msg);
                Err(msg)
            }
        }
    }

    fn parse_required_string(
        field: &str,
        value: Option<CollectionValue>,
    ) -> Result<String, String> {
        let value = Self::parse_optional_string(field, value)?;
        value.ok_or_else(|| {
            let msg = format!("Missing required URI part '{}'", field);
            error!("{}", msg);
            msg
        })
    }

    fn parse_optional_port(
        field: &str,
        value: Option<CollectionValue>,
    ) -> Result<Option<u16>, String> {
        match value {
            None | Some(CollectionValue::Null) => Ok(None),
            Some(value) => Ok(Some(ParseAuthorityCommand::parse_port_arg(field, &value)?)),
        }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for BuildUriCommand {
    async fn exec(&self, context: &Context) -> Result<super::CommandResult, String> {
        let parts = self.parts.evaluate(context).await?;
        let map = parts.try_as_map()?.clone();
        Self::validate_supported_keys(&map).await?;

        let scheme = Self::parse_required_string("scheme", Self::get_field(&map, "scheme").await?)?;
        let authority =
            Self::parse_optional_string("authority", Self::get_field(&map, "authority").await?)?;
        let host = Self::parse_optional_string("host", Self::get_field(&map, "host").await?)?;
        let port = Self::parse_optional_port("port", Self::get_field(&map, "port").await?)?;
        let username =
            Self::parse_optional_string("username", Self::get_field(&map, "username").await?)?;
        let password =
            Self::parse_optional_string("password", Self::get_field(&map, "password").await?)?;
        let path = Self::parse_optional_string("path", Self::get_field(&map, "path").await?)?;
        let query = Self::parse_optional_string("query", Self::get_field(&map, "query").await?)?;
        let fragment =
            Self::parse_optional_string("fragment", Self::get_field(&map, "fragment").await?)?;

        let raw_base = if let Some(host) = host.as_deref() {
            format!("{}://{}", scheme, host)
        } else if let Some(authority) = authority.as_deref() {
            if username.is_some() || password.is_some() || port.is_some() {
                let msg = "Structured URI authority fields cannot be mixed with authority when host is absent".to_string();
                error!("{}", msg);
                return Err(msg);
            }
            format!("{}://{}", scheme, authority)
        } else {
            if username.is_some() || password.is_some() || port.is_some() {
                let msg =
                    "Host is required when username, password, or port is provided".to_string();
                error!("{}", msg);
                return Err(msg);
            }
            if Self::is_authority_required_scheme(&scheme) {
                let msg = format!(
                    "URI scheme '{}' requires host or authority in build-uri",
                    scheme
                );
                error!("{}", msg);
                return Err(msg);
            }
            format!("{}:/", scheme)
        };

        let mut url = Url::parse(&raw_base).map_err(|e| {
            let msg = format!("Invalid URI base '{}': {}", raw_base, e);
            error!("{}", msg);
            msg
        })?;

        if let Some(username) = username.as_deref() {
            url.set_username(username).map_err(|_| {
                let msg = format!(
                    "Invalid URI username '{}' for scheme '{}'",
                    username, scheme
                );
                error!("{}", msg);
                msg
            })?;
        }
        if let Some(password) = password.as_deref() {
            url.set_password(Some(password)).map_err(|_| {
                let msg = format!("Invalid URI password for scheme '{}'", scheme);
                error!("{}", msg);
                msg
            })?;
        }
        if let Some(port) = port {
            url.set_port(Some(port)).map_err(|_| {
                let msg = format!("URI scheme '{}' does not support port '{}'", scheme, port);
                error!("{}", msg);
                msg
            })?;
        }
        if let Some(path) = path.as_deref() {
            url.set_path(path);
        }
        if let Some(query) = query.as_deref() {
            url.set_query(Some(query));
        }
        if let Some(fragment) = fragment.as_deref() {
            url.set_fragment(Some(fragment));
        }

        let built = url.to_string();
        info!("build-uri built '{}'", built);
        Ok(super::CommandResult::success_with_string(built))
    }
}

pub struct BuildQueryCommandParser {
    cmd: Command,
}

impl BuildQueryCommandParser {
    pub fn new() -> Self {
        let cmd = Command::new("build-query")
            .about("Build a URL query string from a typed Map or MultiMap.")
            .after_help(
                r#"
Arguments:
  <params>     A Map or MultiMap describing the query parameters.

Behavior:
  - Accepts a typed Map or MultiMap.
  - Uses `application/x-www-form-urlencoded` encoding.
  - Returns a query string without a leading `?`.
  - For Map values, String/Number/Bool/Null are supported.
  - Map Null values are serialized as empty values (`key=`).
  - For MultiMap values, each key may serialize to multiple `key=value` pairs.
  - The output is normalized by collection iteration order, not original raw pair order.

Examples:
  build-query {
    "redirect_url": "/dashboard",
    "page": 2,
    "exact": true
  }

  capture --value params $(parse-query "tag=alpha&tag=beta")
  build-query $params
"#,
            )
            .arg(
                Arg::new("params")
                    .required(true)
                    .help("Map or MultiMap describing the query parameters"),
            );

        Self { cmd }
    }
}

impl CommandParser for BuildQueryCommandParser {
    fn group(&self) -> CommandGroup {
        CommandGroup::Uri
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
                let msg = format!("Invalid build-query command: {:?}, {}", str_args, e);
                error!("{}", msg);
                msg
            })?;

        let params_index = matches.index_of("params").ok_or_else(|| {
            let msg = format!("Query params are required, but got: {:?}", args);
            error!("{}", msg);
            msg
        })?;
        let params = args[params_index].clone();

        Ok(Arc::new(Box::new(BuildQueryCommand::new(params))))
    }
}

pub struct BuildQueryCommand {
    params: CommandArg,
}

impl BuildQueryCommand {
    pub fn new(params: CommandArg) -> Self {
        Self { params }
    }

    fn stringify_map_value(key: &str, value: CollectionValue) -> Result<String, String> {
        match value {
            CollectionValue::String(value) => Ok(value),
            CollectionValue::Number(value) => Ok(value.to_string()),
            CollectionValue::Bool(value) => Ok(value.to_string()),
            CollectionValue::Null => Ok(String::new()),
            value => {
                let msg = format!(
                    "Invalid query value for key '{}': expected String/Number/Bool/Null, found {}",
                    key,
                    value.get_type()
                );
                error!("{}", msg);
                Err(msg)
            }
        }
    }

    async fn build_from_map(map: &crate::collection::MapCollectionRef) -> Result<String, String> {
        let mut pairs = Vec::new();
        let mut cursor = map.cursor_owned().await?;
        while let Some((key, value)) = cursor.next().await? {
            let value = Self::stringify_map_value(&key, value)?;
            pairs.push((key, value));
        }

        let mut serializer = form_urlencoded::Serializer::new(String::new());
        for (key, value) in pairs {
            serializer.append_pair(&key, &value);
        }

        Ok(serializer.finish())
    }

    async fn build_from_multi_map(
        multi_map: &crate::collection::MultiMapCollectionRef,
    ) -> Result<String, String> {
        let mut pairs = Vec::new();
        let mut cursor = multi_map.cursor_owned().await?;
        while let Some((key, values)) = cursor.next().await? {
            for value in values {
                pairs.push((key.clone(), value));
            }
        }

        let mut serializer = form_urlencoded::Serializer::new(String::new());
        for (key, value) in pairs {
            serializer.append_pair(&key, &value);
        }

        Ok(serializer.finish())
    }
}

#[async_trait::async_trait]
impl CommandExecutor for BuildQueryCommand {
    async fn exec(&self, context: &Context) -> Result<super::CommandResult, String> {
        let params = self.params.evaluate(context).await?;
        let built = match params {
            CollectionValue::Map(map) => Self::build_from_map(&map).await?,
            CollectionValue::MultiMap(multi_map) => Self::build_from_multi_map(&multi_map).await?,
            value => {
                let msg = format!(
                    "build-query expects a Map or MultiMap, found {}",
                    value.get_type()
                );
                error!("{}", msg);
                return Err(msg);
            }
        };

        info!("build-query built '{}'", built);
        Ok(super::CommandResult::success_with_string(built))
    }
}

pub struct QueryGetCommandParser {
    cmd: Command,
}

impl QueryGetCommandParser {
    pub fn new() -> Self {
        let cmd = Command::new("query-get")
            .about("Read one or more values from a raw query string or parsed query MultiMap.")
            .after_help(
                r#"
Arguments:
  <query>     Raw query string or parsed query MultiMap.
  <key>       Query key to read.

Options:
  --all       Return all values for the key as a List.

Behavior:
  - Accepts either a raw query string (with optional leading `?`) or a typed MultiMap from `parse-query`.
  - By default, returns the first value for the key as a String.
  - With `--all`, returns all values for the key as a List of Strings.
  - Missing key returns error.
  - Raw query input is parsed using the same rules as `parse-query`.

Examples:
  query-get "redirect_url=%2Fdashboard" "redirect_url"
  capture --value params $(parse-query "tag=alpha&tag=beta")
  query-get --all $params "tag"
"#,
            )
            .arg(
                Arg::new("all")
                    .long("all")
                    .help("Return all values as a List")
                    .action(clap::ArgAction::SetTrue),
            )
            .arg(
                Arg::new("query")
                    .required(true)
                    .help("Raw query string or parsed query MultiMap"),
            )
            .arg(Arg::new("key").required(true).help("Query key to read"));

        Self { cmd }
    }
}

impl CommandParser for QueryGetCommandParser {
    fn group(&self) -> CommandGroup {
        CommandGroup::Uri
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
                let msg = format!("Invalid query-get command: {:?}, {}", str_args, e);
                error!("{}", msg);
                msg
            })?;

        let query_index = matches.index_of("query").ok_or_else(|| {
            let msg = format!("Query source is required, but got: {:?}", args);
            error!("{}", msg);
            msg
        })?;
        let query = args[query_index].clone();

        let key_index = matches.index_of("key").ok_or_else(|| {
            let msg = format!("Query key is required, but got: {:?}", args);
            error!("{}", msg);
            msg
        })?;
        let key = args[key_index].clone();

        Ok(Arc::new(Box::new(QueryGetCommand::new(
            query,
            key,
            matches.get_flag("all"),
        ))))
    }
}

pub struct QueryGetCommand {
    query: CommandArg,
    key: CommandArg,
    all: bool,
}

impl QueryGetCommand {
    pub fn new(query: CommandArg, key: CommandArg, all: bool) -> Self {
        Self { query, key, all }
    }

    async fn list_from_values(values: Vec<String>) -> Result<CollectionValue, String> {
        let list = MemoryListCollection::new_ref();
        for value in values {
            list.push(CollectionValue::String(value)).await?;
        }
        Ok(CollectionValue::List(list))
    }

    async fn get_from_multi_map(
        &self,
        multi_map: &crate::collection::MultiMapCollectionRef,
        key: &str,
    ) -> Result<super::CommandResult, String> {
        if self.all {
            let Some(values) = multi_map.get_many(key).await? else {
                let msg = format!("Query key '{}' not found", key);
                error!("{}", msg);
                return Err(msg);
            };
            let values = values.dump().await?;
            return Ok(super::CommandResult::success_with_value(
                Self::list_from_values(values).await?,
            ));
        }

        let Some(value) = multi_map.get(key).await? else {
            let msg = format!("Query key '{}' not found", key);
            error!("{}", msg);
            return Err(msg);
        };

        Ok(super::CommandResult::success_with_string(value))
    }
}

#[async_trait::async_trait]
impl CommandExecutor for QueryGetCommand {
    async fn exec(&self, context: &Context) -> Result<super::CommandResult, String> {
        let query = self.query.evaluate(context).await?;
        let key = self.key.evaluate_string(context).await?;

        let multi_map = match query {
            CollectionValue::String(raw) => {
                ParseQueryCommand::parse_query_to_multi_map(&raw).await?
            }
            CollectionValue::MultiMap(multi_map) => CollectionValue::MultiMap(multi_map),
            value => {
                let msg = format!(
                    "query-get expects a raw query String or MultiMap, found {}",
                    value.get_type()
                );
                error!("{}", msg);
                return Err(msg);
            }
        };

        let multi_map = multi_map.try_as_multi_map()?.clone();
        info!("query-get reading key='{}' all={}", key, self.all);
        self.get_from_multi_map(&multi_map, &key).await
    }
}
