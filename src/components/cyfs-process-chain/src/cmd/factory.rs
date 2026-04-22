use super::action::ActionCommandParser;
use super::capture::CaptureCommandParser;
use super::cmd::*;
use super::coll::*;
use super::control::*;
use super::debug::EchoCommandParser;
use super::exec::*;
use super::external::*;
use super::map::*;
use super::match_::*;
use super::string::*;
use super::type_::*;
use super::uri::*;
use super::value::*;
use super::var::*;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct CommandParserFactory {
    parsers: Arc<Mutex<HashMap<String, CommandParserRef>>>,
}

impl CommandParserFactory {
    pub fn new() -> Self {
        Self {
            parsers: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn register(&self, name: &str, parser: CommandParserRef) {
        let mut parsers = self.parsers.lock().unwrap();
        if let Some(_prev) = parsers.insert(name.to_string(), parser) {
            error!("Command parser {} already exists, will be replaced", name);
        }
    }

    pub fn get_parser(&self, name: &str) -> Option<CommandParserRef> {
        let parsers = self.parsers.lock().unwrap();
        parsers.get(name).cloned()
    }

    pub fn get_command_list(&self) -> Vec<String> {
        let parsers = self.parsers.lock().unwrap();
        parsers.keys().cloned().collect()
    }

    pub fn get_group_list(&self) -> HashMap<CommandGroup, Vec<String>> {
        let parsers = self.parsers.lock().unwrap();
        let mut group_map: HashMap<CommandGroup, Vec<String>> = HashMap::new();
        for (name, parser) in parsers.iter() {
            let group = parser.group();
            group_map.entry(group).or_default().push(name.clone());
        }

        // Sort each group
        for group in group_map.iter_mut() {
            group.1.sort();
        }

        group_map
    }

    pub fn init(&self) {
        // control command
        self.register("goto", Arc::new(Box::new(GotoCommandParser::new())));
        self.register("first-ok", Arc::new(Box::new(FirstOkCommandParser::new())));
        self.register("exec", Arc::new(Box::new(ExecCommandParser::new())));
        self.register("invoke", Arc::new(Box::new(InvokeCommandParser::new())));
        self.register("return", Arc::new(Box::new(ReturnCommandParser::new())));
        self.register("error", Arc::new(Box::new(ErrorCommandParser::new())));
        self.register("exit", Arc::new(Box::new(ExitCommandParser::new())));
        self.register("break", Arc::new(Box::new(BreakCommandParser::new())));

        // action command
        let drop_action_parser = ActionCommandParser::new(CommandAction::Drop);
        self.register("drop", Arc::new(Box::new(drop_action_parser)));

        let accept_action = ActionCommandParser::new(CommandAction::Accept);
        self.register("accept", Arc::new(Box::new(accept_action)));

        let reject_action = ActionCommandParser::new(CommandAction::Reject);
        self.register("reject", Arc::new(Box::new(reject_action)));

        // env command
        self.register("assign", Arc::new(Box::new(AssignCommandParser::new())));
        self.register("delete", Arc::new(Box::new(DeleteCommandParser::new())));
        self.register("type", Arc::new(Box::new(TypeCommandParser::new())));
        self.register("to-bool", Arc::new(Box::new(ToBoolCommandParser::new())));
        self.register(
            "to-number",
            Arc::new(Box::new(ToNumberCommandParser::new())),
        );
        self.register("is-null", Arc::new(Box::new(create_is_null_parser())));
        self.register("is-bool", Arc::new(Box::new(create_is_bool_parser())));
        self.register("is-number", Arc::new(Box::new(create_is_number_parser())));
        self.register("capture", Arc::new(Box::new(CaptureCommandParser::new())));

        // match command
        self.register("match", Arc::new(Box::new(MatchCommandParser::new())));
        self.register(
            "match-reg",
            Arc::new(Box::new(MatchRegexCommandParser::new())),
        );
        self.register(
            "match-path",
            Arc::new(Box::new(MatchPathCommandParser::new())),
        );
        self.register(
            "match-host",
            Arc::new(Box::new(MatchHostCommandParser::new())),
        );
        self.register("eq", Arc::new(Box::new(EQCommandParser::new())));
        self.register("ne", Arc::new(Box::new(NECommandParser::new())));
        self.register("oneof", Arc::new(Box::new(OneOfCommandParser::new())));
        self.register("gt", Arc::new(Box::new(create_gt_parser())));
        self.register("ge", Arc::new(Box::new(create_ge_parser())));
        self.register("lt", Arc::new(Box::new(create_lt_parser())));
        self.register("le", Arc::new(Box::new(create_le_parser())));
        self.register("range", Arc::new(Box::new(RangeCommandParser::new())));

        // string command
        self.register("rewrite", Arc::new(Box::new(RewriteCommandParser::new())));
        self.register(
            "rewrite-path",
            Arc::new(Box::new(RewritePathCommandParser::new())),
        );
        self.register(
            "rewrite-host",
            Arc::new(Box::new(RewriteHostCommandParser::new())),
        );
        self.register(
            "rewrite-reg",
            Arc::new(Box::new(RewriteRegexCommandParser::new())),
        );

        self.register(
            "replace",
            Arc::new(Box::new(StringReplaceCommandParser::new())),
        );
        self.register(
            "append",
            Arc::new(Box::new(StringAppendCommandParser::new())),
        );
        self.register("slice", Arc::new(Box::new(StringSliceCommandParser::new())));
        self.register("split", Arc::new(Box::new(StringSplitCommandParser::new())));
        self.register(
            "strlen",
            Arc::new(Box::new(StringLengthCommandParser::new())),
        );
        self.register(
            "starts-with",
            Arc::new(Box::new(StringStartsWithCommandParser::new())),
        );
        self.register(
            "strip-prefix",
            Arc::new(Box::new(StringStripPrefixCommandParser::new())),
        );
        self.register(
            "strip-suffix",
            Arc::new(Box::new(StringStripSuffixCommandParser::new())),
        );
        self.register(
            "ends-with",
            Arc::new(Box::new(StringEndsWithCommandParser::new())),
        );

        // uri commands
        self.register(
            "url_encode",
            Arc::new(Box::new(UrlEncodeCommandParser::new())),
        );
        self.register(
            "url_decode",
            Arc::new(Box::new(UrlDecodeCommandParser::new())),
        );
        self.register(
            "parse-authority",
            Arc::new(Box::new(ParseAuthorityCommandParser::new(
                "parse-authority",
            ))),
        );
        self.register(
            "parse-auth",
            Arc::new(Box::new(ParseAuthorityCommandParser::new("parse-auth"))),
        );
        self.register(
            "parse-uri",
            Arc::new(Box::new(ParseUriCommandParser::new())),
        );
        self.register(
            "parse-query",
            Arc::new(Box::new(ParseQueryCommandParser::new())),
        );
        self.register(
            "build-uri",
            Arc::new(Box::new(BuildUriCommandParser::new())),
        );
        self.register(
            "build-query",
            Arc::new(Box::new(BuildQueryCommandParser::new())),
        );
        self.register(
            "query-get",
            Arc::new(Box::new(QueryGetCommandParser::new())),
        );

        // collection commands
        self.register(
            "match-include",
            Arc::new(Box::new(MatchIncludeCommandParser::new())),
        );

        self.register(
            "list-create",
            Arc::new(Box::new(ListCreateCommandParser::new())),
        );
        self.register(
            "list-push",
            Arc::new(Box::new(ListPushCommandParser::new())),
        );
        self.register(
            "list-insert",
            Arc::new(Box::new(ListInsertCommandParser::new())),
        );
        self.register("list-set", Arc::new(Box::new(ListSetCommandParser::new())));
        self.register(
            "list-remove",
            Arc::new(Box::new(ListRemoveCommandParser::new())),
        );
        self.register("list-pop", Arc::new(Box::new(ListPopCommandParser::new())));
        self.register(
            "list-clear",
            Arc::new(Box::new(ListClearCommandParser::new())),
        );

        self.register(
            "set-create",
            Arc::new(Box::new(SetCreateCommandParser::new())),
        );
        self.register("set-add", Arc::new(Box::new(SetAddCommandParser::new())));
        self.register(
            "set-remove",
            Arc::new(Box::new(SetRemoveCommandParser::new())),
        );

        self.register(
            "map-create",
            Arc::new(Box::new(MapCreateCommandParser::new())),
        );
        self.register("map-add", Arc::new(Box::new(MapAddCommandParser::new())));
        self.register(
            "map-remove",
            Arc::new(Box::new(MapRemoveCommandParser::new())),
        );

        // debug
        self.register("echo", Arc::new(Box::new(EchoCommandParser::new())));

        // map-reduce command
        self.register("map", Arc::new(Box::new(MapReduceCommandParser::new())));

        // external commands
        self.register("call", Arc::new(Box::new(ExternalCommandParser::new())));
    }

    pub fn clear(&self) {
        let mut parsers = self.parsers.lock().unwrap();
        info!("Clearing all command parsers {}", parsers.len());
        parsers.clear();
    }
}

lazy_static::lazy_static! {
    // Global command parser factory instance
    pub static ref COMMAND_PARSER_FACTORY: CommandParserFactory = {
        let factory = CommandParserFactory::new();
        factory.init();
        factory
    };
}

struct CommandFactoryGuard {}

impl CommandFactoryGuard {
    pub const fn new() -> Self {
        Self {}
    }
}

impl Drop for CommandFactoryGuard {
    fn drop(&mut self) {
        info!("Dropping global command parser factory");
        COMMAND_PARSER_FACTORY.clear();
    }
}

// const _GUARD: CommandFactoryGuard = CommandFactoryGuard::new();
