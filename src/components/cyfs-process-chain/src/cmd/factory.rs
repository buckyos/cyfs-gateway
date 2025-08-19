use super::action::ActionCommandParser;
use super::cmd::*;
use super::coll::*;
use super::control::*;
use super::debug::EchoCommandParser;
use super::external::*;
use super::map::*;
use super::match_::*;
use super::string::*;
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
        // self.register("goto", Arc::new(Box::new(GotoCommandParser::new())));
        self.register("exec", Arc::new(Box::new(ExecCommandParser::new())));
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

        // match command
        self.register("match", Arc::new(Box::new(MatchCommandParser::new())));
        self.register(
            "match-reg",
            Arc::new(Box::new(MatchRegexCommandParser::new())),
        );
        self.register("eq", Arc::new(Box::new(EQCommandParser::new())));
        self.register("range", Arc::new(Box::new(RangeCommandParser::new())));

        // string command
        self.register("rewrite", Arc::new(Box::new(RewriteCommandParser::new())));
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
        self.register(
            "strlen",
            Arc::new(Box::new(StringLengthCommandParser::new())),
        );
        self.register(
            "starts-with",
            Arc::new(Box::new(StringStartsWithCommandParser::new())),
        );
        self.register(
            "ends-with",
            Arc::new(Box::new(StringEndsWithCommandParser::new())),
        );

        // collection commands
        self.register(
            "match-include",
            Arc::new(Box::new(MatchIncludeCommandParser::new())),
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

struct CommandFactoryGuard {
}

impl CommandFactoryGuard {
    pub const fn new() -> Self {
        Self {
        }
    }
}

impl Drop for CommandFactoryGuard {
    fn drop(&mut self) {
        info!("Dropping global command parser factory");
        COMMAND_PARSER_FACTORY.clear();
    }
}

// const _GUARD: CommandFactoryGuard = CommandFactoryGuard::new();