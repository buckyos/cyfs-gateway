use super::action::ActionCommandParser;
use super::assign::AssignCommandParser;
use super::cmd::*;
use super::coll::*;
use super::match_::MatchCommandParser;
use super::string::*;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use super::control::*;

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

    pub fn init(&self) {
        // control command
        self.register("goto", Arc::new(Box::new(GotoCommandParser::new())));
        self.register("exec", Arc::new(Box::new(ExecCommandParser::new())));

        // action command
        let drop_action_parser = ActionCommandParser::new(CommandAction::Drop);
        self.register("drop", Arc::new(Box::new(drop_action_parser)));

        let accept_action = ActionCommandParser::new(CommandAction::Accept);
        self.register("pass", Arc::new(Box::new(accept_action)));

        let reject_action = ActionCommandParser::new(CommandAction::Reject);
        self.register("reject", Arc::new(Box::new(reject_action)));

        // assign command
        self.register("assign", Arc::new(Box::new(AssignCommandParser::new())));
        // match command
        self.register("match", Arc::new(Box::new(MatchCommandParser::new())));

        // string command
        self.register("rewrite", Arc::new(Box::new(RewriteCommandParser::new())));
        self.register(
            "rewrite_reg",
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
            "starts_with",
            Arc::new(Box::new(StringStartsWithCommandParser)),
        );
        self.register("ends_with", Arc::new(Box::new(StringEndsWithCommandParser)));

        // collection commands
        self.register(
            "match_include",
            Arc::new(Box::new(MatchIncludeCommandParser::new())),
        );

        self.register(
            "set_create",
            Arc::new(Box::new(SetCreateCommandParser::new())),
        );
        self.register("set_add", Arc::new(Box::new(SetAddCommandParser::new())));
        self.register(
            "set_remove",
            Arc::new(Box::new(SetRemoveCommandParser::new())),
        );

        self.register(
            "map_create",
            Arc::new(Box::new(MapCreateCommandParser::new())),
        );
        self.register("map_add", Arc::new(Box::new(MapAddCommandParser::new())));
        self.register(
            "map_remove",
            Arc::new(Box::new(MapRemoveCommandParser::new())),
        );
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