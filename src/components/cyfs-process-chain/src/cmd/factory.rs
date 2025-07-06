use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use super::cmd::*;
use super::external::ExternalCommandParser;
use super::sni::HttpSniProbeCommandParser;
use super::action::ActionCommandParser;
use super::match_::MatchCommandParser;
use super::assign::AssignCommandParser;
use super::string::*;

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
        // action command
        let drop_action_parser = ActionCommandParser::new(CommandAction::Drop);
        self.register("DROP", Arc::new(Box::new(drop_action_parser)));

        let pass_action = ActionCommandParser::new(CommandAction::Pass);
        self.register("PASS", Arc::new(Box::new(pass_action)));

        // assign command
        self.register("assign", Arc::new(Box::new(AssignCommandParser::new())));
        // match command
        self.register("match", Arc::new(Box::new(MatchCommandParser::new())));

        // external command
        self.register("EXEC", Arc::new(Box::new(ExternalCommandParser::new())));

        // sni command
        self.register("http-sni-probe", Arc::new(Box::new(HttpSniProbeCommandParser::new())));

        // string command
        self.register("rewrite", Arc::new(Box::new(RewriteCommandParser::new())));
        self.register("rewrite_reg", Arc::new(Box::new(RewriteRegexCommandParser::new())));

        self.register("replace", Arc::new(Box::new(StringReplaceCommandParser::new())));
        self.register("append", Arc::new(Box::new(StringAppendCommandParser::new())));
        self.register("slice", Arc::new(Box::new(StringSliceCommandParser::new())));
        self.register("strlen", Arc::new(Box::new(StringLengthCommandParser::new())));
        self.register("starts_with", Arc::new(Box::new(StringStartsWithCommandParser)));
        self.register("ends_with", Arc::new(Box::new(StringEndsWithCommandParser)));

    }
}