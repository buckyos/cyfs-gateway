use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use super::cmd::*;
use super::external::ExternalCommandParser;
use super::label::{HaveLabelCommandParser, SetLabelByHostDbCommandParser};
use super::sni::HttpSniProbeCommandParser;
use super::action::ActionCommandParser;
use super::match_::MatchCommandParser;
use super::assign::AssignCommandParser;

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

    pub fn parse(&self, name: &str, args: &Vec<String>) -> Result<CommandExecutorRef, String> {
        let parser = self.get_parser(name);
        if parser.is_none() {
            let msg = format!("Command parser {} not found", name);
            error!("{}", msg);
            return Err(msg);
        }

        parser.unwrap().parse(args)
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

        // label command
        self.register("set_label_by_host_db", Arc::new(Box::new(SetLabelByHostDbCommandParser::new())));
        self.register("have_label", Arc::new(Box::new(HaveLabelCommandParser::new())));

        // sni command
        self.register("http-sni-probe", Arc::new(Box::new(HttpSniProbeCommandParser::new())));
    }
}