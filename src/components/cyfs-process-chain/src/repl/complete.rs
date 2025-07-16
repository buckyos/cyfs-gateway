use crate::cmd::COMMAND_PARSER_FACTORY;
use rustyline::completion::{Completer, Pair};
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;
use rustyline::{Context, Helper};

pub struct ProcessChainCommandCompleter {
    command_list: Vec<String>,
}

impl ProcessChainCommandCompleter {
    pub fn new() -> Self {
        let command_list = COMMAND_PARSER_FACTORY.get_command_list();
        Self { command_list }
    }
}

impl Completer for ProcessChainCommandCompleter {
    type Candidate = Pair;

    fn complete(
        &self, // FIXME should be `&mut self`
        line: &str,
        _pos: usize,
        _ctx: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Self::Candidate>)> {
        let words = line.split_whitespace().collect::<Vec<_>>();

        if words.len() == 1 {
            // If there's only one word, suggest commands that start with it
            let matches = self
                .command_list
                .iter()
                .filter(|k| k.starts_with(words[0]))
                .map(|k| Pair {
                    display: k.to_string(),
                    replacement: k.to_string(),
                })
                .collect();

            Ok((0, matches))
        } else {
            Ok((0, vec![]))
        }
    }
}

impl Helper for ProcessChainCommandCompleter {}
impl Hinter for ProcessChainCommandCompleter {
    type Hint = String;
}
impl Highlighter for ProcessChainCommandCompleter {}
impl Validator for ProcessChainCommandCompleter {}
