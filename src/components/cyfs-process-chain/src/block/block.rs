use crate::cmd::*;
use std::collections::HashMap;
use std::fmt;
use std::ops::Deref;
use std::str::FromStr;

// The different types of blocks, some cmds are only allowed in certain blocks
// Block type
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum BlockType {
    Probe,
    Process,
    Rewrite,
}

impl BlockType {
    pub fn as_str(&self) -> &str {
        match self {
            BlockType::Probe => "probe",
            BlockType::Process => "process",
            BlockType::Rewrite => "rewrite",
        }
    }
}

impl FromStr for BlockType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "probe" => Ok(BlockType::Probe),
            "process" => Ok(BlockType::Process),
            "rewrite" => Ok(BlockType::Rewrite),
            _ => Err(format!("Invalid block type: {}", s)),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Operator {
    And,  // &&
    Or,   // ||
    None, // None of the above
}

#[derive(Debug, Clone)]
pub enum CommandArg {
    // A simple command arg in string format
    Literal(String),

    // A command arg that is a variable, like $VAR_NAME ${VAR_NAME}
    Var(String), // A reference to a variable, like $VAR_NAME

    // An embedded command, which return is a string value and can be used as an arg, ${COMMAND}
    CommandSubstitution(Box<Expression>),
}

impl CommandArg {
    pub fn is_literal(&self) -> bool {
        matches!(self, CommandArg::Literal(_))
    }

    pub fn as_literal_str(&self) -> Option<&str> {
        if let CommandArg::Literal(s) = self {
            Some(s.as_str())
        } else {
            None
        }
    }

    pub fn is_var(&self) -> bool {
        matches!(self, CommandArg::Var(_))
    }
    
    pub fn as_var_str(&self) -> Option<&str> {
        if let CommandArg::Var(s) = self {
            Some(s.as_str())
        } else {
            None
        }
    }
}

#[derive(Debug, Clone)]
pub struct CommandArgs(Vec<CommandArg>);

impl Deref for CommandArgs {
    type Target = [CommandArg];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Default for CommandArgs {
    fn default() -> Self {
        Self::new_empty()
    }
}

impl CommandArgs {
    pub fn new_empty() -> Self {
        Self(Vec::new())
    }

    pub fn new(args: Vec<CommandArg>) -> Self {
        Self(args)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn as_slice(&self) -> &[CommandArg] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_literal(&self) -> bool {
        self.0.iter().all(|arg| arg.is_literal())
    }

    // Must all args be literal strings
    pub fn as_literal_list(&self) -> Vec<&str> {
        self.0
            .iter()
            .map(|arg| arg.as_literal_str().unwrap())
            .collect()
    }
}

// Single command
#[derive(Debug, Clone)]
pub struct Command {
    pub name: String,
    pub args: CommandArgs,
}

#[derive(Clone)]
pub struct CommandItem {
    pub command: Command,
    pub executor: Option<CommandExecutorRef>,
}

impl fmt::Debug for CommandItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Use command instead of self
        write!(f, "{:?}", self.command)
    }
}

impl CommandItem {
    pub fn new(name: String, args: CommandArgs) -> Self {
        let command = Command { name, args };
        Self {
            command,
            executor: None,
        }
    }

    pub fn new_empty() -> Self {
        Self::new("".to_string(), CommandArgs::new_empty())
    }

    pub fn take_args(&mut self) -> CommandArgs {
        std::mem::take(&mut self.command.args)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssignKind {
    // Normal assignment, use KEY=VALUE, var is visible in the current process chain
    Chain,

    // Local assignment, use local KEY=VALUE, var is only visible in the current block
    Block,

    // Global assignment, use export KEY=VALUE, var is visible in all process chains
    Global,
}

impl Default for AssignKind {
    fn default() -> Self {
        AssignKind::Chain // Default to chain level assignment
    }
}

impl AssignKind {
    pub fn as_str(&self) -> &str {
        match self {
            AssignKind::Chain => "chain",
            AssignKind::Block => "block",
            AssignKind::Global => "global",
        }
    }

    pub fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "chain" => Ok(AssignKind::Chain),
            "block" => Ok(AssignKind::Block),
            "global" => Ok(AssignKind::Global),
            _ => Err(format!("Invalid assign kind: {}", s)),
        }
    }
}

/*
#[derive(Debug, Clone)]
pub struct AssignExpression {
    pub kind: AssignKind,
    pub key: String,
    pub value: Option<CommandArg>,
}

impl AssignExpression {
    pub fn new(kind: AssignKind, key: String, value: Option<CommandArg>) -> Self {
        Self { kind, key, value }
    }
}
*/

// Command or Expression
#[derive(Debug, Clone)]
pub enum Expression {
    Command(CommandItem),
    Group(Vec<(Expression, Operator)>), // Sub-expression in brackets
    Goto(CommandArg),                   // Goto label
}

#[derive(Debug, Clone)]
pub struct Statement {
    pub expressions: Vec<(Expression, Operator)>,
}

// Line of commands, top level structure
#[derive(Debug, Clone)]
pub struct Line {
    pub label: Option<String>,      // Label of the line
    pub statements: Vec<Statement>, // Statements in the line
}

// Block of lines
#[derive(Debug, Clone)]
pub struct Block {
    // pub block_type: BlockType,
    pub id: String, // Unique identifier for the block
    pub lines: Vec<Line>,
    pub label_map: HashMap<String, usize>, // Label to line index
}

impl Block {
    pub fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            lines: Vec::new(),
            label_map: HashMap::new(),
        }
    }
}
