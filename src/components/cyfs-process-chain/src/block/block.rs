use super::linker::CommandArgEvaluator;
use crate::chain::CoercionPolicy;
use crate::chain::Context;
use crate::cmd::*;
use crate::collection::{CollectionValue, NumberValue};
use std::fmt;
use std::ops::Deref;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Operator {
    And, // &&
    Or,  // ||
    Not, // !
}

impl Operator {
    pub fn as_str(&self) -> &str {
        match self {
            Self::And => "&&",
            Self::Or => "||",
            Self::Not => "!",
        }
    }

    // If the operator is a unary operator
    pub fn is_unary(&self) -> bool {
        matches!(self, Self::Not)
    }

    // If the operator is a binary operator
    pub fn is_binary(&self) -> bool {
        matches!(self, Self::And | Self::Or)
    }
}

#[derive(Debug, Clone)]
pub enum CommandArg {
    // Unquoted token that keeps string semantics.
    // Typical examples: command options/keywords/identifiers like
    // `--from`, `lib`, `map-add`, `my_key`.
    // Note: if an unquoted token matches typed literal rules, parser emits
    // `TypedLiteral` instead of `Literal`.
    Literal(String),

    // Quoted string literal (e.g. "123", 'false', "").
    // Always preserved as string and never auto-promoted to typed literal.
    StringLiteral(String),

    // Unquoted typed literal recognized at parse-time, preserving both raw token text
    // and parsed runtime value.
    // Examples: true/false/null/123/12.5
    TypedLiteral(String, CollectionValue),

    // A command arg that is a variable, like $VAR_NAME ${VAR_NAME}
    Var(String), // A reference to a variable, like $VAR_NAME

    // An embedded command, which return is a string value and can be used as an arg, ${COMMAND}
    CommandSubstitution(Box<Expression>),
}

impl CommandArg {
    fn parse_bool_literal(raw: &str) -> Option<bool> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" | "on" => Some(true),
            "false" | "0" | "no" | "off" => Some(false),
            _ => None,
        }
    }

    fn parse_number_literal(raw: &str) -> Option<NumberValue> {
        let trimmed = raw.trim();
        if let Ok(v) = trimmed.parse::<i64>() {
            return Some(NumberValue::Int(v));
        }
        if let Ok(v) = trimmed.parse::<f64>() {
            return Some(NumberValue::Float(v));
        }
        None
    }

    fn coerce_to_string(value: CollectionValue, policy: CoercionPolicy) -> Result<String, String> {
        if let CollectionValue::String(s) = value {
            return Ok(s);
        }

        match value {
            CollectionValue::Null => match policy {
                CoercionPolicy::Legacy => Ok(String::new()),
                CoercionPolicy::Warn => {
                    warn!("Coercing Null to empty string under warn coercion policy");
                    Ok(String::new())
                }
                CoercionPolicy::Strict => {
                    let msg = "Expected string value, found Null (strict coercion)".to_string();
                    warn!("{}", msg);
                    Err(msg)
                }
            },
            CollectionValue::Bool(v) => match policy {
                CoercionPolicy::Legacy => Ok(v.to_string()),
                CoercionPolicy::Warn => {
                    warn!("Coercing Bool to string under warn coercion policy");
                    Ok(v.to_string())
                }
                CoercionPolicy::Strict => {
                    let msg = "Expected string value, found Bool (strict coercion)".to_string();
                    warn!("{}", msg);
                    Err(msg)
                }
            },
            CollectionValue::Number(v) => match policy {
                CoercionPolicy::Legacy => Ok(v.to_string()),
                CoercionPolicy::Warn => {
                    warn!("Coercing Number to string under warn coercion policy");
                    Ok(v.to_string())
                }
                CoercionPolicy::Strict => {
                    let msg = "Expected string value, found Number (strict coercion)".to_string();
                    warn!("{}", msg);
                    Err(msg)
                }
            },
            other => {
                let msg = format!("Expected string value, found: {:?}", other);
                warn!("{}", msg);
                Err(msg)
            }
        }
    }

    fn coerce_to_bool(value: CollectionValue, policy: CoercionPolicy) -> Result<bool, String> {
        match value {
            CollectionValue::Bool(v) => Ok(v),
            CollectionValue::String(s) => Self::parse_bool_literal(&s).ok_or_else(|| {
                let msg = format!("Cannot convert string '{}' to bool", s);
                warn!("{}", msg);
                msg
            }),
            CollectionValue::Number(v) => match policy {
                CoercionPolicy::Legacy => Ok(v.as_f64() != 0.0),
                CoercionPolicy::Warn => {
                    warn!("Coercing Number to bool under warn coercion policy");
                    Ok(v.as_f64() != 0.0)
                }
                CoercionPolicy::Strict => {
                    let msg = "Expected bool value, found Number (strict coercion)".to_string();
                    warn!("{}", msg);
                    Err(msg)
                }
            },
            CollectionValue::Null => match policy {
                CoercionPolicy::Legacy => Ok(false),
                CoercionPolicy::Warn => {
                    warn!("Coercing Null to bool=false under warn coercion policy");
                    Ok(false)
                }
                CoercionPolicy::Strict => {
                    let msg = "Expected bool value, found Null (strict coercion)".to_string();
                    warn!("{}", msg);
                    Err(msg)
                }
            },
            other => {
                let msg = format!("Expected bool value, found: {:?}", other);
                warn!("{}", msg);
                Err(msg)
            }
        }
    }

    fn coerce_to_number(
        value: CollectionValue,
        policy: CoercionPolicy,
    ) -> Result<NumberValue, String> {
        match value {
            CollectionValue::Number(v) => Ok(v),
            CollectionValue::String(s) => Self::parse_number_literal(&s).ok_or_else(|| {
                let msg = format!("Cannot convert string '{}' to number", s);
                warn!("{}", msg);
                msg
            }),
            CollectionValue::Bool(v) => match policy {
                CoercionPolicy::Legacy => Ok(NumberValue::Int(if v { 1 } else { 0 })),
                CoercionPolicy::Warn => {
                    warn!("Coercing Bool to number under warn coercion policy");
                    Ok(NumberValue::Int(if v { 1 } else { 0 }))
                }
                CoercionPolicy::Strict => {
                    let msg = "Expected number value, found Bool (strict coercion)".to_string();
                    warn!("{}", msg);
                    Err(msg)
                }
            },
            CollectionValue::Null => match policy {
                CoercionPolicy::Legacy => Ok(NumberValue::Int(0)),
                CoercionPolicy::Warn => {
                    warn!("Coercing Null to number=0 under warn coercion policy");
                    Ok(NumberValue::Int(0))
                }
                CoercionPolicy::Strict => {
                    let msg = "Expected number value, found Null (strict coercion)".to_string();
                    warn!("{}", msg);
                    Err(msg)
                }
            },
            other => {
                let msg = format!("Expected number value, found: {:?}", other);
                warn!("{}", msg);
                Err(msg)
            }
        }
    }

    pub fn is_literal(&self) -> bool {
        matches!(
            self,
            CommandArg::Literal(_) | CommandArg::StringLiteral(_) | CommandArg::TypedLiteral(_, _)
        )
    }

    pub fn as_literal_str(&self) -> Option<&str> {
        match self {
            CommandArg::Literal(s)
            | CommandArg::StringLiteral(s)
            | CommandArg::TypedLiteral(s, _) => Some(s.as_str()),
            _ => None,
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

    pub fn as_str(&self) -> &str {
        match self {
            CommandArg::Literal(s)
            | CommandArg::StringLiteral(s)
            | CommandArg::TypedLiteral(s, _) => s.as_str(),
            CommandArg::Var(s) => s.as_str(),
            CommandArg::CommandSubstitution(_) => "[command substitution]",
        }
    }

    pub fn is_command_substitution(&self) -> bool {
        matches!(self, CommandArg::CommandSubstitution(_))
    }

    pub fn as_command_substitution(&self) -> Option<&Box<Expression>> {
        if let CommandArg::CommandSubstitution(cmd) = self {
            Some(cmd)
        } else {
            None
        }
    }

    pub fn as_command_substitution_mut(&mut self) -> Option<&mut Box<Expression>> {
        if let CommandArg::CommandSubstitution(cmd) = self {
            Some(cmd)
        } else {
            None
        }
    }

    pub async fn evaluate(&self, context: &Context) -> Result<CollectionValue, String> {
        CommandArgEvaluator::evaluate(self, context).await
    }

    pub async fn evaluate_string(&self, context: &Context) -> Result<String, String> {
        let value = self.evaluate(context).await?;
        Self::coerce_to_string(value, context.env().coercion_policy())
    }

    pub async fn evaluate_bool(&self, context: &Context) -> Result<bool, String> {
        let value = self.evaluate(context).await?;
        Self::coerce_to_bool(value, context.env().coercion_policy())
    }

    pub async fn evaluate_number(&self, context: &Context) -> Result<NumberValue, String> {
        let value = self.evaluate(context).await?;
        Self::coerce_to_number(value, context.env().coercion_policy())
    }

    pub async fn evaluate_nullable(
        &self,
        context: &Context,
    ) -> Result<Option<CollectionValue>, String> {
        let value = self.evaluate(context).await?;
        if value.is_null() {
            Ok(None)
        } else {
            Ok(Some(value))
        }
    }

    pub async fn evaluate_list(
        args: &[CommandArg],
        context: &Context,
    ) -> Result<Vec<CollectionValue>, String> {
        CommandArgEvaluator::evaluate_list(args, context).await
    }

    pub async fn evaluate_string_list(
        args: &[CommandArg],
        context: &Context,
    ) -> Result<Vec<String>, String> {
        let values = Self::evaluate_list(args, context).await?;
        let coercion = context.env().coercion_policy();
        let mut result = Vec::with_capacity(values.len());
        for value in values {
            result.push(Self::coerce_to_string(value, coercion)?);
        }

        Ok(result)
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

impl std::ops::DerefMut for CommandArgs {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
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

    pub fn push_front(&mut self, arg: CommandArg) {
        self.0.insert(0, arg);
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

    pub fn as_str_list(&self) -> Vec<&str> {
        self.0.iter().map(|arg| arg.as_str()).collect()
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
        write!(f, "{:?}, exec={}", self.command, self.executor.is_some())
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

// Command or Expression
#[derive(Debug, Clone)]
pub enum Expression {
    Command(CommandItem),
    Group(Vec<(Option<Operator>, Expression, Option<Operator>)>), // Sub-expression in brackets
}

pub type ExpressionChain = Vec<(Option<Operator>, Expression, Option<Operator>)>;

impl Expression {
    pub fn is_command(&self) -> bool {
        matches!(self, Expression::Command(_))
    }

    pub fn as_command(&self) -> Option<&CommandItem> {
        if let Expression::Command(cmd) = self {
            Some(cmd)
        } else {
            None
        }
    }

    pub fn is_group(&self) -> bool {
        matches!(self, Expression::Group(_))
    }

    pub fn as_group(&self) -> Option<&Vec<(Option<Operator>, Expression, Option<Operator>)>> {
        if let Expression::Group(group) = self {
            Some(group)
        } else {
            None
        }
    }
}

#[derive(Debug, Clone)]
pub struct IfBranch {
    pub condition: ExpressionChain,
    pub lines: Vec<Line>,
}

#[derive(Debug, Clone)]
pub struct IfStatement {
    pub branches: Vec<IfBranch>,
    pub else_lines: Option<Vec<Line>>,
}

#[derive(Debug, Clone)]
pub struct Statement {
    pub expressions: ExpressionChain,
    pub if_statement: Option<IfStatement>,
}

impl Statement {
    pub fn new_expressions(expressions: ExpressionChain) -> Self {
        Self {
            expressions,
            if_statement: None,
        }
    }

    pub fn new_if(if_statement: IfStatement) -> Self {
        Self {
            expressions: Vec::new(),
            if_statement: Some(if_statement),
        }
    }
}

// Line of commands, top level structure
#[derive(Debug, Clone)]
pub struct Line {
    pub source: String,             // Source code of the line
    pub statements: Vec<Statement>, // Statements in the line
}

// Block of lines
#[derive(Debug, Clone)]
pub struct Block {
    pub id: String, // Unique identifier for the block
    pub lines: Vec<Line>,
}

impl Block {
    pub fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            lines: Vec::new(),
        }
    }
}
