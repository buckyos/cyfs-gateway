use super::block::{Block, CommandArg, CommandItem, Expression, IfStatement, Line, Statement};
use super::exec::BlockExecuter;
use super::parser::BlockParser;
use crate::chain::{Context, MissingVarPolicy, ParserContextRef};
use crate::cmd::CommandParserFactory;
use crate::collection::CollectionValue;

pub struct BlockCommandLinker {
    context: ParserContextRef,
    parser: CommandParserFactory,
}

impl BlockCommandLinker {
    pub fn new(context: ParserContextRef, parser: CommandParserFactory) -> Self {
        Self { context, parser }
    }

    pub async fn link(&self, block: &mut Block) -> Result<(), String> {
        for line in &mut block.lines {
            self.link_line(line)?;
        }

        Ok(())
    }

    fn link_line(&self, line: &mut Line) -> Result<(), String> {
        for statement in &mut line.statements {
            self.link_statement(statement)?;
        }

        Ok(())
    }

    fn link_statement(&self, statement: &mut Statement) -> Result<(), String> {
        if let Some(if_statement) = statement.if_statement.as_mut() {
            self.link_if_statement(if_statement)?;
            return Ok(());
        }

        // For each statement, we need to link the expressions
        for (_, expr, _) in &mut statement.expressions {
            self.link_expression(expr)?;
        }

        Ok(())
    }

    fn link_if_statement(&self, if_statement: &mut IfStatement) -> Result<(), String> {
        for branch in &mut if_statement.branches {
            for (_, expr, _) in &mut branch.condition {
                self.link_expression(expr)?;
            }
            for line in &mut branch.lines {
                self.link_line(line)?;
            }
        }

        if let Some(else_lines) = if_statement.else_lines.as_mut() {
            for line in else_lines {
                self.link_line(line)?;
            }
        }

        Ok(())
    }

    fn link_expression(&self, expr: &mut Expression) -> Result<(), String> {
        match expr {
            Expression::Command(cmd) => {
                self.link_command(cmd)?;
            }
            Expression::Group(exprs) => {
                // For group expressions, we need to link each sub-expression
                for (_, sub_expr, _) in exprs {
                    self.link_expression(sub_expr)?;
                }
            }
        }

        Ok(())
    }

    fn link_command(&self, cmd: &mut CommandItem) -> Result<(), String> {
        // debug!("Linking command: {:?}", cmd.command);
        let mut parser = self.parser.get_parser(&cmd.command.name);
        if parser.is_none() {
            // Check if it's a external command
            if self
                .context
                .get_external_command(&cmd.command.name)
                .is_some()
            {
                info!(
                    "Command '{}' is an external command, using 'call' parser",
                    cmd.command.name
                );
                // It's an external command without 'call' keyword
                cmd.command
                    .args
                    .push_front(CommandArg::Literal("call".to_string()));
                cmd.command.name = "call".to_string();

                parser = self.parser.get_parser("call");
            }

            if parser.is_none() {
                let msg = format!("No parser for command: {}", cmd.command.name);
                error!("{}", msg);
                return Err(msg);
            }
        }

        // Recursively link the command arguments
        for arg in &mut cmd.command.args.iter_mut() {
            match arg.as_command_substitution_mut() {
                Some(exp) => {
                    // If it's a command substitution, we need to link it as well
                    self.link_expression(exp)?;
                }
                None => {
                    continue; // Literal or variable, no translation needed
                }
            }
        }

        let parser = parser.unwrap();
        match parser.parse_origin(&self.context, &cmd.command.args) {
            Ok(executor) => {
                // debug!("Command linked: {:?}", cmd.command);
                cmd.executor = Some(executor);

                Ok(())
            }
            Err(e) => {
                let msg = format!("Failed to parse command: {:?} {}", cmd.command, e);
                error!("{}", msg);
                Err(msg)
            }
        }
    }
}

/*
pub struct DelayedCommandExecutor {
    context: ParserContextRef,
    parser: Arc<Box<dyn CommandParser>>,
    args: CommandArgs,
}

impl DelayedCommandExecutor {
    pub fn new(
        context: ParserContextRef,
        parser: Arc<Box<dyn CommandParser>>,
        args: CommandArgs,
    ) -> Self {
        Self {
            context,
            parser,
            args,
        }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for DelayedCommandExecutor {
    async fn exec(&self, context: &Context) -> Result<CommandResult, String> {
        debug!("Executing delayed command with args: {:?}", self.args);

        // First exec embedded commands in args to got their values
        let mut resolved_args = Vec::with_capacity(self.args.len());
        for arg in &*self.args {
            let ret = CommandArgEvaluator::evaluate(arg, context)
                .await
                .map_err(|e| {
                    let msg = format!("Failed to evaluate command arg: {:?}, {}", arg, e);
                    error!("{}", msg);
                    msg
                })?;

            resolved_args.push(ret);
        }

        // Parse the command using the dynamic parser
        let executor =
            self.parser
                .parse_origin_with_context(&self.context, resolved_args, &self.args)?;
        executor.exec(context).await
    }
}

*/

pub struct CommandArgEvaluator {}

#[derive(Debug, Clone, PartialEq, Eq)]
enum VarPathSegment {
    Static(String),
    Dynamic(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct VarPathAccessSegment {
    segment: VarPathSegment,
    optional: bool,
}

#[derive(Debug, Clone)]
enum VarEvalResult {
    Value(CollectionValue),
    Missing { key: String, explicit: bool },
}

impl CommandArgEvaluator {
    pub async fn evaluate_list(
        args: &[CommandArg],
        context: &Context,
    ) -> Result<Vec<CollectionValue>, String> {
        let mut results = Vec::with_capacity(args.len());
        for arg in args {
            let ret = Self::evaluate(arg, context).await?;
            results.push(ret);
        }
        Ok(results)
    }

    fn find_matching_paren(input: &str, start: usize) -> Option<usize> {
        let mut depth = 0usize;
        for (offset, c) in input[start..].char_indices() {
            if c == '(' {
                depth += 1;
            } else if c == ')' {
                depth -= 1;
                if depth == 0 {
                    return Some(start + offset);
                }
            }
        }
        None
    }

    fn find_matching_bracket(input: &str, start: usize) -> Option<usize> {
        let mut depth = 0usize;
        let mut quote: Option<char> = None;
        let mut escaped = false;

        for (offset, c) in input[start..].char_indices() {
            if let Some(q) = quote {
                if escaped {
                    escaped = false;
                    continue;
                }

                if c == '\\' {
                    escaped = true;
                    continue;
                }

                if c == q {
                    quote = None;
                }

                continue;
            }

            if c == '"' || c == '\'' {
                quote = Some(c);
                continue;
            }

            if c == '[' {
                depth += 1;
            } else if c == ']' {
                depth -= 1;
                if depth == 0 {
                    return Some(start + offset);
                }
            }
        }

        None
    }

    fn escape_path_segment(segment: &str) -> String {
        let mut escaped = String::with_capacity(segment.len());
        for ch in segment.chars() {
            match ch {
                '\\' => escaped.push_str("\\\\"),
                '.' => escaped.push_str("\\."),
                _ => escaped.push(ch),
            }
        }

        escaped
    }

    fn push_static_segment(
        segments: &mut Vec<VarPathAccessSegment>,
        current: &mut String,
        pending_optional: &mut bool,
    ) {
        if !current.is_empty() {
            segments.push(VarPathAccessSegment {
                segment: VarPathSegment::Static(std::mem::take(current)),
                optional: *pending_optional,
            });
            *pending_optional = false;
        }
    }

    fn parse_dynamic_segment(inner: &str) -> Result<VarPathSegment, String> {
        let inner = inner.trim();
        if let Some(inner_var) = inner.strip_prefix("${") {
            if !inner.ends_with('}') {
                let msg = format!("Invalid braced dynamic segment: {}", inner);
                error!("{}", msg);
                return Err(msg);
            }

            let inner_var = inner_var[..inner_var.len() - 1].trim();
            if inner_var.is_empty() {
                let msg = "Dynamic segment cannot be empty".to_string();
                error!("{}", msg);
                return Err(msg);
            }
            Ok(VarPathSegment::Dynamic(inner_var.to_string()))
        } else if let Some(inner_var) = inner.strip_prefix('$') {
            let inner_var = inner_var.trim();
            if inner_var.is_empty() {
                let msg = "Dynamic segment cannot be empty after '$'".to_string();
                error!("{}", msg);
                return Err(msg);
            }
            Ok(VarPathSegment::Dynamic(inner_var.to_string()))
        } else {
            Ok(VarPathSegment::Static(inner.to_string()))
        }
    }

    fn parse_bracket_segment(var: &str, start: usize) -> Result<(VarPathSegment, usize), String> {
        let end = Self::find_matching_bracket(var, start).ok_or_else(|| {
            let msg = format!("Unclosed bracket segment in variable: {}", var);
            error!("{}", msg);
            msg
        })?;

        let inner = var[start + 1..end].trim();
        if inner.is_empty() {
            return Ok((VarPathSegment::Static(String::new()), end + 1));
        }

        let first = inner.chars().next().unwrap();
        let last = inner.chars().last().unwrap();
        if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
            let quoted = &inner[1..inner.len() - 1];
            let mut value = String::new();
            let mut escaped = false;
            for ch in quoted.chars() {
                if escaped {
                    value.push(ch);
                    escaped = false;
                    continue;
                }

                if ch == '\\' {
                    escaped = true;
                    continue;
                }

                value.push(ch);
            }

            if escaped {
                value.push('\\');
            }

            return Ok((VarPathSegment::Static(value), end + 1));
        }

        let segment = Self::parse_dynamic_segment(inner)?;
        Ok((segment, end + 1))
    }

    fn parse_var_path(var: &str) -> Result<Vec<VarPathAccessSegment>, String> {
        let mut i = 0usize;
        let mut current = String::new();
        let mut segments = Vec::new();
        let mut pending_optional = false;

        while i < var.len() {
            let ch = var[i..].chars().next().ok_or_else(|| {
                let msg = format!("Invalid variable path: {}", var);
                error!("{}", msg);
                msg
            })?;

            if ch == '\\' {
                i += ch.len_utf8();
                if i < var.len() {
                    let escaped = var[i..].chars().next().ok_or_else(|| {
                        let msg = format!("Invalid escape in variable path: {}", var);
                        error!("{}", msg);
                        msg
                    })?;
                    current.push(escaped);
                    i += escaped.len_utf8();
                } else {
                    current.push('\\');
                }

                continue;
            }

            if ch == '?' {
                let next = i + ch.len_utf8();
                if next < var.len() && var[next..].starts_with('.') {
                    if current.is_empty() && segments.is_empty() {
                        let msg = format!(
                            "Invalid optional access at beginning of variable path: {}",
                            var
                        );
                        error!("{}", msg);
                        return Err(msg);
                    }

                    Self::push_static_segment(&mut segments, &mut current, &mut pending_optional);
                    pending_optional = true;
                    i = next + 1;

                    // Optional legacy dynamic segment: a?.($var)
                    if i < var.len() && var[i..].starts_with('(') {
                        let end = Self::find_matching_paren(var, i).ok_or_else(|| {
                            let msg = format!("Unclosed dynamic segment in variable: {}", var);
                            error!("{}", msg);
                            msg
                        })?;
                        let inner = &var[i + 1..end];
                        segments.push(VarPathAccessSegment {
                            segment: Self::parse_dynamic_segment(inner)?,
                            optional: pending_optional,
                        });
                        pending_optional = false;
                        i = end + 1;
                    }
                    continue;
                }

                if next < var.len() && var[next..].starts_with('[') {
                    if current.is_empty() && segments.is_empty() {
                        let msg = format!(
                            "Invalid optional bracket access at beginning of variable path: {}",
                            var
                        );
                        error!("{}", msg);
                        return Err(msg);
                    }

                    Self::push_static_segment(&mut segments, &mut current, &mut pending_optional);
                    let (segment, next_index) = Self::parse_bracket_segment(var, next)?;
                    segments.push(VarPathAccessSegment {
                        segment,
                        optional: true,
                    });
                    pending_optional = false;
                    i = next_index;
                    continue;
                }
            }

            if ch == '.' {
                // Legacy dynamic segment syntax: a.($var) / a.(${var}) / a.(literal)
                let next_index = i + ch.len_utf8();
                if next_index < var.len() && var[next_index..].starts_with('(') {
                    Self::push_static_segment(&mut segments, &mut current, &mut pending_optional);

                    let end = Self::find_matching_paren(var, next_index).ok_or_else(|| {
                        let msg = format!("Unclosed dynamic segment in variable: {}", var);
                        error!("{}", msg);
                        msg
                    })?;
                    let inner = &var[next_index + 1..end];
                    segments.push(VarPathAccessSegment {
                        segment: Self::parse_dynamic_segment(inner)?,
                        optional: pending_optional,
                    });
                    pending_optional = false;
                    i = end + 1;
                    continue;
                }

                Self::push_static_segment(&mut segments, &mut current, &mut pending_optional);
                i += ch.len_utf8();
                continue;
            }

            if ch == '[' {
                Self::push_static_segment(&mut segments, &mut current, &mut pending_optional);

                let (segment, next_index) = Self::parse_bracket_segment(var, i)?;
                segments.push(VarPathAccessSegment {
                    segment,
                    optional: pending_optional,
                });
                pending_optional = false;
                i = next_index;
                continue;
            }

            current.push(ch);
            i += ch.len_utf8();
        }

        if pending_optional && current.is_empty() {
            let msg = format!("Invalid variable path ending with optional access: {}", var);
            error!("{}", msg);
            return Err(msg);
        }

        if !current.is_empty() {
            segments.push(VarPathAccessSegment {
                segment: VarPathSegment::Static(current),
                optional: pending_optional,
            });
        }

        if segments.is_empty() {
            let msg = format!("Variable path is empty: {}", var);
            error!("{}", msg);
            return Err(msg);
        }

        Ok(segments)
    }

    fn normalize_segment_list(segments: &[String]) -> String {
        segments
            .iter()
            .map(|segment| Self::escape_path_segment(segment))
            .collect::<Vec<_>>()
            .join(".")
    }

    #[async_recursion::async_recursion]
    async fn resolve_segment_key(
        segment: &VarPathSegment,
        current_var_path: &str,
        context: &Context,
    ) -> Result<String, String> {
        let policy = context.env().policy();
        match segment {
            VarPathSegment::Static(value) => Ok(value.clone()),
            VarPathSegment::Dynamic(expr) => {
                let resolved = Self::evaluate_var_expression(expr, context).await?;
                match resolved {
                    VarEvalResult::Value(value) => value.try_as_str().map(|v| v.to_string()),
                    VarEvalResult::Missing { key, explicit } => {
                        if explicit || policy.missing_var == MissingVarPolicy::Lenient {
                            Ok(String::new())
                        } else {
                            let missing_key = if key.is_empty() {
                                expr.to_string()
                            } else {
                                key
                            };
                            let msg = format!(
                                "Dynamic segment variable '{}' not found while resolving '{}'",
                                missing_key, current_var_path
                            );
                            error!("{}", msg);
                            Err(msg)
                        }
                    }
                }
            }
        }
    }

    fn find_top_level_coalesce(expr: &str) -> Option<usize> {
        let mut i = 0usize;
        let mut paren_depth = 0usize;
        let mut bracket_depth = 0usize;
        let mut quote: Option<char> = None;
        let mut escaped = false;

        while i < expr.len() {
            let ch = expr[i..].chars().next()?;

            if let Some(q) = quote {
                i += ch.len_utf8();
                if escaped {
                    escaped = false;
                    continue;
                }

                if ch == '\\' {
                    escaped = true;
                    continue;
                }

                if ch == q {
                    quote = None;
                }
                continue;
            }

            if ch == '"' || ch == '\'' {
                quote = Some(ch);
                i += ch.len_utf8();
                continue;
            }

            if ch == '[' {
                bracket_depth += 1;
                i += ch.len_utf8();
                continue;
            }
            if ch == ']' {
                if bracket_depth > 0 {
                    bracket_depth -= 1;
                }
                i += ch.len_utf8();
                continue;
            }

            if ch == '(' {
                paren_depth += 1;
                i += ch.len_utf8();
                continue;
            }
            if ch == ')' {
                if paren_depth > 0 {
                    paren_depth -= 1;
                }
                i += ch.len_utf8();
                continue;
            }

            if ch == '?'
                && bracket_depth == 0
                && paren_depth == 0
                && i + ch.len_utf8() < expr.len()
                && expr[i + ch.len_utf8()..].starts_with('?')
            {
                return Some(i);
            }

            i += ch.len_utf8();
        }

        None
    }

    fn should_parse_default_as_arg(expr: &str) -> bool {
        let expr = expr.trim_start();
        expr.starts_with('$') || expr.starts_with('"') || expr.starts_with('\'')
    }

    #[async_recursion::async_recursion]
    async fn evaluate_default_expression(
        expr: &str,
        context: &Context,
    ) -> Result<VarEvalResult, String> {
        let expr = expr.trim();
        if expr.is_empty() {
            let msg = "Default expression is empty".to_string();
            error!("{}", msg);
            return Err(msg);
        }

        if Self::should_parse_default_as_arg(expr) {
            let (rest, arg) = BlockParser::parse_arg(expr).map_err(|e| {
                let msg = format!("Invalid default expression '{}': {:?}", expr, e);
                error!("{}", msg);
                msg
            })?;

            if !rest.trim().is_empty() {
                let msg = format!(
                    "Invalid trailing content in default expression '{}': '{}'",
                    expr, rest
                );
                error!("{}", msg);
                return Err(msg);
            }

            if matches!(arg, CommandArg::CommandSubstitution(_)) {
                let msg = format!(
                    "Command substitution is not supported in default expression yet: '{}'",
                    expr
                );
                error!("{}", msg);
                return Err(msg);
            }

            let value = Self::evaluate(&arg, context).await?;
            return Ok(VarEvalResult::Value(value));
        }

        Self::evaluate_var_expression(expr, context).await
    }

    #[async_recursion::async_recursion]
    async fn evaluate_var_path(var: &str, context: &Context) -> Result<VarEvalResult, String> {
        let parsed = Self::parse_var_path(var)?;
        let mut resolved_segments = Vec::with_capacity(parsed.len());

        let first = parsed.first().ok_or_else(|| {
            let msg = format!("Variable path is empty: {}", var);
            error!("{}", msg);
            msg
        })?;
        if first.optional {
            let msg = format!(
                "Invalid optional access for root segment in variable path: {}",
                var
            );
            error!("{}", msg);
            return Err(msg);
        }

        let root_key = Self::resolve_segment_key(&first.segment, var, context).await?;
        resolved_segments.push(root_key.clone());

        let mut current_value = context.env().get(&root_key, None).await?;
        if parsed.len() == 1 {
            return match current_value {
                Some(value) => Ok(VarEvalResult::Value(value)),
                None => Ok(VarEvalResult::Missing {
                    key: Self::normalize_segment_list(&resolved_segments),
                    explicit: false,
                }),
            };
        }

        let mut current_key = root_key;
        for (index, access) in parsed.iter().enumerate().skip(1) {
            let segment_key = Self::resolve_segment_key(&access.segment, var, context).await?;
            resolved_segments.push(segment_key.clone());
            let is_last = index == parsed.len() - 1;

            let next_value = match current_value {
                Some(CollectionValue::Map(map)) => map.get(&segment_key).await?,
                Some(CollectionValue::Set(set)) => {
                    if is_last {
                        if set.contains(&segment_key).await? {
                            Some(CollectionValue::String(segment_key.clone()))
                        } else {
                            None
                        }
                    } else if access.optional {
                        return Ok(VarEvalResult::Missing {
                            key: Self::normalize_segment_list(&resolved_segments),
                            explicit: true,
                        });
                    } else {
                        let found = CollectionValue::Set(set.clone());
                        let msg = format!("Expected a map at '{}', found: {}", current_key, found);
                        warn!("{}", msg);
                        return Err(msg);
                    }
                }
                Some(CollectionValue::MultiMap(multi_map)) => {
                    if is_last {
                        multi_map
                            .get_many(&segment_key)
                            .await?
                            .map(CollectionValue::Set)
                    } else if access.optional {
                        return Ok(VarEvalResult::Missing {
                            key: Self::normalize_segment_list(&resolved_segments),
                            explicit: true,
                        });
                    } else {
                        let found = CollectionValue::MultiMap(multi_map.clone());
                        let msg = format!("Expected a map at '{}', found: {}", current_key, found);
                        warn!("{}", msg);
                        return Err(msg);
                    }
                }
                Some(value) => {
                    if access.optional {
                        return Ok(VarEvalResult::Missing {
                            key: Self::normalize_segment_list(&resolved_segments),
                            explicit: true,
                        });
                    }

                    let msg = format!("Expected a map at '{}', found: {}", current_key, value);
                    warn!("{}", msg);
                    return Err(msg);
                }
                None => {
                    return Ok(VarEvalResult::Missing {
                        key: Self::normalize_segment_list(&resolved_segments),
                        explicit: access.optional,
                    });
                }
            };

            current_key = segment_key;
            current_value = next_value;
        }

        match current_value {
            Some(value) => Ok(VarEvalResult::Value(value)),
            None => Ok(VarEvalResult::Missing {
                key: Self::normalize_segment_list(&resolved_segments),
                explicit: parsed.last().map(|s| s.optional).unwrap_or(false),
            }),
        }
    }

    #[async_recursion::async_recursion]
    async fn evaluate_var_expression(
        var: &str,
        context: &Context,
    ) -> Result<VarEvalResult, String> {
        let var = var.trim();
        if var.is_empty() {
            let msg = "Variable expression is empty".to_string();
            error!("{}", msg);
            return Err(msg);
        }

        if let Some(index) = Self::find_top_level_coalesce(var) {
            let lhs = var[..index].trim();
            let rhs = var[index + 2..].trim();
            if lhs.is_empty() || rhs.is_empty() {
                let msg = format!("Invalid coalesce expression: '{}'", var);
                error!("{}", msg);
                return Err(msg);
            }

            let lhs_value = Self::evaluate_var_expression(lhs, context).await?;
            match lhs_value {
                VarEvalResult::Value(value) => Ok(VarEvalResult::Value(value)),
                VarEvalResult::Missing { .. } => {
                    Self::evaluate_default_expression(rhs, context).await
                }
            }
        } else {
            Self::evaluate_var_path(var, context).await
        }
    }

    #[async_recursion::async_recursion]
    pub async fn evaluate(arg: &CommandArg, context: &Context) -> Result<CollectionValue, String> {
        let ret = match arg {
            CommandArg::Literal(value) => CollectionValue::String(value.clone()),
            CommandArg::StringLiteral(value) => CollectionValue::String(value.clone()),
            CommandArg::TypedLiteral(_, value) => value.clone(),
            CommandArg::Var(var) => {
                debug!("Resolving variable: {}", var);
                let policy = context.env().policy();
                match Self::evaluate_var_expression(var, context).await? {
                    VarEvalResult::Value(value) => value,
                    VarEvalResult::Missing { key, explicit } => {
                        if explicit {
                            // Explicit optional access (?. / ?[]) suppresses strict missing-var errors.
                            CollectionValue::String(String::new())
                        } else {
                            match policy.missing_var {
                                MissingVarPolicy::Lenient => {
                                    warn!(
                                        "Variable '{}' not found in context, using empty string",
                                        key
                                    );
                                    CollectionValue::String(String::new())
                                }
                                MissingVarPolicy::Strict => {
                                    let msg = format!("Variable '{}' not found in context", key);
                                    error!("{}", msg);
                                    return Err(msg);
                                }
                            }
                        }
                    }
                }
            }
            CommandArg::CommandSubstitution(cmd) => {
                let ret = BlockExecuter::execute_expression(cmd, context).await?;
                if !ret.is_substitution_value() {
                    let msg = format!("Command substitution did not return a value: {:?}", cmd);
                    warn!("{}", msg);
                    return Err(msg);
                }

                CollectionValue::String(ret.into_substitution_value().unwrap())
            }
        };

        debug!("Evaluated command arg: {:?}, result: {:?}", arg, ret);
        Ok(ret)
    }
}
