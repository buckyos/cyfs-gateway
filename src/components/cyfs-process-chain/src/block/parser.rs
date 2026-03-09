use super::block::*;
use crate::collection::{CollectionValue, NumberValue};
use nom::{
    IResult, Parser,
    branch::alt,
    bytes::complete::tag,
    bytes::complete::{escaped_transform, is_not},
    bytes::streaming::take_while1,
    character::complete::{alpha1, alphanumeric1, char},
    character::complete::{space0, space1},
    combinator::{complete, map, opt, recognize, value},
    error::{ErrorKind, ParseError},
    multi::many0,
    multi::separated_list0,
    sequence::{delimited, pair, preceded, terminated},
};

pub struct BlockParser {
    id: String,
}

impl BlockParser {
    fn parse_typed_number_literal(input: &str) -> Option<CollectionValue> {
        if input.is_empty() {
            return None;
        }

        let (sign, rest) = if let Some(stripped) = input.strip_prefix('-') {
            ("-", stripped)
        } else {
            ("", input)
        };

        if rest.is_empty() {
            return None;
        }

        if !rest.contains('.') {
            if rest.chars().all(|c| c.is_ascii_digit()) {
                let raw = format!("{}{}", sign, rest);
                if let Ok(v) = raw.parse::<i64>() {
                    return Some(CollectionValue::Number(NumberValue::Int(v)));
                }
            }

            return None;
        }

        let mut split = rest.split('.');
        let int_part = split.next().unwrap_or_default();
        let frac_part = split.next().unwrap_or_default();

        if split.next().is_some() {
            return None;
        }

        if int_part.is_empty() || frac_part.is_empty() {
            return None;
        }

        if !int_part.chars().all(|c| c.is_ascii_digit())
            || !frac_part.chars().all(|c| c.is_ascii_digit())
        {
            return None;
        }

        let raw = format!("{}{}", sign, rest);
        raw.parse::<f64>()
            .ok()
            .map(|v| CollectionValue::Number(NumberValue::Float(v)))
    }

    fn parse_typed_literal(input: &str) -> Option<CollectionValue> {
        match input {
            "true" => Some(CollectionValue::Bool(true)),
            "false" => Some(CollectionValue::Bool(false)),
            "null" => Some(CollectionValue::Null),
            _ => Self::parse_typed_number_literal(input),
        }
    }

    pub fn new(id: &str) -> Self {
        Self { id: id.to_owned() }
    }
}

impl BlockParser {
    pub fn parse(&self, block: &str) -> Result<Block, String> {
        let lines: Vec<&str> = Self::split_lines(block);
        let mut block = Block::new(&self.id);

        if lines.is_empty() {
            warn!("Empty block");
            return Ok(block);
        }

        let (parsed_lines, index) = Self::parse_lines(&lines, 0, false)?;
        if index != lines.len() {
            let msg = format!(
                "Unexpected parser stop at line {}, total lines {}",
                index + 1,
                lines.len()
            );
            error!("{}", msg);
            return Err(msg);
        }
        block.lines = parsed_lines;

        Ok(block)
    }

    // Block contains multiple lines, first split them into lines
    // The lines are separated by '\n' or '\r\n' or '\r' for different OS
    fn split_lines(block: &str) -> Vec<&str> {
        block
            .split(|c| c == '\n' || c == '\r')
            .map(|line| line.trim_end_matches('\r').trim()) // Remove '\r' at the end of line if any
            .filter(|line| {
                if line.is_empty() {
                    return false; // Filter out empty lines
                }

                // Filter out lines that are comments
                !line.starts_with('#') && !line.starts_with("//")
            }) // Filter out empty lines
            .collect()
    }

    fn parse_lines(
        lines: &[&str],
        mut index: usize,
        stop_at_control_keywords: bool,
    ) -> Result<(Vec<Line>, usize), String> {
        let mut parsed_lines = Vec::new();
        while index < lines.len() {
            let line = lines[index].trim();
            if let Some(keyword) = Self::line_control_keyword(line) {
                if stop_at_control_keywords {
                    break;
                } else {
                    let msg = format!(
                        "Unexpected '{}' at line {} without matching 'if'",
                        keyword,
                        index + 1
                    );
                    error!("{}", msg);
                    return Err(msg);
                }
            }

            debug!("Parsing line {}: {}", index, line);
            let (parsed_line, next_index) = if Self::is_if_header(line) {
                Self::parse_if_statement(lines, index)?
            } else if Self::is_for_header(line) {
                Self::parse_for_statement(lines, index)?
            } else {
                (Self::parse_line(line)?, index + 1)
            };

            info!("Parsed line {}: {:?}", index, parsed_line);
            parsed_lines.push(parsed_line);
            index = next_index;
        }

        Ok((parsed_lines, index))
    }

    fn line_control_keyword(line: &str) -> Option<&'static str> {
        let line = line.trim();
        if line == "else" {
            return Some("else");
        }
        if line == "end" {
            return Some("end");
        }
        if line.starts_with("elif ") && line.ends_with(" then") {
            return Some("elif");
        }

        None
    }

    fn is_if_header(line: &str) -> bool {
        let line = line.trim();
        line.starts_with("if ") && line.ends_with(" then")
    }

    fn is_for_header(line: &str) -> bool {
        let line = line.trim();
        line.starts_with("for ") && line.ends_with(" then")
    }

    fn is_valid_loop_var_name(name: &str) -> bool {
        let mut chars = name.chars();
        let Some(first) = chars.next() else {
            return false;
        };

        if !(first.is_ascii_alphabetic() || first == '_') {
            return false;
        }

        chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
    }

    fn parse_for_header(line: &str) -> Result<(String, Option<String>, CommandArg), String> {
        let line = line.trim();
        let body = line
            .strip_prefix("for")
            .ok_or_else(|| format!("Invalid 'for' header: '{}'", line))?
            .trim_start();
        let body = body.strip_suffix("then").ok_or_else(|| {
            let msg = format!("'for' header must end with 'then': '{}'", line);
            error!("{}", msg);
            msg
        })?;
        let body = body.trim_end();
        if body.is_empty() {
            let msg = format!("'for' header must not be empty: '{}'", line);
            error!("{}", msg);
            return Err(msg);
        }

        let in_pos = body.find(" in ").ok_or_else(|| {
            let msg = format!("'for' header must contain 'in': '{}'", line);
            error!("{}", msg);
            msg
        })?;

        let vars_part = body[..in_pos].trim();
        let iterable_part = body[in_pos + " in ".len()..].trim();
        if vars_part.is_empty() || iterable_part.is_empty() {
            let msg = format!("Invalid 'for' header: '{}'", line);
            error!("{}", msg);
            return Err(msg);
        }

        let vars = vars_part.split(',').map(|s| s.trim()).collect::<Vec<_>>();
        if vars.is_empty() || vars.len() > 2 || vars.iter().any(|v| v.is_empty()) {
            let msg = format!(
                "Invalid loop variable list '{}', expected 'key' or 'key, value'",
                vars_part
            );
            error!("{}", msg);
            return Err(msg);
        }

        let key_var = vars[0].to_string();
        if !Self::is_valid_loop_var_name(&key_var) {
            let msg = format!("Invalid loop variable name '{}'", key_var);
            error!("{}", msg);
            return Err(msg);
        }

        let value_var = if vars.len() == 2 {
            let value_var = vars[1].to_string();
            if !Self::is_valid_loop_var_name(&value_var) {
                let msg = format!("Invalid loop variable name '{}'", value_var);
                error!("{}", msg);
                return Err(msg);
            }
            if value_var == key_var {
                let msg = format!(
                    "Loop variable names must be different, found duplicate '{}'",
                    value_var
                );
                error!("{}", msg);
                return Err(msg);
            }
            Some(value_var)
        } else {
            None
        };

        let (rest, iterable) = Self::parse_arg(iterable_part).map_err(|e| {
            let msg = format!("Parse iterable in 'for' header error: '{}', {:?}", line, e);
            error!("{}", msg);
            msg
        })?;
        if !rest.trim().is_empty() {
            let msg = format!(
                "Unexpected content in 'for' header iterable: line='{}', rest='{}'",
                line, rest
            );
            error!("{}", msg);
            return Err(msg);
        }

        Ok((key_var, value_var, iterable))
    }

    fn parse_if_condition(line: &str, keyword: &str) -> Result<ExpressionChain, String> {
        let line = line.trim();
        let condition_part = line
            .strip_prefix(keyword)
            .ok_or_else(|| format!("Invalid '{}' header: '{}'", keyword, line))?
            .trim_start();

        let condition_part = condition_part.strip_suffix("then").ok_or_else(|| {
            let msg = format!("'{}' header must end with 'then': '{}'", keyword, line);
            error!("{}", msg);
            msg
        })?;

        let condition_part = condition_part.trim_end();
        if condition_part.is_empty() {
            let msg = format!("'{}' condition must not be empty: '{}'", keyword, line);
            error!("{}", msg);
            return Err(msg);
        }

        let (rest, condition) = Self::parse_expressions(condition_part).map_err(|e| {
            let msg = format!("Parse '{}' condition error: '{}', {:?}", keyword, line, e);
            error!("{}", msg);
            msg
        })?;

        if !rest.trim().is_empty() {
            let msg = format!(
                "Unexpected content in '{}' condition: line='{}', rest='{}'",
                keyword, line, rest
            );
            error!("{}", msg);
            return Err(msg);
        }

        if condition.is_empty() {
            let msg = format!("'{}' condition must not be empty: '{}'", keyword, line);
            error!("{}", msg);
            return Err(msg);
        }

        Ok(condition)
    }

    fn parse_if_statement(lines: &[&str], index: usize) -> Result<(Line, usize), String> {
        let if_source = lines[index].trim().to_string();
        let mut branches = Vec::new();
        let mut else_lines = None;

        let mut current_condition = Self::parse_if_condition(if_source.as_str(), "if")?;
        let mut cursor = index + 1;

        loop {
            let (branch_lines, next_cursor) = Self::parse_lines(lines, cursor, true)?;
            branches.push(IfBranch {
                condition: current_condition,
                lines: branch_lines,
            });

            if next_cursor >= lines.len() {
                let msg = format!(
                    "Missing 'end' for if statement starting at line {}: '{}'",
                    index + 1,
                    if_source
                );
                error!("{}", msg);
                return Err(msg);
            }

            let control_line = lines[next_cursor].trim();
            match Self::line_control_keyword(control_line) {
                Some("elif") => {
                    current_condition = Self::parse_if_condition(control_line, "elif")?;
                    cursor = next_cursor + 1;
                }
                Some("else") => {
                    let (parsed_else_lines, end_cursor) =
                        Self::parse_lines(lines, next_cursor + 1, true)?;

                    if end_cursor >= lines.len() || lines[end_cursor].trim() != "end" {
                        let msg = format!(
                            "Missing 'end' after else branch for if starting at line {}",
                            index + 1
                        );
                        error!("{}", msg);
                        return Err(msg);
                    }

                    else_lines = Some(parsed_else_lines);
                    cursor = end_cursor + 1;
                    break;
                }
                Some("end") => {
                    cursor = next_cursor + 1;
                    break;
                }
                Some(other) => {
                    let msg = format!(
                        "Unexpected control keyword '{}' in if statement at line {}",
                        other,
                        next_cursor + 1
                    );
                    error!("{}", msg);
                    return Err(msg);
                }
                None => unreachable!(
                    "parse_lines(stop_at_control_keywords=true) must stop at a control keyword"
                ),
            }
        }

        let statement = Statement::new_if(IfStatement {
            branches,
            else_lines,
        });
        let line = Line {
            source: if_source,
            statements: vec![statement],
        };

        Ok((line, cursor))
    }

    fn parse_for_statement(lines: &[&str], index: usize) -> Result<(Line, usize), String> {
        let for_source = lines[index].trim().to_string();
        let (key_var, value_var, iterable) = Self::parse_for_header(for_source.as_str())?;

        let (for_lines, end_cursor) = Self::parse_lines(lines, index + 1, true)?;
        if end_cursor >= lines.len() || lines[end_cursor].trim() != "end" {
            let msg = format!(
                "Missing 'end' for for statement starting at line {}: '{}'",
                index + 1,
                for_source
            );
            error!("{}", msg);
            return Err(msg);
        }

        let statement = Statement::new_for(ForStatement {
            key_var,
            value_var,
            iterable,
            lines: for_lines,
        });
        let line = Line {
            source: for_source,
            statements: vec![statement],
        };

        Ok((line, end_cursor + 1))
    }

    // Parse a single line, support label and expressions
    fn parse_line(line: &str) -> Result<Line, String> {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return Ok(Line {
                source: trimmed.to_string(),
                statements: Vec::new(),
            });
        }

        let (rest, statements) = Self::parse_statements(trimmed).map_err(|e| {
            let msg = format!("Parse statements error: {}, {:?}", trimmed, e);
            error!("{}", msg);
            msg
        })?;

        if !rest.trim().is_empty() {
            let msg = format!(
                "Unexpected content after statements: {}, rest='{}'",
                trimmed, rest
            );
            error!("{}", msg);
            return Err(msg);
        }

        debug!("Parsed line: line={}, statements={:?}", trimmed, statements);

        Ok(Line {
            statements,
            source: trimmed.to_string(),
        })
    }

    fn parse_statements(input: &str) -> IResult<&str, Vec<Statement>> {
        separated_list0(
            preceded(space0, char(';')),
            preceded(space0, Self::parse_expressions),
        )
        .parse(input)
        .map(|(rest, expr_groups)| {
            debug!("Parsed statements: {}, {:?}", rest, expr_groups);
            // Covert each group of expressions into a Statement
            let stmts = expr_groups
                .into_iter()
                .filter(|expressions| !expressions.is_empty())
                .map(Statement::new_expressions)
                .collect();
            (rest, stmts)
        })
    }

    // Parse expressions with operators
    fn parse_expressions(
        input: &str,
    ) -> IResult<&str, Vec<(Option<Operator>, Expression, Option<Operator>)>> {
        debug!("Parsing expressions: {}", input);
        let input = input.trim();
        if input.is_empty() {
            debug!("No expressions to parse");
            return Ok((input, Vec::new()));
        }

        let (i, exprs) = many0(|i| {
            // Parse zero or more not operators
            let (i, not_count) = many0(preceded(space0, tag("!"))).parse(i)?;
            let not_count = not_count.len();
            debug!("Parsed not operators: {}, count={}", i, not_count);
            let prefix_op = if not_count % 2 == 1 {
                Some(Operator::Not)
            } else {
                None
            };

            let (i, expr) = Self::parse_expression(i)?;
            debug!("Parsed expressions: {}, {:?}", i, expr);
            let (i, post_op) = opt(preceded(
                space0,
                alt((
                    map(tag("&&"), |_| Operator::And),
                    map(tag("||"), |_| Operator::Or),
                )),
            ))
            .parse(i)?;

            debug!("Parsed operator: {}, {:?}", i, post_op);
            Ok((i, (prefix_op, expr, post_op)))
        })
        .parse(input)?;

        // Check expressions, only the last expression can have no operator
        if exprs.len() > 1 {
            for expr in &exprs[..exprs.len() - 1] {
                if expr.2.is_none() {
                    let msg = format!("Expression without operator: {}, expr={:?}", input, expr);
                    error!("{}", msg);
                    return Err(nom::Err::Failure(nom::error::Error::from_error_kind(
                        i,
                        ErrorKind::Tag,
                    )));
                }
            }
        }
        debug!("Parsed expressions with operators: {}, {:?}", i, exprs);

        Ok((i, exprs))
    }

    // Parse expression with brackets or command
    fn parse_expression(input: &str) -> IResult<&str, Expression> {
        debug!("Parsing expression: {}", input);
        alt((
            Self::parse_assign,
            Self::parse_group,
            Self::parse_comparison_sugar,
            Self::parse_command,
        ))
        .parse(input)
    }

    // Parse group of expressions with brackets
    fn parse_group(input: &str) -> IResult<&str, Expression> {
        debug!("Parsing group: {}", input);
        let mut parser = preceded(
            space0,
            delimited(tag("("), Self::parse_expressions, tag(")")),
        );

        let (input, expressions) = parser.parse(input)?;

        Ok((input, Expression::Group(expressions)))
    }

    /*
    // Parse assign expression with =
    fn parse_assign(input: &str) -> IResult<&str, Expression> {
        let (input, key) = nom::bytes::complete::take_till(|c: char| c == '=' || c == ':')(input)?;
        let (input, op) = alt((tag(":="), tag("="))).parse(input)?;
        let (input, value) =
            nom::bytes::complete::take_till(|c: char| c.is_whitespace() || c == '&' || c == '|')(
                input,
            )?;

        let name = "assign".to_string();
        let args = vec![
            Self::parse_arg(key.trim())?.1,
            Self::parse_arg(op.trim())?.1,
            Self::parse_arg(value.trim())?.1,
        ];
        let args = CommandArgs::new(args);

        let cmd = CommandItem::new(name, args);
        Ok((input, Expression::Command(cmd)))
    }
    */

    /// Parse assign expression with = or without value
    /// This supports both `export KEY=VALUE` and `export KEY`
    fn parse_assign(input: &str) -> IResult<&str, Expression> {
        debug!("Parsing assign: {}", input);
        let (input, kind) = opt(terminated(
            alt((
                value(AssignKind::Global, tag("export")),
                value(AssignKind::Global, tag("global")),
                value(AssignKind::Chain, tag("chain")),
                value(AssignKind::Block, tag("local")),
                value(AssignKind::Block, tag("block")),
            )),
            space1,
        ))
        .parse(input)?;

        debug!("Parsed assign kind: {}, {:?}", input, kind);

        let (input, key) = recognize(pair(
            alt((alpha1, tag("_"))),
            many0(alt((alphanumeric1, tag("_")))),
        ))
        .parse(input)?;

        debug!("Parsed assign key: {}, {:?}", input, key);

        let (input, _) = space0(input)?;
        let (input, value) = opt(preceded(char('='), Self::parse_arg)).parse(input)?;

        debug!("Parsed assign value: {}, {:?}", input, value);

        if kind.is_none() && value.is_none() {
            // If no kind and no value, it's not an assign expression
            return Err(nom::Err::Error(nom::error::Error::from_error_kind(
                input,
                ErrorKind::Tag,
            )));
        }

        let kind = kind.unwrap_or_default();
        let mut args = vec![
            CommandArg::Literal(kind.as_str().to_string()),
            CommandArg::Literal(key.to_string()),
        ];

        if value.is_some() {
            args.push(value.unwrap());
        } else {
            // For assignments without value, such as: export KEY
        }

        let args = CommandArgs::new(args);
        let cmd = CommandItem::new("assign".to_string(), args);
        Ok((input, Expression::Command(cmd)))
    }

    // Parse infix comparison sugar:
    //   value1 == value2   -> eq --loose value1 value2
    //   value1 === value2  -> eq value1 value2
    //   value1 != value2   -> ne --loose value1 value2
    //   value1 !== value2  -> ne value1 value2
    //   value1 > value2    -> gt value1 value2
    //   value1 >= value2   -> ge value1 value2
    //   value1 < value2    -> lt value1 value2
    //   value1 <= value2   -> le value1 value2
    fn parse_comparison_sugar(input: &str) -> IResult<&str, Expression> {
        debug!("Parsing comparison sugar: {}", input);
        let (input, left) = Self::parse_arg(input)?;
        let (input, op) = preceded(
            space0,
            alt((
                tag("!=="),
                tag("!="),
                tag("==="),
                tag("=="),
                tag(">="),
                tag("<="),
                tag(">"),
                tag("<"),
            )),
        )
        .parse(input)?;
        let (input, right) = Self::parse_arg(input)?;

        let command_name = match op {
            "==" | "===" => "eq",
            "!=" | "!==" => "ne",
            ">" => "gt",
            ">=" => "ge",
            "<" => "lt",
            "<=" => "le",
            _ => unreachable!("unsupported comparison operator: {}", op),
        };
        let mut args = vec![CommandArg::Literal(command_name.to_string())];
        if op == "==" || op == "!=" {
            args.push(CommandArg::Literal("--loose".to_string()));
        }
        args.push(left);
        args.push(right);

        let cmd = CommandItem::new(command_name.to_string(), CommandArgs::new(args));
        Ok((input, Expression::Command(cmd)))
    }

    // Parse command
    fn parse_command(input: &str) -> IResult<&str, Expression> {
        debug!("Parsing command: {}", input);

        // First parse command name
        let (input, _) = space0(input)?;
        let (input, cmd_name) = Self::parse_command_literal(input)?;

        debug!("Parsed command name: {}, {:?}", input, cmd_name);

        let (input, args) =
            separated_list0(space1, preceded(space0, Self::parse_arg)).parse(input)?;
        debug!("Parsed command args: {}, {:?}", input, args);

        let cmd = if let Some(name) = cmd_name.as_literal_str() {
            if name.starts_with('-') {
                let msg = format!(
                    "Command name cannot start with '-', got: {}, {}",
                    name, input
                );
                error!("{}", msg);
                return Err(nom::Err::Error(nom::error::Error::from_error_kind(
                    input,
                    ErrorKind::Tag,
                )));
            }

            // For normal commands, we use the full command line with both name and args
            let name = name.to_owned();
            let mut full_args = vec![cmd_name];
            full_args.extend(args);

            Expression::Command(CommandItem::new(name, CommandArgs::new(full_args)))
        } else {
            let msg = format!("Command name must be a literal string, got: {:?}", args[0]);
            error!("{}", msg);
            return Err(nom::Err::Error(nom::error::Error::from_error_kind(
                input,
                ErrorKind::Tag,
            )));
        };

        Ok((input, cmd))
    }

    fn is_command_char(c: char) -> bool {
        c.is_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '/'
    }

    /// Parse command literal, which can be a command name or a path
    /// This is used for command names like `ls`, `my-command`, `python3`, `./script`
    fn parse_command_literal(input: &str) -> IResult<&str, CommandArg> {
        map(complete(take_while1(Self::is_command_char)), |s: &str| {
            CommandArg::Literal(s.to_string())
        })
        .parse(input)
    }

    fn parse_literal(input: &str) -> IResult<&str, CommandArg> {
        debug!("Parsing literal: {}", input);

        // double quoted string with escapes, also accept "" as empty string
        let double_quoted = delimited(
            char('"'),
            map(
                many0(alt((
                    // Variable with ${var}
                    map(Self::parse_var_braced, |var| var),
                    // Literal with escapes
                    map(
                        escaped_transform(
                            take_while1(|c: char| c != '\\' && c != '$' && c != '"'),
                            '\\',
                            alt((
                                value("\\", tag("\\")),
                                value("\"", tag("\"")),
                                value("\n", tag("n")),
                                value("\t", tag("t")),
                                value("\r", tag("r")),
                                value(" ", tag(" ")),
                                value("$", tag("$")),
                            )),
                        ),
                        |s: String| CommandArg::StringLiteral(s),
                    ),
                ))),
                |args: Vec<CommandArg>| {
                    debug!("Parsed double quoted args: {:?}", args);

                    // Filter out empty strings
                    let args = args
                        .into_iter()
                        .filter(|arg| match arg {
                            CommandArg::Literal(s)
                            | CommandArg::StringLiteral(s)
                            | CommandArg::TypedLiteral(s, _) => !s.is_empty(),
                            _ => true,
                        })
                        .collect::<Vec<_>>();

                    // If no args, return empty string
                    if args.is_empty() {
                        CommandArg::StringLiteral("".to_string())
                    }
                    // If there's only one argument, return it directly
                    else if args.len() == 1 {
                        args.into_iter().next().unwrap()
                    } else {
                        // Wrap multiple args into a command substitution
                        let args = vec![CommandArg::Literal("append".to_string())]
                            .into_iter()
                            .chain(args.into_iter())
                            .collect::<Vec<_>>();
                        CommandArg::CommandSubstitution(Box::new(Expression::Command(
                            CommandItem::new("append".to_string(), CommandArgs::new(args)),
                        )))
                    }
                },
            ),
            char('"'),
        );

        // single quoted string, also accept '' as empty string
        let single_quoted = delimited(
            char('\''),
            map(opt(is_not("'")), |s: Option<&str>| {
                CommandArg::StringLiteral(s.unwrap_or("").to_string())
            }),
            char('\''),
        );

        // Unquoted string, must start with a letter or underscore, followed by letters, digits, underscores, hyphens, or dots
        let unquoted = map(
            recognize(pair(
                alt((nom::character::complete::alphanumeric1, tag("_"))),
                many0(alt((
                    nom::character::complete::alphanumeric1,
                    tag("_"),
                    tag("-"),
                    tag("."),
                    tag(":"),
                    tag("/"),
                ))),
            )),
            |s: &str| {
                if let Some(value) = Self::parse_typed_literal(s) {
                    CommandArg::TypedLiteral(s.to_string(), value)
                } else {
                    CommandArg::Literal(s.to_string())
                }
            },
        );

        let (input, arg) = complete(alt((double_quoted, single_quoted, unquoted))).parse(input)?;

        debug!("Parsed literal: {}, {:?}", input, arg);
        Ok((input, arg))
    }

    fn parse_var_dollar(input: &str) -> IResult<&str, CommandArg> {
        debug!("Parsing var dollar: {}", input);
        let (rest, _) = char('$').parse(input)?;
        if rest.is_empty() {
            let msg = format!(
                "Variable name must not be empty after '$', input: {}",
                input
            );
            error!("{}", msg);
            return Err(nom::Err::Error(nom::error::Error::from_error_kind(
                input,
                ErrorKind::Tag,
            )));
        }

        let mut i = 0usize;
        let mut paren_depth = 0usize;
        let mut bracket_depth = 0usize;
        let mut quote_in_bracket: Option<char> = None;
        let mut escaped_in_quote = false;
        let mut parsed = String::new();

        while i < rest.len() {
            let ch = rest[i..].chars().next().ok_or_else(|| {
                nom::Err::Error(nom::error::Error::from_error_kind(rest, ErrorKind::Tag))
            })?;

            if let Some(quote) = quote_in_bracket {
                parsed.push(ch);
                i += ch.len_utf8();

                if escaped_in_quote {
                    escaped_in_quote = false;
                    continue;
                }

                if ch == '\\' {
                    escaped_in_quote = true;
                    continue;
                }

                if ch == quote {
                    quote_in_bracket = None;
                }

                continue;
            }

            // End of current arg token, only when not inside dynamic/bracket segment
            if paren_depth == 0
                && bracket_depth == 0
                && (ch.is_whitespace() || ch == ';' || ch == ')')
            {
                break;
            }

            if bracket_depth > 0 {
                if ch == '"' || ch == '\'' {
                    quote_in_bracket = Some(ch);
                } else if ch == '[' {
                    bracket_depth += 1;
                } else if ch == ']' {
                    bracket_depth -= 1;
                }

                parsed.push(ch);
                i += ch.len_utf8();
                continue;
            }

            if ch == '[' {
                bracket_depth += 1;
            } else if ch == '(' {
                paren_depth += 1;
            } else if ch == ')' {
                if paren_depth == 0 {
                    break;
                }
                paren_depth -= 1;
            }

            parsed.push(ch);
            i += ch.len_utf8();
        }

        if parsed.is_empty() {
            let msg = format!(
                "Variable name must not be empty after '$', input: {}",
                input
            );
            error!("{}", msg);
            return Err(nom::Err::Error(nom::error::Error::from_error_kind(
                rest,
                ErrorKind::Tag,
            )));
        }

        // Validate non-dynamic plain variable syntax for compatibility
        if !parsed.contains(".(") && !parsed.contains('[') {
            let mut chars = parsed.chars();
            let first = chars.next().unwrap();
            if !(first.is_alphabetic() || first == '_') {
                return Err(nom::Err::Error(nom::error::Error::from_error_kind(
                    rest,
                    ErrorKind::Tag,
                )));
            }

            for c in chars {
                if !(c.is_alphanumeric() || c == '_' || c == '.' || c == '-' || c == '?') {
                    return Err(nom::Err::Error(nom::error::Error::from_error_kind(
                        rest,
                        ErrorKind::Tag,
                    )));
                }
            }
        }

        if paren_depth != 0 || bracket_depth != 0 || quote_in_bracket.is_some() {
            return Err(nom::Err::Error(nom::error::Error::from_error_kind(
                rest,
                ErrorKind::Tag,
            )));
        }

        debug!("Parsed var dollar: {}, {}", &rest[i..], parsed);
        Ok((&rest[i..], CommandArg::Var(parsed)))
    }

    fn parse_var_braced(input: &str) -> IResult<&str, CommandArg> {
        debug!("Parsing var braced: {}", input);
        let (rest, _) = tag("${").parse(input)?;
        let mut i = 0usize;
        let mut paren_depth = 0usize;
        let mut bracket_depth = 0usize;
        let mut quote_in_bracket: Option<char> = None;
        let mut escaped_in_quote = false;
        let mut parsed = String::new();

        while i < rest.len() {
            let ch = rest[i..].chars().next().ok_or_else(|| {
                nom::Err::Error(nom::error::Error::from_error_kind(rest, ErrorKind::Tag))
            })?;

            if let Some(quote) = quote_in_bracket {
                parsed.push(ch);
                i += ch.len_utf8();

                if escaped_in_quote {
                    escaped_in_quote = false;
                    continue;
                }

                if ch == '\\' {
                    escaped_in_quote = true;
                    continue;
                }

                if ch == quote {
                    quote_in_bracket = None;
                }
                continue;
            }

            if ch == '}' && paren_depth == 0 && bracket_depth == 0 {
                break;
            }

            if bracket_depth > 0 {
                if ch == '"' || ch == '\'' {
                    quote_in_bracket = Some(ch);
                } else if ch == '[' {
                    bracket_depth += 1;
                } else if ch == ']' {
                    bracket_depth -= 1;
                }

                parsed.push(ch);
                i += ch.len_utf8();
                continue;
            }

            if ch == '[' {
                bracket_depth += 1;
            } else if ch == '(' {
                paren_depth += 1;
            } else if ch == ')' {
                if paren_depth == 0 {
                    let msg = format!("Unexpected ')' in braced variable: {}", input);
                    debug!("{}", msg);
                    return Err(nom::Err::Error(nom::error::Error::from_error_kind(
                        rest,
                        ErrorKind::Tag,
                    )));
                }
                paren_depth -= 1;
            }

            parsed.push(ch);
            i += ch.len_utf8();
        }

        if parsed.is_empty()
            || i >= rest.len()
            || !rest[i..].starts_with('}')
            || paren_depth != 0
            || bracket_depth != 0
            || quote_in_bracket.is_some()
        {
            let msg = format!("Parse var braced error: {}", input);
            debug!("{}", msg);
            return Err(nom::Err::Error(nom::error::Error::from_error_kind(
                rest,
                ErrorKind::Tag,
            )));
        }

        let ret = (&rest[i + 1..], CommandArg::Var(parsed));

        debug!("Parsed var braced: {}, {:?}", ret.0, ret.1);
        Ok(ret)
    }

    fn parse_command_subst(input: &str) -> IResult<&str, CommandArg> {
        let (rest, _) = tag("$(")(input)?;
        let mut depth = 1;
        let mut chars = rest.char_indices();

        while let Some((idx, c)) = chars.next() {
            match c {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        let content = &rest[..idx];
                        let (cmd_rest, exp) = Self::parse_command(content.trim())?;
                        if !cmd_rest.trim().is_empty() {
                            let msg = format!(
                                "Unexpected content after command substitution: '{}'",
                                cmd_rest
                            );
                            error!("{}", msg);
                            return Err(nom::Err::Failure(nom::error::Error::from_error_kind(
                                cmd_rest,
                                ErrorKind::Tag,
                            )));
                        }

                        let remaining = &rest[idx + 1..];
                        return Ok((remaining, CommandArg::CommandSubstitution(Box::new(exp))));
                    }
                }
                _ => {}
            }
        }

        Err(nom::Err::Error(nom::error::Error::from_error_kind(
            rest,
            ErrorKind::Tag,
        )))
    }

    fn parse_option(input: &str) -> IResult<&str, CommandArg> {
        debug!("Parsing option: {}", input);
        let (input, option) = recognize(alt((
            // Long options start with '--' and can contain letters, digits, underscores, and hyphens
            pair(
                tag("--"),
                pair(
                    alt((alpha1, tag("_"))),
                    many0(alt((alphanumeric1, tag("_"), tag("-")))),
                ),
            ),
            // Short options start with '-' and can contain letters, digits, underscores, and hyphens
            pair(
                tag("-"),
                pair(
                    alt((alpha1, tag("_"))),
                    many0(alt((alphanumeric1, tag("_")))),
                ),
            ),
        )))
        .parse(input)?;

        if option == "-" || option == "--" {
            let msg = format!("Option must have a name after '-' or '--', got: {}", option);
            error!("{}", msg);
            return Err(nom::Err::Error(nom::error::Error::from_error_kind(
                input,
                ErrorKind::Tag,
            )));
        }

        debug!("Parsed option: {}, {}", input, option);
        Ok((input, CommandArg::Literal(option.to_string())))
    }

    // Parse unquoted arg with dynamic nested segments, such as: a.($b).($c)
    // This is translated to an append command substitution at parse-time.
    fn parse_interpolated_unquoted(input: &str) -> IResult<&str, CommandArg> {
        let mut i = 0usize;
        let mut literal = String::new();
        let mut parts: Vec<CommandArg> = Vec::new();
        let mut used_dynamic = false;

        while i < input.len() {
            let ch = input[i..].chars().next().ok_or_else(|| {
                nom::Err::Error(nom::error::Error::from_error_kind(input, ErrorKind::Tag))
            })?;

            if ch.is_whitespace() || ch == ';' {
                break;
            }

            if ch == '(' && literal.ends_with('.') {
                let mut depth = 0usize;
                let mut end_index = None;
                for (offset, c) in input[i..].char_indices() {
                    if c == '(' {
                        depth += 1;
                    } else if c == ')' {
                        depth -= 1;
                        if depth == 0 {
                            end_index = Some(i + offset);
                            break;
                        }
                    }
                }

                let end_index = end_index.ok_or_else(|| {
                    nom::Err::Error(nom::error::Error::from_error_kind(input, ErrorKind::Tag))
                })?;

                let inner = input[i + 1..end_index].trim();
                let (inner_rest, inner_arg) = Self::parse_arg(inner)?;
                if !inner_rest.trim().is_empty() {
                    return Err(nom::Err::Error(nom::error::Error::from_error_kind(
                        input,
                        ErrorKind::Tag,
                    )));
                }

                if !literal.is_empty() {
                    parts.push(CommandArg::StringLiteral(literal.clone()));
                    literal.clear();
                }
                parts.push(inner_arg);
                used_dynamic = true;
                i = end_index + 1;
                continue;
            }

            literal.push(ch);
            i += ch.len_utf8();
        }

        if !used_dynamic {
            return Err(nom::Err::Error(nom::error::Error::from_error_kind(
                input,
                ErrorKind::Tag,
            )));
        }

        if !literal.is_empty() {
            parts.push(CommandArg::StringLiteral(literal));
        }

        let arg = if parts.len() == 1 {
            parts.into_iter().next().unwrap()
        } else {
            let args = vec![CommandArg::Literal("append".to_string())]
                .into_iter()
                .chain(parts.into_iter())
                .collect::<Vec<_>>();
            CommandArg::CommandSubstitution(Box::new(Expression::Command(CommandItem::new(
                "append".to_string(),
                CommandArgs::new(args),
            ))))
        };

        Ok((&input[i..], arg))
    }

    pub(crate) fn parse_arg(input: &str) -> IResult<&str, CommandArg> {
        debug!("Parsing arg: {}", input);
        let ret = preceded(
            space0,
            alt((
                Self::parse_command_subst,         // $(...)
                Self::parse_var_braced,            // ${VAR}
                Self::parse_var_dollar,            // $VAR
                Self::parse_interpolated_unquoted, // a.($b).($c)
                Self::parse_literal,               // "..." or '...' or unquoted
                Self::parse_option,                // -o or --option
            )),
        )
        .parse(input)?;

        debug!("Parsed arg: {}, {:?}", ret.0, ret.1);
        Ok(ret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collection::{CollectionValue, NumberValue};

    #[test]
    fn test_parse_literal() {
        let (input, arg) = BlockParser::parse_literal("abc").unwrap();
        assert_eq!(input, "");
        assert_eq!(arg.as_literal_str().unwrap(), "abc");
        assert!(matches!(arg, CommandArg::Literal(_)));

        let (input, arg) = BlockParser::parse_literal("true").unwrap();
        assert_eq!(input, "");
        assert!(matches!(
            arg,
            CommandArg::TypedLiteral(_, CollectionValue::Bool(true))
        ));

        let (input, arg) = BlockParser::parse_literal("123").unwrap();
        assert_eq!(input, "");
        assert!(matches!(
            arg,
            CommandArg::TypedLiteral(_, CollectionValue::Number(NumberValue::Int(123)))
        ));

        let (input, arg) = BlockParser::parse_literal("12.5").unwrap();
        assert_eq!(input, "");
        assert!(matches!(
            arg,
            CommandArg::TypedLiteral(_, CollectionValue::Number(NumberValue::Float(v)))
            if (v - 12.5).abs() < f64::EPSILON
        ));

        let (input, arg) = BlockParser::parse_literal("null").unwrap();
        assert_eq!(input, "");
        assert!(matches!(
            arg,
            CommandArg::TypedLiteral(_, CollectionValue::Null)
        ));

        let (input, arg) = BlockParser::parse_literal("\"abc def\"").unwrap();
        assert_eq!(input, "");
        assert_eq!(arg.as_literal_str().unwrap(), "abc def");
        assert!(matches!(arg, CommandArg::StringLiteral(_)));

        let (input, arg) = BlockParser::parse_literal("\"line\\nbreak\"").unwrap();
        assert_eq!(input, "");
        assert_eq!(arg.as_literal_str().unwrap(), "line\nbreak");

        let (input, arg) = BlockParser::parse_literal("'abc def'").unwrap();
        assert_eq!(input, "");
        assert_eq!(arg.as_literal_str().unwrap(), "abc def");
        assert!(matches!(arg, CommandArg::StringLiteral(_)));

        let (input, arg) = BlockParser::parse_literal("test123_").unwrap();
        assert_eq!(input, "");
        assert_eq!(arg.as_literal_str().unwrap(), "test123_");

        // Test parse url tcp://127.0.0.1:8083
        let (input, arg) = BlockParser::parse_literal("tcp://127.0.0.1:8083").unwrap();
        assert_eq!(input, "");
        assert_eq!(arg.as_literal_str().unwrap(), "tcp://127.0.0.1:8083");
    }

    #[test]
    fn test_parse_interpolated_unquoted() {
        let (rest, arg) = BlockParser::parse_arg("test1.($test1.key3)").unwrap();
        assert_eq!(rest, "");
        assert!(arg.is_command_substitution());
    }

    #[test]
    fn test_parse_dynamic_var_dollar() {
        let (rest, arg) = BlockParser::parse_arg("$test1.($test1.key3)").unwrap();
        assert_eq!(rest, "");
        assert!(arg.is_var());
        assert_eq!(arg.as_var_str(), Some("test1.($test1.key3)"));
    }

    #[test]
    fn test_parse_dynamic_var_braced() {
        let (rest, arg) = BlockParser::parse_arg("${test1.($test1.key3)}").unwrap();
        assert_eq!(rest, "");
        assert!(arg.is_var());
        assert_eq!(arg.as_var_str(), Some("test1.($test1.key3)"));
    }

    #[test]
    fn test_parse_bracket_var_dollar() {
        let (rest, arg) = BlockParser::parse_arg("$geoByIp[$REQ.clientIp].country").unwrap();
        assert_eq!(rest, "");
        assert!(arg.is_var());
        assert_eq!(arg.as_var_str(), Some("geoByIp[$REQ.clientIp].country"));
    }

    #[test]
    fn test_parse_bracket_var_braced_with_quotes() {
        let (rest, arg) = BlockParser::parse_arg("${geoByIp[\"1.2.3.4\"].country}").unwrap();
        assert_eq!(rest, "");
        assert!(arg.is_var());
        assert_eq!(arg.as_var_str(), Some("geoByIp[\"1.2.3.4\"].country"));
    }

    #[test]
    fn test_parse_braced_var_with_safe_access_and_default() {
        let (rest, arg) =
            BlockParser::parse_arg("${geoByIp[$REQ.clientIp]?.country ?? \"unknown\"}").unwrap();
        assert_eq!(rest, "");
        assert!(arg.is_var());
        assert_eq!(
            arg.as_var_str(),
            Some("geoByIp[$REQ.clientIp]?.country ?? \"unknown\"")
        );
    }

    #[test]
    fn test_parse_dollar_var_with_safe_access() {
        let (rest, arg) = BlockParser::parse_arg("$REQ.geo?.country").unwrap();
        assert_eq!(rest, "");
        assert!(arg.is_var());
        assert_eq!(arg.as_var_str(), Some("REQ.geo?.country"));
    }

    #[test]
    fn test_parse_dollar_var_with_safe_access_and_inline_default() {
        let (rest, arg) =
            BlockParser::parse_arg("$geoByIp[$REQ.clientIp]?.country??\"unknown\"").unwrap();
        assert_eq!(rest, "");
        assert!(arg.is_var());
        assert_eq!(
            arg.as_var_str(),
            Some("geoByIp[$REQ.clientIp]?.country??\"unknown\"")
        );
    }

    #[test]
    fn test_parse() {
        let parser = BlockParser::new("test_block");

        let block_str = r#"
            (map_create test_map) (map_create test_map2);
        "#;
        let ret = parser.parse(block_str);
        assert!(ret.is_err());

        let block_str = r#"
            ! map_create test_map && !!map_create test_map2;
        "#;
        let ret = parser.parse(block_str);
        assert!(ret.is_ok());
        let block = ret.unwrap();
        let line = block.lines.first().unwrap();
        assert_eq!(line.statements.len(), 1);
        let statement = &line.statements[0];
        assert_eq!(statement.expressions.len(), 2);
        assert_eq!(statement.expressions[0].0, Some(Operator::Not));
        assert_eq!(
            statement.expressions[0]
                .1
                .as_command()
                .unwrap()
                .command
                .name,
            "map_create"
        );
        assert_eq!(statement.expressions[0].2, Some(Operator::And));
        assert_eq!(statement.expressions[1].0, None);
        assert_eq!(
            statement.expressions[1]
                .1
                .as_command()
                .unwrap()
                .command
                .name,
            "map_create"
        );
        assert_eq!(statement.expressions[1].2, None);

        let block_str = r#"
            (map_create test_map) && (map_create test_map2 || map_create test_map3);
            local key1="test.key1";
            map_create test_map && map_add test_map key1 value1 && map_add test_map key2 $(append ${key1} _value2);
        "#;

        let block = parser.parse(block_str).unwrap();
        assert_eq!(block.id, "test_block");
        assert_eq!(block.lines.len(), 3);

        // Test string literal with escapes and substitution
        let block_str = r#"
            local VAR = "test_string1";
            echo "a dollar sign: \$ and a variable: ${VAR}";
            echo "This is a test string with a newline\nand a tab\tand a quote\" and a dollar sign \$ and a variable ${VAR}";
            echo 'This is another test string with single quotes';
            echo "This is a test with an escaped quote: \" and a variable: ${VAR}";
        "#;
        let block = parser.parse(block_str).unwrap();
        assert_eq!(block.id, "test_block");
        assert_eq!(block.lines.len(), 5);
    }

    #[test]
    fn test_parse_for_statement_single_var() {
        let parser = BlockParser::new("test_block");
        let block_str = r#"
            for item in $items then
                echo $item;
            end
        "#;

        let block = parser.parse(block_str).unwrap();
        assert_eq!(block.lines.len(), 1);
        let statement = &block.lines[0].statements[0];
        assert!(statement.for_statement.is_some());
        let for_statement = statement.for_statement.as_ref().unwrap();
        assert_eq!(for_statement.key_var, "item");
        assert!(for_statement.value_var.is_none());
        assert_eq!(for_statement.lines.len(), 1);
    }

    #[test]
    fn test_parse_for_statement_key_value() {
        let parser = BlockParser::new("test_block");
        let block_str = r#"
            for key, value in $routes then
                echo $key $value;
            end
        "#;

        let block = parser.parse(block_str).unwrap();
        assert_eq!(block.lines.len(), 1);
        let statement = &block.lines[0].statements[0];
        let for_statement = statement.for_statement.as_ref().unwrap();
        assert_eq!(for_statement.key_var, "key");
        assert_eq!(for_statement.value_var.as_deref(), Some("value"));
        assert_eq!(for_statement.lines.len(), 1);
    }

    #[test]
    fn test_parse_for_statement_missing_end() {
        let parser = BlockParser::new("test_block");
        let block_str = r#"
            for item in $items then
                echo $item;
        "#;

        let err = parser.parse(block_str).unwrap_err();
        assert!(
            err.contains("Missing 'end' for for statement"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn test_parse_comparison_sugar_loose() {
        let (rest, expr) = BlockParser::parse_expression("$a == \"1\"").unwrap();
        assert_eq!(rest, "");

        let cmd = expr.as_command().unwrap();
        assert_eq!(cmd.command.name, "eq");
        assert_eq!(cmd.command.args.len(), 4);
        assert_eq!(cmd.command.args[0].as_literal_str(), Some("eq"));
        assert_eq!(cmd.command.args[1].as_literal_str(), Some("--loose"));
        assert!(matches!(cmd.command.args[2], CommandArg::Var(_)));
        assert!(matches!(cmd.command.args[3], CommandArg::StringLiteral(_)));
    }

    #[test]
    fn test_parse_comparison_sugar_strict() {
        let (rest, expr) = BlockParser::parse_expression("$a === \"1\"").unwrap();
        assert_eq!(rest, "");

        let cmd = expr.as_command().unwrap();
        assert_eq!(cmd.command.name, "eq");
        assert_eq!(cmd.command.args.len(), 3);
        assert_eq!(cmd.command.args[0].as_literal_str(), Some("eq"));
        assert!(matches!(cmd.command.args[1], CommandArg::Var(_)));
        assert!(matches!(cmd.command.args[2], CommandArg::StringLiteral(_)));
    }

    #[test]
    fn test_parse_comparison_sugar_ne_loose() {
        let (rest, expr) = BlockParser::parse_expression("$a != \"1\"").unwrap();
        assert_eq!(rest, "");

        let cmd = expr.as_command().unwrap();
        assert_eq!(cmd.command.name, "ne");
        assert_eq!(cmd.command.args.len(), 4);
        assert_eq!(cmd.command.args[0].as_literal_str(), Some("ne"));
        assert_eq!(cmd.command.args[1].as_literal_str(), Some("--loose"));
        assert!(matches!(cmd.command.args[2], CommandArg::Var(_)));
        assert!(matches!(cmd.command.args[3], CommandArg::StringLiteral(_)));
    }

    #[test]
    fn test_parse_comparison_sugar_ne_strict() {
        let (rest, expr) = BlockParser::parse_expression("$a !== \"1\"").unwrap();
        assert_eq!(rest, "");

        let cmd = expr.as_command().unwrap();
        assert_eq!(cmd.command.name, "ne");
        assert_eq!(cmd.command.args.len(), 3);
        assert_eq!(cmd.command.args[0].as_literal_str(), Some("ne"));
        assert!(matches!(cmd.command.args[1], CommandArg::Var(_)));
        assert!(matches!(cmd.command.args[2], CommandArg::StringLiteral(_)));
    }

    #[test]
    fn test_parse_comparison_sugar_gt() {
        let (rest, expr) = BlockParser::parse_expression("$a > 1").unwrap();
        assert_eq!(rest, "");

        let cmd = expr.as_command().unwrap();
        assert_eq!(cmd.command.name, "gt");
        assert_eq!(cmd.command.args.len(), 3);
        assert_eq!(cmd.command.args[0].as_literal_str(), Some("gt"));
        assert!(matches!(cmd.command.args[1], CommandArg::Var(_)));
        assert!(matches!(
            cmd.command.args[2],
            CommandArg::TypedLiteral(_, _)
        ));
    }

    #[test]
    fn test_parse_comparison_sugar_ge() {
        let (rest, expr) = BlockParser::parse_expression("$a >= 1").unwrap();
        assert_eq!(rest, "");

        let cmd = expr.as_command().unwrap();
        assert_eq!(cmd.command.name, "ge");
        assert_eq!(cmd.command.args.len(), 3);
        assert_eq!(cmd.command.args[0].as_literal_str(), Some("ge"));
        assert!(matches!(cmd.command.args[1], CommandArg::Var(_)));
        assert!(matches!(
            cmd.command.args[2],
            CommandArg::TypedLiteral(_, _)
        ));
    }

    #[test]
    fn test_parse_comparison_sugar_lt() {
        let (rest, expr) = BlockParser::parse_expression("$a < 1").unwrap();
        assert_eq!(rest, "");

        let cmd = expr.as_command().unwrap();
        assert_eq!(cmd.command.name, "lt");
        assert_eq!(cmd.command.args.len(), 3);
        assert_eq!(cmd.command.args[0].as_literal_str(), Some("lt"));
        assert!(matches!(cmd.command.args[1], CommandArg::Var(_)));
        assert!(matches!(
            cmd.command.args[2],
            CommandArg::TypedLiteral(_, _)
        ));
    }

    #[test]
    fn test_parse_comparison_sugar_le() {
        let (rest, expr) = BlockParser::parse_expression("$a <= 1").unwrap();
        assert_eq!(rest, "");

        let cmd = expr.as_command().unwrap();
        assert_eq!(cmd.command.name, "le");
        assert_eq!(cmd.command.args.len(), 3);
        assert_eq!(cmd.command.args[0].as_literal_str(), Some("le"));
        assert!(matches!(cmd.command.args[1], CommandArg::Var(_)));
        assert!(matches!(
            cmd.command.args[2],
            CommandArg::TypedLiteral(_, _)
        ));
    }
}
