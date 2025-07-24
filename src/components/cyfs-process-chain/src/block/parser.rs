use super::block::*;
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

        for (i, line) in lines.iter().enumerate() {
            debug!("Parsing line {}: {}", i, line.trim());
            let parsed_line = Self::parse_line(line)?;
            info!("Parsed line {}: {:?}", i, parsed_line);
            block.lines.push(parsed_line);
        }

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
            let msg = format!("Parse expressions error: {}, {:?}", trimmed, e);
            error!("{}", msg);
            msg
        })?;

        if !rest.trim().is_empty() {
            let msg = format!("Unexpected content after statements: '{}'", rest);
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
                .map(|expressions| Statement { expressions })
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
                    let msg = format!("Expression without operator: {:?}", expr);
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
        alt((Self::parse_assign, Self::parse_group, Self::parse_command)).parse(input)
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
                let msg = format!("Command name cannot start with '-', got: {}", name);
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

        // double quoted string with escapes
        let double_quoted = delimited(
            char('"'),
            escaped_transform(
                is_not("\\\""),
                '\\',
                alt((
                    value("\\", tag("\\")),
                    value("\"", tag("\"")),
                    value("\n", tag("n")),
                    value("\t", tag("t")),
                    value(" ", tag(" ")),
                )),
            ),
            char('"'),
        );

        // single quoted string
        let single_quoted = delimited(
            char('\''),
            map(is_not("'"), |s: &str| s.to_string()),
            char('\''),
        );

        // Unquoted string, must start with a letter or underscore, followed by letters, digits, or underscores
        let unquoted = map(
            recognize(pair(
                alt((nom::character::complete::alpha1, tag("_"))),
                many0(alt((nom::character::complete::alphanumeric1, tag("_"), tag("-")))),
            )),
            |s: &str| s.to_string(),
        );

        let (input, arg) = complete(alt((double_quoted, single_quoted, unquoted))).parse(input)?;

        debug!("Parsed literal: {}, {:?}", input, arg);
        // Return as CommandArg::Literal
        Ok((input, CommandArg::Literal(arg)))
    }

    fn parse_var_dollar(input: &str) -> IResult<&str, CommandArg> {
        debug!("Parsing var dollar: {}", input);
        let (input, var) = preceded(
            char('$'),
            recognize(pair(
                alt((alpha1, tag("_"))),               // Variable must start with a letter or underscore
                many0(alt((alphanumeric1, tag("_")))), // followed by letters, digits, or underscores
            )),
        )
        .parse(input)?;

        if var.is_empty() {
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

        debug!("Parsed var dollar: {}, {}", input, var);
        Ok((input, CommandArg::Var(var.to_string())))
    }

    fn parse_var_braced(input: &str) -> IResult<&str, CommandArg> {
        // ${var}
        map(
            preceded(
                tag("${"),
                terminated(
                    take_while1(|c: char| c.is_alphanumeric() || c == '_'),
                    char('}'),
                ),
            ),
            |var: &str| CommandArg::Var(var.to_string()),
        )
        .parse(input)
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

    fn parse_arg(input: &str) -> IResult<&str, CommandArg> {
        debug!("Parsing arg: {}", input);
        let ret = preceded(
            space0,
            alt((
                Self::parse_command_subst, // $(...)
                Self::parse_var_braced,    // ${VAR}
                Self::parse_var_dollar,    // $VAR
                Self::parse_literal,       // "..." or '...' or unquoted
                Self::parse_option,        // -o or --option
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

    #[test]
    fn test_parse_literal() {
        let (input, arg) = BlockParser::parse_literal("abc").unwrap();
        assert_eq!(input, "");
        assert_eq!(arg.as_literal_str().unwrap(), "abc");

        let (input, arg) = BlockParser::parse_literal("\"abc def\"").unwrap();
        assert_eq!(input, "");
        assert_eq!(arg.as_literal_str().unwrap(), "abc def");

        let (input, arg) = BlockParser::parse_literal("\"line\\nbreak\"").unwrap();
        assert_eq!(input, "");
        assert_eq!(arg.as_literal_str().unwrap(), "line\nbreak");

        let (input, arg) = BlockParser::parse_literal("'abc def'").unwrap();
        assert_eq!(input, "");
        assert_eq!(arg.as_literal_str().unwrap(), "abc def");

        let (input, arg) = BlockParser::parse_literal("test123_").unwrap();
        assert_eq!(input, "");
        assert_eq!(arg.as_literal_str().unwrap(), "test123_");
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
    }
}
