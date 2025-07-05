use super::block::*;
use nom::{
    IResult, Parser,
    branch::alt,
    bytes::complete::tag,
    bytes::complete::{escaped_transform, is_not},
    bytes::streaming::take_while1,
    character::complete::{alpha1, alphanumeric1, char},
    character::complete::{space0, space1},
    character::multispace0,
    combinator::{map, opt, recognize, value},
    error::{ErrorKind, ParseError},
    multi::many0,
    multi::separated_list0,
    sequence::{delimited, pair, preceded, terminated},
};


pub struct BlockParser {
    block_type: BlockType,
}

impl BlockParser {
    pub fn new(block_type: BlockType) -> Self {
        Self { block_type }
    }
}

impl BlockParser {
    pub fn parse(&self, block: &str) -> Result<Block, String> {
        let lines: Vec<&str> = Self::split_lines(block);
        let mut block = Block::new(self.block_type);

        if lines.is_empty() {
            warn!("Empty block");
            return Ok(block);
        }

        for (i, line) in lines.iter().enumerate() {
            let parsed_line = Self::parse_line(line)?;
            if let Some(ref label) = parsed_line.label {
                block.label_map.insert(label.clone(), i);
            }
            block.lines.push(parsed_line);
        }

        Ok(block)
    }

    // Block contains multiple lines, first split them into lines
    // The lines are separated by '\n' or '\r\n' or '\r' for different OS
    fn split_lines(block: &str) -> Vec<&str> {
        block
            .split(|c| c == '\n' || c == '\r')
            .map(|line| line.trim_end_matches('\r')) // Remove '\r' at the end of line if any
            .filter(|line| !line.is_empty()) // Filter out empty lines
            .collect()
    }

    // Parse a single line, support label and expressions
    fn parse_line(line: &str) -> Result<Line, String> {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return Ok(Line {
                label: None,
                statements: Vec::new(),
            });
        }

        // First try to split the line into label and expressions, the label is start with "label: "
        let (label, expr_input) = if let Some((label_part, rest)) = trimmed.split_once(": ") {
            (Some(label_part.trim().to_string()), rest.trim())
        } else {
            (None, trimmed)
        };

        let (_, statements) = Self::parse_statements(expr_input).map_err(|e| {
            let msg = format!("Parse expressions error: {}, {:?}", expr_input, e);
            error!("{}", msg);
            msg
        })?;

        Ok(Line { label, statements })
    }

    fn parse_statements(input: &str) -> IResult<&str, Vec<Statement>> {
        separated_list0(
            preceded(space0, char(';')),
            preceded(space0, Self::parse_expressions),
        )
        .parse(input)
        .map(|(rest, expr_groups)| {
            // Covert each group of expressions into a Statement
            let stmts = expr_groups
                .into_iter()
                .map(|expressions| Statement { expressions })
                .collect();
            (rest, stmts)
        })
    }

    // Parse expressions with operators
    fn parse_expressions(input: &str) -> IResult<&str, Vec<(Expression, Operator)>> {
        many0(|i| {
            let (i, expr) = Self::parse_expression(i)?;
            let (i, op) = opt(alt((
                map(tag("&&"), |_| Operator::And),
                map(tag("||"), |_| Operator::Or),
            )))
            .parse(i)?;

            Ok((i, (expr, op.unwrap_or(Operator::None))))
        })
        .parse(input)
    }

    // Parse expression with brackets or command
    fn parse_expression(input: &str) -> IResult<&str, Expression> {
        alt((Self::parse_assign, Self::parse_group, Self::parse_command)).parse(input)
    }

    // Parse group of expressions with brackets
    fn parse_group(input: &str) -> IResult<&str, Expression> {
        let mut parser = delimited(tag("("), Self::parse_expressions, tag(")"));
        let (input, expressions) = parser.parse(input).map_err(|e| {
            let msg = format!("Parse group error: {}, {:?}", input, e);
            error!("{}", msg);
            e
        })?;

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

    fn parse_assign(input: &str) -> IResult<&str, Expression> {
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

        let kind = kind.unwrap_or_default();

        let (input, key) = recognize(pair(
            alt((alpha1, tag("_"))),
            many0(alt((alphanumeric1, tag("_")))),
        ))
        .parse(input)?;

        let (input, value) = opt(preceded(char('='), Self::parse_arg)).parse(input)?;

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
        let cmd = CommandItem::new(
            "assign".to_string(),
            args,
        );
        Ok((input, Expression::Command(cmd)))
    }

    // Parse command
    fn parse_command(input: &str) -> IResult<&str, Expression> {
        let (input, args) =
            separated_list0(space1, preceded(multispace0(), Self::parse_arg)).parse(input)?;

        let cmd = if args.is_empty() {
            let cmd = CommandItem::new_empty();
            Expression::Command(cmd)
        } else {
            if let Some(name) = args[0].as_literal_str() {
                if name.to_ascii_lowercase() == "goto" && args.len() > 1 {
                    Expression::Goto(args[1].clone())
                } else {
                    Expression::Command(CommandItem::new(
                        name.to_owned(),
                        CommandArgs::new(args[1..].to_vec()),
                    ))
                }
            } else {
                let msg = format!("Command name must be a literal string, got: {:?}", args[0]);
                error!("{}", msg);
                return Err(nom::Err::Error(nom::error::Error::from_error_kind(
                    input,
                    ErrorKind::Tag,
                )));
            }
        };

        Ok((input, cmd))
    }

    fn parse_literal(input: &str) -> IResult<&str, CommandArg> {
        let (input, arg) = alt(
            // double quoted string with escapes
            (
                delimited(
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
                ),
                // single quoted string
                map(delimited(char('\''), is_not("'"), char('\'')), |s: &str| {
                    s.to_string()
                }),
                // unquoted word
                map(
                    take_while1(|c: char| {
                        !c.is_whitespace() && c != '"' && c != '\'' && c != '$' && c != '('
                    }),
                    |s: &str| s.to_string(),
                ),
            ),
        )
        .parse(input)?;

        // Return as CommandArg::Literal
        Ok((input, CommandArg::Literal(arg)))
    }

    fn parse_var_dollar(input: &str) -> IResult<&str, CommandArg> {
        map(preceded(char('$'), alphanumeric1), |var: &str| {
            CommandArg::Var(var.to_string())
        })
        .parse(input)
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
                        let (_, exp) = Self::parse_command(content.trim())?;

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

    fn parse_arg(input: &str) -> IResult<&str, CommandArg> {
        alt((
            Self::parse_command_subst, // $(...)
            Self::parse_var_braced,    // ${VAR}
            Self::parse_var_dollar,    // $VAR
            Self::parse_literal,       // "..." or '...' or unquoted
        ))
        .parse(input)
    }
}