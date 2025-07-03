use super::block::*;
use crate::cmd::CommandParserFactory;
use nom::{
    IResult, Parser,
    branch::alt,
    bytes::complete::tag,
    character::complete::space0,
    combinator::{map, opt},
    multi::many0,
    sequence::delimited,
};
use shlex;

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
                expressions: Vec::new(),
            });
        }

        // First try to split the line into label and expressions, the label is start with "label: "
        let (label, expr_input) = if let Some((label_part, rest)) = trimmed.split_once(": ") {
            (Some(label_part.trim().to_string()), rest.trim())
        } else {
            (None, trimmed)
        };

        let (_, expressions) = Self::parse_expressions(expr_input).map_err(|e| {
            let msg = format!("Parse expressions error: {}, {:?}", expr_input, e);
            error!("{}", msg);
            msg
        })?;

        Ok(Line { label, expressions })
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

    // Parse assign expression with = or :=
    fn parse_assign(input: &str) -> IResult<&str, Expression> {
        let (input, key) = nom::bytes::complete::take_till(|c: char| c == '=' || c == ':')(input)?;
        let (input, op) = alt((tag(":="), tag("="))).parse(input)?;
        let (input, value) =
            nom::bytes::complete::take_till(|c: char| c.is_whitespace() || c == '&' || c == '|')(
                input,
            )?;

        let name = "assign".to_string();
        let args = vec![
            key.trim().to_string(),
            op.trim().to_string(),
            value.trim().to_string(),
        ];

        let cmd = CommandItem::new(name, args);
        Ok((input, Expression::Command(cmd)))
    }

    // Parse command
    fn parse_command(input: &str) -> IResult<&str, Expression> {
        let (input, tokens) = map(
            many0(delimited(
                space0,
                |i| Ok((i, shlex::split(i).unwrap_or_default())),
                space0,
            )),
            |token_sets| {
                if token_sets.is_empty() {
                    let cmd = CommandItem::new_empty();
                    return Expression::Command(cmd);
                }

                let tokens = token_sets[0].clone();
                let name = tokens[0].clone();
                if name.to_ascii_lowercase() == "goto" && tokens.len() > 1 {
                    Expression::Goto(tokens[1].clone())
                } else {
                    let args = tokens[1..].to_vec();
                    Expression::Command(CommandItem::new(name, args))
                }
            },
        )
        .parse(input)
        .map_err(|e| {
            let msg = format!("Parse command error: {}, {:?}", input, e);
            error!("{}", msg);
            e
        })?;

        Ok((input, tokens))
    }
}

pub struct BlockCommandTranslator {
    parser: CommandParserFactory,
}

impl BlockCommandTranslator {
    pub fn new(parser: CommandParserFactory) -> Self {
        Self { parser }
    }

    pub async fn translate(&self, block: &mut Block) -> Result<(), String> {
        for line in &mut block.lines {
            for (expr, _) in &mut line.expressions {
                if let Expression::Command(cmd) = expr {
                    let parser = self.parser.get_parser(&cmd.command.name);
                    if parser.is_none() {
                        let msg = format!("No parser for command: {}", cmd.command.name);
                        error!("{}", msg);
                        return Err(msg);
                    }

                    let parser = parser.unwrap();

                    // First check if cmd is valid for the block type
                    if !parser.check(block.block_type) {
                        let msg = format!(
                            "Invalid command for block type: {:?}, block={:?}",
                            cmd.command, block.block_type
                        );
                        error!("{}", msg);
                        return Err(msg);
                    }

                    // Then parse args to executor
                    let executer = parser.parse(&cmd.command.args).map_err(|e| {
                        let msg = format!("Parse command error: {:?}, {:?}", cmd.command, e);
                        error!("{}", msg);
                        msg
                    })?;

                    cmd.executor = Some(executer);
                }
            }
        }

        Ok(())
    }
}
