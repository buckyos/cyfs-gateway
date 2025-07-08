use super::block::{Block, CommandItem, Expression};
use super::exec::DynamicCommandExecutor;
use crate::cmd::{CommandExecutor, CommandParserFactory};
use std::sync::Arc;

pub struct BlockCommandTranslator {
    parser: CommandParserFactory,
}

impl BlockCommandTranslator {
    pub fn new(parser: CommandParserFactory) -> Self {
        Self { parser }
    }

    pub async fn translate(&self, block: &mut Block) -> Result<(), String> {
        for line in &mut block.lines {
            for statement in &mut line.statements {
                // For each statement, we need to translate the expressions
                for (_, expr, _) in &mut statement.expressions {
                    self.translate_expression(expr)?;
                }
            }
        }

        Ok(())
    }

    fn translate_expression(
        &self,
        expr: &mut Expression,
    ) -> Result<(), String> {
        match expr {
            Expression::Command(cmd) => {
                self.translate_command(cmd)?;
            }
            Expression::Group(exprs) => {
                // For group expressions, we need to translate each sub-expression
                for (_, sub_expr, _) in exprs {
                    self.translate_expression(sub_expr)?;
                }
            }
        }

        Ok(())
    }

    fn translate_command(
        &self,
        cmd: &mut CommandItem,
    ) -> Result<(), String> {
        let parser = self.parser.get_parser(&cmd.command.name);
        if parser.is_none() {
            let msg = format!("No parser for command: {}", cmd.command.name);
            error!("{}", msg);
            return Err(msg);
        }

        let parser = parser.unwrap();

        // Try parse args to executor
        let executer = if cmd.command.args.is_literal() {
            let args = cmd.command.args.as_literal_list();
            parser.parse(&args).map_err(|e| {
                let msg = format!("Parse command error: {:?}, {:?}", cmd.command, e);
                error!("{}", msg);
                msg
            })?
        } else {
            let exec = DynamicCommandExecutor::new(parser, cmd.take_args());

            Arc::new(Box::new(exec) as Box<dyn CommandExecutor>)
        };

        cmd.executor = Some(executer);

        Ok(())
    }
}
