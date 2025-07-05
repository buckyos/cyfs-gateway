use super::block::{Block, BlockType, CommandItem, Expression};
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
                for (expr, _) in &mut statement.expressions {
                    self.translate_expression(expr, block.block_type)?;
                }
            }
        }

        Ok(())
    }

    fn translate_expression(
        &self,
        expr: &mut Expression,
        block_type: BlockType,
    ) -> Result<(), String> {
        match expr {
            Expression::Command(cmd) => {
                self.translate_command(cmd, block_type)?;
            }
            Expression::Group(exprs) => {
                // For group expressions, we need to translate each sub-expression
                for (sub_expr, _) in exprs {
                    self.translate_expression(sub_expr, block_type)?;
                }
            }
            Expression::Goto(_) => {
                // Goto does not need translation
            }
        }

        Ok(())
    }

    fn translate_command(
        &self,
        cmd: &mut CommandItem,
        block_type: BlockType,
    ) -> Result<(), String> {
        let parser = self.parser.get_parser(&cmd.command.name);
        if parser.is_none() {
            let msg = format!("No parser for command: {}", cmd.command.name);
            error!("{}", msg);
            return Err(msg);
        }

        let parser = parser.unwrap();

        // First check if cmd is valid for the block type
        if !parser.check(block_type) {
            let msg = format!(
                "Invalid command for block type: {:?}, cmd={:?}",
                cmd.command, block_type
            );
            error!("{}", msg);
            return Err(msg);
        }

        // Then parse args to executor
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
