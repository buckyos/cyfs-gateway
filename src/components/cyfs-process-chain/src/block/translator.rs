use super::block::{Block, CommandItem, Expression, CommandArg};
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

        // First check if the command is valid
        if let Err(e) = parser.check(&cmd.command.args) {
            let msg = format!("Invalid command: {:?} {}", cmd.command, e);
            error!("{}", msg);
            return Err(msg);
        }

        // Try parse args to executor
        let executer = if cmd.command.args.is_literal() {
            let args = cmd.command.args.as_literal_list();
            let args = args.iter().map(|s| s.to_string()).collect();
            parser.parse(args, &cmd.command.args).map_err(|e| {
                let msg = format!("Parse command error: {:?}, {:?}", cmd.command, e);
                error!("{}", msg);
                msg
            })?
        } else {
            for arg in cmd.command.args.iter_mut() {
                match arg {
                    CommandArg::CommandSubstitution(cmd_sub) => {
                        self.translate_expression(cmd_sub.as_mut())?;
                    }
                    _ => {}
                }
            }

            let exec = DynamicCommandExecutor::new(parser, cmd.take_args());

            Arc::new(Box::new(exec) as Box<dyn CommandExecutor>)
        };

        cmd.executor = Some(executer);

        Ok(())
    }
}
