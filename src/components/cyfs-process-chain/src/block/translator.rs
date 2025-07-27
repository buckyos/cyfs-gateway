use super::block::{Block, CommandArg, CommandArgs, CommandItem, Expression};
use super::exec::BlockExecuter;
use crate::chain::{Context, ParserContextRef};
use crate::cmd::{CommandExecutor, CommandParser, CommandParserFactory, CommandResult};
use crate::collection::CollectionValue;
use std::sync::Arc;


pub struct BlockCommandTranslator {
    context: ParserContextRef,
    parser: CommandParserFactory,
}

impl BlockCommandTranslator {
    pub fn new(context: ParserContextRef, parser: CommandParserFactory) -> Self {
        Self { context, parser }
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

    fn translate_expression(&self, expr: &mut Expression) -> Result<(), String> {
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

    fn translate_command(&self, cmd: &mut CommandItem) -> Result<(), String> {
        let parser = self.parser.get_parser(&cmd.command.name);
        if parser.is_none() {
            let msg = format!("No parser for command: {}", cmd.command.name);
            error!("{}", msg);
            return Err(msg);
        }

        let parser = parser.unwrap();

        // First check if the command is valid
        if let Err(e) = parser.check_with_context(&self.context, &cmd.command.args) {
            let msg = format!("Invalid command: {:?} {}", cmd.command, e);
            error!("{}", msg);
            return Err(msg);
        }

        // Try parse args to executor
        let executer = if cmd.command.args.is_literal() {
            let args = cmd.command.args.as_literal_list();
            let args = args
                .iter()
                .map(|s| CollectionValue::String(s.to_string()))
                .collect();
            parser
                .parse_origin_with_context(&self.context, args, &cmd.command.args)
                .map_err(|e| {
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

            let exec = DelayedCommandExecutor::new(self.context.clone(), parser, cmd.take_args());

            Arc::new(Box::new(exec) as Box<dyn CommandExecutor>)
        };

        cmd.executor = Some(executer);

        Ok(())
    }
}

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
        // First exec embedded commands in args to got their values
        let mut resolved_args = Vec::with_capacity(self.args.len());
        for arg in &*self.args {
            match arg {
                CommandArg::Literal(value) => {
                    resolved_args.push(CollectionValue::String(value.clone()))
                }
                CommandArg::Var(var) => {
                    // Resolve variable from context
                    if let Some(value) = context.env().get(&var, None).await? {
                        resolved_args.push(value);
                    } else {
                        // If variable is not found, push an empty string
                        warn!(
                            "Variable '{}' not found in context, using empty string",
                            var
                        );
                        resolved_args.push(CollectionValue::String(String::new()));
                    }
                }
                CommandArg::CommandSubstitution(cmd) => {
                    // Execute the command and get its result
                    let ret = BlockExecuter::execute_expression(&cmd, context).await?;
                    if !ret.is_substitution_value() {
                        let msg = format!("Command substitution did not return a value: {:?}", cmd);
                        warn!("{}", msg);
                        return Err(msg);
                    }

                    resolved_args.push(CollectionValue::String(
                        ret.into_substitution_value().unwrap(),
                    ));
                }
            }
        }

        // Parse the command using the dynamic parser
        let executor =
            self.parser
                .parse_origin_with_context(&self.context, resolved_args, &self.args)?;
        executor.exec(context).await
    }
}
