use super::block::{Block, CommandArg, CommandItem, Expression};
use super::exec::BlockExecuter;
use crate::chain::{Context, ParserContextRef};
use crate::cmd::{CommandParserFactory};
use crate::collection::CollectionValue;

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
        // debug!("Translating command: {:?}", cmd.command);
        let parser = self.parser.get_parser(&cmd.command.name);
        if parser.is_none() {
            let msg = format!("No parser for command: {}", cmd.command.name);
            error!("{}", msg);
            return Err(msg);
        }

        // Recursively translate the command arguments
        for arg in &mut cmd.command.args.iter_mut() {
            match arg.as_command_substitution_mut() {
                Some(exp) => {
                    // If it's a command substitution, we need to translate it as well
                    self.translate_expression(exp)?;
                }
                None => {
                    continue; // Literal or variable, no translation needed
                }
            }
        }

        let parser = parser.unwrap();
        match parser.parse_origin(&self.context, &cmd.command.args) {
            Ok(executor) => {
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

    pub async fn evaluate(arg: &CommandArg, context: &Context) -> Result<CollectionValue, String> {
        let ret = match arg {
            CommandArg::Literal(value) => CollectionValue::String(value.clone()),
            CommandArg::Var(var) => {
                info!("Resolving variable: {}", var);
                if let Some(value) = context.env().get(&var, None).await? {
                    value
                } else {
                    // If variable is not found, push an empty string
                    warn!(
                        "Variable '{}' not found in context, using empty string",
                        var
                    );
                    CollectionValue::String(String::new())
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
