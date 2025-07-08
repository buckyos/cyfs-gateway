use super::block::{Block, CommandItem, Expression, Line, Operator, Statement};
use super::block::{CommandArg, CommandArgs};
use super::context::Context;
use crate::cmd::CommandResult;
use crate::cmd::{CommandExecutor, CommandParser};
use std::sync::Arc;

pub const MAX_GOTO_COUNT_IN_BLOCK: u32 = 128;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum BlockResult {
    Ok,
    Drop,
    Pass,
}

pub struct BlockExecuter {
    block_id: String, // Block ID
}

impl BlockExecuter {
    pub fn new(block_id: &str) -> Self {
        Self {
            block_id: block_id.to_string(),
        }
    }

    // Execute the block
    pub async fn execute_block(
        &self,
        block: &Block,
        context: &Context,
    ) -> Result<CommandResult, String> {
        info!("Executing block: {} lines {}", block.id, block.lines.len());

        let mut current_line = 0;
        let mut result = CommandResult::success();
        while current_line < block.lines.len() {
            let line = &block.lines[current_line];
            println!(
                "Executing line {}:{}: {:?}",
                self.block_id, current_line, line
            );
            let line_result = Self::execute_line(line, context).await?;
            info!("Line {} executed: result={:?}", current_line, line_result);

            if line_result.is_control() {
                // If the line result is a control action, we handle it immediately
                info!("Control action at line {}: {:?}", current_line, line_result);
                return Ok(line_result);
            }

            result = line_result;
            // Continue to the next line

            current_line += 1;
        }

        Ok(result)
    }

    // Execute a single line with multiple statements
    async fn execute_line(line: &Line, context: &Context) -> Result<CommandResult, String> {
        // We execute each statement in the line sequentially, and got the result of the last statement
        let mut result = CommandResult::success();
        for statement in line.statements.iter() {
            result = Self::execute_statement(statement, context).await?;
            if result.is_control() {
                // If the result is an action (exit/goto/return), we return it immediately
                return Ok(result);
            }
        }

        Ok(result)
    }

    // Execute a single statement
    async fn execute_statement(
        statement: &Statement,
        context: &Context,
    ) -> Result<CommandResult, String> {
        let mut result = CommandResult::success();

        for (prefix_op, expr, post_op) in &statement.expressions {
            println!("Executing expression: {:?}", expr);
            result = Self::execute_expression(expr, context).await?;

            result = match prefix_op {
                Some(Operator::Not) => result.try_not()?,
                _ => result,
            };

            // Check if the result is a special action such as goto/drop/pass
            if result.is_control() {
                return Ok(result);
            }

            match *post_op {
                Some(Operator::And) if !result.is_success() => return Ok(result),
                Some(Operator::Or) if result.is_success() => return Ok(result),
                _ => continue,
            }
        }

        Ok(result)
    }

    // Execute a single expression
    #[async_recursion::async_recursion]
    async fn execute_expression(
        expr: &Expression,
        context: &Context,
    ) -> Result<CommandResult, String> {
        match expr {
            Expression::Command(cmd) => {
                let result = Self::execute_command(cmd, context).await?;
                Ok(result)
            }
            Expression::Group(exprs) => {
                let mut result = CommandResult::success();
                for (prefix_op, sub_expr, post_op) in exprs {
                    result = {
                        let sub_result = Self::execute_expression(sub_expr, context).await?;

                        let sub_result = match prefix_op {
                            Some(Operator::Not) => sub_result.try_not()?,
                            _ => sub_result,
                        };

                        // Check if the result is a special action such as goto/drop/pass
                        if sub_result.is_control() {
                            return Ok(sub_result);
                        }

                        sub_result
                    };

                    match post_op {
                        Some(Operator::And) if !result.is_success() => return Ok(result),
                        Some(Operator::Or) if result.is_success() => return Ok(result),
                        _ => continue,
                    }
                }
                Ok(result)
            }
            Expression::Goto(target) => {
                todo!("Goto expression not implemented yet");
                // Ok(CommandResult::goto(target.clone()))
            }
        }
    }

    async fn execute_command(
        _cmd: &CommandItem,
        _context: &Context,
    ) -> Result<CommandResult, String> {
        todo!("execute_command not implemented yet");
    }
}

pub struct DynamicCommandExecutor {
    pub parser: Arc<Box<dyn CommandParser>>,
    pub args: CommandArgs,
}

impl DynamicCommandExecutor {
    pub fn new(parser: Arc<Box<dyn CommandParser>>, args: CommandArgs) -> Self {
        Self { parser, args }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for DynamicCommandExecutor {
    async fn exec(&self, context: &Context) -> Result<CommandResult, String> {
        // First exec embedded commands in args to got their values
        let mut resolved_args = Vec::with_capacity(self.args.len());
        for arg in &*self.args {
            match arg {
                CommandArg::Literal(value) => resolved_args.push(value.clone()),
                CommandArg::Var(var) => {
                    // Resolve variable from context
                    if let Some(value) = context.get_env_value(&var).await? {
                        resolved_args.push(value.clone());
                    } else {
                        // If variable is not found, push an empty string
                        resolved_args.push("".to_string());
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

                    resolved_args.push(ret.into_substitution_value().unwrap());
                }
            }
        }

        // Parse the command using the dynamic parser
        let executor = self.parser.parse_origin(resolved_args, &self.args)?;
        executor.exec(context).await
    }
}
