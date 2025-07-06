use super::block::{Block, CommandItem, Expression, Line, Operator, Statement};
use super::block::{CommandArg, CommandArgs};
use super::context::Context;
use crate::cmd::{CommandAction, CommandResult};
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
    // Goto counter
    pub goto_counter: u32,
}

impl BlockExecuter {
    pub fn new() -> Self {
        Self { goto_counter: 0 }
    }

    // Execute the block
    pub async fn execute_block(
        &mut self,
        block: &Block,
        context: &Context,
    ) -> Result<BlockResult, String> {
        let mut current_line = 0;
        let mut result = BlockResult::Ok;
        while current_line < block.lines.len() {
            let line = &block.lines[current_line];
            let line_result = Self::execute_line(line, context).await?;
            info!("Line {} executed: result={:?}", current_line, line_result);

            match line_result.action {
                CommandAction::Ok => {
                    current_line += 1;
                    result = BlockResult::Ok;
                }
                CommandAction::Drop => {
                    result = BlockResult::Drop;
                    break;
                }
                CommandAction::Pass => {
                    result = BlockResult::Pass;
                    break;
                }
                CommandAction::Goto(goto_target) => {
                    if let Some(&target_line) = block.label_map.get(&goto_target) {
                        current_line = target_line;

                        // Increase the goto counter and check the limit
                        self.goto_counter += 1;
                        if self.goto_counter > MAX_GOTO_COUNT_IN_BLOCK {
                            let msg =
                                format!("Goto count exceeds limit {}", MAX_GOTO_COUNT_IN_BLOCK);
                            error!("{}", msg);
                            return Err(msg);
                        }
                    } else {
                        let msg = format!("Goto target {} not found", goto_target);
                        error!("{}", msg);
                        return Err(msg);
                    }
                }
                CommandAction::Value(ret) => {
                    let msg = format!(
                        "Unexpected return value from line {}: {}",
                        current_line, ret
                    );
                    error!("{}", msg);
                    return Err(msg);
                }
            }
        }

        Ok(result)
    }

    // Execute a single line with multiple statements
    async fn execute_line(line: &Line, context: &Context) -> Result<CommandResult, String> {
        // We execute each statement in the line sequentially, and got the result of the last statement
        let mut result = CommandResult::success();
        for statement in line.statements.iter() {
            result = Self::execute_statement(statement, context).await?;
        }

        Ok(result)
    }

    // Execute a single statement
    async fn execute_statement(
        statement: &Statement,
        context: &Context,
    ) -> Result<CommandResult, String> {
        let mut result = CommandResult::success();
        for (expr, op) in &statement.expressions {
            result = Self::execute_expression(expr, context).await?;

            // Check if the result is a special action such as goto/drop/pass
            if result.is_special_action() {
                return Ok(result);
            }

            match op {
                Operator::And if !result.success => return Ok(result),
                Operator::Or if result.success => return Ok(result),
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
                for (sub_expr, op) in exprs {
                    result = {
                        let sub_result = Self::execute_expression(sub_expr, context).await?;

                        // Check if the result is a special action such as goto/drop/pass
                        if sub_result.is_special_action() {
                            return Ok(sub_result);
                        }

                        sub_result
                    };
                    match op {
                        Operator::And if !result.success => return Ok(result),
                        Operator::Or if result.success => return Ok(result),
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
                    if !ret.is_value() {
                        let msg = format!("Command substitution did not return a value: {:?}", cmd);
                        warn!("{}", msg);
                        return Err(msg);
                    }

                    resolved_args.push(ret.into_value().unwrap());
                }
            }
        }

        // Parse the command using the dynamic parser
        let executor = self.parser.parse_origin(resolved_args, &self.args)?;
        executor.exec(context).await
    }
}
