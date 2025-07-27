use super::block::{Block, CommandItem, Expression, Line, Operator, Statement};
use crate::chain::Context;
use crate::cmd::CommandResult;

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
            info!(
                "Executing line {}:{}: {:?}",
                self.block_id, current_line, line
            );
            let line_result = Self::execute_line(line, context).await?;
            info!(
                "Line {} executed: {}, {:?}",
                current_line, line.source, line_result
            );

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
            debug!("Executing expression: {:?}", expr);
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
    pub(crate) async fn execute_expression(
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
        }
    }

    async fn execute_command(
        cmd: &CommandItem,
        context: &Context,
    ) -> Result<CommandResult, String> {
        debug!("Executing command: {:?}", cmd);
        let exec = cmd.executor.as_ref().unwrap();
        exec.exec(context).await
    }
}
