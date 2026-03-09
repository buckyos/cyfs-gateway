use super::block::{
    Block, CommandItem, Expression, ExpressionChain, ForStatement, IfStatement, Line, Operator,
    Statement,
};
use crate::chain::{Context, EnvLevel, ProcessChainError, ProcessChainErrorCode};
use crate::cmd::CommandResult;
use crate::collection::{CollectionValue, MemorySetCollection, SetCollection};
use log::log;
use std::sync::Arc;

pub const MAX_GOTO_COUNT_IN_BLOCK: u32 = 128;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum BlockResult {
    Ok,
    Drop,
    Pass,
}

type ForLoopEntry = (CollectionValue, Option<CollectionValue>);

struct LoopVarSnapshot {
    name: String,
    value: Option<CollectionValue>,
    tracker_level: Option<EnvLevel>,
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
        log!(
            context.env().get_log_level(),
            "Executing block: {} lines {}",
            block.id,
            block.lines.len()
        );

        let mut current_line = 0;
        let mut result = CommandResult::success();
        while current_line < block.lines.len() {
            let line = &block.lines[current_line];
            let line_no = current_line + 1;
            log!(
                context.env().get_log_level(),
                "Executing line {}:{}: {:?}",
                self.block_id,
                current_line,
                line
            );
            let line_result = Self::execute_line(line, line_no, context)
                .await
                .map_err(|e| {
                    Self::wrap_runtime_error(
                        context,
                        ProcessChainErrorCode::RuntimeLineExecute,
                        "Failed to execute line",
                        Some(line_no),
                        Some(line.source.as_str()),
                        None,
                        e,
                    )
                })?;
            log!(
                context.env().get_log_level(),
                "Line {} executed: {}, {:?}",
                current_line,
                line.source,
                line_result
            );

            if line_result.is_control() {
                // If the line result is a control action, we handle it immediately
                log!(
                    context.env().get_log_level(),
                    "Control action at line {}: {:?}",
                    current_line,
                    line_result
                );
                return Ok(line_result);
            }

            result = line_result;
            // Continue to the next line

            current_line += 1;
        }

        Ok(result)
    }

    fn wrap_runtime_error(
        context: &Context,
        code: ProcessChainErrorCode,
        message: impl Into<String>,
        line_no: Option<usize>,
        source: Option<&str>,
        command: Option<&str>,
        cause: impl Into<String>,
    ) -> String {
        let mut err = ProcessChainError::new(code, message, context).with_cause(cause.into());
        if let Some(line_no) = line_no {
            err = err.with_line_source(line_no, source.unwrap_or("-"));
        }
        if let Some(command) = command {
            err = err.with_command(command);
        }

        err.to_string()
    }

    // Execute a single line with multiple statements
    #[async_recursion::async_recursion]
    async fn execute_line(
        line: &Line,
        line_no: usize,
        context: &Context,
    ) -> Result<CommandResult, String> {
        // We execute each statement in the line sequentially, and got the result of the last statement
        let mut result = CommandResult::success();
        for statement in line.statements.iter() {
            result =
                Self::execute_statement(statement, line_no, line.source.as_str(), context).await?;
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
        line_no: usize,
        source: &str,
        context: &Context,
    ) -> Result<CommandResult, String> {
        if let Some(if_statement) = statement.if_statement.as_ref() {
            return Self::execute_if_statement(if_statement, line_no, source, context).await;
        }
        if let Some(for_statement) = statement.for_statement.as_ref() {
            return Self::execute_for_statement(for_statement, line_no, source, context).await;
        }

        Self::execute_expression_chain(
            &statement.expressions,
            context,
            Some(line_no),
            Some(source),
            true,
            "",
        )
        .await
    }

    // Execute a single expression
    #[async_recursion::async_recursion]
    pub(crate) async fn execute_expression(
        expr: &Expression,
        context: &Context,
    ) -> Result<CommandResult, String> {
        Self::execute_expression_with_location(expr, context, None, None).await
    }

    #[async_recursion::async_recursion]
    async fn execute_expression_with_location(
        expr: &Expression,
        context: &Context,
        line_no: Option<usize>,
        source: Option<String>,
    ) -> Result<CommandResult, String> {
        match expr {
            Expression::Command(cmd) => {
                let result = Self::execute_command(cmd, context, line_no, source.clone())
                    .await
                    .map_err(|e| {
                        Self::wrap_runtime_error(
                            context,
                            ProcessChainErrorCode::RuntimeCommandExecute,
                            "Failed to execute command expression",
                            line_no,
                            source.as_deref(),
                            Some(&format!("{:?}", cmd.command)),
                            e,
                        )
                    })?;
                Ok(result)
            }
            Expression::Group(exprs) => {
                Self::execute_expression_chain(exprs, context, line_no, source.as_deref(), true, "")
                    .await
            }
        }
    }

    async fn execute_expression_chain(
        expressions: &ExpressionChain,
        context: &Context,
        line_no: Option<usize>,
        source: Option<&str>,
        allow_control: bool,
        control_error_message: &str,
    ) -> Result<CommandResult, String> {
        let mut result = CommandResult::success();

        for (prefix_op, expr, post_op) in expressions {
            debug!("Executing expression: {:?}", expr);
            result = Self::execute_expression_with_location(
                expr,
                context,
                line_no,
                source.map(|s| s.to_string()),
            )
            .await
            .map_err(|e| {
                Self::wrap_runtime_error(
                    context,
                    ProcessChainErrorCode::RuntimeExpressionExecute,
                    "Failed to execute expression",
                    line_no,
                    source,
                    None,
                    e,
                )
            })?;

            result = match prefix_op {
                Some(Operator::Not) => result.try_not().map_err(|e| {
                    Self::wrap_runtime_error(
                        context,
                        ProcessChainErrorCode::RuntimeExpressionExecute,
                        "Failed to apply NOT operator",
                        line_no,
                        source,
                        None,
                        e,
                    )
                })?,
                _ => result,
            };

            if result.is_control() {
                if allow_control {
                    return Ok(result);
                }

                let msg = if control_error_message.is_empty() {
                    "Control action is not allowed in this expression chain".to_string()
                } else {
                    control_error_message.to_string()
                };
                return Err(Self::wrap_runtime_error(
                    context,
                    ProcessChainErrorCode::RuntimeExpressionExecute,
                    msg,
                    line_no,
                    source,
                    None,
                    format!("{:?}", result),
                ));
            }

            match *post_op {
                Some(Operator::And) if !result.is_success() => return Ok(result),
                Some(Operator::Or) if result.is_success() => return Ok(result),
                _ => continue,
            }
        }

        Ok(result)
    }

    async fn execute_nested_lines(
        lines: &[Line],
        line_no: usize,
        context: &Context,
    ) -> Result<CommandResult, String> {
        let mut result = CommandResult::success();
        for line in lines {
            result = Self::execute_line(line, line_no, context).await?;
            if result.is_control() {
                return Ok(result);
            }
        }

        Ok(result)
    }

    async fn execute_if_statement(
        if_statement: &IfStatement,
        line_no: usize,
        source: &str,
        context: &Context,
    ) -> Result<CommandResult, String> {
        for branch in &if_statement.branches {
            let cond_result = Self::execute_expression_chain(
                &branch.condition,
                context,
                Some(line_no),
                Some(source),
                false,
                "Control action is not allowed in if condition",
            )
            .await?;
            if cond_result.is_success() {
                return Self::execute_nested_lines(&branch.lines, line_no, context).await;
            }
        }

        if let Some(else_lines) = if_statement.else_lines.as_ref() {
            return Self::execute_nested_lines(else_lines, line_no, context).await;
        }

        Ok(CommandResult::success())
    }

    async fn snapshot_loop_var(
        var_name: &str,
        context: &Context,
    ) -> Result<LoopVarSnapshot, String> {
        let exists_in_block = context.env().get_block().contains(var_name).await?;
        let value = if exists_in_block {
            context.env().get(var_name, Some(EnvLevel::Block)).await?
        } else {
            None
        };
        let tracker_level = context.env().var_level_entry(var_name);

        Ok(LoopVarSnapshot {
            name: var_name.to_string(),
            value,
            tracker_level,
        })
    }

    async fn restore_loop_vars(
        snapshots: &[LoopVarSnapshot],
        context: &Context,
    ) -> Result<(), String> {
        for snapshot in snapshots {
            if let Some(value) = snapshot.value.as_ref() {
                context
                    .env()
                    .set(&snapshot.name, value.clone(), Some(EnvLevel::Block))
                    .await?;
            } else {
                let _ = context
                    .env()
                    .remove(&snapshot.name, Some(EnvLevel::Block))
                    .await?;
            }

            context
                .env()
                .restore_var_level_entry(&snapshot.name, snapshot.tracker_level);
        }

        Ok(())
    }

    async fn collect_for_loop_entries(
        for_statement: &ForStatement,
        context: &Context,
    ) -> Result<Vec<ForLoopEntry>, String> {
        let iterable = for_statement.iterable.evaluate(context).await?;
        let want_value_var = for_statement.value_var.is_some();

        match iterable {
            CollectionValue::List(list) => {
                let values = list.dump().await?;
                let entries = if want_value_var {
                    values
                        .into_iter()
                        .enumerate()
                        .map(|(idx, value)| {
                            (
                                CollectionValue::Number(crate::collection::NumberValue::Int(
                                    idx as i64,
                                )),
                                Some(value),
                            )
                        })
                        .collect()
                } else {
                    values.into_iter().map(|value| (value, None)).collect()
                };
                Ok(entries)
            }
            CollectionValue::Set(set) => {
                let values = set.dump().await?;
                let entries = values
                    .into_iter()
                    .map(|value| {
                        let value = CollectionValue::String(value);
                        if want_value_var {
                            (value.clone(), Some(value))
                        } else {
                            (value, None)
                        }
                    })
                    .collect();
                Ok(entries)
            }
            CollectionValue::Map(map) => {
                let values = map.dump().await?;
                let entries = values
                    .into_iter()
                    .map(|(key, value)| {
                        if want_value_var {
                            (CollectionValue::String(key), Some(value))
                        } else {
                            (CollectionValue::String(key), None)
                        }
                    })
                    .collect();
                Ok(entries)
            }
            CollectionValue::MultiMap(multi_map) => {
                let values = multi_map.dump().await?;
                let entries = values
                    .into_iter()
                    .map(|(key, set)| {
                        let value = if want_value_var {
                            let set = Arc::new(Box::new(MemorySetCollection::from_set(set))
                                as Box<dyn SetCollection>);
                            Some(CollectionValue::Set(set))
                        } else {
                            None
                        };
                        (CollectionValue::String(key), value)
                    })
                    .collect();
                Ok(entries)
            }
            other => {
                let msg = format!(
                    "For-loop iterable must be List/Set/Map/MultiMap, got {}",
                    other.get_type()
                );
                Err(msg)
            }
        }
    }

    async fn execute_for_statement(
        for_statement: &ForStatement,
        line_no: usize,
        source: &str,
        context: &Context,
    ) -> Result<CommandResult, String> {
        let mut snapshots = Vec::with_capacity(if for_statement.value_var.is_some() {
            2
        } else {
            1
        });

        snapshots.push(Self::snapshot_loop_var(&for_statement.key_var, context).await?);
        if let Some(value_var) = for_statement.value_var.as_ref() {
            snapshots.push(Self::snapshot_loop_var(value_var, context).await?);
        }

        let execute_result: Result<CommandResult, String> = async {
            let entries = Self::collect_for_loop_entries(for_statement, context).await?;
            let mut result = CommandResult::success();

            for (key, value) in entries {
                context
                    .env()
                    .set(&for_statement.key_var, key, Some(EnvLevel::Block))
                    .await?;

                if let Some(value_var) = for_statement.value_var.as_ref() {
                    let value = value.unwrap_or(CollectionValue::Null);
                    context
                        .env()
                        .set(value_var, value, Some(EnvLevel::Block))
                        .await?;
                }

                let loop_result =
                    Self::execute_nested_lines(&for_statement.lines, line_no, context).await?;
                if !loop_result.is_control() {
                    result = loop_result;
                    continue;
                }

                let control = loop_result.as_control().unwrap();
                if control.is_break() {
                    result = CommandResult::success_with_value(control.value().clone());
                    break;
                }

                return Ok(loop_result);
            }

            Ok(result)
        }
        .await;

        let restore_result = Self::restore_loop_vars(&snapshots, context).await;
        match (execute_result, restore_result) {
            (Ok(result), Ok(())) => Ok(result),
            (Err(exec_err), Ok(())) => Err(Self::wrap_runtime_error(
                context,
                ProcessChainErrorCode::RuntimeExpressionExecute,
                "Failed to execute for statement",
                Some(line_no),
                Some(source),
                None,
                exec_err,
            )),
            (Ok(_), Err(restore_err)) => Err(Self::wrap_runtime_error(
                context,
                ProcessChainErrorCode::RuntimeExpressionExecute,
                "Failed to restore loop variable scope",
                Some(line_no),
                Some(source),
                None,
                restore_err,
            )),
            (Err(exec_err), Err(restore_err)) => Err(Self::wrap_runtime_error(
                context,
                ProcessChainErrorCode::RuntimeExpressionExecute,
                "Failed to execute for statement and restore loop variable scope",
                Some(line_no),
                Some(source),
                None,
                format!("exec_error={}, restore_error={}", exec_err, restore_err),
            )),
        }
    }

    async fn execute_command(
        cmd: &CommandItem,
        context: &Context,
        line_no: Option<usize>,
        source: Option<String>,
    ) -> Result<CommandResult, String> {
        debug!("Executing command: {:?}", cmd);
        let command_text = format!("{:?}", cmd.command);
        let exec = cmd.executor.as_ref().ok_or_else(|| {
            let msg = format!("Command not linked: {:?}", cmd);
            error!("{}", msg);
            Self::wrap_runtime_error(
                context,
                ProcessChainErrorCode::RuntimeCommandNotLinked,
                "Command not linked",
                line_no,
                source.as_deref(),
                Some(&command_text),
                msg,
            )
        })?;

        let ret = exec.exec(context).await.map_err(|e| {
            Self::wrap_runtime_error(
                context,
                ProcessChainErrorCode::RuntimeCommandExecute,
                "Command execution failed",
                line_no,
                source.as_deref(),
                Some(&command_text),
                e,
            )
        })?;
        debug!("Command executed: {:?}, result: {:?}", cmd, ret);

        Ok(ret)
    }
}
