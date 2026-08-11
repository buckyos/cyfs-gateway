use super::types::{
    Block, CaseStatement, CommandItem, Expression, ExpressionChain, ForStatement, IfStatement,
    Line, MatchResultBranch, MatchResultControlBranch, MatchResultStatement, Operator, Statement,
};
use crate::chain::{Context, EnvLevel, ProcessChainError, ProcessChainErrorCode};
use crate::cmd::{CommandControl, CommandResult};
use crate::collection::{
    CollectionValue, ListCollectionTraverseCallBack, MapCollectionTraverseCallBack,
    MemorySetCollection, MultiMapCollectionKeyTraverseCallBack,
    MultiMapCollectionTraverseOwnedCallBack, NumberValue, OrderedStringSet, SetCollection,
    SetCollectionTraverseCallBack, TraverseControl,
};
use log::log;
use std::sync::Arc;
use tokio::sync::Mutex;

pub const MAX_GOTO_COUNT_IN_BLOCK: u32 = 128;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum BlockResult {
    Ok,
    Drop,
    Pass,
}

struct LoopVarSnapshot {
    name: String,
    value: Option<CollectionValue>,
    tracker_level: Option<EnvLevel>,
}

enum ForIterationOutcome {
    Continue(CommandResult),
    Break(CommandResult),
    Propagate(CommandResult),
}

struct ForTraverseState {
    result: CommandResult,
    terminal: Option<CommandResult>,
}

impl ForTraverseState {
    fn new() -> Self {
        Self {
            result: CommandResult::success(),
            terminal: None,
        }
    }
}

type ForTraverseStateRef = Arc<Mutex<ForTraverseState>>;

struct ForMapTraverseCallback {
    for_statement: ForStatement,
    line_no: usize,
    context: Context,
    state: ForTraverseStateRef,
}

struct ForListTraverseCallback {
    for_statement: ForStatement,
    line_no: usize,
    context: Context,
    state: ForTraverseStateRef,
}

struct ForSetTraverseCallback {
    for_statement: ForStatement,
    line_no: usize,
    context: Context,
    state: ForTraverseStateRef,
}

struct ForMultiMapKeyTraverseCallback {
    for_statement: ForStatement,
    line_no: usize,
    context: Context,
    state: ForTraverseStateRef,
}

struct ForMultiMapOwnedTraverseCallback {
    for_statement: ForStatement,
    line_no: usize,
    context: Context,
    state: ForTraverseStateRef,
}

#[async_trait::async_trait]
impl MapCollectionTraverseCallBack for ForMapTraverseCallback {
    async fn call(&self, key: &str, value: &CollectionValue) -> Result<bool, String> {
        let loop_value = if self.for_statement.value_var.is_some() {
            Some(value.clone())
        } else {
            None
        };

        let outcome = BlockExecuter::execute_for_iteration(
            &self.for_statement,
            self.line_no,
            &self.context,
            CollectionValue::String(key.to_string()),
            loop_value,
        )
        .await?;

        BlockExecuter::apply_iteration_outcome_bool(&self.state, outcome).await
    }
}

#[async_trait::async_trait]
impl ListCollectionTraverseCallBack for ForListTraverseCallback {
    async fn call(&self, index: usize, value: &CollectionValue) -> Result<bool, String> {
        let key = if self.for_statement.value_var.is_some() {
            CollectionValue::Number(NumberValue::Int(index as i64))
        } else {
            value.clone()
        };
        let loop_value = if self.for_statement.value_var.is_some() {
            Some(value.clone())
        } else {
            None
        };

        let outcome = BlockExecuter::execute_for_iteration(
            &self.for_statement,
            self.line_no,
            &self.context,
            key,
            loop_value,
        )
        .await?;

        BlockExecuter::apply_iteration_outcome_bool(&self.state, outcome).await
    }
}

#[async_trait::async_trait]
impl SetCollectionTraverseCallBack for ForSetTraverseCallback {
    async fn call(&self, item: &str) -> Result<bool, String> {
        let item = CollectionValue::String(item.to_string());
        let key = item.clone();
        let loop_value = if self.for_statement.value_var.is_some() {
            Some(item)
        } else {
            None
        };

        let outcome = BlockExecuter::execute_for_iteration(
            &self.for_statement,
            self.line_no,
            &self.context,
            key,
            loop_value,
        )
        .await?;

        BlockExecuter::apply_iteration_outcome_bool(&self.state, outcome).await
    }
}

#[async_trait::async_trait]
impl MultiMapCollectionKeyTraverseCallBack for ForMultiMapKeyTraverseCallback {
    async fn call(&self, key: &str) -> Result<bool, String> {
        let outcome = BlockExecuter::execute_for_iteration(
            &self.for_statement,
            self.line_no,
            &self.context,
            CollectionValue::String(key.to_string()),
            None,
        )
        .await?;

        BlockExecuter::apply_iteration_outcome_bool(&self.state, outcome).await
    }
}

#[async_trait::async_trait]
impl MultiMapCollectionTraverseOwnedCallBack for ForMultiMapOwnedTraverseCallback {
    async fn call(&self, key: String, values: OrderedStringSet) -> Result<TraverseControl, String> {
        let set =
            Arc::new(Box::new(MemorySetCollection::from_set(values)) as Box<dyn SetCollection>);
        let outcome = BlockExecuter::execute_for_iteration(
            &self.for_statement,
            self.line_no,
            &self.context,
            CollectionValue::String(key),
            Some(CollectionValue::Set(set)),
        )
        .await?;

        BlockExecuter::apply_iteration_outcome_control(&self.state, outcome).await
    }
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
        if let Some(case_statement) = statement.case_statement.as_ref() {
            return Self::execute_case_statement(case_statement, line_no, source, context).await;
        }
        if let Some(for_statement) = statement.for_statement.as_ref() {
            return Self::execute_for_statement(for_statement, line_no, source, context).await;
        }
        if let Some(match_result_statement) = statement.match_result_statement.as_ref() {
            return Self::execute_match_result_statement(
                match_result_statement,
                line_no,
                source,
                context,
            )
            .await;
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

    async fn execute_case_statement(
        case_statement: &CaseStatement,
        line_no: usize,
        source: &str,
        context: &Context,
    ) -> Result<CommandResult, String> {
        if let (Some(subject), Some(binding_var)) = (
            case_statement.subject.as_ref(),
            case_statement.binding_var.as_deref(),
        ) {
            let subject_value = subject.evaluate(context).await?;
            let snapshots = vec![Self::snapshot_block_var(binding_var, context).await?];

            let execute_result: Result<CommandResult, String> = async {
                context
                    .env()
                    .set(binding_var, subject_value, Some(EnvLevel::Block))
                    .await?;

                Self::execute_case_branches(case_statement, line_no, source, context).await
            }
            .await;

            let restore_result = Self::restore_block_vars(&snapshots, context).await;
            return match (execute_result, restore_result) {
                (Ok(result), Ok(())) => Ok(result),
                (Err(exec_err), Ok(())) => Err(Self::wrap_runtime_error(
                    context,
                    ProcessChainErrorCode::RuntimeExpressionExecute,
                    "Failed to execute case statement",
                    Some(line_no),
                    Some(source),
                    None,
                    exec_err,
                )),
                (Ok(_), Err(restore_err)) => Err(Self::wrap_runtime_error(
                    context,
                    ProcessChainErrorCode::RuntimeExpressionExecute,
                    "Failed to restore case subject binding",
                    Some(line_no),
                    Some(source),
                    None,
                    restore_err,
                )),
                (Err(exec_err), Err(restore_err)) => Err(Self::wrap_runtime_error(
                    context,
                    ProcessChainErrorCode::RuntimeExpressionExecute,
                    "Failed to execute case statement and restore subject binding",
                    Some(line_no),
                    Some(source),
                    None,
                    format!("exec_error={}, restore_error={}", exec_err, restore_err),
                )),
            };
        }

        Self::execute_case_branches(case_statement, line_no, source, context).await
    }

    async fn execute_case_branches(
        case_statement: &CaseStatement,
        line_no: usize,
        source: &str,
        context: &Context,
    ) -> Result<CommandResult, String> {
        for branch in &case_statement.branches {
            let cond_result = Self::execute_expression_chain(
                &branch.condition,
                context,
                Some(line_no),
                Some(source),
                false,
                "Control action is not allowed in case condition",
            )
            .await?;
            if cond_result.is_success() {
                return Self::execute_nested_lines(&branch.lines, line_no, context).await;
            }
        }

        if let Some(else_lines) = case_statement.else_lines.as_ref() {
            return Self::execute_nested_lines(else_lines, line_no, context).await;
        }

        Ok(CommandResult::success())
    }

    async fn snapshot_block_var(
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

    async fn execute_match_result_value_branch(
        branch: &MatchResultBranch,
        value: CollectionValue,
        line_no: usize,
        source: &str,
        context: &Context,
    ) -> Result<CommandResult, String> {
        let binding = vec![(branch.binding_var.as_str(), value)];
        Self::execute_match_result_branch_lines(&binding, &branch.lines, line_no, source, context)
            .await
    }

    async fn execute_match_result_control_branch(
        branch: &MatchResultControlBranch,
        control: CommandControl,
        line_no: usize,
        source: &str,
        context: &Context,
    ) -> Result<CommandResult, String> {
        let action = match &control {
            CommandControl::Return(_) => CollectionValue::String("return".to_string()),
            CommandControl::Error(_) => CollectionValue::String("error".to_string()),
            CommandControl::Exit(_) => CollectionValue::String("exit".to_string()),
            CommandControl::Break(_) => CollectionValue::String("break".to_string()),
        };
        let from = match &control {
            CommandControl::Return(v) | CommandControl::Error(v) => {
                CollectionValue::String(v.level.as_str().to_string())
            }
            CommandControl::Exit(_) | CommandControl::Break(_) => CollectionValue::Null,
        };
        let value = control.value().clone();

        let bindings = vec![
            (branch.action_var.as_str(), action),
            (branch.from_var.as_str(), from),
            (branch.value_var.as_str(), value),
        ];
        Self::execute_match_result_branch_lines(&bindings, &branch.lines, line_no, source, context)
            .await
    }

    async fn execute_match_result_branch_lines(
        bindings: &[(&str, CollectionValue)],
        lines: &[Line],
        line_no: usize,
        source: &str,
        context: &Context,
    ) -> Result<CommandResult, String> {
        let mut snapshots = Vec::with_capacity(bindings.len());
        for (var_name, _) in bindings {
            snapshots.push(Self::snapshot_block_var(var_name, context).await?);
        }

        let execute_result: Result<CommandResult, String> = async {
            for (var_name, value) in bindings {
                context
                    .env()
                    .set(var_name, value.clone(), Some(EnvLevel::Block))
                    .await?;
            }

            Self::execute_nested_lines(lines, line_no, context).await
        }
        .await;

        let restore_result = Self::restore_block_vars(&snapshots, context).await;
        match (execute_result, restore_result) {
            (Ok(result), Ok(())) => Ok(result),
            (Err(exec_err), Ok(())) => Err(Self::wrap_runtime_error(
                context,
                ProcessChainErrorCode::RuntimeExpressionExecute,
                "Failed to execute match-result branch",
                Some(line_no),
                Some(source),
                None,
                exec_err,
            )),
            (Ok(_), Err(restore_err)) => Err(Self::wrap_runtime_error(
                context,
                ProcessChainErrorCode::RuntimeExpressionExecute,
                "Failed to restore match-result branch scope",
                Some(line_no),
                Some(source),
                None,
                restore_err,
            )),
            (Err(exec_err), Err(restore_err)) => Err(Self::wrap_runtime_error(
                context,
                ProcessChainErrorCode::RuntimeExpressionExecute,
                "Failed to execute match-result branch and restore scope",
                Some(line_no),
                Some(source),
                None,
                format!("exec_error={}, restore_error={}", exec_err, restore_err),
            )),
        }
    }

    async fn execute_match_result_statement(
        match_result_statement: &MatchResultStatement,
        line_no: usize,
        source: &str,
        context: &Context,
    ) -> Result<CommandResult, String> {
        let result = Self::execute_expression_with_location(
            match_result_statement.command.as_ref(),
            context,
            Some(line_no),
            Some(source.to_string()),
        )
        .await?;

        match result {
            CommandResult::Success(value) => {
                if let Some(branch) = match_result_statement.ok_branch.as_ref() {
                    return Self::execute_match_result_value_branch(
                        branch, value, line_no, source, context,
                    )
                    .await;
                }

                Ok(CommandResult::Success(value))
            }
            CommandResult::Error(value) => {
                if let Some(branch) = match_result_statement.err_branch.as_ref() {
                    return Self::execute_match_result_value_branch(
                        branch, value, line_no, source, context,
                    )
                    .await;
                }

                Ok(CommandResult::Error(value))
            }
            CommandResult::Control(control) => {
                if let Some(branch) = match_result_statement.control_branch.as_ref() {
                    return Self::execute_match_result_control_branch(
                        branch, control, line_no, source, context,
                    )
                    .await;
                }

                Ok(CommandResult::Control(control))
            }
        }
    }

    async fn restore_block_vars(
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

    async fn execute_for_iteration(
        for_statement: &ForStatement,
        line_no: usize,
        context: &Context,
        key: CollectionValue,
        value: Option<CollectionValue>,
    ) -> Result<ForIterationOutcome, String> {
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
            return Ok(ForIterationOutcome::Continue(loop_result));
        }

        let control = loop_result.as_control().unwrap();
        if control.is_break() {
            return Ok(ForIterationOutcome::Break(
                CommandResult::success_with_value(control.value().clone()),
            ));
        }

        Ok(ForIterationOutcome::Propagate(loop_result))
    }

    async fn apply_iteration_outcome_bool(
        state: &ForTraverseStateRef,
        outcome: ForIterationOutcome,
    ) -> Result<bool, String> {
        let mut state = state.lock().await;
        match outcome {
            ForIterationOutcome::Continue(result) => {
                state.result = result;
                Ok(true)
            }
            ForIterationOutcome::Break(result) => {
                state.result = result;
                Ok(false)
            }
            ForIterationOutcome::Propagate(result) => {
                state.terminal = Some(result);
                Ok(false)
            }
        }
    }

    async fn apply_iteration_outcome_control(
        state: &ForTraverseStateRef,
        outcome: ForIterationOutcome,
    ) -> Result<TraverseControl, String> {
        let mut state = state.lock().await;
        match outcome {
            ForIterationOutcome::Continue(result) => {
                state.result = result;
                Ok(TraverseControl::Continue)
            }
            ForIterationOutcome::Break(result) => {
                state.result = result;
                Ok(TraverseControl::Break)
            }
            ForIterationOutcome::Propagate(result) => {
                state.terminal = Some(result);
                Ok(TraverseControl::Break)
            }
        }
    }

    async fn finalize_for_traverse_state(state: &ForTraverseStateRef) -> CommandResult {
        let state = state.lock().await;
        if let Some(result) = state.terminal.as_ref() {
            return result.clone();
        }
        state.result.clone()
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

        snapshots.push(Self::snapshot_block_var(&for_statement.key_var, context).await?);
        if let Some(value_var) = for_statement.value_var.as_ref() {
            snapshots.push(Self::snapshot_block_var(value_var, context).await?);
        }

        let execute_result: Result<CommandResult, String> = async {
            let iterable = for_statement.iterable.evaluate(context).await?;
            let result = match iterable {
                CollectionValue::List(list) => {
                    let state = Arc::new(Mutex::new(ForTraverseState::new()));
                    let callback = Arc::new(Box::new(ForListTraverseCallback {
                        for_statement: for_statement.clone(),
                        line_no,
                        context: context.clone(),
                        state: state.clone(),
                    })
                        as Box<dyn ListCollectionTraverseCallBack>);
                    list.traverse(callback).await?;
                    Self::finalize_for_traverse_state(&state).await
                }
                CollectionValue::Set(set) => {
                    let state = Arc::new(Mutex::new(ForTraverseState::new()));
                    let callback = Arc::new(Box::new(ForSetTraverseCallback {
                        for_statement: for_statement.clone(),
                        line_no,
                        context: context.clone(),
                        state: state.clone(),
                    })
                        as Box<dyn SetCollectionTraverseCallBack>);
                    set.traverse(callback).await?;
                    Self::finalize_for_traverse_state(&state).await
                }
                CollectionValue::Map(map) => {
                    let state = Arc::new(Mutex::new(ForTraverseState::new()));
                    let callback = Arc::new(Box::new(ForMapTraverseCallback {
                        for_statement: for_statement.clone(),
                        line_no,
                        context: context.clone(),
                        state: state.clone(),
                    })
                        as Box<dyn MapCollectionTraverseCallBack>);
                    map.traverse(callback).await?;
                    Self::finalize_for_traverse_state(&state).await
                }
                CollectionValue::MultiMap(multi_map) => {
                    let state = Arc::new(Mutex::new(ForTraverseState::new()));
                    if for_statement.value_var.is_some() {
                        let callback = Arc::new(Box::new(ForMultiMapOwnedTraverseCallback {
                            for_statement: for_statement.clone(),
                            line_no,
                            context: context.clone(),
                            state: state.clone(),
                        })
                            as Box<dyn MultiMapCollectionTraverseOwnedCallBack>);
                        multi_map.traverse_owned(callback).await?;
                    } else {
                        let callback = Arc::new(Box::new(ForMultiMapKeyTraverseCallback {
                            for_statement: for_statement.clone(),
                            line_no,
                            context: context.clone(),
                            state: state.clone(),
                        })
                            as Box<dyn MultiMapCollectionKeyTraverseCallBack>);
                        multi_map.traverse_keys(callback).await?;
                    }
                    Self::finalize_for_traverse_state(&state).await
                }
                other => {
                    let msg = format!(
                        "For-loop iterable must be List/Set/Map/MultiMap, got {}",
                        other.get_type()
                    );
                    return Err(msg);
                }
            };

            Ok(result)
        }
        .await;

        let restore_result = Self::restore_block_vars(&snapshots, context).await;
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
        trace!("Executing command: {:?}", cmd);
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
        trace!("Command executed: {:?}, result: {:?}", cmd, ret);

        Ok(ret)
    }
}
