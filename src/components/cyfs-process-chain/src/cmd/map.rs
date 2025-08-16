use super::cmd::*;
use crate::block::{BlockExecuter, CommandArgs, Expression};
use crate::chain::{Context, EnvExternal, EnvExternalRef, EnvLevel, ParserContext};
use crate::collection::{
    CollectionValue, MapCollectionTraverseCallBack, MultiMapCollectionTraverseCallBack,
    SetCollectionTraverseCallBack,
};
use clap::{Arg, Command};
use std::sync::{Arc, Mutex};

// map ${collection} $(sub command) reduce $(sub command)
// map ${collection} $(sub command)
// map --begin $(sub command) --map $(sub command) --reduce ${sub command}
pub struct MapReduceCommandParser {
    cmd: Command,
}

impl MapReduceCommandParser {
    pub fn new() -> Self {
        let cmd = Command::new("map")
            .about("Perform a map-reduce operation on a collection.")
            // Long mode args
            .arg(
                Arg::new("begin")
                    .long("begin")
                    .num_args(1)
                    .help("Command to run once before processing (optional long mode only)"),
            )
            .arg(
                Arg::new("map")
                    .long("map")
                    .num_args(1)
                    .help("Map command to run for each element (required in long mode)"),
            )
            .arg(
                Arg::new("reduce")
                    .long("reduce")
                    .num_args(1)
                    .help("Reduce command to aggregate results (optional in long mode)"),
            )
            // positional mode args
            .arg(
                Arg::new("coll")
                    .index(1)
                    .required(false)
                    .help("Collection name (required in positional mode)"),
            )
            .arg(
                Arg::new("map_cmd")
                    .index(2)
                    .required(false)
                    .help("Map command in positional mode (required in positional mode)"),
            )
            .arg(
                Arg::new("reduce_kw")
                    .index(3)
                    .required(false)
                    .help("Keyword 'reduce' in positional mode (optional in positional mode)"),
            )
            .arg(
                Arg::new("reduce_cmd")
                    .index(4)
                    .required(false)
                    .help("Reduce command in positional mode (required if 'reduce' is used)"),
            )
            .override_usage(
                r#"
    map --begin <init-cmd> --cmd <map-cmd> [--reduce <reduce-cmd>] <coll>
    map <coll> <map-cmd> reduce <reduce-cmd>
    map <coll> <map-cmd>
"#,
            )
            .after_help(
                r#"
Options:
Long Mode Options:
    --begin <init-cmd>    Command to run once before processing (long mode only)
    --cmd <map-cmd>       Map command to run for each element (required in long mode)
    --reduce <reduce-cmd> Reduce command to aggregate results (optional in long mode)
    -h, --help            Print help
    <coll>                Collection name (required in both mode)

Positional mode Arguments (positional mode):
    <coll>                Collection name (required in both mode)
    <map_cmd>             Map command (required in positional mode)
    <reduce_kw>           Keyword 'reduce' (optional in positional mode)
    <reduce_cmd>          Reduce command (required if 'reduce' is used)

Examples:
  Long mode:
    map --begin $(local sum = "") --map $($sum = append ${key} sum') --reduce $(echo ${sum}) my_coll
  Positional mode:
    map my_coll $($sum = append ${key} sum') reduce $(echo ${sum})
"#,
            );

        Self { cmd }
    }
}

impl CommandParser for MapReduceCommandParser {
    fn group(&self) -> CommandGroup {
        CommandGroup::MapReduce
    }

    fn help(&self, _name: &str, help_type: CommandHelpType) -> String {
        command_help(help_type, &self.cmd)
    }

    /*
    fn check(&self, args: &CommandArgs) -> Result<(), String> {
        let matches = self
            .cmd
            .clone()
            .try_get_matches_from(args.as_str_list())
            .map_err(|e| {
                let msg = format!("Invalid map-reduce command: {}", e);
                error!("{}", msg);
                msg
            })?;

        // Determine if the command is in long mode or positional mode
        let is_long_mode = matches.contains_id("begin") || matches.contains_id("map");
        if is_long_mode {
            // Check required args for long mode
            if !matches.contains_id("map") {
                let msg = format!(
                    "Map command is required in long mode, but not provided. Use --map <command>."
                );
                error!("{}", msg);
                return Err(msg);
            }

            // Check if <coll> is provided at the end
            if !matches.contains_id("coll") {
                let msg = format!(
                    "Collection name is required in long mode, but not provided. Use <coll> at the end."
                );
                error!("{}", msg);
                return Err(msg);
            }
        } else {
            // Check required args for positional mode
            if !matches.contains_id("coll") || !matches.contains_id("map_cmd") {
                let msg = format!(
                    "Collection name and map command are required in positional mode, but not provided. Use map <coll> <map_cmd>."
                );
                error!("{}", msg);
                return Err(msg);
            }
        }

        Ok(())
    }
    */

    fn parse(
        &self,
        _context: &ParserContext,
        str_args: Vec<&str>,
        args: &CommandArgs,
    ) -> Result<CommandExecutorRef, String> {
        debug!("Parsing map-reduce command: {:?}", args);

        let matches = self
            .cmd
            .clone()
            .try_get_matches_from(&str_args)
            .map_err(|e| {
                let msg = format!("Invalid map-reduce command: {:?}, {}", str_args, e);
                error!("{}", msg);
                msg
            })?;

        // Determine if the command is in long mode or positional mode
        let is_long_mode = matches.contains_id("begin") || matches.contains_id("map");
        let indexes = if is_long_mode {
            let coll_index = matches
                .index_of("coll")
                .ok_or_else(|| {
                    let msg = format!(
                        "Collection name is required in long mode, but not provided. Use <coll> at the end."
                    );
                    error!("{}", msg);
                    msg
                })?;

            // Get arg index, then get it from origin_args
            let begin_cmd_index = matches.index_of("begin");

            let map_cmd_index = matches.index_of("map").ok_or_else(|| {
                let msg = format!(
                    "Map command is required in long mode, but not provided. Use --map <command>."
                );
                error!("{}", msg);
                msg
            })?;

            // If reduce is specified, get its index
            let reduce_cmd_index = matches.index_of("reduce");

            (coll_index, begin_cmd_index, map_cmd_index, reduce_cmd_index)
        } else {
            let coll_index = matches
                .index_of("coll")
                .ok_or_else(|| {
                    let msg = format!(
                        "Collection name is required in positional mode, but not provided. Use map <coll> <map_cmd>."
                    );
                    error!("{}", msg);
                    msg
                })?;
            debug!("Collection index in positional mode: {}", coll_index);
            let map_cmd_index = matches
                .index_of("map_cmd")
                .ok_or_else(|| {
                    let msg = format!(
                        "Map command is required in positional mode, but not provided. Use map <coll> <map_cmd>."
                    );
                    error!("{}", msg);
                    msg
                })?;
            debug!("Map command index in positional mode: {}", map_cmd_index);
            // If reduce is specified, get its index
            let reduce_kw_index = matches.index_of("reduce_kw");
            let reduce_cmd_index = if reduce_kw_index.is_some() {
                let index = matches.index_of("reduce_cmd").ok_or_else(|| {
                    let msg = format!(
                        "Reduce command is required if 'reduce' is used in positional mode."
                    );
                    error!("{}", msg);
                    msg
                })?;
                debug!("Reduce command index in positional mode: {}", index);
                Some(index)
            } else {
                None
            };

            (coll_index, None, map_cmd_index, reduce_cmd_index)
        };

        // Get origin args from indexes
        let coll_var = args.get(indexes.0).ok_or_else(|| {
            let msg = format!("Collection name not found at index {}", indexes.0);
            error!("{}", msg);
            msg
        })?;
        debug!("Collection variable: {}", coll_var.as_str());

        let col = coll_var
            .as_var_str()
            .ok_or_else(|| {
                let msg = format!(
                    "Collection name variable is not a valid string: {}",
                    coll_var.as_str()
                );
                error!("{}", msg);
                msg
            })?
            .to_string();

        let begin_cmd = if let Some(begin_index) = indexes.1 {
            let begin_cmd = args.get(begin_index).ok_or_else(|| {
                let msg = format!("Begin command not found at index {}", begin_index);
                error!("{}", msg);
                msg
            })?;

            if !begin_cmd.is_command_substitution() {
                let msg = format!(
                    "Begin command must be a command substitution, found: {}",
                    begin_cmd.as_str()
                );
                error!("{}", msg);
                return Err(msg);
            }

            Some(begin_cmd.as_command_substitution().unwrap().clone())
        } else {
            None
        };

        let map_cmd = args.get(indexes.2).ok_or_else(|| {
            let msg = format!("Map command not found at index {}", indexes.2);
            error!("{}", msg);
            msg
        })?;
        if !map_cmd.is_command_substitution() {
            let msg = format!(
                "Map command must be a command substitution, found: {}",
                map_cmd.as_str()
            );
            error!("{}", msg);
            return Err(msg);
        }
        debug!("Map command: {}", map_cmd.as_str());
        let map_cmd = map_cmd.as_command_substitution().unwrap().clone();

        let reduce_cmd = if let Some(reduce_cmd_index) = indexes.3 {
            let reduce_cmd = args.get(reduce_cmd_index).ok_or_else(|| {
                let msg = format!("Reduce command not found at index {}", reduce_cmd_index);
                error!("{}", msg);
                msg
            })?;

            if !reduce_cmd.is_command_substitution() {
                let msg = format!(
                    "Reduce command must be a command substitution, found: {}",
                    reduce_cmd.as_str()
                );
                error!("{}", msg);
                return Err(msg);
            }

            Some(reduce_cmd.as_command_substitution().unwrap().clone())
        } else {
            None
        };

        let cmd = MapReduceCommand::new(col, begin_cmd, map_cmd, reduce_cmd);
        debug!("Created MapReduceCommand: {:?}", cmd);
        Ok(Arc::new(Box::new(cmd) as Box<dyn CommandExecutor>))
    }
}

#[derive(Debug)]
struct MapReduceCommandInner {
    collection: String,
    begin_cmd: Option<Box<Expression>>,
    map_cmd: Box<Expression>,
    reduce_cmd: Option<Box<Expression>>,
}

type MapReduceCommandInnerRef = Arc<MapReduceCommandInner>;

const MAP_REDUCE_ENV_ID: &str = "__map_reduce__";
const MAP_REDUCE_ENV_KEY: &str = "__key";
const MAP_REDUCE_ENV_VALUE: &str = "__value";
const MAP_REDUCE_ENV_RESULT: &str = "__result";

#[derive(Debug)]
pub struct MapReduceCommand {
    inner: MapReduceCommandInnerRef,
}

impl MapReduceCommand {
    pub fn new(
        collection: String,
        begin_cmd: Option<Box<Expression>>,
        map_cmd: Box<Expression>,
        reduce_cmd: Option<Box<Expression>>,
    ) -> Self {
        Self {
            inner: Arc::new(MapReduceCommandInner {
                collection,
                begin_cmd,
                map_cmd,
                reduce_cmd,
            }),
        }
    }


    async fn exec_impl(
        &self,
        context: &Context,
        coll: CollectionValue,
        map_reduce_env: &MapReduceVariableEnv,
    ) -> Result<CommandResult, String> {
        // Execute begin command if provided
        if let Some(begin_cmd) = &self.inner.begin_cmd {
            let ret = BlockExecuter::execute_expression(begin_cmd, context).await?;
            if !ret.is_success() {
                let msg = format!("Begin command failed with result: {:?}", ret);
                info!("{}", msg);
                return Ok(ret);
            }
        }

        let ret = match coll {
            CollectionValue::Set(set) => {
                context
                    .env()
                    .change_var_level("__key", Some(crate::EnvLevel::Block));

                let cb = CollectionMapReducer::new(self.inner.clone(), context.clone(), map_reduce_env.clone());
                let ret_item = cb.result.clone();
                set.traverse(Arc::new(
                    Box::new(cb) as Box<dyn SetCollectionTraverseCallBack>
                ))
                .await?;
                let result = ret_item
                    .lock()
                    .unwrap()
                    .take()
                    .unwrap_or(CommandResult::success());
                result
            }
            CollectionValue::Map(map) => {
                context
                    .env()
                    .change_var_level("__key", Some(crate::EnvLevel::Block));
                context
                    .env()
                    .change_var_level("__value", Some(crate::EnvLevel::Block));
                let cb = CollectionMapReducer::new(self.inner.clone(), context.clone(), map_reduce_env.clone());
                let ret_item = cb.result.clone();
                map.traverse(Arc::new(
                    Box::new(cb) as Box<dyn MapCollectionTraverseCallBack>
                ))
                .await?;
                let result = ret_item
                    .lock()
                    .unwrap()
                    .take()
                    .unwrap_or(CommandResult::success());
                result
            }
            CollectionValue::MultiMap(multi_map) => {
                context
                    .env()
                    .change_var_level("__key", Some(crate::EnvLevel::Block));
                context
                    .env()
                    .change_var_level("__value", Some(crate::EnvLevel::Block));
                let cb = CollectionMapReducer::new(self.inner.clone(), context.clone(), map_reduce_env.clone());
                let ret_item = cb.result.clone();
                multi_map
                    .traverse(Arc::new(
                        Box::new(cb) as Box<dyn MultiMapCollectionTraverseCallBack>
                    ))
                    .await?;
                let result = ret_item
                    .lock()
                    .unwrap()
                    .take()
                    .unwrap_or(CommandResult::success());
                result
            }
            _ => {
                let msg = format!(
                    "Unsupported collection type for map-reduce: {}",
                    coll.get_type()
                );
                error!("{}", msg);
                return Err(msg);
            }
        };

        if ret.is_control() {
            let ctl = ret.as_control().unwrap();
            if !ctl.is_break() {
                info!(
                    "Map-reduce command returned control flow but not break: {:?}",
                    ctl
                );
                return Ok(ret);
            }

            // If it's a break, we just continue without error
        }

    
        // Execute reduce command if provided
        let ret = if let Some(reduce_cmd) = &self.inner.reduce_cmd {
            // Update reduce command environment with the result
            let ret_value = ret.into_substitution_value().unwrap_or_default();
            map_reduce_env
                .current_env()
                .set(MAP_REDUCE_ENV_RESULT, CollectionValue::String(ret_value))
                .await?;

            BlockExecuter::execute_expression(reduce_cmd, context).await?
        } else {
            ret
        };

        Ok(ret)
    }
}

#[async_trait::async_trait]
impl CommandExecutor for MapReduceCommand {
    async fn exec(&self, context: &Context) -> Result<CommandResult, String> {
        // Get coll from context
        let coll = context
            .env()
            .get(&self.inner.collection, None)
            .await?
            .ok_or_else(|| {
                let msg = format!(
                    "Collection '{}' not found in context",
                    self.inner.collection
                );
                error!("{}", msg);
                msg
            })?;

        if !coll.is_collection() {
            let msg = format!(
                "Expected a collection for '{}', found: {}",
                self.inner.collection,
                coll.get_type()
            );
            error!("{}", msg);
            return Err(msg);
        }

        // Prepare the environment for map-reduce
        let mut need_remove = false;
        let map_reduce_env = match context
            .env()
            .get_env_external(EnvLevel::Block, MAP_REDUCE_ENV_ID)
            .await?
        {
            Some(env) => {
                if let Some(map_reduce_env) = MapReduceVariableEnv::try_from_external(&env) {
                    map_reduce_env.clone()
                } else {
                    let msg = format!("Failed to convert external env to MapReduceVariableEnv");
                    error!("{}", msg);
                    return Err(msg);
                }
            }
            None => {
                // Create a new MapReduceVariableEnv
                let map_reduce_env = MapReduceVariableEnv::new();
                let external_env =
                    Arc::new(Box::new(map_reduce_env.clone()) as Box<dyn EnvExternal>);
                context
                    .env()
                    .add_env_external(EnvLevel::Block, MAP_REDUCE_ENV_ID, external_env)
                    .await
                    .map_err(|e| {
                        let msg = format!("Failed to add MapReduceVariableEnv to block env: {}", e);
                        error!("{}", msg);
                        msg
                    })?;

                need_remove = true;
                map_reduce_env
            }
        };

        // Create a new environment for map-reduce
        map_reduce_env.new_env();

        let ret = self.exec_impl(context, coll, &map_reduce_env).await;

        // Delete the map-reduce environment after execution
        map_reduce_env.pop_env();

        if need_remove {
            context
                .env()
                .remove_env_external(EnvLevel::Block, MAP_REDUCE_ENV_ID)
                .await
                .map_err(|e| {
                    let msg = format!("Failed to remove MapReduceVariableEnv from block env: {}", e);
                    error!("{}", msg);
                    msg
                })?;
        }

        ret
    }
}

struct CollectionMapReducer {
    inner: MapReduceCommandInnerRef,
    context: Context,
    map_reduce_env: MapReduceVariableEnv,
    result: Arc<Mutex<Option<CommandResult>>>,
}

impl CollectionMapReducer {
    pub fn new(
        inner: MapReduceCommandInnerRef,
        context: Context,
        map_reduce_env: MapReduceVariableEnv,
    ) -> Self {
        Self {
            inner,
            context,
            map_reduce_env,
            result: Arc::new(Mutex::new(Some(CommandResult::success()))),
        }
    }
}

#[async_trait::async_trait]
impl SetCollectionTraverseCallBack for CollectionMapReducer {
    async fn call(&self, key: &str) -> Result<bool, String> {
        self.map_reduce_env
            .current_env()
            .set(MAP_REDUCE_ENV_KEY, CollectionValue::String(key.to_string()))
            .await?;

        let ret = BlockExecuter::execute_expression(&self.inner.map_cmd, &self.context).await?;
        let is_continue = if ret.is_control() {
            info!(
                "Map command returned control flow, will stop traversal for key '{}', {:?}",
                key, ret
            );
            false
        } else {
            debug!("Map command return for key '{}', {:?}", key, ret);
            true
        };

        self.result.lock().unwrap().replace(ret);
        Ok(is_continue)
    }
}

#[async_trait::async_trait]
impl MapCollectionTraverseCallBack for CollectionMapReducer {
    async fn call(&self, key: &str, value: &CollectionValue) -> Result<bool, String> {
        // First update the environment with the key and value
        let current_env = self.map_reduce_env.current_env();
        current_env
            .set(MAP_REDUCE_ENV_KEY, CollectionValue::String(key.to_string()))
            .await?;
        current_env
            .set(MAP_REDUCE_ENV_VALUE, value.clone())
            .await?;

        let ret = BlockExecuter::execute_expression(&self.inner.map_cmd, &self.context).await?;
        let is_continue = if ret.is_control() {
            info!(
                "Map command returned control flow, will stop traversal for key '{}': '{}', {:?}",
                key, value, ret
            );
            false
        } else {
            debug!("Map command return for key '{}': '{}'", key, value);
            true
        };

        self.result.lock().unwrap().replace(ret);
        Ok(is_continue)
    }
}

#[async_trait::async_trait]
impl MultiMapCollectionTraverseCallBack for CollectionMapReducer {
    async fn call(&self, key: &str, value: &str) -> Result<bool, String> {
        // First update the environment with the key and value
        let current_env = self.map_reduce_env.current_env();
        current_env
            .set(MAP_REDUCE_ENV_KEY, CollectionValue::String(key.to_string()))
            .await?;
        current_env
            .set(MAP_REDUCE_ENV_VALUE, CollectionValue::String(value.to_string()))
            .await?;

        let ret = BlockExecuter::execute_expression(&self.inner.map_cmd, &self.context).await?;
        let is_continue = if ret.is_control() {
            info!(
                "Map command returned control flow, will stop traversal for key '{}': '{}', {:?}",
                key, value, ret
            );
            false
        } else {
            debug!("Map command return for key '{}': '{}'", key, value);
            true
        };

        self.result.lock().unwrap().replace(ret);
        Ok(is_continue)
    }
}

use crate::chain::{Env, EnvRef};
use std::sync::RwLock;

#[derive(Clone)]
struct MapReduceVariableEnv {
    stack: Arc<RwLock<Vec<EnvRef>>>,
}

impl MapReduceVariableEnv {
    pub fn new() -> Self {
        Self {
            stack: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub fn new_env(&self) {
        let env = Env::new(EnvLevel::Block, None);
        let env = Arc::new(env);

        self.stack.write().unwrap().push(env);
    }

    pub fn pop_env(&self) {
        let mut stack = self.stack.write().unwrap();
        if stack.is_empty() {
            error!("No environment to pop, stack is empty");
            return;
        }

        stack.pop();
    }

    pub fn current_env(&self) -> EnvRef {
        let stack = self.stack.read().unwrap();
        stack.last().unwrap().clone()
    }

    pub fn try_from_external(external: &EnvExternalRef) -> Option<&Self> {
        let boxed_external: &Box<dyn EnvExternal> = external.as_ref();

        let any_external: &dyn std::any::Any = boxed_external.as_ref();
        if let Some(env) = any_external.downcast_ref::<Self>() {
            Some(env)
        } else {
            assert!(
                false,
                "Expected MapReduceVariableEnv, found: {:?}",
                any_external.type_id()
            );
            None
        }
    }
}

#[async_trait::async_trait]
impl EnvExternal for MapReduceVariableEnv {
    async fn contains(&self, key: &str) -> Result<bool, String> {
        self.current_env().contains(key).await
    }

    async fn get(&self, id: &str) -> Result<Option<CollectionValue>, String> {
        let ret = self.current_env().get(id).await?;

        if let Some(value) = &ret {
            debug!(
                "MapReduceEnv variable '{}' found with value: {:?}",
                id, value
            );
        } else {
            debug!("MapReduceEnv variable '{}' not found", id);
        }

        Ok(ret)
    }

    async fn set(
        &self,
        id: &str,
        value: CollectionValue,
    ) -> Result<Option<CollectionValue>, String> {
        let ret = self.current_env().set(id, value.clone()).await?;

        match &ret {
            Some(old_value) => {
                debug!(
                    "MapReduceEnv variable '{}' set to new value: {:?}, prev: {:?}",
                    id, value, old_value
                );
            }
            None => {
                debug!(
                    "MapReduceEnv variable '{}' created with value: {:?}",
                    id, value
                );
            }
        }

        Ok(ret)
    }

    async fn remove(&self, id: &str) -> Result<Option<CollectionValue>, String> {
        let ret = self.current_env().remove(id).await?;

        match &ret {
            Some(old_value) => {
                debug!(
                    "MapReduceEnv variable '{}' removed with value: {:?}",
                    id, old_value
                );
            }
            None => {
                debug!("MapReduceEnv variable '{}' not found to remove", id);
            }
        }

        Ok(ret)
    }
}

#[test]
fn test() {
    let visitor = MapReduceVariableEnv::new();
    let visitor = Arc::new(Box::new(visitor) as Box<dyn EnvExternal>);

    let env = MapReduceVariableEnv::try_from_external(&visitor);
    assert!(env.is_some());
}
