use super::cmd::*;
use crate::block::{BlockExecuter, CommandArgs, Expression};
use crate::chain::{Context, EnvLevel, ParserContext};
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
            .allow_hyphen_values(true) // 防止 map/reduce cmd 里出现 --xxx 被解析
            .trailing_var_arg(true) // 允许 reduce cmd 吃掉后面所有参数
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

    fn need_translate_expression(&self) -> bool {
        false
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

    fn parse_without_translate(
        &self,
        _context: &ParserContext,
        args: &CommandArgs,
    ) -> Result<CommandExecutorRef, String> {
        let str_args = args
            .iter()
            .map(|value| value.as_str())
            .collect::<Vec<&str>>();

        let matches = self
            .cmd
            .clone()
            .try_get_matches_from(&str_args)
            .map_err(|e| {
                let msg = format!("Invalid map-reduce command: {}", e);
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

            let map_cmd_index = matches
                .index_of("map_cmd")
                .ok_or_else(|| {
                    let msg = format!(
                        "Map command is required in positional mode, but not provided. Use map <coll> <map_cmd>."
                    );
                    error!("{}", msg);
                    msg
                })?;

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

        Ok(Arc::new(Box::new(cmd) as Box<dyn CommandExecutor>))
    }
}

struct MapReduceCommandInner {
    collection: String,
    begin_cmd: Option<Box<Expression>>,
    map_cmd: Box<Expression>,
    reduce_cmd: Option<Box<Expression>>,
}

type MapReduceCommandInnerRef = Arc<MapReduceCommandInner>;

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
                let cb = CollectionMapReducer::new(self.inner.clone(), context.clone());
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
                let cb = CollectionMapReducer::new(self.inner.clone(), context.clone());
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
                let cb = CollectionMapReducer::new(self.inner.clone(), context.clone());
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
                info!("Map-reduce command returned control flow but not break: {:?}", ctl);
                return Ok(ret);
            }
            
            // If it's a break, we just continue without error
        }

        // Execute reduce command if provided
        let ret = if let Some(reduce_cmd) = &self.inner.reduce_cmd {
            BlockExecuter::execute_expression(reduce_cmd, context).await?
        } else {
            ret
        };

        Ok(ret)
    }
}

struct CollectionMapReducer {
    inner: MapReduceCommandInnerRef,
    context: Context,
    result: Arc<Mutex<Option<CommandResult>>>,
}

impl CollectionMapReducer {
    pub fn new(inner: MapReduceCommandInnerRef, context: Context) -> Self {
        Self {
            inner,
            context,
            result: Arc::new(Mutex::new(Some(CommandResult::success()))),
        }
    }
}

#[async_trait::async_trait]
impl SetCollectionTraverseCallBack for CollectionMapReducer {
    async fn call(&self, key: &str) -> Result<bool, String> {
        self.context
            .env()
            .set(
                "__key",
                CollectionValue::String(key.to_string()),
                Some(EnvLevel::Block),
            )
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
        self.context
            .env()
            .set(
                "__key",
                CollectionValue::String(key.to_string()),
                Some(EnvLevel::Block),
            )
            .await?;
        self.context
            .env()
            .set("__value", value.clone(), Some(EnvLevel::Block))
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
        self.context
            .env()
            .set(
                "__key",
                CollectionValue::String(key.to_string()),
                Some(EnvLevel::Block),
            )
            .await?;
        self.context
            .env()
            .set(
                "__value",
                CollectionValue::String(value.to_string()),
                Some(EnvLevel::Block),
            )
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
