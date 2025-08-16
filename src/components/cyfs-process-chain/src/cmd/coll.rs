use super::cmd::*;
use crate::block::{CommandArg, CommandArgs};
use crate::chain::{Context, EnvLevel, ParserContext};
use crate::collection::{CollectionType, CollectionValue};
use clap::{Arg, Command};
use std::sync::Arc;

/*
// Map collection commands support both normal map and multi map.
match-include map_id key	// for normal map
match-include map_id key value1	// for normal map or multi map
match-include map_id key value1 value2 // for multi map

map-create [-multi] [-global] map_id

map-add map_id key value	// for normal map, accept only one value
map-add map_id key value1 value2	// for multi map, accept multi value at one call
map-remove map_id key // for normal map
map-remove map_id key value	// for multi map

echo $map_id.key	// for both map, visit value or value collection
*/

// match-include <collection_id> <var> // for normal set/map or multi map

// Check if the variable is included in the specified collection
pub struct MatchIncludeCommandParser {
    cmd: Command,
}

impl MatchIncludeCommandParser {
    pub fn new() -> Self {
        let cmd = Command::new("match-include")
            .about("Match keys or key-value pairs within a collection.")
            .after_help(
                r#"
Match inclusion of a key or key-value(s) in a target collection.
This command supports set, map, and multi-map collection types.

Behavior:
    - match-include <collection> <key>
        Succeeds if <key> exists in a set or map or multi-map collection.

    - match-include <collection> <key> <value>
        Succeeds if the map or multi-map contains the exact (key, value) pair.

    - match-include <collection> <key> <value1> <value2> ...
        For multi-map: succeeds only if ALL (key, valueN) pairs exist in the collection.

Notes:
    - If the target collection does not exist, the match fails.
    - Only exact matches are supported. Glob or regex patterns are NOT supported.
    - Values must be listed as separate arguments (not as a single list).

Examples:
    match-include $test.coll "test_value"
    match-include $HOST $REQ_host "www.test.com" && drop
    match-include $IP $REQ_ip "127.0.0.1" "192.168.100.1" && accept
"#,
            )
            .arg(
                Arg::new("collection")
                    .help("Target collection variable name or collection id")
                    .required(true)
                    .value_name("collection"),
            )
            .arg(
                Arg::new("key")
                    .help("Key to match in the collection")
                    .required(true)
                    .value_name("key"),
            )
            .arg(
                Arg::new("values")
                    .help("One or more values to match with the key")
                    .value_name("value")
                    .num_args(0..)
                    .required(false),
            );

        Self { cmd }
    }
}

impl CommandParser for MatchIncludeCommandParser {
    fn group(&self) -> CommandGroup {
        CommandGroup::Collection
    }

    fn help(&self, _name: &str, help_type: CommandHelpType) -> String {
        command_help(help_type, &self.cmd)
    }

    fn parse(
        &self,
        _context: &ParserContext,
        str_args: Vec<&str>,
        args: &CommandArgs,
    ) -> Result<CommandExecutorRef, String> {
        let matches = self
            .cmd
            .clone()
            .try_get_matches_from(&str_args)
            .map_err(|e| {
                let msg = format!("Invalid match-include command: {:?}, {}", str_args, e);
                error!("{}", msg);
                msg
            })?;

        let collection_index = matches.index_of("collection").ok_or_else(|| {
            let msg = "Collection argument is required for match-include command".to_string();
            error!("{}", msg);
            msg
        })?;
        let collection = args[collection_index].clone();

        let key_index = matches.index_of("key").ok_or_else(|| {
            let msg = "Key argument is required for match-include command".to_string();
            error!("{}", msg);
            msg
        })?;
        let key = args[key_index].clone();

        let values = match matches.indices_of("values") {
            Some(indices) => indices.map(|i| args[i].clone()).collect(),
            None => vec![],
        };

        let cmd = MatchIncludeCommandExecutor::new(collection, key, values);
        Ok(Arc::new(Box::new(cmd)))
    }
}

// MatchIncludeCommandExecutor
struct MatchIncludeCommandExecutor {
    collection: CommandArg,
    key: CommandArg,
    values: Vec<CommandArg>,
}

impl MatchIncludeCommandExecutor {
    pub fn new(collection: CommandArg, key: CommandArg, values: Vec<CommandArg>) -> Self {
        Self {
            collection,
            key,
            values,
        }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for MatchIncludeCommandExecutor {
    async fn exec(&self, context: &Context) -> Result<CommandResult, String> {
        // First evaluate the collection and key arguments
        let collection = self.collection.evaluate(context).await?;
        let key = self.key.evaluate_string(context).await?;
        let values = CommandArg::evaluate_string_list(&self.values, context).await?;

        // Get the collection from the context
        let collection = match collection {
            CollectionValue::String(collection_id) => {
                let ret = context.env().get(&collection_id, None).await?;
                if ret.is_none() {
                    let msg = format!("Collection with id '{:?}' not found", self.collection);
                    warn!("{}", msg);
                    return Ok(CommandResult::error_with_value(msg));
                }
                let coll = ret.unwrap();
                if !coll.is_collection() {
                    let msg = format!(
                        "Expected CollectionValue::Set, CollectionValue::Map or CollectionValue::MultiMap, found {}",
                        coll.get_type(),
                    );
                    warn!("{}", msg);
                    return Err(msg);
                }

                coll
            }
            CollectionValue::Set(_) | CollectionValue::Map(_) | CollectionValue::MultiMap(_) => {
                collection
            }
            CollectionValue::Visitor(_) | CollectionValue::Any(_) => {
                let msg = "Collection cannot be a visitor or any type for match-include command"
                    .to_string();
                warn!("{}", msg);
                return Err(msg);
            }
        };

        match collection {
            CollectionValue::Set(collection) => {
                // For set collection, we check if the key is included
                let contains = collection.contains(&key).await?;
                info!(
                    "MatchInclude command: key='{}', collection='{:?}', contains={}",
                    key, self.collection, contains
                );
                if contains {
                    Ok(CommandResult::success_with_value("true"))
                } else {
                    Ok(CommandResult::error_with_value("false"))
                }
            }
            CollectionValue::Map(collection) => {
                // For map collection, we check if the key exists and matches the value
                let value = collection.get(&key).await?;
                if let Some(value) = value {
                    if values.is_empty() {
                        info!(
                            "MatchInclude command: key='{}', collection='{:?}', value='{}' found",
                            key, self.collection, value
                        );
                        return Ok(CommandResult::success_with_value("true"));
                    } else {
                        if values.len() > 1 {
                            warn!(
                                "match-include command for map with id '{:?}' expects at most one value, got {}",
                                self.collection,
                                self.values.len()
                            );
                        }

                        // Only check if the first value matches
                        match value {
                            CollectionValue::String(ref v) => {
                                if values[0] == *v {
                                    info!(
                                        "match-include command: key='{}', collection='{:?}', value='{}' found",
                                        key, self.collection, v
                                    );
                                    return Ok(CommandResult::success_with_value("true"));
                                } else {
                                    // value is string but not match
                                }
                            }
                            _ => {
                                warn!(
                                    "match-include command: value is not string! key='{}', collection='{:?}', value_type='{}'",
                                    key,
                                    self.collection,
                                    value.get_type()
                                );
                            }
                        }
                    }
                }

                info!(
                    "match-include command: key='{}', collection='{:?}', no matching key or value found",
                    key, self.collection
                );

                Ok(CommandResult::error_with_value("false"))
            }

            CollectionValue::MultiMap(collection) => {
                // For multi-map collection, we check if the key exists and matches all of the values
                let ret = if values.is_empty() {
                    collection.contains_key(&key).await?
                } else {
                    let values = values.iter().map(|v| v.as_str()).collect::<Vec<&str>>();
                    collection.contains_value(&key, &values).await?
                };

                if ret {
                    info!(
                        "MatchInclude command: key='{}', collection='{:?}' exists",
                        key, self.collection
                    );

                    Ok(CommandResult::success_with_value("true"))
                } else {
                    info!(
                        "MatchInclude command: key='{}', collection='{:?}' does not exist",
                        key, self.collection
                    );

                    Ok(CommandResult::error_with_value("false"))
                }
            }

            _ => {
                unreachable!(
                    "Collection type should be Set, Map or MultiMap, found {}",
                    collection.get_type()
                );
            }
        }
    }
}

/// set-create [-global|-chain|-block] <set_id>
/// Create a new set collection with the given id.
pub struct SetCreateCommandParser {
    cmd: Command,
}

impl SetCreateCommandParser {
    pub fn new() -> Self {
        let cmd = Command::new("set-create")
            .about("Create a new set collection with a given identifier and scope.")
            .after_help(
                r#"
Arguments:
  <set_id>    The identifier of the set collection to create.

Scope Options:
  -global, -export    Create the set in the global scope.
  -chain              Create the set in the current process chain scope (default).
  -block, -local      Create the set in the current execution block (local) scope.

Notes:
  - If no scope is specified, the default is chain-level.
  - A set is a collection of unique string items.
  - Sets can later be queried using match-include or modified using set-add/set-remove.

Examples:
  set-create -global trusted_hosts
  set-create -export trusted_hosts
  set-create session_flags
  set-create -block temp_set
  set-create -local temp_set
"#,
            )
            .arg(
                Arg::new("global")
                    .long("global")
                    .visible_alias("export")
                    .action(clap::ArgAction::SetTrue)
                    .conflicts_with_all(&["chain", "block"])
                    .help("Use global scope"),
            )
            .arg(
                Arg::new("chain")
                    .long("chain")
                    .action(clap::ArgAction::SetTrue)
                    .conflicts_with_all(&["global", "block"])
                    .help("Use chain scope (default)"),
            )
            .arg(
                Arg::new("block")
                    .visible_alias("local")
                    .long("block")
                    .action(clap::ArgAction::SetTrue)
                    .conflicts_with_all(&["global", "chain"])
                    .help("Use block scope"),
            )
            .arg(
                Arg::new("set_id")
                    .required(true)
                    .value_name("set_id")
                    .help("The ID of the set to create"),
            );

        Self { cmd }
    }
}

impl CommandParser for SetCreateCommandParser {
    fn group(&self) -> CommandGroup {
        CommandGroup::Collection
    }

    fn help(&self, _name: &str, help_type: CommandHelpType) -> String {
        command_help(help_type, &self.cmd)
    }

    fn parse(
        &self,
        _context: &ParserContext,
        str_args: Vec<&str>,
        args: &CommandArgs,
    ) -> Result<CommandExecutorRef, String> {
        let matches = self
            .cmd
            .clone()
            .try_get_matches_from(&str_args)
            .map_err(|e| {
                let msg = format!("Invalid set-create command: {:?}, {}", str_args, e);
                error!("{}", msg);
                msg
            })?;

        let level = if matches.get_flag("global") {
            EnvLevel::Global
        } else if matches.get_flag("block") {
            EnvLevel::Block
        } else {
            EnvLevel::Chain // Default to chain level
        };

        // Get the set_id from the matches
        let set_index = matches.index_of("set_id").ok_or_else(|| {
            let msg = "set_id argument is required for set-create command".to_string();
            error!("{}", msg);
            msg
        })?;
        let set_id = args[set_index].clone();

        let cmd = SetCreateCommandExecutor::new(level, set_id);
        Ok(Arc::new(Box::new(cmd)))
    }
}

// SetCreateCommandExecutor
pub struct SetCreateCommandExecutor {
    level: EnvLevel, // Chain or Global
    set_id: CommandArg,
}

impl SetCreateCommandExecutor {
    pub fn new(level: EnvLevel, set_id: CommandArg) -> Self {
        Self { level, set_id }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for SetCreateCommandExecutor {
    async fn exec(&self, context: &Context) -> Result<CommandResult, String> {
        // Evaluate the set_id argument
        let set_id = self.set_id.evaluate_string(context).await?;

        // Create a new set collection with the given id
        match context
            .env()
            .create_collection(&set_id, CollectionType::Set, self.level)
            .await?
        {
            Some(_) => {
                info!(
                    "Set collection with id '{:?}' {:?} created successfully",
                    self.set_id, self.level
                );
                Ok(CommandResult::success())
            }
            None => {
                let msg = format!(
                    "Failed to create set collection with id '{:?}' {:?}",
                    self.set_id, self.level
                );
                warn!("{}", msg);
                Ok(CommandResult::error_with_value(msg))
            }
        }
    }
}

/// set-add <set_id> <value>
/// Add a value to the specified set collection.
/// If the value not exists, it will be added and the command will succeed.
/// If the value already exists, the command will fail.
pub struct SetAddCommandParser {
    cmd: Command,
}

impl SetAddCommandParser {
    pub fn new() -> Self {
        let cmd = Command::new("set-add")
            .about("Add a value to a set collection.")
            .after_help(
                r#"
Arguments:
  <set_id>    The identifier of the target set.
  <value>     The value to insert into the set.

Notes:
  - If the set does not exist, the operation fails.
  - Sets only store unique values.
  - Use `set-create` to initialize a set before using this command.

Examples:
  set-add trusted_hosts "192.168.1.1"
  set-add temp_set "flag_enabled"
"#,
            )
            .arg(
                Arg::new("set_id")
                    .required(true)
                    .value_name("set_id")
                    .help("The ID of the target set"),
            )
            .arg(
                Arg::new("value")
                    .required(true)
                    .value_name("value")
                    .help("The value to insert into the set"),
            );

        Self { cmd }
    }
}

impl CommandParser for SetAddCommandParser {
    fn group(&self) -> CommandGroup {
        CommandGroup::Collection
    }

    fn help(&self, _name: &str, help_type: CommandHelpType) -> String {
        command_help(help_type, &self.cmd)
    }

    fn parse(
        &self,
        _context: &ParserContext,
        str_args: Vec<&str>,
        args: &CommandArgs,
    ) -> Result<CommandExecutorRef, String> {
        let matches = self
            .cmd
            .clone()
            .try_get_matches_from(&str_args)
            .map_err(|e| {
                let msg = format!("Invalid set-add command: {:?}, {}", args, e);
                error!("{}", msg);
                msg
            })?;

        let set_index = matches.index_of("set_id").ok_or_else(|| {
            let msg = "set_id argument is required for set-add command".to_string();
            error!("{}", msg);
            msg
        })?;
        let set = args[set_index].clone();

        let value_index = matches.index_of("value").ok_or_else(|| {
            let msg = "value argument is required for set-add command".to_string();
            error!("{}", msg);
            msg
        })?;
        let value = args[value_index].clone();

        let cmd = SetAddCommandExecutor::new(set, value);
        Ok(Arc::new(Box::new(cmd)))
    }
}

// SetAddCommandExecutor
pub struct SetAddCommandExecutor {
    pub set: CommandArg,
    pub value: CommandArg,
}

impl SetAddCommandExecutor {
    pub fn new(set: CommandArg, value: CommandArg) -> Self {
        Self { set, value }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for SetAddCommandExecutor {
    async fn exec(&self, context: &Context) -> Result<CommandResult, String> {
        let set = self.set.evaluate(context).await?;
        let value = self.value.evaluate_string(context).await?;

        let set = match set {
            CollectionValue::String(set_id) => {
                let ret = context.env().get(&set_id, None).await?;
                if ret.is_none() {
                    let msg = format!("Set collection with id '{}' not found", set_id);
                    warn!("{}", msg);
                    return Ok(CommandResult::error_with_value(msg));
                }
                let coll = ret.unwrap();
                if !coll.is_set() {
                    let msg = format!("Expected CollectionValue::Set, found {}", coll.get_type());
                    warn!("{}", msg);
                    return Err(msg);
                }

                coll.into_set().unwrap()
            }
            CollectionValue::Set(set) => set,
            _ => {
                let msg = "Collection must be a Set for set-add command".to_string();
                warn!("{}", msg);
                return Err(msg);
            }
        };

        match set.insert(&value).await? {
            true => {
                info!(
                    "Value '{}' added to set collection with id '{:?}'",
                    value, self.set
                );
                Ok(CommandResult::success())
            }
            false => {
                let msg = format!(
                    "Failed to add value '{}' to set collection with id '{:?}'",
                    value, self.set
                );
                warn!("{}", msg);
                Ok(CommandResult::error_with_value(msg))
            }
        }
    }
}

/// set-remove <set_id> <value>
/// Remove a value from the specified set collection.
/// If the value exists, it will be removed and the command will succeed.
/// If the value does not exist, the command will fail.
pub struct SetRemoveCommandParser {
    cmd: Command,
}

impl SetRemoveCommandParser {
    pub fn new() -> Self {
        let cmd = Command::new("set-remove")
            .about("Remove a value from a set collection.")
            .after_help(
                r#"
Arguments:
  <set_id>    The identifier of the target set.
  <value>     The value to remove from the set.

Notes:
  - If the set does not exist, the operation fails.
  - If the value is not in the set, it is ignored.
  - Sets only store unique values.

Examples:
  set-remove trusted_hosts "192.168.1.1"
  set-remove temp_set "flag_enabled"
"#,
            )
            .arg(
                Arg::new("set_id")
                    .required(true)
                    .value_name("set_id")
                    .help("The ID of the set to remove from"),
            )
            .arg(
                Arg::new("value")
                    .required(true)
                    .value_name("value")
                    .help("The value to remove"),
            );

        Self { cmd }
    }
}

impl CommandParser for SetRemoveCommandParser {
    fn group(&self) -> CommandGroup {
        CommandGroup::Collection
    }

    fn help(&self, _name: &str, help_type: CommandHelpType) -> String {
        command_help(help_type, &self.cmd)
    }

    fn parse(
        &self,
        _context: &ParserContext,
        str_args: Vec<&str>,
        args: &CommandArgs,
    ) -> Result<CommandExecutorRef, String> {
        let matches = self
            .cmd
            .clone()
            .try_get_matches_from(&str_args)
            .map_err(|e| {
                let msg = format!("Invalid set-remove command: {:?}, {}", str_args, e);
                error!("{}", msg);
                msg
            })?;

        let set_index = matches.index_of("set_id").ok_or_else(|| {
            let msg = "set_id argument is required for set-remove command".to_string();
            error!("{}", msg);
            msg
        })?;
        let set = args[set_index].clone();

        let value_index = matches.index_of("value").ok_or_else(|| {
            let msg = "value argument is required for set-remove command".to_string();
            error!("{}", msg);
            msg
        })?;
        let value = args[value_index].clone();

        let cmd = SetRemoveCommandExecutor::new(set, value);
        Ok(Arc::new(Box::new(cmd)))
    }
}

// SetRemoveCommandExecutor
pub struct SetRemoveCommandExecutor {
    pub set: CommandArg,
    pub value: CommandArg,
}

impl SetRemoveCommandExecutor {
    pub fn new(set: CommandArg, value: CommandArg) -> Self {
        Self { set, value }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for SetRemoveCommandExecutor {
    async fn exec(&self, context: &Context) -> Result<CommandResult, String> {
        let set = self.set.evaluate(context).await?;
        let value = self.value.evaluate_string(context).await?;

        let set = match set {
            CollectionValue::String(set_id) => {
                let ret = context.env().get(&set_id, None).await?;
                if ret.is_none() {
                    let msg = format!("Set collection with id '{}' not found", set_id);
                    warn!("{}", msg);
                    return Ok(CommandResult::error_with_value(msg));
                }
                let coll = ret.unwrap();
                if !coll.is_set() {
                    let msg = format!("Expected CollectionValue::Set, found {}", coll.get_type());
                    warn!("{}", msg);
                    return Err(msg);
                }

                coll.into_set().unwrap()
            }
            CollectionValue::Set(set) => set,
            _ => {
                let msg = "Collection must be a Set for set-remove command".to_string();
                warn!("{}", msg);
                return Err(msg);
            }
        };

        // Remove the value from the specified set collection
        match set.remove(&value).await? {
            true => {
                info!(
                    "Value '{}' removed from set collection with id '{:?}'",
                    value, self.set
                );
                Ok(CommandResult::success())
            }
            false => {
                let msg = format!(
                    "Failed to remove value '{}' from set collection with id '{:?}'",
                    value, self.set
                );
                warn!("{}", msg);
                Ok(CommandResult::error_with_value(msg))
            }
        }
    }
}

/// map-create [-multi] [-global|-chain|-block] <map_id>
/// Create a new map collection with the given id, default is chain level.
/// If the map already exists, it will fail
pub struct MapCreateCommandParser {
    cmd: Command,
}

impl MapCreateCommandParser {
    pub fn new() -> Self {
        let cmd = Command::new("map-create")
            .about("Create a new map or multimap collection with a given ID and scope.")
            .after_help(
                r#"
Options:
  -multi                Create a multimap (key → multiple values allowed).
  -global, -export      Global scope (same as -global).
  -chain                Process chain scope (default).
  -block, -local        Block-local scope (same as -block).

Notes:
  - If no scope is specified, the default is chain-level.
  - Use -multi to create a multimap instead of a regular map.

Examples:
  map-create trusted_hosts
  map-create -global user_token_map
  map-create -multi -local ip_event_map
"#,
            )
            .arg(
                Arg::new("multi")
                    .long("multi")
                    .short('m')
                    .help("Create a multimap")
                    .action(clap::ArgAction::SetTrue),
            )
            .arg(
                Arg::new("global")
                    .long("global")
                    .visible_alias("export")
                    .conflicts_with_all(&["chain", "block"])
                    .action(clap::ArgAction::SetTrue)
                    .help("Use global scope"),
            )
            .arg(
                Arg::new("chain")
                    .long("chain")
                    .conflicts_with_all(&["global", "block"])
                    .action(clap::ArgAction::SetTrue)
                    .help("Use chain scope (default)"),
            )
            .arg(
                Arg::new("block")
                    .long("block")
                    .visible_alias("local")
                    .conflicts_with_all(&["global", "chain"])
                    .action(clap::ArgAction::SetTrue)
                    .help("Use block scope"),
            )
            .arg(
                Arg::new("map_id")
                    .required(true)
                    .value_name("map_id")
                    .help("The ID of the map/multimap to create"),
            );

        Self { cmd }
    }
}

impl CommandParser for MapCreateCommandParser {
    fn group(&self) -> CommandGroup {
        CommandGroup::Collection
    }

    fn help(&self, _name: &str, help_type: CommandHelpType) -> String {
        command_help(help_type, &self.cmd)
    }

    fn parse(
        &self,
        _context: &ParserContext,
        str_args: Vec<&str>,
        args: &CommandArgs,
    ) -> Result<CommandExecutorRef, String> {
        let matches = self
            .cmd
            .clone()
            .try_get_matches_from(&str_args)
            .map_err(|e| {
                let msg = format!("Invalid map-create command: {:?}, {}", str_args, e);
                error!("{}", msg);
                msg
            })?;

        let is_multi = matches.get_flag("multi");
        let level = if matches.get_flag("global") {
            EnvLevel::Global
        } else if matches.get_flag("block") {
            EnvLevel::Block
        } else {
            EnvLevel::Chain // Default to chain level
        };

        // Get the map_id from the matches
        let map_index = matches.index_of("map_id").ok_or_else(|| {
            let msg = "map_id argument is required for map-create command".to_string();
            error!("{}", msg);
            msg
        })?;
        let map_id = args[map_index].clone();

        let cmd = MapCreateCommandExecutor::new(is_multi, level, map_id);
        Ok(Arc::new(Box::new(cmd)))
    }
}

// MapCreateCommandExecutor
pub struct MapCreateCommandExecutor {
    level: EnvLevel, // Chain or Global
    is_multi: bool,  // Indicates if this is a multi-map
    map_id: CommandArg,
}

impl MapCreateCommandExecutor {
    pub fn new(is_multi: bool, level: EnvLevel, map_id: CommandArg) -> Self {
        Self {
            level,
            is_multi,
            map_id,
        }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for MapCreateCommandExecutor {
    async fn exec(&self, context: &Context) -> Result<CommandResult, String> {
        // Evaluate the map_id argument
        let map_id = self.map_id.evaluate_string(context).await?;

        // Create a new map collection with the given id
        let ret = if self.is_multi {
            context
                .env()
                .create_collection(&map_id, CollectionType::MultiMap, self.level)
                .await
        } else {
            context
                .env()
                .create_collection(&map_id, CollectionType::Map, self.level)
                .await
        }?;

        match ret {
            Some(_) => {
                info!(
                    "Map collection with id '{:?}' multi={} level={:?}, created successfully",
                    self.map_id, self.is_multi, self.level,
                );
                Ok(CommandResult::success())
            }
            None => {
                let msg = format!(
                    "Failed to create map collection with id '{:?}' multi={} level={:?}",
                    self.map_id, self.is_multi, self.level
                );
                warn!("{}", msg);
                Ok(CommandResult::error_with_value(msg))
            }
        }
    }
}

/// map-add <map_id> <key> <value>; // for normal map
/// map-add <map_id> <key> <value1> <value2>; // for multi map
/// Set a key-value pair in the specified map collection.
/// If the key already exists, it will be updated and the command will succeed.
/// If the key does not exist, it will be added and the command will succeed.
pub struct MapAddCommandParser {
    cmd: Command,
}

impl MapAddCommandParser {
    pub fn new() -> Self {
        let cmd = Command::new("map-add")
            .about("Add or update key-value pairs in a map or multimap collection.")
            .after_help(
                r#"
Arguments:
  <map_id>    The identifier of the map or multimap.
  <key>       The key to insert or update.
  <value>...  One or more values to associate with the key.

Notes:
  - For normal maps, only one value is allowed.
  - For multimaps, multiple values are accepted.
  - Use `map-create` to define the collection before adding items.

Examples:
  map-add session_map session123 user1
  map-add multi_ip_map 192.168.0.1 login blocked
"#,
            )
            .arg(
                Arg::new("map_id")
                    .required(true)
                    .help("The ID of the target map collection"),
            )
            .arg(
                Arg::new("key")
                    .required(true)
                    .help("The key to insert or update"),
            )
            .arg(
                Arg::new("values")
                    .required(true)
                    .num_args(1..)
                    .help("One or more values to associate with the key"),
            );

        Self { cmd }
    }
}

impl CommandParser for MapAddCommandParser {
    fn group(&self) -> CommandGroup {
        CommandGroup::Collection
    }

    fn help(&self, _name: &str, help_type: CommandHelpType) -> String {
        command_help(help_type, &self.cmd)
    }

    fn parse(
        &self,
        _context: &ParserContext,
        str_args: Vec<&str>,
        args: &CommandArgs,
    ) -> Result<CommandExecutorRef, String> {
        let matches = self
            .cmd
            .clone()
            .try_get_matches_from(&str_args)
            .map_err(|e| {
                let msg = format!("Invalid map-add command: {:?}, {}", str_args, e);
                error!("{}", msg);
                msg
            })?;

        let map_index = matches.index_of("map_id").ok_or_else(|| {
            let msg = "map_id argument is required for map-add command".to_string();
            error!("{}", msg);
            msg
        })?;
        let map = args[map_index].clone();

        let key_index = matches.index_of("key").ok_or_else(|| {
            let msg = "key argument is required for map-add command".to_string();
            error!("{}", msg);
            msg
        })?;
        let key = args[key_index].clone();

        let values = match matches.indices_of("values") {
            Some(indices) => indices.map(|i| args[i].clone()).collect(),
            None => {
                let msg = "At least one value is required for map-add command".to_string();
                error!("{}", msg);
                return Err(msg);
            }
        };

        let cmd = MapAddCommandExecutor::new(map, key, values);
        Ok(Arc::new(Box::new(cmd)))
    }
}

// MapAddCommandExecutor
pub struct MapAddCommandExecutor {
    pub map: CommandArg,
    pub key: CommandArg,
    pub value: Vec<CommandArg>,
}

impl MapAddCommandExecutor {
    pub fn new(map: CommandArg, key: CommandArg, value: Vec<CommandArg>) -> Self {
        Self { map, key, value }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for MapAddCommandExecutor {
    async fn exec(&self, context: &Context) -> Result<CommandResult, String> {
        let map = self.map.evaluate(context).await?;
        let key = self.key.evaluate_string(context).await?;
        let values = CommandArg::evaluate_string_list(&self.value, context).await?;

        let map = match map {
            CollectionValue::String(map_id) => {
                let ret = context.env().get(&map_id, None).await?;
                if ret.is_none() {
                    let msg = format!("Map collection with id '{}' not found", map_id);
                    warn!("{}", msg);
                    return Ok(CommandResult::error_with_value(msg));
                }
                let coll = ret.unwrap();
                if !coll.is_map() && !coll.is_multi_map() {
                    let msg = format!(
                        "Expected CollectionValue::Map or CollectionValue::MultiMap, found {}",
                        coll.get_type(),
                    );
                    warn!("{}", msg);
                    return Err(msg);
                }

                coll
            }
            CollectionValue::Map(_) => map,
            CollectionValue::MultiMap(_) => map,
            _ => {
                let msg = "Collection must be a Map or MultiMap for map-add command".to_string();
                warn!("{}", msg);
                return Err(msg);
            }
        };

        // Add the key-value pair to the specified map collection
        match map {
            CollectionValue::Map(collection) => {
                // For normal map, we expect only one value
                if self.value.len() != 1 {
                    warn!(
                        "map-add command for normal map with id '{:?}' expects exactly one value, got {}",
                        self.map,
                        self.value.len()
                    );

                    // FIXME: What should we do if there is more than one value? We now only use the first value
                }

                match collection
                    .insert(&key, CollectionValue::String(values[0].clone()))
                    .await?
                {
                    None => {
                        info!(
                            "Key '{}' with value '{}' added to map collection with id '{:?}'",
                            key, values[0], self.map
                        );
                        Ok(CommandResult::success())
                    }
                    Some(prev) => {
                        info!(
                            "Key '{}' updated from value '{}' to '{}' in map collection with id '{:?}'",
                            key, prev, values[0], self.map
                        );
                        Ok(CommandResult::success())
                    }
                }
            }
            CollectionValue::MultiMap(collection) => {
                let ret = if self.value.len() == 1 {
                    collection.insert(&key, &values[0]).await?
                } else {
                    assert!(
                        values.len() > 1,
                        "map-add command for multi-map with id '{:?}' expects at least one value, got {}",
                        self.map,
                        self.value.len()
                    );

                    let values: Vec<&str> = values.iter().map(|s| s.as_str()).collect();
                    collection.insert_many(&key, &values).await?
                };

                match ret {
                    true => {
                        info!(
                            "Key '{}' with values '{:?}' added to multi-map collection with id '{:?}'",
                            key, values, self.map
                        );
                        Ok(CommandResult::success())
                    }
                    false => {
                        let msg = format!(
                            "Key '{}' with values '{:?}' already exists in multi-map collection with id '{:?}'",
                            key, values, self.map
                        );
                        warn!("{}", msg);
                        Ok(CommandResult::error_with_value(msg))
                    }
                }
            }

            _ => {
                let msg = format!(
                    "Expected CollectionValue::Map or CollectionValue::MultiMap, found {}",
                    map,
                );
                warn!("{}", msg);
                Err(msg)
            }
        }
    }
}

/// map-remove <map_id> <key>; // for normal map and multi map
/// map-remove <map_id> <key> <value>;  // for normal map only, accept only one value
/// map-remove <map_id> <key> <value> <value1> ...;   // for multi map only, accept multi value
/// Remove a key from the specified map collection.
pub struct MapRemoveCommandParser {
    cmd: Command,
}

impl MapRemoveCommandParser {
    pub fn new() -> Self {
        let cmd = Command::new("map-remove")
            .about("Remove a key or key-value pair(s) from a map or multimap collection.")
            .after_help(
                r#"
Usage:
  map-remove <map_id> <key>
  map-remove <map_id> <key> <value>...
  
Arguments:
  <map_id>    ID of the map or multimap.
  <key>       The key to remove or modify.
  <value>...  Optional. One or more values to remove.

Behavior:
  - If only key is provided, remove the whole entry.
  - If values are given:
      - In map: only one value is allowed.
      - In multimap: all values under the key will be removed.

Examples:
  map-remove session_map session123
  map-remove multi_map 127.0.0.1 login_failed blocked
"#,
            )
            .arg(
                Arg::new("map_id")
                    .required(true)
                    .help("The ID of the map or multimap"),
            )
            .arg(
                Arg::new("key")
                    .required(true)
                    .help("The key to remove or update"),
            )
            .arg(
                Arg::new("values")
                    .num_args(0..)
                    .help("Optional value(s) to remove under the key"),
            );

        Self { cmd }
    }
}

impl CommandParser for MapRemoveCommandParser {
    fn group(&self) -> CommandGroup {
        CommandGroup::Collection
    }

    fn help(&self, _name: &str, help_type: CommandHelpType) -> String {
        command_help(help_type, &self.cmd)
    }

    fn parse(
        &self,
        _context: &ParserContext,
        str_args: Vec<&str>,
        args: &CommandArgs,
    ) -> Result<CommandExecutorRef, String> {
        let matches = self
            .cmd
            .clone()
            .try_get_matches_from(&str_args)
            .map_err(|e| {
                let msg = format!("Invalid map-remove command: {:?}, {}", str_args, e);
                error!("{}", msg);
                msg
            })?;

        let map_index = matches.index_of("map_id").ok_or_else(|| {
            let msg = "map_id argument is required for map-remove command".to_string();
            error!("{}", msg);
            msg
        })?;
        let map = args[map_index].clone();

        let key_index = matches.index_of("key").ok_or_else(|| {
            let msg = "key argument is required for map-remove command".to_string();
            error!("{}", msg);
            msg
        })?;
        let key = args[key_index].clone();

        let values = match matches.indices_of("values") {
            Some(indices) => indices.map(|i| args[i].clone()).collect(),
            None => Vec::new(), // No values provided, just remove the key
        };

        let cmd = MapRemoveCommandExecutor::new(map, key, values);
        Ok(Arc::new(Box::new(cmd)))
    }
}

// MapRemoveCommandExecutor
pub struct MapRemoveCommandExecutor {
    map: CommandArg,
    key: CommandArg,
    values: Vec<CommandArg>,
}

impl MapRemoveCommandExecutor {
    pub fn new(map: CommandArg, key: CommandArg, values: Vec<CommandArg>) -> Self {
        Self { map, key, values }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for MapRemoveCommandExecutor {
    async fn exec(&self, context: &Context) -> Result<CommandResult, String> {
        let map = self.map.evaluate(context).await?;
        let key = self.key.evaluate_string(context).await?;
        let values = CommandArg::evaluate_string_list(&self.values, context).await?;

        let map = match map {
            CollectionValue::String(map_id) => {
                let ret = context.env().get(&map_id, None).await?;
                if ret.is_none() {
                    let msg = format!("Map collection with id '{}' not found", map_id);
                    warn!("{}", msg);
                    return Ok(CommandResult::error_with_value(msg));
                }
                let coll = ret.unwrap();
                if !coll.is_map() && !coll.is_multi_map() {
                    let msg = format!(
                        "Expected CollectionValue::Map or CollectionValue::MultiMap, found {}",
                        coll.get_type(),
                    );
                    warn!("{}", msg);
                    return Err(msg);
                }

                coll
            }
            CollectionValue::Map(_) => map,
            CollectionValue::MultiMap(_) => map,
            _ => {
                let msg = "Collection must be a Map or MultiMap for map-remove command".to_string();
                warn!("{}", msg);
                return Err(msg);
            }
        };

        // Remove the key with values from the specified map collection
        match map {
            CollectionValue::Map(collection) => {
                // For normal map, we expect only one value
                if values.len() > 1 {
                    warn!(
                        "map-remove command for normal map with id '{:?}' expects at most one value, got {}",
                        self.map,
                        values.len()
                    );
                }

                match collection.remove(&key).await? {
                    Some(value) => {
                        info!(
                            "Key '{}' removed from map collection with id '{:?}': {}",
                            key, self.map, value,
                        );
                        Ok(CommandResult::success_with_value(value.treat_as_str()))
                    }
                    None => {
                        warn!(
                            "Key '{}' not found in map collection with id '{:?}'",
                            key, self.map,
                        );
                        Ok(CommandResult::error())
                    }
                }
            }
            CollectionValue::MultiMap(collection) => {
                if values.is_empty() {
                    return Ok(CommandResult::error_with_value(
                        "No values provided for multi-map remove".to_string(),
                    ));
                }

                let ret = if values.len() == 0 {
                    match collection.remove_all(&key).await? {
                        Some(ret) => Some(ret.get_all().await?.join(" ")),
                        None => None,
                    }
                } else if values.len() == 1 {
                    let ret = collection.remove(&key, &values[0]).await?;
                    if ret { Some(values[0].clone()) } else { None }
                } else {
                    let values = self
                        .values
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<&str>>();
                    match collection.remove_many(&key, &values).await? {
                        Some(ret) => Some(ret.get_all().await?.join(" ")),
                        None => None,
                    }
                };

                if let Some(value) = ret {
                    info!(
                        "Key '{}' with values '{}' removed from multi-map collection with id '{:?}'",
                        key, value, self.map
                    );
                    Ok(CommandResult::success_with_value(value))
                } else {
                    warn!(
                        "Key '{}' with values '{:?}' not found in multi-map collection with id '{:?}'",
                        key, self.values, self.map
                    );
                    Ok(CommandResult::error())
                }
            }
            _ => {
                let msg = format!(
                    "Expected CollectionValue::Map or CollectionValue::MultiMap, found {}",
                    map,
                );
                warn!("{}", msg);
                Err(msg)
            }
        }
    }
}
