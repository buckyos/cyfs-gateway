use super::cmd::{CommandExecutor, CommandExecutorRef, CommandParser, CommandResult};
use super::helper::CommandArgHelper;
use crate::block::CommandArgs;
use crate::chain::Context;
use crate::collection::{CollectionLevel, CollectionResult, MapCollectionResult};
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

map-get map_id key	// for both map, return value or value collection
*/

// match_include <collection_id> <var> // for normal set/map or multi map

// Check if the variable is included in the specified collection
pub struct MatchIncludeCommandParser {}

impl MatchIncludeCommandParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl CommandParser for MatchIncludeCommandParser {
    fn check(&self, args: &CommandArgs) -> Result<(), String> {
        // Args should have at least two elements
        if args.len() < 2 {
            let msg = format!("Invalid match-include command: {:?}", args);
            error!("{}", msg);
            return Err(msg);
        }

        Ok(())
    }

    fn parse(&self, args: &[&str]) -> Result<CommandExecutorRef, String> {
        assert!(
            args.len() >= 2,
            "match-include command should have at least 2 args"
        );

        let collection_id = args[0];
        let key = args[1];
        let values = if args.len() > 2 {
            // If there are more than 2 args, we treat them as values
            args[2..]
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<String>>()
        } else {
            vec![]
        };
        let cmd = MatchIncludeCommandExecutor::new(collection_id, key, values);
        Ok(Arc::new(Box::new(cmd)))
    }
}

// MatchIncludeCommandExecutor
pub struct MatchIncludeCommandExecutor {
    pub collection_id: String,
    pub key: String,
    pub values: Vec<String>,
}

impl MatchIncludeCommandExecutor {
    pub fn new(collection_id: &str, key: &str, values: Vec<String>) -> Self {
        Self {
            collection_id: collection_id.to_owned(),
            key: key.to_owned(),
            values,
        }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for MatchIncludeCommandExecutor {
    async fn exec(&self, context: &Context) -> Result<CommandResult, String> {
        // Get the collection from the context
        let ret = context
            .collection_manager()
            .get_collection(&self.collection_id)
            .await;
        if ret.is_none() {
            let msg = format!("Collection with id '{}' not found", self.collection_id);
            warn!("{}", msg);
            return Ok(CommandResult::error_with_value(msg));
        }

        match ret.unwrap() {
            CollectionResult::Set(collection) => {
                // For set collection, we check if the key is included
                let contains = collection.contains(&self.key).await?;
                info!(
                    "MatchInclude command: key='{}', collection_id='{}', contains={}",
                    self.key, self.collection_id, contains
                );
                if contains {
                    Ok(CommandResult::success())
                } else {
                    Ok(CommandResult::error())
                }
            }
            CollectionResult::Map(collection) => {
                // For map collection, we check if the key exists and matches the value
                let value = collection.get(&self.key).await?;
                if let Some(value) = value {
                    if self.values.is_empty() {
                        info!(
                            "MatchInclude command: key='{}', collection_id='{}', value='{}' found",
                            self.key, self.collection_id, value
                        );
                        return Ok(CommandResult::success());
                    } else {
                        if self.values.len() > 1 {
                            warn!(
                                "match-include command for map with id '{}' expects at most one value, got {}",
                                self.collection_id,
                                self.values.len()
                            );
                        }

                        // Only check if the first value matches
                        if self.values[0] == value {
                            info!(
                                "MatchInclude command: key='{}', collection_id='{}', value='{}' found",
                                self.key, self.collection_id, value
                            );
                            return Ok(CommandResult::success());
                        }
                    }
                }

                info!(
                    "MatchInclude command: key='{}', collection_id='{}', no matching key or value found",
                    self.key, self.collection_id
                );

                Ok(CommandResult::error())
            }

            CollectionResult::MultiMap(collection) => {
                // For multi-map collection, we check if the key exists and matches any of the values
                let values = collection.get_many(&self.key).await?;
                if let Some(values) = values {
                    if self.values.is_empty() {
                        info!(
                            "MatchInclude command: key='{}', collection_id='{}'",
                            self.key, self.collection_id
                        );

                        return Ok(CommandResult::success());
                    } else {
                        // Check if all values match
                        let mut all_match = false;
                        for value in &self.values {
                            if !values.contains(value).await? {
                                all_match = false;
                                break;
                            } else {
                                all_match = true;
                            }
                        }

                        if all_match {
                            info!(
                                "MatchInclude command: key='{}', collection_id='{}', values match",
                                self.key, self.collection_id
                            );
                            return Ok(CommandResult::success());
                        }
                    }
                }

                info!(
                    "MatchInclude command: key='{}', collection_id='{}', no matching key or values found",
                    self.key, self.collection_id
                );
                Ok(CommandResult::error())
            }
        }
    }
}

/// set-create [-global|-chain] <set_id>
/// Create a new set collection with the given id.
pub struct SetCreateCommandParser {}

impl SetCreateCommandParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl CommandParser for SetCreateCommandParser {
    fn check(&self, args: &CommandArgs) -> Result<(), String> {
        // Args should have at least one element
        if args.len() < 1 {
            let msg = format!("Invalid set-create command: {:?}", args);
            error!("{}", msg);
            return Err(msg);
        }

        // Check options
        if args.len() > 1 {
            CommandArgHelper::check_origin_options(args, &[&["global", "chain"]])?;
        }

        Ok(())
    }

    fn parse(&self, args: &[&str]) -> Result<CommandExecutorRef, String> {
        assert!(
            args.len() >= 1,
            "set-create command should have at least 1 arg"
        );

        // Parse options
        let mut level = CollectionLevel::Chain; // Default to chain level
        if args.len() > 1 {
            let options = CommandArgHelper::parse_options(args, &[&["global", "chain"]])?;
            for option in options {
                if option == "global" {
                    // Set level to Global
                    level = CollectionLevel::Global;
                } else if option == "chain" {
                    // Set level to Chain
                    level = CollectionLevel::Chain;
                } else {
                    let msg = format!("Invalid option '{}' in set-create command", option);
                    error!("{}", msg);
                    return Err(msg);
                }
            }
        }

        let cmd = SetCreateCommandExecutor::new(level, args[0]);
        Ok(Arc::new(Box::new(cmd)))
    }
}

// SetCreateCommandExecutor
pub struct SetCreateCommandExecutor {
    level: CollectionLevel, // Chain or Global
    set_id: String,
}

impl SetCreateCommandExecutor {
    pub fn new(level: CollectionLevel, set_id: &str) -> Self {
        Self {
            level,
            set_id: set_id.to_owned(),
        }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for SetCreateCommandExecutor {
    async fn exec(&self, context: &Context) -> Result<CommandResult, String> {
        // Create a new set collection with the given id
        match context
            .collection_manager()
            .create_set_collection(self.level, &self.set_id)
            .await
        {
            Some(_) => {
                info!(
                    "Set collection with id '{}' {:?} created successfully",
                    self.set_id, self.level
                );
                Ok(CommandResult::success())
            }
            None => {
                let msg = format!(
                    "Failed to create set collection with id '{}' {:?}",
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
pub struct SetAddCommandParser {}

impl SetAddCommandParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl CommandParser for SetAddCommandParser {
    fn check(&self, args: &CommandArgs) -> Result<(), String> {
        // Args should have exactly two elements
        if args.len() != 2 {
            let msg = format!("Invalid set-add command: {:?}", args);
            error!("{}", msg);
            return Err(msg);
        }

        Ok(())
    }

    fn parse(&self, args: &[&str]) -> Result<CommandExecutorRef, String> {
        assert!(args.len() == 2, "SetAdd command should have exactly 2 args");

        let cmd = SetAddCommandExecutor::new(args[0], args[1]);
        Ok(Arc::new(Box::new(cmd)))
    }
}

// SetAddCommandExecutor
pub struct SetAddCommandExecutor {
    pub set_id: String,
    pub value: String,
}

impl SetAddCommandExecutor {
    pub fn new(set_id: &str, value: &str) -> Self {
        Self {
            set_id: set_id.to_owned(),
            value: value.to_owned(),
        }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for SetAddCommandExecutor {
    async fn exec(&self, context: &Context) -> Result<CommandResult, String> {
        // Add the value to the specified set collection
        let ret = context
            .collection_manager()
            .get_set_collection(&self.set_id)
            .await;
        if ret.is_none() {
            let msg = format!("Set collection with id '{}' not found", self.set_id);
            warn!("{}", msg);
            return Ok(CommandResult::error_with_value(msg));
        }

        let collection = ret.unwrap();
        match collection.insert(&self.value).await? {
            true => {
                info!(
                    "Value '{}' added to set collection with id '{}'",
                    self.value, self.set_id
                );
                Ok(CommandResult::success())
            }
            false => {
                let msg = format!(
                    "Failed to add value '{}' to set collection with id '{}'",
                    self.value, self.set_id
                );
                warn!("{}", msg);
                Ok(CommandResult::error_with_value(msg))
            }
        }
    }
}

/// set_remove <set_id> <value>
/// Remove a value from the specified set collection.
/// If the value exists, it will be removed and the command will succeed.
/// If the value does not exist, the command will fail.
pub struct SetRemoveCommandParser {}

impl SetRemoveCommandParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl CommandParser for SetRemoveCommandParser {
    fn check(&self, args: &CommandArgs) -> Result<(), String> {
        // Args should have exactly two elements
        if args.len() != 2 {
            let msg = format!("Invalid set_remove command: {:?}", args);
            error!("{}", msg);
            return Err(msg);
        }

        Ok(())
    }

    fn parse(&self, args: &[&str]) -> Result<CommandExecutorRef, String> {
        assert!(
            args.len() == 2,
            "SetRemove command should have exactly 2 args"
        );

        let cmd = SetRemoveCommandExecutor::new(args[0], args[1]);
        Ok(Arc::new(Box::new(cmd)))
    }
}

// SetRemoveCommandExecutor
pub struct SetRemoveCommandExecutor {
    pub set_id: String,
    pub value: String,
}

impl SetRemoveCommandExecutor {
    pub fn new(set_id: &str, value: &str) -> Self {
        Self {
            set_id: set_id.to_owned(),
            value: value.to_owned(),
        }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for SetRemoveCommandExecutor {
    async fn exec(&self, context: &Context) -> Result<CommandResult, String> {
        // Remove the value from the specified set collection
        let ret = context
            .collection_manager()
            .get_set_collection(&self.set_id)
            .await;
        if ret.is_none() {
            let msg = format!("Set collection with id '{}' not found", self.set_id);
            warn!("{}", msg);
            return Ok(CommandResult::error_with_value(msg));
        }

        let collection = ret.unwrap();
        match collection.remove(&self.value).await? {
            true => {
                info!(
                    "Value '{}' removed from set collection with id '{}'",
                    self.value, self.set_id
                );
                Ok(CommandResult::success())
            }
            false => {
                let msg = format!(
                    "Failed to remove value '{}' from set collection with id '{}'",
                    self.value, self.set_id
                );
                warn!("{}", msg);
                Ok(CommandResult::error_with_value(msg))
            }
        }
    }
}

/// map-create [-multi] [-global|-chain] <map_id>
/// Create a new map collection with the given id, default is chain level.
/// If the map already exists, it will fail
pub struct MapCreateCommandParser {}

impl MapCreateCommandParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl CommandParser for MapCreateCommandParser {
    fn check(&self, args: &CommandArgs) -> Result<(), String> {
        // Args should have exactly one elements
        if args.len() < 1 {
            let msg = format!("Invalid map-create command: {:?}", args);
            error!("{}", msg);
            return Err(msg);
        }

        // If there is options start with "-", it should be "-multi""-global" or "-chain"
        if args.len() > 1 {
            CommandArgHelper::check_origin_options(args, &[&["multi"], &["global", "chain"]])?;
        }

        Ok(())
    }

    fn parse(&self, args: &[&str]) -> Result<CommandExecutorRef, String> {
        assert!(
            args.len() >= 1,
            "map-create command should have at least 1 arg"
        );

        // Parse options
        let mut is_multi = false; // Default to single map
        let mut level = CollectionLevel::Chain; // Default to chain level
        if args.len() > 1 {
            let options =
                CommandArgHelper::parse_options(args, &[&["multi"], &["global", "chain"]])?;
            for option in options {
                if option == "multi" {
                    // Set is_multi to true
                    is_multi = true;
                } else if option == "global" {
                    // Set level to Global
                    level = CollectionLevel::Global;
                } else if option == "chain" {
                    // Set level to Chain
                    level = CollectionLevel::Chain;
                } else {
                    let msg = format!("Invalid option '{}' in map-create command", option);
                    error!("{}", msg);
                    return Err(msg);
                }
            }
        }

        let cmd = MapCreateCommandExecutor::new(
            is_multi,
            level,
            if is_multi { args[1] } else { args[0] },
        );
        Ok(Arc::new(Box::new(cmd)))
    }
}

// MapCreateCommandExecutor
pub struct MapCreateCommandExecutor {
    level: CollectionLevel, // Chain or Global
    is_multi: bool,         // Indicates if this is a multi-map
    map_id: String,
}

impl MapCreateCommandExecutor {
    pub fn new(is_multi: bool, level: CollectionLevel, map_id: &str) -> Self {
        Self {
            level,
            is_multi,
            map_id: map_id.to_owned(),
        }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for MapCreateCommandExecutor {
    async fn exec(&self, context: &Context) -> Result<CommandResult, String> {
        // Create a new map collection with the given id
        let ret = if self.is_multi {
            context
                .collection_manager()
                .create_multi_map_collection(self.level, &self.map_id)
                .await
                .is_some()
        } else {
            context
                .collection_manager()
                .create_map_collection(self.level, &self.map_id)
                .await
                .is_some()
        };

        match ret {
            true => {
                info!(
                    "Map collection with id '{}' multi={} level={:?}, created successfully",
                    self.map_id, self.is_multi, self.level,
                );
                Ok(CommandResult::success())
            }
            false => {
                let msg = format!(
                    "Failed to create map collection with id '{}' multi={} level={:?}",
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
pub struct MapAddCommandParser {}

impl MapAddCommandParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl CommandParser for MapAddCommandParser {
    fn check(&self, args: &CommandArgs) -> Result<(), String> {
        // Args should have at least three elements
        if args.len() < 3 {
            let msg = format!("Invalid map-add command: {:?}", args);
            error!("{}", msg);
            return Err(msg);
        }

        Ok(())
    }

    fn parse(&self, args: &[&str]) -> Result<CommandExecutorRef, String> {
        assert!(
            args.len() >= 3,
            "MapAdd command should have at least 3 args"
        );

        let cmd = MapAddCommandExecutor::new(args[0], args[1], &args[2..]);
        Ok(Arc::new(Box::new(cmd)))
    }
}

// MapAddCommandExecutor
pub struct MapAddCommandExecutor {
    pub map_id: String,
    pub key: String,
    pub value: Vec<String>,
}

impl MapAddCommandExecutor {
    pub fn new(map_id: &str, key: &str, value: &[&str]) -> Self {
        Self {
            map_id: map_id.to_owned(),
            key: key.to_owned(),
            value: value.iter().map(|s| (*s).to_owned()).collect(),
        }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for MapAddCommandExecutor {
    async fn exec(&self, context: &Context) -> Result<CommandResult, String> {
        // Add the key-value pair to the specified map collection
        let ret = context
            .collection_manager()
            .get_map_collection(&self.map_id)
            .await;
        if ret.is_none() {
            let msg = format!("Map collection with id '{}' not found", self.map_id);
            warn!("{}", msg);
            return Ok(CommandResult::error_with_value(msg));
        }

        let ret = ret.unwrap();
        match ret {
            MapCollectionResult::Map(collection) => {
                // For normal map, we expect only one value
                if self.value.len() != 1 {
                    warn!(
                        "map-add command for normal map with id '{}' expects exactly one value, got {}",
                        self.map_id,
                        self.value.len()
                    );

                    // FIXME: What should we do if there is more than one value? We now only use the first value
                }

                match collection.insert(&self.key, &self.value[0]).await? {
                    None => {
                        info!(
                            "Key '{}' with value '{}' added to map collection with id '{}'",
                            self.key, self.value[0], self.map_id
                        );
                        Ok(CommandResult::success())
                    }
                    Some(prev) => {
                        info!(
                            "Key '{}' updated from value '{}' to '{}' in map collection with id '{}'",
                            self.key, prev, self.value[0], self.map_id
                        );
                        Ok(CommandResult::success())
                    }
                }
            }
            MapCollectionResult::MultiMap(collection) => {
                let ret = if self.value.len() == 1 {
                    collection.insert(&self.key, &self.value[0]).await?
                } else {
                    assert!(
                        self.value.len() > 1,
                        "map-add command for multi-map with id '{}' expects at least one value, got {}",
                        self.map_id,
                        self.value.len()
                    );

                    let values: Vec<&str> = self.value.iter().map(|s| s.as_str()).collect();
                    collection.insert_many(&self.key, &values).await?
                };

                match ret {
                    true => {
                        info!(
                            "Key '{}' with values '{:?}' added to multi-map collection with id '{}'",
                            self.key, self.value, self.map_id
                        );
                        Ok(CommandResult::success())
                    }
                    false => {
                        let msg = format!(
                            "Key '{}' with values '{:?}' already exists in multi-map collection with id '{}'",
                            self.key, self.value, self.map_id
                        );
                        warn!("{}", msg);
                        Ok(CommandResult::error_with_value(msg))
                    }
                }
            }
        }
    }
}

/// map-remove <map_id> <key>; // for normal map and multi map
/// map-remove <map_id> <key> value value1;    // for multi map only, accept multi value
/// Remove a key from the specified map collection.
pub struct MapRemoveCommandParser {}

impl MapRemoveCommandParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl CommandParser for MapRemoveCommandParser {
    fn check(&self, args: &CommandArgs) -> Result<(), String> {
        // Args should have at least two elements
        if args.len() < 2 {
            let msg = format!("Invalid map-remove command: {:?}", args);
            error!("{}", msg);
            return Err(msg);
        }

        Ok(())
    }

    fn parse(&self, args: &[&str]) -> Result<CommandExecutorRef, String> {
        assert!(
            args.len() >= 2,
            "map-remove command should have at least 2 args"
        );

        let values = if args.len() > 2 {
            args[2..]
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<String>>()
        } else {
            vec![]
        };

        let cmd = MapRemoveCommandExecutor::new(args[0], args[1], values);
        Ok(Arc::new(Box::new(cmd)))
    }
}

// MapRemoveCommandExecutor
pub struct MapRemoveCommandExecutor {
    map_id: String,
    key: String,
    values: Vec<String>,
}

impl MapRemoveCommandExecutor {
    pub fn new(map_id: &str, key: &str, values: Vec<String>) -> Self {
        Self {
            map_id: map_id.to_owned(),
            key: key.to_owned(),
            values,
        }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for MapRemoveCommandExecutor {
    async fn exec(&self, context: &Context) -> Result<CommandResult, String> {
        // Remove the key from the specified map collection
        let ret = context
            .collection_manager()
            .get_map_collection(&self.map_id)
            .await;
        if ret.is_none() {
            let msg = format!("Map collection with id '{}' not found", self.map_id);
            warn!("{}", msg);
            return Ok(CommandResult::error_with_value(msg));
        }

        let ret = ret.unwrap();
        match ret {
            MapCollectionResult::Map(collection) => {
                // For normal map, we expect only one value
                if self.values.len() > 1 {
                    warn!(
                        "map-remove command for normal map with id '{}' expects at most one value, got {}",
                        self.map_id,
                        self.values.len()
                    );
                }

                match collection.remove(&self.key).await? {
                    Some(value) => {
                        info!(
                            "Key '{}' removed from map collection with id '{}': {}",
                            self.key, self.map_id, value
                        );
                        Ok(CommandResult::success_with_value(value))
                    }
                    None => {
                        warn!(
                            "Key '{}' not found in map collection with id '{}'",
                            self.key, self.map_id
                        );
                        Ok(CommandResult::error())
                    }
                }
            }
            MapCollectionResult::MultiMap(collection) => {
                if self.values.is_empty() {
                    return Ok(CommandResult::error_with_value(
                        "No values provided for multi-map remove".to_string(),
                    ));
                }

                let ret = if self.values.len() == 0 {
                    collection.remove_all(&self.key).await?
                } else if self.values.len() == 1 {
                    collection.remove(&self.key, &self.values[0]).await?
                } else {
                    let values = self
                        .values
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<&str>>();
                    collection.remove_many(&self.key, &values).await?
                };

                if ret {
                    info!(
                        "Key '{}' with values '{:?}' removed from multi-map collection with id '{}'",
                        self.key, self.values, self.map_id
                    );
                    Ok(CommandResult::success())
                } else {
                    warn!(
                        "Key '{}' with values '{:?}' not found in multi-map collection with id '{}'",
                        self.key, self.values, self.map_id
                    );
                    Ok(CommandResult::error())
                }
            }
        }
    }
}

/// map-get <map_id> <key>; // Get the value of a key from the specified map collection. for multi-map, it returns all values join by space
/// Get the value of a key from the specified map collection.
pub struct MapGetCommandParser {}

impl MapGetCommandParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl CommandParser for MapGetCommandParser {
    fn check(&self, args: &CommandArgs) -> Result<(), String> {
        // Args should have exactly two elements
        if args.len() != 2 {
            let msg = format!("Invalid map-get command: {:?}", args);
            error!("{}", msg);
            return Err(msg);
        }

        Ok(())
    }

    fn parse(&self, args: &[&str]) -> Result<CommandExecutorRef, String> {
        assert!(
            args.len() == 2,
            "map-get command should have exactly 2 args"
        );

        let cmd = MapGetCommandExecutor::new(args[0], args[1]);
        Ok(Arc::new(Box::new(cmd)))
    }
}

// MapGetCommandExecutor
pub struct MapGetCommandExecutor {
    pub map_id: String,
    pub key: String,
}

impl MapGetCommandExecutor {
    pub fn new(map_id: &str, key: &str) -> Self {
        Self {
            map_id: map_id.to_owned(),
            key: key.to_owned(),
        }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for MapGetCommandExecutor {
    async fn exec(&self, context: &Context) -> Result<CommandResult, String> {
        // Get the value of the key from the specified map collection
        let ret = context
            .collection_manager()
            .get_map_collection(&self.map_id)
            .await;
        if ret.is_none() {
            let msg = format!("Map collection with id '{}' not found", self.map_id);
            warn!("{}", msg);
            return Ok(CommandResult::error_with_value(msg));
        }

        let ret = ret.unwrap();
        match ret {
            MapCollectionResult::Map(collection) => match collection.get(&self.key).await? {
                Some(value) => {
                    info!(
                        "Key '{}' found in map collection with id '{}': {}",
                        self.key, self.map_id, value
                    );
                    Ok(CommandResult::success_with_value(value))
                }
                None => {
                    warn!(
                        "Key '{}' not found in map collection with id '{}'",
                        self.key, self.map_id
                    );
                    Ok(CommandResult::success_with_value(""))
                }
            },
            MapCollectionResult::MultiMap(collection) => {
                match collection.get_many(&self.key).await? {
                    Some(values) => {
                        let values = values.get_all().await?;
                        if values.is_empty() {
                            warn!(
                                "Key '{}' not found in multi-map collection with id '{}'",
                                self.key, self.map_id
                            );
                            Ok(CommandResult::success_with_value(""))
                        } else {
                            info!(
                                "Key '{}' found in multi-map collection with id '{}': {:?}",
                                self.key, self.map_id, values
                            );

                            let values = values.join(" ");
                            Ok(CommandResult::success_with_value(values))
                        }
                    }
                    None => {
                        warn!(
                            "Key '{}' not found in multi-map collection with id '{}'",
                            self.key, self.map_id
                        );
                        Ok(CommandResult::success_with_value(""))
                    }
                }
            }
        }
    }
}
