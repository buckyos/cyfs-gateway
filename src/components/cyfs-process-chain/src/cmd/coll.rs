use super::cmd::{CommandExecutor, CommandExecutorRef, CommandParser, CommandResult};
use crate::block::CommandArgs;
use crate::chain::Context;
use std::sync::Arc;

// match_include <var> <collection_id>
// Check if the variable is included in the specified collection
pub struct MatchIncludeCommandParser {}

impl MatchIncludeCommandParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl CommandParser for MatchIncludeCommandParser {
    fn check(&self, args: &CommandArgs) -> Result<(), String> {
        // Args should have exactly two elements
        if args.len() != 2 {
            let msg = format!("Invalid match_include command: {:?}", args);
            error!("{}", msg);
            return Err(msg);
        }

        Ok(())
    }

    fn parse(&self, args: &[&str]) -> Result<CommandExecutorRef, String> {
        assert!(
            args.len() == 2,
            "MatchInclude command should have exactly 2 args"
        );

        let cmd = MatchIncludeCommandExecutor::new(args[0], args[1]);
        Ok(Arc::new(Box::new(cmd)))
    }
}

// MatchIncludeCommandExecutor
pub struct MatchIncludeCommandExecutor {
    pub key: String,
    pub collection_id: String,
}

impl MatchIncludeCommandExecutor {
    pub fn new(key: &str, collection_id: &str) -> Self {
        Self {
            key: key.to_owned(),
            collection_id: collection_id.to_owned(),
        }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for MatchIncludeCommandExecutor {
    async fn exec(&self, context: &Context) -> Result<CommandResult, String> {
        // Get the collection from the context
        let contains = context
            .collection_manager()
            .is_include_key(&self.collection_id, &self.key)
            .await?;

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
}

/// set_create <set_id>
/// Create a new set collection with the given id.
pub struct SetCreateCommandParser {}

impl SetCreateCommandParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl CommandParser for SetCreateCommandParser {
    fn check(&self, args: &CommandArgs) -> Result<(), String> {
        // Args should have exactly one element
        if args.len() != 1 {
            let msg = format!("Invalid set_create command: {:?}", args);
            error!("{}", msg);
            return Err(msg);
        }

        Ok(())
    }

    fn parse(&self, args: &[&str]) -> Result<CommandExecutorRef, String> {
        assert!(
            args.len() == 1,
            "SetCreate command should have exactly 1 arg"
        );

        let cmd = SetCreateCommandExecutor::new(args[0]);
        Ok(Arc::new(Box::new(cmd)))
    }
}

// SetCreateCommandExecutor
pub struct SetCreateCommandExecutor {
    pub set_id: String,
}

impl SetCreateCommandExecutor {
    pub fn new(set_id: &str) -> Self {
        Self {
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
            .create_set_collection(&self.set_id)
            .await
        {
            Some(_) => {
                info!(
                    "Set collection with id '{}' created successfully",
                    self.set_id
                );
                Ok(CommandResult::success())
            }
            None => {
                let msg = format!("Failed to create set collection with id '{}'", self.set_id);
                warn!("{}", msg);
                Ok(CommandResult::error_with_value(msg))
            }
        }
    }
}

/// set_add <set_id> <value>
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
            let msg = format!("Invalid set_add command: {:?}", args);
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

/// map create <map_id>
/// Create a new map collection with the given id.
/// If the map already exists, it will fail
pub struct MapCreateCommandParser {}

impl MapCreateCommandParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl CommandParser for MapCreateCommandParser {
    fn check(&self, args: &CommandArgs) -> Result<(), String> {
        // Args should have exactly one element
        if args.len() != 1 {
            let msg = format!("Invalid map_create command: {:?}", args);
            error!("{}", msg);
            return Err(msg);
        }

        Ok(())
    }

    fn parse(&self, args: &[&str]) -> Result<CommandExecutorRef, String> {
        assert!(
            args.len() == 1,
            "MapCreate command should have exactly 1 arg"
        );

        let cmd = MapCreateCommandExecutor::new(args[0]);
        Ok(Arc::new(Box::new(cmd)))
    }
}

// MapCreateCommandExecutor
pub struct MapCreateCommandExecutor {
    pub map_id: String,
}

impl MapCreateCommandExecutor {
    pub fn new(map_id: &str) -> Self {
        Self {
            map_id: map_id.to_owned(),
        }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for MapCreateCommandExecutor {
    async fn exec(&self, context: &Context) -> Result<CommandResult, String> {
        // Create a new map collection with the given id
        match context
            .collection_manager()
            .create_map_collection(&self.map_id)
            .await
        {
            Some(_) => {
                info!(
                    "Map collection with id '{}' created successfully",
                    self.map_id
                );
                Ok(CommandResult::success())
            }
            None => {
                let msg = format!("Failed to create map collection with id '{}'", self.map_id);
                warn!("{}", msg);
                Ok(CommandResult::error_with_value(msg))
            }
        }
    }
}

/// map_add <map_id> <key> <value>
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
        // Args should have exactly three elements
        if args.len() != 3 {
            let msg = format!("Invalid map_add command: {:?}", args);
            error!("{}", msg);
            return Err(msg);
        }

        Ok(())
    }

    fn parse(&self, args: &[&str]) -> Result<CommandExecutorRef, String> {
        assert!(args.len() == 3, "MapAdd command should have exactly 3 args");

        let cmd = MapAddCommandExecutor::new(args[0], args[1], args[2]);
        Ok(Arc::new(Box::new(cmd)))
    }
}

// MapAddCommandExecutor
pub struct MapAddCommandExecutor {
    pub map_id: String,
    pub key: String,
    pub value: String,
}

impl MapAddCommandExecutor {
    pub fn new(map_id: &str, key: &str, value: &str) -> Self {
        Self {
            map_id: map_id.to_owned(),
            key: key.to_owned(),
            value: value.to_owned(),
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

        let collection = ret.unwrap();
        match collection.insert(&self.key, &self.value).await? {
            None => {
                info!(
                    "Key '{}' with value '{}' added to map collection with id '{}'",
                    self.key, self.value, self.map_id
                );
                Ok(CommandResult::success())
            }
            Some(prev) => {
                info!(
                    "Key '{}' updated from value '{}' to '{}' in map collection with id '{}'",
                    self.key, prev, self.value, self.map_id
                );
                Ok(CommandResult::success())
            }
        }
    }
}

/// map_remove <map_id> <key>
/// Remove a key from the specified map collection.
pub struct MapRemoveCommandParser {}

impl MapRemoveCommandParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl CommandParser for MapRemoveCommandParser {
    fn check(&self, args: &CommandArgs) -> Result<(), String> {
        // Args should have exactly two elements
        if args.len() != 2 {
            let msg = format!("Invalid map_remove command: {:?}", args);
            error!("{}", msg);
            return Err(msg);
        }

        Ok(())
    }

    fn parse(&self, args: &[&str]) -> Result<CommandExecutorRef, String> {
        assert!(
            args.len() == 2,
            "MapRemove command should have exactly 2 args"
        );

        let cmd = MapRemoveCommandExecutor::new(args[0], args[1]);
        Ok(Arc::new(Box::new(cmd)))
    }
}

// MapRemoveCommandExecutor
pub struct MapRemoveCommandExecutor {
    pub map_id: String,
    pub key: String,
}

impl MapRemoveCommandExecutor {
    pub fn new(map_id: &str, key: &str) -> Self {
        Self {
            map_id: map_id.to_owned(),
            key: key.to_owned(),
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

        let collection = ret.unwrap();
        match collection.remove(&self.key).await? {
            Some(value) => {
                info!(
                    "Key '{}' removed from map collection with id '{}': {}",
                    self.key, self.map_id, value
                );
                Ok(CommandResult::success_with_value(value))
            }
            None => {
                info!(
                    "Key '{}' not found in map collection with id '{}'",
                    self.key, self.map_id
                );
                Ok(CommandResult::success())
            }
        }
    }
}


/// map-get <map_id> <key>
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
            let msg = format!("Invalid map_get command: {:?}", args);
            error!("{}", msg);
            return Err(msg);
        }

        Ok(())
    }

    fn parse(&self, args: &[&str]) -> Result<CommandExecutorRef, String> {
        assert!(args.len() == 2, "map-get command should have exactly 2 args");

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

        let collection = ret.unwrap();
        match collection.get(&self.key).await? {
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
                Ok(CommandResult::error())
            }
        }
    }
}

