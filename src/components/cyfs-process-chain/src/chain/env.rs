use std::collections::HashMap;
use std::sync::{Arc, RwLock};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum EnvLevel {
    Global, // Global level environment, used for global settings, used by: export name=value
    Chain,  // Chain level environment, used for chain-wide settings, which is default
    Block,  // Block level environment, used for block-specific settings, use by: local name=value
}

impl Default for EnvLevel {
    fn default() -> Self {
        EnvLevel::Chain // Default to chain level
    }
}

impl EnvLevel {
    pub fn as_str(&self) -> &str {
        match self {
            EnvLevel::Global => "global",
            EnvLevel::Chain => "chain",
            EnvLevel::Block => "block",
        }
    }
}

pub struct Env {
    level: EnvLevel,
    values: RwLock<HashMap<String, String>>,
    parent: Option<EnvRef>,
}

pub type EnvRef = Arc<Env>;

impl Env {
    pub fn new(level: EnvLevel, parent: Option<EnvRef>) -> Self {
        Self {
            level,
            values: RwLock::new(HashMap::new()),
            parent,
        }
    }

    pub fn level(&self) -> EnvLevel {
        self.level
    }

    pub fn parent(&self) -> Option<&EnvRef> {
        self.parent.as_ref()
    }

    pub fn set(&self, key: &str, value: &str) -> Option<String> {
        let mut values = self.values.write().unwrap();
        if let Some(prev) = values.insert(key.to_string(), value.to_string()) {
            info!(
                "Env {} key {} already exists, will be replaced, old value: {}",
                self.level.as_str(), key, prev
            );
            Some(prev)
        } else {
            debug!("Set {} env key {} to value {}", self.level.as_str(), key, value);
            None
        }
    }

    pub fn get(&self, key: &str) -> Option<String> {
        let values = self.values.read().unwrap();
        if let Some(value) = values.get(key) {
            return Some(value.clone());
        }

        if let Some(parent) = &self.parent {
            return parent.get(key);
        }

        None
    }

    pub fn delete(&self, key: &str) -> Option<String> {
        let mut values = self.values.write().unwrap();
        if let Some(prev) = values.remove(key) {
            info!("Env {} key {} removed, old value: {}", self.level.as_str(), key, prev);
            Some(prev)
        } else {
            info!("Env {} key {} not found", self.level.as_str(), key);
            None
        }
    }

    pub fn dump(&self) {
        let values = self.values.read().unwrap();
        info!("Env level: {}", self.level.as_str());
        for (key, value) in values.iter() {
            info!("{}: {}", key, value);
        }
    }
}

#[derive(Clone)]
pub struct EnvManager {
    global: EnvRef,
    chain: EnvRef,
    block: EnvRef,

    // Tracking variables current level
    var_level_tracker: Arc<RwLock<HashMap<String, EnvLevel>>>, 
}

impl EnvManager {
    pub fn new(global_env: EnvRef, chain_env: EnvRef) -> Self {
        assert!(
            global_env.level() == EnvLevel::Global,
            "Global environment must be at global level"
        );
        assert!(
            chain_env.level() == EnvLevel::Chain,
            "Chain environment must be at chain level"
        );

        let block = Arc::new(Env::new(EnvLevel::Block, Some(chain_env.clone())));
        let var_level_tracker = Arc::new(RwLock::new(HashMap::new()));

        Self {
            global: global_env,
            chain: chain_env,
            block,
            var_level_tracker,
        }
    }

    fn get_env(&self, level: EnvLevel) -> &EnvRef {
        match level {
            EnvLevel::Global => &self.global,
            EnvLevel::Chain => &self.chain,
            EnvLevel::Block => &self.block,
        }
    }

    pub fn get_var_level(&self, key: &str) -> EnvLevel {
        let tracker = self.var_level_tracker.read().unwrap();
        tracker.get(key).cloned().unwrap_or_default()
    }

    pub fn change_var_level(&self, key: &str, level: Option<EnvLevel>) {
        let level = level.unwrap_or_default();
        let mut tracker = self.var_level_tracker.write().unwrap();
        match tracker.entry(key.to_string()) {
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                if entry.get() != &level {
                    info!(
                        "Variable '{}' level changed from '{}' to '{}'",
                        key,
                        entry.get().as_str(),
                        level.as_str()
                    );
                    entry.insert(level);
                } else {
                    debug!("Variable '{}' already at level '{}'", key, level.as_str());
                }
            }
            std::collections::hash_map::Entry::Vacant(entry) => {
                if level != EnvLevel::default() {
                    entry.insert(level);
                    info!(
                        "Variable '{}' set to level '{}'",
                        key,
                        level.as_str()
                    );
                }
            }
        }
    }

    /*
    // FIXME: Should we allow moving variables between levels? or just track their level?
    fn move_var_level(&self, key: &str, from: EnvLevel, to: EnvLevel) {
        let from_env = self.get_env(from);
        let value = from_env.delete(key);
        if let Some(value) = value {
            let to_end = self.get_env(to);
            if let Some(prev) = to_end.set(key, &value) {
                info!(
                    "Moved variable '{}' from '{}' to '{}', replaced value: {}",
                    key, from.as_str(), to.as_str(), prev
                );
            } else {
                info!("Moved variable '{}' from '{}' to '{}'", key, from.as_str(), to.as_str());
            }
        } else {
            warn!(
                "Variable '{}' not found in '{}' environment, cannot move to '{}'",
                key, from.as_str(), to.as_str()
            );
        }
    }
    */

    pub fn get_global(&self) -> &EnvRef {
        &self.global
    }

    pub fn get_chain(&self) -> &EnvRef {
        &self.chain
    }

    pub fn get_block(&self) -> &EnvRef {
        &self.block
    }

    // Set a value in the environment, level can be specified or default to chain level
    pub fn set(&self, key: &str, value: &str, level: Option<EnvLevel>) -> Option<String> {
        let level = level.unwrap_or_default();
        let ret = self.set_inner(level, key, value);
        self.change_var_level(key, Some(level));

        ret
    }

    fn set_inner(&self, level: EnvLevel, key: &str, value: &str) -> Option<String> {
        match level {
            EnvLevel::Global => self.global.set(key, value),
            EnvLevel::Chain => self.chain.set(key, value),
            EnvLevel::Block => self.block.set(key, value),
        }
    }

    pub fn get(&self, key: &str, level: Option<EnvLevel>) -> Option<String> {
        let level = match level {
            Some(l) => l,
            None => self.get_var_level(key),
        };

        self.get_inner(level, key)
    }

    fn get_inner(&self, level: EnvLevel, key: &str) -> Option<String> {
        match level {
            EnvLevel::Global => self.global.get(key),
            EnvLevel::Chain => self.chain.get(key),
            EnvLevel::Block => self.block.get(key),
        }
    }

    pub fn delete(&self, key: &str, level: Option<EnvLevel>) -> Option<String> {
        let level = match level {
            Some(l) => l,
            None => self.get_var_level(key),
        };

        self.delete_inner(level, key)
    }

    fn delete_inner(&self, level: EnvLevel, key: &str) -> Option<String> {
        match level {
            EnvLevel::Global => self.global.delete(key),
            EnvLevel::Chain => self.chain.delete(key),
            EnvLevel::Block => self.block.delete(key),
        }
    }

    pub fn dump(&self) {
        self.global.dump();
        self.chain.dump();
        self.block.dump();
    }
}
