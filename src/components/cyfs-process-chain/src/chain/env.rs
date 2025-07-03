use std::collections::HashMap;
use std::sync::{Arc, RwLock};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum EnvLevel {
    Global,
    Chain,
    Block,
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

    pub fn set(&self, key: &str, value: &str) {
        let mut values = self.values.write().unwrap();
        if let Some(prev) = values.insert(key.to_string(), value.to_string()) {
            info!(
                "Env key {} already exists, will be replaced, old value: {}",
                key, prev
            );
        } else {
            debug!("Set env key {} to value {}", key, value);
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
            info!("Env key {} removed, old value: {}", key, prev);
            Some(prev)
        } else {
            info!("Env key {} not found", key);
            None
        }
    }

    pub fn dump(&self) {
        let values = self.values.read().unwrap();
        info!("Env level: {:?}", self.level);
        for (key, value) in values.iter() {
            info!("{}: {}", key, value);
        }
    }
}

pub struct EnvManager {
    global: EnvRef,
    chain: EnvRef,
    block: EnvRef,
}

impl EnvManager {
    pub fn new() -> Self {
        let global = Arc::new(Env::new(EnvLevel::Global, None));
        let chain = Arc::new(Env::new(EnvLevel::Chain, Some(global.clone())));
        let block = Arc::new(Env::new(EnvLevel::Block, Some(chain.clone())));

        Self {
            global,
            chain,
            block,
        }
    }

    pub fn get_global(&self) -> &EnvRef {
        &self.global
    }

    pub fn get_chain(&self) -> &EnvRef {
        &self.chain
    }

    pub fn get_block(&self) -> &EnvRef {
        &self.block
    }

    fn parse_key(key: &str) -> Result<(EnvLevel, &str), String> {
        let parts: Vec<&str> = key.split('.').collect();
        let level = match parts.len() {
            1 => EnvLevel::Block,
            2 => match parts[0].to_ascii_lowercase().as_str() {
                "global" => EnvLevel::Global,
                "chain" => EnvLevel::Chain,
                "block" => EnvLevel::Block,
                _ => {
                    let msg = format!("Invalid env key: {}", key);
                    error!("{}", msg);
                    return Err(msg);
                }
            },
            _ => {
                let msg = format!("Invalid env key: {}", key);
                error!("{}", msg);
                return Err(msg);
            }
        };

        let key = parts[parts.len() - 1];
        Ok((level, key))
    }

    // Key format: level.key, if level not specified, use block level
    pub fn set(&self, key: &str, value: &str) -> Result<(), String> {
        let (level, key) = Self::parse_key(key)?;
        self.set_inner(level, key, value);

        Ok(())
    }

    fn set_inner(&self, level: EnvLevel, key: &str, value: &str) {
        match level {
            EnvLevel::Global => self.global.set(key, value),
            EnvLevel::Chain => self.chain.set(key, value),
            EnvLevel::Block => self.block.set(key, value),
        }
    }

    pub fn get(&self, key: &str) -> Result<Option<String>, String> {
        let (level, key) = Self::parse_key(key)?;

        Ok(self.get_inner(level, key))
    }

    fn get_inner(&self, level: EnvLevel, key: &str) -> Option<String> {
        match level {
            EnvLevel::Global => self.global.get(key),
            EnvLevel::Chain => self.chain.get(key),
            EnvLevel::Block => self.block.get(key),
        }
    }

    pub fn delete(&self, key: &str) -> Result<Option<String>, String> {
        let (level, key) = Self::parse_key(key)?;

        Ok(self.delete_inner(level, key))
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
