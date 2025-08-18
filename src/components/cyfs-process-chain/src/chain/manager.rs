use super::chain::ProcessChainRef;
use std::{any::Any, sync::{Arc, RwLock}};

#[async_trait::async_trait]
pub trait ProcessChainLib: Any + Send + Sync {
    fn get_id(&self) -> &str;
    fn get_priority(&self) -> i32;

    fn get_chain(&self, id: &str) -> Result<Option<ProcessChainRef>, String>;

    fn get_len(&self) -> Result<usize, String>;
    fn get_chain_by_index(&self, index: usize) -> Result<Option<ProcessChainRef>, String>;
}

pub type ProcessChainLibRef = Arc<Box<dyn ProcessChainLib>>;

pub struct ProcessChainListLib {
    id: String,
    priority: i32,
    chains: Arc<RwLock<Vec<ProcessChainRef>>>,
}

impl ProcessChainListLib {
    pub fn new_empty(id: &str, priority: i32) -> Self {
        Self {
            id: id.to_owned(),
            priority,
            chains: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub fn new(id: &str,  priority: i32, mut chains: Vec<ProcessChainRef>) -> Self {
        // Sort the chains by priority
        chains.sort_by(|a, b| a.priority().cmp(&b.priority()));

        Self {
            id: id.to_owned(),
            priority,
            chains: Arc::new(RwLock::new(chains)),
        }
    }


    pub fn add_chain(&self, chain: ProcessChainRef) -> Result<(), String> {
        let mut chains = self.chains.write().unwrap();
        if chains.iter().any(|c| c.id() == chain.id()) {
            let msg = format!("Process chain with id '{}' already exists", chain.id());
            error!("{}", msg);
            return Err(msg);
        }

        info!("Added process chain with id '{}'", chain.id());
        chains.push(chain);
        
        // Sort the chains by priority
        chains.sort_by(|a, b| a.priority().cmp(&b.priority()));

        Ok(())
    }
}

#[async_trait::async_trait]
impl ProcessChainLib for ProcessChainListLib {
    fn get_id(&self) -> &str {
        &self.id
    }

    fn get_priority(&self) -> i32 {
        self.priority
    }

    fn get_chain(&self, id: &str) -> Result<Option<ProcessChainRef>, String> {
        let chains = self.chains.read().unwrap();
        if let Some(chain) = chains.iter().find(|c| c.id() == id) {
            Ok(Some(chain.clone()))
        } else {
            Err(format!("Process chain with id '{}' not found", id))
        }
    }

    fn get_len(&self) -> Result<usize, String> {
        let chains = self.chains.read().unwrap();
        Ok(chains.len())
    }

    fn get_chain_by_index(&self, index: usize) -> Result<Option<ProcessChainRef>, String> {
        let chains = self.chains.read().unwrap();
        if index < chains.len() {
            Ok(Some(chains[index].clone()))
        } else {
            Err(format!("No process chain found at index {}", index))
        }
    }
}

// Manager for process chain libraries
pub struct ProcessChainManager {
    libs: RwLock<Vec<ProcessChainLibRef>>,
}

impl ProcessChainManager {
    pub fn new() -> Self {
        Self {
            libs: RwLock::new(Vec::new()),
        }
    }

    pub fn add_lib(&self, lib: ProcessChainLibRef) -> Result<(), String> {
        let mut libs = self.libs.write().unwrap();
        if libs.iter().any(|l| l.get_id() == lib.get_id()) {
            let msg = format!("Process chain library with id '{}' already exists", lib.get_id());
            error!("{}", msg);
            return Err(msg);
        }

        info!("Added process chain library with id '{}'", lib.get_id());
        libs.push(lib);

        // Sort the libraries by priority
        libs.sort_by(|a, b| a.get_priority().cmp(&b.get_priority()));

        Ok(())
    }

    pub fn remove_lib(&self, id: &str) -> Result<Option<ProcessChainLibRef>, String> {
        let mut libs = self.libs.write().unwrap();
        if let Some(pos) = libs.iter().position(|l| l.get_id() == id) {
            let lib = libs.remove(pos);
            info!("Removed process chain library with id '{}'", id);
            Ok(Some(lib))
        } else {
            let msg = format!("Process chain library with id '{}' not found", id);
            warn!("{}", msg);
            Ok(None)
        }
    }

    pub fn get_lib(&self, id: &str) -> Option<ProcessChainLibRef> {
        let libs = self.libs.read().unwrap();
        libs.iter().find(|l| l.get_id() == id).cloned()
    }

    pub fn get_chain(&self, id: &str) -> Result<Option<ProcessChainRef>, String> {
        let libs = self.libs.read().unwrap();
        for lib in libs.iter() {
            if let Some(chain) = lib.get_chain(id)? {
                return Ok(Some(chain));
            }
        }

        warn!("Process chain with id '{}' not found in any library", id);
        Ok(None)
    }
}

pub type ProcessChainManagerRef = Arc<ProcessChainManager>;
