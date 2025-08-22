use super::chain::{ParserContextRef, ProcessChain, ProcessChainRef};
use std::{
    any::Any,
    ops::Deref,
    sync::{Arc, RwLock},
};

#[async_trait::async_trait]
pub trait ProcessChainLib: Any + Send + Sync {
    fn get_id(&self) -> &str;
    fn get_priority(&self) -> i32;

    fn get_chain(&self, id: &str) -> Result<Option<ProcessChainRef>, String>;

    fn get_len(&self) -> Result<usize, String>;
    fn get_chain_by_index(&self, index: usize) -> Result<ProcessChainRef, String>;
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

    pub fn new(id: &str, priority: i32, mut chains: Vec<ProcessChainRef>) -> Self {
        // Sort the chains by priority
        chains.sort_by(|a, b| a.priority().cmp(&b.priority()));

        Self {
            id: id.to_owned(),
            priority,
            chains: Arc::new(RwLock::new(chains)),
        }
    }

    pub fn into_process_chain_lib(self) -> ProcessChainLibRef {
        Arc::new(Box::new(self) as Box<dyn ProcessChainLib>)
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
            Ok(None)
        }
    }

    fn get_len(&self) -> Result<usize, String> {
        let chains = self.chains.read().unwrap();
        Ok(chains.len())
    }

    fn get_chain_by_index(&self, index: usize) -> Result<ProcessChainRef, String> {
        let chains = self.chains.read().unwrap();
        if index < chains.len() {
            Ok(chains[index].clone())
        } else {
            let msg = format!("Index {} out of bounds for process chain list", index);
            error!("{}", msg);
            Err(msg)
        }
    }
}

pub struct ProcessChainConstListLib {
    id: String,
    priority: i32,
    chains: Vec<ProcessChainRef>,
}

impl ProcessChainConstListLib {
    pub fn new(id: &str, priority: i32, mut chains: Vec<ProcessChainRef>) -> Self {
        // Sort the chains by priority
        chains.sort_by(|a, b| a.priority().cmp(&b.priority()));

        Self {
            id: id.to_owned(),
            priority,
            chains,
        }
    }

    pub fn new_raw(id: &str, priority: i32, chains: Vec<ProcessChain>) -> Self {
        let mut chains = chains
            .into_iter()
            .map(Arc::new)
            .collect::<Vec<ProcessChainRef>>();
        // Sort the chains by priority
        chains.sort_by(|a, b| a.priority().cmp(&b.priority()));

        Self {
            id: id.to_owned(),
            priority,
            chains,
        }
    }

    pub fn into_process_chain_lib(self) -> ProcessChainLibRef {
        Arc::new(Box::new(self) as Box<dyn ProcessChainLib>)
    }
}

impl ProcessChainLib for ProcessChainConstListLib {
    fn get_id(&self) -> &str {
        &self.id
    }

    fn get_priority(&self) -> i32 {
        self.priority
    }

    fn get_chain(&self, id: &str) -> Result<Option<ProcessChainRef>, String> {
        if let Some(chain) = self.chains.iter().find(|c| c.id() == id) {
            Ok(Some(chain.clone()))
        } else {
            Err(format!("Process chain with id '{}' not found", id))
        }
    }

    fn get_len(&self) -> Result<usize, String> {
        Ok(self.chains.len())
    }

    fn get_chain_by_index(&self, index: usize) -> Result<ProcessChainRef, String> {
        if index < self.chains.len() {
            Ok(self.chains[index].clone())
        } else {
            let msg = format!("Index {} out of bounds for process chain list", index);
            error!("{}", msg);
            Err(msg)
        }
    }
}

struct ProcessChainClonedLib {
    id: String,
    priority: i32,
    chains: Vec<ProcessChain>,
}

pub(crate) struct ProcessChainLinkedLib {
    pub id: String,
    pub priority: i32,
    pub chains: Vec<ProcessChainRef>,
}

impl ProcessChainLinkedLib {
    fn new(lib: ProcessChainClonedLib) -> Self {
        Self {
            id: lib.id,
            priority: lib.priority,
            chains: lib.chains.into_iter().map(Arc::new).collect(),
        }
    }
}

/// Manager for process chain libraries
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
            let msg = format!(
                "Process chain library with id '{}' already exists",
                lib.get_id()
            );
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

    /// Clone all chains from all libraries for linking
    fn clone_chains(&self) -> Result<Vec<ProcessChainClonedLib>, String> {
        let libs = self.libs.read().unwrap();
        let mut result = Vec::with_capacity(libs.len());
        for lib in libs.iter() {
            let len = lib.get_len()?;
            let mut chains = Vec::with_capacity(len);
            for i in 0..len {
                let chain = lib.get_chain_by_index(i)?;
                let chain = chain.as_ref().clone();
                chains.push(chain);
            }

            let ret = ProcessChainClonedLib {
                id: lib.get_id().to_string(),
                priority: lib.get_priority(),
                chains,
            };

            result.push(ret);
        }

        Ok(result)
    }

    pub async fn link(
        &self,
        context: &ParserContextRef,
    ) -> Result<ProcessChainLinkedManagerRef, String> {
        let libs = self.clone_chains()?;
        let mut result = Vec::with_capacity(libs.len());
        for lib in libs {
            info!("Linking process chain library: {}", lib.id);
            let mut linked_chains = Vec::with_capacity(lib.chains.len());
            for mut chain in lib.chains {
                chain.link(context).await?;

                linked_chains.push(Arc::new(chain));
            }

            let linked_lib = ProcessChainConstListLib::new(&lib.id, lib.priority, linked_chains);

            result.push(Arc::new(Box::new(linked_lib) as Box<dyn ProcessChainLib>));
        }

        let manager = ProcessChainLinkedManager::new_with_libs(result);
        Ok(Arc::new(manager))
    }
}

pub type ProcessChainManagerRef = Arc<ProcessChainManager>;

/// A manager for linked process chains, which can be used to execute multiple chains
pub struct ProcessChainLinkedManager {
    libs: Vec<ProcessChainLibRef>,
}

impl ProcessChainLinkedManager {
    pub fn new() -> Self {
        Self { libs: Vec::new() }
    }

    /// Create a new linked manager with the given libraries, the libraries must be linked first
    pub fn new_with_libs(libs: Vec<ProcessChainLibRef>) -> Self {
        Self { libs }
    }

    /// Add a new library to the linked manager, the library must be linked first
    pub fn add_lib(&mut self, lib: ProcessChainLibRef) -> Result<(), String> {
        if self.libs.iter().any(|l| l.get_id() == lib.get_id()) {
            let msg = format!(
                "Process chain library with id '{}' already exists",
                lib.get_id()
            );
            error!("{}", msg);
            return Err(msg);
        }

        info!("Added process chain library with id '{}'", lib.get_id());
        self.libs.push(lib);

        // Sort the libraries by priority
        self.libs
            .sort_by(|a, b| a.get_priority().cmp(&b.get_priority()));

        Ok(())
    }

    pub fn get_lib(&self, id: &str) -> Option<ProcessChainLibRef> {
        self.libs.iter().find(|l| l.get_id() == id).cloned()
    }

    pub fn get_chain(
        &self,
        lib_id: Option<&str>,
        chain_id: &str,
    ) -> Result<Option<(ProcessChainLibRef, ProcessChainRef)>, String> {
        // If a specific library is provided, search only in that library
        if let Some(lib_id) = lib_id {
            if let Some(lib) = self.get_lib(lib_id) {
                match lib.get_chain(chain_id)? {
                    Some(chain) => return Ok(Some((lib, chain))),
                    None => {
                        warn!(
                            "Process chain with id '{}' not found in library '{}'",
                            chain_id, lib_id
                        );
                        return Ok(None);
                    }
                }
            } else {
                let msg = format!("Process chain library with id '{}' not found", lib_id);
                error!("{}", msg);
                return Ok(None);
            }
        }

        // Otherwise, search in all linked libraries
        for lib in &self.libs {
            if let Some(chain) = lib.get_chain(chain_id)? {
                return Ok(Some((lib.clone(), chain)));
            }
        }

        warn!(
            "Process chain with id '{}' not found in any linked library",
            chain_id
        );
        Ok(None)
    }

    pub fn get_block(
        &self,
        lib_id: Option<&str>,
        chain_id: &str,
        block_id: &str,
    ) -> Result<Option<(ProcessChainLibRef, ProcessChainRef)>, String> {

        // If a specific library is provided, search only in that library
        if let Some(lib_id) = lib_id {
            if let Some(lib) = self.get_lib(lib_id) {
                if let Some(chain) = lib.get_chain(chain_id)? {
                    match chain.get_block(block_id) {
                        Some(_block) => return Ok(Some((lib.clone(), chain))),
                        None => {
                            warn!(
                                "Block with id '{}' not found in chain '{}'",
                                block_id, chain_id
                            );
                            return Ok(None);
                        }
                    }
                } else {
                    let msg = format!(
                        "Process chain with id '{}' not found in library '{}'",
                        chain_id, lib_id
                    );
                    error!("{}", msg);
                    return Ok(None);
                }
            } else {
                let msg = format!("Process chain library with id '{}' not found", lib_id);
                error!("{}", msg);
                return Ok(None);
            }
        }

        // Otherwise, search in all linked libraries
        for lib in &self.libs {
            if let Some(chain) = lib.get_chain(chain_id)? {
                match chain.get_block(block_id) {
                    Some(_block) => return Ok(Some((lib.clone(), chain))),
                    None => {
                        warn!(
                            "Block with id '{}' not found in chain '{}'",
                            block_id, chain_id
                        );
                        continue;
                    }
                }
            }
        }

        warn!(
            "Process chain '{}' and block with id '{}' not found in any linked library",
            chain_id, block_id
        );
        Ok(None)
    }
}

impl Deref for ProcessChainLinkedManager {
    type Target = [ProcessChainLibRef];

    fn deref(&self) -> &Self::Target {
        &self.libs
    }
}

pub type ProcessChainLinkedManagerRef = Arc<ProcessChainLinkedManager>;
