use super::env::{Env, EnvLevel};
use crate::chain::{
    EnvManager, EnvRef, ProcessChainLibRef, ProcessChainLinkedManagerRef, ProcessChainRef,
};
use crate::pipe::CommandPipe;
use std::sync::atomic::AtomicU32;
use std::sync::{Arc, RwLock};

pub const MAX_GOTO_COUNT: u32 = 128; // Maximum number of times the goto command can be executed in process chains execution

pub struct GotoCounter {
    pub count: AtomicU32, // The number of times the goto command has been executed
}

impl GotoCounter {
    pub fn new() -> Self {
        Self {
            count: AtomicU32::new(0),
        }
    }

    pub fn increment(&self) -> Result<(), String> {
        let prev = self.count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if prev >= MAX_GOTO_COUNT {
            let msg = format!(
                "Goto command has been executed {} times, exceeding the maximum limit of {}",
                prev + 1,
                MAX_GOTO_COUNT
            );
            error!("{}", msg);
            return Err(msg);
        }

        Ok(())
    }

    pub fn get_count(&self) -> u32 {
        self.count.load(std::sync::atomic::Ordering::SeqCst)
    }
}

pub type GotoCounterRef = Arc<GotoCounter>;

struct ExecPointerInner {
    lib: Option<ProcessChainLibRef>, // The library that this pointer is executing
    chain: Option<ProcessChainRef>,  // The chain that this pointer is executing
    block: Option<String>,           // The block id that this pointer is currently executing
}

#[derive(Clone)]
pub struct ExecPointer {
    inner: Arc<RwLock<ExecPointerInner>>, // The inner state of the execution pointer
}

impl ExecPointer {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(ExecPointerInner {
                lib: None,
                chain: None,
                block: None,
            })),
        }
    }

    pub fn set_lib(&self, lib: ProcessChainLibRef) {
        let mut inner = self.inner.write().unwrap();
        inner.lib = Some(lib);
    }

    pub fn reset_lib(&self) {
        let mut inner = self.inner.write().unwrap();
        inner.lib = None;
    }

    pub fn set_chain(&self, chain: ProcessChainRef) {
        let mut inner = self.inner.write().unwrap();
        inner.chain = Some(chain);
    }

    pub fn reset_chain(&self) {
        let mut inner = self.inner.write().unwrap();
        inner.chain = None;
    }

    pub fn set_block(&self, block: &str) {
        let mut inner = self.inner.write().unwrap();
        inner.block = Some(block.to_string());
    }

    pub fn reset_block(&self) {
        let mut inner = self.inner.write().unwrap();
        inner.block = None;
    }

    pub fn get_lib(&self) -> Option<ProcessChainLibRef> {
        let inner = self.inner.read().unwrap();
        inner.lib.clone()
    }

    pub fn get_chain(&self) -> Option<ProcessChainRef> {
        let inner = self.inner.read().unwrap();
        inner.chain.clone()
    }

    pub fn get_block(&self) -> Option<String> {
        let inner = self.inner.read().unwrap();
        inner.block.clone()
    }

    // Keep the lib and chain, but reset the block
    pub fn fork_block(&self) -> Self {
        // Create a new execution pointer that inherits the current state
        let inner = self.inner.read().unwrap();
        Self {
            inner: Arc::new(RwLock::new(ExecPointerInner {
                lib: inner.lib.clone(),
                chain: inner.chain.clone(),
                block: None,
            })),
        }
    }

    // Keep the lib, but reset the chain and block
    pub fn fork_chain(&self) -> Self {
        // Create a new execution pointer that inherits the current state
        let inner = self.inner.read().unwrap();
        Self {
            inner: Arc::new(RwLock::new(ExecPointerInner {
                lib: inner.lib.clone(),
                chain: None,
                block: None,
            })),
        }
    }
}

pub struct ExecPointerLibGuard<'a> {
    pointer: &'a ExecPointer, // The execution pointer that this guard is managing
}

impl<'a> ExecPointerLibGuard<'a> {
    pub fn new(pointer: &'a ExecPointer, lib: ProcessChainLibRef) -> Self {
        pointer.set_lib(lib);
        Self { pointer }
    }
}

impl<'a> Drop for ExecPointerLibGuard<'a> {
    fn drop(&mut self) {
        self.pointer.reset_lib();
    }
}

pub struct ExecPointerChainGuard<'a> {
    pointer: &'a ExecPointer, // The execution pointer that this guard is managing
}

impl<'a> ExecPointerChainGuard<'a> {
    pub fn new(pointer: &'a ExecPointer, chain: ProcessChainRef) -> Self {
        pointer.set_chain(chain);
        Self { pointer }
    }
}

impl<'a> Drop for ExecPointerChainGuard<'a> {
    fn drop(&mut self) {
        self.pointer.reset_chain();
    }
}

pub struct ExecPointerBlockGuard<'a> {
    pointer: &'a ExecPointer, // The execution pointer that this guard is managing
}

impl<'a> ExecPointerBlockGuard<'a> {
    pub fn new(pointer: &'a ExecPointer, block: &str) -> Self {
        pointer.set_block(block);
        Self { pointer }
    }
}

impl<'a> Drop for ExecPointerBlockGuard<'a> {
    fn drop(&mut self) {
        self.pointer.reset_block();
    }
}

pub struct SearchResult {
    pub lib: Option<ProcessChainLibRef>, // The library where the chain or block was found
    pub same_lib: bool, // Whether the found chain or block is in the same library as the current pointer

    pub chain: Option<ProcessChainRef>, // The chain where the block was found
    pub same_chain: bool, // Whether the found block is in the same chain as the current pointer
}

// The context in which the block are executed
#[derive(Clone)]
pub struct Context {
    current_pointer: ExecPointer, // The current execution pointer
    process_chain_manager: ProcessChainLinkedManagerRef,
    env: EnvManager,
    goto_counter: GotoCounterRef, // Counter for goto command executions
    pipe: CommandPipe,            // Pipe for command execution
}

impl Context {
    pub fn new(
        process_chain_manager: ProcessChainLinkedManagerRef,
        global_env: EnvRef,
        goto_counter: GotoCounterRef,
        pipe: CommandPipe,
    ) -> Self {
        let chain_env = Arc::new(Env::new(EnvLevel::Chain, Some(global_env.clone())));
        let env_manager = EnvManager::new(global_env, chain_env);

        Self {
            current_pointer: ExecPointer::new(), // Initialize with a new execution pointer
            process_chain_manager,
            env: env_manager,
            goto_counter,
            pipe,
        }
    }

    pub fn current_pointer(&self) -> &ExecPointer {
        &self.current_pointer
    }

    pub fn process_chain_manager(&self) -> &ProcessChainLinkedManagerRef {
        &self.process_chain_manager
    }

    pub fn search_lib(&self, lib_id: &str) -> Result<Option<SearchResult>, String> {
        // If current pointer is same as the requested lib_id, return it
        let current_lib = self.current_pointer.get_lib().unwrap();
        if current_lib.get_id() == lib_id {
            let ret = SearchResult {
                lib: Some(current_lib),
                same_lib: true,
                chain: None,
                same_chain: false,
            };
            return Ok(Some(ret));
        }

        // Otherwise, check the process chain manager for the lib
        let ret = self.process_chain_manager.get_lib(lib_id);
        match ret {
            Some(lib) => {
                let ret = SearchResult {
                    lib: Some(lib),
                    same_lib: false,
                    chain: None,
                    same_chain: false,
                };
                Ok(Some(ret))
            }
            None => Ok(None),
        }
    }

    pub fn search_chain(
        &self,
        lib_id: Option<&str>,
        chain_id: &str,
    ) -> Result<Option<SearchResult>, String> {
        // If lib_id is not specified, or is same as the current pointer's lib, then just get the chain from the current pointer
        let current_lib = self.current_pointer.get_lib().unwrap();
        if lib_id.is_none() || current_lib.get_id() == lib_id.unwrap() {
            // If chain_id is same as the current pointer's chain, return it
            let current_chain = self.current_pointer.get_chain().unwrap();
            if current_chain.id() == chain_id {
                let ret = SearchResult {
                    lib: Some(current_lib),
                    same_lib: true,
                    chain: Some(current_chain),
                    same_chain: true,
                };
                return Ok(Some(ret));
            }

            // If current pointer has a lib set, check if it contains the chain
            if let Some(chain) = current_lib.get_chain(chain_id)? {
                let ret = SearchResult {
                    lib: Some(current_lib),
                    same_lib: true,
                    chain: Some(chain),
                    same_chain: false,
                };
                return Ok(Some(ret));
            }

            // If no chain found, return None
            warn!(
                "Process chain '{}' not found in current pointer's lib '{}'",
                chain_id, current_lib.get_id()
            );
            return Ok(None);
        }

        // Search in the specified library from the process chain manager
        assert!(lib_id.is_some(), "lib_id must be specified when searching for a chain");
        let ret = self.process_chain_manager.get_chain(lib_id, chain_id)?;
        match ret {
            Some((lib, chain)) => Ok(Some(SearchResult {
                lib: Some(lib),
                same_lib: false,
                chain: Some(chain),
                same_chain: false,
            })),
            None => {
                warn!(
                    "Process chain '{}' not found in library '{}'",
                    chain_id, lib_id.unwrap()
                );
                Ok(None)
            }
        }
    }

    pub fn search_block(
        &self,
        lib_id: Option<&str>,
        chain_id: Option<&str>,
        block_id: &str,
    ) -> Result<Option<SearchResult>, String> {
        let current_lib = self.current_pointer.get_lib().unwrap();

        // If lib_id is not specified, or is same as the current pointer's lib, then just get the block from the current pointer
        if lib_id.is_none() || current_lib.get_id() == lib_id.unwrap() {
            let current_chain = self.current_pointer.get_chain().unwrap();
            // If chain_id is same as the current pointer's chain, or if chain_id is None, check the current chain for the block
            if chain_id.is_none() || current_chain.id() == chain_id.unwrap() {
                // If the current pointer has a block set, check if it matches the requested block_id
                if let Some(_block) = current_chain.get_block(block_id) {
                    return Ok(Some(SearchResult {
                        lib: Some(current_lib),
                        same_lib: true,
                        chain: Some(current_chain),
                        same_chain: true,
                    }));
                } else {
                    warn!(
                        "Block '{}' not found in current chain '{}'",
                        block_id, current_chain.id()
                    );
                    return Ok(None);
                }
            }

            let chain_id = chain_id.unwrap();
            let ret = current_lib.get_chain(chain_id)?;
            match ret {
                Some(chain) => {
                    if let Some(_block) = chain.get_block(block_id) {
                        return Ok(Some(SearchResult {
                            lib: Some(current_lib),
                            same_lib: true,
                            chain: Some(chain),
                            same_chain: false,
                        }));
                    } else {
                        warn!(
                            "Block '{}' not found in chain '{}' of current pointer's lib '{}'",
                            block_id, chain_id, current_lib.get_id()
                        );
                        return Ok(None);
                    }
                }
                None => {
                    warn!(
                        "Chain '{}' not found in current pointer's lib '{}'",
                        chain_id, current_lib.get_id()
                    );
                    return Ok(None);
                }
            }
        }

        assert!(lib_id.is_some(), "lib_id must be specified when searching for a block");
        assert!(chain_id.is_some(), "chain_id must be specified when searching for a block");

        // Get the block from the process chain manager
        let chain_id = chain_id.unwrap();
        let ret = self.process_chain_manager.get_block(lib_id, chain_id, block_id)?;
        match ret {
            Some((lib, chain)) => Ok(Some(SearchResult {
                lib: Some(lib),
                same_lib: false,
                chain: Some(chain),
                same_chain: false,
            })),
            None => {
                warn!(
                    "Block '{}' not found in chain '{}' of library '{}'",
                    block_id, chain_id, lib_id.unwrap()
                );
                Ok(None)
            }
        }
    }

    pub fn global_env(&self) -> &EnvRef {
        self.env.get_global()
    }

    pub fn chain_env(&self) -> &EnvRef {
        self.env.get_chain()
    }

    pub fn env(&self) -> &EnvManager {
        &self.env
    }

    pub fn counter(&self) -> &GotoCounterRef {
        &self.goto_counter
    }

    pub fn pipe(&self) -> &CommandPipe {
        &self.pipe
    }

    pub fn fork_block(&self) -> Self {
        // Create a new block environment that inherits from the chain environment

        // Use the same global and chain environment
        let env = EnvManager::new(self.env.get_global().clone(), self.env.get_chain().clone());
        Self {
            current_pointer: self.current_pointer.fork_block(), // Use the current chain and lib for the block context
            process_chain_manager: self.process_chain_manager.clone(),
            env,
            goto_counter: self.goto_counter.clone(), // Use the same goto counter for the block context
            pipe: self.pipe.clone(),
        }
    }

    pub fn fork_chain(&self) -> Self {
        // Create a new chain environment that inherits from the global environment
        let chain_env = Arc::new(Env::new(EnvLevel::Chain, Some(self.global_env().clone())));
        let env = EnvManager::new(self.env.get_global().clone(), chain_env);
        
        Self {
            current_pointer: self.current_pointer.fork_chain(), // Use the current lib for the chain context
            process_chain_manager: self.process_chain_manager.clone(),
            env,
            goto_counter: self.goto_counter.clone(), // Use the same goto counter for the chain context
            pipe: self.pipe.clone(),
        }
    }
}
