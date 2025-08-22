use super::env::{Env, EnvLevel};
use super::pointer::*;
use crate::chain::{
    EnvManager, EnvRef, ProcessChainLibRef, ProcessChainLinkedManagerRef, ProcessChainRef,
};
use crate::pipe::CommandPipe;
use std::sync::Arc;

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
                chain_id,
                current_lib.get_id()
            );
            return Ok(None);
        }

        // Search in the specified library from the process chain manager
        assert!(
            lib_id.is_some(),
            "lib_id must be specified when searching for a chain"
        );
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
                    chain_id,
                    lib_id.unwrap()
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
                        block_id,
                        current_chain.id()
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
                            block_id,
                            chain_id,
                            current_lib.get_id()
                        );
                        return Ok(None);
                    }
                }
                None => {
                    warn!(
                        "Chain '{}' not found in current pointer's lib '{}'",
                        chain_id,
                        current_lib.get_id()
                    );
                    return Ok(None);
                }
            }
        }

        assert!(
            lib_id.is_some(),
            "lib_id must be specified when searching for a block"
        );
        assert!(
            chain_id.is_some(),
            "chain_id must be specified when searching for a block"
        );

        // Get the block from the process chain manager
        let chain_id = chain_id.unwrap();
        let ret = self
            .process_chain_manager
            .get_block(lib_id, chain_id, block_id)?;
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
                    block_id,
                    chain_id,
                    lib_id.unwrap()
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
            current_pointer: self.current_pointer.clone(),
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
            current_pointer: self.current_pointer.clone(),
            process_chain_manager: self.process_chain_manager.clone(),
            env,
            goto_counter: self.goto_counter.clone(), // Use the same goto counter for the chain context
            pipe: self.pipe.clone(),
        }
    }
}
