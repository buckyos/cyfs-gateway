use log::Level;

use super::env::{Env, EnvLevel};
use super::stack::*;
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
        if let Some(current_lib) = self.current_pointer.get_lib()
            && current_lib.get_id() == lib_id
        {
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
        // If lib_id is not specified, or is same as the current pointer's lib, then first try the current pointer.
        if let Some(current_lib) = self.current_pointer.get_lib()
            && (lib_id.is_none() || current_lib.get_id() == lib_id.unwrap())
        {
            // If chain_id is same as the current pointer's chain, return it
            if let Some(current_chain) = self.current_pointer.get_chain()
                && current_chain.id() == chain_id
            {
                let ret = SearchResult {
                    lib: Some(current_lib.clone()),
                    same_lib: true,
                    chain: Some(current_chain),
                    same_chain: true,
                };
                return Ok(Some(ret));
            }

            // If current pointer has a lib set, check if it contains the chain
            if let Some(chain) = current_lib.get_chain(chain_id)? {
                let ret = SearchResult {
                    lib: Some(current_lib.clone()),
                    same_lib: true,
                    chain: Some(chain),
                    same_chain: false,
                };
                return Ok(Some(ret));
            }

            if lib_id.is_some() {
                warn!(
                    "Process chain '{}' not found in current pointer's lib '{}'",
                    chain_id,
                    current_lib.get_id()
                );
                return Ok(None);
            }
        }

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
        // If lib_id is not specified, or is same as the current pointer's lib, then first try the current pointer.
        if let Some(current_lib) = self.current_pointer.get_lib()
            && (lib_id.is_none() || current_lib.get_id() == lib_id.unwrap())
        {
            if let Some(current_chain) = self.current_pointer.get_chain() {
                // If chain_id is same as the current pointer's chain, or if chain_id is None, check the current chain for the block
                if chain_id.is_none() || current_chain.id() == chain_id.unwrap() {
                    if let Some(_block) = current_chain.get_block(block_id) {
                        return Ok(Some(SearchResult {
                            lib: Some(current_lib.clone()),
                            same_lib: true,
                            chain: Some(current_chain),
                            same_chain: true,
                        }));
                    }

                    if chain_id.is_none() {
                        warn!(
                            "Block '{}' not found in current chain '{}'",
                            block_id,
                            current_chain.id()
                        );
                        return Ok(None);
                    }
                }
            } else if chain_id.is_none() {
                warn!(
                    "Block '{}' lookup requires a current chain when chain_id is not specified",
                    block_id
                );
                return Ok(None);
            }

            if let Some(chain_id) = chain_id {
                let ret = current_lib.get_chain(chain_id)?;
                match ret {
                    Some(chain) => {
                        if let Some(_block) = chain.get_block(block_id) {
                            return Ok(Some(SearchResult {
                                lib: Some(current_lib.clone()),
                                same_lib: true,
                                chain: Some(chain),
                                same_chain: false,
                            }));
                        }

                        if lib_id.is_some() {
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
                        if lib_id.is_some() {
                            warn!(
                                "Chain '{}' not found in current pointer's lib '{}'",
                                chain_id,
                                current_lib.get_id()
                            );
                            return Ok(None);
                        }
                    }
                }
            }
        }

        let Some(chain_id) = chain_id else {
            warn!(
                "Block '{}' lookup requires chain_id when no current chain is available",
                block_id
            );
            return Ok(None);
        };

        // Get the block from the process chain manager
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

    pub fn get_log_level(&self) -> Level {
        self.env.get_log_level()
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
        env.set_policy(self.env.policy());
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
        env.set_policy(self.env.policy());

        Self {
            current_pointer: self.current_pointer.clone(),
            process_chain_manager: self.process_chain_manager.clone(),
            env,
            goto_counter: self.goto_counter.clone(), // Use the same goto counter for the chain context
            pipe: self.pipe.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::ParserContext;
    use crate::hook_point::HookPoint;

    const SIMPLE_LIB: &str = r#"
<process_chain_lib id="test_lib" priority="100">
    <process_chain id="main">
        <block id="entry">
            <![CDATA[
                return --from lib "ok";
            ]]>
        </block>
    </process_chain>
</process_chain_lib>
"#;

    async fn build_context() -> Result<Context, String> {
        let hook_point = HookPoint::new("context-search-test");
        hook_point
            .load_process_chain_lib("test_lib", 0, SIMPLE_LIB)
            .await?;

        let parser_context = Arc::new(ParserContext::new());
        let manager = hook_point
            .process_chain_manager()
            .link(&parser_context)
            .await?;

        let global_env = Arc::new(Env::new(EnvLevel::Global, None));
        Ok(Context::new(
            manager,
            global_env,
            Arc::new(GotoCounter::new()),
            CommandPipe::default(),
        ))
    }

    #[tokio::test]
    async fn search_without_current_pointer_uses_global_resolution() {
        let context = build_context().await.expect("context should build");

        let lib = context
            .search_lib("test_lib")
            .expect("lib lookup should succeed")
            .expect("lib should exist");
        assert!(!lib.same_lib);
        assert_eq!(lib.lib.expect("lib result").get_id(), "test_lib");

        let chain = context
            .search_chain(None, "main")
            .expect("chain lookup should succeed")
            .expect("chain should exist");
        assert!(!chain.same_lib);
        assert!(!chain.same_chain);
        assert_eq!(chain.chain.expect("chain result").id(), "main");

        let block = context
            .search_block(None, Some("main"), "entry")
            .expect("block lookup should succeed")
            .expect("block should exist");
        assert!(!block.same_lib);
        assert!(!block.same_chain);
        assert_eq!(block.chain.expect("block chain result").id(), "main");
    }

    #[tokio::test]
    async fn search_block_without_current_chain_returns_none() {
        let context = build_context().await.expect("context should build");

        let block = context
            .search_block(None, None, "entry")
            .expect("block lookup should not fail");
        assert!(block.is_none());
    }
}
