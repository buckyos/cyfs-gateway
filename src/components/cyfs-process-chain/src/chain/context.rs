use super::env::{Env, EnvLevel};
use crate::chain::{EnvManager, EnvRef, ProcessChainRef, ProcessChainManagerRef};
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

// The context in which the block are executed
#[derive(Clone)]
pub struct Context {
    current_chain: Arc<RwLock<Option<ProcessChainRef>>>, // The chain that this context is executing
    process_chain_manager: ProcessChainManagerRef,
    env: EnvManager,
    goto_counter: GotoCounterRef, // Counter for goto command executions
    pipe: CommandPipe,            // Pipe for command execution
}

impl Context {
    pub fn new(process_chain_manager: ProcessChainManagerRef, global_env: EnvRef, goto_counter: GotoCounterRef, pipe: CommandPipe) -> Self {
        let chain_env = Arc::new(Env::new(EnvLevel::Chain, Some(global_env.clone())));
        let env_manager = EnvManager::new(global_env, chain_env);

        Self {
            current_chain: Arc::new(RwLock::new(None)),
            process_chain_manager,
            env: env_manager,
            goto_counter,
            pipe,
        }
    }

    pub fn bind_chain(&self, chain: ProcessChainRef) {
        let mut current_chain = self.current_chain.write().unwrap();
        *current_chain = Some(chain);
    }

    pub fn process_chain_manager(&self) -> &ProcessChainManagerRef {
        &self.process_chain_manager
    }

    pub fn chain(&self) -> Option<ProcessChainRef> {
        let current_chain = self.current_chain.read().unwrap();
        current_chain.clone()
    }

    pub fn get_chain(&self, id: &str) -> Result<Option<ProcessChainRef>, String> {
        self.process_chain_manager.get_chain(id)
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

    /*
    pub fn fork_chain(&self, chain: ProcessChainRef) -> Self {
        // Call new that will create a new chain environment that inherits from the global environment

        Self::new(
            self.env.get_global().clone(), // Use independent chain environment, just share global environment
            self.collection_manager.get_global_collections().clone(), // Use independent chain collections, just share global collections
            self.goto_counter.clone(), // Use the same goto counter for the chain context
            self.pipe.clone(),
        )
    }
    */

    pub fn fork_block(&self) -> Self {
        // Create a new block environment that inherits from the chain environment

        // Use the same global and chain environment
        let env = EnvManager::new(self.env.get_global().clone(), self.env.get_chain().clone());
        let current_chain = self.current_chain.read().unwrap().clone();
        Self {
            current_chain: Arc::new(RwLock::new(current_chain)), // Use the current chain for the block context
            process_chain_manager: self.process_chain_manager.clone(),
            env,
            goto_counter: self.goto_counter.clone(), // Use the same goto counter for the block context
            pipe: self.pipe.clone(),
        }
    }
}
