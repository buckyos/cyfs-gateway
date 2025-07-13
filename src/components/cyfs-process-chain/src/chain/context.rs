use crate::chain::{EnvManager, EnvRef, ProcessChainRef};
use crate::collection::CollectionManager;
use crate::pipe::CommandPipe;
use std::sync::Arc;
use std::sync::atomic::AtomicU32;

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
pub struct Context {
    chain: ProcessChainRef, // The chain that this context belongs to
    env: EnvManager,
    collection_manager: CollectionManager,
    goto_counter: GotoCounterRef, // Counter for goto command executions
    pipe: CommandPipe,            // Pipe for command execution
}

impl Context {
    pub fn new(
        chain: ProcessChainRef,
        global_env: EnvRef,
        chain_env: EnvRef,
        collection_manager: CollectionManager,
        goto_counter: GotoCounterRef,
        pipe: CommandPipe,
    ) -> Self {
        let env_manager = EnvManager::new(global_env, chain_env);

        Self {
            chain,
            env: env_manager,
            collection_manager,
            goto_counter,
            pipe,
        }
    }

    pub fn collection_manager(&self) -> &CollectionManager {
        &self.collection_manager
    }

    pub fn chain(&self) -> &ProcessChainRef {
        &self.chain
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

    pub fn fork_chain(&self, chain: ProcessChainRef) -> Self {
        // Create a new chain environment that inherits from the global environment
        let chain_env = self.env.create_chain_env();

        Self::new(
            chain,
            self.env.get_global().clone(),
            chain_env,
            self.collection_manager.clone(),
            self.goto_counter.clone(), // Use the same goto counter for the chain context
            self.pipe.clone(),
        )
    }

    pub fn fork_block(&self) -> Self {
        // Create a new block environment that inherits from the chain environment
        Self::new(
            self.chain.clone(),
            self.env.get_global().clone(),
            self.env.get_chain().clone(),
            self.collection_manager.clone(),
            self.goto_counter.clone(), // Use the same goto counter for the block context
            self.pipe.clone(),
        )
    }
}
