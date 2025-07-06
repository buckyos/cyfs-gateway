use crate::chain::{EnvManager, EnvRef, ProcessChainManagerRef, ProcessChainRef, EnvLevel};
use crate::collection::CollectionManager;

// The context in which the block are executed
pub struct Context {
    env: EnvManager,
    process_chain_manager: ProcessChainManagerRef,
    collection_manager: CollectionManager,
}

impl Context {
    fn new(
        global_env: EnvRef,
        chain_env: EnvRef,
        process_chain_manager: ProcessChainManagerRef,
    ) -> Self {
        let env_manager = EnvManager::new(global_env, chain_env);
        let collection_manager = CollectionManager::new();

        Self {
            env: env_manager,
            process_chain_manager,
            collection_manager,
        }
    }

    pub fn collection_manager(&self) -> &CollectionManager {
        &self.collection_manager
    }

    pub fn get_env_value(&self, key: &str) -> Option<String> {
        self.env.get(key, None)
    }

    pub fn set_env_value(&self, key: &str, value: &str, level: Option<EnvLevel>) -> Option<String> {
        self.env.set(key, value, level)
    }

    pub fn delete_env_value(&self, key: &str) -> Option<String> {
        self.env.delete(key, None)
    }

    pub fn get_process_chain(&self, id: &str) -> Option<ProcessChainRef> {
        self.process_chain_manager
            .get_chain(id)
    }
}
