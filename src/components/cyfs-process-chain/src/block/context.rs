use crate::chain::{EnvLevel, EnvManager, EnvRef, ProcessChainManagerRef, ProcessChainRef};
use crate::collection::{CollectionManager, VariableVisitorManager};

// The context in which the block are executed
pub struct Context {
    chain: ProcessChainRef, // The chain that this context belongs to
    env: EnvManager,
    process_chain_manager: ProcessChainManagerRef,
    collection_manager: CollectionManager,
    variable_visitor_manager: VariableVisitorManager,
}

impl Context {
    pub fn new(
        chain: ProcessChainRef,
        global_env: EnvRef,
        chain_env: EnvRef,
        process_chain_manager: ProcessChainManagerRef,
        collection_manager: CollectionManager,
        variable_visitor_manager: VariableVisitorManager,
    ) -> Self {
        let env_manager = EnvManager::new(global_env, chain_env);

        Self {
            chain,
            env: env_manager,
            process_chain_manager,
            collection_manager,
            variable_visitor_manager,
        }
    }

    pub fn collection_manager(&self) -> &CollectionManager {
        &self.collection_manager
    }

    pub fn chain(&self) -> &ProcessChainRef {
        &self.chain
    }

    pub async fn get_env_value(&self, key: &str) -> Result<Option<String>, String> {
        // First check if the key in visitor manager
        if let Some(value) = self.variable_visitor_manager.get_value(key).await? {
            return Ok(Some(value));
        }

        // Then treat it as a regular environment variable
        let ret = self.env.get(key, None);
        Ok(ret)
    }

    pub async fn set_env_value(
        &self,
        key: &str,
        value: &str,
        level: Option<EnvLevel>,
    ) -> Result<Option<String>, String> {
        println!("Setting env value: {} = {}", key, value);
        // First check if the key in visitor manager
        let (exists, ret) = self.variable_visitor_manager.set_value(key, value).await?;
        if exists {
            return Ok(ret);
        }

        // Then treat it as a regular environment variable
        let ret = self.env.set(key, value, level);
        Ok(ret)
    }

    pub fn delete_env_value(&self, key: &str) -> Option<String> {
        self.env.delete(key, None)
    }

    pub fn get_process_chain(&self, id: &str) -> Option<ProcessChainRef> {
        self.process_chain_manager.get_chain(id)
    }

    pub fn fork_chain(&self, chain: ProcessChainRef) -> Self {
        // Create a new chain environment that inherits from the global environment
        let chain_env = self.process_chain_manager.create_chain_env();

        Self::new(
            chain,
            self.env.get_global().clone(),
            chain_env,
            self.process_chain_manager.clone(),
            self.collection_manager.clone(),
            self.variable_visitor_manager.clone(),
        )
    }

    pub fn fork_block(&self) -> Self {
        // Create a new block environment that inherits from the chain environment
        Self::new(
            self.chain.clone(),
            self.env.get_global().clone(),
            self.env.get_chain().clone(),
            self.process_chain_manager.clone(),
            self.collection_manager.clone(),
            self.variable_visitor_manager.clone(),
        )
    }
}
