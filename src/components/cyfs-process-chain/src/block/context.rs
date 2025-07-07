use crate::chain::{EnvManager, EnvRef, ProcessChainManagerRef, ProcessChainRef, EnvLevel};
use crate::collection::{CollectionManager, VariableVisitorManager};

// The context in which the block are executed
pub struct Context {
    env: EnvManager,
    process_chain_manager: ProcessChainManagerRef,
    collection_manager: CollectionManager,
    variable_visitor_manager: VariableVisitorManager,
}

impl Context {
    pub fn new(
        global_env: EnvRef,
        chain_env: EnvRef,
        process_chain_manager: ProcessChainManagerRef,
    ) -> Self {
        let env_manager = EnvManager::new(global_env, chain_env);
        let collection_manager = CollectionManager::new();
        let variable_visitor_manager = VariableVisitorManager::new();

        Self {
            env: env_manager,
            process_chain_manager,
            collection_manager,
            variable_visitor_manager,
        }
    }

    pub fn collection_manager(&self) -> &CollectionManager {
        &self.collection_manager
    }

    pub async fn get_env_value(&self, key: &str) -> Result<Option<String>, String> {
        // First check if the key in visitor manager
        if let Some(value) = self.variable_visitor_manager.get_value(key).await? {
            return Ok(Some(value));
        }

        // Then treat it as a regular environment variable
        let ret= self.env.get(key, None);
        Ok(ret)
    }

    pub async fn set_env_value(&self, key: &str, value: &str, level: Option<EnvLevel>) -> Result<Option<String>, String> {
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
        self.process_chain_manager
            .get_chain(id)
    }
}
