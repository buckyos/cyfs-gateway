use super::hook_point::HookPoint;
use crate::chain::{Env, EnvLevel, EnvRef, ProcessChainListExecutor, ProcessChainsExecutor};
use crate::collection::*;
use crate::pipe::SharedMemoryPipe;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub struct HookPointEnv {
    id: String,
    data_dir: PathBuf,
    global_collections: Collections,
    global_env: EnvRef,
    pipe: SharedMemoryPipe,
}

impl HookPointEnv {
    pub fn new(id: impl Into<String>, data_dir: PathBuf) -> Self {
        let global_collections = Collections::new();
        let pipe: SharedMemoryPipe = SharedMemoryPipe::new_empty();

        let global_env = Arc::new(Env::new(EnvLevel::Global, None));
        Self {
            id: id.into(),
            data_dir,
            global_collections,
            global_env,
            pipe,
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    pub fn global_collections(&self) -> &Collections {
        &self.global_collections
    }

    pub fn global_env(&self) -> &EnvRef {
        &self.global_env
    }

    // Return variable visitor manager in global env
    pub fn variable_visitor_manager(&self) -> &VariableVisitorManager {
        &self.global_env.variable_visitor_manager()
    }

    pub fn pipe(&self) -> &SharedMemoryPipe {
        &self.pipe
    }

    pub async fn flush_collections(&self) -> Result<(), String> {
        self.global_collections.flush().await
    }

    pub async fn load_collection(
        &self,
        id: &str,
        collection_type: CollectionType,
        collection_format: CollectionFileFormat,
        auto_create: bool,
    ) -> Result<(), String> {
        let file_name = match collection_format {
            CollectionFileFormat::Json => format!("{}.json", id),
            CollectionFileFormat::Sqlite => format!("{}.db", id),
        };
        let file_path = self.data_dir.join(file_name);
        if !file_path.exists() && !auto_create {
            let msg = format!(
                "Collection file '{}' not found and auto-create is disabled",
                file_path.display()
            );
            error!("{}", msg);
            return Err(msg);
        }

        match collection_type {
            CollectionType::Set => {
                let set = match collection_format {
                    CollectionFileFormat::Json => {
                        let set = JsonSetCollection::new(file_path.clone())?;
                        Box::new(set) as Box<dyn SetCollection>
                    }
                    CollectionFileFormat::Sqlite => {
                        unimplemented!("Sqlite collection not implemented yet");
                    }
                };

                let ret = self
                    .global_collections
                    .add_set_collection(id, Arc::new(set))
                    .await;
                if ret.is_none() {
                    let msg = format!(
                        "Failed to add set collection with id '{}', already exists",
                        id
                    );
                    error!("{}", msg);
                    return Err(msg);
                }
            }
            CollectionType::Map => {
                let map = match collection_format {
                    CollectionFileFormat::Json => {
                        let map = JsonMapCollection::new(file_path.clone())?;
                        Box::new(map) as Box<dyn MapCollection>
                    }
                    CollectionFileFormat::Sqlite => {
                        unimplemented!("Sqlite collection not implemented yet");
                    }
                };

                let ret = self
                    .global_collections
                    .add_map_collection(id, Arc::new(map))
                    .await;
                if ret.is_none() {
                    let msg = format!(
                        "Failed to add map collection with id '{}', already exists",
                        id
                    );
                    error!("{}", msg);
                    return Err(msg);
                }
            }
            CollectionType::MultiMap => {
                let multi_map = match collection_format {
                    CollectionFileFormat::Json => {
                        let multi_map = JsonMultiMapCollection::new(file_path.clone())?;
                        Box::new(multi_map) as Box<dyn MultiMapCollection>
                    }
                    CollectionFileFormat::Sqlite => {
                        unimplemented!("Sqlite collection not implemented yet");
                    }
                };

                let ret = self
                    .global_collections
                    .add_multi_map_collection(id, Arc::new(multi_map))
                    .await;
                if ret.is_none() {
                    let msg = format!(
                        "Failed to add multi-map collection with id '{}', already exists",
                        id
                    );
                    error!("{}", msg);
                    return Err(msg);
                }
            }
        }

        info!(
            "Collection '{}' of type '{:?}' loaded successfully",
            id, collection_type
        );
        Ok(())
    }

    // Prepare execute the chain list defined in the hook point, will return a ProcessChainListExecutor
    // which can be used to execute the chain list.
    pub fn prepare_exec_list(&self, hook_point: &HookPoint) -> ProcessChainListExecutor {
        ProcessChainListExecutor::new(
            hook_point.process_chain_manager(),
            self.global_env.clone(),
            self.global_collections.clone(),
            self.pipe.pipe().clone(),
        )
    }

    /*
    pub async fn exec_list(&self, hook_point: &HookPoint) -> Result<CommandResult, String> {
        info!("Executing hook point chain list: {}", hook_point.id());

        let exec = ProcessChainListExecutor::new(
            &hook_point.process_chain_manager(),
            self.global_env.clone(),
            self.global_collections.clone(),
            self.pipe.pipe().clone(),
        );

        exec.execute_all().await
    }
    */

    // Prepare a ProcessChainsExecutor to execute the chain in the hook point
    // This executor can be used to execute a single chain or multiple chains.
    pub fn prepare_exec_chain(&self, hook_point: &HookPoint) -> ProcessChainsExecutor {
        ProcessChainsExecutor::new(
            hook_point.process_chain_manager().clone(),
            self.global_env.clone(),
            self.global_collections.clone(),
            self.pipe.pipe().clone(),
        )
    }

    /*
    // Just execute a single chain by id(maybe exec multi chain if there is one or more goto commands)
    pub async fn exec_chain(
        &self,
        hook_point: &HookPoint,
        id: &str,
    ) -> Result<CommandResult, String> {
        info!("Executing process chain: {}", id);

        let exec = ProcessChainsExecutor::new(
            hook_point.process_chain_manager().clone(),
            self.global_env.clone(),
            self.global_collections.clone(),
            self.pipe.pipe().clone(),
        );

        exec.execute_chain_by_id(id).await
    }
    */
}

pub type HookPointEnvRef = Arc<HookPointEnv>;
