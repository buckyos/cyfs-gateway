use super::hook_point::HookPoint;
use crate::chain::{Env, EnvLevel, EnvRef, ProcessChainsExecutor};
use crate::cmd::CommandResult;
use crate::collection::*;
use crate::pipe::SharedMemoryPipe;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub struct HookPointEnv {
    id: String,
    data_dir: PathBuf,
    collection_manager: CollectionManager,
    global_env: EnvRef,
    variable_visitor_manager: VariableVisitorManager,
    pipe: SharedMemoryPipe,
}

impl HookPointEnv {
    pub fn new(id: String, data_dir: PathBuf) -> Self {
        let collection_manager = CollectionManager::new();

        let variable_visitor_manager = VariableVisitorManager::new();
        let pipe: SharedMemoryPipe = SharedMemoryPipe::new_empty();

        let global_env = Arc::new(Env::new(EnvLevel::Global, None));
        Self {
            id,
            data_dir,
            collection_manager,
            global_env,
            variable_visitor_manager,
            pipe,
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    pub fn collection_manager(&self) -> &CollectionManager {
        &self.collection_manager
    }

    pub fn global_env(&self) -> &EnvRef {
        &self.global_env
    }

    pub fn variable_visitor_manager(&self) -> &VariableVisitorManager {
        &self.variable_visitor_manager
    }

    pub fn pipe(&self) -> &SharedMemoryPipe {
        &self.pipe
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
                    .collection_manager
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
                    .collection_manager
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
                    .collection_manager
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

    pub async fn exec(&self, hook_point: &HookPoint) -> Result<CommandResult, String> {
        info!("Executing hook point: {}", hook_point.id());

        let exec = ProcessChainsExecutor::new(
            hook_point.process_chain_manager().clone(),
            self.global_env.clone(),
            self.collection_manager.clone(),
            self.variable_visitor_manager.clone(),
            self.pipe.pipe().clone(),
        );

        exec.execute_chain_by_id("chain1").await
    }
}
