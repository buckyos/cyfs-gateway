use super::hook_point::{HookPoint, HookPointExecutor};
use crate::chain::*;
use crate::cmd::{ExternalCommand, ExternalCommandRef};
use crate::collection::*;
use crate::js::AsyncJavaScriptCommandExecutor;
use crate::pipe::SharedMemoryPipe;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub struct HookPointEnv {
    id: String,
    data_dir: PathBuf,
    global_env: EnvRef,
    pipe: SharedMemoryPipe,
    parser_context: ParserContextRef,

    // Each hook point env has its own JavaScript command executor, which is used to execute JavaScript commands in the hook point
    // This allows the hook point to execute JavaScript commands independently in its own thread
    js_command_executor: AsyncJavaScriptCommandExecutor,
}

impl HookPointEnv {
    pub fn new(id: impl Into<String>, data_dir: PathBuf) -> Self {
        let pipe: SharedMemoryPipe = SharedMemoryPipe::new_empty();

        let global_env = Arc::new(Env::new(EnvLevel::Global, None));
        let parser_context = ParserContext::new();
        let js_command_executor = AsyncJavaScriptCommandExecutor::new();

        Self {
            id: id.into(),
            data_dir,
            global_env,
            pipe,
            parser_context: Arc::new(parser_context),
            js_command_executor,
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    pub fn parser_context(&self) -> &ParserContextRef {
        &self.parser_context
    }

    pub fn global_env(&self) -> &EnvRef {
        &self.global_env
    }

    pub fn pipe(&self) -> &SharedMemoryPipe {
        &self.pipe
    }

    pub fn register_external_command(
        &self,
        name: &str,
        command: ExternalCommandRef,
    ) -> Result<(), String> {
        self.parser_context.register_external_command(name, command)
    }

    pub async fn register_js_external_command(
        &self,
        name: &str,
        source: String,
    ) -> Result<(), String> {
        let cmd = self
            .js_command_executor
            .load_command(name.to_owned(), source)
            .await
            .map_err(|e| {
                let msg = format!(
                    "Failed to register JavaScript external command '{}': {}",
                    name, e
                );
                error!("{}", msg);
                msg
            })?;

        self.register_external_command(name, Arc::new(Box::new(cmd) as Box<dyn ExternalCommand>))
    }

    pub fn get_external_command(&self, name: &str) -> Option<ExternalCommandRef> {
        self.parser_context.get_external_command(name)
    }

    pub async fn flush_collections(&self) -> Result<(), String> {
        self.global_env.flush().await
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
                    .global_env
                    .create(id, CollectionValue::Set(Arc::new(set)))
                    .await?;
                if !ret {
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
                    .global_env
                    .create(id, CollectionValue::Map(Arc::new(map)))
                    .await?;
                if !ret {
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
                    .global_env
                    .create(id, CollectionValue::MultiMap(Arc::new(multi_map)))
                    .await?;
                if !ret {
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

    /// Link the hook point with the current environment.
    pub async fn link_hook_point(
        &self,
        hook_point: &HookPoint,
    ) -> Result<HookPointExecutor, String> {
        let process_chain_manager = hook_point
            .process_chain_manager()
            .link(&self.parser_context)
            .await
            .map_err(|e| {
                let msg = format!(
                    "Failed to link process chain manager for hook point '{}': {}",
                    hook_point.id(),
                    e
                );
                error!("{}", msg);
                msg
            })?;

        let executor = HookPointExecutor::new(hook_point.id(), process_chain_manager);
        Ok(executor)
    }
}

pub type HookPointEnvRef = Arc<HookPointEnv>;
