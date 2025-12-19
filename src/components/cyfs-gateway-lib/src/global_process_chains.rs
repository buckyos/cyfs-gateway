use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::sync::atomic::AtomicU32;
use buckyos_kit::AsyncStream;
use tokio::sync::RwLock;
use cyfs_process_chain::*;
use crate::{config_err, ConfigErrorCode, ConfigResult, GlobalCollectionManagerRef, ProcessChainConfig};

pub struct GlobalProcessChains {
    process_chains: Mutex<Vec<ProcessChainLibRef>>,
}
pub type GlobalProcessChainsRef = Arc<GlobalProcessChains>;

impl GlobalProcessChains {
    pub fn new() -> Self {
        Self {
            process_chains: Mutex::new(vec![]),
        }
    }

    pub fn add_process_chain(&self, process_chain: ProcessChainRef) -> ConfigResult<()> {
        if self.get_process_chain(process_chain.id()).is_some() {
            return Err(config_err!(
                ConfigErrorCode::AlreadyExists,
                "process chain {} already exists",
                process_chain.id()
            ));
        }
        let process_chain_lib = ProcessChainListLib::new(process_chain.id().to_string().as_str(), 0, vec![process_chain]);
        self.process_chains.lock().unwrap().push(process_chain_lib.into_process_chain_lib());
        Ok(())
    }

    pub fn replace_process_chains(&self, process_chains: Vec<ProcessChainLibRef>) {
        self.clear_process_chains();
        *self.process_chains.lock().unwrap() = process_chains;
    }

    pub fn clear_process_chains(&self) {
        self.process_chains.lock().unwrap().clear();
    }

    pub fn update_process_chain(&self, process_chain: ProcessChainRef) {
        let id = process_chain.id().to_string();
        let new_chain_lib = ProcessChainListLib::new(id.as_str(), 0, vec![process_chain]);
        for process_chain_lib in self.process_chains.lock().unwrap().iter_mut() {
            if process_chain_lib.get_id() == id {
                *process_chain_lib = new_chain_lib.into_process_chain_lib();
                break;
            }
        }
    }

    pub fn get_process_chain(&self, id: &str) -> Option<ProcessChainLibRef> {
        for process_chain_lib in self.process_chains.lock().unwrap().iter() {
            if process_chain_lib.get_id() == id {
                return Some(process_chain_lib.clone());
            }
        }
        None
    }

    pub fn get_process_chains(&self) -> Vec<ProcessChainLibRef> {
        self.process_chains.lock().unwrap().clone()
    }

    pub fn register_global_process_chain(&self, hook_point: &HookPoint) -> ConfigResult<()> {
        let process_chains = self.process_chains.lock().unwrap();
        for process_chain_lib in process_chains.iter() {
            hook_point.add_process_chain_lib(process_chain_lib.clone())
                .map_err(|e| config_err!(ConfigErrorCode::InvalidConfig, "{}", e))?;
        }
        Ok(())
    }
}

#[derive(Clone)]
struct StreamRequestMap {
    pub request: Arc<RwLock<StreamRequest>>,
    transverse_counter: Arc<AtomicU32>, // Indicates if a traversal is currently happening
}

impl StreamRequestMap {
    pub fn new(request: StreamRequest) -> Self {
        Self {
            request: Arc::new(RwLock::new(request)),
            transverse_counter: Arc::new(AtomicU32::new(0)), // Initialize counter to 0
        }
    }

    fn is_during_traversal(&self) -> bool {
        self.transverse_counter
            .load(std::sync::atomic::Ordering::SeqCst)
            > 0
    }

    pub fn into_request(self) -> Result<StreamRequest, String> {
        let req = Arc::try_unwrap(self.request)
            .map_err(|_| "Failed to unwrap StreamRequestMap".to_string())?
            .into_inner();

        Ok(req)
    }

    pub async fn register(&self, env: &EnvRef) -> Result<bool, String> {
        let coll = Arc::new(Box::new(self.clone()) as Box<dyn MapCollection>);
        env.create("REQ", CollectionValue::Map(coll)).await
    }
}

#[async_trait::async_trait]
impl MapCollection for StreamRequestMap {
    async fn len(&self) -> Result<usize, String> {
        Ok(STREAM_REQUEST_LEN)
    }

    async fn insert_new(&self, key: &str, value: CollectionValue) -> Result<bool, String> {
        if self.is_during_traversal() {
            let msg = "Cannot insert new key during traversal".to_string();
            error!("{}", msg);
            return Err(msg);
        }

        self.insert(key, value).await.map(|prev| prev.is_none())
    }

    async fn insert(
        &self,
        key: &str,
        value: CollectionValue,
    ) -> Result<Option<CollectionValue>, String> {
        if self.is_during_traversal() {
            let msg = "Cannot insert key during traversal".to_string();
            error!("{}", msg);
            return Err(msg);
        }

        let mut request = self.request.write().await;
        let prev;

        match key {
            "dest_port" => {
                prev = Some(CollectionValue::String(request.dest_port.to_string()));
                if let CollectionValue::String(port_str) = value {
                    request.dest_port = port_str.parse().map_err(|e| {
                        let msg = format!("Failed to parse dest_port: {}, {}", port_str, e);
                        error!("{}", msg);
                        msg
                    })?;
                } else {
                    let msg = format!("dest_port must be an integer or string, got {:?}", value);
                    error!("{}", msg);
                    return Err(msg);
                }
            }
            "dest_host" => {
                prev = request.dest_host.clone().map(CollectionValue::String);
                if let CollectionValue::String(host) = value {
                    request.dest_host = Some(host);
                } else {
                    let msg = format!("dest_host must be a string, got {:?}", value);
                    error!("{}", msg);
                    return Err(msg);
                }
            }
            "dest_addr" => {
                prev = request
                    .dest_addr
                    .map(|addr| CollectionValue::String(addr.to_string()));
                if let CollectionValue::String(addr) = value {
                    request.dest_addr = Some(addr.parse().map_err(|e| {
                        let msg = format!("Failed to parse dest_addr: {}, {}", addr, e);
                        error!("{}", msg);
                        msg
                    })?);
                } else {
                    let msg = format!("dest_addr must be a string, got {:?}", value);
                    error!("{}", msg);
                    return Err(msg);
                }
            }
            "app_protocol" => {
                prev = request.app_protocol.clone().map(CollectionValue::String);
                if let CollectionValue::String(protocol) = value {
                    request.app_protocol = Some(protocol);
                } else {
                    let msg = format!("app_protocol must be a string, got {:?}", value);
                    error!("{}", msg);
                    return Err(msg);
                }
            }
            "dest_url" => {
                prev = request.dest_url.clone().map(CollectionValue::String);
                if let CollectionValue::String(url) = value {
                    request.dest_url = Some(url);
                } else {
                    let msg = format!("dest_url must be a string, got {:?}", value);
                    error!("{}", msg);
                    return Err(msg);
                }
            }
            "source_addr" => {
                prev = request
                    .source_addr
                    .map(|addr| CollectionValue::String(addr.to_string()));
                if let CollectionValue::String(addr) = value {
                    request.source_addr = Some(addr.parse().map_err(|e| {
                        let msg = format!("Failed to parse source_addr: {}, {}", addr, e);
                        error!("{}", msg);
                        msg
                    })?);
                } else {
                    let msg = format!("source_addr must be a string, got {:?}", value);
                    error!("{}", msg);
                    return Err(msg);
                }
            }
            "source_mac" => {
                prev = request.source_mac.clone().map(CollectionValue::String);
                if let CollectionValue::String(mac) = value {
                    request.source_mac = Some(mac);
                } else {
                    let msg = format!("source_mac must be a string, got {:?}", value);
                    error!("{}", msg);
                    return Err(msg);
                }
            }
            "source_device_id" => {
                prev = request
                    .source_device_id
                    .clone()
                    .map(CollectionValue::String);
                if let CollectionValue::String(device_id) = value {
                    request.source_device_id = Some(device_id);
                } else {
                    let msg = format!("source_device_id must be a string, got {:?}", value);
                    error!("{}", msg);
                    return Err(msg);
                }
            }
            "source_app_id" => {
                prev = request.source_app_id.clone().map(CollectionValue::String);
                if let CollectionValue::String(app_id) = value {
                    request.source_app_id = Some(app_id);
                } else {
                    let msg = format!("source_app_id must be a string, got {:?}", value);
                    error!("{}", msg);
                    return Err(msg);
                }
            }
            "source_user_id" => {
                prev = request.source_user_id.clone().map(CollectionValue::String);
                if let CollectionValue::String(user_id) = value {
                    request.source_user_id = Some(user_id);
                } else {
                    let msg = format!("source_user_id must be a string, got {:?}", value);
                    error!("{}", msg);
                    return Err(msg);
                }
            }
            "incoming_stream" => {
                if value.is_any() {
                    if let CollectionValue::Any(stream) = value {
                        if let Some(async_stream) = stream
                            .downcast::<Arc<Mutex<Option<Box<dyn AsyncStream>>>>>()
                            .ok()
                        {
                            prev = Some(CollectionValue::Any(request.incoming_stream.clone()));
                            *request.incoming_stream.lock().unwrap() =
                                async_stream.lock().unwrap().take();
                        } else {
                            let msg = format!(
                                "incoming_stream must be of type Arc<Mutex<Option<Box<dyn AsyncStream>>>>",
                            );
                            error!("{}", msg);
                            return Err(msg);
                        }
                    } else {
                        let msg =
                            format!("incoming_stream must be of type AnyType, got {:?}", value);
                        error!("{}", msg);
                        return Err(msg);
                    }
                } else {
                    let msg = format!("incoming_stream must be of type AnyType, got {:?}", value);
                    error!("{}", msg);
                    return Err(msg);
                }
            }
            "ext" => {
                if let CollectionValue::Map(ext) = value {
                    prev = request.ext.clone().map(CollectionValue::Map);
                    request.ext = Some(ext);
                } else {
                    let msg = format!("ext must be a Map, got {:?}", value);
                    error!("{}", msg);
                    return Err(msg);
                }
            }
            _ => {
                let msg = format!("Unknown key: {}", key);
                error!("{}", msg);
                return Err(msg);
            }
        }

        Ok(prev)
    }

    async fn get(&self, key: &str) -> Result<Option<CollectionValue>, String> {
        let request = self.request.read().await;
        match key {
            "dest_port" => Ok(Some(CollectionValue::String(request.dest_port.to_string()))),
            "dest_host" => Ok(request.dest_host.clone().map(CollectionValue::String)),
            "dest_addr" => Ok(request
                .dest_addr
                .map(|addr| CollectionValue::String(addr.to_string()))),
            "app_protocol" => Ok(request.app_protocol.clone().map(CollectionValue::String)),
            "dest_url" => Ok(request.dest_url.clone().map(CollectionValue::String)),
            "source_addr" => Ok(request
                .source_addr
                .map(|addr| CollectionValue::String(addr.to_string()))),
            "source_mac" => Ok(request.source_mac.clone().map(CollectionValue::String)),
            "source_device_id" => Ok(request
                .source_device_id
                .clone()
                .map(CollectionValue::String)),
            "source_app_id" => Ok(request.source_app_id.clone().map(CollectionValue::String)),
            "source_user_id" => Ok(request.source_user_id.clone().map(CollectionValue::String)),
            "ext" => Ok(request.ext.clone().map(CollectionValue::Map)),
            "incoming_stream" => {
                let stream = request.incoming_stream.lock().unwrap();
                if stream.is_some() {
                    Ok(Some(CollectionValue::Any(request.incoming_stream.clone())))
                } else {
                    Ok(None)
                }
            }
            _ => {
                let msg = format!("Unknown key: {}", key);
                error!("{}", msg);
                Err(msg)
            }
        }
    }

    async fn contains_key(&self, key: &str) -> Result<bool, String> {
        let request = self.request.read().await;
        match key {
            "dest_port" => Ok(true),
            "dest_host" => Ok(request.dest_host.is_some()),
            "dest_addr" => Ok(request.dest_addr.is_some()),
            "app_protocol" => Ok(request.app_protocol.is_some()),
            "dest_url" => Ok(request.dest_url.is_some()),
            "source_addr" => Ok(request.source_addr.is_some()),
            "source_mac" => Ok(request.source_mac.is_some()),
            "source_device_id" => Ok(request.source_device_id.is_some()),
            "source_app_id" => Ok(request.source_app_id.is_some()),
            "source_user_id" => Ok(request.source_user_id.is_some()),
            "ext" => Ok(request.ext.is_some()),
            "incoming_stream" => {
                let stream = request.incoming_stream.lock().unwrap();
                Ok(stream.is_some())
            }
            _ => {
                let msg = format!("Unknown key: {}", key);
                error!("{}", msg);
                Err(msg)
            }
        }
    }

    async fn remove(&self, key: &str) -> Result<Option<CollectionValue>, String> {
        if self.is_during_traversal() {
            let msg = "Cannot remove key during traversal".to_string();
            error!("{}", msg);
            return Err(msg);
        }

        let mut request = self.request.write().await;
        match key {
            "dest_port" => Ok(Some(CollectionValue::String(request.dest_port.to_string()))),
            "dest_host" => Ok(request.dest_host.take().map(CollectionValue::String)),
            "dest_addr" => Ok(request
                .dest_addr
                .take()
                .map(|addr| CollectionValue::String(addr.to_string()))),
            "app_protocol" => Ok(request.app_protocol.take().map(CollectionValue::String)),
            "dest_url" => Ok(request.dest_url.take().map(CollectionValue::String)),
            "source_addr" => Ok(request
                .source_addr
                .take()
                .map(|addr| CollectionValue::String(addr.to_string()))),
            "source_mac" => Ok(request.source_mac.take().map(CollectionValue::String)),
            "source_device_id" => Ok(request.source_device_id.take().map(CollectionValue::String)),
            "source_app_id" => Ok(request.source_app_id.take().map(CollectionValue::String)),
            "source_user_id" => Ok(request.source_user_id.take().map(CollectionValue::String)),
            "ext" => Ok(request.ext.take().map(CollectionValue::Map)),
            "incoming_stream" => {
                let stream = request.incoming_stream.lock().unwrap().take();
                if let Some(s) = stream {
                    Ok(Some(CollectionValue::Any(Arc::new(Mutex::new(Some(s))))))
                } else {
                    Ok(None)
                }
            }
            _ => Err(format!("Unknown key: {}", key)),
        }
    }

    async fn traverse(&self, callback: MapCollectionTraverseCallBackRef) -> Result<(), String> {
        let _guard = TraverseGuard::new(&self.transverse_counter);

        let request = self.request.read().await;
        for (key, value) in [
            ("dest_port", request.dest_port.to_string()),
            ("dest_host", request.dest_host.clone().unwrap_or_default()),
            (
                "dest_addr",
                request
                    .dest_addr
                    .map(|addr| addr.to_string())
                    .unwrap_or_default(),
            ),
            (
                "app_protocol",
                request.app_protocol.clone().unwrap_or_default(),
            ),
            ("dest_url", request.dest_url.clone().unwrap_or_default()),
            (
                "source_addr",
                request
                    .source_addr
                    .map(|addr| addr.to_string())
                    .unwrap_or_default(),
            ),
            ("source_mac", request.source_mac.clone().unwrap_or_default()),
            (
                "source_device_id",
                request.source_device_id.clone().unwrap_or_default(),
            ),
            (
                "source_app_id",
                request.source_app_id.clone().unwrap_or_default(),
            ),
            (
                "source_user_id",
                request.source_user_id.clone().unwrap_or_default(),
            ),
        ] {
            if !callback.call(key, &CollectionValue::String(value)).await? {
                break;
            }
        }

        if let Some(ext) = &request.ext {
            ext.traverse(callback).await?;
        }

        Ok(())
    }

    async fn dump(&self) -> Result<Vec<(String, CollectionValue)>, String> {
        let request = self.request.read().await;
        let mut result = Vec::new();
        result.push((
            "dest_port".to_string(),
            CollectionValue::String(request.dest_port.to_string()),
        ));
        if let Some(host) = &request.dest_host {
            result.push((
                "dest_host".to_string(),
                CollectionValue::String(host.clone()),
            ));
        }
        if let Some(addr) = &request.dest_addr {
            result.push((
                "dest_addr".to_string(),
                CollectionValue::String(addr.to_string()),
            ));
        }
        if let Some(protocol) = &request.app_protocol {
            result.push((
                "app_protocol".to_string(),
                CollectionValue::String(protocol.clone()),
            ));
        }
        if let Some(url) = &request.dest_url {
            result.push(("dest_url".to_string(), CollectionValue::String(url.clone())));
        }
        if let Some(addr) = &request.source_addr {
            result.push((
                "source_addr".to_string(),
                CollectionValue::String(addr.to_string()),
            ));
        }
        if let Some(mac) = &request.source_mac {
            result.push((
                "source_mac".to_string(),
                CollectionValue::String(mac.clone()),
            ));
        }
        if let Some(device_id) = &request.source_device_id {
            result.push((
                "source_device_id".to_string(),
                CollectionValue::String(device_id.clone()),
            ));
        }
        if let Some(app_id) = &request.source_app_id {
            result.push((
                "source_app_id".to_string(),
                CollectionValue::String(app_id.clone()),
            ));
        }
        if let Some(user_id) = &request.source_user_id {
            result.push((
                "source_user_id".to_string(),
                CollectionValue::String(user_id.clone()),
            ));
        }
        if let Some(ext) = &request.ext {
            result.push(("ext".to_string(), CollectionValue::Map(ext.clone())));
        }

        Ok(result)
    }
}

pub async fn create_process_chain_executor(
    chains: &Vec<ProcessChainConfig>,
    global_process_chains: Option<GlobalProcessChainsRef>,
    global_collection_manager: Option<GlobalCollectionManagerRef>,
    external_commands: Option<Vec<(String, ExternalCommandRef)>>,
) -> ConfigResult<(ProcessChainLibExecutor, HookPointEnv)> {
    let hook_point = HookPoint::new("cyfs_server_hook_point");
    let process_chain_lib = ProcessChainListLib::new_empty("main", 0);
    for chain_config in chains.iter() {
        process_chain_lib.add_chain(Arc::new(chain_config.create_process_chain()?))
            .map_err(|e| config_err!(ConfigErrorCode::InvalidConfig, "{}", e))?;
    }
    hook_point.add_process_chain_lib(process_chain_lib.into_process_chain_lib())
        .map_err(|e| config_err!(ConfigErrorCode::InvalidConfig, "{}", e))?;

    if let Some(global_process_chains) = global_process_chains {
        global_process_chains.register_global_process_chain(&hook_point)?;
    }

    let hook_point_env = HookPointEnv::new("cyfs_server_hook_point_env", PathBuf::new());

    if let Some(external_commands) = external_commands {
        for (name, cmd) in external_commands {
            hook_point_env.register_external_command(name.as_str(), cmd.clone())
                .map_err(|e| config_err!(ConfigErrorCode::ProcessChainError, "{}", e))?;
        }
    }
    
    if let Some(global_collection_manager) = global_collection_manager {
        global_collection_manager.register_collection(hook_point_env.hook_point_env()).await?;
    }

    let executor = hook_point_env
        .link_hook_point(&hook_point)
        .await
        .map_err(|e| config_err!(ConfigErrorCode::ProcessChainError, "{}", e))?;
    Ok((executor.prepare_exec_lib("main")
            .map_err(|e| config_err!(ConfigErrorCode::ProcessChainError, "{}", e))?, hook_point_env))
}


pub async fn execute_stream_chain(executor: ProcessChainLibExecutor, request: StreamRequest) -> ConfigResult<(CommandResult, Box<dyn AsyncStream>)> {
    let request_map = StreamRequestMap::new(request);
    let global_env = executor.global_env();
    request_map.register(global_env)
        .await
        .map_err(|e| config_err!(ConfigErrorCode::ProcessChainError, "{}", e))?;
    let ret = executor
        .execute_lib()
        .await
        .map_err(|e| config_err!(ConfigErrorCode::ProcessChainError, "{}", e))?;

    let request = request_map.request.read().await;
    let socket = request.incoming_stream.lock().unwrap().take();
    if socket.is_none() {
        return Err(config_err!(
                ConfigErrorCode::ProcessChainError,
                "socket is none"
            ));
    }
    let socket = socket.unwrap();
    Ok((ret, socket))
}

pub async fn execute_chain(executor: ProcessChainLibExecutor, coll: MapCollectionRef) -> ConfigResult<CommandResult> {
    let global_env = executor.global_env();
    global_env.create("REQ", CollectionValue::Map(coll))
        .await
        .map_err(|e| config_err!(ConfigErrorCode::ProcessChainError, "{}", e))?;
    let ret = executor
        .execute_lib()
        .await
        .map_err(|e| config_err!(ConfigErrorCode::ProcessChainError, "{}", e))?;
    Ok(ret)
}
