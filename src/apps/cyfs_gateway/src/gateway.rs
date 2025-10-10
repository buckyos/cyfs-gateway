use std::collections::HashMap;
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use super::config_loader::GatewayConfig;
use cyfs_gateway_lib::*;

use name_client::*;
use name_lib::*;
use buckyos_kit::*;
use url::Url;
use anyhow::Result;
use chrono::{Utc};
use jsonwebtoken::{DecodingKey, EncodingKey};
use jsonwebtoken::jwk::Jwk;
use kRPC::RPCSessionToken;
use serde::Serialize;
use serde_json::Value;
use sha2::Digest;
use crate::cyfs_cmd_client::{cmd_err, into_cmd_err};
use crate::cyfs_cmd_server::{CmdErrorCode, CmdResult, CyfsCmdHandler, CyfsTokenFactory, CyfsTokenVerifier};

//use buckyos_api::{*};
pub struct GatewayParams {
    pub keep_tunnel: Vec<String>,
}

pub struct GatewayFactory {
    servers: ServerManagerRef,
    global_process_chains: GlobalProcessChainsRef,
    connection_manager: ConnectionManagerRef,
    tunnel_manager: TunnelManager,
    inner_service_manager: InnerServiceManagerRef,
    stack_factory: CyfsStackFactory,
    server_factory: CyfsServerFactory,
    inner_service_factory: CyfsInnerServiceFactory,
}
impl GatewayFactory {
    pub fn new(
        servers: ServerManagerRef,
        global_process_chains: GlobalProcessChainsRef,
        connection_manager: ConnectionManagerRef,
        tunnel_manager: TunnelManager,
        inner_service_manager: InnerServiceManagerRef) -> Self {
        Self {
            servers,
            global_process_chains,
            connection_manager,
            tunnel_manager,
            inner_service_manager,
            stack_factory: CyfsStackFactory::new(),
            server_factory: CyfsServerFactory::new(),
            inner_service_factory: CyfsInnerServiceFactory::new(),
        }
    }

    pub fn register_stack_factory(&self, protocol: StackProtocol, factory: Arc<dyn StackFactory>) {
        self.stack_factory.register(protocol, factory);
    }

    pub fn register_server_factory<T: Into<String>>(&self, server_type: T, factory: Arc<dyn ServerFactory>) {
        self.server_factory.register(server_type.into(), factory);
    }

    pub fn register_inner_service_factory<T: Into<String>>(
        &self,
        service_type: T,
        factory: Arc<dyn InnerServiceFactory>,
    ) {
        self.inner_service_factory.register(service_type.into(), factory);
    }

    pub async fn create_gateway(
        &self,
        config: GatewayConfig,
    ) -> Result<Gateway> {
        let stack_manager = StackManager::new();
        for stack_config in config.stacks.iter() {
            let stack = self.stack_factory.create(stack_config.clone()).await?;
            stack_manager.add_stack(stack);
        }

        for server_config in config.servers.iter() {
            let server = self.server_factory.create(server_config.clone()).await?;
            self.servers.add_server(server.id(), server);
        }

        for inner_service_config in config.inner_services.iter() {
            let service = self.inner_service_factory.create(inner_service_config.clone()).await?;
            self.inner_service_manager.add_service(service.id(), service);
        }

        for process_chain_config in config.global_process_chains.iter() {
            let process_chain = process_chain_config.create_process_chain()?;
            self.global_process_chains.add_process_chain(Arc::new(process_chain));
        }

        Ok(Gateway {
            config: Mutex::new(config),
            stack_manager,
            tunnel_manager: self.tunnel_manager.clone(),
            server_manager: self.servers.clone(),
            inner_service_factory: self.inner_service_manager.clone(),
            global_process_chains: self.global_process_chains.clone(),
            connection_manager: self.connection_manager.clone(),
        })
    }
}

pub struct Gateway {
    config: Mutex<GatewayConfig>,
    stack_manager: StackManagerRef,
    tunnel_manager: TunnelManager,
    server_manager: ServerManagerRef,
    inner_service_factory: InnerServiceManagerRef,
    global_process_chains: GlobalProcessChainsRef,
    connection_manager: ConnectionManagerRef,
}

impl Drop for Gateway {
    fn drop(&mut self) {
        info!("Gateway is dropped!");
    }
}

impl Gateway {
    pub fn tunnel_manager(&self) -> &TunnelManager {
        &self.tunnel_manager
    }

    pub async fn start(&self, params: GatewayParams) {
        let mut real_machine_config = BuckyOSMachineConfig::default();
        let machine_config = BuckyOSMachineConfig::load_machine_config();
        if machine_config.is_some() {
            real_machine_config = machine_config.unwrap();
        }
        let init_result = init_name_lib(&real_machine_config.web3_bridge).await;
        if init_result.is_err() {
            error!("init default name client failed, err:{}", init_result.err().unwrap());
            return;
        }
        info!("init default name client OK!");

        if !params.keep_tunnel.is_empty() {
            self.keep_tunnels(params.keep_tunnel).await;
        }

        if let Err(e) = self.stack_manager.start().await {
            error!("start stack manager failed, err:{}", e);
        }
    }
    async fn keep_tunnels(&self, keep_tunnel: Vec<String>) {
        for tunnel in keep_tunnel {
            self.keep_tunnel(tunnel.as_str()).await;
        }
    }

    async fn keep_tunnel(&self, tunnel: &str) {
        let tunnel_url = format!("rtcp://{}", tunnel);
        info!("Will keep tunnel: {}", tunnel_url);
        let tunnel_url = Url::parse(tunnel_url.as_str());
        if tunnel_url.is_err() {
            warn!("Invalid tunnel url: {}", tunnel_url.err().unwrap());
            return;
        }

        let tunnel_manager = self.tunnel_manager().clone();
        tokio::task::spawn(async move {
            let tunnel_url = tunnel_url.unwrap();
            loop {
                let last_ok;
                let tunnel = tunnel_manager.get_tunnel(&tunnel_url, None).await;
                if tunnel.is_err() {
                    warn!("Error getting tunnel: {}", tunnel.err().unwrap());
                    last_ok = false;
                } else {
                    let tunnel = tunnel.unwrap();
                    let ping_result = tunnel.ping().await;
                    if ping_result.is_err() {
                        warn!("Error pinging tunnel: {}", ping_result.err().unwrap());
                        last_ok = false;
                    } else {
                        last_ok = true;
                    }
                }

                if last_ok {
                    tokio::time::sleep(std::time::Duration::from_secs(60 * 2)).await;
                } else {
                    tokio::time::sleep(std::time::Duration::from_secs(15)).await;
                }
            }
        });
    }

    pub fn get_all_config(&self) -> Result<Value> {
        let config = self.config.lock().unwrap();
        let mut config_value = HashMap::new();
        let mut stacks = vec![];
        for stack in config.stacks.iter() {
            let stack_value: Value = serde_json::from_str(stack.get_config_json().as_str())?;
            stacks.push(stack_value);
        }
        config_value.insert("stacks".to_string(), Value::Array(stacks));

        let mut servers = vec![];
        for server in config.servers.iter() {
            let server_value: Value = serde_json::from_str(server.get_config_json().as_str())?;
            servers.push(server_value);
        }
        config_value.insert("servers".to_string(), Value::Array(servers));

        let mut inner_services = vec![];
        for service in config.inner_services.iter() {
            let service_value: Value = serde_json::from_str(service.get_config_json().as_str())?;
            inner_services.push(service_value);
        }
        config_value.insert("inner_services".to_string(), Value::Array(inner_services));

        let global_config = serde_json::to_value(&config.global_process_chains)?;
        config_value.insert("global_process_chains".to_string(), global_config);

        Ok(serde_json::to_value(&config_value)?)
    }

    pub fn get_config(&self, config_type: &str, config_id: &str) -> Result<Value> {
        let config = self.config.lock().unwrap();
        match config_type {
            "stack" => {
                for stack in config.stacks.iter() {
                    if stack.id() == config_id {
                        return Ok(serde_json::from_str(stack.get_config_json().as_str())?);
                    }
                }
            }
            "server" => {
                for server in config.servers.iter() {
                    if server.id() == config_id {
                        return Ok(serde_json::from_str(server.get_config_json().as_str())?);
                    }
                }
            }
            "inner_service" => {
                for service in config.inner_services.iter() {
                    if service.id() == config_id {
                        return Ok(serde_json::from_str(service.get_config_json().as_str())?);
                    }
                }
            }
            "global_process_chain" => {
                for chain in config.global_process_chains.iter() {
                    if chain.id == config_id {
                        return Ok(serde_json::to_value(chain)?);
                    }
                }
            }
            _ => {
                Err(cmd_err!(
                    CmdErrorCode::InvalidConfigType,
                    "Invalid config type: {}", config_type,
                ))?;
            }
        }

        Err(anyhow::Error::new(cmd_err!(
            CmdErrorCode::ConfigNotFound,
            "Config not found: {}", config_id,
        )))
    }

    pub async fn add_chain(&self, config_type: &str, config_id: &str, hook_point: Option<String>, chain: ProcessChainConfig) -> Result<()> {
        match config_type {
            "stack" => {
                let mut stack_info = None;
                {
                    let config = self.config.lock().unwrap();
                    for (index, stack) in config.stacks.iter().enumerate() {
                        if stack.id() == config_id {
                            let new_stack = stack.add_process_chain(chain);
                            stack_info = Some((index, new_stack));
                            break;
                        }
                    }
                }
                if let Some((index, stack_config)) = stack_info {
                    if let Some(stack) = self.stack_manager.get_stack(config_id).await {
                        stack.update_config(stack_config.clone()).await?;
                        let mut config = self.config.lock().unwrap();
                        config.stacks[index] = stack_config;
                    }
                }
            }
            "server" => {
                let hook_point = hook_point.unwrap_or("pre".to_string());
                let mut server_info = None;
                {
                    let config = self.config.lock().unwrap();
                    for (index, server) in config.servers.iter().enumerate() {
                        if server.id() == config_id {
                            let new_server = if hook_point == "pre" {
                                server.add_pre_hook_point_process_chain(chain)
                            } else {
                                server.add_post_hook_point_process_chain(chain)
                            };
                            server_info = Some((index, new_server));
                            break;
                        }
                    }
                }
                if let Some((index, server_config)) = server_info {
                    if let Some(server) = self.server_manager.get_server(config_id) {
                        server.update_config(server_config.clone()).await?;
                        let mut config = self.config.lock().unwrap();
                        config.servers[index] = server_config;
                    }
                }
            }
            _ => {
                Err(cmd_err!(
                    CmdErrorCode::InvalidConfigType,
                    "Invalid config type: {}", config_type,
                ))?;
            }
        }
        Ok(())
    }

    pub async fn remove_chain(&self, config_type: &str, config_id: &str, hook_point: Option<String>, chain_id: &str) -> Result<()> {
        match config_type {
            "stack" => {
                let mut stack_info = None;
                {
                    let config = self.config.lock().unwrap();
                    for (index, stack) in config.stacks.iter().enumerate() {
                        if stack.id() == config_id {
                            let new_stack = stack.remove_process_chain(chain_id);
                            stack_info = Some((index, new_stack));
                            break;
                        }
                    }
                }
                if let Some((index, stack_config)) = stack_info {
                    if let Some(stack) = self.stack_manager.get_stack(config_id).await {
                        stack.update_config(stack_config.clone()).await?;
                        let mut config = self.config.lock().unwrap();
                        config.stacks[index] = stack_config;
                    }
                }
            }
            "server" => {
                let hook_point = hook_point.unwrap_or("pre".to_string());
                let mut server_info = None;
                {
                    let config = self.config.lock().unwrap();
                    for (index, server) in config.servers.iter().enumerate() {
                        if server.id() == config_id {
                            let new_server = if hook_point == "pre" {
                                server.remove_pre_hook_point_process_chain(chain_id)
                            } else {
                                server.remove_post_hook_point_process_chain(chain_id)
                            };
                            server_info = Some((index, new_server));
                            break;
                        }
                    }
                }
                if let Some((index, server_config)) = server_info {
                    if let Some(server) = self.server_manager.get_server(config_id) {
                        server.update_config(server_config.clone()).await?;
                        let mut config = self.config.lock().unwrap();
                        config.servers[index] = server_config;
                    }
                }
            }
            _ => {
                Err(cmd_err!(
                    CmdErrorCode::InvalidConfigType,
                    "Invalid config type: {}", config_type,
                ))?;
            }
        }
        Ok(())
    }
}

pub struct GatewayCmdHandler {
    gateway: Mutex<Option<Arc<Gateway>>>,
    external_cmd_store: ExternalCmdStoreRef,
}

impl GatewayCmdHandler {
    pub fn new(external_cmd_store: ExternalCmdStoreRef) -> Arc<Self> {
        Arc::new(Self {
            gateway: Mutex::new(None),
            external_cmd_store,
        })
    }

    pub fn set_gateway(&self, gateway: Arc<Gateway>) {
        self.gateway.lock().unwrap().replace(gateway);
    }

    fn get_gateway(&self) -> Option<Arc<Gateway>> {
        self.gateway.lock().unwrap().clone()
    }

    async fn run_external_cmd(&self, cmd: &str, params: &str) -> CmdResult<String> {
        let python_cmd = format!("python \"{}\" {}", cmd, params);
        let data = sfo_io::execute(python_cmd.as_str()).await
            .map_err(into_cmd_err!(CmdErrorCode::RunPythonFailed))?;
        let resp = String::from_utf8_lossy(data.as_slice()).to_string();
        log::info!("cmd {} params {} resp {}", cmd, params, resp);
        Ok(resp)
    }
}

#[derive(Serialize)]
struct ConnInfo {
    source: String,
    dest: String,
    protocol: StackProtocol,
    upload_speed: u64,
    download_speed: u64,
}

#[async_trait::async_trait]
impl CyfsCmdHandler for GatewayCmdHandler {
    async fn handle(&self, method: &str, params: Value) -> CmdResult<Value> {
        let gateway = self.get_gateway();
        if gateway.is_none() {
            return Err(cmd_err!(CmdErrorCode::NoGateway, "gateway not init"));
        }
        let gateway = gateway.unwrap();
        match method {
            "get_config" => {
                let params = serde_json::from_value::<HashMap<String, String>>(params)
                    .map_err(into_cmd_err!(CmdErrorCode::InvalidParams))?;
                let config_type = params.get("config_type");
                let config_id = params.get("config_id");
                if config_type.is_none() || config_id.is_none() {
                    gateway.get_all_config()
                        .map_err(|e| cmd_err!(CmdErrorCode::Failed, "{}", e))
                } else {
                    gateway.get_config(config_type.unwrap(), config_id.unwrap())
                        .map_err(|e| cmd_err!(CmdErrorCode::Failed, "{}", e))
                }
            },
            "del_chain" => {
                let params = serde_json::from_value::<HashMap<String, String>>(params)
                    .map_err(into_cmd_err!(CmdErrorCode::InvalidParams))?;
                let config_type = params.get("config_type");
                let config_id = params.get("config_id");
                let hook_point = params.get("hook_point");
                let chain_id = params.get("chain_id");
                if config_type.is_none() || config_id.is_none() || chain_id.is_none() {
                    Err(cmd_err!(
                        CmdErrorCode::InvalidParams,
                        "Invalid params: config_type or chain_id or config_id is None",
                    ))?;
                }

                gateway.remove_chain(config_type.unwrap(),
                                     config_id.unwrap(),
                                     hook_point.map(|s| s.to_string()),
                                     params.get("chain_id").unwrap()).await
                    .map_err(|e| cmd_err!(CmdErrorCode::Failed, "{}", e))?;
                Ok(Value::String("ok".to_string()))
            }
            "get_connections" => {
                let conn_infos = gateway.connection_manager.get_all_connection_info().iter().map(|info| {
                    ConnInfo {
                        source: info.source().to_string(),
                        dest: info.destination().to_string(),
                        protocol: info.protocol(),
                        upload_speed: info.get_upload_speed(),
                        download_speed: info.get_download_speed(),
                    }
                }).collect::<Vec<_>>();
                Ok(serde_json::to_value(conn_infos).map_err(into_cmd_err!(CmdErrorCode::SerializeFailed))?)
            }
            "add_chain" => {
                let params = serde_json::from_value::<HashMap<String, String>>(params)
                    .map_err(into_cmd_err!(CmdErrorCode::InvalidParams))?;
                let config_type = params.get("config_type");
                let config_id = params.get("config_id");
                let hook_point = params.get("hook_point");
                let chain_id = params.get("chain_id");
                let chain_type = params.get("chain_type");
                let chain_params = params.get("chain_params");
                if config_type.is_none() || config_id.is_none() || chain_id.is_none() || chain_type.is_none() || chain_params.is_none() {
                    Err(cmd_err!(
                        CmdErrorCode::InvalidParams,
                        "Invalid params: config_type or chain_id or config_id or chain_type or chain_params is None",
                    ))?;
                }
                let cmd = self.external_cmd_store.read_external_cmd(chain_type.unwrap()).await?;
                let block = self.run_external_cmd(cmd.as_str(), chain_params.unwrap().as_str()).await?;
                let process_chain_config = ProcessChainConfig {
                    id: chain_id.unwrap().to_string(),
                    priority: 0,
                    blocks: vec![BlockConfig {
                        id: "main".to_string(),
                        block: block.trim().to_string(),
                    }],
                };
                gateway.add_chain(
                    config_type.unwrap(),
                    config_id.unwrap(),
                    hook_point.map(|s| s.to_string()),
                    process_chain_config,
                ).await
                    .map_err(|e| cmd_err!(CmdErrorCode::Failed, "{}", e))?;
                Ok(Value::String("ok".to_string()))
            }
            v => {
                Err(cmd_err!(CmdErrorCode::InvalidMethod, "Invalid method: {}", v))
            }
        }
    }
}

#[async_trait::async_trait]
pub trait TokenKeyStore: Send + Sync + 'static {
    async fn load_key(&self) -> CmdResult<(EncodingKey, DecodingKey)>;
    async fn save_key(&self, sign_key: String, public_key: Value) -> CmdResult<()>;
}

pub struct LocalTokenKeyStore {
    data_dir: PathBuf,
}

impl LocalTokenKeyStore {
    pub fn new(data_dir: PathBuf) -> Self {
        LocalTokenKeyStore { data_dir }
    }
}

#[async_trait::async_trait]
impl TokenKeyStore for LocalTokenKeyStore {
    async fn load_key(&self) -> CmdResult<(EncodingKey, DecodingKey)> {
        let private_key = self.data_dir.join("private_key.pem");
        let public_key = self.data_dir.join("public_key.json");
        let encode_key = load_private_key(private_key.as_path())
            .map_err(into_cmd_err!(CmdErrorCode::Failed))?;

        let public_key = tokio::fs::read_to_string(public_key).await
            .map_err(into_cmd_err!(CmdErrorCode::Failed))?;
        let public_key: Jwk = serde_json::from_str(public_key.as_str())
            .map_err(into_cmd_err!(CmdErrorCode::Failed))?;
        let decode_key = DecodingKey::from_jwk(&public_key)
            .map_err(into_cmd_err!(CmdErrorCode::Failed))?;
        Ok((encode_key, decode_key))
    }

    async fn save_key(&self, sign_key: String, public_key: Value) -> CmdResult<()> {
        let private_key = self.data_dir.join("private_key.pem");
        let public_key_path = self.data_dir.join("public_key.json");
        tokio::fs::write(private_key.as_path(), sign_key).await
            .map_err(into_cmd_err!(CmdErrorCode::Failed))?;
        tokio::fs::write(public_key_path.as_path(), serde_json::to_string(&public_key).unwrap()).await
            .map_err(into_cmd_err!(CmdErrorCode::Failed))?;
        Ok(())
    }
}

pub struct LocalTokenManager<S: TokenKeyStore> {
    pub user_name: Option<String>,
    pub password: Option<String>,
    pub token_encode_key: EncodingKey,
    pub token_decode_key: DecodingKey,
    _p: PhantomData<S>,
}

impl<S: TokenKeyStore> LocalTokenManager<S> {
    pub async fn new(user_name: Option<String>,
                     password: Option<String>,
                     store: S) -> CmdResult<Arc<Self>> {
        let (encode_key, decode_key) = match store.load_key().await {
            Ok(ret) => {
                ret
            }
            Err(_) => {
                let (sign_key, public_key_value) = generate_ed25519_key_pair();
                let jwk = serde_json::from_value::<Jwk>(public_key_value.clone()).unwrap();
                let encode_key = EncodingKey::from_ed_pem(sign_key.as_bytes()).unwrap();
                let decode_key = DecodingKey::from_jwk(&jwk).unwrap();
                store.save_key(sign_key, public_key_value).await?;
                (encode_key, decode_key)
            }
        };
        Ok(Arc::new(LocalTokenManager {
            user_name,
            password,
            token_encode_key: encode_key,
            token_decode_key: decode_key,
            _p: Default::default(),
        }))
    }

    fn load(private_key: &Path, public_key: &Path) -> CmdResult<(EncodingKey, DecodingKey)> {
        if !private_key.exists() || !public_key.exists() {
            return Err(cmd_err!(CmdErrorCode::Failed));
        }

        let encode_key = load_private_key(private_key)
            .map_err(into_cmd_err!(CmdErrorCode::Failed))?;

        let public_key = std::fs::read_to_string(public_key)
            .map_err(into_cmd_err!(CmdErrorCode::Failed))?;
        let public_key: Jwk = serde_json::from_str(public_key.as_str())
            .map_err(into_cmd_err!(CmdErrorCode::Failed))?;
        let decode_key = DecodingKey::from_jwk(&public_key)
            .map_err(into_cmd_err!(CmdErrorCode::Failed))?;
        Ok((encode_key, decode_key))
    }
}
#[async_trait::async_trait]
impl<S: TokenKeyStore> CyfsTokenFactory for LocalTokenManager<S> {
    async fn create(&self, user_name: &str, password: &str, timestamp: u64) -> CmdResult<String> {
        if self.user_name.is_none() || self.password.is_none() {
            return Err(cmd_err!(CmdErrorCode::NotSupportLogin, "not support login"));
        }
        if (Utc::now().timestamp() - timestamp as i64).abs() > 120 {
            return Err(cmd_err!(CmdErrorCode::Expired, "login session expired"));
        }

        if user_name != self.user_name.as_ref().unwrap() {
            return Err(cmd_err!(CmdErrorCode::InvalidUserName, "invalid user name"));
        }

        let mut sha256 = sha2::Sha256::new();
        sha256.update(format!("{}_{}_{}", user_name, self.password.as_ref().unwrap(), timestamp));
        if hex::encode(sha256.finalize()).to_lowercase() != password.to_lowercase() {
            return Err(cmd_err!(CmdErrorCode::InvalidPassword, "invalid password"));
        }

        let (token, _) = RPCSessionToken::generate_jwt_token(
            user_name,
            "cyfs-gateway",
            None,
            &self.token_encode_key, )
            .map_err(into_cmd_err!(CmdErrorCode::CreateTokenFailed, "create token failed"))?;
        Ok(token)
    }
}

#[async_trait::async_trait]
impl<S: TokenKeyStore> CyfsTokenVerifier for LocalTokenManager<S> {
    async fn verify_and_renew(&self, token: &str) -> CmdResult<Option<String>> {
        let mut session_token = match RPCSessionToken::from_string(token) {
            Ok(session_token) => session_token,
            Err(e) => {
                error!("invalid token: {}", e);
                return Err(cmd_err!(CmdErrorCode::InvalidToken));
            }
        };

        if let Err(_) = session_token.verify_by_key(&self.token_decode_key) {
            return Err(cmd_err!(CmdErrorCode::InvalidToken));
        }

        if session_token.exp.is_some() {
            if session_token.exp.unwrap() < Utc::now().timestamp() as u64 {
                return Err(cmd_err!(CmdErrorCode::Expired));
            }

            match RPCSessionToken::generate_jwt_token(
                self.user_name.as_ref().unwrap_or(&("root".to_string())),
                "cyfs-gateway",
                None,
                &self.token_encode_key) {
                Ok((token, _)) => {
                    Ok(Some(token))
                },
                Err(_) => {
                    Err(cmd_err!(CmdErrorCode::InvalidToken))
                }
            }
        } else {
            Ok(None)
        }
    }
}

#[async_trait::async_trait]
pub trait ExternalCmdStore: Send + Sync + 'static {
    async fn read_external_cmd(&self, cmd: &str) -> CmdResult<String>;
}
pub type ExternalCmdStoreRef = Arc<dyn ExternalCmdStore>;

pub struct LocalExternalCmdStore {
    cmd_path: PathBuf,
}

impl LocalExternalCmdStore {
    pub fn new(cmd_path: PathBuf) -> Self {
        LocalExternalCmdStore {
            cmd_path,
        }
    }
}

#[async_trait::async_trait]
impl ExternalCmdStore for LocalExternalCmdStore {
    async fn read_external_cmd(&self, cmd: &str) -> CmdResult<String> {
        let path = self.cmd_path.join(format!("{}.py", cmd));
        if !path.exists() {
            return Err(cmd_err!(CmdErrorCode::UnknownCmd, "unknown cmd {}", cmd));
        }

        Ok(path.to_string_lossy().to_string())
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use super::super::gateway::*;
    use kRPC::RPCSessionToken;
    use chrono::Utc;

    pub struct TempKeyStore {
        private_key: tokio::sync::Mutex<tempfile::NamedTempFile>,
        public_key: tokio::sync::Mutex<tempfile::NamedTempFile>,
    }

    impl TempKeyStore {
        pub fn new() -> Self {
            TempKeyStore {
                private_key: tokio::sync::Mutex::new(tempfile::NamedTempFile::new().unwrap()),
                public_key: tokio::sync::Mutex::new(tempfile::NamedTempFile::new().unwrap()),
            }
        }

        pub async fn new_key(&self) {
            let (sign_key, public_key_value) = generate_ed25519_key_pair();
            self.save_key(sign_key, public_key_value).await.unwrap();
        }
    }

    #[async_trait::async_trait]
    impl TokenKeyStore for TempKeyStore {
        async fn load_key(&self) -> CmdResult<(EncodingKey, DecodingKey)> {
            let mut private_key = self.private_key.lock().await;
            let mut content: String = String::new();
            private_key.read_to_string(&mut content)
                .map_err(into_cmd_err!(CmdErrorCode::Failed))?;
            let private_key = EncodingKey::from_ed_pem(content.as_bytes())
                .map_err(into_cmd_err!(CmdErrorCode::Failed))?;
            let mut public_key = self.public_key.lock().await;
            let mut content: String = String::new();
            public_key.read_to_string(&mut content)
                .map_err(into_cmd_err!(CmdErrorCode::Failed))?;

            let public_key: Jwk = serde_json::from_str(content.as_str())
                .map_err(into_cmd_err!(CmdErrorCode::Failed))?;
            let decode_key = DecodingKey::from_jwk(&public_key)
                .map_err(into_cmd_err!(CmdErrorCode::Failed))?;
            Ok((private_key, decode_key))
        }

        async fn save_key(&self, sign_key: String, public_key: Value) -> CmdResult<()> {
            let mut private_key = self.private_key.lock().await;
            private_key.write_all(sign_key.as_bytes()).unwrap();
            let mut public_file = self.public_key.lock().await;
            public_file.write_all(serde_json::to_string(&public_key).unwrap().as_bytes()).unwrap();
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_local_token_manager_create_success() {
        let user_name = "test_user".to_string();
        let password = "test_password".to_string();
        let store = TempKeyStore::new();
        let manager = LocalTokenManager::new(Some(user_name.clone()), Some(password.clone()), store).await;
        assert!(manager.is_ok());
        let manager = manager.unwrap();

        let timestamp = Utc::now().timestamp() as u64;
        let mut sha256 = sha2::Sha256::new();
        sha256.update(format!("{}_{}_{}", user_name, password, timestamp));
        let password_hash = hex::encode(sha256.finalize()).to_lowercase();

        let result = manager.create(&user_name, &password_hash, timestamp).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_local_token_manager_create_expired() {
        let user_name = "test_user".to_string();
        let password = "test_password".to_string();
        let store = TempKeyStore::new();
        let manager = LocalTokenManager::new(Some(user_name.clone()), Some(password.clone()), store).await;
        assert!(manager.is_ok());
        let manager = manager.unwrap();

        let timestamp = (Utc::now().timestamp() - 121) as u64; // 121 seconds old, should be expired
        let mut sha256 = sha2::Sha256::new();
        sha256.update(format!("{}_{}_{}", user_name, password, timestamp));
        let password_hash = hex::encode(sha256.finalize()).to_lowercase();

        let result = manager.create(&user_name, &password_hash, timestamp).await;
        assert!(result.is_err());
        let error = result.err().unwrap();
        assert_eq!(error.code(), CmdErrorCode::Expired);
    }

    #[tokio::test]
    async fn test_local_token_manager_create_invalid_user() {
        let user_name = "test_user".to_string();
        let password = "test_password".to_string();
        let store = TempKeyStore::new();
        let manager = LocalTokenManager::new(Some(user_name.clone()), Some(password.clone()), store).await;
        assert!(manager.is_ok());
        let manager = manager.unwrap();

        let timestamp = Utc::now().timestamp() as u64;
        let mut sha256 = sha2::Sha256::new();
        sha256.update(format!("{}_{}_{}", "wrong_user", password, timestamp));
        let password_hash = hex::encode(sha256.finalize()).to_lowercase();

        let result = manager.create("wrong_user", &password_hash, timestamp).await;
        assert!(result.is_err());
        let error = result.err().unwrap();
        assert_eq!(error.code(), CmdErrorCode::InvalidUserName);
    }

    #[tokio::test]
    async fn test_local_token_manager_create_invalid_password() {
        let user_name = "test_user".to_string();
        let password = "test_password".to_string();
        let store = TempKeyStore::new();
        let manager = LocalTokenManager::new(Some(user_name.clone()), Some(password.clone()), store).await;
        assert!(manager.is_ok());
        let manager = manager.unwrap();

        let timestamp = Utc::now().timestamp() as u64;
        let mut sha256 = sha2::Sha256::new();
        sha256.update(format!("{}_{}_{}", user_name, "wrong_password", timestamp));
        let password_hash = hex::encode(sha256.finalize()).to_lowercase();

        let result = manager.create(&user_name, &password_hash, timestamp).await;
        assert!(result.is_err());
        let error = result.err().unwrap();
        assert_eq!(error.code(), CmdErrorCode::InvalidPassword);
    }

    #[tokio::test]
    async fn test_local_token_manager_verify_and_renew_success() {
        let user_name = "test_user".to_string();
        let password = "test_password".to_string();
        let store = TempKeyStore::new();
        let manager = LocalTokenManager::new(Some(user_name.clone()), Some(password.clone()), store).await;
        assert!(manager.is_ok());
        let manager = manager.unwrap();

        let timestamp = Utc::now().timestamp() as u64;
        let mut sha256 = sha2::Sha256::new();
        sha256.update(format!("{}_{}_{}", user_name, password, timestamp));
        let password_hash = hex::encode(sha256.finalize()).to_lowercase();

        let token = manager.create(&user_name, &password_hash, timestamp).await.unwrap();
        let result = manager.verify_and_renew(&token).await;

        assert!(result.is_ok());
        // Should return Some(new_token) for valid tokens that have expiration
        assert!(result.unwrap().is_some());
    }

    #[tokio::test]
    async fn test_local_token_manager_verify_and_renew_invalid_token() {
        let user_name = "test_user".to_string();
        let password = "test_password".to_string();
        let store = TempKeyStore::new();
        let manager = LocalTokenManager::new(Some(user_name.clone()), Some(password.clone()), store).await;
        assert!(manager.is_ok());
        let manager = manager.unwrap();

        let invalid_token = "invalid.token.string";
        let result = manager.verify_and_renew(invalid_token).await;

        assert!(result.is_err());
        let error = result.err().unwrap();
        assert_eq!(error.code(), CmdErrorCode::InvalidToken);
    }
}
