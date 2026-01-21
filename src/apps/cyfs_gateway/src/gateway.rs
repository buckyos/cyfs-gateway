use std::collections::{HashMap, HashSet};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use super::config_loader::GatewayConfig;
use cyfs_gateway_lib::*;

use log::*;
use name_client::*;
use name_lib::*;
use buckyos_kit::*;
use url::Url;
use anyhow::{anyhow, Result};
use chrono::{Utc};
use jsonwebtoken::{DecodingKey, EncodingKey};
use jsonwebtoken::jwk::Jwk;
use kRPC::RPCSessionToken;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sfo_js::{JsEngine, JsPkg, JsPkgManagerRef, JsString, JsValue, NativeFunction};
use sfo_js::object::builtins::JsArray;
use sha2::Digest;
use rand::{Rng};
use rand::distr::Alphanumeric;
use rand::rng;
use crate::gateway_control_client::{cmd_err, into_cmd_err};
use crate::gateway_control_server::{ControlErrorCode, ControlResult, GatewayControlCmdHandler, CyfsTokenFactory, CyfsTokenVerifier};
use crate::config_loader::GatewayConfigParserRef;
use crate::gateway_control_server::{
    GatewayControlServerConfigParser, GATEWAY_CONTROL_SERVER_CONFIG, GATEWAY_CONTROL_SERVER_KEY,
};
use crate::merge;

fn get_default_saved_gateway_config_path() -> PathBuf {
    get_buckyos_service_data_dir("cyfs_gateway").join("cyfs_gateway_saved.json")
}

pub fn get_default_config_path() -> PathBuf {
    let mut default_config = get_buckyos_system_etc_dir().join("cyfs_gateway.yaml");
    if !default_config.exists() {
        default_config = get_buckyos_system_etc_dir().join("cyfs_gateway.json");
    }
    default_config
}

fn strip_includes_field(mut config: Value) -> Value {
    if let Some(obj) = config.as_object_mut() {
        obj.remove("includes");
    }
    config
}

fn read_config_value(path: &Path) -> Result<Value> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| anyhow!("read config {} failed: {}", path.to_string_lossy(), e))?;
    let ext = path.extension().and_then(|ext| ext.to_str()).unwrap_or("");
    let value = match ext.to_ascii_lowercase().as_str() {
        "yaml" | "yml" => serde_yaml_ng::from_str(&content)?,
        "json" => serde_json::from_str(&content)?,
        _ => serde_json::from_str(&content).or_else(|_| serde_yaml_ng::from_str(&content))?,
    };
    Ok(value)
}

fn load_include_paths(config: &Value, config_dir: &Path) -> Vec<PathBuf> {
    let mut includes = Vec::new();
    let include_value = match config.get("include") {
        Some(value) => value,
        None => return includes,
    };
    let include_list = match include_value.as_array() {
        Some(list) => list,
        None => return includes,
    };
    for entry in include_list {
        let path_value = match entry {
            Value::String(path) => Some(path.as_str()),
            Value::Object(map) => map.get("path").and_then(|v| v.as_str()),
            _ => None,
        };
        if let Some(path) = path_value {
            includes.push(config_dir.join(path));
        }
    }
    includes
}

fn saved_config_newer_than_others(saved_path: &Path, config_file: &Path, config_dir: &Path) -> bool {
    let saved_mtime = match std::fs::metadata(saved_path).and_then(|meta| meta.modified()) {
        Ok(time) => time,
        Err(_) => return false,
    };
    let mut other_paths = vec![config_file.to_path_buf()];
    if let Ok(root_config) = read_config_value(config_file) {
        other_paths.extend(load_include_paths(&root_config, config_dir));
    }
    for path in other_paths {
        if let Ok(other_time) = std::fs::metadata(path).and_then(|meta| meta.modified()) {
            if saved_mtime <= other_time {
                return false;
            }
        }
    }
    true
}

fn is_default_gateway_config(config_file: &Path) -> bool {
    let default_config = get_default_config_path();
    config_file == default_config
}

fn resolve_save_path(requested: Option<&str>) -> PathBuf {
    let default_path = get_default_saved_gateway_config_path();
    let requested = match requested {
        Some(path) if !path.is_empty() => path,
        _ => return default_path,
    };
    let mut path = PathBuf::from(requested);
    if path.is_relative() {
        path = std::env::current_dir().unwrap_or(PathBuf::new()).join(path);
    }
    if path.exists() && path.is_dir() {
        return path.join(default_path.file_name().unwrap());
    }
    let ends_with_sep = requested.ends_with('/') || requested.ends_with('\\');
    if path.extension().is_none() && ends_with_sep {
        return path.join(default_path.file_name().unwrap());
    }
    path
}

pub async fn load_config_from_file(config_file: &Path) -> Result<serde_json::Value> {
    let config_dir = config_file.parent().ok_or_else(|| {
        let msg = format!("cannot get config dir: {:?}", config_file);
        error!("{}", msg);
        anyhow::anyhow!(msg)
    })?;

    let saved_path = get_default_saved_gateway_config_path();
    let saved_mtime = if is_default_gateway_config(config_file) && saved_path.exists() {
        std::fs::metadata(saved_path.as_path())
            .and_then(|meta| meta.modified())
            .ok()
    } else {
        None
    };
    let saved_config = if saved_mtime.is_some() {
        match read_config_value(saved_path.as_path()) {
            Ok(config) => Some(config),
            Err(e) => {
                warn!("load saved config {} failed: {}", saved_path.to_string_lossy(), e);
                None
            }
        }
    } else {
        None
    };

    let mut config_json = crate::ConfigMerger::load_dir_with_root(
        &config_dir,
        &config_file,
        saved_mtime,
    )
        .await
        .map_err(|e| {
            let msg = format!("local config {} failed {:?}", config_file.to_string_lossy().to_string(), e);
            error!("{}", msg);
            anyhow::anyhow!(msg)
        })?;
    if let Some(mut saved_config) = saved_config.clone() {
        merge(&mut saved_config, &config_json);
        config_json = saved_config;
        info!("Merge saved gateway config {}", saved_path.to_string_lossy());
    }

    info!("Gateway config before merge: {}", serde_json::to_string_pretty(&config_json).unwrap());

    let mut cmd_config: serde_json::Value = serde_yaml_ng::from_str(GATEWAY_CONTROL_SERVER_CONFIG).unwrap();
    merge(&mut cmd_config, &config_json);

    let mut config_json = buckyos_kit::apply_params_to_json(&cmd_config, None)
        .map_err(|e| {
            let msg = format!("apply params to config json failed: {}", e);
            error!("{}", msg);
            anyhow::anyhow!(msg)
        })?;
    info!("Apply params to gateway config.");
    normalize_all_path_value_config(&mut config_json,config_dir);
    info!("normalize_all_path_value_config for gateway config.");
    Ok(config_json)
}

pub(crate) async fn run_server_tempalte_pkg(mut pkg: JsPkg, args: Vec<String>) -> ControlResult<String> {
    pkg.enable_fetch(false)
        .init_callback(move |engine| {
            engine.register_global_builtin_callable("currentDir".to_string(), 0, NativeFunction::from_copy_closure(|_, _, _| {
                Ok(JsValue::from(JsString::from(std::env::current_dir().unwrap_or(PathBuf::new()).to_string_lossy().to_string())))
            }))?;
            Ok(())
        });
    let output = pkg.run(args).await.map_err(into_cmd_err!(ControlErrorCode::Failed, "run pkg failed"))?;
    Ok(output)
}

//use buckyos_api::{*};
pub struct GatewayParams {
    pub keep_tunnel: Vec<String>,
}

pub struct GatewayFactory {
    stacks: StackManagerRef,
    global_process_chains: GlobalProcessChainsRef,
    server_factory: CyfsServerFactoryRef,
    servers: ServerManagerRef,

    stack_factory: CyfsStackFactoryRef,
    parser: GatewayConfigParserRef,

    connection_manager: ConnectionManagerRef,
    tunnel_manager: TunnelManager,

    //inner_service_factory: CyfsInnerServiceFactoryRef,
    //inner_service_manager: InnerServiceManagerRef,
    acme_mgr: AcmeCertManagerRef,
    limiter_manager: LimiterManagerRef,
    stat_manager: StatManagerRef,
    self_cert_mgr: SelfCertMgrRef,
    global_collection_manager: GlobalCollectionManagerRef,
    external_cmds: JsPkgManagerRef,
}

impl GatewayFactory {
    pub fn new(
        stacks: StackManagerRef,
        servers: ServerManagerRef,
        global_process_chains: GlobalProcessChainsRef,
        connection_manager: ConnectionManagerRef,
        tunnel_manager: TunnelManager,
        acme_mgr: AcmeCertManagerRef,
        limiter_manager: LimiterManagerRef,
        stat_manager: StatManagerRef,
        self_cert_mgr: SelfCertMgrRef,
        global_collection_manager: GlobalCollectionManagerRef,
        external_cmds: JsPkgManagerRef,
        parser: GatewayConfigParserRef, ) -> Self {
        Self {
            stacks,
            servers,
            global_process_chains,
            connection_manager,
            tunnel_manager,
            stack_factory: Arc::new(CyfsStackFactory::new()),
            server_factory: Arc::new(CyfsServerFactory::new()),
            acme_mgr,
            limiter_manager,
            stat_manager,
            self_cert_mgr,
            global_collection_manager,
            external_cmds,
            parser,
        }
    }

    pub fn register_stack_factory(&self, protocol: StackProtocol, factory: Arc<dyn StackFactory>) {
        self.stack_factory.register(protocol, factory);
    }

    pub fn register_server_factory<T: Into<String>>(&self, server_type: T, factory: Arc<dyn ServerFactory>) {
        self.server_factory.register(server_type.into(), factory);
    }


    pub async fn create_gateway(
        &self,
        config: GatewayConfig,
    ) -> Result<Gateway> {
        for process_chain_config in config.global_process_chains.iter() {
            let process_chain = process_chain_config.create_process_chain()?;
            self.global_process_chains.add_process_chain(Arc::new(process_chain))?;
        }

        let stack_manager = self.stacks.clone();
        for stack_config in config.stacks.iter() {
            let stack = self.stack_factory.create(stack_config.clone()).await?;
            stack_manager.add_stack(stack)?;
        }

        for server_config in config.servers.iter() {
            let servers = self.server_factory.create(server_config.clone()).await?;
            for server in servers.into_iter() {
                self.servers.add_server(server)?;
            }
        }

        Ok(Gateway {
            config: Arc::new(Mutex::new(config)),
            stack_manager,
            tunnel_manager: self.tunnel_manager.clone(),
            server_manager: self.servers.clone(),
            parser: self.parser.clone(),
            global_process_chains: self.global_process_chains.clone(),
            connection_manager: self.connection_manager.clone(),
            acme_mgr: self.acme_mgr.clone(),
            stack_factory: self.stack_factory.clone(),
            server_factory: self.server_factory.clone(),
            limiter_manager: self.limiter_manager.clone(),
            stat_manager: self.stat_manager.clone(),
            self_cert_mgr: self.self_cert_mgr.clone(),
            global_collection_manager: self.global_collection_manager.clone(),
            external_cmds: self.external_cmds.clone(),
        })
    }
}

pub struct Gateway {
    config: Arc<Mutex<GatewayConfig>>,
    stack_manager: StackManagerRef,
    tunnel_manager: TunnelManager,
    server_manager: ServerManagerRef,
    parser: GatewayConfigParserRef,
    global_process_chains: GlobalProcessChainsRef,
    connection_manager: ConnectionManagerRef,
    acme_mgr: AcmeCertManagerRef,
    stack_factory: CyfsStackFactoryRef,
    server_factory: CyfsServerFactoryRef,
    limiter_manager: LimiterManagerRef,
    stat_manager: StatManagerRef,
    self_cert_mgr: SelfCertMgrRef,
    global_collection_manager: GlobalCollectionManagerRef,
    external_cmds: JsPkgManagerRef,
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

        if let Err(e) = self.stack_manager.start().await {
            error!("start stack manager failed, err:{}", e);
        }

        if !params.keep_tunnel.is_empty() {
            self.keep_tunnels(params.keep_tunnel).await;
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
        let mut raw_config = config.raw_config.clone();
        let control_config: Value = serde_yaml_ng::from_str(GATEWAY_CONTROL_SERVER_CONFIG)
            .unwrap_or(Value::Null);
        if let Some(stacks) = control_config.get("stacks").and_then(|v| v.as_object()) {
            if let Some(raw_stacks) = raw_config.get_mut("stacks").and_then(|v| v.as_object_mut()) {
                for key in stacks.keys() {
                    raw_stacks.remove(key);
                }
            }
        }
        if let Some(servers) = control_config.get("servers").and_then(|v| v.as_object()) {
            if let Some(raw_servers) = raw_config.get_mut("servers").and_then(|v| v.as_object_mut()) {
                for key in servers.keys() {
                    raw_servers.remove(key);
                }
            }
        }
        Ok(raw_config)
    }

    pub fn get_config(&self, config_type: &str, config_id: &str) -> Result<Value> {
        if config_id == GATEWAY_CONTROL_SERVER_KEY {
            return Err(anyhow::Error::new(cmd_err!(
            ControlErrorCode::ConfigNotFound,
            "Config not found: {}", config_id,
        )));
        }
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
            "global_process_chain" => {
                for chain in config.global_process_chains.iter() {
                    if chain.id == config_id {
                        return Ok(serde_json::to_value(chain)?);
                    }
                }
            }
            _ => {
                warn!("Invalid config type: {}", config_type);
                Err(cmd_err!(
                    ControlErrorCode::InvalidConfigType,
                    "Invalid config type: {}", config_type,
                ))?;
            }
        }

        Err(anyhow::Error::new(cmd_err!(
            ControlErrorCode::ConfigNotFound,
            "Config not found: {}", config_id,
        )))
    }

    pub fn get_config_by_id(&self, id: &str) -> Result<Value> {
        let id_list = id.split(':').collect::<Vec<&str>>();
        if id_list.len() < 2 {
            return Err(anyhow!("Invalid config id: {}", id));
        }
        let config_type = id_list[0];
        if config_type != "stack" && config_type != "server" {
            return Err(anyhow!("Invalid config type: {}", config_type));
        }
        let config_id = id_list[1];
        if config_id == GATEWAY_CONTROL_SERVER_KEY {
            return Err(anyhow!(cmd_err!(
                ControlErrorCode::ConfigNotFound,
                "Config not found: {}", config_id,
            )));
        }

        let mut index = 2;
        if id_list.len() > index && id_list[index] == "hook_point" {
            index += 1;
        }
        let chain_id = if id_list.len() > index { Some(id_list[index]) } else { None };
        index += 1;
        if id_list.len() > index && id_list[index] == "blocks" {
            index += 1;
        }
        let block_id = if id_list.len() > index { Some(id_list[index]) } else { None };
        if id_list.len() > index + 1 {
            return Err(anyhow!("Invalid config id: {}", id));
        }

        let config_value = self.get_config(config_type, config_id)?;
        if chain_id.is_none() {
            return Ok(config_value);
        }

        let target_config = config_value
            .as_object()
            .ok_or_else(|| anyhow!("Invalid {} config: {}", config_type, config_id))?;
        if config_type == "server" {
            let server_type = target_config
                .get("type")
                .and_then(|value| value.as_str())
                .ok_or_else(|| anyhow!("Invalid server type: null"))?;
            if server_type != "http" && server_type != "dns" {
                return Err(anyhow!("Invalid server type: {}", server_type));
            }
        }

        let hook_point = target_config
            .get("hook_point")
            .ok_or_else(|| anyhow!("hook_point not found"))?
            .as_object()
            .ok_or_else(|| anyhow!("hook_point must be an object"))?;
        let chain_id = chain_id.unwrap();
        let chain_value = hook_point
            .get(chain_id)
            .ok_or_else(|| anyhow!("chain not found: {}", chain_id))?;
        if block_id.is_none() {
            return Ok(chain_value.clone());
        }

        let chain_obj = chain_value
            .as_object()
            .ok_or_else(|| anyhow!("chain {} must be an object", chain_id))?;
        let blocks = chain_obj
            .get("blocks")
            .ok_or_else(|| anyhow!("blocks not found in chain {}", chain_id))?
            .as_object()
            .ok_or_else(|| anyhow!("blocks must be an object"))?;
        let block_id = block_id.unwrap();
        let block_value = blocks
            .get(block_id)
            .ok_or_else(|| anyhow!("block not found: {}", block_id))?;
        Ok(block_value.clone())
    }

    fn add_rule_to_config(mut raw_config: Value, id: &str, rule: &str) -> Result<Value> {
        let id_list = id.split(':').collect::<Vec<&str>>();
        if id_list.len() < 2 {
            return Err(anyhow!("Invalid config id: {}", id));
        }
        let config_type = id_list[0];
        if config_type != "stack" && config_type != "server" {
            return Err(anyhow!("Invalid config type: {}", config_type));
        }
        let config_id = id_list[1];
        if config_id == GATEWAY_CONTROL_SERVER_KEY {
            return Err(anyhow!(cmd_err!(
                ControlErrorCode::ConfigNotFound,
                "Config not found: {}", config_id,
            )));
        }

        let mut index = 2;
        if id_list.len() > index && id_list[index] == "hook_point" {
            index += 1;
        }

        let chain_id = if id_list.len() > index { Some(id_list[index]) } else { None };
        index += 1;
        if id_list.len() > index && id_list[index] == "blocks" {
            index += 1;
        }
        let block_id = if id_list.len() > index { Some(id_list[index]) } else { None };

        let root_key = if config_type == "stack" {
            "stacks"
        } else if config_type == "server" {
            "servers"
        } else {
            return Err(anyhow!("Invalid config type: {}", config_type));
        };
        let stacks_or_servers = raw_config
            .get_mut(root_key)
            .ok_or_else(|| anyhow!("{} not found in config", root_key))?;
        let stacks_or_servers = stacks_or_servers
            .as_object_mut()
            .ok_or_else(|| anyhow!("{} must be an object", root_key))?;
        let target_config = stacks_or_servers
            .get_mut(config_id)
            .ok_or_else(|| anyhow!("Config not found: {}", config_id))?;
        let target_config = target_config
            .as_object_mut()
            .ok_or_else(|| anyhow!("Invalid {} config: {}", config_type, config_id))?;
        if config_type == "server" {
            let server_type = target_config.get("type");
            if server_type != Some(&Value::String("http".to_string())) && server_type != Some(&Value::String("dns".to_string())) {
                return Err(anyhow!("Invalid server type: {}", server_type.unwrap()));
            }
        }

        let hook_point_value = target_config
            .entry("hook_point")
            .or_insert_with(|| Value::Object(Map::new()));
        let hook_point = hook_point_value
            .as_object_mut()
            .ok_or_else(|| anyhow!("hook_point must be an object"))?;

        let chain_id = if let Some(chain_id) = chain_id {
            chain_id.to_string()
        } else {
            Self::gen_unique_id(hook_point)
        };

        let chain_priority = Self::next_highest_priority(hook_point);
        let chain_value = hook_point.entry(chain_id.clone()).or_insert_with(|| {
            let mut map = Map::new();
            map.insert("priority".to_string(), Value::Number(chain_priority.into()));
            map.insert("blocks".to_string(), Value::Object(Map::new()));
            Value::Object(map)
        });
        let chain_value = chain_value
            .as_object_mut()
            .ok_or_else(|| anyhow!("chain {} must be an object", chain_id))?;
        let blocks_value = chain_value
            .entry("blocks")
            .or_insert_with(|| Value::Object(Map::new()));
        let blocks = blocks_value
            .as_object_mut()
            .ok_or_else(|| anyhow!("blocks must be an object"))?;

        match block_id {
            None => {
                let block_priority = Self::next_highest_priority(blocks);
                let new_block_id = Self::gen_unique_id(blocks);
                let mut block = Map::new();
                block.insert("priority".to_string(), Value::Number(block_priority.into()));
                block.insert("block".to_string(), Value::String(rule.to_string()));
                blocks.insert(new_block_id, Value::Object(block));
            }
            Some(block_id) => {
                if let Some(block_value) = blocks.get_mut(block_id) {
                    let block_value = block_value
                        .as_object_mut()
                        .ok_or_else(|| anyhow!("block {} must be an object", block_id))?;
                    let old_rule = block_value
                        .get("block")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let mut new_rule = rule.to_string();
                    if !rule.ends_with('\n') {
                        new_rule.push('\n');
                    }
                    new_rule.push_str(old_rule);
                    block_value.insert("block".to_string(), Value::String(new_rule));
                } else {
                    let block_priority = Self::next_highest_priority(blocks);
                    let mut block = Map::new();
                    block.insert("priority".to_string(), Value::Number(block_priority.into()));
                    block.insert("block".to_string(), Value::String(rule.to_string()));
                    blocks.insert(block_id.to_string(), Value::Object(block));
                }
            }
        }
        Ok(raw_config)
    }

    fn gen_unique_id(map: &Map<String, Value>) -> String {
        loop {
            let candidate: String = rng()
                .sample_iter(&Alphanumeric)
                .take(5)
                .map(char::from)
                .collect();
            let candidate = candidate.to_lowercase();
            if !map.contains_key(&candidate) {
                return candidate;
            }
        }
    }

    fn gen_unique_id_with_prefix(map: &Map<String, Value>, prefix: &str) -> String {
        loop {
            let candidate: String = rng()
                .sample_iter(&Alphanumeric)
                .take(5)
                .map(char::from)
                .collect();
            let candidate = format!("{}{}", prefix, candidate.to_lowercase());
            if !map.contains_key(&candidate) {
                return candidate;
            }
        }
    }

    fn next_highest_priority(map: &Map<String, Value>) -> i32 {
        let mut min_priority: Option<i32> = None;
        for value in map.values() {
            if let Some(obj) = value.as_object() {
                if let Some(p) = obj.get("priority").and_then(|v| v.as_i64()) {
                    let p = p as i32;
                    min_priority = Some(min_priority.map_or(p, |m| m.min(p)));
                }
            }
        }
        min_priority.map(|p| p - 1).unwrap_or(1)
    }

    fn next_lowest_priority(map: &Map<String, Value>) -> i32 {
        let mut max_priority: Option<i32> = None;
        for value in map.values() {
            if let Some(obj) = value.as_object() {
                if let Some(p) = obj.get("priority").and_then(|v| v.as_i64()) {
                    let p = p as i32;
                    max_priority = Some(max_priority.map_or(p, |m| m.max(p)));
                }
            }
        }
        max_priority.map(|p| p + 1).unwrap_or(1)
    }

    fn insert_rule_to_config(mut raw_config: Value, id: &str, pos: i32, rule: &str) -> Result<Value> {
        let id_list = id.split(':').collect::<Vec<&str>>();
        if id_list.len() < 2 {
            return Err(anyhow!("Invalid config id: {}", id));
        }
        let config_type = id_list[0];
        if config_type != "stack" && config_type != "server" {
            return Err(anyhow!("Invalid config type: {}", config_type));
        }
        let config_id = id_list[1];
        if config_id == GATEWAY_CONTROL_SERVER_KEY {
            return Err(anyhow!(cmd_err!(
                ControlErrorCode::ConfigNotFound,
                "Config not found: {}", config_id,
            )));
        }

        let mut index = 2;
        if id_list.len() > index && id_list[index] == "hook_point" {
            index += 1;
        }
        let chain_id = if id_list.len() > index { Some(id_list[index]) } else { None };
        index += 1;
        if id_list.len() > index && id_list[index] == "blocks" {
            index += 1;
        }
        let block_id = if id_list.len() > index { Some(id_list[index]) } else { None };

        let root_key = if config_type == "stack" {
            "stacks"
        } else if config_type == "server" {
            "servers"
        } else {
            return Err(anyhow!("Invalid config type: {}", config_type));
        };
        let stacks_or_servers = raw_config
            .get_mut(root_key)
            .ok_or_else(|| anyhow!("{} not found in config", root_key))?;
        let stacks_or_servers = stacks_or_servers
            .as_object_mut()
            .ok_or_else(|| anyhow!("{} must be an object", root_key))?;
        let target_config = stacks_or_servers
            .get_mut(config_id)
            .ok_or_else(|| anyhow!("Config not found: {}", config_id))?;
        let target_config = target_config
            .as_object_mut()
            .ok_or_else(|| anyhow!("Invalid {} config: {}", config_type, config_id))?;

        if config_type == "server" {
            let server_type = target_config.get("type");
            if server_type != Some(&Value::String("http".to_string())) && server_type != Some(&Value::String("dns".to_string())) {
                return Err(anyhow!("Invalid server type: {}", server_type.unwrap()));
            }
        }

        let hook_point_value = target_config
            .entry("hook_point")
            .or_insert_with(|| Value::Object(Map::new()));
        let hook_point = hook_point_value
            .as_object_mut()
            .ok_or_else(|| anyhow!("hook_point must be an object"))?;

        let chain_id = if let Some(chain_id) = chain_id {
            chain_id.to_string()
        } else {
            Self::gen_unique_id(hook_point)
        };

        let chain_value = hook_point.entry(chain_id.clone()).or_insert_with(|| {
            let mut map = Map::new();
            map.insert("priority".to_string(), Value::Number(pos.into()));
            map.insert("blocks".to_string(), Value::Object(Map::new()));
            Value::Object(map)
        });
        let chain_value = chain_value
            .as_object_mut()
            .ok_or_else(|| anyhow!("chain {} must be an object", chain_id))?;
        let blocks_value = chain_value
            .entry("blocks")
            .or_insert_with(|| Value::Object(Map::new()));
        let blocks = blocks_value
            .as_object_mut()
            .ok_or_else(|| anyhow!("blocks must be an object"))?;

        match block_id {
            None => {
                let new_block_id = Self::gen_unique_id(blocks);
                let mut block = Map::new();
                block.insert("priority".to_string(), Value::Number(pos.into()));
                block.insert("block".to_string(), Value::String(rule.to_string()));
                blocks.insert(new_block_id, Value::Object(block));
            }
            Some(block_id) => {
                if let Some(block_value) = blocks.get_mut(block_id) {
                    let block_value = block_value
                        .as_object_mut()
                        .ok_or_else(|| anyhow!("block {} must be an object", block_id))?;
                    let content = block_value
                        .get("block")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let mut lines: Vec<String> = content.split('\n').map(|s| s.to_string()).collect();
                    let insert_at = if pos <= 0 { 0 } else { (pos as usize).saturating_sub(1) };
                    let insert_at = insert_at.min(lines.len());
                    let mut new_lines: Vec<String> = rule.split('\n').map(|s| s.to_string()).collect();
                    lines.splice(insert_at..insert_at, new_lines.drain(..));
                    let new_content = lines.join("\n");
                    block_value.insert("block".to_string(), Value::String(new_content));
                } else {
                    let mut block = Map::new();
                    block.insert("priority".to_string(), Value::Number(pos.into()));
                    block.insert("block".to_string(), Value::String(rule.to_string()));
                    blocks.insert(block_id.to_string(), Value::Object(block));
                }
            }
        }
        Ok(raw_config)
    }

    fn move_rule_in_config(mut raw_config: Value, id: &str, new_pos: i32) -> Result<Value> {
        let id_list = id.split(':').collect::<Vec<&str>>();
        if id_list.len() < 3 {
            return Err(anyhow!("Invalid id: {}", id));
        }
        let config_type = id_list[0];
        if config_type != "stack" && config_type != "server" {
            return Err(anyhow!("Invalid config type: {}", config_type));
        }
        let config_id = id_list[1];
        if config_id == GATEWAY_CONTROL_SERVER_KEY {
            return Err(anyhow!(cmd_err!(
                ControlErrorCode::ConfigNotFound,
                "Config not found: {}", config_id,
            )));
        }

        let mut index = 2;
        if id_list.len() > index && id_list[index] == "hook_point" {
            index += 1;
        }
        let chain_id = id_list.get(index).ok_or_else(|| anyhow!("Missing chain id in {}", id))?;
        index += 1;
        if id_list.len() > index && id_list[index] == "blocks" {
            index += 1;
        }
        let block_id = id_list.get(index).copied();
        let line_spec = if id_list.len() > index + 1 {
            Some(id_list[index + 1..].join(":"))
        } else {
            None
        };
        if line_spec.is_some() && block_id.is_none() {
            return Err(anyhow!("line position can only be used when block id is specified"));
        }

        let root_key = if config_type == "stack" {
            "stacks"
        } else if config_type == "server" {
            "servers"
        } else {
            return Err(anyhow!("Invalid config type: {}", config_type));
        };
        let stacks_or_servers = raw_config
            .get_mut(root_key)
            .ok_or_else(|| anyhow!("{} not found in config", root_key))?;
        let stacks_or_servers = stacks_or_servers
            .as_object_mut()
            .ok_or_else(|| anyhow!("{} must be an object", root_key))?;
        let target_config = stacks_or_servers
            .get_mut(config_id)
            .ok_or_else(|| anyhow!("Config not found: {}", config_id))?;
        let target_config = target_config
            .as_object_mut()
            .ok_or_else(|| anyhow!("Invalid {} config: {}", config_type, config_id))?;

        if config_type == "server" {
            let server_type = target_config.get("type");
            if server_type != Some(&Value::String("http".to_string())) && server_type != Some(&Value::String("dns".to_string())) {
                return Err(anyhow!("Invalid server type: {}", server_type.unwrap()));
            }
        }

        let hook_point_value = target_config
            .get_mut("hook_point")
            .ok_or_else(|| anyhow!("hook_point not found"))?;
        let hook_point = hook_point_value
            .as_object_mut()
            .ok_or_else(|| anyhow!("hook_point must be an object"))?;

        let chain_value = hook_point
            .get_mut(*chain_id)
            .ok_or_else(|| anyhow!("chain not found: {}", chain_id))?;
        let chain_obj = chain_value
            .as_object_mut()
            .ok_or_else(|| anyhow!("chain {} must be an object", chain_id))?;

        if let Some(block_id) = block_id {
            let blocks_value = chain_obj
                .get_mut("blocks")
                .ok_or_else(|| anyhow!("blocks not found in chain {}", chain_id))?;
            let blocks = blocks_value
                .as_object_mut()
                .ok_or_else(|| anyhow!("blocks must be an object"))?;

            let block_value = blocks
                .get_mut(block_id)
                .ok_or_else(|| anyhow!("block not found: {}", block_id))?;
            let block_obj = block_value
                .as_object_mut()
                .ok_or_else(|| anyhow!("block {} must be an object", block_id))?;

            if let Some(line_spec) = line_spec {
                let block_content = block_obj
                    .get("block")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow!("block content not found"))?;
                let ends_with_newline = block_content.ends_with('\n');
                let mut lines: Vec<String> = block_content.lines().map(|s| s.to_string()).collect();
                if lines.is_empty() {
                    return Err(anyhow!("block content is empty"));
                }

                let (start_str, end_str) = if let Some((s, e)) = line_spec.split_once(':') {
                    (s, e)
                } else {
                    (line_spec.as_str(), line_spec.as_str())
                };
                let start: usize = start_str.parse().map_err(|_| anyhow!("invalid line spec {}", line_spec))?;
                let end: usize = end_str.parse().map_err(|_| anyhow!("invalid line spec {}", line_spec))?;
                if start == 0 || end == 0 || start > end || end > lines.len() {
                    return Err(anyhow!("line range out of bounds"));
                }
                let start_idx = start - 1;
                let end_idx = end - 1;
                let mut moving: Vec<String> = lines.drain(start_idx..=end_idx).collect();
                let remaining_len = lines.len();
                let mut insert_at: usize = if new_pos <= 0 {
                    0
                } else {
                    (new_pos as usize).saturating_sub(1)
                };
                if insert_at > remaining_len {
                    insert_at = remaining_len;
                }
                lines.splice(insert_at..insert_at, moving.drain(..));
                let mut new_content = lines.join("\n");
                if ends_with_newline && !new_content.is_empty() && !new_content.ends_with('\n') {
                    new_content.push('\n');
                }
                block_obj.insert("block".to_string(), Value::String(new_content));
            } else {
                block_obj.insert("priority".to_string(), Value::Number(new_pos.into()));
            }
        } else {
            chain_obj.insert("priority".to_string(), Value::Number(new_pos.into()));
        }

        Ok(raw_config)
    }

    fn normalize_protocol(protocol: Option<&str>) -> Result<String> {
        let protocol = protocol.unwrap_or("tcp").to_lowercase();
        if protocol != "tcp" && protocol != "udp" {
            return Err(anyhow!("Invalid protocol: {}", protocol));
        }
        Ok(protocol)
    }

    fn parse_local_endpoint(local: &str) -> Result<(String, String, u16)> {
        if local.contains(':') {
            let mut parts = local.splitn(2, ':');
            let ip = parts
                .next()
                .ok_or_else(|| anyhow!("invalid local: {}", local))?
                .trim();
            let port = parts
                .next()
                .ok_or_else(|| anyhow!("invalid local: {}", local))?
                .trim();
            let ip_addr: std::net::IpAddr = ip.parse().map_err(|_| anyhow!("invalid ip: {}", ip))?;
            let port: u16 = port.parse().map_err(|_| anyhow!("invalid port: {}", local))?;
            Ok((format!("{}:{}", ip_addr, port), ip_addr.to_string(), port))
        } else {
            let port: u16 = local.trim().parse().map_err(|_| anyhow!("invalid port: {}", local))?;
            let ip = "0.0.0.0".to_string();
            Ok((format!("{}:{}", ip, port), ip, port))
        }
    }

    fn parse_target_endpoint(target: &str) -> Result<String> {
        let mut parts = target.splitn(2, ':');
        let ip = parts
            .next()
            .ok_or_else(|| anyhow!("invalid target: {}", target))?
            .trim();
        let port = parts
            .next()
            .ok_or_else(|| anyhow!("invalid target: {}", target))?
            .trim();
        let ip_addr: std::net::IpAddr = ip.parse().map_err(|_| anyhow!("invalid target ip: {}", ip))?;
        let port: u16 = port.parse().map_err(|_| anyhow!("invalid target port: {}", target))?;
        Ok(format!("{}:{}", ip_addr, port))
    }

    fn dispatch_stack_id(protocol: &str, local_ip: &str, local_port: u16) -> String {
        let ip_for_id = local_ip.replace('.', "_");
        format!("dispatch_{}_{}_{}", protocol, ip_for_id, local_port)
    }

    fn router_block_id(uri: &str, target: &str) -> String {
        let mut sha = sha2::Sha256::new();
        sha.update(uri.as_bytes());
        sha.update(b"|");
        sha.update(target.as_bytes());
        let digest = sha.finalize();
        let hex = format!("{:x}", digest);
        format!("router_{}", &hex[..12])
    }

    fn router_priority(uri: &str) -> i32 {
        // smaller number => higher priority
        if let Some(stripped) = uri.strip_prefix('=') {
            return -3_000_000 - stripped.len() as i32;
        }
        if uri.starts_with('~') {
            return -2_000_000;
        }
        if uri.ends_with("/*") || uri.ends_with('/') {
            let prefix = uri.trim_end_matches('*').trim_end_matches('/');
            return -1_000_000 - prefix.len() as i32;
        }
        -500_000 - uri.len() as i32
    }

    fn ensure_http_server(raw_config: &mut Value, id: &str) -> Result<()> {
        let servers = raw_config
            .get_mut("servers")
            .ok_or_else(|| anyhow!("servers not found in config"))?
            .as_object_mut()
            .ok_or_else(|| anyhow!("servers must be an object"))?;

        if let Some(existing) = servers.get(id) {
            let obj = existing
                .as_object()
                .ok_or_else(|| anyhow!("server {} must be an object", id))?;
            let server_type = obj
                .get("type")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("server {} type not found", id))?;
            if server_type != "http" {
                return Err(anyhow!("server {} must be http", id));
            }
            return Ok(());
        }

        let mut hook_point = Map::new();
        let mut main = Map::new();
        main.insert("priority".to_string(), Value::Number(1.into()));
        main.insert("blocks".to_string(), Value::Object(Map::new()));
        hook_point.insert("main".to_string(), Value::Object(main));

        let mut server = Map::new();
        server.insert("type".to_string(), Value::String("http".to_string()));
        server.insert("hook_point".to_string(), Value::Object(hook_point));
        servers.insert(id.to_string(), Value::Object(server));
        Ok(())
    }

    fn ensure_dir_server(raw_config: &mut Value, root_path: &str) -> Result<String> {
        let servers = raw_config
            .get_mut("servers")
            .ok_or_else(|| anyhow!("servers not found in config"))?
            .as_object_mut()
            .ok_or_else(|| anyhow!("servers must be an object"))?;
        let mut sha = sha2::Sha256::new();
        sha.update(root_path.as_bytes());
        let digest = sha.finalize();
        let hex = format!("{:x}", digest);
        let server_id = format!("router_dir_{}", &hex[..12]);

        if !servers.contains_key(&server_id) {
            let mut server = Map::new();
            server.insert("type".to_string(), Value::String("dir".to_string()));
            server.insert("root_path".to_string(), Value::String(root_path.to_string()));
            servers.insert(server_id.clone(), Value::Object(server));
        }
        Ok(server_id)
    }

    fn parse_router_server_id(id: &str) -> Result<String> {
        if let Some(rest) = id.strip_prefix("server:") {
            if rest.is_empty() {
                return Err(anyhow!("router id must target server config: {}", id));
            }
            return Ok(rest.to_string());
        }
        Ok(id.to_string())
    }

    fn find_router_server_by_block(raw_config: &Value, block_id: &str) -> Result<String> {
        let servers = raw_config
            .get("servers")
            .and_then(|v| v.as_object())
            .ok_or_else(|| anyhow!("servers not found"))?;
        for (server_id, server) in servers.iter() {
            if server
                .get("type")
                .and_then(|v| v.as_str())
                != Some("http")
            {
                continue;
            }
            if let Some(hook_point) = server.get("hook_point").and_then(|v| v.as_object()) {
                if let Some(main) = hook_point.get("main").and_then(|v| v.as_object()) {
                    if let Some(blocks) = main.get("blocks").and_then(|v| v.as_object()) {
                        if blocks.contains_key(block_id) {
                            return Ok(server_id.clone());
                        }
                    }
                }
            }
        }
        Err(anyhow!("router rule not found: {}", block_id))
    }

    fn parse_router_uri(uri: &str) -> Result<(String, String)> {
        if uri.is_empty() {
            return Err(anyhow!("uri cannot be empty"));
        }
        if uri.starts_with('=') {
            let u = uri.trim_start_matches('=').to_string();
            return Ok(("exact".to_string(), u));
        }
        if uri.starts_with('~') {
            let u = uri.trim_start_matches('~').to_string();
            return Ok(("regex".to_string(), u));
        }
        if uri.ends_with("/*") || uri.ends_with('*') {
            let u = uri.trim_end_matches('*').to_string();
            return Ok(("wildcard".to_string(), u));
        }
        Ok(("prefix".to_string(), uri.to_string()))
    }

    fn normalize_regex_uri(uri: &str) -> String {
        if uri.ends_with("/*") {
            let trimmed = uri.trim_end_matches("/*");
            return format!("{}(.*)$", trimmed);
        }
        uri.to_string()
    }

    fn build_router_rule(
        raw_config: &mut Value,
        uri: &str,
        target: &str,
    ) -> Result<(String, i32, String, Option<String>)> {
        let (kind, uri_value) = Self::parse_router_uri(uri)?;
        let regex_value = if kind == "regex" {
            Self::normalize_regex_uri(&uri_value)
        } else {
            uri_value.clone()
        };
        let block_id = Self::router_block_id(uri, target);
        let priority = Self::router_priority(uri);

        // match part
        let match_cmd = match kind.as_str() {
            "exact" => format!(r#"eq ${{REQ.path}} "{}""#, uri_value),
            "regex" => format!(r#"match-reg ${{REQ.path}} "{}""#, regex_value),
            "wildcard" => format!(r#"match ${{REQ.path}} "{}*""#, uri_value),
            _ => format!(r#"starts-with ${{REQ.path}} "{}""#, uri_value),
        };

        let target_trim = target.trim();
        let is_http = target_trim.starts_with("http://") || target_trim.starts_with("https://");
        let is_unix = target_trim.starts_with("unix:");
        let has_scheme = target_trim.contains("://");
        let is_local = target_trim.starts_with('/') || (!is_http && !is_unix && !has_scheme);

        if !is_http && !is_unix && !is_local {
            return Err(anyhow!("invalid target: {}", target));
        }

        let mut actions: Vec<String> = Vec::new();
        actions.push(match_cmd);

        let mut forward_to = None;
        let mut call_server = None;
        let mut rewrite = None;

        if is_local {
            let mut dir_root = target_trim.to_string();
            if kind == "regex" {
                if let Some(idx) = target_trim.find('$') {
                    dir_root = target_trim[..idx].trim_end_matches('/').to_string();
                    let placeholder = target_trim[idx..].trim_start_matches('/');
                    if !placeholder.is_empty() {
                        let replace = format!("/{}", placeholder);
                        rewrite = Some(format!(
                            r#"rewrite ${{REQ.path}} "{}" "{}""#,
                            regex_value, replace
                        ));
                    }
                }
            } else {
                if target_trim.ends_with('/') {
                    rewrite = if uri_value.ends_with('/') {
                        Some(format!(
                            r#"rewrite ${{REQ.path}} "{}*" "/*""#,
                            uri_value,
                        ))
                    } else {
                        Some(format!(
                            r#"rewrite ${{REQ.path}} "{}*" "*""#,
                            uri_value,
                        ))
                    };
                }
            }
            let dir_root_had_trailing_slash = dir_root.ends_with('/');
            if dir_root.is_empty() {
                dir_root.push('/');
            }
            if !Path::new(&dir_root).is_absolute() {
                let base_dir = std::env::current_dir()
                    .map_err(|e| anyhow!("get current dir failed: {}", e))?;
                let mut resolved = base_dir.join(&dir_root).to_string_lossy().to_string();
                if dir_root_had_trailing_slash
                    && !resolved.ends_with(std::path::MAIN_SEPARATOR)
                    && !resolved.ends_with('/')
                {
                    resolved.push(std::path::MAIN_SEPARATOR);
                }
                dir_root = resolved;
            }
            let server_id = Self::ensure_dir_server(raw_config, &dir_root)?;
            call_server = Some(server_id);
        } else if is_http || is_unix {
            if is_http {
                let url = Url::parse(target_trim)
                    .map_err(|e| anyhow!("invalid target url {}: {}", target_trim, e))?;
                let host = url.host_str().ok_or_else(|| anyhow!("invalid target url host"))?;
                let port = url.port().map(|p| format!(":{}", p)).unwrap_or_default();
                let base = format!("{}://{}{}", url.scheme(), host, port);
                forward_to = Some(base);
                let path = url.path().to_string();
                if kind == "regex" {
                    if let Some(_) = path.find('$') {
                        rewrite = Some(format!(
                            r#"rewrite ${{REQ.path}} "{}" "{}""#,
                            regex_value, path
                        ));
                    } else if path.len() > 1 {
                        if path.ends_with('/') {
                            rewrite = Some(format!(
                                r#"rewrite ${{REQ.path}} "/*" "{}*""#,
                                path
                            ));
                        } else {
                            rewrite = Some(format!(
                                r#"rewrite ${{REQ.path}} "/*" "{}/*""#,
                                path
                            ));
                        }
                    }
                } else {
                    let trailing_slash = target_trim.ends_with('/');

                    if trailing_slash {
                        let from_pattern = if kind == "wildcard" {
                            format!("{}*", uri_value)
                        } else if kind == "exact" {
                            uri_value.clone()
                        } else if kind == "regex" {
                            uri_value.clone()
                        } else {
                            format!("{}*", uri_value)
                        };
                        let replace = if kind == "regex" {
                            path.to_string()
                        } else {
                            let mut p = path.trim_end_matches('/').to_string();
                            if uri_value.ends_with('/') {
                                if !p.starts_with('/') {
                                    p.insert(0, '/');
                                }
                                if !p.ends_with('/') {
                                    p.push('/');
                                }
                            }
                            format!("{}*", p.trim_end_matches('*'))
                        };
                        if kind == "regex" {
                            rewrite = Some(format!(r#"rewrite-reg ${{REQ.path}} "{}" "{}""#, regex_value, replace));
                        } else {
                            rewrite = Some(format!(r#"rewrite ${{REQ.path}} "{}" "{}""#, from_pattern, replace));
                        }
                    }
                }
            } else {
                forward_to = Some(target_trim.to_string());
            }
        }

        if let Some(rw) = rewrite {
            actions.push(rw);
        }
        if let Some(server_id) = &call_server {
            actions.push(format!(r#"call-server {}"#, server_id));
        } else if let Some(forward) = forward_to {
            actions.push(format!(r#"forward "{}""#, forward));
        }

        let rule = format!("{};", actions.join(" && "));
        Ok((rule, priority, block_id, call_server))
    }

    fn add_dispatch_to_config(
        mut raw_config: Value,
        local: &str,
        target: &str,
        protocol: Option<&str>,
    ) -> Result<(Value, String)> {
        let protocol = Self::normalize_protocol(protocol)?;
        let (local_bind, local_ip, local_port) = Self::parse_local_endpoint(local)?;
        let target = Self::parse_target_endpoint(target)?;
        let stack_id = Self::dispatch_stack_id(&protocol, &local_ip, local_port);

        let stacks = raw_config
            .get_mut("stacks")
            .ok_or_else(|| anyhow!("stacks not found in config"))?;
        let stacks = stacks
            .as_object_mut()
            .ok_or_else(|| anyhow!("stacks must be an object"))?;
        if stacks.contains_key(&stack_id) {
            return Err(anyhow!("dispatch already exists: {}", stack_id));
        }

        let mut block = Map::new();
        block.insert("block".to_string(), Value::String(format!("forward \"{}:///{}\";", protocol, target)));
        let mut blocks = Map::new();
        blocks.insert("default".to_string(), Value::Object(block));

        let mut main = Map::new();
        main.insert("priority".to_string(), Value::Number(1.into()));
        main.insert("blocks".to_string(), Value::Object(blocks));

        let mut hook_point = Map::new();
        hook_point.insert("main".to_string(), Value::Object(main));

        let mut stack = Map::new();
        stack.insert("bind".to_string(), Value::String(local_bind));
        stack.insert("protocol".to_string(), Value::String(protocol.clone()));
        stack.insert("hook_point".to_string(), Value::Object(hook_point));

        stacks.insert(stack_id.clone(), Value::Object(stack));
        Ok((raw_config, stack_id))
    }

    fn remove_dispatch_from_config(
        mut raw_config: Value,
        local: &str,
        protocol: Option<&str>,
    ) -> Result<(Value, String)> {
        let protocol = Self::normalize_protocol(protocol)?;
        let (_, local_ip, local_port) = Self::parse_local_endpoint(local)?;
        let stack_id = Self::dispatch_stack_id(&protocol, &local_ip, local_port);

        let stacks = raw_config
            .get_mut("stacks")
            .ok_or_else(|| anyhow!("stacks not found in config"))?;
        let stacks = stacks
            .as_object_mut()
            .ok_or_else(|| anyhow!("stacks must be an object"))?;
        if stacks.remove(&stack_id).is_none() {
            return Err(anyhow!("dispatch not found: {}", stack_id));
        }

        Ok((raw_config, stack_id))
    }

    fn add_router_to_config(
        mut raw_config: Value,
        router_id: Option<&str>,
        uri: &str,
        target: &str,
    ) -> Result<(Value, String, Option<String>)> {
        let server_id = if let Some(id) = router_id {
            Self::parse_router_server_id(id)?
        } else {
            let default_map = Map::new();
            let server_map = raw_config
                .get("servers")
                .and_then(|v| v.as_object())
                .unwrap_or_else(|| &default_map);
            Self::gen_unique_id_with_prefix(server_map, "router_")
        };

        Self::ensure_http_server(&mut raw_config, &server_id)?;
        let (rule, priority, block_id, _maybe_dir) = Self::build_router_rule(&mut raw_config, uri, target)?;

        let servers = raw_config
            .get_mut("servers")
            .and_then(|v| v.as_object_mut())
            .unwrap();
        let server = servers.get_mut(&server_id).unwrap().as_object_mut().unwrap();
        let hook_point = server
            .entry("hook_point")
            .or_insert_with(|| Value::Object(Map::new()))
            .as_object_mut()
            .ok_or_else(|| anyhow!("hook_point must be object"))?;
        let main = hook_point
            .entry("main")
            .or_insert_with(|| {
                let mut m = Map::new();
                m.insert("priority".to_string(), Value::Number(1.into()));
                m.insert("blocks".to_string(), Value::Object(Map::new()));
                Value::Object(m)
            })
            .as_object_mut()
            .ok_or_else(|| anyhow!("main must be object"))?;
        let blocks = main
            .entry("blocks")
            .or_insert_with(|| Value::Object(Map::new()))
            .as_object_mut()
            .ok_or_else(|| anyhow!("blocks must be object"))?;

        if blocks.contains_key(&block_id) {
            return Err(anyhow!("router rule already exists: {}", block_id));
        }

        let mut block_obj = Map::new();
        block_obj.insert("priority".to_string(), Value::Number(priority.into()));
        block_obj.insert("block".to_string(), Value::String(rule));
        blocks.insert(block_id, Value::Object(block_obj));

        Ok((raw_config, server_id, _maybe_dir))
    }

    fn remove_router_from_config(
        mut raw_config: Value,
        router_id: Option<&str>,
        uri: &str,
        target: &str,
    ) -> Result<(Value, String)> {
        let block_id = Self::router_block_id(uri, target);
        let server_id = if let Some(id) = router_id {
            Self::parse_router_server_id(id)?
        } else {
            Self::find_router_server_by_block(&raw_config, &block_id)?
        };
        let servers = raw_config
            .get_mut("servers")
            .ok_or_else(|| anyhow!("servers not found"))?
            .as_object_mut()
            .ok_or_else(|| anyhow!("servers must be object"))?;
        let server = servers
            .get_mut(&server_id)
            .ok_or_else(|| anyhow!("server not found: {}", server_id))?
            .as_object_mut()
            .ok_or_else(|| anyhow!("server {} must be object", server_id))?;
        let server_type = server
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if server_type != "http" {
            return Err(anyhow!("server {} must be http", server_id));
        }
        let hook_point = server
            .get_mut("hook_point")
            .ok_or_else(|| anyhow!("hook_point not found in server {}", server_id))?
            .as_object_mut()
            .ok_or_else(|| anyhow!("hook_point must be object"))?;
        let main = hook_point
            .get_mut("main")
            .ok_or_else(|| anyhow!("main hook point not found"))?
            .as_object_mut()
            .ok_or_else(|| anyhow!("main must be object"))?;
        let blocks = main
            .get_mut("blocks")
            .ok_or_else(|| anyhow!("blocks not found"))?
            .as_object_mut()
            .ok_or_else(|| anyhow!("blocks must be object"))?;

        if blocks.remove(&block_id).is_none() {
            return Err(anyhow!("router rule not found"));
        }

        if blocks.is_empty() {
            hook_point.remove("main");
        }
        if hook_point.is_empty() && server_id.starts_with("router_") {
            servers.remove(&server_id);
        }

        Ok((raw_config, server_id))
    }

    fn set_rule_in_config(mut raw_config: Value, id: &str, rule: &str) -> Result<Value> {
        let id_list = id.split(':').collect::<Vec<&str>>();
        if id_list.len() < 3 {
            return Err(anyhow!("Invalid id: {}", id));
        }
        let config_type = id_list[0];
        if config_type != "stack" && config_type != "server" {
            return Err(anyhow!("Invalid config type: {}", config_type));
        }
        let config_id = id_list[1];
        if config_id == GATEWAY_CONTROL_SERVER_KEY {
            return Err(anyhow!(cmd_err!(
                ControlErrorCode::ConfigNotFound,
                "Config not found: {}", config_id,
            )));
        }

        let mut index = 2;
        if id_list.len() > index && id_list[index] == "hook_point" {
            index += 1;
        }
        let chain_id = id_list.get(index).ok_or_else(|| anyhow!("Missing chain id in {}", id))?;
        index += 1;
        if id_list.len() > index && id_list[index] == "blocks" {
            index += 1;
        }
        let block_id = id_list.get(index).copied();
        let line_spec = if id_list.len() > index + 1 {
            Some(id_list[index + 1..].join(":"))
        } else {
            None
        };
        if line_spec.is_some() && block_id.is_none() {
            return Err(anyhow!("line position can only be used when block id is specified"));
        }

        let root_key = match config_type {
            "stack" => "stacks",
            "server" => "servers",
            _ => return Err(anyhow!("Invalid config type: {}", config_type)),
        };
        let stacks_or_servers = raw_config
            .get_mut(root_key)
            .ok_or_else(|| anyhow!("{} not found in config", root_key))?;
        let stacks_or_servers = stacks_or_servers
            .as_object_mut()
            .ok_or_else(|| anyhow!("{} must be an object", root_key))?;
        let target_config = stacks_or_servers
            .get_mut(config_id)
            .ok_or_else(|| anyhow!("Config not found: {}", config_id))?;
        let target_config = target_config
            .as_object_mut()
            .ok_or_else(|| anyhow!("Invalid {} config: {}", config_type, config_id))?;

        if config_type == "server" {
            let server_type = target_config
                .get("type")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("Invalid server type"))?;
            if server_type != "http" && server_type != "dns" {
                return Err(anyhow!("Invalid server type: {}", server_type));
            }
        }

        let hook_point_value = target_config
            .get_mut("hook_point")
            .ok_or_else(|| anyhow!("hook_point not found"))?;
        let hook_point = hook_point_value
            .as_object_mut()
            .ok_or_else(|| anyhow!("hook_point must be an object"))?;

        let chain_value = hook_point
            .get_mut(*chain_id)
            .ok_or_else(|| anyhow!("chain not found: {}", chain_id))?;
        let chain_obj = chain_value
            .as_object_mut()
            .ok_or_else(|| anyhow!("chain {} must be an object", chain_id))?;

        if let Some(block_id) = block_id {
            let blocks_value = chain_obj
                .get_mut("blocks")
                .ok_or_else(|| anyhow!("blocks not found in chain {}", chain_id))?;
            let blocks = blocks_value
                .as_object_mut()
                .ok_or_else(|| anyhow!("blocks must be an object"))?;

            let block_value = blocks
                .get_mut(block_id)
                .ok_or_else(|| anyhow!("block not found: {}", block_id))?;
            let block_obj = block_value
                .as_object_mut()
                .ok_or_else(|| anyhow!("block {} must be an object", block_id))?;

            if let Some(line_spec) = line_spec {
                let block_content = block_obj
                    .get("block")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow!("block content not found"))?;
                let ends_with_newline = block_content.ends_with('\n');
                let mut lines: Vec<String> = block_content.lines().map(|s| s.to_string()).collect();
                if lines.is_empty() {
                    return Err(anyhow!("block content is empty"));
                }

                let (start_str, end_str) = if let Some((s, e)) = line_spec.split_once(':') {
                    (s, e)
                } else {
                    (line_spec.as_str(), line_spec.as_str())
                };
                let start: usize = start_str.parse().map_err(|_| anyhow!("invalid line spec {}", line_spec))?;
                let end: usize = end_str.parse().map_err(|_| anyhow!("invalid line spec {}", line_spec))?;
                if start == 0 || end == 0 || start > end || end > lines.len() {
                    return Err(anyhow!("line range out of bounds"));
                }
                let start_idx = start - 1;
                let end_idx = end - 1;
                let new_lines: Vec<String> = rule.split('\n').map(|s| s.to_string()).collect();
                lines.splice(start_idx..=end_idx, new_lines.into_iter());
                let mut new_content = lines.join("\n");
                if ends_with_newline && !new_content.is_empty() && !new_content.ends_with('\n') {
                    new_content.push('\n');
                }
                block_obj.insert("block".to_string(), Value::String(new_content));
            } else {
                block_obj.insert("block".to_string(), Value::String(rule.to_string()));
            }
        } else {
            let blocks_value = chain_obj
                .get_mut("blocks")
                .ok_or_else(|| anyhow!("blocks not found in chain {}", chain_id))?;
            let blocks = blocks_value
                .as_object_mut()
                .ok_or_else(|| anyhow!("blocks must be an object"))?;

            let (new_block_id, priority) = if let Some((first_id, value)) = blocks.iter().next() {
                let priority = value
                    .as_object()
                    .and_then(|v| v.get("priority"))
                    .and_then(|v| v.as_i64())
                    .unwrap_or(1);
                (first_id.clone(), priority as i32)
            } else {
                let priority = 1;
                ("default".to_string(), priority)
            };
            let mut new_block = Map::new();
            new_block.insert("priority".to_string(), Value::Number(priority.into()));
            new_block.insert("block".to_string(), Value::String(rule.to_string()));
            blocks.clear();
            blocks.insert(new_block_id, Value::Object(new_block));
        }

        Ok(raw_config)
    }

    fn append_rule_to_config(mut raw_config: Value, id: &str, rule: &str) -> Result<Value> {
        let id_list = id.split(':').collect::<Vec<&str>>();
        if id_list.len() < 2 {
            return Err(anyhow!("Invalid config id: {}", id));
        }
        let config_type = id_list[0];
        if config_type != "stack" && config_type != "server" {
            return Err(anyhow!("Invalid config type: {}", config_type));
        }
        let config_id = id_list[1];
        if config_id == GATEWAY_CONTROL_SERVER_KEY {
            return Err(anyhow!(cmd_err!(
                ControlErrorCode::ConfigNotFound,
                "Config not found: {}", config_id,
            )));
        }

        let mut index = 2;
        if id_list.len() > index && id_list[index] == "hook_point" {
            index += 1;
        }
        let chain_id = if id_list.len() > index { Some(id_list[index]) } else { None };
        index += 1;
        if id_list.len() > index && id_list[index] == "blocks" {
            index += 1;
        }
        let block_id = if id_list.len() > index { Some(id_list[index]) } else { None };

        let root_key = if config_type == "stack" {
            "stacks"
        } else if config_type == "server" {
            "servers"
        } else {
            return Err(anyhow!("Invalid config type: {}", config_type));
        };
        let stacks_or_servers = raw_config
            .get_mut(root_key)
            .ok_or_else(|| anyhow!("{} not found in config", root_key))?;
        let stacks_or_servers = stacks_or_servers
            .as_object_mut()
            .ok_or_else(|| anyhow!("{} must be an object", root_key))?;
        let target_config = stacks_or_servers
            .get_mut(config_id)
            .ok_or_else(|| anyhow!("Config not found: {}", config_id))?;
        let target_config = target_config
            .as_object_mut()
            .ok_or_else(|| anyhow!("Invalid {} config: {}", config_type, config_id))?;

        if config_type == "server" {
            let server_type = target_config.get("type");
            if server_type != Some(&Value::String("http".to_string())) && server_type != Some(&Value::String("dns".to_string())) {
                return Err(anyhow!("Invalid server type: {}", server_type.unwrap()));
            }
        }

        let hook_point_value = target_config
            .entry("hook_point")
            .or_insert_with(|| Value::Object(Map::new()));
        let hook_point = hook_point_value
            .as_object_mut()
            .ok_or_else(|| anyhow!("hook_point must be an object"))?;

        let chain_id = if let Some(chain_id) = chain_id {
            chain_id.to_string()
        } else {
            Self::gen_unique_id(hook_point)
        };

        let chain_priority = Self::next_lowest_priority(hook_point);
        let chain_value = hook_point.entry(chain_id.clone()).or_insert_with(|| {
            let mut map = Map::new();
            map.insert("priority".to_string(), Value::Number(chain_priority.into()));
            map.insert("blocks".to_string(), Value::Object(Map::new()));
            Value::Object(map)
        });
        let chain_value = chain_value
            .as_object_mut()
            .ok_or_else(|| anyhow!("chain {} must be an object", chain_id))?;
        let blocks_value = chain_value
            .entry("blocks")
            .or_insert_with(|| Value::Object(Map::new()));
        let blocks = blocks_value
            .as_object_mut()
            .ok_or_else(|| anyhow!("blocks must be an object"))?;

        match block_id {
            None => {
                let block_priority = Self::next_lowest_priority(blocks);
                let new_block_id = Self::gen_unique_id(blocks);
                let mut block = Map::new();
                block.insert("priority".to_string(), Value::Number(block_priority.into()));
                block.insert("block".to_string(), Value::String(rule.to_string()));
                blocks.insert(new_block_id, Value::Object(block));
            }
            Some(block_id) => {
                if let Some(block_value) = blocks.get_mut(block_id) {
                    let block_value = block_value
                        .as_object_mut()
                        .ok_or_else(|| anyhow!("block {} must be an object", block_id))?;
                    let old_rule = block_value
                        .get("block")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let mut new_rule = old_rule.to_string();
                    if !new_rule.is_empty() && !new_rule.ends_with('\n') {
                        new_rule.push('\n');
                    }
                    new_rule.push_str(rule);
                    block_value.insert("block".to_string(), Value::String(new_rule));
                } else {
                    let block_priority = Self::next_lowest_priority(blocks);
                    let mut block = Map::new();
                    block.insert("priority".to_string(), Value::Number(block_priority.into()));
                    block.insert("block".to_string(), Value::String(rule.to_string()));
                    blocks.insert(block_id.to_string(), Value::Object(block));
                }
            }
        }
        Ok(raw_config)
    }

    pub async fn add_rule(&self, id: &str, rule: &str) -> Result<()> {
        let id_list = id.split(':').collect::<Vec<&str>>();
        if id_list.len() < 2 {
            return Err(anyhow!("Invalid config id: {}", id));
        }
        let config_type = id_list[0];
        let config_id = id_list[1];
        if config_id == GATEWAY_CONTROL_SERVER_KEY {
            return Err(anyhow!(cmd_err!(
                ControlErrorCode::ConfigNotFound,
                "Config not found: {}", config_id,
            )));
        }

        let raw_config = {
            self.config.lock().unwrap().raw_config.clone()
        };
        let raw_config = Self::add_rule_to_config(raw_config, id, rule)?;
        let gateway_config = self.parser
            .parse(raw_config)
            .map_err(|e| anyhow!("parse config failed: {}", e))?;
        match config_type {
            "stack" => {
                let new_stack_config = gateway_config
                    .stacks
                    .iter()
                    .find(|s| s.id() == config_id)
                    .cloned()
                    .ok_or_else(|| anyhow!("stack config not found after parse: {}", config_id))?;

                if let Some(stack) = self.stack_manager.get_stack(config_id) {
                    stack.update_config(new_stack_config.clone()).await?;
                }
            }
            "server" => {
                let new_server_config = gateway_config
                    .servers
                    .iter()
                    .find(|s| s.id() == config_id)
                    .cloned()
                    .ok_or_else(|| anyhow!("server config not found after parse: {}", config_id))?;

                let new_servers = self.server_factory.create(new_server_config.clone()).await?;
                for server in new_servers.into_iter() {
                    self.server_manager.replace_server(server);
                }
            }
            _ => {
                return Err(anyhow!(cmd_err!(
                    ControlErrorCode::InvalidConfigType,
                    "Invalid config type: {}", config_type,
                )));
            }
        }

        let mut guard = self.config.lock().unwrap();
        *guard = gateway_config;
        Ok(())
    }

    pub async fn append_rule(&self, id: &str, rule: &str) -> Result<()> {
        let id_list = id.split(':').collect::<Vec<&str>>();
        if id_list.len() < 2 {
            return Err(anyhow!("Invalid config id: {}", id));
        }
        let config_type = id_list[0];
        let config_id = id_list[1];
        if config_id == GATEWAY_CONTROL_SERVER_KEY {
            return Err(anyhow!(cmd_err!(
                ControlErrorCode::ConfigNotFound,
                "Config not found: {}", config_id,
            )));
        }

        let raw_config = {
            self.config.lock().unwrap().raw_config.clone()
        };
        let raw_config = Self::append_rule_to_config(raw_config, id, rule)?;
        let gateway_config = self.parser
            .parse(raw_config)
            .map_err(|e| anyhow!("parse config failed: {}", e))?;
        match config_type {
            "stack" => {
                let new_stack_config = gateway_config
                    .stacks
                    .iter()
                    .find(|s| s.id() == config_id)
                    .cloned()
                    .ok_or_else(|| anyhow!("stack config not found after parse: {}", config_id))?;

                if let Some(stack) = self.stack_manager.get_stack(config_id) {
                    stack.update_config(new_stack_config.clone()).await?;
                }
            }
            "server" => {
                let new_server_config = gateway_config
                    .servers
                    .iter()
                    .find(|s| s.id() == config_id)
                    .cloned()
                    .ok_or_else(|| anyhow!("server config not found after parse: {}", config_id))?;

                let new_servers = self.server_factory.create(new_server_config.clone()).await?;
                for server in new_servers.into_iter() {
                    self.server_manager.replace_server(server);
                }
            }
            _ => {
                return Err(anyhow!(cmd_err!(
                    ControlErrorCode::InvalidConfigType,
                    "Invalid config type: {}", config_type,
                )));
            }
        }

        let mut guard = self.config.lock().unwrap();
        *guard = gateway_config;
        Ok(())
    }

    pub async fn insert_rule(&self, id: &str, pos: i32, rule: &str) -> Result<()> {
        let id_list = id.split(':').collect::<Vec<&str>>();
        if id_list.len() < 2 {
            return Err(anyhow!("Invalid config id: {}", id));
        }
        let config_type = id_list[0];
        let config_id = id_list[1];
        if config_id == GATEWAY_CONTROL_SERVER_KEY {
            return Err(anyhow!(cmd_err!(
                ControlErrorCode::ConfigNotFound,
                "Config not found: {}", config_id,
            )));
        }

        let raw_config = {
            self.config.lock().unwrap().raw_config.clone()
        };
        let raw_config = Self::insert_rule_to_config(raw_config, id, pos, rule)?;
        let gateway_config = self.parser
            .parse(raw_config)
            .map_err(|e| anyhow!("parse config failed: {}", e))?;
        match config_type {
            "stack" => {
                let new_stack_config = gateway_config
                    .stacks
                    .iter()
                    .find(|s| s.id() == config_id)
                    .cloned()
                    .ok_or_else(|| anyhow!("stack config not found after parse: {}", config_id))?;

                if let Some(stack) = self.stack_manager.get_stack(config_id) {
                    stack.update_config(new_stack_config.clone()).await?;
                }
            }
            "server" => {
                let new_server_config = gateway_config
                    .servers
                    .iter()
                    .find(|s| s.id() == config_id)
                    .cloned()
                    .ok_or_else(|| anyhow!("server config not found after parse: {}", config_id))?;

                let new_servers = self.server_factory.create(new_server_config.clone()).await?;
                for server in new_servers.into_iter() {
                    self.server_manager.replace_server(server);
                }
            }
            _ => {
                return Err(anyhow!(cmd_err!(
                    ControlErrorCode::InvalidConfigType,
                    "Invalid config type: {}", config_type,
                )));
            }
        }

        let mut guard = self.config.lock().unwrap();
        *guard = gateway_config;
        Ok(())
    }

    pub async fn move_rule(&self, id: &str, new_pos: i32) -> Result<()> {
        let id_list = id.split(':').collect::<Vec<&str>>();
        if id_list.len() < 3 {
            return Err(anyhow!("Invalid rule id: {}", id));
        }
        let config_type = id_list[0];
        let config_id = id_list[1];
        if config_id == GATEWAY_CONTROL_SERVER_KEY {
            return Err(anyhow!(cmd_err!(
                ControlErrorCode::ConfigNotFound,
                "Config not found: {}", config_id,
            )));
        }

        let raw_config = {
            self.config.lock().unwrap().raw_config.clone()
        };
        let raw_config = Self::move_rule_in_config(raw_config, id, new_pos)?;
        let gateway_config = self.parser
            .parse(raw_config)
            .map_err(|e| anyhow!("parse config failed: {}", e))?;

        match config_type {
            "stack" => {
                let new_stack_config = gateway_config
                    .stacks
                    .iter()
                    .find(|s| s.id() == config_id)
                    .cloned()
                    .ok_or_else(|| anyhow!("stack config not found after parse: {}", config_id))?;

                if let Some(stack) = self.stack_manager.get_stack(config_id) {
                    stack.update_config(new_stack_config.clone()).await?;
                }
            }
            "server" => {
                let new_server_config = gateway_config
                    .servers
                    .iter()
                    .find(|s| s.id() == config_id)
                    .cloned()
                    .ok_or_else(|| anyhow!("server config not found after parse: {}", config_id))?;

                let new_servers = self.server_factory.create(new_server_config.clone()).await?;
                for server in new_servers.into_iter() {
                    self.server_manager.replace_server(server);
                }
            }
            _ => {
                return Err(anyhow!(cmd_err!(
                    ControlErrorCode::InvalidConfigType,
                    "Invalid config type: {}", config_type,
                )));
            }
        }

        let mut guard = self.config.lock().unwrap();
        *guard = gateway_config;
        Ok(())
    }

    pub async fn add_dispatch(&self, local: &str, target: &str, protocol: Option<&str>) -> Result<()> {
        let raw_config = {
            self.config.lock().unwrap().raw_config.clone()
        };
        let (raw_config, stack_id) = Self::add_dispatch_to_config(raw_config, local, target, protocol)?;
        let gateway_config = self.parser
            .parse(raw_config)
            .map_err(|e| anyhow!("parse config failed: {}", e))?;

        let new_stack_config = gateway_config
            .stacks
            .iter()
            .find(|s| s.id() == stack_id)
            .cloned()
            .ok_or_else(|| anyhow!("stack config not found after parse: {}", stack_id))?;
        let new_stack = self.stack_factory.create(new_stack_config.clone()).await?;
        self.stack_manager.add_stack(new_stack.clone())?;
        new_stack.start().await?;

        let mut guard = self.config.lock().unwrap();
        *guard = gateway_config;
        Ok(())
    }

    pub async fn add_router(&self, server_id: Option<&str>, uri: &str, target: &str) -> Result<String> {
        let raw_config = {
            self.config.lock().unwrap().raw_config.clone()
        };
        let (raw_config, server_id, dir_server) = Self::add_router_to_config(raw_config, server_id, uri, target)?;
        let gateway_config = self.parser
            .parse(raw_config)
            .map_err(|e| anyhow!("parse config failed: {}", e))?;

        if let Some(dir_server) = dir_server {
            let new_server_config = gateway_config
                .servers
                .iter()
                .find(|s| s.id() == dir_server)
                .cloned()
                .ok_or_else(|| anyhow!("server config not found after parse: {}", server_id))?;

            let new_servers = self.server_factory.create(new_server_config.clone()).await?;
            for server in new_servers.into_iter() {
                self.server_manager.replace_server(server);
            }
        }

        let new_server_config = gateway_config
            .servers
            .iter()
            .find(|s| s.id() == server_id)
            .cloned()
            .ok_or_else(|| anyhow!("server config not found after parse: {}", server_id))?;

        let new_servers = self.server_factory.create(new_server_config.clone()).await?;
        for server in new_servers.into_iter() {
            self.server_manager.replace_server(server);
        }

        let mut guard = self.config.lock().unwrap();
        *guard = gateway_config;
        Ok(server_id)
    }

    pub async fn remove_router(&self, server_id: Option<&str>, uri: &str, target: &str) -> Result<()> {
        let raw_config = {
            self.config.lock().unwrap().raw_config.clone()
        };
        let (raw_config, removed_server_id) = Self::remove_router_from_config(raw_config, server_id, uri, target)?;
        let gateway_config = self.parser
            .parse(raw_config)
            .map_err(|e| anyhow!("parse config failed: {}", e))?;

        if gateway_config
            .servers
            .iter()
            .any(|s| s.id() == removed_server_id)
        {
            let new_server_config = gateway_config
                .servers
                .iter()
                .find(|s| s.id() == removed_server_id)
                .cloned()
                .ok_or_else(|| anyhow!("server config not found after parse"))?;
            let new_servers = self.server_factory.create(new_server_config.clone()).await?;
            for server in new_servers.into_iter() {
                self.server_manager.replace_server(server);
            }
        } else {
            self.server_manager.remove_server(&removed_server_id);
        }

        let mut guard = self.config.lock().unwrap();
        *guard = gateway_config;
        Ok(())
    }

    pub async fn remove_dispatch(&self, local: &str, protocol: Option<&str>) -> Result<()> {
        let raw_config = {
            self.config.lock().unwrap().raw_config.clone()
        };
        let (raw_config, stack_id) = Self::remove_dispatch_from_config(raw_config, local, protocol)?;
        let gateway_config = self.parser
            .parse(raw_config)
            .map_err(|e| anyhow!("parse config failed: {}", e))?;

        self.stack_manager.remove(stack_id.as_str());

        let mut guard = self.config.lock().unwrap();
        *guard = gateway_config;
        Ok(())
    }

    pub async fn set_rule(&self, id: &str, rule: &str) -> Result<()> {
        let id_list = id.split(':').collect::<Vec<&str>>();
        if id_list.len() < 3 {
            return Err(anyhow!("Invalid rule id: {}", id));
        }
        let config_type = id_list[0];
        let config_id = id_list[1];
        if config_id == GATEWAY_CONTROL_SERVER_KEY {
            return Err(anyhow!(cmd_err!(
                ControlErrorCode::ConfigNotFound,
                "Config not found: {}", config_id,
            )));
        }

        let raw_config = {
            self.config.lock().unwrap().raw_config.clone()
        };
        let raw_config = Self::set_rule_in_config(raw_config, id, rule)?;
        let gateway_config = self.parser
            .parse(raw_config)
            .map_err(|e| anyhow!("parse config failed: {}", e))?;

        match config_type {
            "stack" => {
                let new_stack_config = gateway_config
                    .stacks
                    .iter()
                    .find(|s| s.id() == config_id)
                    .cloned()
                    .ok_or_else(|| anyhow!("stack config not found after parse: {}", config_id))?;

                if let Some(stack) = self.stack_manager.get_stack(config_id) {
                    stack.update_config(new_stack_config.clone()).await?;
                }
            }
            "server" => {
                let new_server_config = gateway_config
                    .servers
                    .iter()
                    .find(|s| s.id() == config_id)
                    .cloned()
                    .ok_or_else(|| anyhow!("server config not found after parse: {}", config_id))?;

                let new_servers = self.server_factory.create(new_server_config.clone()).await?;
                for server in new_servers.into_iter() {
                    self.server_manager.replace_server(server);
                }
            }
            _ => {
                return Err(anyhow!(cmd_err!(
                    ControlErrorCode::InvalidConfigType,
                    "Invalid config type: {}", config_type,
                )));
            }
        }

        let mut guard = self.config.lock().unwrap();
        *guard = gateway_config;
        Ok(())
    }

    fn remove_rule_from_config(mut raw_config: Value, id: &str) -> Result<Value> {
        let id_list = id.split(':').collect::<Vec<&str>>();
        if id_list.len() < 3 {
            return Err(anyhow!("Invalid rule id: {}", id));
        }
        let config_type = id_list[0];
        if config_type != "stack" && config_type != "server" {
            return Err(anyhow!("Invalid config type: {}", config_type));
        }
        let config_id = id_list[1];
        if config_id == GATEWAY_CONTROL_SERVER_KEY {
            return Err(anyhow!(cmd_err!(
                ControlErrorCode::ConfigNotFound,
                "Config not found: {}", config_id,
            )));
        }

        let mut index = 2;
        if id_list.len() > index && id_list[index] == "hook_point" {
            index += 1;
        }
        let chain_id = id_list.get(index).ok_or_else(|| anyhow!("Missing chain id in {}", id))?;
        index += 1;
        if id_list.len() > index && id_list[index] == "blocks" {
            index += 1;
        }
        let block_id = id_list.get(index).copied();

        let root_key = if config_type == "stack" {
            "stacks"
        } else if config_type == "server" {
            "servers"
        } else {
            return Err(anyhow!("Invalid config type: {}", config_type));
        };
        let stacks_or_servers = raw_config
            .get_mut(root_key)
            .ok_or_else(|| anyhow!("{} not found in config", root_key))?;
        let stacks_or_servers = stacks_or_servers
            .as_object_mut()
            .ok_or_else(|| anyhow!("{} must be an object", root_key))?;
        let target_config = stacks_or_servers
            .get_mut(config_id)
            .ok_or_else(|| anyhow!("Config not found: {}", config_id))?;
        let target_config = target_config
            .as_object_mut()
            .ok_or_else(|| anyhow!("Invalid {} config: {}", config_type, config_id))?;

        if config_type == "server" {
            let server_type = target_config.get("type");
            if server_type != Some(&Value::String("http".to_string())) && server_type != Some(&Value::String("dns".to_string())) {
                return Err(anyhow!("Invalid server type: {}", server_type.unwrap()));
            }
        }

        let hook_point_value = target_config
            .get_mut("hook_point")
            .ok_or_else(|| anyhow!("hook_point not found"))?;
        let hook_point = hook_point_value
            .as_object_mut()
            .ok_or_else(|| anyhow!("hook_point must be an object"))?;

        let only_chain = hook_point.len() == 1;
        let line_spec = if id_list.len() > index + 1 { Some(id_list[index + 1..].join(":")) } else { None };
        if line_spec.is_some() && block_id.is_none() {
            return Err(anyhow!("line range can only be used when block id is specified"));
        }

        let chain_value = hook_point
            .get_mut(*chain_id)
            .ok_or_else(|| anyhow!("chain not found: {}", chain_id))?;
        let chain_obj = chain_value
            .as_object_mut()
            .ok_or_else(|| anyhow!("chain {} must be an object", chain_id))?;
        let blocks_value = chain_obj
            .get_mut("blocks")
            .ok_or_else(|| anyhow!("blocks not found in chain {}", chain_id))?;
        let blocks = blocks_value
            .as_object_mut()
            .ok_or_else(|| anyhow!("blocks must be an object"))?;

        let only_block = blocks.len() == 1;
        if only_chain && only_block && block_id.is_some() && line_spec.is_none() {
            return Err(anyhow!("cannot delete the last block of the last chain"));
        }

        if let Some(block_id) = block_id {
            let block_value = blocks
                .get_mut(block_id)
                .ok_or_else(|| anyhow!("block not found: {}", block_id))?;
            let mut block_obj = block_value
                .as_object()
                .cloned()
                .ok_or_else(|| anyhow!("block {} must be an object", block_id))?;

            if let Some(line_spec) = line_spec.as_deref() {
                let block_content = block_obj
                    .get("block")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow!("block content not found"))?;
                let ends_with_newline = block_content.ends_with('\n');
                let mut lines: Vec<String> = block_content.lines().map(|s| s.to_string()).collect();
                if lines.is_empty() {
                    return Err(anyhow!("block content is empty"));
                }

                let (start_str, end_str) = if let Some((s, e)) = line_spec.split_once(':') {
                    (s, e)
                } else {
                    (line_spec, line_spec)
                };
                let start: usize = start_str.parse().map_err(|_| anyhow!("invalid line spec {}", line_spec))?;
                let end: usize = end_str.parse().map_err(|_| anyhow!("invalid line spec {}", line_spec))?;
                if start == 0 || end == 0 || start > end || end > lines.len() {
                    return Err(anyhow!("line range out of bounds"));
                }

                lines.drain((start - 1)..end);
                if lines.is_empty() {
                    if only_chain && only_block {
                        return Err(anyhow!("cannot delete the last block of the last chain"));
                    }
                    blocks.remove(block_id);
                } else {
                    let mut new_content = lines.join("\n");
                    if ends_with_newline && !new_content.is_empty() && !new_content.ends_with('\n') {
                        new_content.push('\n');
                    }
                    block_obj.insert("block".to_string(), Value::String(new_content));
                    *block_value = Value::Object(block_obj);
                }
            } else {
                blocks.remove(block_id);
            }
        } else {
            // remove entire chain
            if only_chain && only_block {
                return Err(anyhow!("cannot delete the last block of the last chain"));
            }
            hook_point.remove(*chain_id);
            return Ok(raw_config);
        }

        if blocks.is_empty() {
            hook_point.remove(*chain_id);
        }
        Ok(raw_config)
    }

    pub async fn remove_rule(&self, id: &str) -> Result<()> {
        let id_list = id.split(':').collect::<Vec<&str>>();
        if id_list.len() < 3 {
            return Err(anyhow!("Invalid rule id: {}", id));
        }
        let config_type = id_list[0];
        let config_id = id_list[1];
        if config_id == GATEWAY_CONTROL_SERVER_KEY {
            return Err(anyhow!(cmd_err!(
                ControlErrorCode::ConfigNotFound,
                "Config not found: {}", config_id,
            )));
        }

        let raw_config = {
            self.config.lock().unwrap().raw_config.clone()
        };
        let raw_config = Self::remove_rule_from_config(raw_config, id)?;
        let gateway_config = self.parser
            .parse(raw_config)
            .map_err(|e| anyhow!("parse config failed: {}", e))?;

        match config_type {
            "stack" => {
                let new_stack_config = gateway_config
                    .stacks
                    .iter()
                    .find(|s| s.id() == config_id)
                    .cloned()
                    .ok_or_else(|| anyhow!("stack config not found after parse: {}", config_id))?;

                if let Some(stack) = self.stack_manager.get_stack(config_id) {
                    stack.update_config(new_stack_config.clone()).await?;
                }
            }
            "server" => {
                let new_server_config = gateway_config
                    .servers
                    .iter()
                    .find(|s| s.id() == config_id)
                    .cloned()
                    .ok_or_else(|| anyhow!("server config not found after parse: {}", config_id))?;

                let new_servers = self.server_factory.create(new_server_config.clone()).await?;
                for server in new_servers.into_iter() {
                    self.server_manager.replace_server(server);
                }
            }
            _ => {
                return Err(anyhow!(cmd_err!(
                    ControlErrorCode::InvalidConfigType,
                    "Invalid config type: {}", config_type,
                )));
            }
        }

        let mut guard = self.config.lock().unwrap();
        *guard = gateway_config;
        Ok(())
    }

    pub async fn reload(&self, mut config: GatewayConfig) -> Result<()> {
        let old_config = {
            self.config.lock().unwrap().clone()
        };
        let mut new_process_chains = HashMap::new();
        for process_chain_config in config.global_process_chains.iter() {
            let process_chain = Arc::new(process_chain_config.create_process_chain()?);
            if new_process_chains.contains_key(process_chain.id()) {
                Err(cmd_err!(
                    ConfigErrorCode::AlreadyExists,
                    "Duplicated process chain: {}", process_chain.id(),
                ))?;
            }
            new_process_chains.insert(process_chain.id().to_string(), process_chain);
        }



        self.global_process_chains.clear_process_chains();
        for process_chain in new_process_chains.values() {
            self.global_process_chains.add_process_chain(process_chain.clone())?;
        }

        let mut new_servers = HashMap::new();
        for server_config in config.servers.iter() {
            let new_server = self.server_factory.create(server_config.clone()).await?;
            for server in new_server.into_iter() {
                if new_servers.contains_key(server.full_key().as_str()) {
                    Err(cmd_err!(
                    ConfigErrorCode::AlreadyExists,
                    "Duplicated server: {}", server.full_key(),
                ))?;
                }
                new_servers.insert(server.full_key(), server);
            }
        }



        for server in new_servers.values() {
            self.server_manager.replace_server(server.clone());
        }

        let mut success_stacks = Vec::new();
        for stack_config in config.stacks.iter() {
            if let Some(stack) = self.stack_manager.get_stack(stack_config.id().as_str()) {
                if let Err(e) = stack.update_config(stack_config.clone()).await {
                    if e.code() == StackErrorCode::BindUnmatched {
                        self.stack_manager.remove(stack_config.id().as_str());
                        let new_stack = match self.stack_factory.create(stack_config.clone()).await {
                            Ok(stack) => stack,
                            Err(e) => {
                                log::error!("Failed to create stack {}: {}", stack_config.id(), e);
                                continue;
                            }
                        };
                        if let Err(e) = self.stack_manager.add_stack(new_stack.clone()) {
                            log::error!("Failed to add stack {}: {}", stack_config.id(), e);
                        }
                        if let Err(e) = new_stack.start().await {
                            self.stack_manager.remove(stack_config.id().as_str());
                            log::error!("Failed to start stack {}: {}", stack_config.id(), e);
                        }
                        success_stacks.push(stack_config.clone());
                    } else {
                        log::error!("Failed to update stack {}: {}", stack_config.id(), e);
                        let config = self.config.lock().unwrap();
                        for old_config in config.stacks.iter() {
                            if old_config.id() == stack_config.id() {
                                success_stacks.push(old_config.clone());
                            }
                        }
                    }
                } else {
                    success_stacks.push(stack_config.clone());
                }
            } else {
                let new_stack = match self.stack_factory.create(stack_config.clone()).await {
                    Ok(stack) => stack,
                    Err(e) => {
                        log::error!("Failed to create stack {}: {}", stack_config.id(), e);
                        continue;
                    }
                };
                if let Err(e) = self.stack_manager.add_stack(new_stack.clone()) {
                    log::error!("Failed to add stack {}: {}", stack_config.id(), e);
                    continue;
                }
                if let Err(e) = new_stack.start().await {
                    self.stack_manager.remove(stack_config.id().as_str());
                    log::error!("Failed to start stack {}: {}", stack_config.id(), e);
                    continue;
                }
                success_stacks.push(stack_config.clone());
            }
        }

        config.stacks = success_stacks;
        self.stack_manager.retain(|id| {
            config.stacks.iter().any(|stack| stack.id() == id)
        });
        self.server_manager.retain(|id| {
            new_servers.contains_key(id)
        });

        if config.acme_config != old_config.acme_config {
            if config.acme_config.is_some() {
                let acme_config = config.acme_config.clone().unwrap();
                let mut cert_config = CertManagerConfig::default();
                let data_dir = get_buckyos_service_data_dir("cyfs_gateway").join("certs");
                let dns_provider_dir = get_buckyos_system_etc_dir().join("cyfs_gateway").join("acme_dns_provider");
                cert_config.keystore_path = data_dir.to_string_lossy().to_string();
                cert_config.account = acme_config.account;
                if acme_config.issuer.is_some() {
                    cert_config.acme_server = acme_config.issuer.unwrap();
                }
                cert_config.dns_providers = acme_config.dns_providers;
                if acme_config.check_interval.is_some() {
                    if let Some(check_interval) = chrono::Duration::new(acme_config.check_interval.unwrap() as i64, 0) {
                        cert_config.check_interval = check_interval;
                    }
                }

                if acme_config.renew_before_expiry.is_some() {
                    if let Some(renew_before_expiry) = chrono::Duration::new(acme_config.renew_before_expiry.unwrap() as i64, 0) {
                        cert_config.renew_before_expiry = renew_before_expiry;
                    }
                }
                cert_config.dns_provider_path = Some(dns_provider_dir.to_string_lossy().to_string());
                if let Err(e) = self.acme_mgr.update(cert_config).await {
                    log::error!("Failed to update acme manager: {}", e);
                }
            } else {
                let mut cert_config = CertManagerConfig::default();
                let data_dir = get_buckyos_service_data_dir("cyfs_gateway").join("certs");
                let dns_provider_dir = get_buckyos_system_etc_dir().join("cyfs_gateway").join("acme_dns_provider");
                cert_config.keystore_path = data_dir.to_string_lossy().to_string();
                cert_config.dns_provider_path = Some(dns_provider_dir.to_string_lossy().to_string());
                if let Err(e) = self.acme_mgr.update(cert_config).await {
                    log::error!("Failed to update acme manager: {}", e);
                }
            }
        }

        if config.limiters_config != old_config.limiters_config {
            if config.limiters_config.is_some() {
                let limiters_config = config.limiters_config.clone().unwrap();
                let mut limiter_set = HashSet::new();
                for limiter_config in limiters_config.iter() {
                    limiter_set.insert(limiter_config.id.clone());
                    if let Some(limiter) = self.limiter_manager.get_limiter(limiter_config.id.as_str()) {
                        if limiter.get_upper_limiter().map(|limiter| limiter.get_id().map(|v| v.to_string())) == Some(limiter_config.upper_limiter.clone()) {
                            limiter.set_speed(limiter_config.concurrent.map(|v| v as u32),
                                              limiter_config.download_speed.map(|v| v as u32),
                                              limiter_config.upload_speed.map(|v| v as u32));
                            continue;
                        }
                    }
                    if let Some(upper_limiter) = limiter_config.upper_limiter.clone() {
                        if self.limiter_manager.get_limiter(upper_limiter.as_str()).is_none() {
                            log::error!("Update limiter {} error: upper limiter {} not found", limiter_config.id, upper_limiter);
                        }
                    }
                    let _ = self.limiter_manager.new_limiter(limiter_config.id.clone(),
                                                             limiter_config.upper_limiter.clone(),
                                                             limiter_config.concurrent.map(|v| v as u32),
                                                             limiter_config.download_speed.map(|v| v as u32),
                                                             limiter_config.upload_speed.map(|v| v as u32));
                }

                self.limiter_manager.retain(|id, _| {
                    limiter_set.contains(id)
                });
            } else {
                self.limiter_manager.retain(|_, _| {
                    false
                });
            }
        }

        if config.tls_ca != old_config.tls_ca {
            if config.tls_ca.is_some() {
                let tls_ca = config.tls_ca.clone().unwrap();
                let data_dir = get_buckyos_service_data_dir("cyfs_gateway").join("self_certs");
                let mut self_cert_config = SelfCertConfig::default();
                self_cert_config.ca_path = Some(tls_ca.cert_path);
                self_cert_config.key_path = Some(tls_ca.key_path);
                self_cert_config.store_path = data_dir.to_string_lossy().to_string();
                if let Err(e) = self.self_cert_mgr.update(self_cert_config).await {
                    log::error!("Failed to update self cert manager: {}", e);
                }
            } else {
                let data_dir = get_buckyos_service_data_dir("cyfs_gateway").join("self_certs");
                let mut self_cert_config = SelfCertConfig::default();
                self_cert_config.store_path = data_dir.to_string_lossy().to_string();
                if let Err(e) = self.self_cert_mgr.update(self_cert_config).await {
                    log::error!("Failed to update self cert manager: {}", e);
                }
            }
        }

        *self.config.lock().unwrap() = config;
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
pub struct ExternalCmd {
    pub name: String,
    pub description: String,
}

#[derive(Deserialize)]
struct StartTemplateParams {
    template_id: String,
    args: Option<Vec<String>>,
}

pub struct GatewayCmdHandler {
    gateway: Mutex<Option<Arc<Gateway>>>,
    config_file: Option<PathBuf>,
    parser: GatewayConfigParserRef,
}

impl GatewayCmdHandler {
    pub fn new(config_file: Option<PathBuf>,
               parser: GatewayConfigParserRef, ) -> Arc<Self> {
        Arc::new(Self {
            gateway: Mutex::new(None),
            config_file,
            parser,
        })
    }

    pub fn set_gateway(&self, gateway: Arc<Gateway>) {
        self.gateway.lock().unwrap().replace(gateway);
    }

    fn get_gateway(&self) -> Option<Arc<Gateway>> {
        self.gateway.lock().unwrap().clone()
    }

    async fn start_template(&self, template_id: &str, args: Vec<String>) -> ControlResult<Value> {
        let gateway = self.get_gateway().ok_or_else(|| cmd_err!(ControlErrorCode::NoGateway, "gateway not init"))?;
        let current_config = {
            gateway.config.lock().unwrap().clone()
        };
        let pkg = gateway.external_cmds.get_pkg(template_id)
            .await
            .map_err(into_cmd_err!(ControlErrorCode::Failed, "get pkg failed"))?;
        let output = run_server_tempalte_pkg(pkg, args).await?;
        let template_config: Value = serde_json::from_str(output.as_str())
            .map_err(into_cmd_err!(ControlErrorCode::InvalidParams, "invalid template config"))?;
        let mut raw_config = current_config.raw_config.clone();
        merge(&mut raw_config, &template_config);
        let gateway_config = self.parser
            .parse(raw_config)
            .map_err(into_cmd_err!(ControlErrorCode::Failed, "parse config failed"))?;
        let existing_stack_ids: HashSet<String> = current_config.stacks.iter()
            .map(|stack| stack.id().to_string())
            .collect();
        let existing_server_ids: HashSet<String> = current_config.servers.iter()
            .map(|server| server.id().to_string())
            .collect();
        let existing_chain_ids: HashSet<String> = current_config.global_process_chains.iter()
            .map(|chain| chain.id.clone())
            .collect();

        let mut added_chains = Vec::new();
        for chain_config in gateway_config.global_process_chains.iter() {
            if existing_chain_ids.contains(chain_config.id.as_str()) {
                continue;
            }
            let process_chain = Arc::new(chain_config.create_process_chain()
                .map_err(|e| cmd_err!(ControlErrorCode::Failed, "create process chain {} failed: {}", chain_config.id, e))?);
            gateway.global_process_chains.add_process_chain(process_chain)
                .map_err(|e| cmd_err!(ControlErrorCode::Failed, "add process chain {} failed: {}", chain_config.id, e))?;
            added_chains.push(chain_config.clone());
        }

        let mut added_stacks = Vec::new();
        for stack_config in gateway_config.stacks.iter() {
            if existing_stack_ids.contains(stack_config.id().as_str()) {
                continue;
            }
            let new_stack = gateway.stack_factory.create(stack_config.clone()).await
                .map_err(|e| cmd_err!(ControlErrorCode::Failed, "create stack {} failed: {}", stack_config.id(), e))?;
            gateway.stack_manager.add_stack(new_stack.clone())
                .map_err(|e| cmd_err!(ControlErrorCode::Failed, "add stack {} failed: {}", stack_config.id(), e))?;
            if let Err(e) = new_stack.start().await {
                gateway.stack_manager.remove(stack_config.id().as_str());
                return Err(cmd_err!(ControlErrorCode::Failed, "start stack {} failed: {}", stack_config.id(), e));
            }
            added_stacks.push(stack_config.clone());
        }

        let mut added_servers = Vec::new();
        for server_config in gateway_config.servers.iter() {
            if existing_server_ids.contains(server_config.id().as_str()) {
                continue;
            }
            let new_servers = gateway.server_factory.create(server_config.clone()).await
                .map_err(|e| cmd_err!(ControlErrorCode::Failed, "create server {} failed: {}", server_config.id(), e))?;
            let mut added_any = false;
            for server in new_servers.into_iter() {
                if gateway.server_manager.get_server_by_key(server.full_key().as_str()).is_some() {
                    continue;
                }
                gateway.server_manager.add_server(server)
                    .map_err(|e| cmd_err!(ControlErrorCode::Failed, "add server failed: {}", e))?;
                added_any = true;
            }
            if added_any {
                added_servers.push(server_config.clone());
            }
        }

        let mut updated_config = current_config.clone();
        updated_config.raw_config = gateway_config.raw_config.clone();
        if !added_chains.is_empty() {
            updated_config.global_process_chains.extend(added_chains);
        }
        if !added_stacks.is_empty() {
            updated_config.stacks.extend(added_stacks);
        }
        if !added_servers.is_empty() {
            updated_config.servers.extend(added_servers);
        }
        *gateway.config.lock().unwrap() = updated_config;
        Ok(template_config)
    }

    async fn get_external_cmds(&self) -> ControlResult<Vec<ExternalCmd>> {
        let mut cmds = Vec::new();
        if let Some(gateway) = self.get_gateway() {
            let external_cmds = gateway.external_cmds.list_pkgs().await
                .map_err(into_cmd_err!(ControlErrorCode::Failed, "list pkgs failed"))?;
            for external_cmd in external_cmds {
                cmds.push(ExternalCmd {
                    name: external_cmd.name().to_string(),
                    description: external_cmd.description().to_string(),
                });
            }
        }
        Ok(cmds)
    }

    async fn get_external_cmd_help(&self, cmd: &str) -> ControlResult<String> {
        if let Some(gateway) = self.get_gateway() {
            let mut pkg = gateway.external_cmds.get_pkg(cmd)
                .await
                .map_err(into_cmd_err!(ControlErrorCode::Failed, "get pkg failed"))?;

            pkg.init_callback(move |engine| {
                engine.register_global_builtin_callable("currentDir".to_string(), 0, NativeFunction::from_copy_closure(|_, _, _| {
                    Ok(JsValue::from(JsString::from(std::env::current_dir().unwrap_or(PathBuf::new()).to_string_lossy().to_string())))
                }))?;
                Ok(())
            });

            pkg.help().await.map_err(into_cmd_err!(ControlErrorCode::Failed, "get help failed"))
        } else {
            Ok("".to_string())
        }
    }

    async fn save_config_to_device(&self, requested_path: Option<&str>) -> ControlResult<String> {
        let gateway = self.get_gateway().ok_or_else(|| cmd_err!(ControlErrorCode::NoGateway, "gateway not init"))?;
        let raw_config = {
            let config = gateway.config.lock().unwrap();
            strip_includes_field(config.raw_config.clone())
        };
        let save_path = resolve_save_path(requested_path);
        if let Some(parent) = save_path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(into_cmd_err!(ControlErrorCode::Failed, "create config dir failed"))?;
        }
        let content = serde_json::to_string_pretty(&raw_config)
            .map_err(into_cmd_err!(ControlErrorCode::SerializeFailed))?;
        tokio::fs::write(save_path.as_path(), content)
            .await
            .map_err(into_cmd_err!(ControlErrorCode::Failed, "write config failed"))?;
        Ok(save_path.to_string_lossy().to_string())
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
impl GatewayControlCmdHandler for GatewayCmdHandler {
    async fn handle(&self, method: &str, params: Value) -> ControlResult<Value> {
        let gateway = self.get_gateway();
        if gateway.is_none() {
            return Err(cmd_err!(ControlErrorCode::NoGateway, "gateway not init"));
        }
        let gateway = gateway.unwrap();
        match method {
            "get_config" => {
                if params.is_null() {
                    return gateway.get_all_config()
                        .map_err(|e| cmd_err!(ControlErrorCode::Failed, "{}", e));
                }
                let params = serde_json::from_value::<HashMap<String, String>>(params)
                    .map_err(into_cmd_err!(ControlErrorCode::InvalidParams))?;
                if let Some(id) = params.get("id") {
                    return gateway.get_config_by_id(id)
                        .map_err(|e| cmd_err!(ControlErrorCode::Failed, "{}", e));
                } else {
                    gateway.get_all_config()
                        .map_err(|e| cmd_err!(ControlErrorCode::Failed, "{}", e))
                }
            },
            "save_config" => {
                let requested_path = if params.is_null() {
                    None
                } else {
                    let params = serde_json::from_value::<HashMap<String, String>>(params)
                        .map_err(into_cmd_err!(ControlErrorCode::InvalidParams))?;
                    params.get("config").cloned()
                };
                let saved_path = self.save_config_to_device(requested_path.as_deref()).await?;
                Ok(Value::String(saved_path))
            },
            "remove_rule" => {
                let params = serde_json::from_value::<HashMap<String, String>>(params)
                    .map_err(into_cmd_err!(ControlErrorCode::InvalidParams))?;
                let id = params.get("id");
                if id.is_none() {
                    Err(cmd_err!(
                        ControlErrorCode::InvalidParams,
                        "Invalid params: id is None",
                    ))?;
                }
                gateway.remove_rule(id.unwrap()).await
                    .map_err(|e| cmd_err!(ControlErrorCode::Failed, "{}", e))?;
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
                Ok(serde_json::to_value(conn_infos).map_err(into_cmd_err!(ControlErrorCode::SerializeFailed))?)
            }
            "add_rule" => {
                let params = serde_json::from_value::<HashMap<String, String>>(params)
                    .map_err(into_cmd_err!(ControlErrorCode::InvalidParams))?;
                let id = params.get("id");
                let rule = params.get("rule");
                if id.is_none() || rule.is_none() {
                    Err(cmd_err!(
                        ControlErrorCode::InvalidParams,
                        "Invalid params: id or rule is None",
                    ))?;
                }
                gateway.add_rule(
                    id.unwrap(),
                    rule.unwrap(),
                ).await
                    .map_err(|e| cmd_err!(ControlErrorCode::Failed, "{}", e))?;
                Ok(Value::String("ok".to_string()))
            }
            "add_dispatch" => {
                let params = serde_json::from_value::<HashMap<String, String>>(params)
                    .map_err(into_cmd_err!(ControlErrorCode::InvalidParams))?;
                let local = params.get("local");
                let target = params.get("target");
                let protocol = params.get("protocol").map(|s| s.as_str());
                if local.is_none() || target.is_none() {
                    Err(cmd_err!(
                        ControlErrorCode::InvalidParams,
                        "Invalid params: local or target is None",
                    ))?;
                }
                gateway.add_dispatch(local.unwrap(), target.unwrap(), protocol).await
                    .map_err(|e| cmd_err!(ControlErrorCode::Failed, "{}", e))?;
                Ok(Value::String("ok".to_string()))
            }
            "remove_dispatch" => {
                let params = serde_json::from_value::<HashMap<String, String>>(params)
                    .map_err(into_cmd_err!(ControlErrorCode::InvalidParams))?;
                let local = params.get("local");
                let protocol = params.get("protocol").map(|s| s.as_str());
                if local.is_none() {
                    Err(cmd_err!(
                        ControlErrorCode::InvalidParams,
                        "Invalid params: local is None",
                    ))?;
                }
                gateway.remove_dispatch(local.unwrap(), protocol).await
                    .map_err(|e| cmd_err!(ControlErrorCode::Failed, "{}", e))?;
                Ok(Value::String("ok".to_string()))
            }
            "add_router" => {
                let params = serde_json::from_value::<HashMap<String, String>>(params)
                    .map_err(into_cmd_err!(ControlErrorCode::InvalidParams))?;
                let uri = params.get("uri");
                let target = params.get("target");
                if uri.is_none() || target.is_none() {
                    Err(cmd_err!(
                        ControlErrorCode::InvalidParams,
                        "Invalid params: uri or target is None",
                    ))?;
                }
                let server_id = params.get("id").map(|s| s.as_str());
                let server_id = gateway.add_router(server_id, uri.unwrap(), target.unwrap()).await
                    .map_err(|e| cmd_err!(ControlErrorCode::Failed, "{}", e))?;
                Ok(Value::String(server_id))
            }
            "remove_router" => {
                let params = serde_json::from_value::<HashMap<String, String>>(params)
                    .map_err(into_cmd_err!(ControlErrorCode::InvalidParams))?;
                let id = params.get("id");
                let uri = params.get("uri");
                let target = params.get("target");
                if uri.is_none() || target.is_none() {
                    Err(cmd_err!(
                        ControlErrorCode::InvalidParams,
                        "Invalid params: uri or target is None",
                    ))?;
                }
                let id = id.map(|s| s.as_str());
                gateway.remove_router(id, uri.unwrap(), target.unwrap()).await
                    .map_err(|e| cmd_err!(ControlErrorCode::Failed, "{}", e))?;
                Ok(Value::String("ok".to_string()))
            }
            "append_rule" => {
                let params = serde_json::from_value::<HashMap<String, String>>(params)
                    .map_err(into_cmd_err!(ControlErrorCode::InvalidParams))?;
                let id = params.get("id");
                let rule = params.get("rule");
                if id.is_none() || rule.is_none() {
                    Err(cmd_err!(
                        ControlErrorCode::InvalidParams,
                        "Invalid params: id or rule is None",
                    ))?;
                }
                gateway.append_rule(
                    id.unwrap(),
                    rule.unwrap(),
                ).await
                    .map_err(|e| cmd_err!(ControlErrorCode::Failed, "{}", e))?;
                Ok(Value::String("ok".to_string()))
            }
            "insert_rule" => {
                let params = serde_json::from_value::<HashMap<String, String>>(params)
                    .map_err(into_cmd_err!(ControlErrorCode::InvalidParams))?;
                let id = params.get("id");
                let rule = params.get("rule");
                let pos = params.get("pos");
                if id.is_none() || rule.is_none() || pos.is_none() {
                    Err(cmd_err!(
                        ControlErrorCode::InvalidParams,
                        "Invalid params: id or rule or pos is None",
                    ))?;
                }
                let pos: i32 = pos.unwrap().parse().map_err(|_| {
                    cmd_err!(ControlErrorCode::InvalidParams, "pos must be integer")
                })?;
                gateway.insert_rule(
                    id.unwrap(),
                    pos,
                    rule.unwrap(),
                ).await
                    .map_err(|e| cmd_err!(ControlErrorCode::Failed, "{}", e))?;
                Ok(Value::String("ok".to_string()))
            }
            "move_rule" => {
                let params = serde_json::from_value::<HashMap<String, String>>(params)
                    .map_err(into_cmd_err!(ControlErrorCode::InvalidParams))?;
                let id = params.get("id");
                let pos = params.get("new_pos");
                if id.is_none() || pos.is_none() {
                    Err(cmd_err!(
                        ControlErrorCode::InvalidParams,
                        "Invalid params: id or new_pos is None",
                    ))?;
                }
                let pos: i32 = pos.unwrap().parse().map_err(|_| {
                    cmd_err!(ControlErrorCode::InvalidParams, "new_pos must be integer")
                })?;
                gateway.move_rule(
                    id.unwrap(),
                    pos,
                ).await
                    .map_err(|e| cmd_err!(ControlErrorCode::Failed, "{}", e))?;
                Ok(Value::String("ok".to_string()))
            }
            "set_rule" => {
                let params = serde_json::from_value::<HashMap<String, String>>(params)
                    .map_err(into_cmd_err!(ControlErrorCode::InvalidParams))?;
                let id = params.get("id");
                let rule = params.get("rule");
                if id.is_none() || rule.is_none() {
                    Err(cmd_err!(
                        ControlErrorCode::InvalidParams,
                        "Invalid params: id or rule is None",
                    ))?;
                }
                gateway.set_rule(
                    id.unwrap(),
                    rule.unwrap(),
                ).await
                    .map_err(|e| cmd_err!(ControlErrorCode::Failed, "{}", e))?;
                Ok(Value::String("ok".to_string()))
            }
            "reload" => {
                if self.config_file.is_none() {
                    Err(cmd_err!(
                        ControlErrorCode::InvalidParams,
                        "Invalid params: config_file is None",
                    ))?;
                }
                info!("*** reload gateway config ...");
                let gateway_config = load_config_from_file(self.config_file.as_ref().unwrap().as_path()).await
                    .map_err(|e| cmd_err!(ControlErrorCode::Failed, "{}", e))?;
                let gateway_config = self.parser.parse(gateway_config)
                    .map_err(into_cmd_err!(ControlErrorCode::Failed))?;
                gateway.reload(gateway_config).await
                    .map_err(|e| cmd_err!(ControlErrorCode::Failed, "{}", e))?;
                info!("*** reload gateway config success !");
                Ok(Value::String("ok".to_string()))
            }
            "start" => {
                let params = serde_json::from_value::<StartTemplateParams>(params)
                    .map_err(into_cmd_err!(ControlErrorCode::InvalidParams))?;
                let args = params.args.unwrap_or_default();
                let result = self.start_template(params.template_id.as_str(), args).await?;
                Ok(result)
            }
            "external_cmds" => {
                let cmds = self.get_external_cmds().await?;
                Ok(serde_json::to_value(cmds).map_err(into_cmd_err!(ControlErrorCode::SerializeFailed))?)
            }
            "cmd_help" => {
                let params = serde_json::from_value::<HashMap<String, String>>(params)
                    .map_err(into_cmd_err!(ControlErrorCode::InvalidParams))?;
                let cmd = params.get("cmd").unwrap();
                let help = self.get_external_cmd_help(cmd).await?;
                Ok(serde_json::to_value(help).map_err(into_cmd_err!(ControlErrorCode::SerializeFailed))?)
            }
            v => {
                Err(cmd_err!(ControlErrorCode::InvalidMethod, "Invalid method: {}", v))
            }
        }
    }
}

#[async_trait::async_trait]
pub trait TokenKeyStore: Send + Sync + 'static {
    async fn load_key(&self) -> ControlResult<(EncodingKey, DecodingKey)>;
    async fn save_key(&self, sign_key: String, public_key: Value) -> ControlResult<()>;
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
    async fn load_key(&self) -> ControlResult<(EncodingKey, DecodingKey)> {
        let private_key = self.data_dir.join("private_key.pem");
        let public_key = self.data_dir.join("public_key.json");
        let encode_key = load_private_key(private_key.as_path())
            .map_err(into_cmd_err!(ControlErrorCode::Failed))?;

        let public_key = tokio::fs::read_to_string(public_key).await
            .map_err(into_cmd_err!(ControlErrorCode::Failed))?;
        let public_key: Jwk = serde_json::from_str(public_key.as_str())
            .map_err(into_cmd_err!(ControlErrorCode::Failed))?;
        let decode_key = DecodingKey::from_jwk(&public_key)
            .map_err(into_cmd_err!(ControlErrorCode::Failed))?;
        Ok((encode_key, decode_key))
    }

    async fn save_key(&self, sign_key: String, public_key: Value) -> ControlResult<()> {
        let private_key = self.data_dir.join("private_key.pem");
        let public_key_path = self.data_dir.join("public_key.json");
        tokio::fs::write(private_key.as_path(), sign_key).await
            .map_err(into_cmd_err!(ControlErrorCode::Failed))?;
        tokio::fs::write(public_key_path.as_path(), serde_json::to_string(&public_key).unwrap()).await
            .map_err(into_cmd_err!(ControlErrorCode::Failed))?;
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
                     store: S) -> ControlResult<Arc<Self>> {
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

    fn load(private_key: &Path, public_key: &Path) -> ControlResult<(EncodingKey, DecodingKey)> {
        if !private_key.exists() || !public_key.exists() {
            return Err(cmd_err!(ControlErrorCode::Failed));
        }

        let encode_key = load_private_key(private_key)
            .map_err(into_cmd_err!(ControlErrorCode::Failed))?;

        let public_key = std::fs::read_to_string(public_key)
            .map_err(into_cmd_err!(ControlErrorCode::Failed))?;
        let public_key: Jwk = serde_json::from_str(public_key.as_str())
            .map_err(into_cmd_err!(ControlErrorCode::Failed))?;
        let decode_key = DecodingKey::from_jwk(&public_key)
            .map_err(into_cmd_err!(ControlErrorCode::Failed))?;
        Ok((encode_key, decode_key))
    }
}
#[async_trait::async_trait]
impl<S: TokenKeyStore> CyfsTokenFactory for LocalTokenManager<S> {
    async fn create(&self, user_name: &str, password: &str, timestamp: u64) -> ControlResult<String> {
        if self.user_name.is_none() || self.password.is_none() {
            return Err(cmd_err!(ControlErrorCode::NotSupportLogin, "not support login"));
        }
        if (Utc::now().timestamp() - timestamp as i64).abs() > 120 {
            return Err(cmd_err!(ControlErrorCode::Expired, "login session expired"));
        }

        if user_name != self.user_name.as_ref().unwrap() {
            return Err(cmd_err!(ControlErrorCode::InvalidUserName, "invalid user name"));
        }

        let mut sha256 = sha2::Sha256::new();
        sha256.update(format!("{}_{}_{}", user_name, self.password.as_ref().unwrap(), timestamp));
        if hex::encode(sha256.finalize()).to_lowercase() != password.to_lowercase() {
            return Err(cmd_err!(ControlErrorCode::InvalidPassword, "invalid password"));
        }

        let (token, _) = RPCSessionToken::generate_jwt_token(
            user_name,
            "cyfs-gateway",
            None,
            &self.token_encode_key, )
            .map_err(into_cmd_err!(ControlErrorCode::CreateTokenFailed, "create token failed"))?;
        Ok(token)
    }
}

#[async_trait::async_trait]
impl<S: TokenKeyStore> CyfsTokenVerifier for LocalTokenManager<S> {
    async fn verify_and_renew(&self, token: &str) -> ControlResult<Option<String>> {
        let mut session_token = match RPCSessionToken::from_string(token) {
            Ok(session_token) => session_token,
            Err(e) => {
                error!("invalid token: {}", e);
                return Err(cmd_err!(ControlErrorCode::InvalidToken));
            }
        };

        if let Err(_) = session_token.verify_by_key(&self.token_decode_key) {
            return Err(cmd_err!(ControlErrorCode::InvalidToken));
        }

        if session_token.exp.is_some() {
            if session_token.exp.unwrap() < Utc::now().timestamp() as u64 {
                return Err(cmd_err!(ControlErrorCode::Expired));
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
                    Err(cmd_err!(ControlErrorCode::InvalidToken))
                }
            }
        } else {
            Ok(None)
        }
    }
}

#[async_trait::async_trait]
pub trait ExternalCmdStore: Send + Sync + 'static {
    async fn read_external_cmd(&self, cmd: &str) -> ControlResult<String>;
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
    async fn read_external_cmd(&self, cmd: &str) -> ControlResult<String> {
        let path = self.cmd_path.join(format!("{}.js", cmd));
        if !path.exists() {
            return Err(cmd_err!(ControlErrorCode::UnknownCmd, "unknown cmd {}", cmd));
        }

        Ok(path.to_string_lossy().to_string())
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::path::PathBuf;
    use super::super::gateway::*;
    use kRPC::RPCSessionToken;
    use chrono::Utc;
    use serde_json::json;
    use tempfile::TempDir;

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
        async fn load_key(&self) -> ControlResult<(EncodingKey, DecodingKey)> {
            let mut private_key = self.private_key.lock().await;
            let mut content: String = String::new();
            private_key.read_to_string(&mut content)
                .map_err(into_cmd_err!(ControlErrorCode::Failed))?;
            let private_key = EncodingKey::from_ed_pem(content.as_bytes())
                .map_err(into_cmd_err!(ControlErrorCode::Failed))?;
            let mut public_key = self.public_key.lock().await;
            let mut content: String = String::new();
            public_key.read_to_string(&mut content)
                .map_err(into_cmd_err!(ControlErrorCode::Failed))?;

            let public_key: Jwk = serde_json::from_str(content.as_str())
                .map_err(into_cmd_err!(ControlErrorCode::Failed))?;
            let decode_key = DecodingKey::from_jwk(&public_key)
                .map_err(into_cmd_err!(ControlErrorCode::Failed))?;
            Ok((private_key, decode_key))
        }

        async fn save_key(&self, sign_key: String, public_key: Value) -> ControlResult<()> {
            let mut private_key = self.private_key.lock().await;
            private_key.write_all(sign_key.as_bytes()).unwrap();
            let mut public_file = self.public_key.lock().await;
            public_file.write_all(serde_json::to_string(&public_key).unwrap().as_bytes()).unwrap();
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_add_rule_to_existing_block_preserves_priority_and_prepends() {
        let raw_config = json!({
            "stacks": {
                "s1": {
                    "protocol": "tcp",
                    "bind": "0.0.0.0:1",
                    "hook_point": {
                        "main": {
                            "priority": 2,
                            "blocks": {
                                "default": {
                                    "priority": 2,
                                    "block": "old;"
                                }
                            }
                        }
                    }
                }
            },
            "servers": {
                "s1": {
                    "type": "http",
                    "hook_point": {
                        "main": {
                            "priority": 2,
                            "blocks": {
                                "default": {
                                    "priority": 2,
                                    "block": "old;"
                                }
                            }
                        }
                    }
                },
                "s2": {
                    "type": "dir",
                    "root_path": ""
                }
            }
        });

        let ret = Gateway::add_rule_to_config(raw_config.clone(), "stack:s1:hook_point:main:default", "new;");
        assert!(ret.is_ok());
        let updated = ret.unwrap();
        let block = updated["stacks"]["s1"]["hook_point"]["main"]["blocks"]["default"].as_object().unwrap();
        assert_eq!(block.get("priority").and_then(|v| v.as_i64()), Some(2));
        let block_str = block.get("block").and_then(|v| v.as_str()).unwrap();
        println!("{}", block_str);
        assert_eq!(block_str, "new;\nold;");

        let ret = Gateway::add_rule_to_config(raw_config.clone(), "stack:s2:hook_point:main", "new;");
        assert!(ret.is_err());        
        let ret = Gateway::add_rule_to_config(raw_config.clone(), "server:s2", "new;");
        assert!(ret.is_err());

        let updated = Gateway::add_rule_to_config(raw_config.clone(), "stack:s1:hook_point:main:default1", "new;").unwrap();

        let block = updated["stacks"]["s1"]["hook_point"]["main"]["blocks"]["default1"].as_object().unwrap();
        assert_eq!(block.get("priority").and_then(|v| v.as_i64()), Some(1));
        let block_str = block.get("block").and_then(|v| v.as_str()).unwrap();

        let updated = Gateway::add_rule_to_config(raw_config.clone(), "stack:s1:main:default1", "new;").unwrap();
        let block = updated["stacks"]["s1"]["hook_point"]["main"]["blocks"]["default1"].as_object().unwrap();
        assert_eq!(block.get("priority").and_then(|v| v.as_i64()), Some(1));
        let block_str = block.get("block").and_then(|v| v.as_str()).unwrap();
        assert_eq!(block_str, "new;");

        let updated = Gateway::add_rule_to_config(raw_config.clone(), "stack:s1:main:blocks:default1", "new;").unwrap();
        let block = updated["stacks"]["s1"]["hook_point"]["main"]["blocks"]["default1"].as_object().unwrap();
        assert_eq!(block.get("priority").and_then(|v| v.as_i64()), Some(1));
        let block_str = block.get("block").and_then(|v| v.as_str()).unwrap();
        assert_eq!(block_str, "new;");

        let updated = Gateway::add_rule_to_config(raw_config.clone(), "stack:s1:main", "new;").unwrap();
        let blocks = updated["stacks"]["s1"]["hook_point"]["main"]["blocks"].clone();
        let updated = Gateway::add_rule_to_config(raw_config.clone(), "stack:s1", "new;").unwrap();
        let blocks = updated["stacks"]["s1"]["hook_point"].clone();
    }

    #[tokio::test]
    async fn test_append_rule_to_config_adds_lowest_priority_and_appends_text() {
        let raw_config = json!({
            "stacks": {
                "s1": {
                    "protocol": "tcp",
                    "bind": "0.0.0.0:1",
                    "hook_point": {
                        "main": {
                            "priority": 1,
                            "blocks": {
                                "b1": {
                                    "priority": 2,
                                    "block": "old1\nold2"
                                }
                            }
                        }
                    }
                }
            },
            "servers": {
                "s1": {
                    "type": "http",
                    "hook_point": {
                        "main": {
                            "priority": 2,
                            "blocks": {
                                "default": {
                                    "priority": 2,
                                    "block": "old;"
                                }
                            }
                        }
                    }
                },
                "s2": {
                    "type": "dir",
                    "root_path": ""
                }
            }
        });

        // append into existing block
        let updated = Gateway::append_rule_to_config(raw_config.clone(), "stack:s1:hook_point:main:b1", "new").unwrap();
        let block = updated["stacks"]["s1"]["hook_point"]["main"]["blocks"]["b1"].as_object().unwrap();
        assert_eq!(block.get("priority").and_then(|v| v.as_i64()), Some(2));
        let content = block.get("block").and_then(|v| v.as_str()).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert!(lines.ends_with(&["old1", "old2", "new"]));

        let ret = Gateway::append_rule_to_config(raw_config.clone(), "stack:s2:hook_point:main", "new;");
        assert!(ret.is_err());
        let ret = Gateway::append_rule_to_config(raw_config.clone(), "server:s2", "new;");
        assert!(ret.is_err());

        // append new block should get lowest priority (max+1)
        let updated = Gateway::append_rule_to_config(raw_config.clone(), "stack:s1:hook_point:main:b2", "newblock").unwrap();
        let blocks = updated["stacks"]["s1"]["hook_point"]["main"]["blocks"].as_object().unwrap();
        let p1 = blocks.get("b1").and_then(|v| v.get("priority")).and_then(|v| v.as_i64()).unwrap();
        let p2 = blocks.get("b2").and_then(|v| v.get("priority")).and_then(|v| v.as_i64()).unwrap();
        assert!(p2 > p1);

        let updated = Gateway::append_rule_to_config(raw_config.clone(), "stack:s1:hook_point:main:default1", "new;").unwrap();

        let block = updated["stacks"]["s1"]["hook_point"]["main"]["blocks"]["default1"].as_object().unwrap();
        assert_eq!(block.get("priority").and_then(|v| v.as_i64()), Some(3));
        let block_str = block.get("block").and_then(|v| v.as_str()).unwrap();

        let updated = Gateway::append_rule_to_config(raw_config.clone(), "stack:s1:main:default1", "new;").unwrap();
        let block = updated["stacks"]["s1"]["hook_point"]["main"]["blocks"]["default1"].as_object().unwrap();
        assert_eq!(block.get("priority").and_then(|v| v.as_i64()), Some(3));
        let block_str = block.get("block").and_then(|v| v.as_str()).unwrap();
        assert_eq!(block_str, "new;");

        let updated = Gateway::append_rule_to_config(raw_config.clone(), "stack:s1:main:blocks:default1", "new;").unwrap();
        let block = updated["stacks"]["s1"]["hook_point"]["main"]["blocks"]["default1"].as_object().unwrap();
        assert_eq!(block.get("priority").and_then(|v| v.as_i64()), Some(3));
        let block_str = block.get("block").and_then(|v| v.as_str()).unwrap();
        assert_eq!(block_str, "new;");

        let updated = Gateway::append_rule_to_config(raw_config.clone(), "stack:s1:main", "new;").unwrap();
        let blocks = updated["stacks"]["s1"]["hook_point"]["main"]["blocks"].clone();
        let updated = Gateway::append_rule_to_config(raw_config.clone(), "stack:s1", "new;").unwrap();
        let blocks = updated["stacks"]["s1"]["hook_point"].clone();
    }

    #[tokio::test]
    async fn test_insert_rule_to_config() {
        let raw_config = json!({
            "stacks": {
                "s1": {
                    "protocol": "tcp",
                    "bind": "0.0.0.0:1",
                    "hook_point": {
                        "main": {
                            "priority": 5,
                            "blocks": {
                                "b1": {
                                    "priority": 5,
                                    "block": "l1\nl3"
                                }
                            }
                        }
                    }
                }
            }
        });

        // insert inside existing block
        let updated = Gateway::insert_rule_to_config(raw_config.clone(), "stack:s1:hook_point:main:b1", 2, "l2").unwrap();
        let block = updated["stacks"]["s1"]["hook_point"]["main"]["blocks"]["b1"].as_object().unwrap();
        assert_eq!(block.get("priority").and_then(|v| v.as_i64()), Some(5));
        let lines: Vec<&str> = block.get("block").and_then(|v| v.as_str()).unwrap().lines().collect();
        assert_eq!(lines, vec!["l1", "l2", "l3"]);

        // insert new block with given priority
        let updated = Gateway::insert_rule_to_config(raw_config.clone(), "stack:s1:hook_point:main:b2", 10, "nb").unwrap();
        let block = updated["stacks"]["s1"]["hook_point"]["main"]["blocks"]["b2"].as_object().unwrap();
        assert_eq!(block.get("priority").and_then(|v| v.as_i64()), Some(10));
        assert_eq!(block.get("block").and_then(|v| v.as_str()), Some("nb"));

        // insert new chain and block with given priority
        let updated = Gateway::insert_rule_to_config(raw_config.clone(), "stack:s1:new_chain", 7, "nc").unwrap();
        let chain = updated["stacks"]["s1"]["hook_point"]["new_chain"].as_object().unwrap();
        assert_eq!(chain.get("priority").and_then(|v| v.as_i64()), Some(7));
        let blocks = chain.get("blocks").and_then(|v| v.as_object()).unwrap();
        let b = blocks.values().next().unwrap().as_object().unwrap();
        assert_eq!(b.get("priority").and_then(|v| v.as_i64()), Some(7));
        assert_eq!(b.get("block").and_then(|v| v.as_str()), Some("nc"));
    }

    #[tokio::test]
    async fn test_move_rule_updates_priority_and_lines() {
        let raw_config = json!({
            "stacks": {
                "s1": {
                    "protocol": "tcp",
                    "bind": "0.0.0.0:1",
                    "hook_point": {
                        "main": {
                            "priority": 5,
                            "blocks": {
                                "b1": {
                                    "priority": 10,
                                    "block": "l1\nl2\nl3\nl4\n"
                                },
                                "b2": {
                                    "priority": 20,
                                    "block": "keep;"
                                }
                            }
                        },
                        "other": {
                            "priority": 8,
                            "blocks": {
                                "x1": {
                                    "priority": 1,
                                    "block": "x;"
                                }
                            }
                        }
                    }
                }
            }
        });

        // move chain priority
        let updated = Gateway::move_rule_in_config(raw_config.clone(), "stack:s1:hook_point:other", 2).unwrap();
        let chains = updated["stacks"]["s1"]["hook_point"].as_object().unwrap();
        assert_eq!(chains.get("other").and_then(|v| v.get("priority")).and_then(|v| v.as_i64()), Some(2));
        assert_eq!(chains.get("main").and_then(|v| v.get("priority")).and_then(|v| v.as_i64()), Some(5));

        let updated = Gateway::move_rule_in_config(raw_config.clone(), "stack:s1:other", 2).unwrap();
        let chains = updated["stacks"]["s1"]["hook_point"].as_object().unwrap();
        assert_eq!(chains.get("other").and_then(|v| v.get("priority")).and_then(|v| v.as_i64()), Some(2));
        assert_eq!(chains.get("main").and_then(|v| v.get("priority")).and_then(|v| v.as_i64()), Some(5));

        let updated = Gateway::move_rule_in_config(raw_config.clone(), "stack:2other", 2);
        assert!(updated.is_err());

        // move block priority
        let updated = Gateway::move_rule_in_config(raw_config.clone(), "stack:s1:hook_point:main:b2", -1).unwrap();
        let blocks = updated["stacks"]["s1"]["hook_point"]["main"]["blocks"].as_object().unwrap();
        assert_eq!(blocks.get("b2").and_then(|v| v.get("priority")).and_then(|v| v.as_i64()), Some(-1));
        assert_eq!(blocks.get("b1").and_then(|v| v.get("priority")).and_then(|v| v.as_i64()), Some(10));

        // move single line to top, keep trailing newline
        let updated = Gateway::move_rule_in_config(raw_config.clone(), "stack:s1:hook_point:main:b1:3", 1).unwrap();
        let content = updated["stacks"]["s1"]["hook_point"]["main"]["blocks"]["b1"]["block"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(content, "l3\nl1\nl2\nl4\n");

        // move multiple lines toward end
        let updated = Gateway::move_rule_in_config(raw_config.clone(), "stack:s1:hook_point:main:b1:1:2", 3).unwrap();
        let content = updated["stacks"]["s1"]["hook_point"]["main"]["blocks"]["b1"]["block"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(content, "l3\nl4\nl1\nl2\n");

        // move multiple lines toward end
        let updated = Gateway::move_rule_in_config(raw_config, "stack:s1:hook_point:main:b1:1:2", 30).unwrap();
        let content = updated["stacks"]["s1"]["hook_point"]["main"]["blocks"]["b1"]["block"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(content, "l3\nl4\nl1\nl2\n");
    }

    #[tokio::test]
    async fn test_set_rule_in_config() {
        let raw_config = json!({
            "stacks": {
                "s1": {
                    "protocol": "tcp",
                    "bind": "0.0.0.0:1",
                    "hook_point": {
                        "main": {
                            "priority": 1,
                            "blocks": {
                                "b1": {
                                    "priority": 5,
                                    "block": "a\nb\nc\n"
                                },
                                "b2": {
                                    "priority": 6,
                                    "block": "keep;"
                                }
                            }
                        }
                    }
                }
            }
        });

        // replace whole block content, priority unchanged
        let updated = Gateway::set_rule_in_config(raw_config.clone(), "stack:s1:hook_point:main:b1", "new_block").unwrap();
        let block = updated["stacks"]["s1"]["hook_point"]["main"]["blocks"]["b1"].as_object().unwrap();
        assert_eq!(block.get("priority").and_then(|v| v.as_i64()), Some(5));
        assert_eq!(block.get("block").and_then(|v| v.as_str()), Some("new_block"));
        assert_eq!(updated["stacks"]["s1"]["hook_point"]["main"]["blocks"]["b2"]["block"].as_str(), Some("keep;"));

        // replace chain rules with a single block, keep first block id and priority
        let updated = Gateway::set_rule_in_config(raw_config.clone(), "stack:s1:hook_point:main", "chain_new").unwrap();
        let blocks = updated["stacks"]["s1"]["hook_point"]["main"]["blocks"].as_object().unwrap();
        assert_eq!(blocks.len(), 1);
        let block = blocks.get("b1").unwrap().as_object().unwrap();
        assert_eq!(block.get("priority").and_then(|v| v.as_i64()), Some(5));
        assert_eq!(block.get("block").and_then(|v| v.as_str()), Some("chain_new"));

        // replace specific line range, preserve trailing newline
        let updated = Gateway::set_rule_in_config(raw_config.clone(), "stack:s1:hook_point:main:b1:2", "middle").unwrap();
        let content = updated["stacks"]["s1"]["hook_point"]["main"]["blocks"]["b1"]["block"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(content, "a\nmiddle\nc\n");

        // replace multiple lines
        let updated = Gateway::set_rule_in_config(raw_config.clone(), "stack:s1:hook_point:main:b1:1:2", "x\ny").unwrap();
        let content = updated["stacks"]["s1"]["hook_point"]["main"]["blocks"]["b1"]["block"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(content, "x\ny\nc\n");
    }

    #[tokio::test]
    async fn test_set_rule_in_config_invalid_range() {
        let raw_config = json!({
            "stacks": {
                "s1": {
                    "protocol": "tcp",
                    "bind": "0.0.0.0:1",
                    "hook_point": {
                        "main": {
                            "priority": 1,
                            "blocks": {
                                "b1": {
                                    "priority": 1,
                                    "block": "only\n"
                                }
                            }
                        }
                    }
                }
            }
        });

        let err = Gateway::set_rule_in_config(raw_config.clone(), "stack:s1:hook_point:main:b1:0", "x");
        assert!(err.is_err());
        let err = Gateway::set_rule_in_config(raw_config, "stack:s1:hook_point:main:b1:5", "x");
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn test_set_rule_in_config_invalid_config_type_and_dns_server() {
        let raw_config = json!({
            "servers": {
                "dns1": {
                    "type": "dns",
                    "hook_point": {
                        "main": {
                            "priority": 1,
                            "blocks": {
                                "default": {
                                    "priority": 1,
                                    "block": "a;"
                                }
                            }
                        }
                    }
                }
            }
        });

        let err = Gateway::set_rule_in_config(raw_config.clone(), "invalid:dns1:hook_point:main:default", "b;");
        assert!(err.is_err());

        let updated = Gateway::set_rule_in_config(raw_config, "server:dns1:hook_point:main:default", "b;").unwrap();
        let block = updated["servers"]["dns1"]["hook_point"]["main"]["blocks"]["default"]
            .as_object()
            .unwrap();
        assert_eq!(block.get("block").and_then(|v| v.as_str()), Some("b;"));
    }

    #[tokio::test]
    async fn test_add_and_remove_dispatch_to_config() {
        let raw_config = json!({
            "stacks": {}
        });

        // default protocol tcp, port only
        let (updated, stack_id) = Gateway::add_dispatch_to_config(raw_config.clone(), "18080", "192.168.0.1:1900", None).unwrap();
        assert_eq!(stack_id, "dispatch_tcp_0_0_0_0_18080");
        let stack = updated["stacks"][stack_id.as_str()].as_object().unwrap();
        assert_eq!(stack.get("bind").and_then(|v| v.as_str()), Some("0.0.0.0:18080"));
        assert_eq!(stack.get("protocol").and_then(|v| v.as_str()), Some("tcp"));
        let block = stack["hook_point"]["main"]["blocks"]["default"].as_object().unwrap();
        let block_str = block.get("block").and_then(|v| v.as_str()).unwrap();
        assert!(block_str.contains("tcp:///192.168.0.1:1900"));

        // udp with explicit ip
        let (updated, stack_id_udp) = Gateway::add_dispatch_to_config(raw_config.clone(), "0.0.0.0:8080", "10.0.0.1:9000", Some("udp")).unwrap();
        assert_eq!(stack_id_udp, "dispatch_udp_0_0_0_0_8080");
        let stack = updated["stacks"][stack_id_udp.as_str()].as_object().unwrap();
        assert_eq!(stack.get("bind").and_then(|v| v.as_str()), Some("0.0.0.0:8080"));
        assert_eq!(stack.get("protocol").and_then(|v| v.as_str()), Some("udp"));
        let block = stack["hook_point"]["main"]["blocks"]["default"].as_object().unwrap();
        let block_str = block.get("block").and_then(|v| v.as_str()).unwrap();
        assert!(block_str.contains("udp:///10.0.0.1:9000"));

        // duplicate add
        let dup = Gateway::add_dispatch_to_config(updated.clone(), "0.0.0.0:8080", "10.0.0.1:9000", Some("udp"));
        assert!(dup.is_err());

        // remove existing
        let (removed, removed_id) = Gateway::remove_dispatch_from_config(updated, "0.0.0.0:8080", Some("udp")).unwrap();
        assert_eq!(removed_id, "dispatch_udp_0_0_0_0_8080");
        assert!(removed["stacks"].get(removed_id).is_none());

        // remove missing
        let err = Gateway::remove_dispatch_from_config(removed, "0.0.0.0:8080", Some("udp"));
        assert!(err.is_err());

        // invalid target
        let err = Gateway::add_dispatch_to_config(raw_config.clone(), "18080", "bad_target", None);
        assert!(err.is_err());

        // invalid protocol
        let err = Gateway::add_dispatch_to_config(raw_config, "18080", "192.168.0.1:1900", Some("http"));
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn test_add_and_remove_router_to_config() {
        let raw_config = json!({
            "servers": {}
        });

        // create with generated server id, http target with trailing slash
        let (updated, sid, _) = Gateway::add_router_to_config(raw_config.clone(), None, "/sn", "http://127.0.0.1:9000/").unwrap();
        assert!(sid.starts_with("router_"));
        let server = updated["servers"][sid.as_str()].as_object().unwrap();
        assert_eq!(server.get("type").and_then(|v| v.as_str()), Some("http"));
        let blocks = server["hook_point"]["main"]["blocks"].as_object().unwrap();
        assert_eq!(blocks.len(), 1);
        let rule = blocks.values().next().unwrap()["block"].as_str().unwrap().to_string();
        println!("{}", rule);
        assert_eq!(rule, r#"starts-with ${REQ.path} "/sn" && rewrite ${REQ.path} "/sn*" "*" && forward "http://127.0.0.1:9000";"#);

        let (updated, removed_id) = Gateway::remove_router_from_config(updated, Some(sid.as_str()), "/sn", "http://127.0.0.1:9000/").unwrap();
        assert_eq!(removed_id, sid);
        assert!(updated["servers"].get(&removed_id).is_none());

        let (updated, sid, _) = Gateway::add_router_to_config(raw_config.clone(), None, "/sn/", "http://127.0.0.1:9000/").unwrap();
        assert!(sid.starts_with("router_"));
        let server = updated["servers"][sid.as_str()].as_object().unwrap();
        assert_eq!(server.get("type").and_then(|v| v.as_str()), Some("http"));
        let blocks = server["hook_point"]["main"]["blocks"].as_object().unwrap();
        assert_eq!(blocks.len(), 1);
        let rule = blocks.values().next().unwrap()["block"].as_str().unwrap().to_string();
        println!("{}", rule);
        assert_eq!(rule, r#"starts-with ${REQ.path} "/sn/" && rewrite ${REQ.path} "/sn/*" "/*" && forward "http://127.0.0.1:9000";"#);

        let (updated, sid, _) = Gateway::add_router_to_config(raw_config.clone(), None, "/sn/*", "http://127.0.0.1:9000/").unwrap();
        assert!(sid.starts_with("router_"));
        let server = updated["servers"][sid.as_str()].as_object().unwrap();
        assert_eq!(server.get("type").and_then(|v| v.as_str()), Some("http"));
        let blocks = server["hook_point"]["main"]["blocks"].as_object().unwrap();
        assert_eq!(blocks.len(), 1);
        let rule = blocks.values().next().unwrap()["block"].as_str().unwrap().to_string();
        println!("{}", rule);
        assert_eq!(rule, r#"match ${REQ.path} "/sn/*" && rewrite ${REQ.path} "/sn/*" "/*" && forward "http://127.0.0.1:9000";"#);

        let (updated, sid, _) = Gateway::add_router_to_config(raw_config.clone(), None, "/sn/*", "http://127.0.0.1:9000/api/").unwrap();
        assert!(sid.starts_with("router_"));
        let server = updated["servers"][sid.as_str()].as_object().unwrap();
        assert_eq!(server.get("type").and_then(|v| v.as_str()), Some("http"));
        let blocks = server["hook_point"]["main"]["blocks"].as_object().unwrap();
        assert_eq!(blocks.len(), 1);
        let rule = blocks.values().next().unwrap()["block"].as_str().unwrap().to_string();
        println!("{}", rule);
        assert_eq!(rule, r#"match ${REQ.path} "/sn/*" && rewrite ${REQ.path} "/sn/*" "/api/*" && forward "http://127.0.0.1:9000";"#);


        let (updated, sid2, _) = Gateway::add_router_to_config(raw_config.clone(), Some("router_test"), "~^/static/(.*)$", "http://127.0.0.1:9000/$1").unwrap();
        assert_eq!(sid2, "router_test");
        let server = updated["servers"][sid2.as_str()].as_object().unwrap();
        let blocks = server["hook_point"]["main"]["blocks"].as_object().unwrap();
        let rule = blocks.values().next().unwrap()["block"].as_str().unwrap().to_string();
        println!("{}", rule);
        assert!(rule.starts_with(r#"match-reg ${REQ.path} "^/static/(.*)$" && rewrite ${REQ.path} "^/static/(.*)$" "/$1" && forward "http://127.0.0.1:9000";"#));

        let (updated, sid2, _) = Gateway::add_router_to_config(raw_config.clone(), Some("router_test"), "~^/static/(.*)$", "http://127.0.0.1:9000/api/$1").unwrap();
        assert_eq!(sid2, "router_test");
        let server = updated["servers"][sid2.as_str()].as_object().unwrap();
        let blocks = server["hook_point"]["main"]["blocks"].as_object().unwrap();
        let rule = blocks.values().next().unwrap()["block"].as_str().unwrap().to_string();
        println!("{}", rule);
        assert!(rule.starts_with(r#"match-reg ${REQ.path} "^/static/(.*)$" && rewrite ${REQ.path} "^/static/(.*)$" "/api/$1" && forward "http://127.0.0.1:9000";"#));

        let (updated, sid2, _) = Gateway::add_router_to_config(raw_config.clone(), Some("router_test"), "~^/static/(.*)$", "http://127.0.0.1:9000/api/").unwrap();
        assert_eq!(sid2, "router_test");
        let server = updated["servers"][sid2.as_str()].as_object().unwrap();
        let blocks = server["hook_point"]["main"]["blocks"].as_object().unwrap();
        let rule = blocks.values().next().unwrap()["block"].as_str().unwrap().to_string();
        println!("{}", rule);
        assert_eq!(rule, r#"match-reg ${REQ.path} "^/static/(.*)$" && rewrite ${REQ.path} "/*" "/api/*" && forward "http://127.0.0.1:9000";"#);

        let (updated, sid2, _) = Gateway::add_router_to_config(raw_config.clone(), Some("router_test"), "~^/static/(.*)$", "http://127.0.0.1:9000").unwrap();
        assert_eq!(sid2, "router_test");
        let server = updated["servers"][sid2.as_str()].as_object().unwrap();
        let blocks = server["hook_point"]["main"]["blocks"].as_object().unwrap();
        let rule = blocks.values().next().unwrap()["block"].as_str().unwrap().to_string();
        println!("{}", rule);
        assert_eq!(rule, r#"match-reg ${REQ.path} "^/static/(.*)$" && forward "http://127.0.0.1:9000";"#);

        // create with local dir target and explicit server id
        let (updated, sid2, _) = Gateway::add_router_to_config(raw_config.clone(), Some("router_test"), "/static/*", "/www/").unwrap();
        assert_eq!(sid2, "router_test");
        let server = updated["servers"][sid2.as_str()].as_object().unwrap();
        let blocks = server["hook_point"]["main"]["blocks"].as_object().unwrap();
        let rule = blocks.values().next().unwrap()["block"].as_str().unwrap().to_string();
        println!("{}", rule);
        assert!(rule.starts_with(r#"match ${REQ.path} "/static/*" && rewrite ${REQ.path} "/static/*" "/*" && call-server"#));
        // dir server created
        assert!(updated["servers"].as_object().unwrap().keys().any(|k| k.starts_with("router_dir_")));

        let (updated, removed_id) = Gateway::remove_router_from_config(updated, Some("router_test"), "/static/*", "/www/").unwrap();
        let servers = updated["servers"].as_object().unwrap();
        let server = servers.get(&removed_id);
        assert!(server.is_none());

        // create with local dir target and explicit server id
        let (updated, sid2, _) = Gateway::add_router_to_config(raw_config.clone(), Some("router_test"), "/static/", "/www/").unwrap();
        assert_eq!(sid2, "router_test");
        let server = updated["servers"][sid2.as_str()].as_object().unwrap();
        let blocks = server["hook_point"]["main"]["blocks"].as_object().unwrap();
        let rule = blocks.values().next().unwrap()["block"].as_str().unwrap().to_string();
        println!("{}", rule);
        assert!(rule.starts_with(r#"starts-with ${REQ.path} "/static/" && rewrite ${REQ.path} "/static/*" "/*" && call-server"#));

        let (updated, sid2, _) = Gateway::add_router_to_config(raw_config.clone(), Some("router_test"), "/static/", "/www").unwrap();
        assert_eq!(sid2, "router_test");
        let server = updated["servers"][sid2.as_str()].as_object().unwrap();
        let blocks = server["hook_point"]["main"]["blocks"].as_object().unwrap();
        let rule = blocks.values().next().unwrap()["block"].as_str().unwrap().to_string();
        println!("{}", rule);
        println!("{}", serde_json::to_string_pretty(&updated).unwrap());
        assert!(rule.starts_with(r#"starts-with ${REQ.path} "/static/" && call-server"#));

        // create with local dir target and explicit server id
        let (updated, sid2, _) = Gateway::add_router_to_config(raw_config.clone(), Some("router_test"), "/static", "/www/").unwrap();
        assert_eq!(sid2, "router_test");
        let server = updated["servers"][sid2.as_str()].as_object().unwrap();
        let blocks = server["hook_point"]["main"]["blocks"].as_object().unwrap();
        let rule = blocks.values().next().unwrap()["block"].as_str().unwrap().to_string();
        println!("{}", rule);
        assert!(rule.starts_with(r#"starts-with ${REQ.path} "/static" && rewrite ${REQ.path} "/static*" "*" && call-server"#));

        let (updated, sid2, _) = Gateway::add_router_to_config(raw_config.clone(), Some("router_test"), "/static", "/www").unwrap();
        assert_eq!(sid2, "router_test");
        let server = updated["servers"][sid2.as_str()].as_object().unwrap();
        let blocks = server["hook_point"]["main"]["blocks"].as_object().unwrap();
        let rule = blocks.values().next().unwrap()["block"].as_str().unwrap().to_string();
        println!("{}", rule);
        assert!(rule.starts_with(r#"starts-with ${REQ.path} "/static" && call-server"#));

        let (updated, sid2, _) = Gateway::add_router_to_config(raw_config.clone(), Some("router_test"), "~^/static/(.*)$", "/www/$1").unwrap();
        assert_eq!(sid2, "router_test");
        let server = updated["servers"][sid2.as_str()].as_object().unwrap();
        let blocks = server["hook_point"]["main"]["blocks"].as_object().unwrap();
        let rule = blocks.values().next().unwrap()["block"].as_str().unwrap().to_string();
        println!("{}", rule);
        assert!(rule.starts_with(r#"match-reg ${REQ.path} "^/static/(.*)$" && rewrite ${REQ.path} "^/static/(.*)$" "/$1" && call-server"#));
        let (updated, removed_id) = Gateway::remove_router_from_config(updated, Some("router_test"), "~^/static/(.*)$", "/www/$1").unwrap();
        let servers = updated["servers"].as_object().unwrap();
        let server = servers.get(&removed_id);
        assert!(server.is_none());

        let (updated, sid2, _) = Gateway::add_router_to_config(raw_config.clone(), Some("router_test"), "~^/static/(.*)$", "/www/").unwrap();
        assert_eq!(sid2, "router_test");
        let server = updated["servers"][sid2.as_str()].as_object().unwrap();
        let blocks = server["hook_point"]["main"]["blocks"].as_object().unwrap();
        let rule = blocks.values().next().unwrap()["block"].as_str().unwrap().to_string();
        println!("{}", rule);
        assert!(rule.starts_with(r#"match-reg ${REQ.path} "^/static/(.*)$" && call-server"#));
    }

    #[tokio::test]
    async fn test_remove_rule_from_config() {
        let raw_config = json!({
            "stacks": {
                "s1": {
                    "protocol": "tcp",
                    "bind": "0.0.0.0:1",
                    "hook_point": {
                        "main": {
                            "priority": 2,
                            "blocks": {
                                "b1": {
                                    "priority": 2,
                                    "block": "old;"
                                },
                                "b2": {
                                    "priority": 3,
                                    "block": "old2;"
                                }
                            }
                        },
                        "main2": {
                            "priority": 2,
                            "blocks": {
                                "b1": {
                                    "priority": 2,
                                    "block": "old;"
                                },
                                "b2": {
                                    "priority": 3,
                                    "block": "old2;"
                                }
                            }
                        }
                    }
                }
            }
        });

        // remove a specific block
        let updated = Gateway::remove_rule_from_config(raw_config.clone(), "stack:s1:hook_point:main:b1").unwrap();
        let blocks = updated["stacks"]["s1"]["hook_point"]["main"]["blocks"].as_object().unwrap();
        assert!(!blocks.contains_key("b1"));
        assert!(blocks.contains_key("b2"));

        // remove last block should drop chain
        let updated = Gateway::remove_rule_from_config(updated, "stack:s1:hook_point:main:b2").unwrap();
        assert!(updated["stacks"]["s1"]["hook_point"].get("main").is_none());

        // single chain/block guard
        let single = json!({
            "stacks": {
                "s1": {
                    "protocol": "tcp",
                    "bind": "0.0.0.0:1",
                    "hook_point": {
                        "main": {
                            "priority": 1,
                            "blocks": {
                                "b1": {
                                    "priority": 1,
                                    "block": "only;"
                                }
                            }
                        }
                    }
                }
            }
        });
        let err = Gateway::remove_rule_from_config(single, "stack:s1:hook_point:main:b1");
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn test_remove_rule_from_config_line_range() {
        let raw_config = json!({
            "stacks": {
                "s1": {
                    "protocol": "tcp",
                    "bind": "0.0.0.0:1",
                    "hook_point": {
                        "main": {
                            "priority": 1,
                            "blocks": {
                                "b1": {
                                    "priority": 1,
                                    "block": "line1\nline2\nline3\n"
                                },
                                "b2": {
                                    "priority": 2,
                                    "block": "keep;"
                                }
                            }
                        }
                    }
                }
            }
        });

        // remove middle line
        let updated = Gateway::remove_rule_from_config(raw_config.clone(), "stack:s1:hook_point:main:b1:2").unwrap();
        let content = updated["stacks"]["s1"]["hook_point"]["main"]["blocks"]["b1"]["block"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(content.contains("line1"));
        assert!(content.contains("line3"));
        assert!(!content.contains("line2"));

        // remove remaining lines, block should be removed but chain stays because b2 exists
        let updated = Gateway::remove_rule_from_config(updated, "stack:s1:hook_point:main:b1:1:2").unwrap();
        let blocks = updated["stacks"]["s1"]["hook_point"]["main"]["blocks"]
            .as_object()
            .unwrap();
        assert!(!blocks.contains_key("b1"));
        assert!(blocks.contains_key("b2"));

        let updated = Gateway::remove_rule_from_config(updated, "stack:s1:hook_point:main:b2:1:2");
        assert!(updated.is_err());
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
        assert_eq!(error.code(), ControlErrorCode::Expired);
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
        assert_eq!(error.code(), ControlErrorCode::InvalidUserName);
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
        assert_eq!(error.code(), ControlErrorCode::InvalidPassword);
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
        assert_eq!(error.code(), ControlErrorCode::InvalidToken);
    }
}
