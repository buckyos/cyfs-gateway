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
use json_value_merge::Merge;
use jsonwebtoken::{DecodingKey, EncodingKey};
use jsonwebtoken::jwk::Jwk;
use kRPC::RPCSessionToken;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sfo_js::{JsEngine, JsPkgManagerRef, JsString, JsValue};
use sfo_js::object::builtins::JsArray;
use sha2::Digest;
use rand::{Rng};
use rand::distr::Alphanumeric;
use rand::thread_rng;
use crate::gateway_control_client::{cmd_err, into_cmd_err};
use crate::gateway_control_server::{ControlErrorCode, ControlResult, GatewayControlCmdHandler, CyfsTokenFactory, CyfsTokenVerifier};
use crate::config_loader::GatewayConfigParserRef;
use crate::gateway_control_server::{
    GatewayControlServerConfigParser, GATEWAY_CONTROL_SERVER_CONFIG, GATEWAY_CONTROL_SERVER_KEY,
};

pub async fn load_config_from_file(config_file: &Path) -> Result<serde_json::Value> {
    let config_dir = config_file.parent().ok_or_else(|| {
        let msg = format!("cannot get config dir: {:?}", config_file);
        error!("{}", msg);
        anyhow::anyhow!(msg)
    })?;

    let config_json = buckyos_kit::ConfigMerger::load_dir_with_root(&config_dir, &config_file).await
        .map_err(|e| {
            let msg = format!("local config {} failed {:?}", config_file.to_string_lossy().to_string(), e);
            error!("{}", msg);
            anyhow::anyhow!(msg)
        })?;

    info!("Gateway config before merge: {}", serde_json::to_string_pretty(&config_json).unwrap());

    let mut cmd_config: serde_json::Value = serde_yaml_ng::from_str(GATEWAY_CONTROL_SERVER_CONFIG).unwrap();
    cmd_config.merge(&config_json);

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
        let mut config_value = HashMap::new();
        let mut stacks = vec![];
        for stack in config.stacks.iter() {
            if stack.id().as_str() == GATEWAY_CONTROL_SERVER_KEY {
                continue;
            }
            let stack_value: Value = serde_json::from_str(stack.get_config_json().as_str())?;
            stacks.push(stack_value);
        }
        config_value.insert("stacks".to_string(), Value::Array(stacks));

        let mut servers = vec![];
        for server in config.servers.iter() {
            if server.id().as_str() == GATEWAY_CONTROL_SERVER_KEY {
                continue;
            }
            let server_value: Value = serde_json::from_str(server.get_config_json().as_str())?;
            servers.push(server_value);
        }
        config_value.insert("servers".to_string(), Value::Array(servers));


        let global_config = serde_json::to_value(&config.global_process_chains)?;
        config_value.insert("global_process_chains".to_string(), global_config);

        Ok(serde_json::to_value(&config_value)?)
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
            let candidate: String = thread_rng()
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

pub struct GatewayCmdHandler {
    gateway: Mutex<Option<Arc<Gateway>>>,
    external_cmd_store: ExternalCmdStoreRef,
    config_file: PathBuf,
    parser: GatewayConfigParserRef,
}

impl GatewayCmdHandler {
    pub fn new(external_cmd_store: ExternalCmdStoreRef,
               config_file: PathBuf,
               parser: GatewayConfigParserRef, ) -> Arc<Self> {
        Arc::new(Self {
            gateway: Mutex::new(None),
            external_cmd_store,
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

    async fn run_external_cmd(&self, cmd: impl Into<String>, params: impl Into<String>) -> ControlResult<String> {
        let cmd = cmd.into();
        let params = params.into();

        tokio::spawn(async move {
            let mut js_engine = JsEngine::builder()
                .enable_fetch(false)
                .build()
                .map_err(into_cmd_err!(ControlErrorCode::RunJsFailed))?;
            js_engine.eval_file(Path::new(cmd.as_str()))
                .map_err(into_cmd_err!(ControlErrorCode::RunJsFailed))?;

            let args: Vec<JsValue> = if let Some(args) = shlex::split(params.as_str()) {
                args.into_iter().map(|arg| JsValue::from(JsString::from(arg))).collect()
            } else {
                vec![]
            };
            let args = JsArray::from_iter(args.into_iter(), js_engine.context());
            let result = js_engine.call("main",
                                        vec![JsValue::from(args)])
                .map_err(into_cmd_err!(ControlErrorCode::RunJsFailed))?;
            if result.is_string() {
                Ok(result.as_string().unwrap().as_str().to_std_string_lossy())
            } else {
                Err(cmd_err!(ControlErrorCode::RunJsFailed, "result {:?}", result))
            }
        }).await.map_err(into_cmd_err!(ControlErrorCode::Failed))?
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
            let external_cmd = gateway.external_cmds.get_pkg(cmd)
                .await
                .map_err(into_cmd_err!(ControlErrorCode::Failed, "get pkg failed"))?;
            external_cmd.help().await.map_err(into_cmd_err!(ControlErrorCode::Failed, "get help failed"))
        } else {
            Ok("".to_string())
        }
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
                let params = serde_json::from_value::<HashMap<String, String>>(params)
                    .map_err(into_cmd_err!(ControlErrorCode::InvalidParams))?;
                let config_type = params.get("config_type");
                let config_id = params.get("config_id");
                if config_type.is_none() || config_id.is_none() {
                    gateway.get_all_config()
                        .map_err(|e| cmd_err!(ControlErrorCode::Failed, "{}", e))
                } else {
                    gateway.get_config(config_type.unwrap(), config_id.unwrap())
                        .map_err(|e| cmd_err!(ControlErrorCode::Failed, "{}", e))
                }
            },
            "del_rule" => {
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
                info!("*** reload gateway config ...");
                let gateway_config = load_config_from_file(self.config_file.as_path()).await
                    .map_err(|e| cmd_err!(ControlErrorCode::Failed, "{}", e))?;
                let gateway_config = self.parser.parse(gateway_config)
                    .map_err(into_cmd_err!(ControlErrorCode::Failed))?;
                gateway.reload(gateway_config).await
                    .map_err(|e| cmd_err!(ControlErrorCode::Failed, "{}", e))?;
                info!("*** reload gateway config success !");
                Ok(Value::String("ok".to_string()))
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
