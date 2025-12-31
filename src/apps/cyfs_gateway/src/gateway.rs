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
use serde::Serialize;
use serde_json::{json, Value};
use sfo_js::{JsEngine, JsString, JsValue};
use sfo_js::object::builtins::JsArray;
use sha2::Digest;
use crate::gateway_control_client::{cmd_err, into_cmd_err};
use crate::gateway_control_server::{ControlErrorCode, ControlResult, GatewayControlCmdHandler, CyfsTokenFactory, CyfsTokenVerifier};
use crate::config_loader::GatewayConfigParser;
use crate::gateway_control_server::{GATEWAY_CONTROL_SERVER_CONFIG, GATEWAY_CONTROL_SERVER_KEY};

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

    connection_manager: ConnectionManagerRef,
    tunnel_manager: TunnelManager,

    //inner_service_factory: CyfsInnerServiceFactoryRef,
    //inner_service_manager: InnerServiceManagerRef,
    acme_mgr: AcmeCertManagerRef,
    limiter_manager: LimiterManagerRef,
    stat_manager: StatManagerRef,
    self_cert_mgr: SelfCertMgrRef,
    global_collection_manager: GlobalCollectionManagerRef,
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
        global_collection_manager: GlobalCollectionManagerRef, ) -> Self {
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
            global_process_chains: self.global_process_chains.clone(),
            connection_manager: self.connection_manager.clone(),
            acme_mgr: self.acme_mgr.clone(),
            stack_factory: self.stack_factory.clone(),
            server_factory: self.server_factory.clone(),
            limiter_manager: self.limiter_manager.clone(),
            stat_manager: self.stat_manager.clone(),
            self_cert_mgr: self.self_cert_mgr.clone(),
            global_collection_manager: self.global_collection_manager.clone(),
        })
    }
}

pub struct Gateway {
    config: Arc<Mutex<GatewayConfig>>,
    stack_manager: StackManagerRef,
    tunnel_manager: TunnelManager,
    server_manager: ServerManagerRef,
    global_process_chains: GlobalProcessChainsRef,
    connection_manager: ConnectionManagerRef,
    acme_mgr: AcmeCertManagerRef,
    stack_factory: CyfsStackFactoryRef,
    server_factory: CyfsServerFactoryRef,
    limiter_manager: LimiterManagerRef,
    stat_manager: StatManagerRef,
    self_cert_mgr: SelfCertMgrRef,
    global_collection_manager: GlobalCollectionManagerRef,
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

        let config = self.config.clone();
        let sn_list = params.keep_tunnel.clone();
        if sn_list.len() > 0 {
            let sn = sn_list[0].clone();
            let weak_acme_mgr = Arc::downgrade(&self.acme_mgr);
            self.acme_mgr.register_dns_provider("sn-dns", move |op: String, domain: String, key_hash: String| {
                let sn = sn.clone();
                let mut rtcp_config = None;
                let config = config.lock().unwrap();
                for config in config.stacks.iter() {
                    if config.stack_protocol() == StackProtocol::Rtcp {
                        rtcp_config = Some(config.clone());
                    }
                }
                let weak_acme_mgr = weak_acme_mgr.clone();
                async move {
                    let mut token = None;
                    let mut did = None;
                    if let Some(config) = rtcp_config {
                        let config = config.as_ref().as_any().downcast_ref::<RtcpStackConfig>()
                            .ok_or(anyhow!("invalid rtcp stack config"))?;
                        let private_key = load_raw_private_key(Path::new(config.key_path.as_str()))
                            .map_err(|_| anyhow!(format!("load private key {} failed", config.key_path)))?;
                        let public_key = encode_ed25519_pkcs8_sk_to_pk(&private_key);

                        let encoding_key = jsonwebtoken::EncodingKey::from_ed_der(private_key.as_slice());
                        let (token_str, _) = RPCSessionToken::generate_jwt_token("cyfs_gateway", "cyfs_gateway", None, &encoding_key)
                            .map_err(|_| anyhow!(format!("generate jwt token failed")))?;
                        let device_config = DeviceConfig::new("cyfs_gateway", public_key);
                        token = Some(token_str);
                        did = Some(device_config.id);
                    }

                    if token.is_none() {
                        return Err(anyhow!("no rtcp stack found"));
                    }
                    let krpc = kRPC::kRPC::new(format!("https://{}", sn).as_str(), token);
                    if op == "add_challenge" {
                        krpc.call("add_dns_record", json!({
                            "device_did": did.unwrap().to_string(),
                            "domain": domain,
                            "record_type": "TXT",
                            "record": key_hash,
                            "ttl": 600
                        })).await.map_err(|_| anyhow!(format!("add_dns_record failed")))?;
                    } else if op == "del_challenge" {
                        let mut has_cert = false;
                        if let Some(acme_mgr) = weak_acme_mgr.upgrade() {
                            if let Some(cert) = acme_mgr.get_cert_by_host(domain.as_str()) {
                                if let Some(_) = cert.get_cert() {
                                    has_cert = true;
                                }
                            }
                        }
                        krpc.call("remove_dns_record", json!({
                            "device_did": did.unwrap().to_string(),
                            "domain": domain,
                            "record_type": "TXT",
                            "has_cert": has_cert,
                        })).await.map_err(|_| anyhow!(format!("add_dns_record failed")))?;
                    }
                    Ok(())
                }
            });
        }

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

    pub async fn add_chain(&self, config_type: &str, config_id: &str, hook_point: Option<String>, chain: ProcessChainConfig) -> Result<()> {
        if config_id == GATEWAY_CONTROL_SERVER_KEY {
            return Err(anyhow::Error::new(cmd_err!(
            ControlErrorCode::ConfigNotFound,
            "Config not found: {}", config_id,
        )));
        }
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
                    if let Some(stack) = self.stack_manager.get_stack(config_id) {
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
                    let new_server = self.server_factory.create(server_config.clone()).await?;
                    for server in new_server.into_iter() {
                        self.server_manager.replace_server(server);
                    }
                    let mut config = self.config.lock().unwrap();
                    config.servers[index] = server_config;
                }
            }
            _ => {
                Err(cmd_err!(
                    ControlErrorCode::InvalidConfigType,
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
                    if let Some(stack) = self.stack_manager.get_stack(config_id) {
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
                    let new_server = self.server_factory.create(server_config.clone()).await?;
                    for server in new_server.into_iter() {
                        self.server_manager.replace_server(server);
                    }
                    let mut config = self.config.lock().unwrap();
                    config.servers[index] = server_config;
                }
            }
            _ => {
                Err(cmd_err!(
                    ControlErrorCode::InvalidConfigType,
                    "Invalid config type: {}", config_type,
                ))?;
            }
        }
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

pub struct GatewayCmdHandler {
    gateway: Mutex<Option<Arc<Gateway>>>,
    external_cmd_store: ExternalCmdStoreRef,
    config_file: PathBuf,
    parser: GatewayConfigParser,
}

impl GatewayCmdHandler {
    pub fn new(external_cmd_store: ExternalCmdStoreRef,
               config_file: PathBuf,
               parser: GatewayConfigParser, ) -> Arc<Self> {
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
            "del_chain" => {
                let params = serde_json::from_value::<HashMap<String, String>>(params)
                    .map_err(into_cmd_err!(ControlErrorCode::InvalidParams))?;
                let config_type = params.get("config_type");
                let config_id = params.get("config_id");
                let hook_point = params.get("hook_point");
                let chain_id = params.get("chain_id");
                if config_type.is_none() || config_id.is_none() || chain_id.is_none() {
                    Err(cmd_err!(
                        ControlErrorCode::InvalidParams,
                        "Invalid params: config_type or chain_id or config_id is None",
                    ))?;
                }

                gateway.remove_chain(config_type.unwrap(),
                                     config_id.unwrap(),
                                     hook_point.map(|s| s.to_string()),
                                     params.get("chain_id").unwrap()).await
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
            "add_chain" => {
                let params = serde_json::from_value::<HashMap<String, String>>(params)
                    .map_err(into_cmd_err!(ControlErrorCode::InvalidParams))?;
                let config_type = params.get("config_type");
                let config_id = params.get("config_id");
                let hook_point = params.get("hook_point");
                let chain_id = params.get("chain_id");
                let chain_type = params.get("chain_type");
                let chain_params = params.get("chain_params");
                if config_type.is_none() || config_id.is_none() || chain_id.is_none() || chain_type.is_none() || chain_params.is_none() {
                    Err(cmd_err!(
                        ControlErrorCode::InvalidParams,
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
                        priority: 1,
                        block: block.trim().to_string(),
                    }],
                };
                gateway.add_chain(
                    config_type.unwrap(),
                    config_id.unwrap(),
                    hook_point.map(|s| s.to_string()),
                    process_chain_config,
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
