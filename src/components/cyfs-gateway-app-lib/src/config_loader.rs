use std::sync::Arc;

use crate::*;

use cyfs_gateway_lib::{
    config_err, CollectionConfig, ConfigErrorCode, ConfigResult, ProcessChainConfig,
    ProcessChainConfigs, ServerConfig, StackConfig,
};
use log::*;

pub struct GatewayConfigParser {
    composition: Arc<GatewayComposition>,
}

pub type GatewayConfigParserRef = Arc<GatewayConfigParser>;

impl GatewayConfigParser {
    pub fn new(composition: Arc<GatewayComposition>) -> Self {
        Self { composition }
    }

    pub fn server_registry(&self) -> &Arc<GatewayServerRegistry> {
        self.composition.server_registry()
    }

    pub fn stack_registry(&self) -> &Arc<GatewayStackRegistry> {
        self.composition.stack_registry()
    }

    pub fn composition(&self) -> &Arc<GatewayComposition> {
        &self.composition
    }

    pub fn parse(&self, json_value: serde_json::Value) -> ConfigResult<GatewayConfig> {
        let raw_config = json_value.clone();
        let identity_manager = json_value
            .get("identity_manager")
            .map(|value| {
                serde_json::from_value::<GatewayIdentityManagerConfig>(value.clone()).map_err(|e| {
                    config_err!(
                        ConfigErrorCode::InvalidConfig,
                        "invalid identity_manager config: {:?}\n{}",
                        e,
                        serde_json::to_string_pretty(value)
                            .unwrap_or_else(|_| "<invalid json>".to_string())
                    )
                })
            })
            .transpose()?;

        let mut stacks = vec![];
        if let Some(stacks_value) = json_value.get("stacks") {
            let stack_value_list = stacks_value.as_object();
            if stack_value_list.is_none() {
                warn!(
                    "invalid stacks config,stacks_value.as_object() is None input:\n{:?}",
                    stacks_value
                );
                return Err(config_err!(
                    ConfigErrorCode::InvalidConfig,
                    "invalid stacks config,stacks_value.as_object() is None input:\n{}",
                    serde_json::to_string_pretty(stacks_value).unwrap()
                ));
            }

            for (id, stack_value) in stack_value_list.unwrap() {
                let mut stack_value = stack_value.clone();
                stack_value["id"] = serde_json::Value::String(id.clone());
                stack_value =
                    apply_gateway_identity_manager_to_stack(stack_value, identity_manager.as_ref());
                stacks.push(
                    self.composition
                        .stack_registry()
                        .parse_stack_config(stack_value)?,
                );
            }
        }

        let mut servers = vec![];
        if let Some(servers_value) = json_value.get("servers") {
            let servers_value_list = servers_value.as_object();
            if servers_value_list.is_none() {
                warn!(
                    "invalid servers config,servers_value.as_object() is None input:\n{:?}",
                    servers_value
                );
                return Err(config_err!(
                    ConfigErrorCode::InvalidConfig,
                    "invalid servers config,servers_value.as_object() is None input:\n{}",
                    serde_json::to_string_pretty(servers_value).unwrap()
                ));
            }

            for (id, server_value) in servers_value_list.unwrap() {
                let mut server_value = server_value.clone();
                server_value["id"] = serde_json::Value::String(id.clone());
                servers.push(
                    self.composition
                        .server_registry()
                        .parse_server_config(server_value)?,
                );
            }
        }

        let mut global_process_chains = vec![];
        if let Some(global_chains_value) = json_value.get("global_process_chains") {
            if let Some(global_chains_value) = global_chains_value.as_object() {
                for (id, process_chain) in global_chains_value.iter() {
                    let mut chain_value = process_chain.clone();
                    chain_value["id"] = serde_json::Value::String(id.clone());
                    if let Some(blocks) = chain_value.get("blocks") {
                        chain_value["blocks"] = blocks_map_to_vector(blocks)?;
                    }
                    let chain =
                        serde_json::from_value::<ProcessChainConfig>(chain_value).map_err(|e| {
                            config_err!(
                                ConfigErrorCode::InvalidConfig,
                                "invalid global_process_chains: {:?}\n{}",
                                e,
                                serde_json::to_string_pretty(global_chains_value).unwrap()
                            )
                        })?;
                    global_process_chains.push(chain);
                }
            }
        }

        let tls_ca: Option<TlsCA> = match json_value.get("tls_ca") {
            Some(config) => match serde_json::from_value::<TlsCA>(config.clone()) {
                Ok(config) => Some(config),
                Err(err) => {
                    let msg = format!("invalid ca config: {}", err);
                    error!("{}", msg);
                    None
                }
            },
            None => None,
        };

        let limiters_config = parse_limiters_from_raw_config(&json_value)?;
        let collections = parse_collections_from_raw_config(
            &json_value,
            self.composition.profile().service_data_namespace,
        )?;
        let timers = parse_timers_from_raw_config(&json_value)?;
        let device_manager = json_value
            .get("device_manager")
            .map(|value| {
                serde_json::from_value::<DeviceManagerConfig>(value.clone()).map_err(|e| {
                    config_err!(
                        ConfigErrorCode::InvalidConfig,
                        "invalid device_manager config: {:?}\n{}",
                        e,
                        serde_json::to_string_pretty(value)
                            .unwrap_or_else(|_| "<invalid json>".to_string())
                    )
                })
            })
            .transpose()?
            .unwrap_or_default();
        let traffic = match (
            json_value.get("traffic"),
            self.composition.traffic_adapter(),
        ) {
            (value, Some(adapter)) => Some(adapter.parse_config(value)?),
            (Some(_), None) => {
                return Err(config_err!(
                    ConfigErrorCode::InvalidConfig,
                    "config section 'traffic' requires an installed traffic module; installed modules: [{}]",
                    self.composition.manifest().modules.join(", ")
                ));
            }
            (None, None) => None,
        };

        Ok(GatewayConfig {
            raw_config,
            identity_manager: identity_manager.clone(),
            limiters_config,
            acme_config: parse_acme_config_from_raw_config(&json_value, identity_manager.as_ref()),
            tls_ca,
            stacks,
            servers,
            global_process_chains,
            collections,
            timers,
            device_manager,
            traffic,
        })
    }
}

fn parse_limiters_from_raw_config(
    raw_config: &serde_json::Value,
) -> ConfigResult<Option<Vec<LimiterConfig>>> {
    let Some(config) = raw_config.get("limiters") else {
        return Ok(None);
    };
    let configs = config.as_object().ok_or(config_err!(
        ConfigErrorCode::InvalidConfig,
        "invalid limiters config.\n{}",
        serde_json::to_string_pretty(config).unwrap()
    ))?;
    let mut limiters_config = vec![];
    for (id, config) in configs {
        let mut config = config.clone();
        config["id"] = serde_json::Value::String(id.clone());
        let config: LimiterConfig = serde_json::from_value(config.clone()).map_err(|e| {
            config_err!(
                ConfigErrorCode::InvalidConfig,
                "invalid limiters: {:?}\n{}",
                e,
                serde_json::to_string_pretty(&config).unwrap()
            )
        })?;
        limiters_config.push(config);
    }

    let mut sorted_indices = Vec::with_capacity(limiters_config.len());
    let mut processed = std::collections::HashSet::new();
    while sorted_indices.len() < limiters_config.len() {
        let mut changed = false;
        for (index, limiter) in limiters_config.iter().enumerate() {
            if processed.contains(&index) {
                continue;
            }

            let can_process = match limiter.upper_limiter {
                Some(ref upper_id) => {
                    let mut upper_processed = false;
                    for (upper_index, upper_limiter) in limiters_config.iter().enumerate() {
                        if &upper_limiter.id == upper_id {
                            upper_processed = processed.contains(&upper_index);
                            break;
                        }
                    }
                    upper_processed || !limiters_config.iter().any(|l| &l.id == upper_id)
                }
                None => true,
            };

            if can_process {
                sorted_indices.push(index);
                processed.insert(index);
                changed = true;
            }
        }

        if !changed {
            for (index, _) in limiters_config.iter().enumerate() {
                if !processed.contains(&index) {
                    sorted_indices.push(index);
                }
            }
            break;
        }
    }

    Ok(Some(
        sorted_indices
            .into_iter()
            .map(|i| limiters_config[i].clone())
            .collect(),
    ))
}

#[derive(Clone)]
pub struct GatewayConfig {
    pub raw_config: serde_json::Value,
    pub identity_manager: Option<GatewayIdentityManagerConfig>,
    pub limiters_config: Option<Vec<LimiterConfig>>,
    pub acme_config: Option<AcmeConfig>,
    pub tls_ca: Option<TlsCA>,
    pub stacks: Vec<Arc<dyn StackConfig>>,
    pub servers: Vec<Arc<dyn ServerConfig>>,
    pub global_process_chains: ProcessChainConfigs,
    pub collections: Vec<CollectionConfig>,
    pub timers: Vec<TimerConfig>,
    pub device_manager: DeviceManagerConfig,
    pub traffic: Option<GatewayTrafficConfigRef>,
}
