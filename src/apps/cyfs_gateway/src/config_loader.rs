use cyfs_gateway_lib::{ConfigErrorCode, ConfigResult, ProcessChainConfigs, ProcessChainHttpServerConfig, QuicStackConfig, RtcpStackConfig, ServerConfig, StackConfig, TcpStackConfig, UdpStackConfig, config_err};
use cyfs_socks::SocksServerConfig;
use cyfs_sn::*;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use serde::{Deserialize, Deserializer, Serialize};
use cyfs_dns::{DnsServerConfig, LocalDnsConfig};
use cyfs_tun::TunStackConfig;
//use buckyos_api::ZONE_PROVIDER;

pub trait StackConfigParser<D: for<'de> Deserializer<'de>>: Send + Sync {
    fn parse(&self, de: D) -> ConfigResult<Arc<dyn StackConfig>>;
}

pub struct CyfsStackConfigParser<D: for<'de> Deserializer<'de>> {
    parsers: Mutex<HashMap<String, Arc<dyn StackConfigParser<D>>>>,
}

impl<D: for<'de> Deserializer<'de>> Default for CyfsStackConfigParser<D> {
    fn default() -> Self {
        Self::new()
    }
}

impl<D: for<'de> Deserializer<'de>> CyfsStackConfigParser<D> {
    pub fn new() -> Self {
        Self {
            parsers: Mutex::new(HashMap::new()),
        }
    }

    pub fn register(&self, protocol: &str, factory: Arc<dyn StackConfigParser<D>>) {
        self.parsers.lock().unwrap().insert(protocol.to_string(), factory);
    }
}

#[derive(Serialize, Deserialize)]
struct StackProtocolConfig {
    protocol: String,
}

impl<D: for<'de> Deserializer<'de> + Clone> StackConfigParser<D> for CyfsStackConfigParser<D> {
    fn parse(&self, de: D) -> ConfigResult<Arc<dyn StackConfig>> {
        let config = StackProtocolConfig::deserialize(de.clone())
            .map_err(|e| config_err!(ConfigErrorCode::InvalidConfig, "invalid stack config.{}\n{}",
                e,
                serde_json::to_string_pretty(&serde_json::Value::deserialize(de.clone()).unwrap()).unwrap()))?;
        let factory = {
            self.parsers.lock().unwrap().get(config.protocol.as_str())
                .ok_or(config_err!(ConfigErrorCode::InvalidConfig, "invalid stack config.{}\n{}",
                    config.protocol,
                    serde_json::to_string_pretty(&serde_json::Value::deserialize(de.clone()).unwrap()).unwrap()
                ))?.clone()
        };
        factory.parse(de)
    }
}

pub struct TcpStackConfigParser {}

impl TcpStackConfigParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl<D: for<'de> Deserializer<'de> + Clone> StackConfigParser<D> for TcpStackConfigParser {
    fn parse(&self, de: D) -> ConfigResult<Arc<dyn StackConfig>> {
        let tcp_config = TcpStackConfig::deserialize(de.clone())
            .map_err(|e| config_err!(ConfigErrorCode::InvalidConfig, "invalid tcp stack config.{}\n{}",
                e,
                serde_json::to_string_pretty(&serde_json::Value::deserialize(de.clone()).unwrap()).unwrap()))?;
        Ok(Arc::new(tcp_config))
    }
}

pub struct UdpStackConfigParser {}

impl UdpStackConfigParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl<D: for<'de> Deserializer<'de> + Clone> StackConfigParser<D> for UdpStackConfigParser {
    fn parse(&self, de: D) -> ConfigResult<Arc<dyn StackConfig>> {
        let udp_config = UdpStackConfig::deserialize(de.clone())
            .map_err(|e| config_err!(ConfigErrorCode::InvalidConfig, "invalid udp stack config.{}\n{}",
                e,
                serde_json::to_string_pretty(&serde_json::Value::deserialize(de.clone()).unwrap()).unwrap()))?;
        Ok(Arc::new(udp_config))
    }
}
pub struct TlsStackConfigParser {}

impl TlsStackConfigParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl<D: for<'de> Deserializer<'de> + Clone> StackConfigParser<D> for TlsStackConfigParser {
    fn parse(&self, de: D) -> ConfigResult<Arc<dyn StackConfig>> {
        let tls_config = cyfs_gateway_lib::TlsStackConfig::deserialize(de.clone())
            .map_err(|e| config_err!(ConfigErrorCode::InvalidConfig, "invalid tls stack config: {}\n{}",
                e,
                serde_json::to_string_pretty(&serde_json::Value::deserialize(de.clone()).unwrap()).unwrap()))?;
        Ok(Arc::new(tls_config))
    }
}

pub struct QuicStackConfigParser {}

impl QuicStackConfigParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl<D: for<'de> Deserializer<'de> + Clone> StackConfigParser<D> for QuicStackConfigParser {
    fn parse(&self, de: D) -> ConfigResult<Arc<dyn StackConfig>> {
        let quic_config = QuicStackConfig::deserialize(de.clone())
            .map_err(|e| config_err!(ConfigErrorCode::InvalidConfig, "invalid quic stack config: {}\n{}",
                e,
                serde_json::to_string_pretty(&serde_json::Value::deserialize(de.clone()).unwrap()).unwrap()))?;
        Ok(Arc::new(quic_config))
    }
}
pub struct RtcpStackConfigParser {}

impl RtcpStackConfigParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl<D: for<'de> Deserializer<'de> + Clone> StackConfigParser<D> for RtcpStackConfigParser {
    fn parse(&self, de: D) -> ConfigResult<Arc<dyn StackConfig>> {
        let rtcp_config = RtcpStackConfig::deserialize(de.clone())
            .map_err(|e| config_err!(ConfigErrorCode::InvalidConfig, "invalid rtcp stack config: {}\n{}",
                e,
                serde_json::to_string_pretty(&serde_json::Value::deserialize(de.clone()).unwrap()).unwrap()))?;
        Ok(Arc::new(rtcp_config))
    }
}

pub struct TunStackConfigParser {}

impl TunStackConfigParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl<D: for<'de> Deserializer<'de> + Clone> StackConfigParser<D> for TunStackConfigParser {
    fn parse(&self, de: D) -> ConfigResult<Arc<dyn StackConfig>> {
        let tun_config = TunStackConfig::deserialize(de.clone())
            .map_err(|e| config_err!(ConfigErrorCode::InvalidConfig, "invalid tun stack config: {}\n{}",
                e,
                serde_json::to_string_pretty(&serde_json::Value::deserialize(de.clone()).unwrap()).unwrap())
            )?;
        Ok(Arc::new(tun_config))
    }
}

pub trait ServerConfigParser<D: for<'de> Deserializer<'de>>: Send + Sync {
    fn parse(&self, de: D) -> ConfigResult<Arc<dyn ServerConfig>>;
}

pub struct CyfsServerConfigParser<D: for<'de> Deserializer<'de>> {
    parsers: Mutex<HashMap<String, Arc<dyn ServerConfigParser<D>>>>,
}

impl<D: for<'de> Deserializer<'de>> CyfsServerConfigParser<D> {
    pub fn new() -> Self {
        Self {
            parsers: Mutex::new(HashMap::new()),
        }
    }

    pub fn register(&self, name: &str, parser: Arc<dyn ServerConfigParser<D>>) {
        self.parsers.lock().unwrap().insert(name.to_string(), parser);
    }
}

#[derive(Serialize, Deserialize)]
pub struct ServerConfigType {
    #[serde(rename = "type")]
    ty: String,
}

impl<D: for<'de> Deserializer<'de> + Clone> ServerConfigParser<D> for CyfsServerConfigParser<D> {
    fn parse(&self, de: D) -> ConfigResult<Arc<dyn ServerConfig>> {
        let server_type = ServerConfigType::deserialize(de.clone())
            .map_err(|e| config_err!(ConfigErrorCode::InvalidConfig, "invalid stack config.{}", e))?;
        let parser = {
            self.parsers.lock().unwrap().get(&server_type.ty).cloned()
        };
        if let Some(parser) = parser {
            parser.parse(de)
        } else {
            Err(config_err!(
                ConfigErrorCode::InvalidConfig,
                "invalid stack config.unknown server type:{}",
                server_type.ty
            ))
        }
    }
}


pub struct HttpServerConfigParser {}

impl HttpServerConfigParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl<D: for<'de> Deserializer<'de> + Clone> ServerConfigParser<D> for HttpServerConfigParser {
    fn parse(&self, de: D) -> ConfigResult<Arc<dyn ServerConfig>> {
        let config = ProcessChainHttpServerConfig::deserialize(de.clone())
            .map_err(|e| config_err!(ConfigErrorCode::InvalidConfig, "invalid http server config.{}\n{}",
                e,
                serde_json::to_string_pretty(&serde_json::Value::deserialize(de.clone()).unwrap()).unwrap()))?;
        Ok(Arc::new(config))
    }
}

pub struct DnsServerConfigParser {
}

impl DnsServerConfigParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl<D: for<'de> Deserializer<'de> + Clone> ServerConfigParser<D> for DnsServerConfigParser {
    fn parse(&self, de: D) -> ConfigResult<Arc<dyn ServerConfig>> {
        let config = DnsServerConfig::deserialize(de.clone())
            .map_err(|e| config_err!(ConfigErrorCode::InvalidConfig, "invalid dns server config.{:?}\n{}",
                e,
                serde_json::to_string_pretty(&serde_json::Value::deserialize(de.clone()).unwrap()).unwrap()
            ))?;
        Ok(Arc::new(config))
    }
}

pub struct SocksServerConfigParser {}

impl SocksServerConfigParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl<D: for<'de> Deserializer<'de> + Clone> ServerConfigParser<D> for SocksServerConfigParser {
    fn parse(&self, de: D) -> ConfigResult<Arc<dyn ServerConfig>> {
        let config = SocksServerConfig::deserialize(de.clone())
            .map_err(|e| config_err!(ConfigErrorCode::InvalidConfig, "invalid socks server config.{}\n{}",
                e,
                serde_json::to_string_pretty(&serde_json::Value::deserialize(de.clone()).unwrap()).unwrap()))?;

        Ok(Arc::new(config))
    }
}







pub struct LocalDnsConfigParser {}

impl LocalDnsConfigParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl<D: for<'de> Deserializer<'de> + Clone> ServerConfigParser<D> for LocalDnsConfigParser {
    fn parse(&self, de: D) -> ConfigResult<Arc<dyn ServerConfig>> {
        let config = LocalDnsConfig::deserialize(de.clone())
            .map_err(|e| config_err!(ConfigErrorCode::InvalidConfig, "invalid local dns config.{:?}\n{}",
                e,
                serde_json::to_string_pretty(&serde_json::Value::deserialize(de.clone()).unwrap()).unwrap()
            ))?;
        Ok(Arc::new(config))
    }
}

pub struct SNServerConfigParser {}

impl SNServerConfigParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl<D: for<'de> Deserializer<'de> + Clone> ServerConfigParser<D> for SNServerConfigParser {
    fn parse(&self, de: D) -> ConfigResult<Arc<dyn ServerConfig>> {
        let config = SNServerConfig::deserialize(de.clone())
            .map_err(|e| config_err!(ConfigErrorCode::InvalidConfig, "invalid sn server config.{:?}\n{}",
                e,
                serde_json::to_string_pretty(&serde_json::Value::deserialize(de.clone()).unwrap()).unwrap()
            ))?;
        Ok(Arc::new(config))
    }
}

pub struct GatewayConfigParser {
    stack_config_parser: CyfsStackConfigParser<serde_json::Value>,
    server_config_parser: CyfsServerConfigParser<serde_json::Value>,

}

impl GatewayConfigParser {
    pub fn new() -> Self {
        let cyfs_stack_parser = CyfsStackConfigParser::new();

        let cyfs_server_parser = CyfsServerConfigParser::new();


        GatewayConfigParser {
            stack_config_parser: cyfs_stack_parser,
            server_config_parser: cyfs_server_parser,
        }
    }

    pub fn register_stack_config_parser(&self, protocol: &str, parser: Arc<dyn StackConfigParser<serde_json::Value>>) {
        self.stack_config_parser.register(protocol, parser);
    }

    pub fn register_server_config_parser(&self, server_type: &str, parser: Arc<dyn ServerConfigParser<serde_json::Value>>) {
        self.server_config_parser.register(server_type, parser);
    }

    pub fn parse(&self, json_value: serde_json::Value) -> ConfigResult<GatewayConfig> {
        let mut stacks = vec![];
        if let Some(stacks_value) = json_value.get("stacks") {
            let stack_value_list = stacks_value.as_array()
                .ok_or(config_err!(ConfigErrorCode::InvalidConfig, "invalid stacks config.\n{}",
                    serde_json::to_string_pretty(stacks_value).unwrap()))?;
            for stack_value in stack_value_list {
                stacks.push(self.stack_config_parser.parse(stack_value.clone())?);
            }
        }

        let mut servers = vec![];
        if let Some(servers_value) = json_value.get("servers") {
            let servers_value_list = servers_value.as_array()
                .ok_or(config_err!(ConfigErrorCode::InvalidConfig, "invalid servers config.\n{}",
                    serde_json::to_string_pretty(servers_value).unwrap()))?;
            for server_value in servers_value_list {
                servers.push(self.server_config_parser.parse(server_value.clone())?);
            }
        }


        let mut global_process_chains = vec![];
        if let Some(global_chains_value) = json_value.get("global_process_chains") {
            global_process_chains = serde_json::from_value(global_chains_value.clone()).map_err(|e| {
                config_err!(ConfigErrorCode::InvalidConfig, "invalid global_process_chains: {:?}\n{}", e,
                serde_json::to_string_pretty(global_chains_value).unwrap())
            })?;
        }

        let acme_config: Option<AcmeConfig> = match json_value.get("acme") {
            Some(config) => {
                match serde_json::from_value::<AcmeConfig>(config.clone()) {
                    Ok(config) => Some(config),
                    Err(err) => {
                        let msg = format!("invalid acme config: {}", err);
                        error!("{}", msg);
                        None
                    }
                }
            },
            None => None
        };
        Ok(GatewayConfig {
            acme_config,
            stacks,
            servers,
            global_process_chains,
        })
    }
}

#[derive(Deserialize, Clone)]
pub struct AcmeConfig {
    pub account: Option<String>,
    pub issuer: Option<String>,
    pub dns_providers: Option<HashMap<String, serde_json::Value>>,
    pub check_interval: Option<u64>,
    pub renew_before_expiry: Option<u64>,
}


pub struct GatewayConfig {
    pub acme_config: Option<AcmeConfig>,
    pub stacks: Vec<Arc<dyn StackConfig>>,
    pub servers: Vec<Arc<dyn ServerConfig>>,
    pub global_process_chains: ProcessChainConfigs,
}
