use log::*;
use cyfs_gateway_lib::{ConfigErrorCode, ConfigResult, ProcessChainConfigs, ProcessChainHttpServerConfig, QuicStackConfig, RtcpStackConfig, ServerConfig, StackConfig, TcpStackConfig, UdpStackConfig, config_err, DirServerConfig, AcmeHttpChallengeServerConfig, ProcessChainConfig};
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

fn blocks_map_to_vector(blocks: &serde_json::Value) -> ConfigResult<serde_json::Value> {
    if let Some(blocks) = blocks.as_object() {
        let mut block_list = vec![];
        for (id, value) in blocks {
            let mut new_value = value.clone();
            new_value["id"] = serde_json::Value::String(id.to_string());
            block_list.push(new_value);
        }
        Ok(serde_json::Value::Array(block_list))
    } else {
        Err(config_err!(ConfigErrorCode::InvalidConfig, "invalid block config.It must be map\n{}",
            serde_json::to_string_pretty(blocks).unwrap()))
    }
}

fn hook_point_map_to_vector(hook_point: &serde_json::Value) -> ConfigResult<serde_json::Value> {
    if let Some(chains) = hook_point.as_object() {
        let mut chain_list = vec![];
        for (id, value) in chains {
            let mut new_value = value.clone();
            new_value["id"] = serde_json::Value::String(id.to_string());
            if let Some(blocks) = value.get("blocks") {
                new_value["blocks"] = blocks_map_to_vector(blocks)?;
            }
            chain_list.push(new_value);
        }
        let new_hook_point = serde_json::Value::Array(chain_list);
        ProcessChainConfigs::deserialize(new_hook_point.clone()).map_err(|e| {
            config_err!(ConfigErrorCode::InvalidConfig, "invalid hook point config.{}\n{}",
                e,
                serde_json::to_string_pretty(hook_point).unwrap())
        })?;
        Ok(new_hook_point)
    } else {
        Err(config_err!(ConfigErrorCode::InvalidConfig, "invalid hook point config.It must be map\n{}",
            serde_json::to_string_pretty(hook_point).unwrap()))
    }
}

fn hook_point_value_map_to_vector<D: for<'de> Deserializer<'de> + Clone>(de: D, key_name: &str) -> ConfigResult<serde_json::Value> {
    let mut stack_config = serde_json::Value::deserialize(de.clone()).map_err(|e| {
        config_err!(ConfigErrorCode::InvalidConfig, "invalid stack config.{}\n{}",
                e,
                serde_json::to_string_pretty(&serde_json::Value::deserialize(de.clone()).unwrap()).unwrap())
    })?;

    if let Some(hook_point) = stack_config.get(key_name) {
        let hook_point = hook_point_map_to_vector(hook_point)?;
        stack_config["hook_point"] = hook_point;
    };

    Ok(stack_config)
}


pub struct TcpStackConfigParser {}

impl TcpStackConfigParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl<D: for<'de> Deserializer<'de> + Clone> StackConfigParser<D> for TcpStackConfigParser {
    fn parse(&self, de: D) -> ConfigResult<Arc<dyn StackConfig>> {
        let tcp_config = TcpStackConfig::deserialize(hook_point_value_map_to_vector(de.clone(), "hook_point")?)
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
        let udp_config = UdpStackConfig::deserialize(hook_point_value_map_to_vector(de.clone(), "hook_point")?)
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
        let tls_config = cyfs_gateway_lib::TlsStackConfig::deserialize(hook_point_value_map_to_vector(de.clone(), "hook_point")?)
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
        let quic_config = QuicStackConfig::deserialize(hook_point_value_map_to_vector(de.clone(), "hook_point")?)
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
        let rtcp_config = RtcpStackConfig::deserialize(hook_point_value_map_to_vector(de.clone(), "hook_point")?)
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
        let tun_config = TunStackConfig::deserialize(hook_point_value_map_to_vector(de.clone(), "hook_point")?)
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
        let config = ProcessChainHttpServerConfig::deserialize(hook_point_value_map_to_vector(de.clone(), "hook_point")?)
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
        let config = DnsServerConfig::deserialize(hook_point_value_map_to_vector(de.clone(), "hook_point")?)
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
        let config = SocksServerConfig::deserialize(hook_point_value_map_to_vector(de.clone(), "hook_point")?)
            .map_err(|e| config_err!(ConfigErrorCode::InvalidConfig, "invalid socks server config.{}\n{}",
                e,
                serde_json::to_string_pretty(&serde_json::Value::deserialize(de.clone()).unwrap()).unwrap()))?;

        Ok(Arc::new(config))
    }
}


pub struct DirServerConfigParser {}

impl DirServerConfigParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl<D: for<'de> Deserializer<'de> + Clone> ServerConfigParser<D> for DirServerConfigParser {
    fn parse(&self, de: D) -> ConfigResult<Arc<dyn ServerConfig>> {
        let config = DirServerConfig::deserialize(de.clone())
            .map_err(|e| config_err!(ConfigErrorCode::InvalidConfig, "invalid dir server config.{}\n{}",
                e,
                serde_json::to_string_pretty(&serde_json::Value::deserialize(de.clone()).unwrap()).unwrap()
            ))?;
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

pub struct AcmeHttpChallengeServerConfigParser {}

impl AcmeHttpChallengeServerConfigParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl<D: for<'de> Deserializer<'de> + Clone> ServerConfigParser<D> for AcmeHttpChallengeServerConfigParser {
    fn parse(&self, de: D) -> ConfigResult<Arc<dyn ServerConfig>> {
        let config = AcmeHttpChallengeServerConfig::deserialize(de.clone())
            .map_err(|e| config_err!(ConfigErrorCode::InvalidConfig, "invalid acme http challenge server config.{:?}\n{}",
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
            let stack_value_list = stacks_value.as_object()
                .ok_or(config_err!(ConfigErrorCode::InvalidConfig, "invalid stacks config.\n{}",
                    serde_json::to_string_pretty(stacks_value).unwrap()))?;
            for (id, stack_value) in stack_value_list {
                let mut stack_value = stack_value.clone();
                stack_value["id"] = serde_json::Value::String(id.clone());
                stacks.push(self.stack_config_parser.parse(stack_value)?);
            }
        }

        let mut servers = vec![];
        if let Some(servers_value) = json_value.get("servers") {
            let servers_value_list = servers_value.as_object()
                .ok_or(config_err!(ConfigErrorCode::InvalidConfig, "invalid servers config.\n{}",
                    serde_json::to_string_pretty(servers_value).unwrap()))?;
            for (id, server_value) in servers_value_list {
                let mut server_value = server_value.clone();
                server_value["id"] = serde_json::Value::String(id.clone());
                servers.push(self.server_config_parser.parse(server_value)?);
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
                    let chain = serde_json::from_value::<ProcessChainConfig>(chain_value).map_err(|e| {
                        config_err!(ConfigErrorCode::InvalidConfig, "invalid global_process_chains: {:?}\n{}", e,
                        serde_json::to_string_pretty(global_chains_value).unwrap())
                    })?;
                    global_process_chains.push(chain);
                }
            }
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


        let limiters_config: Option<Vec<LimiterConfig>> = match json_value.get("limiters") {
            Some(config) => {
                let configs = config.as_object()
                    .ok_or(config_err!(ConfigErrorCode::InvalidConfig, "invalid limiters config.\n{}",
                        serde_json::to_string_pretty(config).unwrap()))?;
                let mut limiters_config = vec![];
                for (id, config) in configs {
                    let mut config = config.clone();
                    config["id"] = serde_json::Value::String(id.clone());
                    let config: LimiterConfig = serde_json::from_value(config.clone()).map_err(|e| {
                        config_err!(ConfigErrorCode::InvalidConfig, "invalid limiters: {:?}\n{}", e,
                        serde_json::to_string_pretty(&config).unwrap())
                    })?;


                    limiters_config.push(config);
                }


                // 数组需要根据upper_limiter的值进行排序，upper_limitter是必须指向LimiterConfig的另外的对象，这个对象必须排列在前面
                // 根据upper_limiter字段对limiters进行拓扑排序，确保被引用的对象排在前面
                let mut sorted_indices = Vec::with_capacity(limiters_config.len());
                let mut processed = std::collections::HashSet::new();

                while sorted_indices.len() < limiters_config.len() {
                    let mut changed = false;
                    for (index, limiter) in limiters_config.iter().enumerate() {
                        // 如果已经处理过了，跳过
                        if processed.contains(&index) {
                            continue;
                        }

                        // 检查是否有依赖或者依赖已经被处理
                        let can_process = match limiter.upper_limiter {
                            Some(ref upper_id) => {
                                // 查找upper_id对应的索引是否已被处理
                                let mut upper_processed = false;
                                for (upper_index, upper_limiter) in limiters_config.iter().enumerate() {
                                    if &upper_limiter.id == upper_id {
                                        upper_processed = processed.contains(&upper_index);
                                        break;
                                    }
                                }
                                // 如果找不到upper_id，也认为可以处理
                                upper_processed || !limiters_config.iter().any(|l| &l.id == upper_id)
                            },
                            None => true,
                        };

                        if can_process {
                            sorted_indices.push(index);
                            processed.insert(index);
                            changed = true;
                        }
                    }

                    // 如果一轮下来没有添加任何元素，说明存在循环依赖或无法解决的依赖关系
                    if !changed {
                        // 将未处理的元素按原顺序添加到最后
                        for (index, _) in limiters_config.iter().enumerate() {
                            if !processed.contains(&index) {
                                sorted_indices.push(index);
                            }
                        }
                        break;
                    }
                }

                // 根据排序后的索引构建最终的排序结果
                let sorted_limiters: Vec<LimiterConfig> = sorted_indices
                    .into_iter()
                    .map(|i| limiters_config[i].clone())
                    .collect();

                Some(sorted_limiters)
            },
            None => None
        };

        Ok(GatewayConfig {
            limiters_config,
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

#[derive(Deserialize, Clone)]
pub struct LimiterConfig {
    pub id: String,
    pub upper_limiter: Option<String>,
    #[serde(with = "speed_parser")]
    #[serde(default)]
    pub download_speed: Option<u64>,
    #[serde(with = "speed_parser")]
    #[serde(default)]
    pub upload_speed: Option<u64>,
    pub concurrent: Option<u64>,
}

mod speed_parser {
    use serde::{Deserialize, Deserializer};
    use serde::de::Error;
    use cyfs_gateway_lib::parse_speed;

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = Option::<String>::deserialize(deserializer)?;
        if s.is_none() {
            return Ok(None);
        }
        match parse_speed(s.unwrap().as_str()) {
            Ok(speed) => Ok(Some(speed)),
            Err(e) => {
                Err(D::Error::custom(e))
            },
        }
    }
}

pub struct GatewayConfig {
    pub limiters_config: Option<Vec<LimiterConfig>>,
    pub acme_config: Option<AcmeConfig>,
    pub stacks: Vec<Arc<dyn StackConfig>>,
    pub servers: Vec<Arc<dyn ServerConfig>>,
    pub global_process_chains: ProcessChainConfigs,
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_limiter_config_parser() {
        let json = r#"
        {
            "id": "limiter_id",
            "upper_limiter": "upper_limiter",
            "download_speed": "100KB/s",
            "upload_speed": "100KB/s",
            "concurrent": 100
        }
        "#;
        let config = serde_json::from_str::<super::LimiterConfig>(json).unwrap();
        assert_eq!(config.upper_limiter, Some("upper_limiter".to_string()));
        assert_eq!(config.download_speed, Some(100 * 1024));
        assert_eq!(config.upload_speed, Some(100 * 1024));
        assert_eq!(config.concurrent, Some(100));

        let json = r#"
        {
            "id": "limiter_id",
            "download_speed": "100KB/s",
            "upload_speed": "100KB/s",
            "concurrent": 100
        }
        "#;
        let config = serde_json::from_str::<super::LimiterConfig>(json).unwrap();
        assert_eq!(config.upper_limiter, None);
        assert_eq!(config.download_speed, Some(100 * 1024));
        assert_eq!(config.upload_speed, Some(100 * 1024));
        assert_eq!(config.concurrent, Some(100));

        let json = r#"
        {
            "id": "limiter_id",
            "upper_limiter": "upper_limiter",
            "download_speed": "101KB/s",
            "concurrent": 100
        }
        "#;
        let config = serde_json::from_str::<super::LimiterConfig>(json).unwrap();
        assert_eq!(config.upper_limiter, Some("upper_limiter".to_string()));
        assert_eq!(config.upload_speed, None);
        assert_eq!(config.download_speed, Some(101 * 1024));
        assert_eq!(config.concurrent, Some(100));

        let json = r#"
        {
            "id": "limiter_id",
            "upper_limiter": "upper_limiter",
            "download_speed": "100KB/s",
            "upload_speed": "100KB/s"
        }
        "#;
        let config = serde_json::from_str::<super::LimiterConfig>(json).unwrap();
        assert_eq!(config.upper_limiter, Some("upper_limiter".to_string()));
        assert_eq!(config.download_speed, Some(100 * 1024));
        assert_eq!(config.upload_speed, Some(100 * 1024));
        assert_eq!(config.concurrent, None);
    }
}
