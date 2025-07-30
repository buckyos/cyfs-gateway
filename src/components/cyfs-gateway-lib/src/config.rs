

use tokio::fs;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use serde::{Deserialize, Serialize};
use url::Url;
use cyfs_socks::SocksProxyConfig;

fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize, Clone)]
pub struct NamedDataMgrRouteConfig {
    pub named_data_mgr_id : String,
    #[serde(default = "default_true")]
    pub read_only:bool,
    #[serde(default = "default_true")]
    pub guest_access:bool,// 是否允许zone外访问
    #[serde(default = "default_true")]
    //是否将chunkid放在路径的第一级，
    //如果为true，则使用https://ndn.$zoneid/$chunkid/index.html?ref=www.buckyos.org
    //如果为false，则将chunkid放在host的第一段https://$chunkid.ndn.$zoneid/index.html?ref=www.buckyos.org
    pub is_object_id_in_path:bool,
    #[serde(default = "default_true")]
    pub enable_mgr_file_path:bool,// 是否使用mgr路径模式
    #[serde(default = "default_true")]
    pub enable_zone_put_chunk:bool
}

impl Default for NamedDataMgrRouteConfig {
    fn default()->Self {
        Self {
            named_data_mgr_id:"default".to_string(),
            read_only:true,
            guest_access:false,
            is_object_id_in_path:true,
            enable_mgr_file_path:true,
            enable_zone_put_chunk:true,
        }
    }
}


#[derive(Debug, Deserialize, Clone, Default)]
pub struct HostConfig {
    #[serde(default)]
    pub enable_cors: bool,
    #[serde(default)]
    pub redirect_to_https: bool,
    #[serde(default)]
    pub tls: TlsConfig,
    pub routes: HashMap<String, RouteConfig>,
}


#[derive(Debug, Clone)]
pub enum RedirectType {
    None,
    Permanent,
    Temporary,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(from = "String")]

pub struct UpstreamRouteConfig {
    pub target: String,
    pub redirect: RedirectType,
}

impl From<String> for UpstreamRouteConfig {
    fn from(s: String) -> Self {
        Self::from_str(&s)
    }
}

impl UpstreamRouteConfig {
    pub fn from_str(s: &str) -> Self {
        let parts: Vec<&str> = s.split_whitespace().collect();
        let target = parts[0].to_string();
        let mut redirect = RedirectType::None;

        if parts.len() > 1 && parts[1] == "redirect" {
            if parts.len() > 2 {
                redirect = match parts[2] {
                    "permanent" => RedirectType::Permanent,
                    "temporary" => RedirectType::Temporary,
                    _ => RedirectType::None
                };
            } else {
                redirect = RedirectType::Temporary;
            }
        }

        Self {
            target,
            redirect
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct ResponseRouteConfig {
    pub status: Option<u16>,
    pub headers: Option<HashMap<String, String>>,
    pub body: Option<String>,
}


fn default_enable_cors() -> bool {
    true
}
#[derive(Debug, Deserialize, Clone)]
pub struct RouteConfig {
    #[serde(default = "default_enable_cors")]
    pub enable_cors: bool,
    pub response: Option<ResponseRouteConfig>,
    pub upstream: Option<UpstreamRouteConfig>,
    pub local_dir: Option<String>,
    pub inner_service: Option<String>,
    pub tunnel_selector: Option<String>,
    pub bucky_service: Option<String>,
    pub named_mgr: Option<NamedDataMgrRouteConfig>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct TlsConfig {
    pub disable_tls: bool,
    pub enable_acme: bool,
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
}


impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            disable_tls: true,
            enable_acme: false,
            cert_path: None,
            key_path: None,
        }
    }
}


fn default_tls_port() -> u16 {
    0
}

fn default_http_port() -> u16 {
    80
}

#[derive(Debug, Deserialize, Clone)]
pub struct WarpServerConfig {
    #[serde(default = "default_tls_port")]
    pub tls_port:u16,
    #[serde(default = "default_http_port")]
    pub http_port:u16,
    pub bind:Option<String>,
    pub hosts: HashMap<String, HostConfig>,
}

impl WarpServerConfig {
    pub async fn from_file(path: &str) -> anyhow::Result<Self> {
        let content = fs::read_to_string(path).await?;
        let config: WarpServerConfig = serde_json::from_str(&content)?;
        Ok(config)
    }
}



#[derive(Deserialize, Debug,Clone)]
pub enum DNSProviderType {
    #[serde(rename = "dns")]
    DNS,//query name info by system
    SN,//query name info by sn server
    LocalConfig,

}

#[derive(Deserialize,Clone,Debug)]
pub struct DNSProviderConfig {
    #[serde(rename = "type")]
    pub provider_type: DNSProviderType,
    #[serde(flatten)]
    pub config: serde_json::Value,
}

#[derive(Deserialize, Clone, Debug)]
pub struct DNSServerConfig {
    pub bind : Option<String>,
    pub port : u16,
    //dot_port : u16,
    //doh_port : u16,
    //tls: Option<TlsConfig>, include cert.pem and key.pem
    //dnssec: bool,
    //pub this_name:Option<String>,
    pub resolver_chain : Vec<DNSProviderConfig>,
    pub fallback : Vec<String>,//fallback dns servers
}

#[derive(Debug)]
pub enum ServerConfig {
    Warp(WarpServerConfig),
    DNS(DNSServerConfig),
    Socks(SocksProxyConfig),
}

#[derive(Clone,Debug)]
pub enum DispatcherTarget {
    Forward(Url),
    Server(String),
    Selector(String),
    ProbeSelector(String,String), //probeid,selectorid
}

#[derive(Clone,Debug)]
pub struct DispatcherConfig {
    pub incoming: Url,
    pub target: DispatcherTarget
}


impl DispatcherConfig {
    pub fn new_forward(incoming: Url, target: Url) -> Self {
        DispatcherConfig {
            incoming,
            target : DispatcherTarget::Forward(target)
        }
    }

    pub fn new_server(incoming: Url, server_id: String) -> Self {
        DispatcherConfig {
            incoming,
            target : DispatcherTarget::Server(server_id),
        }
    }

    pub fn new_selector(incoming: Url, selector_id: String) -> Self {
        DispatcherConfig {
            incoming,
            target : DispatcherTarget::Selector(selector_id),
        }
    }

    pub fn new_probe_selector(incoming: Url, probe_id: String, selector_id: String) -> Self {
        DispatcherConfig {
            incoming,
            target : DispatcherTarget::ProbeSelector(probe_id, selector_id),
        }
    }
}


#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone, Copy)]
pub enum CyfsServerProtocol {
    #[serde(rename = "tcp")]
    TCP,
    #[serde(rename = "udp")]
    UDP,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct BlockConfig {
    pub id: String,
    pub block: String,
}

impl BlockConfig {
    pub fn create_block(&self) -> ConfigResult<Block> {
        let parser = BlockParser::new(self.id.as_str());
        parser.parse(self.block.as_str()).map_err(|e| {
            config_err!(
                ConfigErrorCode::InvalidConfig,
                "{}",
                e
            )
        })
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ProcessChainConfig {
    pub id: String,
    pub priority: i32,
    pub blocks: Vec<BlockConfig>,
}

impl ProcessChainConfig {
    pub fn create_process_chain(&self) -> ConfigResult<ProcessChain> {
        let mut chain = ProcessChain::new(self.id.clone(), self.priority);
        for block in self.blocks.iter() {
            chain.add_block(block.create_block()?).map_err(|e| {
                config_err!(
                    ConfigErrorCode::InvalidConfig,
                    "{}",
                    e
                )
            })?;
        }
        Ok(chain)
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CyfsServerConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    protocol: Option<CyfsServerProtocol>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bind: Option<IpAddr>,
    port: u16,
    process_chains: Vec<ProcessChainConfig>,
}

impl CyfsServerConfig {
    pub fn new(listen: u16) -> Self {
        CyfsServerConfig {
            protocol: None,
            bind: None,
            port: listen,
            process_chains: vec![],
        }
    }

    pub fn set_protocol(&mut self, protocol: CyfsServerProtocol) {
        self.protocol = Some(protocol);
    }

    pub fn set_bind(&mut self, bind: IpAddr) {
        self.bind = Some(bind);
    }

    pub fn add_process_chain(&mut self, process_chain: ProcessChainConfig) {
        self.process_chains.push(process_chain);
    }

    pub fn get_protocol(&self) -> CyfsServerProtocol {
        self.protocol.unwrap_or(CyfsServerProtocol::TCP)
    }

    pub fn get_bind(&self) -> IpAddr {
        self.bind.unwrap_or(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)))
    }

    pub fn get_port(&self) -> u16 {
        self.port
    }

    pub fn get_process_chains(&self) -> &Vec<ProcessChainConfig> {
        &self.process_chains
    }
}

#[derive(Debug, Copy, Clone)]
pub enum ConfigErrorCode {
    InvalidConfig,
}
pub type ConfigResult<T> = sfo_result::Result<T, ConfigErrorCode>;
pub type ConfigError = sfo_result::Error<ConfigErrorCode>;
use sfo_result::err as config_err;
use cyfs_process_chain::{Block, BlockParser, ProcessChain};

pub trait CyfsServerConfigParser {
    fn parse(config: &str) -> ConfigResult<Vec<CyfsServerConfig>>;
}

pub trait CyfsServerConfigDumps {
    fn dumps(config: &[CyfsServerConfig]) -> ConfigResult<String>;
}

#[derive(Serialize, Deserialize)]
struct YamlServers {
    servers: Vec<YamlServer>
}

#[derive(Serialize, Deserialize)]
struct YamlServer {
    server: CyfsServerConfig,
}

pub struct YamlCyfsServerConfigParser;
impl CyfsServerConfigParser for YamlCyfsServerConfigParser {
    fn parse(config: &str) -> ConfigResult<Vec<CyfsServerConfig>> {
        let config: YamlServers = serde_pretty_yaml::from_str(config).map_err(|e| config_err!(ConfigErrorCode::InvalidConfig, "{:?}", e))?;
        Ok(config.servers.into_iter().map(|s| s.server).collect())
    }
}

pub struct YamlCyfsServerConfigDumps;
impl CyfsServerConfigDumps for YamlCyfsServerConfigDumps {
    fn dumps(config: &[CyfsServerConfig]) -> ConfigResult<String> {
        let servers: Vec<YamlServer> = config.iter().map(|s| YamlServer {
            server: s.clone(),
        }).collect();
        Ok(serde_pretty_yaml::to_string(&YamlServers {
            servers,
        }).map_err(|e| config_err!(ConfigErrorCode::InvalidConfig, "{:?}", e))?)
    }
}

#[cfg(test)]
mod test {
    use std::net::IpAddr;
    use std::str::FromStr;
    use crate::{CyfsServerConfigParser, YamlCyfsServerConfigParser};

    #[test]
    fn test_cyfs_server_config_parse() {
        let yaml_config = r#"
servers:
- server:
    protocol: tcp
    bind: 0.0.0.0
    port: 8080
    process_chains:
      - id: main
        priority: 1
        blocks:
            # 根据host匹配的规则
           - id: default
             block: |
                probe_http || probe_https;
                match $REQ.host "*.buckyos.com" && return "forward tcp://127.0.0.1:8081"";
                match $REQ.host "*.buckyos.cc" && return "forward tcp://127.0.0.1:8082"";

- server:
    port: 8085
    process_chains:
    - id: main
      priority: 1
      blocks:
        - id: default
          block: |
              return "forward tcp://127.0.0.1:8020"";

- server:
    protocol: udp
    port: 8081
    process_chains:
      - id: main
        priority: 1
        blocks:
            - id: default
              block: |
                return "forward udp://127.0.0.1:8082"";

- server:
    port: 80
    process_chains:
    - id: main
      priority: 1
      blocks:
        - id: default
          block: |
              probe_http;
              match $REQ.host "www.buckyos.com" && goto www.buckyos.com;
    - id: www.buckyos.com
      priority: 2
      blocks:
        - id: default
          block: |
              match $REQ.url "/api" && return "forward http://127.0.0.1:8082"";

- server:
    port: 443
    process_chains:
      - id: main
        priority: 1
        blocks:
          - id: default
            block: |
              probe_https;
              match $REQ.host "www.buckyos.com" && resp_tls www.buckyos.com.cert www.buckyos.com.key && goto www.buckyos.com;
      - id: www.buckyos.com
        priority: 2
        blocks:
          - id: default
            block: |
              match $REQ.url "/api" && return "forward https://127.0.0.1:8082"";

"#;
        let config = YamlCyfsServerConfigParser::parse(yaml_config).unwrap();
        assert_eq!(config.len(), 5);
        assert_eq!(config[0].protocol, Some(super::CyfsServerProtocol::TCP));
        assert_eq!(config[0].bind, Some(IpAddr::from_str("0.0.0.0").unwrap()));
        assert_eq!(config[0].port, 8080);
        assert_eq!(config[0].process_chains.len(), 1);
        assert_eq!(config[0].process_chains[0].id, "main");
        assert_eq!(config[0].process_chains[0].priority, 1);
        assert_eq!(config[0].process_chains[0].blocks.len(), 1);
        assert_eq!(config[0].process_chains[0].blocks[0].id, "default");
        assert_eq!(
            config[0].process_chains[0].blocks[0].block,
            r#"probe_http || probe_https;
match $REQ.host "*.buckyos.com" && return "forward tcp://127.0.0.1:8081"";
match $REQ.host "*.buckyos.cc" && return "forward tcp://127.0.0.1:8082"";
"#
        );
        assert_eq!(config[1].protocol, None);
        assert_eq!(config[1].bind, None);
        assert_eq!(config[1].port, 8085);
        assert_eq!(config[1].process_chains.len(), 1);
        assert_eq!(config[1].process_chains[0].id, "main");
        assert_eq!(config[1].process_chains[0].priority, 1);
        assert_eq!(config[1].process_chains[0].blocks.len(), 1);
        assert_eq!(config[1].process_chains[0].blocks[0].id, "default");
        assert_eq!(
            config[1].process_chains[0].blocks[0].block,
            r#"return "forward tcp://127.0.0.1:8020"";
"#
        );
        assert_eq!(config[2].protocol, Some(super::CyfsServerProtocol::UDP));
        assert_eq!(config[2].bind, None);
        assert_eq!(config[2].port, 8081);
        assert_eq!(config[2].process_chains.len(), 1);
        assert_eq!(config[2].process_chains[0].id, "main");
        assert_eq!(config[2].process_chains[0].priority, 1);
        assert_eq!(config[2].process_chains[0].blocks.len(), 1);
        assert_eq!(config[2].process_chains[0].blocks[0].id, "default");
        assert_eq!(
            config[2].process_chains[0].blocks[0].block,
            r#"return "forward udp://127.0.0.1:8082"";
"#
        );
        assert_eq!(config[3].protocol, None);
        assert_eq!(config[3].bind, None);
        assert_eq!(config[3].port, 80);
        assert_eq!(config[3].process_chains.len(), 2);
        assert_eq!(config[3].process_chains[0].id, "main");
        assert_eq!(config[3].process_chains[0].priority, 1);
        assert_eq!(config[3].process_chains[0].blocks.len(), 1);
        assert_eq!(config[3].process_chains[0].blocks[0].id, "default");
        assert_eq!(
            config[3].process_chains[0].blocks[0].block,
            r#"probe_http;
match $REQ.host "www.buckyos.com" && goto www.buckyos.com;
"#
        );
        assert_eq!(config[3].process_chains[1].id, "www.buckyos.com");
        assert_eq!(config[3].process_chains[1].priority, 2);
        assert_eq!(config[3].process_chains[1].blocks.len(), 1);
        assert_eq!(config[3].process_chains[1].blocks[0].id, "default");
        assert_eq!(
            config[3].process_chains[1].blocks[0].block,
            r#"match $REQ.url "/api" && return "forward http://127.0.0.1:8082"";
"#
        );
        assert_eq!(config[4].protocol, None);
        assert_eq!(config[4].bind, None);
        assert_eq!(config[4].port, 443);
        assert_eq!(config[4].process_chains.len(), 2);
        assert_eq!(config[4].process_chains[0].id, "main");
        assert_eq!(config[4].process_chains[0].priority, 1);
        assert_eq!(config[4].process_chains[0].blocks.len(), 1);
        assert_eq!(config[4].process_chains[0].blocks[0].id, "default");
        assert_eq!(
            config[4].process_chains[0].blocks[0].block,
            r#"probe_https;
match $REQ.host "www.buckyos.com" && resp_tls www.buckyos.com.cert www.buckyos.com.key && goto www.buckyos.com;
"#
        );
        assert_eq!(config[4].process_chains[1].id, "www.buckyos.com");
        assert_eq!(config[4].process_chains[1].priority, 2);
        assert_eq!(config[4].process_chains[1].blocks.len(), 1);
        assert_eq!(config[4].process_chains[1].blocks[0].id, "default");
        assert_eq!(
            config[4].process_chains[1].blocks[0].block,
            r#"match $REQ.url "/api" && return "forward https://127.0.0.1:8082"";
"#
        );
    }
}

pub fn gen_demo_gateway_json_config() -> String {
    let result = r#"
{
    "tunnel_builder":{
        "tunnel_bdt" : {
            "enable-tunnel" : ["bdt","rtcp"],
            "sn" : "127.0.0.1"
        },
        "tunnel_ssr":{
            "enable-tunnel" : ["ssr","ss"],
            "proxy_config": {
                "host":"myssr.test.com",
                "port":8889,
                "auth":"aes:23323"
            }
        }
    },
    "servers":{
        "main_http_server":{
            "type":"cyfs-warp",
            "bind":"0.0.0.0",
            "http_port":80,
            "https_port":443,
            "hosts": {
                "another.com": {
                    "tls_only":1,
                    "tls": {
                        "cert_path": "/path/to/cert.pem",
                        "key_path": "/path/to/key.pem"
                    },
                    "routes": {
                        "/": {
                            "upstream": "http://localhost:9090"
                        }
                    }
                },
                "example.com": {
                    "routes": {
                        "/api": {
                            "upstream": "http://localhost:8080"
                        },
                        "/static": {
                            "local_dir": "D:\\temp"
                        }
                    }
                }
            }
        },
        "main_socks_server":{
            "type":"cyfs-socks",
            "bind":"localhost",
            "port":8000,

            "target":"ood02:6000",
            "enable-tunnel":["direct", "rtcp"],

            "rule_config":"http://www.buckyos.io/cyfs-socks-rule.toml"
        },
        "main_dns_server":{
            "type":"cyfs-dns",
            "bind":"localhost:53",
            "ddns":{
                "enable":true,
                "bind":"localhost:8080"
            },
            "rule_config":"http://www.buckyos.io/cyfs-socks-rule.toml",
            "providers":[
                {
                    "order":0,
                    "type":"zone_system_config"
                },
                {
                    "order":1,
                    "type":"d-dns"
                },
                {
                    "order":2,
                    "type":"ens-client",
                    "target":"http://ens.buckyos.org"
                },
                {
                    "order":3,
                    "type":"dns"
                }

            ],
            "fallback":[
                "114.114.114.114:53",
                "8.8.8.8",
                "https://dns.google/dns-query"
            ]
        }
    },
    "dispatcher" : {
        "tcp://0.0.0.0:80":{
            "type":"server",
            "id":"main_http_server"
        },
        "tcp://0.0.0.0:443":{
            "type":"server",
            "id":"main_http_server"
        },
        "tcp://127.0.0.1:8000":{
            "type":"server",
            "id":"main_socks_server"
        },
        "udp://0.0.0.0:53":{
            "type":"server",
            "id":"main_dns_server"
        },

        "tcp://0.0.0.0:6000":{
            "type":"forward",
            "target":"ood02:6000",
            "enable-tunnel":["direct","rtcp"]
        },
        "tcp://0.0.0.0:6001":{
            "type":"forward",
            "target":"192.168.1.102:6001"
        }
    }
}
    "#;

    return result.to_string();
}
