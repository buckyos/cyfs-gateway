

use tokio::fs;
use std::collections::HashMap;
use std::net::{SocketAddr};
use serde::{Deserialize, Serialize};

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
pub type ProcessChainConfigs = Vec<ProcessChainConfig>;

pub fn get_min_priority(chain_configs: &ProcessChainConfigs) -> i32 {
    chain_configs.iter().map(|c| c.priority).min().unwrap_or(0)
}


#[derive(Debug, Copy, Clone)]
pub enum ConfigErrorCode {
    InvalidConfig,
    ProcessChainError,
    AlreadyExists,
}
pub type ConfigResult<T> = sfo_result::Result<T, ConfigErrorCode>;
pub type ConfigError = sfo_result::Error<ConfigErrorCode>;
pub use sfo_result::err as config_err;
pub use sfo_result::into_err as into_config_err;
use cyfs_acme::ChallengeType;
use cyfs_process_chain::{Block, BlockParser, ProcessChain};
use crate::{StackProtocol};

#[derive(Serialize, Deserialize, Clone)]
pub struct TcpConfig {
    protocol: StackProtocol,
    bind: SocketAddr,
    hook_point: Vec<ProcessChainConfig>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct UdpConfig {
    pub protocol: StackProtocol,
    pub bind: SocketAddr,
    pub hook_point: Vec<ProcessChainConfig>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CertInfo {
    pub cert_file: String,
    pub key_file: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub enum CertType {
    Acme,
    Local(CertInfo),
}

#[derive(Serialize, Deserialize, Clone)]
pub struct StackCertConfig {
    pub domain: String,
    pub acme_type: Option<ChallengeType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_file: Option<String>,
    #[serde(flatten)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

#[derive(Serialize, Deserialize, Clone)]
struct StackConfigBase {
    protocol: StackProtocol,
}
//
// #[derive(Serialize, Clone)]
// #[serde(untagged)]
// pub enum StackConfig {
//     Tcp(TcpConfig),
//     Udp(UdpConfig),
//     Rtcp(RtcpConfig),
//     Tls(TlsStackConfig),
//     Quic(QuicStackConfig),
// }
//
// impl<'de> Deserialize<'de> for StackConfig {
//     fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
//     where
//         D: Deserializer<'de>,
//     {
//         let value = serde_json::Value::deserialize(deserializer)?;
//         let stack_base = StackConfigBase::deserialize(value.clone()).map_err(|e| serde::de::Error::custom(e))?;
//         match stack_base.protocol {
//             StackProtocol::Tcp => {
//                 let config = TcpConfig::deserialize(value).map_err(|e| serde::de::Error::custom(e))?;
//                 Ok(StackConfig::Tcp(config))
//             }
//             StackProtocol::Udp => {
//                 let config = UdpConfig::deserialize(value).map_err(|e| serde::de::Error::custom(e))?;
//                 Ok(StackConfig::Udp(config))
//             }
//             StackProtocol::Quic => {
//                 let config = QuicStackConfig::deserialize(value).map_err(|e| serde::de::Error::custom(e))?;
//                 Ok(StackConfig::Quic(config))
//             }
//             StackProtocol::Rtcp => {
//                 let config = RtcpConfig::deserialize(value).map_err(|e| serde::de::Error::custom(e))?;
//                 Ok(StackConfig::Rtcp(config))
//             }
//             StackProtocol::Tls => {
//                 let config = TlsStackConfig::deserialize(value).map_err(|e| {
//                     serde::de::Error::custom(e)})?;
//                 Ok(StackConfig::Tls(config))
//             }
//         }
//     }
// }
//
// #[derive(Serialize, Deserialize, Clone)]
// pub struct CyfsConfig {
//     stacks: Vec<StackConfig>,
// }
//
//
// #[cfg(test)]
// mod test {
//     use std::net::IpAddr;
//     use crate::{CyfsConfig};
//
//     #[test]
//     fn test_stack_config_serialization() {
//         let yaml_config = r#"
// stacks:
//   - bind: 0.0.0.0:8080
//     protocol: tcp
//     hook_point:
//       - id: main
//         priority: 1
//         blocks:
//           - id: default
//             block: |
//               call https-sni-probe && return "forward tcp:///${REQ.dest_host}:443";
//               call http-probe || reject;
//               eq ${REQ.ext.method} "CONNECT" && return "forward tcp:///${REQ.dest_host}";
//               return "forward tcp:///${REQ.dest_host}:80";
//
//   - bind: 0.0.0.0:8081
//     protocol: udp
//     hook_point:
//       - id: main
//         priority: 1
//         blocks:
//           - id: default
//             block: |
//               reject;
//
//   - bind: 0.0.0.0:8082
//     protocol: rtcp
//     device_name: "web3.buckyos.com"
//     device_key: ./identity.json
//     hook_point:
//       - id: main
//         priority: 1
//         blocks:
//           - id: default
//             block: |
//               reject;
//
//   - bind: 0.0.0.0:8083
//     protocol: tls
//     certs:
//       - domain: "web3.buckyos.com"
//         cert_file: ./cert.pem
//         key_file: ./key.pem
//     hook_point:
//       - id: main
//         priority: 1
//         blocks:
//           - id: default
//             block: |
//               reject;
//
//   - bind: 0.0.0.0:8083
//     protocol: quic
//     certs:
//       - domain: "web3.buckyos.com"
//         cert_file: ./cert.pem
//         key_file: ./key.pem
//     hook_point:
//       - id: main
//         priority: 1
//         blocks:
//           - id: default
//             block: |
//               reject;
//         "#;
//
//         let config: CyfsConfig = serde_yaml_ng::from_str(yaml_config).unwrap();
//         assert_eq!(config.stacks.len(), 5);
//     }
//
//     #[test]
//     fn test_stack_config_deserialization_from_json() {
//         use crate::{StackConfig, StackProtocol};
//         use std::net::{SocketAddr, Ipv4Addr};
//
//         // Test deserializing TcpStackConfig from JSON
//         let tcp_json = r#"{
//             "protocol": "tcp",
//             "bind": "127.0.0.1:8080",
//             "hook_point": []
//         }"#;
//
//         let tcp_config: StackConfig = serde_json::from_str(tcp_json).unwrap();
//         match tcp_config {
//             StackConfig::Tcp(tcp) => {
//                 assert_eq!(tcp.protocol, StackProtocol::Tcp);
//                 assert_eq!(tcp.bind, SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080));
//             }
//             _ => panic!("Expected Tcp variant"),
//         }
//
//         // Test deserializing UdpStackConfig from JSON
//         let udp_json = r#"{
//             "protocol": "udp",
//             "bind": "127.0.0.1:8081",
//             "hook_point": []
//         }"#;
//
//         let udp_config: StackConfig = serde_json::from_str(udp_json).unwrap();
//         match udp_config {
//             StackConfig::Udp(udp) => {
//                 assert_eq!(udp.protocol, StackProtocol::Udp);
//                 assert_eq!(udp.bind, SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8081));
//             }
//             _ => panic!("Expected Udp variant"),
//         }
//     }
// }
//

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
