

use tokio::fs;
use std::collections::HashMap;
use std::net::{SocketAddr};
use serde::{Deserialize, Serialize};

fn default_true() -> bool {
    true
}

#[derive(Debug, Serialize, Deserialize, Clone)]
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

fn default_priority() -> i32 {
    1
}
#[derive(Serialize, Deserialize, Clone)]
pub struct BlockConfig {
    pub id: String,
    #[serde(default = "default_priority")]
    pub priority: i32,
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
    #[serde(default = "default_priority")]
    pub priority: i32,
    pub blocks: Vec<BlockConfig>,
}

impl ProcessChainConfig {
    pub fn create_process_chain(&self) -> ConfigResult<ProcessChain> {
        let mut chain = ProcessChain::new(self.id.clone(), self.priority);
        let mut blocks = self.blocks.clone();
        blocks.sort_by(|a, b| a.priority.cmp(&b.priority));
        for block in blocks.iter() {
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
pub struct StackCertConfig {
    pub domain: String,
    pub acme_type: Option<ChallengeType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_path: Option<String>,
    #[serde(flatten)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

#[derive(Serialize, Deserialize, Clone)]
struct StackConfigBase {
    protocol: StackProtocol,
}
