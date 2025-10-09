use crate::SocksProxyAuth;
use cyfs_gateway_lib::{ServerConfig, ProcessChainConfig};
use cyfs_process_chain::*;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use url::Url;

#[derive(Serialize, Deserialize, Clone)]
pub struct SocksServerConfig {
    pub id: String,

    pub auth: SocksProxyAuth,

    pub target: Url,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable_tunnel: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_config: Option<String>,

    pub hook_point: Vec<ProcessChainConfig>,
}

impl SocksServerConfig {
    pub fn parse_process_chain(&self) -> Result<ProcessChainLibRef, String> {
        let mut json_list = Vec::new();
        for pc in self.hook_point.iter() {
            let block_list = pc
                .blocks
                .iter()
                .map(|b| BlockJSONItem {
                    id: b.id.clone(),
                    content: b.block.clone(),
                })
                .collect::<Vec<_>>();

            let item = ProcessChainJSONItem {
                id: pc.id.clone(),
                priority: pc.priority,
                blocks: block_list,
            };
            json_list.push(item);
        }

        ProcessChainJSONLoader::parser_direct(json_list).and_then(|chains| {
            let chains = chains
                .into_iter()
                .map(|chain| Arc::new(chain))
                .collect::<Vec<_>>();

            let lib = ProcessChainListLib::new("main", 0, chains);
            let lib = Arc::new(Box::new(lib) as Box<dyn ProcessChainLib>);

            Ok(lib)
        })
    }
}

impl ServerConfig for SocksServerConfig {
    fn server_type(&self) -> String {
        "socks".to_string()
    }

    fn get_config_json(&self) -> String {
        serde_json::to_string(self).unwrap()
    }
}
