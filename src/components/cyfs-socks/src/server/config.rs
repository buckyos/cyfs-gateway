use crate::SocksProxyAuth;
use cyfs_gateway_lib::{ServerConfig, ProcessChainConfig, get_min_priority};
use cyfs_process_chain::*;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use url::Url;

#[derive(Serialize, Deserialize, Clone)]
pub struct SocksServerConfig {
    pub id: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,

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
    fn id(&self) -> String {
        self.id.clone()
    }

    fn server_type(&self) -> String {
        "socks".to_string()
    }

    fn get_config_json(&self) -> String {
        serde_json::to_string(self).unwrap()
    }

    fn add_pre_hook_point_process_chain(&self, mut process_chain: ProcessChainConfig) -> Arc<dyn ServerConfig> {
        let mut config = self.clone();
        process_chain.priority = get_min_priority(&config.hook_point) - 1;
        config.hook_point.push(process_chain);
        Arc::new(config)
    }

    fn remove_pre_hook_point_process_chain(&self, process_chain_id: &str) -> Arc<dyn ServerConfig> {
        let mut config = self.clone();
        config.hook_point.retain(|chain| chain.id != process_chain_id);
        Arc::new(config)
    }

    fn add_post_hook_point_process_chain(&self, _process_chain: ProcessChainConfig) -> Arc<dyn ServerConfig> {
        Arc::new(self.clone())
    }

    fn remove_post_hook_point_process_chain(&self, _process_chain_id: &str) -> Arc<dyn ServerConfig> {
        Arc::new(self.clone())
    }
}
