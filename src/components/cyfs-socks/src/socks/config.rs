use crate::{
    rule::RuleEngine,
    RuleResult,
};
use buckyos_kit::get_buckyos_system_etc_dir;
use url::Url;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SocksProxyAuth {
    None,
    Password(String, String),
}

#[derive(Debug, Clone)]
pub struct SocksProxyConfig {
    pub id: String,

    // The target url to proxy
    pub target: Url,
    pub enable_tunnel: Option<Vec<String>>,

    pub auth: SocksProxyAuth,

    // The rule config, if not set, use the default r ule config in the /{buckyos}/etc/rules/ dir
    pub rule_config: Option<String>,
    pub rule_engine: Option<RuleEngine>,
}

impl SocksProxyConfig {
    pub async fn load_rules(&mut self) -> RuleResult<()> {
        assert!(self.rule_engine.is_none());

        let root_dir = get_buckyos_system_etc_dir().join("rules");
        let rule_engine = RuleEngine::new(&root_dir);

        if let Some(rule_config) = self.rule_config.as_ref() {
            rule_engine.load_target(rule_config).await?;
        } else {
            rule_engine.load_rules().await?;
        }

        self.rule_engine = Some(rule_engine);

        Ok(())
    }
}
