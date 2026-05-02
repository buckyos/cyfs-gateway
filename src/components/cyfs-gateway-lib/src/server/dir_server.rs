use std::path::PathBuf;
use std::sync::Arc;

use buckyos_http_server::DirServer;
use serde::{Deserialize, Serialize};

use crate::{
    Server, ServerConfig, ServerContextRef, ServerErrorCode, ServerFactory, ServerResult,
    server_err,
};

#[derive(Serialize, Deserialize, Clone)]
pub struct DirServerConfig {
    pub id: String,
    #[serde(rename = "type")]
    pub ty: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub root_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index_file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallback_file: Option<String>,
    #[serde(default)]
    pub autoindex: bool,
    #[serde(default = "dir_server_default_etag")]
    pub etag: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub if_modified_since: Option<String>,
}

fn dir_server_default_etag() -> bool {
    true
}

impl ServerConfig for DirServerConfig {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn server_type(&self) -> String {
        "dir".to_string()
    }

    fn get_config_json(&self) -> String {
        serde_json::to_string(self).unwrap()
    }
}

pub struct DirServerFactory;

impl DirServerFactory {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl ServerFactory for DirServerFactory {
    async fn create(
        &self,
        config: Arc<dyn ServerConfig>,
        _context: Option<ServerContextRef>,
    ) -> ServerResult<Vec<Server>> {
        let config = config
            .as_any()
            .downcast_ref::<DirServerConfig>()
            .ok_or(server_err!(
                ServerErrorCode::InvalidConfig,
                "invalid dir server config"
            ))?;

        let mut builder = DirServer::builder()
            .id(config.id.clone())
            .root_path(PathBuf::from(config.root_path.clone()));

        if let Some(version) = &config.version {
            builder = builder.version(version.clone());
        }

        if let Some(index_file) = &config.index_file {
            builder = builder.index_file(index_file.clone());
        }

        if let Some(fallback_file) = &config.fallback_file {
            builder = builder.fallback_file(fallback_file.clone());
        }

        builder = builder.autoindex(config.autoindex);
        builder = builder.etag(config.etag);

        if let Some(if_modified_since) = &config.if_modified_since {
            builder = builder.if_modified_since(if_modified_since.clone());
        }

        let server = builder.build().await?;
        Ok(vec![Server::Http(Arc::new(server))])
    }
}
