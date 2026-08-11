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
    /// URL prefix this dir server is mounted at; it is stripped from the request
    /// path before resolving under `root_path`. Defaults to `/`, i.e. the request
    /// path maps 1:1 onto the directory tree.
    ///
    /// Use it when the public URL carries a prefix that is not part of the
    /// on-disk layout — e.g. serving a `did:web` document set from a BuckyOS
    /// identity directory, where the documents sit flat in the directory but are
    /// published under `/.well-known/`:
    ///
    /// ```yaml
    /// root_path: /opt/buckyos/local/identity/node1.example.com
    /// base_url: /.well-known          # GET /.well-known/did.json -> <root>/did.json
    /// ```
    ///
    /// A request path that does not carry the prefix is still resolved relative
    /// to `root_path` (the prefix is a rewrite, not an access check), so callers
    /// that mount a dir server on a prefix must route only that prefix to it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
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

        if let Some(base_url) = &config.base_url {
            builder = builder.base_url(base_url.clone());
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

#[cfg(test)]
mod tests {
    use super::*;
    use buckyos_http_server::StreamInfo;
    use http::StatusCode;
    use http_body_util::{BodyExt, Full};
    use hyper::body::Bytes;
    use std::path::Path;

    fn config_from_yaml(yaml: &str) -> DirServerConfig {
        serde_yaml_ng::from_str(yaml).expect("dir server config must parse")
    }

    #[test]
    fn test_dir_server_config_defaults_base_url_to_none() {
        let config = config_from_yaml(
            r#"
id: sn_did_web
type: dir
root_path: /opt/buckyos/local/identity/node1.example.com
autoindex: false
"#,
        );

        // 不写 base_url 时保持历史行为：请求 path 与目录树 1:1。
        assert_eq!(config.base_url, None);
    }

    #[test]
    fn test_dir_server_config_reads_base_url() {
        let config = config_from_yaml(
            r#"
id: sn_did_web
type: dir
root_path: /opt/buckyos/local/identity/node1.example.com
base_url: /.well-known
autoindex: false
etag: true
"#,
        );

        assert_eq!(config.base_url.as_deref(), Some("/.well-known"));
        // get_config_json 要能带上 base_url，否则 show/save 出来的配置会丢挂载点。
        let round_tripped: DirServerConfig =
            serde_json::from_str(&config.get_config_json()).unwrap();
        assert_eq!(round_tripped.base_url.as_deref(), Some("/.well-known"));
    }

    async fn get(root_path: &Path, base_url: Option<&str>, uri: &str) -> (StatusCode, Vec<u8>) {
        let config = Arc::new(DirServerConfig {
            id: "sn_did_web".to_string(),
            ty: "dir".to_string(),
            version: None,
            root_path: root_path.to_string_lossy().to_string(),
            base_url: base_url.map(str::to_string),
            index_file: None,
            fallback_file: None,
            autoindex: false,
            etag: true,
            if_modified_since: None,
        });

        let servers = DirServerFactory::new().create(config, None).await.unwrap();
        let server = match servers.into_iter().next().unwrap() {
            Server::Http(server) => server,
            _ => panic!("dir server must be an http server"),
        };

        let request = http::Request::builder()
            .method("GET")
            .uri(uri)
            .body(Full::new(Bytes::new()).map_err(|e| match e {}).boxed())
            .unwrap();
        let response = server
            .serve_request(request, StreamInfo::new("127.0.0.1:50000".to_string()))
            .await
            .unwrap();

        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, body.to_vec())
    }

    /// did:web 发布面的实际形状：文档按身份路径协议平铺在 identity 目录里
    /// （did.json、device.json…，没有 .well-known 子目录），却要发布在
    /// /.well-known/ 下。base_url 就是这个挂载点，省掉 process chain 里的
    /// path rewrite。
    #[tokio::test]
    async fn test_base_url_maps_mount_prefix_onto_flat_root() {
        let temp_dir = tempfile::tempdir().unwrap();
        tokio::fs::write(temp_dir.path().join("did.json"), b"flat-did-doc")
            .await
            .unwrap();

        let (status, body) = get(temp_dir.path(), Some("/.well-known"), "/.well-known/did.json")
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, b"flat-did-doc");

        // 目录里没有这个文档 => 404，而不是把请求漏给别的东西。
        let (status, _) = get(
            temp_dir.path(),
            Some("/.well-known"),
            "/.well-known/owner.json",
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    /// 不配 base_url 的既有行为不能变：请求 path 与目录树 1:1，
    /// /.well-known/did.json 找的是 <root>/.well-known/did.json。
    #[tokio::test]
    async fn test_without_base_url_request_path_maps_one_to_one() {
        let temp_dir = tempfile::tempdir().unwrap();
        tokio::fs::write(temp_dir.path().join("did.json"), b"flat-did-doc")
            .await
            .unwrap();

        let (status, body) = get(temp_dir.path(), None, "/did.json").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, b"flat-did-doc");

        let (status, _) = get(temp_dir.path(), None, "/.well-known/did.json").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    /// base_url 是 rewrite 而不是访问控制：不带前缀的 path 仍然按 root 相对解析。
    /// 挂在前缀上的调用方必须只把该前缀路由过来——sn_relay.yaml 靠 process chain
    /// 的 match-reg 做这件事。
    #[tokio::test]
    async fn test_base_url_is_a_rewrite_not_an_access_check() {
        let temp_dir = tempfile::tempdir().unwrap();
        tokio::fs::write(temp_dir.path().join("did.json"), b"flat-did-doc")
            .await
            .unwrap();

        let (status, body) = get(temp_dir.path(), Some("/.well-known"), "/did.json").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, b"flat-did-doc");
    }
}
