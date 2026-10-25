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
    /// Cache-Control preset: `html-revalidate` (default; HTML responses carry
    /// `no-cache` so entry pages pick up new deployments, other files carry
    /// none) or `none`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_policy: Option<String>,
    /// Cache-Control for HTML responses, replacing the preset's value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub html_cache_control: Option<String>,
    /// Cache-Control for non-HTML file responses, replacing the preset's value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_control: Option<String>,
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

        if let Some(cache_policy) = &config.cache_policy {
            builder = builder.cache_policy(cache_policy.clone());
        }

        if let Some(html_cache_control) = &config.html_cache_control {
            builder = builder.html_cache_control(html_cache_control.clone());
        }

        if let Some(cache_control) = &config.cache_control {
            builder = builder.cache_control(cache_control.clone());
        }

        let server = builder.build().await?;
        Ok(vec![Server::Http(Arc::new(server))])
    }
}

#[cfg(test)]
mod tests {
    use super::super::http_compression::HttpCompressionSettings;
    use super::*;
    use crate::{
        HttpServer, ProcessChainConfigs, ProcessChainHttpServer, ServerError, ServerManager,
        TunnelManager, hyper_serve_http1,
    };
    use async_compression::tokio::bufread::GzipDecoder;
    use buckyos_http_server::StreamInfo;
    use http::StatusCode;
    use http_body_util::combinators::BoxBody;
    use http_body_util::{BodyExt, Full};
    use hyper::body::Bytes;
    use std::path::Path;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
            cache_policy: None,
            html_cache_control: None,
            cache_control: None,
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

    #[test]
    fn test_dir_server_config_reads_cache_options() {
        let config = config_from_yaml(
            r#"
id: site
type: dir
root_path: /var/www
cache_policy: none
html_cache_control: max-age=60
cache_control: "public, max-age=31536000, immutable"
"#,
        );

        assert_eq!(config.cache_policy.as_deref(), Some("none"));
        assert_eq!(config.html_cache_control.as_deref(), Some("max-age=60"));
        assert_eq!(
            config.cache_control.as_deref(),
            Some("public, max-age=31536000, immutable")
        );
        let round_tripped: DirServerConfig =
            serde_json::from_str(&config.get_config_json()).unwrap();
        assert_eq!(round_tripped.cache_policy, config.cache_policy);
        assert_eq!(round_tripped.html_cache_control, config.html_cache_control);
        assert_eq!(round_tripped.cache_control, config.cache_control);

        // Unset options stay out of the saved config.
        let json = config_from_yaml("id: site\ntype: dir\nroot_path: /var/www\n").get_config_json();
        assert!(!json.contains("cache"), "{json}");
    }

    async fn dir_servers_from_yaml(root_path: &Path, options: &str) -> ServerResult<Vec<Server>> {
        let config = config_from_yaml(&format!(
            "id: site\ntype: dir\nroot_path: {}\n{}",
            root_path.display(),
            options
        ));
        DirServerFactory::new().create(Arc::new(config), None).await
    }

    /// A `type: http` server whose hook point calls the dir server, with the
    /// gateway's response compression switched on for text.
    async fn gateway_over_dir(
        root_path: &Path,
        options: &str,
    ) -> (Arc<ProcessChainHttpServer>, Arc<ServerManager>) {
        let manager = Arc::new(ServerManager::new());
        for server in dir_servers_from_yaml(root_path, options).await.unwrap() {
            manager.add_server(server).unwrap();
        }
        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(
            r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        call-server site;
"#,
        )
        .unwrap();

        let mut compression = HttpCompressionSettings::default();
        compression.gzip = true;
        compression.gzip_vary = true;
        compression.gzip_min_length = 1;
        compression.gzip_types = vec!["text/plain".to_string(), "text/html".to_string()];

        let http = ProcessChainHttpServer::builder()
            .id("gateway")
            .version("HTTP/1.1")
            .hook_point(chains)
            .tunnel_manager(TunnelManager::new())
            .server_mgr(Arc::downgrade(&manager))
            .compression(compression)
            .build()
            .await
            .unwrap();
        (Arc::new(http), manager)
    }

    async fn through_gateway(
        http: &ProcessChainHttpServer,
        method: &str,
        uri: &str,
        headers: &[(&str, &str)],
    ) -> http::Response<BoxBody<Bytes, ServerError>> {
        let mut builder = http::Request::builder().method(method).uri(uri);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let request = builder
            .body(Full::new(Bytes::new()).map_err(|e| match e {}).boxed())
            .unwrap();
        http.serve_request(request, StreamInfo::new("127.0.0.1:50000".to_string()))
            .await
            .unwrap()
    }

    fn header<'a>(
        response: &'a http::Response<BoxBody<Bytes, ServerError>>,
        name: &str,
    ) -> Option<&'a str> {
        response.headers().get(name).and_then(|v| v.to_str().ok())
    }

    async fn body_of(response: http::Response<BoxBody<Bytes, ServerError>>) -> Vec<u8> {
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec()
    }

    async fn gunzip(data: Vec<u8>) -> Vec<u8> {
        let mut decoder = GzipDecoder::new(tokio::io::BufReader::new(std::io::Cursor::new(data)));
        let mut output = Vec::new();
        decoder.read_to_end(&mut output).await.unwrap();
        output
    }

    #[tokio::test]
    async fn test_call_server_serves_decoded_paths_and_redirects_directories() {
        let temp_dir = tempfile::tempdir().unwrap();
        let root = temp_dir.path();
        tokio::fs::write(root.join("a b.txt"), b"space")
            .await
            .unwrap();
        tokio::fs::write(root.join("中文.txt"), b"unicode")
            .await
            .unwrap();
        tokio::fs::create_dir(root.join("docs")).await.unwrap();
        tokio::fs::write(root.join("docs/index.html"), b"<p>docs</p>")
            .await
            .unwrap();
        #[cfg(unix)]
        {
            tokio::fs::write(root.join("blob"), b"export {}")
                .await
                .unwrap();
            std::os::unix::fs::symlink(root.join("blob"), root.join("app.js")).unwrap();
        }
        let (http, _manager) = gateway_over_dir(root, "").await;

        for (uri, body) in [
            ("/a%20b.txt", "space"),
            ("/%E4%B8%AD%E6%96%87.txt", "unicode"),
        ] {
            let response = through_gateway(&http, "GET", uri, &[]).await;
            assert_eq!(response.status(), StatusCode::OK, "{uri}");
            assert_eq!(body_of(response).await, body.as_bytes(), "{uri}");
        }

        let response = through_gateway(&http, "GET", "/docs?lang=en", &[]).await;
        assert_eq!(response.status(), StatusCode::MOVED_PERMANENTLY);
        assert_eq!(header(&response, "location"), Some("./docs/?lang=en"));

        let response = through_gateway(&http, "GET", "/docs/", &[]).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(header(&response, "content-type"), Some("text/html"));
        assert_eq!(header(&response, "cache-control"), Some("no-cache"));
        assert_eq!(body_of(response).await, b"<p>docs</p>");

        #[cfg(unix)]
        {
            let response = through_gateway(&http, "GET", "/app.js", &[]).await;
            assert_eq!(
                header(&response, "content-type"),
                Some(
                    mime_guess::from_path("app.js")
                        .first_or_octet_stream()
                        .as_ref()
                )
            );
        }
    }

    #[tokio::test]
    async fn test_call_server_ranges_and_validators_with_compression() {
        let temp_dir = tempfile::tempdir().unwrap();
        tokio::fs::write(temp_dir.path().join("digits.txt"), b"0123456789")
            .await
            .unwrap();
        let (http, _manager) = gateway_over_dir(temp_dir.path(), "").await;
        let gzip = ("accept-encoding", "gzip");

        // The complete file is compressed by the http layer, which turns it
        // into another representation: no ranges, weak validator.
        let response = through_gateway(&http, "GET", "/digits.txt", &[gzip]).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(header(&response, "content-encoding"), Some("gzip"));
        assert_eq!(header(&response, "accept-ranges"), None);
        let weak_etag = header(&response, "etag").unwrap().to_string();
        assert!(weak_etag.starts_with("W/\""), "{weak_etag}");
        assert_eq!(gunzip(body_of(response).await).await, b"0123456789");

        // A range of the identity bytes is never compressed.
        let response =
            through_gateway(&http, "GET", "/digits.txt", &[gzip, ("range", "bytes=-3")]).await;
        assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(header(&response, "content-encoding"), None);
        assert_eq!(header(&response, "content-range"), Some("bytes 7-9/10"));
        let strong_etag = header(&response, "etag").unwrap().to_string();
        assert_eq!(weak_etag, format!("W/{strong_etag}"));
        assert_eq!(body_of(response).await, b"789");

        for (range, status, body) in [
            (
                "bytes=5-999",
                StatusCode::PARTIAL_CONTENT,
                b"56789".as_slice(),
            ),
            ("bytes=0-1,7-8", StatusCode::OK, b"0123456789".as_slice()),
        ] {
            let response = through_gateway(&http, "GET", "/digits.txt", &[("range", range)]).await;
            assert_eq!(response.status(), status, "{range}");
            assert_eq!(body_of(response).await, body, "{range}");
        }

        let response =
            through_gateway(&http, "GET", "/digits.txt", &[gzip, ("range", "bytes=10-")]).await;
        assert_eq!(response.status(), StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(header(&response, "content-encoding"), None);
        assert_eq!(header(&response, "content-range"), Some("bytes */10"));

        // If-Range with the weak tag of the compressed body cannot resume a
        // range: the complete (compressed) current file comes back instead.
        let response = through_gateway(
            &http,
            "GET",
            "/digits.txt",
            &[
                gzip,
                ("range", "bytes=2-3"),
                ("if-range", weak_etag.as_str()),
            ],
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(gunzip(body_of(response).await).await, b"0123456789");
        for (if_range, status) in [
            (strong_etag.as_str(), StatusCode::PARTIAL_CONTENT),
            ("\"stale\"", StatusCode::OK),
        ] {
            let response = through_gateway(
                &http,
                "GET",
                "/digits.txt",
                &[("range", "bytes=2-3"), ("if-range", if_range)],
            )
            .await;
            assert_eq!(response.status(), status, "{if_range}");
        }

        for (headers, status) in [
            (
                vec![("if-none-match", weak_etag.as_str())],
                StatusCode::NOT_MODIFIED,
            ),
            (vec![("if-none-match", "*")], StatusCode::NOT_MODIFIED),
            (
                vec![("if-match", "\"stale\"")],
                StatusCode::PRECONDITION_FAILED,
            ),
            (
                vec![("if-match", weak_etag.as_str())],
                StatusCode::PRECONDITION_FAILED,
            ),
            (vec![("if-match", strong_etag.as_str())], StatusCode::OK),
        ] {
            let response = through_gateway(&http, "GET", "/digits.txt", &headers).await;
            assert_eq!(response.status(), status, "{headers:?}");
        }
    }

    #[tokio::test]
    async fn test_call_server_head_over_http_has_no_body() {
        let temp_dir = tempfile::tempdir().unwrap();
        tokio::fs::write(temp_dir.path().join("digits.txt"), b"0123456789")
            .await
            .unwrap();
        let (http, _manager) = gateway_over_dir(temp_dir.path(), "").await;
        let server: Arc<dyn HttpServer> = http;

        let (mut client, server_stream) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            let _ = hyper_serve_http1(Box::new(server_stream), server, StreamInfo::default()).await;
        });
        client
            .write_all(
                b"HEAD /digits.txt HTTP/1.1\r\nHost: localhost\r\nRange: bytes=0-1\r\nAccept-Encoding: gzip\r\n\r\nGET /digits.txt HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        let mut raw = Vec::new();
        client.read_to_end(&mut raw).await.unwrap();

        let head_end = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
        let head = String::from_utf8_lossy(&raw[..head_end]).to_ascii_lowercase();
        assert!(head.starts_with("http/1.1 200 ok"), "{head}");
        assert!(head.contains("\r\ncontent-length: 10"), "{head}");
        assert!(!head.contains("content-range"), "{head}");
        assert!(!head.contains("content-encoding"), "{head}");
        // The GET response follows the HEAD head directly: HEAD sent no body.
        let rest = &raw[head_end + 4..];
        assert!(
            rest.starts_with(b"HTTP/1.1 200 OK"),
            "{}",
            String::from_utf8_lossy(rest)
        );
    }

    #[tokio::test]
    async fn test_call_server_applies_configured_cache_policy() {
        let temp_dir = tempfile::tempdir().unwrap();
        tokio::fs::write(temp_dir.path().join("index.html"), b"<p>x</p>")
            .await
            .unwrap();
        tokio::fs::write(temp_dir.path().join("app.css"), b"p{}")
            .await
            .unwrap();

        for (options, html, other) in [
            ("", Some("no-cache"), None),
            ("cache_policy: none\n", None, None),
            (
                "cache_policy: none\ncache_control: \"public, max-age=600\"\n",
                None,
                Some("public, max-age=600"),
            ),
            ("html_cache_control: max-age=60\n", Some("max-age=60"), None),
        ] {
            let (http, _manager) = gateway_over_dir(temp_dir.path(), options).await;
            let response = through_gateway(&http, "GET", "/", &[]).await;
            assert_eq!(header(&response, "cache-control"), html, "{options}");
            let response = through_gateway(&http, "GET", "/app.css", &[]).await;
            assert_eq!(header(&response, "cache-control"), other, "{options}");
        }

        // `no-transform` keeps the http layer from compressing the file.
        tokio::fs::write(temp_dir.path().join("notes.txt"), b"notes")
            .await
            .unwrap();
        for (options, encoding) in [
            ("", Some("gzip")),
            ("cache_control: \"max-age=60, no-transform\"\n", None),
        ] {
            let (http, _manager) = gateway_over_dir(temp_dir.path(), options).await;
            let response =
                through_gateway(&http, "GET", "/notes.txt", &[("accept-encoding", "gzip")]).await;
            assert_eq!(header(&response, "content-encoding"), encoding, "{options}");
        }

        let err = dir_servers_from_yaml(temp_dir.path(), "cache_policy: forever\n")
            .await
            .err()
            .expect("unknown cache_policy must be rejected");
        assert_eq!(err.code(), ServerErrorCode::InvalidConfig);
    }
}
