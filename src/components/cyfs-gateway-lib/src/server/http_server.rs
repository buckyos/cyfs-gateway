use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use http::Version;
use http_body_util::combinators::{BoxBody};
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes};
use hyper::{http, StatusCode, Request};
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as TlsError, SignatureScheme};
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use cyfs_process_chain::{CollectionValue, CommandControl, ProcessChainLibExecutor};
use regex::Regex;
use crate::{get_external_commands, GlobalCollectionManagerRef, HttpRequestHeaderMap, HttpResponseHeaderMap, HttpServer, JsExternalsManagerRef, ProcessChainConfigs, Server, ServerConfig, ServerContext, ServerContextRef, ServerError, ServerErrorCode, ServerFactory, ServerManagerWeakRef, ServerResult, StreamInfo, TunnelManager};
use crate::global_process_chains::{create_process_chain_executor, GlobalProcessChainsRef};
use super::{server_err,into_server_err};
use super::http_compression::{apply_request_decompression, apply_response_compression, CompressionRequestInfo, HttpCompressionSettings};
use crate::tunnel_connector::TunnelConnector;
use url::Url;

pub struct ProcessChainHttpServerBuilder {
    id: Option<String>,
    version: Option<String>,
    h3_port: Option<u16>,
    hook_point: Option<ProcessChainConfigs>,
    post_hook_point: Option<ProcessChainConfigs>,
    global_process_chains: Option<GlobalProcessChainsRef>,
    js_externals: Option<JsExternalsManagerRef>,
    server_mgr: Option<ServerManagerWeakRef>,
    tunnel_manager: Option<TunnelManager>,
    global_collection_manager: Option<GlobalCollectionManagerRef>,
    compression: HttpCompressionSettings,
}

// Add setter methods for HttpServerBuilder
impl ProcessChainHttpServerBuilder {
    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    pub fn version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }

    pub fn hook_point(mut self, hook_point: ProcessChainConfigs) -> Self {
        self.hook_point = Some(hook_point);
        self
    }

    pub fn post_hook_point(mut self, post_hook_point: ProcessChainConfigs) -> Self {
        self.post_hook_point = Some(post_hook_point);
        self
    }

    pub fn global_process_chains(mut self, global_process_chains: GlobalProcessChainsRef) -> Self {
        self.global_process_chains = Some(global_process_chains);
        self
    }

    pub fn js_externals(mut self, js_externals: JsExternalsManagerRef) -> Self {
        self.js_externals = Some(js_externals);
        self
    }

    pub fn server_mgr(mut self, server_mgr: ServerManagerWeakRef) -> Self {
        self.server_mgr = Some(server_mgr);
        self
    }

    pub fn h3_port(mut self, h3_port: u16) -> Self {
        self.h3_port = Some(h3_port);
        self
    }

    pub fn tunnel_manager(mut self, tunnel_manager: TunnelManager) -> Self {
        self.tunnel_manager = Some(tunnel_manager);
        self
    }

    pub fn global_collection_manager(mut self, global_collection_manager: GlobalCollectionManagerRef) -> Self {
        self.global_collection_manager = Some(global_collection_manager);
        self
    }

    pub fn compression(mut self, compression: HttpCompressionSettings) -> Self {
        self.compression = compression;
        self
    }

    pub async fn build(self) -> ServerResult<ProcessChainHttpServer> {
        ProcessChainHttpServer::create_server(self).await
    }

    fn build_compression_settings(
        config: &ProcessChainHttpServerConfig,
    ) -> ServerResult<HttpCompressionSettings> {
        let gzip_http_version = parse_gzip_http_version(&config.gzip_http_version)?;
        let gzip_disable = match config.gzip_disable.as_ref() {
            Some(expr) => Some(Regex::new(expr).map_err(|e| {
                server_err!(ServerErrorCode::InvalidConfig, "invalid gzip_disable regex: {}", e)
            })?),
            None => None,
        };

        Ok(HttpCompressionSettings {
            gzip: config.gzip,
            gzip_request: config.gzip_request,
            gzip_types: normalize_content_types(&config.gzip_types),
            gzip_min_length: config.gzip_min_length,
            gzip_comp_level: clamp_gzip_comp_level(config.gzip_comp_level),
            gzip_http_version,
            gzip_vary: config.gzip_vary,
            gzip_disable,
            brotli: config.brotli,
            brotli_types: normalize_content_types(&config.brotli_types),
            brotli_min_length: config.brotli_min_length,
            brotli_comp_level: clamp_brotli_comp_level(config.brotli_comp_level),
        })
    }
}

pub struct ProcessChainHttpServer {
    id: String,
    version: http::Version,
    h3_port: Option<u16>,
    server_mgr: ServerManagerWeakRef,
    executor: Arc<Mutex<ProcessChainLibExecutor>>,
    post_executor: Option<Arc<Mutex<ProcessChainLibExecutor>>>,
    tunnel_manager: TunnelManager,
    compression: HttpCompressionSettings,
}

#[derive(Debug)]
struct NoCertificateVerifier;

impl ServerCertVerifier for NoCertificateVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer,
        _intermediates: &[CertificateDer],
        _server_name: &ServerName,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

impl Drop for ProcessChainHttpServer {
    fn drop(&mut self) {
        debug!("ProcessChainHttpServer {} drop", self.id);
    }
}

impl ProcessChainHttpServer {
    pub fn builder() -> ProcessChainHttpServerBuilder {
        ProcessChainHttpServerBuilder {
            id: None,
            version: None,
            h3_port: None,
            hook_point: None,
            post_hook_point: None,
            global_process_chains: None,
            js_externals: None,
            server_mgr: None,
            tunnel_manager: None,
            global_collection_manager: None,
            compression: HttpCompressionSettings::default(),
        }
    }

    async fn create_server(builder: ProcessChainHttpServerBuilder) -> ServerResult<ProcessChainHttpServer> {
        if builder.id.is_none() {
            return Err(server_err!(ServerErrorCode::InvalidConfig, "id is none"));
        }

        if builder.hook_point.is_none() {
            return Err(server_err!(ServerErrorCode::InvalidConfig, "hook_point is none"));
        }

        let server_mgr = builder
            .server_mgr
            .ok_or(server_err!(ServerErrorCode::InvalidConfig, "server_mgr is none"))?;
        let server_mgr_ref = server_mgr
            .upgrade()
            .ok_or(server_err!(ServerErrorCode::InvalidConfig, "server_mgr is unavailable"))?;

        if builder.tunnel_manager.is_none() {
            return Err(server_err!(ServerErrorCode::InvalidConfig, "tunnel_manager is none"));
        }

        let version: http::Version = match builder.version {
            Some(ref version) => {
                match version.as_str() {
                    "HTTP/0.9" => http::Version::HTTP_09,
                    "HTTP/1.0" => http::Version::HTTP_10,
                    "HTTP/1.1" => http::Version::HTTP_11,
                    "HTTP/2" => http::Version::HTTP_2,
                    "HTTP/3" => http::Version::HTTP_3,
                    _ => return Err(server_err!(ServerErrorCode::InvalidConfig, "invalid http version")),
                }
            },
            None => http::Version::HTTP_11,
        };

        let global_process_chains = builder.global_process_chains.clone();
        let global_collection_manager = builder.global_collection_manager.clone();
        let external_commands = Some(get_external_commands(Arc::downgrade(&server_mgr_ref)));
        let (executor, _) = create_process_chain_executor(
            builder.hook_point.as_ref().unwrap(),
            global_process_chains.clone(),
            global_collection_manager.clone(),
            external_commands.clone(),
            builder.js_externals.clone(),
        )
        .await
        .map_err(into_server_err!(ServerErrorCode::ProcessChainError))?;
        let post_executor = if let Some(post_hook_point) = builder.post_hook_point.as_ref() {
            let (post_executor, _) = create_process_chain_executor(
                post_hook_point,
                global_process_chains,
                global_collection_manager,
                external_commands,
                builder.js_externals,
            )
            .await
            .map_err(into_server_err!(ServerErrorCode::ProcessChainError))?;
            Some(Arc::new(Mutex::new(post_executor)))
        } else {
            None
        };
        Ok(ProcessChainHttpServer {
            id: builder.id.unwrap(),
            version,
            h3_port: builder.h3_port,
            server_mgr,
            executor: Arc::new(Mutex::new(executor)),
            post_executor,
            tunnel_manager: builder.tunnel_manager.unwrap(),
            compression: builder.compression,
        })
    }

    async fn handle_forward_upstream(&self, req: http::Request<BoxBody<Bytes, ServerError>>, target_url: &str) -> ServerResult<http::Response<BoxBody<Bytes, ServerError>>> {
        let org_url = req.uri().to_string();
        // Trim URL boundary slashes so we don't end up with "//" when target_url ends with '/'
        // and org_url starts with '/'.
        let raw_url = if target_url.ends_with('/') || org_url.starts_with('/') {
            let base = target_url.trim_end_matches('/');
            let path = org_url.trim_start_matches('/');
            format!("{}/{}", base, path)
        } else {
            format!("{}{}", target_url, org_url)
        };
        let request_url = Url::parse(&raw_url).map_err(|e| {
            server_err!(
                ServerErrorCode::InvalidConfig,
                "Failed to parse request upstream url {}: {}",
                raw_url,
                e
            )
        })?;
        info!("handle_upstream url: {}", request_url);
        let scheme = request_url.scheme();
        match scheme {
            "http" => {
                let client: Client<_, BoxBody<Bytes, Box<dyn std::error::Error + Send + Sync>>> =
                    Client::builder(TokioExecutor::new()).build_http();
                let header = req.headers().clone();
                let method = req.method().clone();
                let body = req.into_body().map_err(|e| {
                    Box::new(e) as Box<dyn std::error::Error + Send + Sync>
                }).boxed();
                let mut upstream_req = Request::builder()
                    .method(method)
                    .uri(request_url.as_str())
                    .body(body).map_err(|e| {
                    server_err!(ServerErrorCode::InvalidConfig, "Failed to build request: {}", e)
                })?;

                *upstream_req.headers_mut() = header;

                let resp = client.request(upstream_req).await.map_err(|e| {
                    server_err!(ServerErrorCode::InvalidConfig, "Failed to request upstream {}: {}", request_url, e)
                })?;
                let resp = resp.map(|body| body.map_err(|e| ServerError::new(ServerErrorCode::StreamError, format!("{:?}", e))).boxed());
                Ok(resp)
            },
            "https" => {
                let header = req.headers().clone();
                let method = req.method().clone();
                let upstream_http_version = match req.version() {
                    http::Version::HTTP_10 => http::Version::HTTP_10,
                    http::Version::HTTP_11 => http::Version::HTTP_11,
                    _ => http::Version::HTTP_11,
                };

                let connect_host = request_url.host_str().ok_or_else(|| {
                    server_err!(
                        ServerErrorCode::InvalidConfig,
                        "Missing upstream host in url: {}",
                        request_url
                    )
                })?;
                let connect_port = request_url.port_or_known_default().ok_or_else(|| {
                    server_err!(
                        ServerErrorCode::InvalidConfig,
                        "Missing upstream port in url: {}",
                        request_url
                    )
                })?;

                let sni_host = {
                    let host = header.get("host").and_then(|h| h.to_str().ok()).map(|h| h.trim());
                    let parsed = host.and_then(|h| {
                        if h.is_empty() {
                            return None;
                        }
                        if let Some(stripped) = h.strip_prefix('[') {
                            let end = stripped.find(']')?;
                            return Some(stripped[..end].to_string());
                        }
                        Some(h.split(':').next().unwrap_or(h).to_string())
                    });
                    parsed.or_else(|| request_url.host_str().map(|h| h.to_string()))
                }.ok_or_else(|| {
                    server_err!(
                        ServerErrorCode::InvalidConfig,
                        "Missing SNI host for upstream: {}",
                        request_url
                    )
                })?;

                let tcp_stream = TcpStream::connect(format!("{}:{}", connect_host, connect_port))
                    .await
                    .map_err(|e| {
                        server_err!(
                            ServerErrorCode::InvalidConfig,
                            "Failed to connect upstream {}:{}: {}",
                            connect_host,
                            connect_port,
                            e
                        )
                    })?;

                let tls_config = ClientConfig::builder_with_provider(Arc::new(
                    rustls::crypto::ring::default_provider(),
                ))
                    .with_safe_default_protocol_versions()
                    .map_err(|e| server_err!(ServerErrorCode::InvalidConfig, "Invalid tls config: {}", e))?
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(NoCertificateVerifier))
                    .with_no_client_auth();
                let tls_connector = TlsConnector::from(Arc::new(tls_config));
                let server_name = ServerName::try_from(sni_host.clone()).map_err(|e| {
                    server_err!(
                        ServerErrorCode::InvalidConfig,
                        "Invalid upstream host for tls {}: {}",
                        sni_host,
                        e
                    )
                })?;
                let tls_stream = tls_connector.connect(server_name, tcp_stream).await.map_err(|e| {
                    server_err!(
                        ServerErrorCode::InvalidConfig,
                        "Failed tls handshake with upstream {} via {}:{}: {}",
                        sni_host,
                        connect_host,
                        connect_port,
                        e
                    )
                })?;

                let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls_stream))
                    .await
                    .map_err(|e| {
                        server_err!(
                            ServerErrorCode::StreamError,
                            "Failed to build https client connection: {}",
                            e
                        )
                    })?;
                tokio::spawn(async move {
                    if let Err(e) = conn.await {
                        debug!("https upstream connection closed with error: {}", e);
                    }
                });

                let body = req.into_body().map_err(|e| {
                    Box::new(e) as Box<dyn std::error::Error + Send + Sync>
                }).boxed();
                let mut upstream_req = Request::builder()
                    .method(method)
                    .uri(org_url)
                    .version(upstream_http_version)
                    .body(body)
                    .map_err(|e| {
                        server_err!(
                            ServerErrorCode::BadRequest,
                            "Failed to build https upstream request: {}",
                            e
                        )
                    })?;
                *upstream_req.headers_mut() = header;

                let resp = sender.send_request(upstream_req).await.map_err(|e| {
                    server_err!(
                        ServerErrorCode::InvalidConfig,
                        "Failed to request https upstream {} via {}:{}: {}",
                        sni_host,
                        connect_host,
                        connect_port,
                        e
                    )
                })?;
                let resp = resp.map(|body| body.map_err(|e| ServerError::new(ServerErrorCode::StreamError, format!("{:?}", e))).boxed());
                Ok(resp)
            },
            _ => {
                let tunnel_connector = TunnelConnector {
                    target_stream_url: target_url.to_string(),
                    tunnel_manager: self.tunnel_manager.clone(),
                };


                let client: Client<TunnelConnector, BoxBody<Bytes, Box<dyn std::error::Error + Send + Sync>>> = Client::builder(TokioExecutor::new())
                    .build(tunnel_connector);

                let header = req.headers().clone();
                let mut host_name = "localhost".to_string();
                let hname =  req.headers().get("host");
                if hname.is_some() {
                    host_name = hname.unwrap().to_str().unwrap().to_string();
                }
                let fake_url = format!("http://{}{}", host_name, org_url);
                let method = req.method().clone();
                let body = req.into_body().map_err(|e| {
                    Box::new(e) as Box<dyn std::error::Error + Send + Sync>
                }).boxed();
                let mut upstream_req = Request::builder()
                    .method(method)
                    .uri(fake_url)
                    .body(body).map_err(|e| {
                        server_err!(ServerErrorCode::BadRequest, "Failed to build upstream_req: {}", e)
                    })?;

                *upstream_req.headers_mut() = header;
                let resp = client.request(upstream_req).await.map_err(|e| {
                    server_err!(ServerErrorCode::TunnelError, "Failed to request upstream: {}", e)
                })?;
                let resp = resp.map(|body| body.map_err(|e| ServerError::new(ServerErrorCode::StreamError, format!("{:?}", e))).boxed());
                return Ok(resp)
            }
        }
    }

    fn parse_redirect_status_code(status: Option<&str>) -> ServerResult<StatusCode> {
        let status_code = match status {
            Some(status) => {
                let code = status.parse::<u16>().map_err(|e| {
                    server_err!(ServerErrorCode::InvalidConfig, "invalid redirect status code: {}, {}", status, e)
                })?;
                StatusCode::from_u16(code).map_err(|e| {
                    server_err!(ServerErrorCode::InvalidConfig, "invalid redirect status code: {}, {}", code, e)
                })?
            }
            None => StatusCode::FOUND,
        };

        match status_code {
            StatusCode::MOVED_PERMANENTLY
            | StatusCode::FOUND
            | StatusCode::SEE_OTHER
            | StatusCode::TEMPORARY_REDIRECT
            | StatusCode::PERMANENT_REDIRECT => Ok(status_code),
            _ => Err(server_err!(
                ServerErrorCode::InvalidConfig,
                "invalid redirect status code: {}, supported values are 301, 302, 303, 307, 308",
                status_code.as_u16()
            )),
        }
    }

    fn build_redirect_response(
        &self,
        location: &str,
        status: StatusCode,
    ) -> ServerResult<http::Response<BoxBody<Bytes, ServerError>>> {
        let response = http::Response::builder()
            .status(status)
            .header(http::header::LOCATION, location)
            .body(Full::new(Bytes::new()).map_err(|e| match e {}).boxed())
            .map_err(|e| {
                server_err!(
                    ServerErrorCode::BadRequest,
                    "Failed to build redirect response: {}",
                    e
                )
            })?;
        Ok(response)
    }

    fn parse_error_status_code(status: &str) -> ServerResult<StatusCode> {
        let code = status.parse::<u16>().map_err(|e| {
            server_err!(
                ServerErrorCode::InvalidConfig,
                "invalid error status code: {}, {}",
                status,
                e
            )
        })?;
        if !(400..=599).contains(&code) {
            return Err(server_err!(
                ServerErrorCode::InvalidConfig,
                "invalid error status code: {}, supported range is 400..=599",
                code
            ));
        }
        StatusCode::from_u16(code).map_err(|e| {
            server_err!(
                ServerErrorCode::InvalidConfig,
                "invalid error status code: {}, {}",
                code,
                e
            )
        })
    }

    fn build_error_response(
        &self,
        status: StatusCode,
        message: Option<&str>,
    ) -> ServerResult<http::Response<BoxBody<Bytes, ServerError>>> {
        let body = message.unwrap_or("");
        let response = http::Response::builder()
            .status(status)
            .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(Full::new(Bytes::from(body.to_string())).map_err(|e| match e {}).boxed())
            .map_err(|e| {
                server_err!(
                    ServerErrorCode::BadRequest,
                    "Failed to build error response: {}",
                    e
                )
            })?;
        Ok(response)
    }

    // Post-hook rules:
    // - post_hook_point is optional; when absent, response is returned as-is.
    // - RESP is a header-only map (no status/version keys).
    // - Post chain control results are ignored; only header mutations are applied.
    async fn apply_post_chain(
        &self,
        resp: http::Response<BoxBody<Bytes, ServerError>>,
        info: Option<&StreamInfo>,
    ) -> ServerResult<http::Response<BoxBody<Bytes, ServerError>>> {
        let post_executor = match &self.post_executor {
            Some(executor) => executor.lock().unwrap().fork(),
            None => return Ok(resp),
        };

        let resp_map = HttpResponseHeaderMap::new(resp);
        let global_env = post_executor.global_env();
        if let Some(info) = info {
            if let Some(src_addr) = info.src_addr.as_ref() {
                if let Ok(socket_addr) = src_addr.parse::<SocketAddr>() {
                    global_env
                        .create(
                            "REQ_remote_ip",
                            CollectionValue::String(socket_addr.ip().to_string()),
                        )
                        .await
                        .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{}", e))?;
                    global_env
                        .create(
                            "REQ_remote_port",
                            CollectionValue::String(socket_addr.port().to_string()),
                        )
                        .await
                        .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{}", e))?;
                }
            }
            if let Some(src_addr) = info.conn_src_addr.as_ref() {
                if let Ok(socket_addr) = src_addr.parse::<SocketAddr>() {
                    global_env
                        .create(
                            "REQ_conn_remote_ip",
                            CollectionValue::String(socket_addr.ip().to_string()),
                        )
                        .await
                        .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{}", e))?;
                    global_env
                        .create(
                            "REQ_conn_remote_port",
                            CollectionValue::String(socket_addr.port().to_string()),
                        )
                        .await
                        .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{}", e))?;
                }
            }
            if let Some(src_addr) = info.real_src_addr.as_ref() {
                if let Ok(socket_addr) = src_addr.parse::<SocketAddr>() {
                    global_env
                        .create(
                            "REQ_real_remote_ip",
                            CollectionValue::String(socket_addr.ip().to_string()),
                        )
                        .await
                        .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{}", e))?;
                    global_env
                        .create(
                            "REQ_real_remote_port",
                            CollectionValue::String(socket_addr.port().to_string()),
                        )
                        .await
                        .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{}", e))?;
                }
            }
            if let Some(source_mac) = info.source_mac.as_ref() {
                global_env
                    .create(
                        "REQ_source_mac",
                        CollectionValue::String(source_mac.to_string()),
                    )
                    .await
                    .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{}", e))?;
            }
            if let Some(source_hostname) = info.source_hostname.as_ref() {
                global_env
                    .create(
                        "REQ_source_hostname",
                        CollectionValue::String(source_hostname.to_string()),
                    )
                    .await
                    .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{}", e))?;
            }
            if let Some(source_online_secs) = info.source_online_secs.as_ref() {
                global_env
                    .create(
                        "REQ_source_online_secs",
                        CollectionValue::String(source_online_secs.to_string()),
                    )
                    .await
                    .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{}", e))?;
            }
        }
        resp_map
            .register_visitors(&global_env)
            .await
            .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{}", e))?;

        let ret = post_executor
            .execute_lib()
            .await
            .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{}", e))?;
        if ret.is_control() {
            debug!(
                "post_hook_point control result ignored hook_point={} final_value={:?}",
                self.id,
                ret.value(),
            );
        }

        let resp = resp_map
            .into_response()
            .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{}", e))?;
        Ok(resp)
    }

    async fn apply_post_chain_result(
        &self,
        resp: ServerResult<http::Response<BoxBody<Bytes, ServerError>>>,
        req_info: &CompressionRequestInfo,
        info: Option<&StreamInfo>,
    ) -> ServerResult<http::Response<BoxBody<Bytes, ServerError>>> {
        match resp {
            Ok(resp) => {
                let resp = self.apply_post_chain(resp, info).await?;
                apply_response_compression(resp, req_info, &self.compression)
            }
            Err(err) => Err(err),
        }
    }
}

#[async_trait::async_trait]
impl HttpServer for ProcessChainHttpServer {
    async fn serve_request(&self, req: http::Request<BoxBody<Bytes, ServerError>>, info: StreamInfo) -> ServerResult<http::Response<BoxBody<Bytes, ServerError>>> {
        let req_info = CompressionRequestInfo::from_request(&req);
        let req = match apply_request_decompression(req, &self.compression) {
            Ok(req) => req,
            Err(err) => {
                let mut response = http::Response::new(
                    Full::new(Bytes::from(err.msg().to_string()))
                        .map_err(|e| match e {})
                        .boxed(),
                );
                *response.status_mut() = StatusCode::BAD_REQUEST;
                return self
                    .apply_post_chain_result(Ok(response), &req_info, Some(&info))
                    .await;
            }
        };

        // Capture request meta early so we can log it even if the process chain
        // decides to drop/reject without forwarding the request.
        let req_method = req.method().to_string();
        let req_host = req
            .headers()
            .get("host")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("none")
            .to_string();
        let req_uri = req.uri().to_string();
        let req_remote = info
            .src_addr
            .as_deref()
            .unwrap_or("unknown")
            .to_string();

        let executor = {
            self.executor.lock().unwrap().fork()
        };

        let req_map = HttpRequestHeaderMap::new(req);
        let global_env = executor.global_env();
        if let Some(src_addr) = info.src_addr.as_ref() {
            if let Ok(socket_addr) = src_addr.parse::<SocketAddr>() {
                global_env
                    .create(
                        "REQ_remote_ip",
                        CollectionValue::String(socket_addr.ip().to_string()),
                    )
                    .await
                    .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{}", e))?;
                global_env
                    .create(
                        "REQ_remote_port",
                        CollectionValue::String(socket_addr.port().to_string()),
                    )
                    .await
                    .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{}", e))?;
            }
        }
        if let Some(src_addr) = info.conn_src_addr.as_ref() {
            if let Ok(socket_addr) = src_addr.parse::<SocketAddr>() {
                global_env
                    .create(
                        "REQ_conn_remote_ip",
                        CollectionValue::String(socket_addr.ip().to_string()),
                    )
                    .await
                    .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{}", e))?;
                global_env
                    .create(
                        "REQ_conn_remote_port",
                        CollectionValue::String(socket_addr.port().to_string()),
                    )
                    .await
                    .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{}", e))?;
            }
        }
        if let Some(src_addr) = info.real_src_addr.as_ref() {
            if let Ok(socket_addr) = src_addr.parse::<SocketAddr>() {
                global_env
                    .create(
                        "REQ_real_remote_ip",
                        CollectionValue::String(socket_addr.ip().to_string()),
                    )
                    .await
                    .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{}", e))?;
                global_env
                    .create(
                        "REQ_real_remote_port",
                        CollectionValue::String(socket_addr.port().to_string()),
                    )
                    .await
                    .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{}", e))?;
            }
        }
        if let Some(source_mac) = info.source_mac.as_ref() {
            global_env
                .create(
                    "REQ_source_mac",
                    CollectionValue::String(source_mac.to_string()),
                )
                .await
                .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{}", e))?;
        }
        if let Some(source_hostname) = info.source_hostname.as_ref() {
            global_env
                .create(
                    "REQ_source_hostname",
                    CollectionValue::String(source_hostname.to_string()),
                )
                .await
                .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{}", e))?;
        }
        if let Some(source_online_secs) = info.source_online_secs.as_ref() {
            global_env
                .create(
                    "REQ_source_online_secs",
                    CollectionValue::String(source_online_secs.to_string()),
                )
                .await
                .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{}", e))?;
        }
        req_map.register_visitors(&global_env).await.map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{}", e))?;

        let ret = executor.execute_lib().await.map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{}", e))?;

        if ret.is_control() {
            if ret.is_drop() {
                debug!("Request dropped by the process chain");
                let response = http::Response::new(
                    Full::new(Bytes::from("Request dropped"))
                        .map_err(|e| match e {})
                        .boxed(),
                );
                return self
                    .apply_post_chain_result(Ok(response), &req_info, Some(&info))
                    .await;
            } else if ret.is_reject() {
                debug!(
                    "process_chain_reject server={} remote={} method={} host={} uri={}",
                    self.id,
                    req_remote,
                    req_method,
                    req_host,
                    req_uri,
                );
                let mut response = http::Response::new(Full::new(Bytes::new()).map_err(|e| match e {}).boxed());
                *response.status_mut() = StatusCode::FORBIDDEN;
                return self
                    .apply_post_chain_result(Ok(response), &req_info, Some(&info))
                    .await;
            }
            if let Some(CommandControl::Return(ret)) = ret.as_control() {
                if let Some(list) = shlex::split(ret.value.as_str()) {
                    if list.is_empty() {
                        log::error!("process chain return is empty");
                        let mut response = http::Response::new(Full::new(Bytes::new()).map_err(|e| match e {}).boxed());
                        *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                        return self
                            .apply_post_chain_result(Ok(response), &req_info, Some(&info))
                            .await;
                    }

                    let cmd = list[0].as_str();
                    match cmd {
                        "server" => {
                            if list.len() < 2 {
                                return Err(server_err!(
                                    ServerErrorCode::InvalidConfig,
                                    "invalid server command"
                                ));
                            }

                            let server_id = list[1].as_str();
                            let post_req= req_map.into_request()
                                .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{}", e))?;

                            if let Some(server_mgr) = self.server_mgr.upgrade() {
                                if let Some(service) = server_mgr.get_http_server(server_id) {
                                    let resp = service.serve_request(post_req, info.clone()).await;
                                    return self.apply_post_chain_result(resp, &req_info, Some(&info)).await;
                                }
                            } else {
                                log::error!("server manager is unavailable");
                            }
                        },
                        "forward" => {
                            if list.len() < 2 {
                                return Err(server_err!(
                                    ServerErrorCode::InvalidConfig,
                                    "invalid forward command"
                                ));
                            }
                            let target_url = list[1].as_str();
                            let post_req= req_map.into_request()
                                .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{}", e))?;
                            let resp = self.handle_forward_upstream(post_req, target_url).await;
                            return self.apply_post_chain_result(resp, &req_info, Some(&info)).await;
                        },
                        "redirect" => {
                            if list.len() < 2 || list.len() > 3 {
                                return Err(server_err!(
                                    ServerErrorCode::InvalidConfig,
                                    "invalid redirect command"
                                ));
                            }

                            let location = list[1].as_str();
                            if location.is_empty() {
                                return Err(server_err!(
                                    ServerErrorCode::InvalidConfig,
                                    "invalid redirect command"
                                ));
                            }
                            let status = Self::parse_redirect_status_code(
                                list.get(2).map(|v| v.as_str()),
                            )?;
                            let resp = self.build_redirect_response(location, status)?;
                            return self
                                .apply_post_chain_result(Ok(resp), &req_info, Some(&info))
                                .await;
                        },
                        "error" => {
                            if list.len() < 2 || list.len() > 3 {
                                return Err(server_err!(
                                    ServerErrorCode::InvalidConfig,
                                    "invalid error command"
                                ));
                            }
                            let status = Self::parse_error_status_code(list[1].as_str())?;
                            let message = list.get(2).map(|v| v.as_str());
                            let resp = self.build_error_response(status, message)?;
                            return self
                                .apply_post_chain_result(Ok(resp), &req_info, Some(&info))
                                .await;
                        }
                        _ => {
                            log::error!("unknown command: {}", cmd);
                        }
                    }
                }
            }
        } else {
            // Log only the non-control (normal) outcome.
            // A normal value like "false" often means no routing rule matched.
            debug!(
                "process_chain_decision hook_point={} final_result_kind=normal final_value={:?}",
                self.id,
                ret.value(),
            );
        }
        let mut response = http::Response::new(Full::new(Bytes::new()).map_err(|e| match e {}).boxed());
        *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
        self.apply_post_chain_result(Ok(response), &req_info, Some(&info)).await
    }

    fn id(&self) -> String {
        self.id.clone()
    }

    fn http_version(&self) -> Version {
        self.version
    }

    fn http3_port(&self) -> Option<u16> {
        self.h3_port
    }
}

fn default_gzip_min_length() -> u64 {
    20
}

fn default_gzip_comp_level() -> u32 {
    1
}

fn default_gzip_http_version() -> String {
    "1.1".to_string()
}

fn default_brotli_min_length() -> u64 {
    20
}

fn default_brotli_comp_level() -> u32 {
    4
}

fn clamp_gzip_comp_level(level: u32) -> u32 {
    level.clamp(1, 9)
}

fn clamp_brotli_comp_level(level: u32) -> u32 {
    level.clamp(0, 11)
}

fn normalize_content_types(types: &[String]) -> Vec<String> {
    types
        .iter()
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .collect()
}

fn parse_gzip_http_version(value: &str) -> ServerResult<Version> {
    match value.trim().to_ascii_uppercase().as_str() {
        "1.0" | "HTTP/1.0" => Ok(Version::HTTP_10),
        "1.1" | "HTTP/1.1" => Ok(Version::HTTP_11),
        "2" | "2.0" | "HTTP/2" => Ok(Version::HTTP_2),
        "3" | "3.0" | "HTTP/3" => Ok(Version::HTTP_3),
        _ => Err(server_err!(
            ServerErrorCode::InvalidConfig,
            "invalid gzip_http_version: {}",
            value
        )),
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ProcessChainHttpServerConfig {
    pub id: String,
    #[serde(rename = "type")]
    pub ty: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub h3_port: Option<u16>,
    pub hook_point: ProcessChainConfigs,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post_hook_point: Option<ProcessChainConfigs>,
    #[serde(default)]
    pub gzip: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gzip_types: Vec<String>,
    #[serde(default = "default_gzip_min_length")]
    pub gzip_min_length: u64,
    #[serde(default = "default_gzip_comp_level")]
    pub gzip_comp_level: u32,
    #[serde(default = "default_gzip_http_version")]
    pub gzip_http_version: String,
    #[serde(default)]
    pub gzip_vary: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gzip_disable: Option<String>,
    #[serde(default)]
    pub gzip_request: bool,
    #[serde(default)]
    pub brotli: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub brotli_types: Vec<String>,
    #[serde(default = "default_brotli_min_length")]
    pub brotli_min_length: u64,
    #[serde(default = "default_brotli_comp_level")]
    pub brotli_comp_level: u32,
}

impl ServerConfig for ProcessChainHttpServerConfig {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn server_type(&self) -> String {
        "http".to_string()
    }

    fn get_config_json(&self) -> String {
        serde_json::to_string(self).unwrap()
    }
}

#[derive(Clone)]
pub struct HttpServerContext {
    pub server_mgr: ServerManagerWeakRef,
    pub global_process_chains: GlobalProcessChainsRef,
    pub js_externals: JsExternalsManagerRef,
    pub tunnel_manager: TunnelManager,
    pub global_collection_manager: GlobalCollectionManagerRef,
}

impl HttpServerContext {
    pub fn new(
        server_mgr: ServerManagerWeakRef,
        global_process_chains: GlobalProcessChainsRef,
        js_externals: JsExternalsManagerRef,
        tunnel_manager: TunnelManager,
        global_collection_manager: GlobalCollectionManagerRef,
    ) -> Self {
        Self {
            server_mgr,
            global_process_chains,
            js_externals,
            tunnel_manager,
            global_collection_manager,
        }
    }
}

impl ServerContext for HttpServerContext {
    fn get_server_type(&self) -> String {
        "http".to_string()
    }
}

pub struct ProcessChainHttpServerFactory;

impl ProcessChainHttpServerFactory {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl ServerFactory for ProcessChainHttpServerFactory {
    async fn create(
        &self,
        config: Arc<dyn ServerConfig>,
        context: Option<ServerContextRef>,
    ) -> ServerResult<Vec<Server>> {
        let config = config.as_any().downcast_ref::<ProcessChainHttpServerConfig>()
            .ok_or(server_err!(ServerErrorCode::InvalidConfig, "invalid process chain http server config"))?;

        let context = context.ok_or(server_err!(
            ServerErrorCode::InvalidConfig,
            "http server context is required"
        ))?;
        let context = context
            .as_ref()
            .as_any()
            .downcast_ref::<HttpServerContext>()
            .ok_or(server_err!(
                ServerErrorCode::InvalidConfig,
                "invalid http server context"
            ))?;
        let mut builder = ProcessChainHttpServer::builder()
            .hook_point(config.hook_point.clone())
            .id(config.id.clone())
            .server_mgr(context.server_mgr.clone())
            .tunnel_manager(context.tunnel_manager.clone())
            .global_process_chains(context.global_process_chains.clone())
            .js_externals(context.js_externals.clone())
            .global_collection_manager(context.global_collection_manager.clone());
        let compression = ProcessChainHttpServerBuilder::build_compression_settings(config)?;
        builder = builder.compression(compression);
        if config.h3_port.is_some() {
            builder = builder.h3_port(config.h3_port.clone().unwrap());
        }
        if config.version.is_some() {
            builder = builder.version(config.version.clone().unwrap());
        }
        if let Some(post_hook_point) = config.post_hook_point.as_ref() {
            builder = builder.post_hook_point(post_hook_point.clone());
        }
        let server = builder.build().await?;
        Ok(vec![Server::Http(Arc::new(server))])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_compression::tokio::bufread::{BrotliDecoder, GzipDecoder, GzipEncoder};
    use std::io::Cursor;
    use std::sync::Arc;
    use buckyos_kit::init_logging;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use crate::{GlobalCollectionManager, GlobalProcessChains, JsExternalsManager, ServerManager, StreamInfo, hyper_serve_http, hyper_serve_http1};
    use tokio::io::AsyncReadExt;

    struct FixedResponseServer {
        id: String,
        body: Bytes,
        content_type: &'static str,
        status: StatusCode,
        content_encoding: Option<&'static str>,
    }

    #[async_trait::async_trait]
    impl HttpServer for FixedResponseServer {
        async fn serve_request(
            &self,
            _req: http::Request<BoxBody<Bytes, ServerError>>,
            _info: StreamInfo,
        ) -> ServerResult<http::Response<BoxBody<Bytes, ServerError>>> {
            let body = self.body.clone();
            let len = body.len();
            let mut builder = http::Response::builder()
                .status(self.status)
                .header("Content-Type", self.content_type)
                .header("Content-Length", len);
            if let Some(encoding) = self.content_encoding {
                builder = builder.header("Content-Encoding", encoding);
            }
            let response = builder
                .body(Full::new(body).map_err(|e| match e {}).boxed())
                .map_err(|e| server_err!(ServerErrorCode::BadRequest, "Failed to build response: {}", e))?;
            Ok(response)
        }

        fn id(&self) -> String {
            self.id.clone()
        }

        fn http_version(&self) -> Version {
            Version::HTTP_11
        }

        fn http3_port(&self) -> Option<u16> {
            None
        }
    }

    struct EchoBodyServer {
        id: String,
    }

    #[async_trait::async_trait]
    impl HttpServer for EchoBodyServer {
        async fn serve_request(
            &self,
            req: http::Request<BoxBody<Bytes, ServerError>>,
            _info: StreamInfo,
        ) -> ServerResult<http::Response<BoxBody<Bytes, ServerError>>> {
            let body_bytes = req
                .collect()
                .await
                .map_err(|e| server_err!(ServerErrorCode::StreamError, "Stream error: {}", e))?
                .to_bytes();
            let len = body_bytes.len();
            let response = http::Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/octet-stream")
                .header("Content-Length", len)
                .body(Full::new(body_bytes).map_err(|e| match e {}).boxed())
                .map_err(|e| server_err!(ServerErrorCode::BadRequest, "Failed to build response: {}", e))?;
            Ok(response)
        }

        fn id(&self) -> String {
            self.id.clone()
        }

        fn http_version(&self) -> Version {
            Version::HTTP_11
        }

        fn http3_port(&self) -> Option<u16> {
            None
        }
    }

    async fn gzip_bytes(data: &[u8]) -> Bytes {
        let cursor = Cursor::new(data.to_vec());
        let reader = tokio::io::BufReader::new(cursor);
        let mut encoder = GzipEncoder::new(reader);
        let mut output = Vec::new();
        encoder.read_to_end(&mut output).await.unwrap();
        Bytes::from(output)
    }

    async fn gunzip_bytes(data: Bytes) -> Bytes {
        let cursor = Cursor::new(data.to_vec());
        let reader = tokio::io::BufReader::new(cursor);
        let mut decoder = GzipDecoder::new(reader);
        let mut output = Vec::new();
        decoder.read_to_end(&mut output).await.unwrap();
        Bytes::from(output)
    }

    async fn brotli_decode_bytes(data: Bytes) -> Bytes {
        let cursor = Cursor::new(data.to_vec());
        let reader = tokio::io::BufReader::new(cursor);
        let mut decoder = BrotliDecoder::new(reader);
        let mut output = Vec::new();
        decoder.read_to_end(&mut output).await.unwrap();
        Bytes::from(output)
    }

    #[tokio::test]
    async fn test_http_server_builder_creation() {
        let builder = ProcessChainHttpServer::builder();
        assert!(builder.version.is_none());
        assert!(builder.hook_point.is_none());
        assert!(builder.post_hook_point.is_none());
        assert!(builder.global_process_chains.is_none());
        assert!(builder.server_mgr.is_none());
    }

    #[tokio::test]
    async fn test_gzip_min_length_no_compress() {
        let mock_server_mgr = Arc::new(ServerManager::new());
        let server = FixedResponseServer {
            id: "test".to_string(),
            body: Bytes::from_static(b"small-body"),
            content_type: "text/plain",
            status: StatusCode::OK,
            content_encoding: None,
        };
        mock_server_mgr
            .add_server(Server::Http(Arc::new(server)))
            .unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "server test";
        "#;
        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let mut compression = HttpCompressionSettings::default();
        compression.gzip = true;
        compression.gzip_vary = true;
        compression.gzip_min_length = 1024;
        compression.gzip_types = vec!["text/plain".to_string()];

        let result = ProcessChainHttpServer::builder()
            .id("test_gzip_min")
            .version("HTTP/1.1".to_string())
            .hook_point(chains)
            .tunnel_manager(TunnelManager::new())
            .server_mgr(Arc::downgrade(&mock_server_mgr))
            .compression(compression)
            .build()
            .await;

        assert!(result.is_ok());
        let http_server = result.unwrap();

        let request = http::Request::builder()
            .method("GET")
            .uri("http://localhost/")
            .header("Accept-Encoding", "gzip")
            .body(Full::new(Bytes::new()).map_err(|e| match e {}).boxed())
            .unwrap();

        let resp = http_server
            .serve_request(request, StreamInfo::default())
            .await
            .unwrap();

        assert!(resp.headers().get("content-encoding").is_none());
        let vary = resp
            .headers()
            .get("vary")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");
        assert!(vary.to_ascii_lowercase().contains("accept-encoding"));

        let body = resp.collect().await.unwrap().to_bytes();
        assert_eq!(body, Bytes::from_static(b"small-body"));
    }

    #[tokio::test]
    async fn test_gzip_response_compress() {
        let mock_server_mgr = Arc::new(ServerManager::new());
        let raw_body = Bytes::from_static(b"compress-body-contents");
        let server = FixedResponseServer {
            id: "compress".to_string(),
            body: raw_body.clone(),
            content_type: "text/plain",
            status: StatusCode::OK,
            content_encoding: None,
        };
        mock_server_mgr
            .add_server(Server::Http(Arc::new(server)))
            .unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "server compress";
        "#;
        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let mut compression = HttpCompressionSettings::default();
        compression.gzip = true;
        compression.gzip_vary = true;
        compression.gzip_min_length = 1;
        compression.gzip_types = vec!["text/plain".to_string()];

        let http_server = ProcessChainHttpServer::builder()
            .id("test_gzip_compress")
            .version("HTTP/1.1".to_string())
            .hook_point(chains)
            .tunnel_manager(TunnelManager::new())
            .server_mgr(Arc::downgrade(&mock_server_mgr))
            .compression(compression)
            .build()
            .await
            .unwrap();

        let request = http::Request::builder()
            .method("GET")
            .uri("http://localhost/")
            .header("Accept-Encoding", "gzip")
            .body(Full::new(Bytes::new()).map_err(|e| match e {}).boxed())
            .unwrap();

        let resp = http_server
            .serve_request(request, StreamInfo::default())
            .await
            .unwrap();

        assert_eq!(
            resp.headers()
                .get("content-encoding")
                .and_then(|value| value.to_str().ok()),
            Some("gzip")
        );
        assert!(resp.headers().get("content-length").is_none());
        let vary = resp
            .headers()
            .get("vary")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");
        assert!(vary.to_ascii_lowercase().contains("accept-encoding"));

        let body = resp.collect().await.unwrap().to_bytes();
        let decoded = gunzip_bytes(body).await;
        assert_eq!(decoded, raw_body);
    }

    #[tokio::test]
    async fn test_gzip_request_decompression() {
        let mock_server_mgr = Arc::new(ServerManager::new());
        let server = EchoBodyServer {
            id: "echo".to_string(),
        };
        mock_server_mgr
            .add_server(Server::Http(Arc::new(server)))
            .unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "server echo";
        "#;
        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let mut compression = HttpCompressionSettings::default();
        compression.gzip_request = true;

        let http_server = ProcessChainHttpServer::builder()
            .id("test_gzip_request")
            .version("HTTP/1.1".to_string())
            .hook_point(chains)
            .tunnel_manager(TunnelManager::new())
            .server_mgr(Arc::downgrade(&mock_server_mgr))
            .compression(compression)
            .build()
            .await
            .unwrap();

        let original = Bytes::from_static(b"request-body");
        let compressed = gzip_bytes(original.as_ref()).await;

        let request = http::Request::builder()
            .method("POST")
            .uri("http://localhost/")
            .header("Content-Encoding", "gzip")
            .body(Full::new(compressed).map_err(|e| match e {}).boxed())
            .unwrap();

        let resp = http_server
            .serve_request(request, StreamInfo::default())
            .await
            .unwrap();

        let body = resp.collect().await.unwrap().to_bytes();
        assert_eq!(body, original);
    }

    #[tokio::test]
    async fn test_gzip_response_skip_when_already_encoded() {
        let mock_server_mgr = Arc::new(ServerManager::new());
        let raw_body = Bytes::from_static(b"already-encoded");
        let server = FixedResponseServer {
            id: "encoded".to_string(),
            body: raw_body.clone(),
            content_type: "text/plain",
            status: StatusCode::OK,
            content_encoding: Some("gzip"),
        };
        mock_server_mgr
            .add_server(Server::Http(Arc::new(server)))
            .unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "server encoded";
        "#;
        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let mut compression = HttpCompressionSettings::default();
        compression.gzip = true;
        compression.gzip_vary = true;
        compression.gzip_min_length = 1;
        compression.gzip_types = vec!["text/plain".to_string()];

        let http_server = ProcessChainHttpServer::builder()
            .id("test_gzip_encoded")
            .version("HTTP/1.1".to_string())
            .hook_point(chains)
            .tunnel_manager(TunnelManager::new())
            .server_mgr(Arc::downgrade(&mock_server_mgr))
            .compression(compression)
            .build()
            .await
            .unwrap();

        let request = http::Request::builder()
            .method("GET")
            .uri("http://localhost/")
            .header("Accept-Encoding", "gzip")
            .body(Full::new(Bytes::new()).map_err(|e| match e {}).boxed())
            .unwrap();

        let resp = http_server
            .serve_request(request, StreamInfo::default())
            .await
            .unwrap();

        assert_eq!(
            resp.headers()
                .get("content-encoding")
                .and_then(|value| value.to_str().ok()),
            Some("gzip")
        );
        let body = resp.collect().await.unwrap().to_bytes();
        assert_eq!(body, raw_body);
    }

    #[tokio::test]
    async fn test_gzip_response_skip_for_head() {
        let mock_server_mgr = Arc::new(ServerManager::new());
        let raw_body = Bytes::from_static(b"head-body-content");
        let server = FixedResponseServer {
            id: "head".to_string(),
            body: raw_body.clone(),
            content_type: "text/plain",
            status: StatusCode::OK,
            content_encoding: None,
        };
        mock_server_mgr
            .add_server(Server::Http(Arc::new(server)))
            .unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "server head";
        "#;
        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let mut compression = HttpCompressionSettings::default();
        compression.gzip = true;
        compression.gzip_vary = true;
        compression.gzip_min_length = 1;
        compression.gzip_types = vec!["text/plain".to_string()];

        let http_server = ProcessChainHttpServer::builder()
            .id("test_gzip_head")
            .version("HTTP/1.1".to_string())
            .hook_point(chains)
            .tunnel_manager(TunnelManager::new())
            .server_mgr(Arc::downgrade(&mock_server_mgr))
            .compression(compression)
            .build()
            .await
            .unwrap();

        let request = http::Request::builder()
            .method("HEAD")
            .uri("http://localhost/")
            .header("Accept-Encoding", "gzip")
            .body(Full::new(Bytes::new()).map_err(|e| match e {}).boxed())
            .unwrap();

        let resp = http_server
            .serve_request(request, StreamInfo::default())
            .await
            .unwrap();

        assert!(resp.headers().get("content-encoding").is_none());
        let body = resp.collect().await.unwrap().to_bytes();
        assert_eq!(body, raw_body);
    }

    #[tokio::test]
    async fn test_gzip_response_skip_for_status() {
        let mock_server_mgr = Arc::new(ServerManager::new());
        let server = FixedResponseServer {
            id: "no_content".to_string(),
            body: Bytes::new(),
            content_type: "text/plain",
            status: StatusCode::NO_CONTENT,
            content_encoding: None,
        };
        mock_server_mgr
            .add_server(Server::Http(Arc::new(server)))
            .unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "server no_content";
        "#;
        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let mut compression = HttpCompressionSettings::default();
        compression.gzip = true;
        compression.gzip_vary = true;
        compression.gzip_min_length = 1;
        compression.gzip_types = vec!["text/plain".to_string()];

        let http_server = ProcessChainHttpServer::builder()
            .id("test_gzip_no_content")
            .version("HTTP/1.1".to_string())
            .hook_point(chains)
            .tunnel_manager(TunnelManager::new())
            .server_mgr(Arc::downgrade(&mock_server_mgr))
            .compression(compression)
            .build()
            .await
            .unwrap();

        let request = http::Request::builder()
            .method("GET")
            .uri("http://localhost/")
            .header("Accept-Encoding", "gzip")
            .body(Full::new(Bytes::new()).map_err(|e| match e {}).boxed())
            .unwrap();

        let resp = http_server
            .serve_request(request, StreamInfo::default())
            .await
            .unwrap();

        assert!(resp.headers().get("content-encoding").is_none());
    }

    #[tokio::test]
    async fn test_gzip_response_skip_for_not_modified() {
        let mock_server_mgr = Arc::new(ServerManager::new());
        let server = FixedResponseServer {
            id: "not_modified".to_string(),
            body: Bytes::new(),
            content_type: "text/plain",
            status: StatusCode::NOT_MODIFIED,
            content_encoding: None,
        };
        mock_server_mgr
            .add_server(Server::Http(Arc::new(server)))
            .unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "server not_modified";
        "#;
        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let mut compression = HttpCompressionSettings::default();
        compression.gzip = true;
        compression.gzip_vary = true;
        compression.gzip_min_length = 1;
        compression.gzip_types = vec!["text/plain".to_string()];

        let http_server = ProcessChainHttpServer::builder()
            .id("test_gzip_not_modified")
            .version("HTTP/1.1".to_string())
            .hook_point(chains)
            .tunnel_manager(TunnelManager::new())
            .server_mgr(Arc::downgrade(&mock_server_mgr))
            .compression(compression)
            .build()
            .await
            .unwrap();

        let request = http::Request::builder()
            .method("GET")
            .uri("http://localhost/")
            .header("Accept-Encoding", "gzip")
            .body(Full::new(Bytes::new()).map_err(|e| match e {}).boxed())
            .unwrap();

        let resp = http_server
            .serve_request(request, StreamInfo::default())
            .await
            .unwrap();

        assert!(resp.headers().get("content-encoding").is_none());
    }

    #[tokio::test]
    async fn test_brotli_response_compress() {
        let mock_server_mgr = Arc::new(ServerManager::new());
        let raw_body = Bytes::from_static(b"brotli-contents");
        let server = FixedResponseServer {
            id: "brotli".to_string(),
            body: raw_body.clone(),
            content_type: "text/plain",
            status: StatusCode::OK,
            content_encoding: None,
        };
        mock_server_mgr
            .add_server(Server::Http(Arc::new(server)))
            .unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "server brotli";
        "#;
        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let mut compression = HttpCompressionSettings::default();
        compression.brotli = true;
        compression.gzip_vary = true;
        compression.brotli_min_length = 1;
        compression.brotli_types = vec!["text/plain".to_string()];

        let http_server = ProcessChainHttpServer::builder()
            .id("test_brotli_compress")
            .version("HTTP/1.1".to_string())
            .hook_point(chains)
            .tunnel_manager(TunnelManager::new())
            .server_mgr(Arc::downgrade(&mock_server_mgr))
            .compression(compression)
            .build()
            .await
            .unwrap();

        let request = http::Request::builder()
            .method("GET")
            .uri("http://localhost/")
            .header("Accept-Encoding", "br")
            .body(Full::new(Bytes::new()).map_err(|e| match e {}).boxed())
            .unwrap();

        let resp = http_server
            .serve_request(request, StreamInfo::default())
            .await
            .unwrap();

        assert_eq!(
            resp.headers()
                .get("content-encoding")
                .and_then(|value| value.to_str().ok()),
            Some("br")
        );
        assert!(resp.headers().get("content-length").is_none());
        let vary = resp
            .headers()
            .get("vary")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");
        assert!(vary.to_ascii_lowercase().contains("accept-encoding"));

        let body = resp.collect().await.unwrap().to_bytes();
        let decoded = brotli_decode_bytes(body).await;
        assert_eq!(decoded, raw_body);
    }

    #[tokio::test]
    async fn test_gzip_http_version_gate() {
        let mock_server_mgr = Arc::new(ServerManager::new());
        let raw_body = Bytes::from_static(b"version-gate");
        let server = FixedResponseServer {
            id: "version".to_string(),
            body: raw_body.clone(),
            content_type: "text/plain",
            status: StatusCode::OK,
            content_encoding: None,
        };
        mock_server_mgr
            .add_server(Server::Http(Arc::new(server)))
            .unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "server version";
        "#;
        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let mut compression = HttpCompressionSettings::default();
        compression.gzip = true;
        compression.gzip_vary = true;
        compression.gzip_min_length = 1;
        compression.gzip_types = vec!["text/plain".to_string()];
        compression.gzip_http_version = Version::HTTP_2;

        let http_server = ProcessChainHttpServer::builder()
            .id("test_version_gate")
            .version("HTTP/1.1".to_string())
            .hook_point(chains)
            .tunnel_manager(TunnelManager::new())
            .server_mgr(Arc::downgrade(&mock_server_mgr))
            .compression(compression)
            .build()
            .await
            .unwrap();

        let request = http::Request::builder()
            .version(Version::HTTP_11)
            .method("GET")
            .uri("http://localhost/")
            .header("Accept-Encoding", "gzip")
            .body(Full::new(Bytes::new()).map_err(|e| match e {}).boxed())
            .unwrap();

        let resp = http_server
            .serve_request(request, StreamInfo::default())
            .await
            .unwrap();

        assert!(resp.headers().get("content-encoding").is_none());
        let vary = resp
            .headers()
            .get("vary")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");
        assert!(vary.to_ascii_lowercase().contains("accept-encoding"));
        let body = resp.collect().await.unwrap().to_bytes();
        assert_eq!(body, raw_body);
    }

    #[tokio::test]
    async fn test_gzip_disable_user_agent() {
        let mock_server_mgr = Arc::new(ServerManager::new());
        let raw_body = Bytes::from_static(b"ua-disable");
        let server = FixedResponseServer {
            id: "ua".to_string(),
            body: raw_body.clone(),
            content_type: "text/plain",
            status: StatusCode::OK,
            content_encoding: None,
        };
        mock_server_mgr
            .add_server(Server::Http(Arc::new(server)))
            .unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "server ua";
        "#;
        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let mut compression = HttpCompressionSettings::default();
        compression.gzip = true;
        compression.gzip_vary = true;
        compression.gzip_min_length = 1;
        compression.gzip_types = vec!["text/plain".to_string()];
        compression.gzip_disable = Some(Regex::new("TestAgent").unwrap());

        let http_server = ProcessChainHttpServer::builder()
            .id("test_gzip_disable")
            .version("HTTP/1.1".to_string())
            .hook_point(chains)
            .tunnel_manager(TunnelManager::new())
            .server_mgr(Arc::downgrade(&mock_server_mgr))
            .compression(compression)
            .build()
            .await
            .unwrap();

        let request = http::Request::builder()
            .method("GET")
            .uri("http://localhost/")
            .header("Accept-Encoding", "gzip")
            .header("User-Agent", "TestAgent/1.0")
            .body(Full::new(Bytes::new()).map_err(|e| match e {}).boxed())
            .unwrap();

        let resp = http_server
            .serve_request(request, StreamInfo::default())
            .await
            .unwrap();

        assert!(resp.headers().get("content-encoding").is_none());
        let vary = resp
            .headers()
            .get("vary")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");
        assert!(vary.to_ascii_lowercase().contains("accept-encoding"));
        let body = resp.collect().await.unwrap().to_bytes();
        assert_eq!(body, raw_body);
    }

    #[tokio::test]
    async fn test_create_server_without_hook_point() {
        let mock_server_mgr = Arc::new(ServerManager::new());

        let result = ProcessChainHttpServer::builder()
            .server_mgr(Arc::downgrade(&mock_server_mgr)).build().await;
        if let Err(e) = result {
            assert_eq!(e.code(), ServerErrorCode::InvalidConfig);
        }
    }

    #[tokio::test]
    async fn test_create_server_without_inner_services() {
        let builder = ProcessChainHttpServer::builder()
            .hook_point(vec![]);
        let result = ProcessChainHttpServer::create_server(builder).await;
        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(e.code(), ServerErrorCode::InvalidConfig);
        }
    }

    #[tokio::test]
    async fn test_create_server_with_invalid_version() {
        let mock_server_mgr = Arc::new(ServerManager::new());

        let result = ProcessChainHttpServer::builder()
            .version("HTTP/1.2".to_string())
            .hook_point(vec![])
            .server_mgr(Arc::downgrade(&mock_server_mgr)).build().await;

        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(e.code(), ServerErrorCode::InvalidConfig);
        }
    }

    #[tokio::test]
    async fn test_create_server_with_http11_version() {
        let mock_server_mgr = Arc::new(ServerManager::new());

        let result = ProcessChainHttpServer::builder()
            .id("1")
            .version("HTTP/1.1".to_string())
            .hook_point(vec![])
            .tunnel_manager(TunnelManager::new())
            .server_mgr(Arc::downgrade(&mock_server_mgr)).build().await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_create_server_with_http2_version() {
        let mock_server_mgr = Arc::new(ServerManager::new());

        let result = ProcessChainHttpServer::builder()
            .id("1")
            .version("HTTP/2".to_string())
            .hook_point(vec![])
            .tunnel_manager(TunnelManager::new())
            .server_mgr(Arc::downgrade(&mock_server_mgr)).build().await;
        assert!(result.is_ok());
    }


    #[tokio::test]
    async fn test_handle_http1_request_http1_server() {
        let mock_server_mgr = Arc::new(ServerManager::new());
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        reject;
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let result = ProcessChainHttpServer::builder()
            .id("1")
            .version("HTTP/1.1".to_string())
            .hook_point(chains)
            .tunnel_manager(TunnelManager::new())
            .server_mgr(Arc::downgrade(&mock_server_mgr)).build().await;

        assert!(result.is_ok());
        let http_server = Arc::new(result.unwrap());

        let (client, server) = tokio::io::duplex(128);

        tokio::spawn(async move {
            hyper_serve_http1(Box::new(server), http_server, StreamInfo::default()).await.unwrap();
        });

        let request = http::Request::builder()
            .method("GET")
            .uri("http://localhost/")
            .body(Full::new(Bytes::new()))
            .unwrap();

        let (mut sender, conn) = hyper::client::conn::http1::Builder::new().handshake(TokioIo::new(client)).await.unwrap();
        tokio::spawn(async move {
            conn.await.unwrap();
        });
        let resp = sender.send_request(request).await.unwrap();
        assert_eq!(resp.version(), Version::HTTP_11);
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_post_hook_point_adds_header() {
        let mock_server_mgr = Arc::new(ServerManager::new());
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        reject;
        "#;
        let post_chains = r#"
- id: post
  priority: 1
  blocks:
    - id: post
      block: |
        map-add RESP x-test "1";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();
        let post_chains: ProcessChainConfigs = serde_yaml_ng::from_str(post_chains).unwrap();

        let result = ProcessChainHttpServer::builder()
            .id("1")
            .version("HTTP/1.1".to_string())
            .hook_point(chains)
            .post_hook_point(post_chains)
            .tunnel_manager(TunnelManager::new())
            .server_mgr(Arc::downgrade(&mock_server_mgr))
            .build()
            .await;

        assert!(result.is_ok());
        let http_server = Arc::new(result.unwrap());

        let (client, server) = tokio::io::duplex(128);

        tokio::spawn(async move {
            hyper_serve_http1(Box::new(server), http_server, StreamInfo::default()).await.unwrap();
        });

        let request = http::Request::builder()
            .method("GET")
            .uri("http://localhost/")
            .body(Full::new(Bytes::new()))
            .unwrap();

        let (mut sender, conn) = hyper::client::conn::http1::Builder::new().handshake(TokioIo::new(client)).await.unwrap();
        tokio::spawn(async move {
            conn.await.unwrap();
        });
        let resp = sender.send_request(request).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(resp.headers().get("x-test").unwrap(), "1");
    }

    #[tokio::test]
    async fn test_handle_http1_request_http2_server() {
        let mock_server_mgr = Arc::new(ServerManager::new());
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        reject;
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let result = ProcessChainHttpServer::builder()
            .id("1")
            .version("HTTP/2".to_string())
            .hook_point(chains)
            .tunnel_manager(TunnelManager::new())
            .server_mgr(Arc::downgrade(&mock_server_mgr)).build().await;

        assert!(result.is_ok());
        let http_server = Arc::new(result.unwrap());

        let (client, server) = tokio::io::duplex(128);

        tokio::spawn(async move {
            hyper_serve_http(Box::new(server), http_server, StreamInfo::default()).await.unwrap();
        });

        let request = http::Request::builder()
            .method("GET")
            .uri("http://localhost/")
            .body(Full::new(Bytes::new()))
            .unwrap();

        let (mut sender, conn) = hyper::client::conn::http1::Builder::new().handshake(TokioIo::new(client)).await.unwrap();
        tokio::spawn(async move {
            conn.await.unwrap();
        });
        let resp = sender.send_request(request).await.unwrap();
        assert_eq!(resp.version(), Version::HTTP_11);
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_handle_http2_request_http2_server() {
        let mock_server_mgr = Arc::new(ServerManager::new());
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        reject;
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let result = ProcessChainHttpServer::builder()
            .id("1")
            .version("HTTP/2".to_string())
            .hook_point(chains)
            .tunnel_manager(TunnelManager::new())
            .server_mgr(Arc::downgrade(&mock_server_mgr)).build().await;

        assert!(result.is_ok());
        let http_server = Arc::new(result.unwrap());

        let (client, server) = tokio::io::duplex(128);

        tokio::spawn(async move {
            hyper_serve_http(Box::new(server), http_server, StreamInfo::default()).await.unwrap();
        });

        let request = http::Request::builder()
            .version(http::Version::HTTP_2)
            .method("GET")
            .uri("http://localhost/")
            .body(Full::new(Bytes::new()))
            .unwrap();

        let (mut sender, conn) = hyper::client::conn::http2::Builder::new(TokioExecutor::new()).handshake(TokioIo::new(client)).await.unwrap();
        tokio::spawn(async move {
            conn.await.unwrap();
        });
        let resp = sender.send_request(request).await.unwrap();
        assert_eq!(resp.version(), Version::HTTP_2);
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_handle_http2_request_http1_server() {
        let mock_server_mgr = Arc::new(ServerManager::new());
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        reject;
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let result = ProcessChainHttpServer::builder()
            .id("1")
            .version("HTTP/1.1".to_string())
            .hook_point(chains)
            .tunnel_manager(TunnelManager::new())
            .server_mgr(Arc::downgrade(&mock_server_mgr)).build().await;

        assert!(result.is_ok());
        let http_server = Arc::new(result.unwrap());

        let (client, server) = tokio::io::duplex(128);

        tokio::spawn(async move {
            let ret = hyper_serve_http(Box::new(server), http_server, StreamInfo::default()).await;
            assert!(ret.is_err());
        });

        let request = http::Request::builder()
            .version(http::Version::HTTP_2)
            .method("GET")
            .uri("http://localhost/")
            .body(Full::new(Bytes::new()))
            .unwrap();

        let (mut sender, conn) = hyper::client::conn::http2::Builder::new(TokioExecutor::new()).handshake(TokioIo::new(client)).await.unwrap();
        tokio::spawn(async move {
            let ret = conn.await;
            assert!(ret.is_err());
        });
        let resp = sender.send_request(request).await;
        assert!(resp.is_err());
    }

    #[tokio::test]
    async fn test_process_chain_http_server_forward() {
        // 鍒涘缓涓�涓洃鍚�8090绔彛鐨凥TTP鏈嶅姟鍣ㄦ潵澶勭悊璇锋眰
        tokio::spawn(async move {
            use http_body_util::BodyExt;
            use tokio::net::TcpListener;

            let listener = TcpListener::bind("127.0.0.1:18090").await.unwrap();

            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let service = hyper::service::service_fn(|req: http::Request<hyper::body::Incoming>| async move {
                    println!("{:?}", req.headers());
                    assert!(req.headers().get("X-Real-IP").is_some());
                    assert_eq!(req.headers().get("X-Real-IP").map(|v| v.to_str().unwrap()), Some("127.0.0.1"));
                    assert!(req.headers().get("X-Real-Port").is_some());
                    assert_eq!(req.headers().get("X-Real-Port").map(|v| v.to_str().unwrap()), Some("344"));
                    let _ = req.collect().await; // 娑堣垂璇锋眰浣�
                    Ok::<_, ServerError>(http::Response::builder()
                        .status(StatusCode::OK)
                        .body(Full::new(Bytes::from("forward success")).map_err(|e| match e {}).boxed())
                        .unwrap())
                });

                tokio::spawn(async move {
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });

        // 绛夊緟鏈嶅姟鍣ㄥ惎鍔�
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let mock_server_mgr = Arc::new(ServerManager::new());
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        map-add REQ X-Real-IP $REQ_remote_ip && map-add REQ X-Real-Port $REQ_remote_port && forward http://127.0.0.1:18090;
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let result = ProcessChainHttpServer::builder()
            .id("test_forward")
            .version("HTTP/1.1".to_string())
            .hook_point(chains)
            .server_mgr(Arc::downgrade(&mock_server_mgr))
            .tunnel_manager(TunnelManager::new())
            .build()
            .await;

        assert!(result.is_ok());
        let http_server = Arc::new(result.unwrap());

        let (client, server) = tokio::io::duplex(128);

        tokio::spawn(async move {
            hyper_serve_http(Box::new(server), http_server, StreamInfo {
                src_addr: Some("127.0.0.1:344".to_string()),
                conn_src_addr: Some("127.0.0.1:344".to_string()),
                real_src_addr: None,
                source_mac: None,
                source_hostname: None,
                source_online_secs: None,
            }).await.unwrap();
        });

        let request = http::Request::builder()
            .method("GET")
            .uri("/test")
            .body(Full::new(Bytes::new()).map_err(|e| match e {}).boxed())
            .unwrap();

        let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
            .handshake(TokioIo::new(client))
            .await
            .unwrap();

        tokio::spawn(async move {
            conn.await.unwrap();
        });

        let resp = sender.send_request(request).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = resp.collect().await.unwrap().to_bytes();
        assert_eq!(body, Bytes::from("forward success"));
    }

    #[tokio::test]
    async fn test_process_chain_http_server_forward_tcp() {
        tokio::spawn(async move {
            use http_body_util::BodyExt;
            use tokio::net::TcpListener;

            let listener = TcpListener::bind("127.0.0.1:18091").await.unwrap();

            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let service = hyper::service::service_fn(|req: http::Request<hyper::body::Incoming>| async move {
                    println!("{:?}", req.headers());
                    let _ = req.collect().await; // 娑堣垂璇锋眰浣�
                    Ok::<_, ServerError>(http::Response::builder()
                        .status(StatusCode::OK)
                        .body(Full::new(Bytes::from("forward success")).map_err(|e| match e {}).boxed())
                        .unwrap())
                });

                tokio::spawn(async move {
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });

        // 绛夊緟鏈嶅姟鍣ㄥ惎鍔�
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let mock_server_mgr = Arc::new(ServerManager::new());
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        forward tcp:///127.0.0.1:18091;
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let result = ProcessChainHttpServer::builder()
            .id("test_forward")
            .version("HTTP/1.1".to_string())
            .hook_point(chains)
            .server_mgr(Arc::downgrade(&mock_server_mgr))
            .tunnel_manager(TunnelManager::new())
            .build()
            .await;

        assert!(result.is_ok());
        let http_server = Arc::new(result.unwrap());

        let (client, server) = tokio::io::duplex(128);

        tokio::spawn(async move {
            hyper_serve_http(Box::new(server), http_server, StreamInfo::default()).await.unwrap();
        });

        let request = http::Request::builder()
            .method("GET")
            .uri("/test")
            .body(Full::new(Bytes::new()).map_err(|e| match e {}).boxed())
            .unwrap();

        let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
            .handshake(TokioIo::new(client))
            .await
            .unwrap();

        tokio::spawn(async move {
            conn.await.unwrap();
        });

        let resp = sender.send_request(request).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = resp.collect().await.unwrap().to_bytes();
        assert_eq!(body, Bytes::from("forward success"));
    }

    #[tokio::test]
    async fn test_process_chain_http_server_forward_err() {
        init_logging("test", false);
        let mock_server_mgr = Arc::new(ServerManager::new());
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "forward http://127.0.0.1:19999";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let result = ProcessChainHttpServer::builder()
            .id("test_forward_err")
            .version("HTTP/1.1".to_string())
            .hook_point(chains)
            .server_mgr(Arc::downgrade(&mock_server_mgr))
            .tunnel_manager(TunnelManager::new())
            .build()
            .await;

        assert!(result.is_ok());
        let http_server = Arc::new(result.unwrap());

        let (client, server) = tokio::io::duplex(128);

        tokio::spawn(async move {
            hyper_serve_http(Box::new(server), http_server, StreamInfo::default()).await.unwrap();
        });

        let request = http::Request::builder()
            .method("GET")
            .uri("/test")
            .body(Full::new(Bytes::new()).map_err(|e| match e {}).boxed())
            .unwrap();

        let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
            .handshake(TokioIo::new(client))
            .await
            .unwrap();

        tokio::spawn(async move {
            conn.await.unwrap();
        });

        let resp = sender.send_request(request).await.unwrap();
        // 褰揻orward澶辫触鏃讹紝搴旇杩斿洖500閿欒
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_process_chain_http_server_redirect_default_status() {
        let mock_server_mgr = Arc::new(ServerManager::new());
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "redirect https://example.com/path";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let result = ProcessChainHttpServer::builder()
            .id("test_redirect_default")
            .version("HTTP/1.1".to_string())
            .hook_point(chains)
            .server_mgr(Arc::downgrade(&mock_server_mgr))
            .tunnel_manager(TunnelManager::new())
            .build()
            .await;

        assert!(result.is_ok());
        let http_server = Arc::new(result.unwrap());

        let (client, server) = tokio::io::duplex(128);

        tokio::spawn(async move {
            hyper_serve_http(Box::new(server), http_server, StreamInfo::default()).await.unwrap();
        });

        let request = http::Request::builder()
            .method("GET")
            .uri("/test")
            .body(Full::new(Bytes::new()).map_err(|e| match e {}).boxed())
            .unwrap();

        let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
            .handshake(TokioIo::new(client))
            .await
            .unwrap();

        tokio::spawn(async move {
            conn.await.unwrap();
        });

        let resp = sender.send_request(request).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FOUND);
        assert_eq!(
            resp.headers().get(http::header::LOCATION).and_then(|v| v.to_str().ok()),
            Some("https://example.com/path")
        );
    }

    #[tokio::test]
    async fn test_process_chain_http_server_redirect_custom_status() {
        let mock_server_mgr = Arc::new(ServerManager::new());
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "redirect https://example.com/permanent 301";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let result = ProcessChainHttpServer::builder()
            .id("test_redirect_custom")
            .version("HTTP/1.1".to_string())
            .hook_point(chains)
            .server_mgr(Arc::downgrade(&mock_server_mgr))
            .tunnel_manager(TunnelManager::new())
            .build()
            .await;

        assert!(result.is_ok());
        let http_server = Arc::new(result.unwrap());

        let (client, server) = tokio::io::duplex(128);

        tokio::spawn(async move {
            hyper_serve_http(Box::new(server), http_server, StreamInfo::default()).await.unwrap();
        });

        let request = http::Request::builder()
            .method("GET")
            .uri("/test")
            .body(Full::new(Bytes::new()).map_err(|e| match e {}).boxed())
            .unwrap();

        let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
            .handshake(TokioIo::new(client))
            .await
            .unwrap();

        tokio::spawn(async move {
            conn.await.unwrap();
        });

        let resp = sender.send_request(request).await.unwrap();
        assert_eq!(resp.status(), StatusCode::MOVED_PERMANENTLY);
        assert_eq!(
            resp.headers().get(http::header::LOCATION).and_then(|v| v.to_str().ok()),
            Some("https://example.com/permanent")
        );
    }

    #[tokio::test]
    async fn test_process_chain_http_server_redirect_invalid_status() {
        let mock_server_mgr = Arc::new(ServerManager::new());
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "redirect https://example.com/invalid 200";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let result = ProcessChainHttpServer::builder()
            .id("test_redirect_invalid")
            .version("HTTP/1.1".to_string())
            .hook_point(chains)
            .server_mgr(Arc::downgrade(&mock_server_mgr))
            .tunnel_manager(TunnelManager::new())
            .build()
            .await;

        assert!(result.is_ok());
        let http_server = Arc::new(result.unwrap());

        let (client, server) = tokio::io::duplex(128);

        tokio::spawn(async move {
            hyper_serve_http(Box::new(server), http_server, StreamInfo::default()).await.unwrap();
        });

        let request = http::Request::builder()
            .method("GET")
            .uri("/test")
            .body(Full::new(Bytes::new()).map_err(|e| match e {}).boxed())
            .unwrap();

        let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
            .handshake(TokioIo::new(client))
            .await
            .unwrap();

        tokio::spawn(async move {
            conn.await.unwrap();
        });

        let resp = sender.send_request(request).await.unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_process_chain_http_server_error_status() {
        let mock_server_mgr = Arc::new(ServerManager::new());
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "error 404";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let result = ProcessChainHttpServer::builder()
            .id("test_error_status")
            .version("HTTP/1.1".to_string())
            .hook_point(chains)
            .server_mgr(Arc::downgrade(&mock_server_mgr))
            .tunnel_manager(TunnelManager::new())
            .build()
            .await;

        assert!(result.is_ok());
        let http_server = Arc::new(result.unwrap());

        let (client, server) = tokio::io::duplex(128);

        tokio::spawn(async move {
            hyper_serve_http(Box::new(server), http_server, StreamInfo::default()).await.unwrap();
        });

        let request = http::Request::builder()
            .method("GET")
            .uri("/test")
            .body(Full::new(Bytes::new()).map_err(|e| match e {}).boxed())
            .unwrap();

        let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
            .handshake(TokioIo::new(client))
            .await
            .unwrap();

        tokio::spawn(async move {
            conn.await.unwrap();
        });

        let resp = sender.send_request(request).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_process_chain_http_server_error_with_message() {
        let mock_server_mgr = Arc::new(ServerManager::new());
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "error 503 \"upstream unavailable\"";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let result = ProcessChainHttpServer::builder()
            .id("test_error_message")
            .version("HTTP/1.1".to_string())
            .hook_point(chains)
            .server_mgr(Arc::downgrade(&mock_server_mgr))
            .tunnel_manager(TunnelManager::new())
            .build()
            .await;

        assert!(result.is_ok());
        let http_server = Arc::new(result.unwrap());

        let (client, server) = tokio::io::duplex(128);

        tokio::spawn(async move {
            hyper_serve_http(Box::new(server), http_server, StreamInfo::default()).await.unwrap();
        });

        let request = http::Request::builder()
            .method("GET")
            .uri("/test")
            .body(Full::new(Bytes::new()).map_err(|e| match e {}).boxed())
            .unwrap();

        let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
            .handshake(TokioIo::new(client))
            .await
            .unwrap();

        tokio::spawn(async move {
            conn.await.unwrap();
        });

        let resp = sender.send_request(request).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = resp.collect().await.unwrap().to_bytes();
        assert_eq!(body, Bytes::from("upstream unavailable"));
    }

    #[tokio::test]
    async fn test_process_chain_http_server_error_invalid_status() {
        let mock_server_mgr = Arc::new(ServerManager::new());
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "error 200 should fail";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let result = ProcessChainHttpServer::builder()
            .id("test_error_invalid")
            .version("HTTP/1.1".to_string())
            .hook_point(chains)
            .server_mgr(Arc::downgrade(&mock_server_mgr))
            .tunnel_manager(TunnelManager::new())
            .build()
            .await;

        assert!(result.is_ok());
        let http_server = Arc::new(result.unwrap());

        let (client, server) = tokio::io::duplex(128);

        tokio::spawn(async move {
            hyper_serve_http(Box::new(server), http_server, StreamInfo::default()).await.unwrap();
        });

        let request = http::Request::builder()
            .method("GET")
            .uri("/test")
            .body(Full::new(Bytes::new()).map_err(|e| match e {}).boxed())
            .unwrap();

        let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
            .handshake(TokioIo::new(client))
            .await
            .unwrap();

        tokio::spawn(async move {
            conn.await.unwrap();
        });

        let resp = sender.send_request(request).await.unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_factory() {
        let config = ProcessChainHttpServerConfig {
            id: "test".to_string(),
            ty: "http".to_string(),
            version: None,
            h3_port: None,
            hook_point: ProcessChainConfigs::default(),
            post_hook_point: None,
            gzip: false,
            gzip_types: Vec::new(),
            gzip_min_length: default_gzip_min_length(),
            gzip_comp_level: default_gzip_comp_level(),
            gzip_http_version: default_gzip_http_version(),
            gzip_vary: false,
            gzip_disable: None,
            gzip_request: false,
            brotli: false,
            brotli_types: Vec::new(),
            brotli_min_length: default_brotli_min_length(),
            brotli_comp_level: default_brotli_comp_level(),
        };
        let server_mgr = Arc::new(ServerManager::new());
        let context = HttpServerContext::new(
            Arc::downgrade(&server_mgr),
            Arc::new(GlobalProcessChains::new()),
            Arc::new(JsExternalsManager::new()),
            TunnelManager::new(),
            GlobalCollectionManager::create(vec![]).await.unwrap(),
        );
        let factory = ProcessChainHttpServerFactory::new();
        let result = factory.create(Arc::new(config), Some(Arc::new(context))).await;
        assert!(result.is_ok());
    }
}
