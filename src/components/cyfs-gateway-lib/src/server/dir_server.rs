use std::path::{Path, PathBuf};
use http::{Version, StatusCode};
use http_body_util::combinators::{BoxBody};
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Bytes, Frame};
use serde::{Deserialize, Serialize};
use crate::{HttpServer, Server, ServerConfig, ServerError, ServerErrorCode, ServerFactory, ServerResult, StreamInfo};
use super::server_err;
use futures_util::TryStreamExt;
use tokio::io::AsyncReadExt;
use std::sync::Arc;

/// DirServer Builder for fluent configuration
pub struct DirServerBuilder {
    id: Option<String>,
    version: Option<String>,
    root_dir: Option<PathBuf>,
    index_file: Option<String>,
}

impl DirServerBuilder {
    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    pub fn version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }

    pub fn root_dir(mut self, root_dir: impl Into<PathBuf>) -> Self {
        self.root_dir = Some(root_dir.into());
        self
    }

    pub fn index_file(mut self, index_file: impl Into<String>) -> Self {
        self.index_file = Some(index_file.into());
        self
    }

    pub async fn build(self) -> ServerResult<DirServer> {
        DirServer::create_server(self).await
    }
}

/// DirServer - A simple HTTP server that serves files from a local directory
pub struct DirServer {
    id: String,
    version: http::Version,
    root_dir: PathBuf,
    index_file: String,
}

impl DirServer {
    pub fn builder() -> DirServerBuilder {
        DirServerBuilder {
            id: None,
            version: None,
            root_dir: None,
            index_file: None,
        }
    }

    async fn create_server(builder: DirServerBuilder) -> ServerResult<DirServer> {
        if builder.id.is_none() {
            return Err(server_err!(ServerErrorCode::InvalidConfig, "id is required"));
        }

        if builder.root_dir.is_none() {
            return Err(server_err!(ServerErrorCode::InvalidConfig, "root_dir is required"));
        }

        let root_dir = builder.root_dir.unwrap();
        if !root_dir.exists() {
            return Err(server_err!(ServerErrorCode::InvalidConfig, "root_dir does not exist: {:?}", root_dir));
        }

        if !root_dir.is_dir() {
            return Err(server_err!(ServerErrorCode::InvalidConfig, "root_dir is not a directory: {:?}", root_dir));
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

        let index_file = builder.index_file.unwrap_or_else(|| "index.html".to_string());

        Ok(DirServer {
            id: builder.id.unwrap(),
            version,
            root_dir,
            index_file,
        })
    }

    /// Parse Range header (e.g., "bytes=start-end")
    fn parse_range(&self, range: &str, file_size: u64) -> ServerResult<(u64, u64)> {
        let range = range.trim_start_matches("bytes=");
        let mut parts = range.split('-');

        let start = parts.next()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);

        let end = parts.next()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(file_size - 1);

        // Validate range
        if start >= file_size || end >= file_size || start > end {
            return Err(server_err!(ServerErrorCode::InvalidParam, "Invalid range"));
        }

        Ok((start, end))
    }

    /// Serve a file from the local directory
    async fn serve_file(
        &self,
        file_path: &Path,
        req: &http::Request<BoxBody<Bytes, ServerError>>,
    ) -> ServerResult<http::Response<BoxBody<Bytes, ServerError>>> {
        let file = tokio::fs::File::open(&file_path).await.map_err(|e| {
            warn!("Failed to open file: {:?}, error: {}", file_path, e);
            server_err!(ServerErrorCode::IOError, "Failed to open file: {}", e)
        })?;

        let file_meta = file.metadata().await.map_err(|e| {
            warn!("Failed to get file metadata: {:?}, error: {}", file_path, e);
            server_err!(ServerErrorCode::IOError, "Failed to get file metadata: {}", e)
        })?;

        let file_size = file_meta.len();
        let mime_type = mime_guess::from_path(&file_path).first_or_octet_stream();

        // Handle Range requests
        if let Some(range_header) = req.headers().get(hyper::header::RANGE) {
            if let Ok(range_str) = range_header.to_str() {
                if let Ok((start, end)) = self.parse_range(range_str, file_size) {
                    let mut file = tokio::io::BufReader::new(file);
                    // Seek to the start position
                    use tokio::io::AsyncSeekExt;
                    file.seek(std::io::SeekFrom::Start(start))
                        .await
                        .map_err(|e| {
                            server_err!(ServerErrorCode::IOError, "Failed to seek file: {}", e)
                        })?;

                    let content_length = end - start + 1;
                    // Take only the content_length bytes
                    let limited_reader = file.take(content_length);
                    let stream = tokio_util::io::ReaderStream::with_capacity(
                        limited_reader,
                        content_length as usize,
                    );
                    let stream_body = StreamBody::new(stream.map_ok(Frame::data));

                    return Ok(http::Response::builder()
                        .status(StatusCode::PARTIAL_CONTENT)
                        .header("Content-Type", mime_type.as_ref())
                        .header("Content-Length", content_length)
                        .header("Content-Range", format!("bytes {}-{}/{}", start, end, file_size))
                        .header("Accept-Ranges", "bytes")
                        .body(
                            BodyExt::map_err(stream_body, |e| {
                                ServerError::new(ServerErrorCode::StreamError, format!("Stream error: {}", e))
                            })
                            .boxed(),
                        )
                        .map_err(|e| {
                            server_err!(ServerErrorCode::IOError, "Failed to build response: {}", e)
                        })?);
                }
            }
        }

        // Non-Range request: return full file
        let stream = tokio_util::io::ReaderStream::with_capacity(file, file_size as usize);
        let stream_body = StreamBody::new(stream.map_ok(Frame::data));
        
        Ok(http::Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", mime_type.as_ref())
            .header("Content-Length", file_size)
            .header("Accept-Ranges", "bytes")
            .body(
                BodyExt::map_err(stream_body, |e| {
                    ServerError::new(ServerErrorCode::StreamError, format!("Stream error: {}", e))
                })
                .boxed(),
            )
            .map_err(|e| {
                server_err!(ServerErrorCode::IOError, "Failed to build response: {}", e)
            })?)
    }

    /// Normalize the request path and resolve to local file path
    fn resolve_path(&self, req_path: &str) -> PathBuf {
        // Remove leading slash
        let sub_path = req_path.trim_start_matches('/');
        
        // Resolve the full path
        let mut file_path = self.root_dir.join(sub_path);

        // If it's a directory, append index file
        if file_path.is_dir() {
            file_path = file_path.join(&self.index_file);
        }

        file_path
    }
}

#[async_trait::async_trait]
impl HttpServer for DirServer {
    async fn serve_request(
        &self,
        req: http::Request<BoxBody<Bytes, ServerError>>,
        _info: StreamInfo,
    ) -> ServerResult<http::Response<BoxBody<Bytes, ServerError>>> {
        let req_path = req.uri().path();
        let req_method = req.method();

        info!("DirServer[{}] {} {}", self.id, req_method, req_path);

        // Only support GET and HEAD methods
        if req_method != hyper::Method::GET && req_method != hyper::Method::HEAD {
            warn!("Method not allowed: {}", req_method);
            return Ok(http::Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(Full::new(Bytes::from("Method not allowed")).map_err(|e| match e {}).boxed())
                .unwrap());
        }

        let file_path = self.resolve_path(req_path);

        // Security check: prevent path traversal
        if !file_path.starts_with(&self.root_dir) {
            warn!("Path traversal attempt: {:?}", file_path);
            return Ok(http::Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Full::new(Bytes::from("Forbidden")).map_err(|e| match e {}).boxed())
                .unwrap());
        }

        // Check if file exists
        if !file_path.exists() || !file_path.is_file() {
            warn!("File not found: {:?}", file_path);
            return Ok(http::Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Full::new(Bytes::from("Not found")).map_err(|e| match e {}).boxed())
                .unwrap());
        }

        info!("Serving file: {:?}", file_path);

        // Serve the file
        self.serve_file(&file_path, &req).await
    }

    fn id(&self) -> String {
        self.id.clone()
    }

    fn http_version(&self) -> Version {
        self.version
    }

    fn http3_port(&self) -> Option<u16> {
        None
    }
}

/// Configuration for DirServer
#[derive(Serialize, Deserialize, Clone)]
pub struct DirServerConfig {
    pub id: String,
    #[serde(rename = "type")]
    pub ty: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub root_dir: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index_file: Option<String>,
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

    fn add_pre_hook_point_process_chain(&self, _process_chain: crate::ProcessChainConfig) -> Arc<dyn ServerConfig> {
        // DirServer doesn't support process chains
        Arc::new(self.clone())
    }

    fn remove_pre_hook_point_process_chain(&self, _process_chain_id: &str) -> Arc<dyn ServerConfig> {
        Arc::new(self.clone())
    }

    fn add_post_hook_point_process_chain(&self, _process_chain: crate::ProcessChainConfig) -> Arc<dyn ServerConfig> {
        Arc::new(self.clone())
    }

    fn remove_post_hook_point_process_chain(&self, _process_chain_id: &str) -> Arc<dyn ServerConfig> {
        Arc::new(self.clone())
    }
}

/// Factory for creating DirServer instances
pub struct DirServerFactory;

impl DirServerFactory {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl ServerFactory for DirServerFactory {
    async fn create(&self, config: Arc<dyn ServerConfig>) -> ServerResult<Server> {
        let config = config
            .as_any()
            .downcast_ref::<DirServerConfig>()
            .ok_or(server_err!(ServerErrorCode::InvalidConfig, "invalid config"))?;

        let mut builder = DirServer::builder()
            .id(config.id.clone())
            .root_dir(PathBuf::from(config.root_dir.clone()));

        if let Some(version) = &config.version {
            builder = builder.version(version.clone());
        }

        if let Some(index_file) = &config.index_file {
            builder = builder.index_file(index_file.clone());
        }

        let server = builder.build().await?;
        Ok(Server::Http(Arc::new(server)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use http_body_util::Full;
    use crate::{hyper_serve_http1, StreamInfo};
    use hyper_util::rt::TokioIo;

    #[tokio::test]
    async fn test_dir_server_builder_creation() {
        let builder = DirServer::builder();
        assert!(std::mem::size_of_val(&builder) > 0);
    }

    #[tokio::test]
    async fn test_create_server_without_id() {
        let result = DirServer::builder()
            .root_dir(PathBuf::from("/tmp"))
            .build()
            .await;
        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(e.code(), ServerErrorCode::InvalidConfig);
        }
    }

    #[tokio::test]
    async fn test_create_server_without_root_dir() {
        let result = DirServer::builder().id("test").build().await;
        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(e.code(), ServerErrorCode::InvalidConfig);
        }
    }

    #[tokio::test]
    async fn test_create_server_with_non_existent_dir() {
        let result = DirServer::builder()
            .id("test")
            .root_dir(PathBuf::from("/non/existent/dir"))
            .build()
            .await;
        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(e.code(), ServerErrorCode::InvalidConfig);
        }
    }

    #[tokio::test]
    async fn test_create_server_with_valid_config() {
        // Create a temporary directory
        let temp_dir = tempfile::tempdir().unwrap();
        
        let result = DirServer::builder()
            .id("test")
            .root_dir(temp_dir.path().to_path_buf())
            .build()
            .await;
        
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_serve_existing_file() {
        // Create a temporary directory
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        
        // Write test content
        tokio::fs::write(&file_path, b"Hello, World!").await.unwrap();
        
        let server = Arc::new(
            DirServer::builder()
                .id("test")
                .root_dir(temp_dir.path().to_path_buf())
                .build()
                .await
                .unwrap(),
        );

        let (client, server_stream) = tokio::io::duplex(1024);

        tokio::spawn(async move {
            hyper_serve_http1(Box::new(server_stream), server, StreamInfo::default())
                .await
                .unwrap();
        });

        let request = http::Request::builder()
            .method("GET")
            .uri("http://localhost/test.txt")
            .body(Full::new(Bytes::new()))
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
        
        let body_bytes = resp.collect().await.unwrap().to_bytes();
        assert_eq!(body_bytes.as_ref(), b"Hello, World!");
    }

    #[tokio::test]
    async fn test_serve_non_existent_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        
        let server = Arc::new(
            DirServer::builder()
                .id("test")
                .root_dir(temp_dir.path().to_path_buf())
                .build()
                .await
                .unwrap(),
        );

        let (client, server_stream) = tokio::io::duplex(1024);

        tokio::spawn(async move {
            hyper_serve_http1(Box::new(server_stream), server, StreamInfo::default())
                .await
                .unwrap();
        });

        let request = http::Request::builder()
            .method("GET")
            .uri("http://localhost/non_existent.txt")
            .body(Full::new(Bytes::new()))
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
    async fn test_factory() {
        let temp_dir = tempfile::tempdir().unwrap();
        
        let config = DirServerConfig {
            id: "test".to_string(),
            ty: "dir".to_string(),
            version: None,
            root_dir: temp_dir.path().to_string_lossy().to_string(),
            index_file: None,
        };
        
        let factory = DirServerFactory::new();
        let result = factory.create(Arc::new(config)).await;
        assert!(result.is_ok());
    }
}

