use std::path::{Component, Path, PathBuf};
use http::{Version, StatusCode};
use http_body_util::combinators::{BoxBody};
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Bytes, Frame};
use serde::{Deserialize, Serialize};
use crate::{HttpServer, Server, ServerConfig, ServerContextRef, ServerError, ServerErrorCode, ServerFactory, ServerResult, StreamInfo};
use super::server_err;
use futures_util::TryStreamExt;
use tokio::io::AsyncReadExt;
use std::sync::Arc;

/// DirServer Builder for fluent configuration
pub struct DirServerBuilder {
    id: Option<String>,
    version: Option<String>,
    root_path: Option<PathBuf>,
    index_file: Option<String>,
    fallback_file: Option<String>,
    base_url: Option<String>,
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

    pub fn root_path(mut self, root_path: impl Into<PathBuf>) -> Self {
        self.root_path = Some(root_path.into());
        self
    }

    pub fn index_file(mut self, index_file: impl Into<String>) -> Self {
        self.index_file = Some(index_file.into());
        self
    }

    pub fn fallback_file(mut self, fallback_file: impl Into<String>) -> Self {
        self.fallback_file = Some(fallback_file.into());
        self
    }

    pub fn base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = Some(base_url.into());
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
    fallback_file: Option<String>,
    base_url: String,
}

impl DirServer {
    pub fn builder() -> DirServerBuilder {
        DirServerBuilder {
            id: None,
            version: None,
            root_path: None,
            index_file: None,
            fallback_file: None,
            base_url: None,
        }
    }

    async fn create_server(builder: DirServerBuilder) -> ServerResult<DirServer> {
        if builder.id.is_none() {
            return Err(server_err!(ServerErrorCode::InvalidConfig, "id is required"));
        }

        if builder.root_path.is_none() {
            return Err(server_err!(ServerErrorCode::InvalidConfig, "root_path is required"));
        }

        let root_path = builder.root_path.unwrap();
        if !root_path.exists() {
            return Err(server_err!(ServerErrorCode::InvalidConfig, "root_path does not exist: {:?}", root_path));
        }

        if !root_path.is_dir() {
            return Err(server_err!(ServerErrorCode::InvalidConfig, "root_path is not a directory: {:?}", root_path));
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
        let fallback_file = if let Some(fallback_file) = builder.fallback_file {
            let fallback_path = Path::new(&fallback_file);
            if fallback_path.is_absolute() {
                return Err(server_err!(
                    ServerErrorCode::InvalidConfig,
                    "fallback_file must be a relative path"
                ));
            }
            if fallback_path
                .components()
                .any(|c| matches!(c, Component::ParentDir))
            {
                return Err(server_err!(
                    ServerErrorCode::InvalidConfig,
                    "fallback_file must not contain '..'"
                ));
            }
            Some(fallback_file)
        } else {
            None
        };
        let new_root_dir = root_path.canonicalize().map_err(|e| {
            server_err!(ServerErrorCode::IOError, "Failed to canonicalize path: {}", e)
        })?;
        info!("after normalize,root_dir is : {:?}", new_root_dir);
        Ok(DirServer {
            id: builder.id.unwrap(),
            version,
            root_dir: new_root_dir,
            index_file,
            fallback_file,
            base_url: builder.base_url.unwrap_or_else(|| "/".to_string()),
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
        let sub_path = req_path.trim_start_matches(&self.base_url);
        
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
            if let Some(fallback_file) = &self.fallback_file {
                let fallback_path = self.root_dir.join(fallback_file);
                match fallback_path.canonicalize() {
                    Ok(fallback_path) => {
                        if fallback_path.starts_with(&self.root_dir)
                            && fallback_path.exists()
                            && fallback_path.is_file()
                        {
                            info!("Fallback to file: {:?}", fallback_path);
                            return self.serve_file(&fallback_path, &req).await;
                        }
                        warn!("Fallback file not found: {:?}", fallback_path);
                    }
                    Err(e) => {
                        warn!("Failed to resolve fallback file: {:?}, error: {}", fallback_path, e);
                    }
                }
            }
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
    pub root_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index_file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallback_file: Option<String>,
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

/// Factory for creating DirServer instances
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
            .ok_or(server_err!(ServerErrorCode::InvalidConfig, "invalid dir server config"))?;

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

        let server = builder.build().await?;
        Ok(vec![Server::Http(Arc::new(server))])
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
            .root_path(PathBuf::from("/tmp"))
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
            .root_path(PathBuf::from("/non/existent/dir"))
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
            .root_path(temp_dir.path().to_path_buf())
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
                .root_path(temp_dir.path().to_path_buf())
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
                .root_path(temp_dir.path().to_path_buf())
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
            root_path: temp_dir.path().to_string_lossy().to_string(),
            index_file: None,
            fallback_file: None,
        };
        
        let factory = DirServerFactory::new();
        let result = factory.create(Arc::new(config), None).await;
        assert!(result.is_ok());
    }
}
