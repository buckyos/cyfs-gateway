use super::server_err;
use crate::{
    HttpServer, Server, ServerConfig, ServerContextRef, ServerError, ServerErrorCode,
    ServerFactory, ServerResult, StreamInfo,
};
use chrono::{DateTime, Local};
use futures_util::TryStreamExt;
use http::{StatusCode, Version};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Bytes, Frame};
use hyper::header::{ETAG, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED, RANGE};
use mini_moka::sync::Cache;
use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use serde::de::{self, Visitor};
use serde::{Deserialize, Serialize};
#[cfg(target_os = "linux")]
use std::ffi::CString;
use std::fmt;
use std::io::ErrorKind;
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncSeekExt};

const PATH_SEGMENT_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'`')
    .add(b'{')
    .add(b'}')
    .add(b'/');
const SMALL_FILE_INLINE_LIMIT: u64 = 64 * 1024;
const MIN_FILE_STREAM_BUFFER_SIZE: usize = 16 * 1024;
const MAX_FILE_STREAM_BUFFER_SIZE: usize = 512 * 1024;

/// DirServer Builder for fluent configuration
pub struct DirServerBuilder {
    id: Option<String>,
    version: Option<String>,
    root_path: Option<PathBuf>,
    index_file: Option<String>,
    fallback_file: Option<String>,
    base_url: Option<String>,
    autoindex: bool,
    etag: Option<bool>,
    if_modified_since: Option<String>,
    open_file_cache: Option<OpenFileCacheSettings>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IfModifiedSinceMode {
    Off,
    Exact,
    Before,
}

#[derive(Clone, Debug)]
struct OpenFileCacheSettings {
    max: u64,
    inactive: Duration,
    valid: Duration,
    min_uses: u64,
    errors: bool,
}

impl Default for OpenFileCacheSettings {
    fn default() -> Self {
        Self {
            max: 10_000,
            inactive: Duration::from_secs(60),
            valid: Duration::from_secs(60),
            min_uses: 2,
            errors: true,
        }
    }
}

impl OpenFileCacheSettings {
    fn from_config(
        config: DirServerOpenFileCacheConfig,
        valid: Option<DirServerCacheDuration>,
        min_uses: Option<u64>,
        errors: Option<bool>,
    ) -> ServerResult<Option<Self>> {
        if config.off {
            return Ok(None);
        }

        let defaults = Self::default();
        let settings = Self {
            max: config.max.unwrap_or(defaults.max),
            inactive: config
                .inactive
                .map(|v| v.into_duration())
                .unwrap_or(defaults.inactive),
            valid: valid.map(|v| v.into_duration()).unwrap_or(defaults.valid),
            min_uses: min_uses.unwrap_or(defaults.min_uses),
            errors: errors.unwrap_or(defaults.errors),
        };

        if settings.max == 0 {
            return Err(server_err!(
                ServerErrorCode::InvalidConfig,
                "open_file_cache max must be greater than 0"
            ));
        }

        if settings.min_uses == 0 {
            return Err(server_err!(
                ServerErrorCode::InvalidConfig,
                "open_file_cache_min_uses must be greater than 0"
            ));
        }

        Ok(Some(settings))
    }
}

#[derive(Clone, Debug)]
struct OpenFileCache {
    settings: OpenFileCacheSettings,
    stat_cache: Cache<PathBuf, CachedPathStat>,
    admission_counts: Cache<PathBuf, u64>,
}

impl OpenFileCache {
    fn new(settings: OpenFileCacheSettings) -> Self {
        let admission_capacity = settings.max.saturating_mul(2).max(1);
        Self {
            stat_cache: Cache::builder()
                .max_capacity(settings.max)
                .time_to_live(settings.valid)
                .time_to_idle(settings.inactive)
                .build(),
            admission_counts: Cache::builder()
                .max_capacity(admission_capacity)
                .time_to_idle(settings.inactive)
                .build(),
            settings,
        }
    }

    fn stat_path(&self, path: &Path) -> DirPathStat {
        let key = path.to_path_buf();
        if let Some(cached) = self.stat_cache.get(&key) {
            return cached.into_stat();
        }

        let stat = DirPathStat::from_path(path);
        let uses = self.admission_counts.get(&key).unwrap_or(0) + 1;
        self.admission_counts.insert(key.clone(), uses);

        if uses >= self.settings.min_uses && (stat.exists() || self.settings.errors) {
            self.stat_cache.insert(key, CachedPathStat::from(&stat));
        }

        stat
    }
}

#[derive(Clone, Debug)]
struct CachedPathStat {
    result: Result<CachedPathMetadata, CachedPathError>,
}

impl CachedPathStat {
    fn into_stat(self) -> DirPathStat {
        match self.result {
            Ok(metadata) => DirPathStat::Found(metadata),
            Err(e) => DirPathStat::Error(e.into_io_error()),
        }
    }
}

impl From<&DirPathStat> for CachedPathStat {
    fn from(stat: &DirPathStat) -> Self {
        let result = match stat {
            DirPathStat::Found(metadata) => Ok(metadata.clone()),
            DirPathStat::Error(e) => Err(CachedPathError {
                kind: e.kind(),
                message: e.to_string(),
            }),
        };
        Self { result }
    }
}

#[derive(Clone, Debug)]
struct CachedPathMetadata {
    metadata: std::fs::Metadata,
}

#[derive(Clone, Debug)]
struct CachedPathError {
    kind: ErrorKind,
    message: String,
}

impl CachedPathError {
    fn into_io_error(self) -> std::io::Error {
        std::io::Error::new(self.kind, self.message)
    }
}

#[derive(Debug)]
enum DirPathStat {
    Found(CachedPathMetadata),
    Error(std::io::Error),
}

struct OpenedDirFile {
    file: tokio::fs::File,
    metadata: std::fs::Metadata,
    canonical_path: Option<PathBuf>,
}

impl DirPathStat {
    fn from_path(path: &Path) -> Self {
        match std::fs::metadata(path) {
            Ok(metadata) => Self::Found(CachedPathMetadata { metadata }),
            Err(e) => Self::Error(e),
        }
    }

    fn exists(&self) -> bool {
        matches!(self, Self::Found(_))
    }

    fn is_dir(&self) -> bool {
        matches!(self, Self::Found(metadata) if metadata.metadata.is_dir())
    }

    fn is_file(&self) -> bool {
        matches!(self, Self::Found(metadata) if metadata.metadata.is_file())
    }

    fn metadata(&self) -> Option<std::fs::Metadata> {
        match self {
            Self::Found(metadata) => Some(metadata.metadata.clone()),
            Self::Error(_) => None,
        }
    }

    #[cfg(test)]
    fn is_not_found(&self) -> bool {
        matches!(self, Self::Error(e) if e.kind() == ErrorKind::NotFound)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub enum DirServerCacheDuration {
    Seconds(u64),
}

impl DirServerCacheDuration {
    fn into_duration(self) -> Duration {
        match self {
            Self::Seconds(seconds) => Duration::from_secs(seconds),
        }
    }
}

impl<'de> Deserialize<'de> for DirServerCacheDuration {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct DurationVisitor;

        impl<'de> Visitor<'de> for DurationVisitor {
            type Value = DirServerCacheDuration;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a duration in seconds or a string ending with s/m/h")
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(DirServerCacheDuration::Seconds(value))
            }

            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if value < 0 {
                    return Err(E::custom("duration must be non-negative"));
                }
                Ok(DirServerCacheDuration::Seconds(value as u64))
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                parse_cache_duration(value)
                    .map(DirServerCacheDuration::Seconds)
                    .map_err(E::custom)
            }
        }

        deserializer.deserialize_any(DurationVisitor)
    }
}

fn parse_cache_duration(value: &str) -> Result<u64, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("duration must not be empty".to_string());
    }

    let (number, multiplier) = if let Some(number) = value.strip_suffix("ms") {
        let millis = number
            .trim()
            .parse::<u64>()
            .map_err(|_| format!("invalid duration: {}", value))?;
        return Ok(millis.div_ceil(1000));
    } else if let Some(number) = value.strip_suffix('s') {
        (number, 1)
    } else if let Some(number) = value.strip_suffix('m') {
        (number, 60)
    } else if let Some(number) = value.strip_suffix('h') {
        (number, 60 * 60)
    } else {
        (value, 1)
    };

    let number = number
        .trim()
        .parse::<u64>()
        .map_err(|_| format!("invalid duration: {}", value))?;
    number
        .checked_mul(multiplier)
        .ok_or_else(|| format!("duration is too large: {}", value))
}

impl IfModifiedSinceMode {
    fn parse(mode: &str) -> Option<Self> {
        match mode {
            "off" => Some(Self::Off),
            "exact" => Some(Self::Exact),
            "before" => Some(Self::Before),
            _ => None,
        }
    }
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

    pub fn autoindex(mut self, autoindex: bool) -> Self {
        self.autoindex = autoindex;
        self
    }

    pub fn etag(mut self, etag: bool) -> Self {
        self.etag = Some(etag);
        self
    }

    pub fn if_modified_since(mut self, mode: impl Into<String>) -> Self {
        self.if_modified_since = Some(mode.into());
        self
    }

    pub fn open_file_cache(
        mut self,
        config: DirServerOpenFileCacheConfig,
        valid: Option<DirServerCacheDuration>,
        min_uses: Option<u64>,
        errors: Option<bool>,
    ) -> ServerResult<Self> {
        self.open_file_cache = OpenFileCacheSettings::from_config(config, valid, min_uses, errors)?;
        Ok(self)
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
    #[cfg(target_os = "linux")]
    root_dir_file: Arc<std::fs::File>,
    index_file: String,
    fallback_file: Option<String>,
    base_url: String,
    autoindex: bool,
    etag: bool,
    if_modified_since: IfModifiedSinceMode,
    open_file_cache: Option<OpenFileCache>,
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
            autoindex: false,
            etag: None,
            if_modified_since: None,
            open_file_cache: None,
        }
    }

    async fn create_server(builder: DirServerBuilder) -> ServerResult<DirServer> {
        if builder.id.is_none() {
            return Err(server_err!(
                ServerErrorCode::InvalidConfig,
                "id is required"
            ));
        }

        if builder.root_path.is_none() {
            return Err(server_err!(
                ServerErrorCode::InvalidConfig,
                "root_path is required"
            ));
        }

        let root_path = builder.root_path.unwrap();
        if !root_path.exists() {
            return Err(server_err!(
                ServerErrorCode::InvalidConfig,
                "root_path does not exist: {:?}",
                root_path
            ));
        }

        if !root_path.is_dir() {
            return Err(server_err!(
                ServerErrorCode::InvalidConfig,
                "root_path is not a directory: {:?}",
                root_path
            ));
        }

        let version: http::Version = match builder.version {
            Some(ref version) => match version.as_str() {
                "HTTP/0.9" => http::Version::HTTP_09,
                "HTTP/1.0" => http::Version::HTTP_10,
                "HTTP/1.1" => http::Version::HTTP_11,
                "HTTP/2" => http::Version::HTTP_2,
                "HTTP/3" => http::Version::HTTP_3,
                _ => {
                    return Err(server_err!(
                        ServerErrorCode::InvalidConfig,
                        "invalid http version"
                    ));
                }
            },
            None => http::Version::HTTP_11,
        };

        let index_file = builder
            .index_file
            .unwrap_or_else(|| "index.html".to_string());
        let etag = builder.etag.unwrap_or(true);
        let if_modified_since = match builder.if_modified_since {
            Some(mode) => IfModifiedSinceMode::parse(mode.as_str()).ok_or_else(|| {
                server_err!(
                    ServerErrorCode::InvalidConfig,
                    "invalid if_modified_since: {}, expected one of off|exact|before",
                    mode
                )
            })?,
            None => IfModifiedSinceMode::Exact,
        };
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
            server_err!(
                ServerErrorCode::IOError,
                "Failed to canonicalize path: {}",
                e
            )
        })?;
        #[cfg(target_os = "linux")]
        let root_dir_file = Arc::new(std::fs::File::open(&new_root_dir).map_err(|e| {
            server_err!(
                ServerErrorCode::IOError,
                "Failed to open root directory: {}",
                e
            )
        })?);
        debug!("after normalize,root_dir is : {:?}", new_root_dir);
        Ok(DirServer {
            id: builder.id.unwrap(),
            version,
            root_dir: new_root_dir,
            #[cfg(target_os = "linux")]
            root_dir_file,
            index_file,
            fallback_file,
            base_url: builder.base_url.unwrap_or_else(|| "/".to_string()),
            autoindex: builder.autoindex,
            etag,
            if_modified_since,
            open_file_cache: builder.open_file_cache.map(OpenFileCache::new),
        })
    }

    fn format_http_date(st: SystemTime) -> String {
        httpdate::fmt_http_date(st)
    }

    fn normalize_etag_tag(token: &str) -> &str {
        let token = token.trim();
        if let Some(stripped) = token.strip_prefix("W/") {
            stripped.trim()
        } else {
            token
        }
    }

    fn etag_matches_if_none_match(current_etag: Option<&str>, if_none_match: &str) -> bool {
        let current_etag = match current_etag {
            Some(etag) => etag,
            None => return false,
        };

        let target = Self::normalize_etag_tag(current_etag);
        if_none_match
            .split(',')
            .map(str::trim)
            .any(|item| item == "*" || Self::normalize_etag_tag(item) == target)
    }

    fn compare_if_modified_since(
        &self,
        last_modified: SystemTime,
        if_modified_since: &str,
    ) -> bool {
        let since = match httpdate::parse_http_date(if_modified_since) {
            Ok(t) => t,
            Err(_) => return false,
        };

        let mtime_secs = last_modified
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        let since_secs = since
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        match self.if_modified_since {
            IfModifiedSinceMode::Off => false,
            IfModifiedSinceMode::Exact => mtime_secs == since_secs,
            IfModifiedSinceMode::Before => mtime_secs <= since_secs,
        }
    }

    fn request_not_modified(
        &self,
        req: &http::Request<BoxBody<Bytes, ServerError>>,
        current_etag: Option<&str>,
        last_modified: Option<SystemTime>,
    ) -> bool {
        let if_none_match = req
            .headers()
            .get(IF_NONE_MATCH)
            .and_then(|v| v.to_str().ok());

        if let Some(if_none_match) = if_none_match {
            return Self::etag_matches_if_none_match(current_etag, if_none_match);
        }

        let if_modified_since = req
            .headers()
            .get(IF_MODIFIED_SINCE)
            .and_then(|v| v.to_str().ok());

        if let (Some(last_modified), Some(if_modified_since)) = (last_modified, if_modified_since) {
            return self.compare_if_modified_since(last_modified, if_modified_since);
        }

        false
    }

    fn build_etag(file_meta: &std::fs::Metadata) -> Option<String> {
        let modified = file_meta.modified().ok()?;
        let dur = modified.duration_since(UNIX_EPOCH).ok()?;
        Some(format!(
            "\"{:x}-{:x}-{:x}\"",
            file_meta.len(),
            dur.as_secs(),
            dur.subsec_nanos()
        ))
    }

    fn stat_path(&self, path: &Path) -> DirPathStat {
        match &self.open_file_cache {
            Some(cache) => cache.stat_path(path),
            None => DirPathStat::from_path(path),
        }
    }

    async fn open_file_for_read(&self, file_path: &Path) -> std::io::Result<OpenedDirFile> {
        self.open_path_in_root(file_path).await
    }

    async fn open_path_in_root(&self, file_path: &Path) -> std::io::Result<OpenedDirFile> {
        #[cfg(target_os = "linux")]
        if let Ok(opened) = self.open_path_in_root_openat2(file_path) {
            return Ok(opened);
        }

        let canonical_path = file_path.canonicalize()?;
        if !canonical_path.starts_with(&self.root_dir) {
            return Err(std::io::Error::new(
                ErrorKind::PermissionDenied,
                "path out of root directory",
            ));
        }

        let file = tokio::fs::File::open(&canonical_path).await?;
        let metadata = file.metadata().await?;
        Ok(OpenedDirFile {
            file,
            metadata,
            canonical_path: Some(canonical_path),
        })
    }

    #[cfg(target_os = "linux")]
    fn open_path_in_root_openat2(&self, file_path: &Path) -> std::io::Result<OpenedDirFile> {
        use std::os::unix::ffi::OsStrExt;

        let relative_path = file_path.strip_prefix(&self.root_dir).map_err(|_| {
            std::io::Error::new(ErrorKind::PermissionDenied, "path out of root directory")
        })?;

        if relative_path.as_os_str().is_empty() {
            return Err(std::io::Error::new(
                ErrorKind::InvalidInput,
                "root directory cannot be opened as a file",
            ));
        }

        let path = CString::new(relative_path.as_os_str().as_bytes()).map_err(|_| {
            std::io::Error::new(ErrorKind::InvalidInput, "path contains interior nul byte")
        })?;
        let mut how: libc::open_how = unsafe { std::mem::zeroed() };
        how.flags = (libc::O_RDONLY | libc::O_CLOEXEC) as u64;
        how.resolve = (libc::RESOLVE_BENEATH | libc::RESOLVE_NO_MAGICLINKS) as u64;

        let fd = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                self.root_dir_file.as_raw_fd(),
                path.as_ptr(),
                &how,
                std::mem::size_of::<libc::open_how>(),
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }

        let file = unsafe { std::fs::File::from_raw_fd(fd as i32) };
        let metadata = file.metadata()?;
        let canonical_path = if metadata.is_file() {
            None
        } else {
            std::fs::read_link(format!("/proc/self/fd/{}", fd))
                .ok()
                .filter(|path| path.starts_with(&self.root_dir))
        };
        Ok(OpenedDirFile {
            file: tokio::fs::File::from_std(file),
            metadata,
            canonical_path,
        })
    }

    fn file_stream_buffer_size(content_length: u64) -> usize {
        content_length.clamp(
            MIN_FILE_STREAM_BUFFER_SIZE as u64,
            MAX_FILE_STREAM_BUFFER_SIZE as u64,
        ) as usize
    }

    fn empty_body() -> BoxBody<Bytes, ServerError> {
        Full::new(Bytes::new()).map_err(|e| match e {}).boxed()
    }

    async fn full_or_stream_body(
        mut file: tokio::fs::File,
        content_length: u64,
    ) -> ServerResult<BoxBody<Bytes, ServerError>> {
        if content_length <= SMALL_FILE_INLINE_LIMIT {
            let mut body = Vec::with_capacity(content_length as usize);
            file.read_to_end(&mut body)
                .await
                .map_err(|e| server_err!(ServerErrorCode::IOError, "Failed to read file: {}", e))?;
            return Ok(Full::new(Bytes::from(body)).map_err(|e| match e {}).boxed());
        }

        let stream = tokio_util::io::ReaderStream::with_capacity(
            file,
            Self::file_stream_buffer_size(content_length),
        );
        let stream_body = StreamBody::new(stream.map_ok(Frame::data));
        Ok(BodyExt::map_err(stream_body, |e| {
            ServerError::new(ServerErrorCode::StreamError, format!("Stream error: {}", e))
        })
        .boxed())
    }

    async fn range_body(
        mut file: tokio::fs::File,
        start: u64,
        content_length: u64,
    ) -> ServerResult<BoxBody<Bytes, ServerError>> {
        file.seek(std::io::SeekFrom::Start(start))
            .await
            .map_err(|e| server_err!(ServerErrorCode::IOError, "Failed to seek file: {}", e))?;

        if content_length <= SMALL_FILE_INLINE_LIMIT {
            let mut limited_reader = file.take(content_length);
            let mut body = Vec::with_capacity(content_length as usize);
            limited_reader.read_to_end(&mut body).await.map_err(|e| {
                server_err!(ServerErrorCode::IOError, "Failed to read file range: {}", e)
            })?;
            return Ok(Full::new(Bytes::from(body)).map_err(|e| match e {}).boxed());
        }

        let limited_reader = file.take(content_length);
        let stream = tokio_util::io::ReaderStream::with_capacity(
            limited_reader,
            Self::file_stream_buffer_size(content_length),
        );
        let stream_body = StreamBody::new(stream.map_ok(Frame::data));
        Ok(BodyExt::map_err(stream_body, |e| {
            ServerError::new(ServerErrorCode::StreamError, format!("Stream error: {}", e))
        })
        .boxed())
    }

    /// Parse Range header (e.g., "bytes=start-end")
    fn parse_range(&self, range: &str, file_size: u64) -> ServerResult<(u64, u64)> {
        let range = range.trim_start_matches("bytes=");
        let mut parts = range.split('-');

        let start = parts
            .next()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);

        let end = parts
            .next()
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
        let opened_file = self.open_file_for_read(file_path).await.map_err(|e| {
            warn!("Failed to open file: {:?}, error: {}", file_path, e);
            server_err!(ServerErrorCode::IOError, "Failed to open file: {}", e)
        })?;
        self.serve_opened_file(file_path, opened_file, req).await
    }

    async fn serve_opened_file(
        &self,
        file_path: &Path,
        opened_file: OpenedDirFile,
        req: &http::Request<BoxBody<Bytes, ServerError>>,
    ) -> ServerResult<http::Response<BoxBody<Bytes, ServerError>>> {
        let file = opened_file.file;
        let file_meta = opened_file.metadata;
        let file_size = file_meta.len();
        let mime_type = mime_guess::from_path(&file_path).first_or_octet_stream();
        let last_modified = file_meta.modified().ok();
        let etag = if self.etag {
            Self::build_etag(&file_meta)
        } else {
            None
        };

        if self.request_not_modified(&req, etag.as_deref(), last_modified) {
            let mut response_builder = http::Response::builder().status(StatusCode::NOT_MODIFIED);
            if let Some(etag) = etag.as_ref() {
                response_builder = response_builder.header(ETAG, etag.as_str());
            }
            if let Some(last_modified) = last_modified {
                let formatted = Self::format_http_date(last_modified);
                response_builder = response_builder.header(LAST_MODIFIED, formatted);
            }

            return response_builder.body(Self::empty_body()).map_err(|e| {
                server_err!(ServerErrorCode::IOError, "Failed to build response: {}", e)
            });
        }

        // Handle Range requests
        if let Some(range_header) = req.headers().get(RANGE) {
            if let Ok(range_str) = range_header.to_str() {
                if let Ok((start, end)) = self.parse_range(range_str, file_size) {
                    let content_length = end - start + 1;
                    let mut response_builder = http::Response::builder()
                        .status(StatusCode::PARTIAL_CONTENT)
                        .header("Content-Type", mime_type.as_ref())
                        .header("Content-Length", content_length)
                        .header(
                            "Content-Range",
                            format!("bytes {}-{}/{}", start, end, file_size),
                        )
                        .header("Accept-Ranges", "bytes");

                    if let Some(etag) = etag.as_ref() {
                        response_builder = response_builder.header(ETAG, etag.as_str());
                    }
                    if let Some(last_modified) = last_modified {
                        let formatted = Self::format_http_date(last_modified);
                        response_builder = response_builder.header(LAST_MODIFIED, formatted);
                    }

                    let body = if req.method() == hyper::Method::HEAD {
                        Self::empty_body()
                    } else {
                        Self::range_body(file, start, content_length).await?
                    };
                    return response_builder.body(body).map_err(|e| {
                        server_err!(ServerErrorCode::IOError, "Failed to build response: {}", e)
                    });
                }
            }
        }

        let mut response_builder = http::Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", mime_type.as_ref())
            .header("Content-Length", file_size)
            .header("Accept-Ranges", "bytes");

        if let Some(etag) = etag.as_ref() {
            response_builder = response_builder.header(ETAG, etag.as_str());
        }
        if let Some(last_modified) = last_modified {
            let formatted = Self::format_http_date(last_modified);
            response_builder = response_builder.header(LAST_MODIFIED, formatted);
        }

        let body = if req.method() == hyper::Method::HEAD {
            Self::empty_body()
        } else {
            Self::full_or_stream_body(file, file_size).await?
        };

        response_builder
            .body(body)
            .map_err(|e| server_err!(ServerErrorCode::IOError, "Failed to build response: {}", e))
    }

    fn resolve_path(&self, req_path: &str) -> ServerResult<PathBuf> {
        let stripped = req_path.strip_prefix(&self.base_url).unwrap_or(req_path);
        let sub_path = stripped.trim_start_matches('/');
        let mut path = self.root_dir.clone();

        for component in Path::new(sub_path).components() {
            match component {
                Component::CurDir => {}
                Component::Normal(part) => path.push(part),
                Component::ParentDir => {
                    return Err(server_err!(
                        ServerErrorCode::InvalidParam,
                        "path traversal is not allowed"
                    ));
                }
                Component::RootDir | Component::Prefix(_) => {}
            }
        }

        Ok(path)
    }

    fn build_text_response(
        &self,
        status: StatusCode,
        body: impl Into<Bytes>,
    ) -> http::Response<BoxBody<Bytes, ServerError>> {
        http::Response::builder()
            .status(status)
            .body(Full::new(body.into()).map_err(|e| match e {}).boxed())
            .unwrap()
    }

    fn build_html_response(
        &self,
        status: StatusCode,
        body: String,
    ) -> http::Response<BoxBody<Bytes, ServerError>> {
        http::Response::builder()
            .status(status)
            .header("Content-Type", "text/html; charset=utf-8")
            .body(Full::new(Bytes::from(body)).map_err(|e| match e {}).boxed())
            .unwrap()
    }

    fn ensure_path_in_root(&self, path: &Path) -> ServerResult<PathBuf> {
        let canonical_path = path.canonicalize().map_err(|e| {
            server_err!(
                ServerErrorCode::IOError,
                "Failed to canonicalize path: {}",
                e
            )
        })?;
        if !canonical_path.starts_with(&self.root_dir) {
            return Err(server_err!(
                ServerErrorCode::InvalidParam,
                "path out of root directory"
            ));
        }
        Ok(canonical_path)
    }

    fn escape_html(input: &str) -> String {
        let mut escaped = String::with_capacity(input.len());
        for ch in input.chars() {
            match ch {
                '&' => escaped.push_str("&amp;"),
                '<' => escaped.push_str("&lt;"),
                '>' => escaped.push_str("&gt;"),
                '"' => escaped.push_str("&quot;"),
                '\'' => escaped.push_str("&#39;"),
                _ => escaped.push(ch),
            }
        }
        escaped
    }

    fn format_modified_time(st: std::time::SystemTime) -> String {
        let dt: DateTime<Local> = st.into();
        dt.format("%d-%b-%Y %H:%M").to_string()
    }

    async fn serve_directory_listing(
        &self,
        req_path: &str,
        dir_path: &Path,
    ) -> ServerResult<http::Response<BoxBody<Bytes, ServerError>>> {
        struct Entry {
            name: String,
            href: String,
            is_dir: bool,
            modified: String,
            size: String,
        }

        let mut entries = Vec::new();
        let mut read_dir = tokio::fs::read_dir(dir_path).await.map_err(|e| {
            server_err!(ServerErrorCode::IOError, "Failed to read directory: {}", e)
        })?;

        let req_base = if req_path.ends_with('/') {
            req_path.to_string()
        } else {
            format!("{}/", req_path)
        };

        while let Some(entry) = read_dir.next_entry().await.map_err(|e| {
            server_err!(
                ServerErrorCode::IOError,
                "Failed to read directory entry: {}",
                e
            )
        })? {
            let file_name = entry.file_name();
            let name = file_name.to_string_lossy().to_string();
            if name.starts_with('.') {
                continue;
            }

            let metadata = entry.metadata().await.map_err(|e| {
                server_err!(ServerErrorCode::IOError, "Failed to read metadata: {}", e)
            })?;
            let is_dir = metadata.is_dir();
            let encoded_name = utf8_percent_encode(&name, PATH_SEGMENT_ENCODE_SET).to_string();
            let mut href = format!("{}{}", req_base, encoded_name);
            if is_dir {
                href.push('/');
            }

            let modified = metadata
                .modified()
                .ok()
                .map(Self::format_modified_time)
                .unwrap_or_else(|| "-".to_string());
            let size = if is_dir {
                "-".to_string()
            } else {
                metadata.len().to_string()
            };

            entries.push(Entry {
                name,
                href,
                is_dir,
                modified,
                size,
            });
        }

        entries.sort_by(|a, b| {
            b.is_dir
                .cmp(&a.is_dir)
                .then_with(|| a.name.as_bytes().cmp(b.name.as_bytes()))
        });

        let escaped_path = Self::escape_html(req_path);
        let mut html = String::new();
        html.push_str("<!doctype html>\r\n<html lang=\"en\">\r\n<head>\r\n<meta charset=\"utf-8\">\r\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\r\n<title>Index of ");
        html.push_str(&escaped_path);
        html.push_str("</title>\r\n<style>\r\n:root {\r\n  color-scheme: light;\r\n  --bg: #f3f6fb;\r\n  --panel: #ffffff;\r\n  --text: #1f2937;\r\n  --muted: #64748b;\r\n  --line: #d8e1ec;\r\n  --link: #0f62d6;\r\n  --link-hover: #0b4fb0;\r\n}\r\n* { box-sizing: border-box; }\r\nbody {\r\n  margin: 0;\r\n  font-family: \"Segoe UI\", \"PingFang SC\", \"Microsoft YaHei\", sans-serif;\r\n  color: var(--text);\r\n  background: radial-gradient(circle at top right, #e8f0ff 0%, var(--bg) 45%, #edf2f9 100%);\r\n}\r\nmain {\r\n  max-width: 980px;\r\n  margin: 24px auto;\r\n  padding: 0 16px;\r\n}\r\nsection {\r\n  background: var(--panel);\r\n  border: 1px solid var(--line);\r\n  border-radius: 12px;\r\n  box-shadow: 0 10px 24px rgba(15, 23, 42, 0.08);\r\n  overflow: hidden;\r\n}\r\nh1 {\r\n  margin: 0;\r\n  padding: 18px 20px;\r\n  font-size: 20px;\r\n  font-weight: 600;\r\n  letter-spacing: 0.01em;\r\n}\r\nhr {\r\n  margin: 0;\r\n  border: 0;\r\n  border-top: 1px solid var(--line);\r\n}\r\npre {\r\n  margin: 0;\r\n  padding: 14px 20px 20px;\r\n  overflow-x: auto;\r\n  font-family: Consolas, \"Courier New\", monospace;\r\n  font-size: 14px;\r\n  line-height: 1.55;\r\n}\r\na {\r\n  color: var(--link);\r\n  text-decoration: none;\r\n}\r\na:hover {\r\n  color: var(--link-hover);\r\n  text-decoration: underline;\r\n}\r\n@media (max-width: 640px) {\r\n  main {\r\n    margin: 14px auto;\r\n    padding: 0 10px;\r\n  }\r\n  h1 {\r\n    padding: 14px 14px;\r\n    font-size: 18px;\r\n  }\r\n  pre {\r\n    padding: 10px 14px 14px;\r\n    font-size: 13px;\r\n  }\r\n}\r\n</style>\r\n</head>\r\n<body>\r\n<main><section>\r\n<h1>Index of ");
        html.push_str(&escaped_path);
        html.push_str("</h1><hr><pre><a href=\"../\">../</a>\r\n");

        for entry in entries {
            let mut display_name = entry.name;
            if entry.is_dir {
                display_name.push('/');
            }

            let mut short_name: String = display_name.chars().take(50).collect();
            if display_name.chars().count() > 50 {
                short_name = format!("{}..>", display_name.chars().take(47).collect::<String>());
            }

            let escaped_name = Self::escape_html(&short_name);
            let escaped_href = Self::escape_html(&entry.href);
            let pad = 50usize.saturating_sub(short_name.chars().count());
            let spaces = " ".repeat(pad);
            html.push_str(&format!(
                "<a href=\"{}\">{}</a>{} {} {:>19}\r\n",
                escaped_href, escaped_name, spaces, entry.modified, entry.size
            ));
        }

        html.push_str("</pre><hr></section></main></body>\r\n</html>\r\n");
        Ok(self.build_html_response(StatusCode::OK, html))
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

        debug!("DirServer[{}] {} {}", self.id, req_method, req_path);

        // Only support GET and HEAD methods
        if req_method != hyper::Method::GET && req_method != hyper::Method::HEAD {
            warn!("Method not allowed: {}", req_method);
            return Ok(
                self.build_text_response(StatusCode::METHOD_NOT_ALLOWED, "Method not allowed")
            );
        }

        let mut file_path = match self.resolve_path(req_path) {
            Ok(path) => path,
            Err(_) => {
                warn!("Path traversal attempt: {}", req_path);
                return Ok(self.build_text_response(StatusCode::FORBIDDEN, "Forbidden"));
            }
        };

        let mut opened_canonical_path = None;
        let mut file_stat = match self.open_path_in_root(&file_path).await {
            Ok(opened_file) if opened_file.metadata.is_file() => {
                info!("Serving file: {:?}", file_path);
                return self.serve_opened_file(&file_path, opened_file, &req).await;
            }
            Ok(opened_file) => {
                opened_canonical_path = opened_file.canonical_path;
                DirPathStat::Found(CachedPathMetadata {
                    metadata: opened_file.metadata,
                })
            }
            Err(e) if e.kind() == ErrorKind::PermissionDenied => {
                warn!("Path traversal attempt: {:?}", file_path);
                return Ok(self.build_text_response(StatusCode::FORBIDDEN, "Forbidden"));
            }
            Err(_) => self.stat_path(&file_path),
        };
        if file_stat.exists() {
            file_path = match opened_canonical_path.take() {
                Some(path) => path,
                None => match self.ensure_path_in_root(&file_path) {
                    Ok(path) => path,
                    Err(_) => {
                        warn!("Path traversal attempt: {:?}", file_path);
                        return Ok(self.build_text_response(StatusCode::FORBIDDEN, "Forbidden"));
                    }
                },
            };
            file_stat = self.stat_path(&file_path);
        }

        if file_stat.is_dir() {
            let index_path = file_path.join(&self.index_file);
            match self.open_path_in_root(&index_path).await {
                Ok(opened_file) if opened_file.metadata.is_file() => {
                    info!("Serving index file: {:?}", index_path);
                    return self.serve_opened_file(&index_path, opened_file, &req).await;
                }
                Ok(_) => {}
                Err(e) if e.kind() == ErrorKind::PermissionDenied => {
                    warn!("Path traversal attempt: {:?}", index_path);
                    return Ok(self.build_text_response(StatusCode::FORBIDDEN, "Forbidden"));
                }
                Err(_) => {}
            }

            if self.autoindex {
                info!("Serving directory listing: {:?}", file_path);
                return self.serve_directory_listing(req_path, &file_path).await;
            }
        }

        // Check if file exists
        if !file_stat.is_file() {
            warn!("File not found: {:?}", file_path);
            if let Some(fallback_file) = &self.fallback_file {
                let fallback_path = self.root_dir.join(fallback_file);
                match self.open_path_in_root(&fallback_path).await {
                    Ok(opened_file) => {
                        if opened_file.metadata.is_file() {
                            info!("Fallback to file: {:?}", fallback_path);
                            return self
                                .serve_opened_file(&fallback_path, opened_file, &req)
                                .await;
                        }
                        warn!("Fallback file not found: {:?}", fallback_path);
                    }
                    Err(e) => {
                        warn!(
                            "Failed to resolve fallback file: {:?}, error: {}",
                            fallback_path, e
                        );
                    }
                }
            }
            return Ok(self.build_text_response(StatusCode::NOT_FOUND, "Not found"));
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
    #[serde(default)]
    pub autoindex: bool,
    #[serde(default = "dir_server_default_etag")]
    pub etag: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub if_modified_since: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub open_file_cache: Option<DirServerOpenFileCacheConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub open_file_cache_valid: Option<DirServerCacheDuration>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub open_file_cache_min_uses: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub open_file_cache_errors: Option<bool>,
}

/// Nginx-like `open_file_cache` directive for DirServer path metadata lookup.
#[derive(Clone, Debug, Default)]
pub struct DirServerOpenFileCacheConfig {
    pub max: Option<u64>,
    pub inactive: Option<DirServerCacheDuration>,
    off: bool,
}

impl Serialize for DirServerOpenFileCacheConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if self.off {
            return serializer.serialize_str("off");
        }

        let mut parts = Vec::new();
        if let Some(max) = self.max {
            parts.push(format!("max={}", max));
        }
        if let Some(inactive) = self.inactive {
            parts.push(format!("inactive={}s", inactive.into_duration().as_secs()));
        }

        if parts.is_empty() {
            parts.push("max=10000".to_string());
            parts.push("inactive=60s".to_string());
        }

        serializer.serialize_str(parts.join(" ").as_str())
    }
}

impl<'de> Deserialize<'de> for DirServerOpenFileCacheConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct OpenFileCacheVisitor;

        impl<'de> Visitor<'de> for OpenFileCacheVisitor {
            type Value = DirServerOpenFileCacheConfig;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("an nginx-like open_file_cache string")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                parse_open_file_cache_directive(value).map_err(E::custom)
            }

            fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if !value {
                    return Ok(DirServerOpenFileCacheConfig {
                        max: None,
                        inactive: None,
                        off: true,
                    });
                }

                Err(E::custom("open_file_cache true is invalid; use max=..."))
            }
        }

        deserializer.deserialize_any(OpenFileCacheVisitor)
    }
}

fn parse_open_file_cache_directive(value: &str) -> Result<DirServerOpenFileCacheConfig, String> {
    let value = value.trim();
    if value.eq_ignore_ascii_case("off") {
        return Ok(DirServerOpenFileCacheConfig {
            max: None,
            inactive: None,
            off: true,
        });
    }

    if value.is_empty() {
        return Err("open_file_cache must not be empty".to_string());
    }

    let mut config = DirServerOpenFileCacheConfig::default();
    for part in value.split_whitespace() {
        let (key, raw_value) = part
            .split_once('=')
            .ok_or_else(|| format!("invalid open_file_cache parameter: {}", part))?;
        match key {
            "max" => {
                config.max = Some(
                    raw_value
                        .parse::<u64>()
                        .map_err(|_| format!("invalid open_file_cache max: {}", raw_value))?,
                );
            }
            "inactive" => {
                config.inactive = Some(DirServerCacheDuration::Seconds(parse_cache_duration(
                    raw_value,
                )?));
            }
            _ => return Err(format!("unknown open_file_cache parameter: {}", key)),
        }
    }

    Ok(config)
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

        if let Some(open_file_cache) = &config.open_file_cache {
            builder = builder.open_file_cache(
                open_file_cache.clone(),
                config.open_file_cache_valid,
                config.open_file_cache_min_uses,
                config.open_file_cache_errors,
            )?;
        }

        let server = builder.build().await?;
        Ok(vec![Server::Http(Arc::new(server))])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{StreamInfo, hyper_serve_http1};
    use http_body_util::Full;
    use hyper_util::rt::TokioIo;
    use std::sync::Arc;

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
        tokio::fs::write(&file_path, b"Hello, World!")
            .await
            .unwrap();

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
            autoindex: false,
            etag: true,
            if_modified_since: None,
            open_file_cache: None,
            open_file_cache_valid: None,
            open_file_cache_min_uses: None,
            open_file_cache_errors: None,
        };

        let factory = DirServerFactory::new();
        let result = factory.create(Arc::new(config), None).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_open_file_cache_config_deserializes_nginx_like_fields() {
        let config: DirServerConfig = serde_json::from_value(serde_json::json!({
            "id": "test",
            "type": "dir",
            "root_path": "/tmp",
            "open_file_cache": "max=10000 inactive=60s",
            "open_file_cache_valid": "1m",
            "open_file_cache_min_uses": 2,
            "open_file_cache_errors": true
        }))
        .unwrap();

        let cache_config = config.open_file_cache.unwrap();
        assert_eq!(cache_config.max, Some(10_000));
        assert_eq!(
            cache_config.inactive.unwrap().into_duration(),
            Duration::from_secs(60)
        );
        assert_eq!(
            config.open_file_cache_valid.unwrap().into_duration(),
            Duration::from_secs(60)
        );
        assert_eq!(config.open_file_cache_min_uses, Some(2));
        assert_eq!(config.open_file_cache_errors, Some(true));
    }

    #[test]
    fn test_open_file_cache_defaults_to_off_when_omitted() {
        let config: DirServerConfig = serde_json::from_value(serde_json::json!({
            "id": "test",
            "type": "dir",
            "root_path": "/tmp"
        }))
        .unwrap();

        assert!(config.open_file_cache.is_none());
        assert!(config.open_file_cache_valid.is_none());
        assert!(config.open_file_cache_min_uses.is_none());
        assert!(config.open_file_cache_errors.is_none());
    }

    #[tokio::test]
    async fn test_open_file_cache_defaults_when_directive_has_only_max() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config = parse_open_file_cache_directive("max=10000").unwrap();
        let server = DirServer::builder()
            .id("test")
            .root_path(temp_dir.path().to_path_buf())
            .open_file_cache(config, None, None, None)
            .unwrap()
            .build()
            .await
            .unwrap();

        let cache = server.open_file_cache.as_ref().unwrap();
        assert_eq!(cache.settings.max, 10_000);
        assert_eq!(cache.settings.inactive, Duration::from_secs(60));
        assert_eq!(cache.settings.valid, Duration::from_secs(60));
        assert_eq!(cache.settings.min_uses, 2);
        assert!(cache.settings.errors);
    }

    #[tokio::test]
    async fn test_open_file_cache_off_disables_cache() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config = parse_open_file_cache_directive("off").unwrap();
        let server = DirServer::builder()
            .id("test")
            .root_path(temp_dir.path().to_path_buf())
            .open_file_cache(
                config,
                Some(DirServerCacheDuration::Seconds(60)),
                Some(2),
                Some(true),
            )
            .unwrap()
            .build()
            .await
            .unwrap();

        assert!(server.open_file_cache.is_none());
    }

    #[test]
    fn test_open_file_cache_min_uses_and_error_cache() {
        let temp_dir = tempfile::tempdir().unwrap();
        let missing_path = temp_dir.path().join("missing.txt");
        let cache = OpenFileCache::new(OpenFileCacheSettings {
            max: 16,
            inactive: Duration::from_secs(60),
            valid: Duration::from_secs(60),
            min_uses: 2,
            errors: true,
        });

        assert!(cache.stat_path(&missing_path).is_not_found());
        assert!(cache.stat_cache.get(&missing_path).is_none());

        assert!(cache.stat_path(&missing_path).is_not_found());
        assert!(cache.stat_cache.get(&missing_path).is_some());
    }

    #[test]
    fn test_open_file_cache_keeps_only_path_metadata_after_min_uses() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("cached.txt");
        std::fs::write(&file_path, b"cached").unwrap();
        let cache = OpenFileCache::new(OpenFileCacheSettings {
            max: 16,
            inactive: Duration::from_secs(60),
            valid: Duration::from_secs(60),
            min_uses: 2,
            errors: true,
        });

        assert!(cache.stat_cache.get(&file_path).is_none());
        assert_eq!(cache.stat_path(&file_path).metadata().unwrap().len(), 6);
        assert!(cache.stat_cache.get(&file_path).is_none());
        let cached = cache.stat_path(&file_path);
        assert_eq!(cached.metadata().unwrap().len(), 6);
        assert!(cache.stat_cache.get(&file_path).is_some());
    }

    #[test]
    fn test_open_file_cache_promotes_cached_stat_without_file_handle() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("cached.txt");
        std::fs::write(&file_path, b"old").unwrap();

        let stat = DirPathStat::from_path(&file_path);
        std::fs::write(&file_path, b"new-content").unwrap();

        let cached = CachedPathStat::from(&stat).into_stat();
        assert_eq!(cached.metadata().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn test_open_file_cache_does_not_reuse_stale_metadata_for_serve_file_headers() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("cached.txt");
        tokio::fs::write(&file_path, b"old").await.unwrap();
        let cached_metadata = std::fs::metadata(&file_path).unwrap();
        tokio::fs::write(&file_path, b"new-content").await.unwrap();

        let server = DirServer::builder()
            .id("test")
            .root_path(temp_dir.path().to_path_buf())
            .open_file_cache(
                DirServerOpenFileCacheConfig {
                    max: Some(16),
                    inactive: None,
                    off: false,
                },
                Some(DirServerCacheDuration::Seconds(60)),
                Some(1),
                Some(true),
            )
            .unwrap()
            .build()
            .await
            .unwrap();
        let cache = server.open_file_cache.as_ref().unwrap();
        cache.stat_cache.insert(
            file_path.clone(),
            CachedPathStat {
                result: Ok(CachedPathMetadata {
                    metadata: cached_metadata,
                }),
            },
        );

        let req = http::Request::builder()
            .method("GET")
            .uri("http://localhost/cached.txt")
            .body(Full::new(Bytes::new()).map_err(|e| match e {}).boxed())
            .unwrap();
        let resp = server.serve_file(&file_path, &req).await.unwrap();

        assert_eq!(resp.headers().get("Content-Length").unwrap(), "11");
    }

    #[tokio::test]
    async fn test_open_file_cache_does_not_cache_full_file_body() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("cached-body.txt");
        tokio::fs::write(&file_path, b"old-body").await.unwrap();

        let server = DirServer::builder()
            .id("test")
            .root_path(temp_dir.path().to_path_buf())
            .open_file_cache(
                DirServerOpenFileCacheConfig {
                    max: Some(16),
                    inactive: None,
                    off: false,
                },
                Some(DirServerCacheDuration::Seconds(60)),
                Some(1),
                Some(true),
            )
            .unwrap()
            .build()
            .await
            .unwrap();

        let req = http::Request::builder()
            .method("GET")
            .uri("http://localhost/cached-body.txt")
            .body(Full::new(Bytes::new()).map_err(|e| match e {}).boxed())
            .unwrap();
        let resp = server.serve_file(&file_path, &req).await.unwrap();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body.as_ref(), b"old-body");

        tokio::fs::write(&file_path, b"new-body").await.unwrap();

        let req = http::Request::builder()
            .method("GET")
            .uri("http://localhost/cached-body.txt")
            .body(Full::new(Bytes::new()).map_err(|e| match e {}).boxed())
            .unwrap();
        let resp = server.serve_file(&file_path, &req).await.unwrap();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body.as_ref(), b"new-body");
    }

    #[tokio::test]
    async fn test_head_request_returns_headers_without_body() {
        let temp_dir = tempfile::tempdir().unwrap();
        tokio::fs::write(temp_dir.path().join("head.txt"), b"head-body")
            .await
            .unwrap();

        let server = DirServer::builder()
            .id("test")
            .root_path(temp_dir.path().to_path_buf())
            .build()
            .await
            .unwrap();

        let req = http::Request::builder()
            .method("HEAD")
            .uri("http://localhost/head.txt")
            .body(Full::new(Bytes::new()).map_err(|e| match e {}).boxed())
            .unwrap();
        let resp = server
            .serve_request(req, StreamInfo::default())
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get("Content-Length").unwrap(), "9");
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert!(body.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_symlink_escape_is_forbidden() {
        let root_dir = tempfile::tempdir().unwrap();
        let outside_dir = tempfile::tempdir().unwrap();
        let outside_file = outside_dir.path().join("secret.txt");
        tokio::fs::write(&outside_file, b"secret").await.unwrap();
        std::os::unix::fs::symlink(&outside_file, root_dir.path().join("leak.txt")).unwrap();

        let server = DirServer::builder()
            .id("test")
            .root_path(root_dir.path().to_path_buf())
            .build()
            .await
            .unwrap();
        let req = http::Request::builder()
            .method("GET")
            .uri("http://localhost/leak.txt")
            .body(Full::new(Bytes::new()).map_err(|e| match e {}).boxed())
            .unwrap();
        let resp = server
            .serve_request(req, StreamInfo::default())
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn test_open_file_cache_errors_off_does_not_cache_missing_path() {
        let temp_dir = tempfile::tempdir().unwrap();
        let missing_path = temp_dir.path().join("missing.txt");
        let cache = OpenFileCache::new(OpenFileCacheSettings {
            max: 16,
            inactive: Duration::from_secs(60),
            valid: Duration::from_secs(60),
            min_uses: 1,
            errors: false,
        });

        assert!(cache.stat_path(&missing_path).is_not_found());
        assert!(cache.stat_cache.get(&missing_path).is_none());
    }

    #[tokio::test]
    async fn test_dir_prefers_index_file_before_autoindex_listing() {
        let temp_dir = tempfile::tempdir().unwrap();
        tokio::fs::write(temp_dir.path().join("index.html"), b"index-body")
            .await
            .unwrap();
        tokio::fs::write(temp_dir.path().join("another.txt"), b"another")
            .await
            .unwrap();

        let server = Arc::new(
            DirServer::builder()
                .id("test")
                .root_path(temp_dir.path().to_path_buf())
                .autoindex(true)
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
            .uri("http://localhost/")
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
        assert_eq!(body_bytes.as_ref(), b"index-body");
    }

    #[tokio::test]
    async fn test_dir_returns_listing_when_index_missing_and_autoindex_enabled() {
        let temp_dir = tempfile::tempdir().unwrap();
        tokio::fs::write(temp_dir.path().join("visible.txt"), b"visible")
            .await
            .unwrap();
        tokio::fs::write(temp_dir.path().join(".hidden.txt"), b"hidden")
            .await
            .unwrap();

        let server = Arc::new(
            DirServer::builder()
                .id("test")
                .root_path(temp_dir.path().to_path_buf())
                .autoindex(true)
                .build()
                .await
                .unwrap(),
        );

        let (client, server_stream) = tokio::io::duplex(4096);

        tokio::spawn(async move {
            hyper_serve_http1(Box::new(server_stream), server, StreamInfo::default())
                .await
                .unwrap();
        });

        let request = http::Request::builder()
            .method("GET")
            .uri("http://localhost/")
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
        let content_type = resp
            .headers()
            .get("Content-Type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert_eq!(content_type, "text/html; charset=utf-8");

        let body = String::from_utf8(resp.collect().await.unwrap().to_bytes().to_vec()).unwrap();
        assert!(body.contains("visible.txt"));
        assert!(!body.contains(".hidden.txt"));
        assert!(body.contains("Index of /"));
    }

    #[tokio::test]
    async fn test_if_none_match_returns_not_modified() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("etag.txt");
        tokio::fs::write(&file_path, b"etag-body").await.unwrap();

        let server = Arc::new(
            DirServer::builder()
                .id("test")
                .root_path(temp_dir.path().to_path_buf())
                .build()
                .await
                .unwrap(),
        );

        let (client, server_stream) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            hyper_serve_http1(Box::new(server_stream), server, StreamInfo::default())
                .await
                .unwrap();
        });

        let first_req = http::Request::builder()
            .method("GET")
            .uri("http://localhost/etag.txt")
            .body(Full::new(Bytes::new()))
            .unwrap();

        let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
            .handshake(TokioIo::new(client))
            .await
            .unwrap();

        tokio::spawn(async move {
            conn.await.unwrap();
        });

        let first_resp = sender.send_request(first_req).await.unwrap();
        assert_eq!(first_resp.status(), StatusCode::OK);
        let etag = first_resp
            .headers()
            .get(ETAG)
            .and_then(|v| v.to_str().ok())
            .unwrap()
            .to_string();

        let second_req = http::Request::builder()
            .method("GET")
            .uri("http://localhost/etag.txt")
            .header(IF_NONE_MATCH, etag)
            .body(Full::new(Bytes::new()))
            .unwrap();

        let second_resp = sender.send_request(second_req).await.unwrap();
        assert_eq!(second_resp.status(), StatusCode::NOT_MODIFIED);
    }

    #[tokio::test]
    async fn test_if_modified_since_exact_returns_not_modified() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("ims.txt");
        tokio::fs::write(&file_path, b"ims-body").await.unwrap();

        let metadata = tokio::fs::metadata(&file_path).await.unwrap();
        let modified = metadata.modified().unwrap();
        let since = httpdate::fmt_http_date(modified);

        let server = Arc::new(
            DirServer::builder()
                .id("test")
                .root_path(temp_dir.path().to_path_buf())
                .if_modified_since("exact")
                .build()
                .await
                .unwrap(),
        );

        let (client, server_stream) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            hyper_serve_http1(Box::new(server_stream), server, StreamInfo::default())
                .await
                .unwrap();
        });

        let request = http::Request::builder()
            .method("GET")
            .uri("http://localhost/ims.txt")
            .header(IF_MODIFIED_SINCE, since)
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
        assert_eq!(resp.status(), StatusCode::NOT_MODIFIED);
    }

    #[tokio::test]
    async fn test_if_none_match_precedence_over_if_modified_since() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("precedence.txt");
        tokio::fs::write(&file_path, b"precedence-body")
            .await
            .unwrap();

        let metadata = tokio::fs::metadata(&file_path).await.unwrap();
        let modified = metadata.modified().unwrap();
        let since = httpdate::fmt_http_date(modified);

        let server = Arc::new(
            DirServer::builder()
                .id("test")
                .root_path(temp_dir.path().to_path_buf())
                .if_modified_since("exact")
                .build()
                .await
                .unwrap(),
        );

        let (client, server_stream) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            hyper_serve_http1(Box::new(server_stream), server, StreamInfo::default())
                .await
                .unwrap();
        });

        let request = http::Request::builder()
            .method("GET")
            .uri("http://localhost/precedence.txt")
            .header(IF_NONE_MATCH, "\"mismatch-etag\"")
            .header(IF_MODIFIED_SINCE, since)
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
    }

    #[tokio::test]
    async fn test_response_contains_etag_and_last_modified() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("headers.txt");
        tokio::fs::write(&file_path, b"headers-body").await.unwrap();

        let server = Arc::new(
            DirServer::builder()
                .id("test")
                .root_path(temp_dir.path().to_path_buf())
                .build()
                .await
                .unwrap(),
        );

        let (client, server_stream) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            hyper_serve_http1(Box::new(server_stream), server, StreamInfo::default())
                .await
                .unwrap();
        });

        let request = http::Request::builder()
            .method("GET")
            .uri("http://localhost/headers.txt")
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
        assert!(resp.headers().contains_key(ETAG));
        assert!(resp.headers().contains_key(LAST_MODIFIED));
    }

    #[tokio::test]
    async fn test_invalid_if_modified_since_config() {
        let temp_dir = tempfile::tempdir().unwrap();
        let result = DirServer::builder()
            .id("test")
            .root_path(temp_dir.path().to_path_buf())
            .if_modified_since("invalid")
            .build()
            .await;

        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(e.code(), ServerErrorCode::InvalidConfig);
        }
    }
}
