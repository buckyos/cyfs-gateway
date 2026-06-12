use super::server_err;
use crate::{
    HttpServer, Server, ServerConfig, ServerContextRef, ServerError, ServerErrorCode,
    ServerFactory, ServerResult, StreamInfo,
};
use chrono::{DateTime, Local};
use futures_util::{Stream, TryStreamExt};
use http::{StatusCode, Version};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Bytes, Frame};
use hyper::header::{ETAG, IF_MODIFIED_SINCE, IF_NONE_MATCH, IF_RANGE, LAST_MODIFIED, RANGE};
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
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncSeekExt, SeekFrom};
use tokio_util::bytes::{BufMut, BytesMut};
use tokio_util::io::ReaderStream;

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
const DEFAULT_FILE_READ_BUFFER_SIZE: usize = 64 * 1024;

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
    file_io_mode: DirServerFileIoMode,
    file_read_buffer_size: usize,
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

    async fn stat_path(&self, path: &Path, file_io_mode: DirServerFileIoMode) -> DirPathStat {
        let key = path.to_path_buf();
        if let Some(cached) = self.stat_cache.get(&key) {
            return cached.into_stat();
        }

        let stat = DirPathStat::from_path(path, file_io_mode).await;
        let uses = self.admission_counts.get(&key).unwrap_or(0) + 1;
        self.admission_counts.insert(key.clone(), uses);

        if uses >= self.settings.min_uses && (stat.exists() || self.settings.errors) {
            self.stat_cache.insert(key, CachedPathStat::from(&stat));
        }

        stat
    }

    fn record_opened_file_metadata(&self, path: &Path, metadata: &std::fs::Metadata) {
        if !metadata.is_file() {
            return;
        }

        let key = path.to_path_buf();
        if self.stat_cache.get(&key).is_some() {
            self.stat_cache.insert(
                key,
                CachedPathStat {
                    result: Ok(CachedPathMetadata {
                        metadata: metadata.clone(),
                    }),
                },
            );
            return;
        }

        let uses = self.admission_counts.get(&key).unwrap_or(0) + 1;
        self.admission_counts.insert(key.clone(), uses);

        if uses >= self.settings.min_uses {
            self.stat_cache.insert(
                key,
                CachedPathStat {
                    result: Ok(CachedPathMetadata {
                        metadata: metadata.clone(),
                    }),
                },
            );
        }
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
            DirPathStat::Opened(_) => Err(CachedPathError {
                kind: ErrorKind::Other,
                message: "opened path metadata is not cacheable".to_string(),
            }),
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

struct DirFileRequestInfo {
    is_head: bool,
    is_get: bool,
    range_header_count: usize,
    range_header: Option<String>,
    invalid_range_header: bool,
    if_range: Option<String>,
    if_none_match: Option<String>,
    if_modified_since: Option<String>,
}

impl DirFileRequestInfo {
    fn from_request(req: &http::Request<UnsyncBoxBody<Bytes, ServerError>>) -> Self {
        let range_headers = req.headers().get_all(RANGE);
        let range_header_count = range_headers.iter().count();
        let mut invalid_range_header = false;
        let range_header = if range_header_count == 1 {
            match range_headers.iter().next().map(|value| value.to_str()) {
                Some(Ok(value)) => Some(value.to_owned()),
                Some(Err(_)) => {
                    invalid_range_header = true;
                    None
                }
                None => None,
            }
        } else {
            None
        };

        Self {
            is_head: req.method() == hyper::Method::HEAD,
            is_get: req.method() == hyper::Method::GET,
            range_header_count,
            range_header,
            invalid_range_header,
            if_range: req
                .headers()
                .get(IF_RANGE)
                .and_then(|value| value.to_str().ok())
                .map(|value| value.to_owned()),
            if_none_match: req
                .headers()
                .get(IF_NONE_MATCH)
                .and_then(|value| value.to_str().ok())
                .map(|value| value.to_owned()),
            if_modified_since: req
                .headers()
                .get(IF_MODIFIED_SINCE)
                .and_then(|value| value.to_str().ok())
                .map(|value| value.to_owned()),
        }
    }
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
    Opened(std::fs::Metadata),
    Error(std::io::Error),
}

struct OpenedDirFile {
    file: Option<DirReadFile>,
    metadata: std::fs::Metadata,
    canonical_path: Option<PathBuf>,
}

enum DirReadFile {
    Tokio(tokio::fs::File),
    Sync(std::fs::File),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DirRangeRequest {
    Apply { start: u64, end: u64 },
    Ignore,
    Reject,
}

struct SyncFileBodyStream {
    file: std::fs::File,
    remaining: u64,
    buffer_size: usize,
    buf: BytesMut,
}

impl SyncFileBodyStream {
    fn new(file: std::fs::File, content_length: u64, buffer_size: usize) -> Self {
        Self {
            file,
            remaining: content_length,
            buffer_size,
            buf: BytesMut::with_capacity(buffer_size),
        }
    }
}

impl Stream for SyncFileBodyStream {
    type Item = std::io::Result<Frame<Bytes>>;

    fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.remaining == 0 {
            return Poll::Ready(None);
        }

        let read_len = DirServer::file_stream_buffer_size(self.buffer_size, self.remaining);
        if self.buf.capacity() == 0 {
            let buffer_size = self.buffer_size;
            self.buf.reserve(buffer_size);
        }

        let read_result = {
            let this = &mut *self;
            let spare = this.buf.spare_capacity_mut();
            let read_len = read_len.min(spare.len());
            // Read initializes at most `read_len` bytes, which are made visible below.
            let dst = unsafe {
                std::slice::from_raw_parts_mut(spare.as_mut_ptr().cast::<u8>(), read_len)
            };
            std::io::Read::read(&mut this.file, dst)
        };

        match read_result {
            Ok(0) => {
                self.remaining = 0;
                Poll::Ready(Some(Err(std::io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "sync file stream ended before expected content length",
                ))))
            }
            Ok(n) => {
                // `read` reported exactly `n` initialized bytes in the spare capacity.
                unsafe {
                    self.buf.advance_mut(n);
                }
                self.remaining = self.remaining.saturating_sub(n as u64);
                let chunk = self.buf.split();
                Poll::Ready(Some(Ok(Frame::data(chunk.freeze()))))
            }
            Err(e) => {
                self.remaining = 0;
                Poll::Ready(Some(Err(e)))
            }
        }
    }
}

impl DirPathStat {
    async fn from_path(path: &Path, file_io_mode: DirServerFileIoMode) -> Self {
        match DirServer::fs_metadata(file_io_mode, path).await {
            Ok(metadata) => Self::Found(CachedPathMetadata { metadata }),
            Err(e) => Self::Error(e),
        }
    }

    fn exists(&self) -> bool {
        matches!(self, Self::Found(_) | Self::Opened(_))
    }

    fn is_dir(&self) -> bool {
        match self {
            Self::Found(metadata) => metadata.metadata.is_dir(),
            Self::Opened(metadata) => metadata.is_dir(),
            Self::Error(_) => false,
        }
    }

    fn is_file(&self) -> bool {
        match self {
            Self::Found(metadata) => metadata.metadata.is_file(),
            Self::Opened(metadata) => metadata.is_file(),
            Self::Error(_) => false,
        }
    }

    fn metadata(&self) -> Option<std::fs::Metadata> {
        match self {
            Self::Found(metadata) => Some(metadata.metadata.clone()),
            Self::Opened(_) => None,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DirServerFileIoMode {
    Async,
    Sync,
}

impl Default for DirServerFileIoMode {
    fn default() -> Self {
        Self::Sync
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

    pub fn file_io_mode(mut self, mode: DirServerFileIoMode) -> Self {
        self.file_io_mode = mode;
        self
    }

    pub fn file_read_buffer_size(mut self, size: usize) -> Self {
        self.file_read_buffer_size = size;
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
    #[cfg(target_os = "linux")]
    root_dir_file: Arc<std::fs::File>,
    index_file: String,
    fallback_file: Option<String>,
    base_url: String,
    autoindex: bool,
    etag: bool,
    if_modified_since: IfModifiedSinceMode,
    open_file_cache: Option<OpenFileCache>,
    file_io_mode: DirServerFileIoMode,
    file_read_buffer_size: usize,
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
            file_io_mode: DirServerFileIoMode::default(),
            file_read_buffer_size: DEFAULT_FILE_READ_BUFFER_SIZE,
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
        let file_io_mode = builder.file_io_mode;
        if builder.file_read_buffer_size == 0 {
            return Err(server_err!(
                ServerErrorCode::InvalidConfig,
                "file_read_buffer_size must be greater than 0"
            ));
        }

        let root_metadata = match Self::fs_metadata(file_io_mode, &root_path).await {
            Ok(metadata) => metadata,
            Err(e) if e.kind() == ErrorKind::NotFound => {
                return Err(server_err!(
                    ServerErrorCode::InvalidConfig,
                    "root_path does not exist: {:?}",
                    root_path
                ));
            }
            Err(e) => {
                return Err(server_err!(
                    ServerErrorCode::IOError,
                    "Failed to read root_path metadata: {}",
                    e
                ));
            }
        };

        if !root_metadata.is_dir() {
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
        let new_root_dir = Self::fs_canonicalize(file_io_mode, &root_path).await.map_err(|e| {
            server_err!(
                ServerErrorCode::IOError,
                "Failed to canonicalize path: {}",
                e
            )
        })?;
        #[cfg(target_os = "linux")]
        let root_dir_file = Arc::new(Self::open_std_file(file_io_mode, &new_root_dir).await.map_err(|e| {
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
            file_io_mode,
            file_read_buffer_size: builder.file_read_buffer_size,
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
        req_info: &DirFileRequestInfo,
        current_etag: Option<&str>,
        last_modified: Option<SystemTime>,
    ) -> bool {
        if let Some(if_none_match) = req_info.if_none_match.as_deref() {
            return Self::etag_matches_if_none_match(current_etag, if_none_match);
        }

        if let (Some(last_modified), Some(if_modified_since)) =
            (last_modified, req_info.if_modified_since.as_deref())
        {
            return self.compare_if_modified_since(last_modified, if_modified_since);
        }

        false
    }

    fn if_range_matches(if_range: &str, current_etag: Option<&str>) -> bool {
        let if_range = if_range.trim();
        if if_range.is_empty() || if_range.starts_with("W/") {
            return false;
        }

        if if_range.starts_with('"') {
            return matches!(current_etag, Some(etag) if etag == if_range);
        }

        // Last-Modified has one-second HTTP-date granularity and is not a
        // strong validator for local files here; date-form If-Range therefore
        // cannot safely authorize a partial response.
        false
    }

    fn can_apply_if_range(req_info: &DirFileRequestInfo, current_etag: Option<&str>) -> bool {
        req_info
            .if_range
            .as_deref()
            .map(|if_range| Self::if_range_matches(if_range, current_etag))
            .unwrap_or(true)
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

    async fn stat_path(&self, path: &Path) -> DirPathStat {
        match &self.open_file_cache {
            Some(cache) => cache.stat_path(path, self.file_io_mode).await,
            None => DirPathStat::from_path(path, self.file_io_mode).await,
        }
    }

    async fn fs_metadata(
        file_io_mode: DirServerFileIoMode,
        path: &Path,
    ) -> std::io::Result<std::fs::Metadata> {
        match file_io_mode {
            DirServerFileIoMode::Async => tokio::fs::metadata(path).await,
            DirServerFileIoMode::Sync => std::fs::metadata(path),
        }
    }

    async fn fs_canonicalize(
        file_io_mode: DirServerFileIoMode,
        path: &Path,
    ) -> std::io::Result<PathBuf> {
        match file_io_mode {
            DirServerFileIoMode::Async => tokio::fs::canonicalize(path).await,
            DirServerFileIoMode::Sync => std::fs::canonicalize(path),
        }
    }

    async fn open_std_file(
        file_io_mode: DirServerFileIoMode,
        path: &Path,
    ) -> std::io::Result<std::fs::File> {
        match file_io_mode {
            DirServerFileIoMode::Async => Ok(tokio::fs::File::open(path).await?.into_std().await),
            DirServerFileIoMode::Sync => std::fs::File::open(path),
        }
    }

    async fn open_file_for_read(&self, file_path: &Path) -> std::io::Result<OpenedDirFile> {
        self.open_path_in_root_cached(file_path).await
    }

    async fn open_path_in_root_cached(
        &self,
        file_path: &Path,
    ) -> std::io::Result<OpenedDirFile> {
        let opened = self.open_path_in_root(file_path).await?;
        if let Some(cache) = &self.open_file_cache {
            cache.record_opened_file_metadata(file_path, &opened.metadata);
        }
        Ok(opened)
    }

    async fn open_path_in_root(&self, file_path: &Path) -> std::io::Result<OpenedDirFile> {
        #[cfg(target_os = "linux")]
        if let Ok(opened) = self.open_path_in_root_openat2(file_path).await {
            return Ok(opened);
        }

        let canonical_path = Self::fs_canonicalize(self.file_io_mode, file_path).await?;
        if !canonical_path.starts_with(&self.root_dir) {
            return Err(std::io::Error::new(
                ErrorKind::PermissionDenied,
                "path out of root directory",
            ));
        }

        let metadata = Self::fs_metadata(self.file_io_mode, &canonical_path).await?;
        if metadata.is_dir() {
            return Ok(OpenedDirFile {
                file: None,
                metadata,
                canonical_path: Some(canonical_path),
            });
        }

        let file = match self.file_io_mode {
            DirServerFileIoMode::Async => {
                DirReadFile::Tokio(tokio::fs::File::open(&canonical_path).await?)
            }
            DirServerFileIoMode::Sync => {
                DirReadFile::Sync(Self::open_std_file(self.file_io_mode, &canonical_path).await?)
            }
        };

        Ok(OpenedDirFile {
            file: Some(file),
            metadata,
            canonical_path: Some(canonical_path),
        })
    }

    #[cfg(target_os = "linux")]
    async fn open_path_in_root_openat2(&self, file_path: &Path) -> std::io::Result<OpenedDirFile> {
        use std::os::unix::ffi::OsStrExt;

        let root_dir = self.root_dir.clone();
        let root_dir_file = self.root_dir_file.clone();
        let file_path = file_path.to_path_buf();
        let file_io_mode = self.file_io_mode;

        let open_with_openat2 = move || {
            let relative_path = file_path.strip_prefix(&root_dir).map_err(|_| {
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
                    root_dir_file.as_raw_fd(),
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
                std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))
                    .ok()
                    .filter(|path| path.starts_with(&root_dir))
            };
            let file = if metadata.is_file() {
                Some(match file_io_mode {
                    DirServerFileIoMode::Async => DirReadFile::Tokio(tokio::fs::File::from_std(file)),
                    DirServerFileIoMode::Sync => DirReadFile::Sync(file),
                })
            } else {
                None
            };

            Ok(OpenedDirFile {
                file,
                metadata,
                canonical_path,
            })
        };

        if self.file_io_mode == DirServerFileIoMode::Sync {
            open_with_openat2()
        } else {
            tokio::task::spawn_blocking(open_with_openat2)
                .await
                .map_err(|e| std::io::Error::new(ErrorKind::Other, e))?
        }
    }

    fn file_stream_buffer_size(configured_size: usize, content_length: u64) -> usize {
        let content_length = usize::try_from(content_length).unwrap_or(usize::MAX);
        configured_size.min(content_length).max(1)
    }

    fn should_inline_file_body(&self, content_length: u64) -> bool {
        let inline_limit = u64::try_from(self.file_read_buffer_size).unwrap_or(u64::MAX);
        content_length <= inline_limit
    }

    fn empty_body() -> UnsyncBoxBody<Bytes, ServerError> {
        Full::new(Bytes::new())
            .map_err(|e| match e {})
            .boxed_unsync()
    }

    async fn full_or_stream_body(
        &self,
        file: DirReadFile,
        content_length: u64,
    ) -> ServerResult<UnsyncBoxBody<Bytes, ServerError>> {
        if content_length == 0 {
            return Ok(Self::empty_body());
        }

        let mut file = match file {
            DirReadFile::Tokio(file) => file,
            file @ DirReadFile::Sync(_) => {
                return self.sync_full_or_stream_body(file, content_length).await;
            }
        };

        if self.should_inline_file_body(content_length) {
            let mut buf = Vec::with_capacity(content_length as usize);
            file.read_to_end(&mut buf).await.map_err(|e| {
                server_err!(
                    ServerErrorCode::IOError,
                    "Failed to read file content: {}",
                    e
                )
            })?;
            return Ok(Full::new(Bytes::from(buf))
                .map_err(|e| match e {})
                .boxed_unsync());
        }

        let stream =
            ReaderStream::with_capacity(
                file,
                Self::file_stream_buffer_size(self.file_read_buffer_size, content_length),
            )
                .map_ok(Frame::data);

        Ok(BodyExt::map_err(StreamBody::new(stream), |e| {
            server_err!(
                ServerErrorCode::IOError,
                "Failed to read file stream: {}",
                e
            )
        })
        .boxed_unsync())
    }

    async fn sync_full_or_stream_body(
        &self,
        file: DirReadFile,
        content_length: u64,
    ) -> ServerResult<UnsyncBoxBody<Bytes, ServerError>> {
        let DirReadFile::Sync(mut file) = file else {
            unreachable!("sync_full_or_stream_body only accepts sync files");
        };

        if self.should_inline_file_body(content_length) {
            let mut buf = Vec::with_capacity(content_length as usize);
            std::io::Read::read_to_end(&mut file, &mut buf).map_err(|e| {
                server_err!(
                    ServerErrorCode::IOError,
                    "Failed to read sync file content: {}",
                    e
                )
            })?;

            return Ok(Full::new(Bytes::from(buf))
                .map_err(|e| match e {})
                .boxed_unsync());
        }

        Ok(Self::sync_file_stream_body(
            file,
            content_length,
            Self::file_stream_buffer_size(self.file_read_buffer_size, content_length),
            "Failed to read sync file stream",
        ))
    }

    async fn range_body(
        &self,
        file: DirReadFile,
        start: u64,
        content_length: u64,
    ) -> ServerResult<UnsyncBoxBody<Bytes, ServerError>> {
        if content_length == 0 {
            return Ok(Self::empty_body());
        }

        let mut file = match file {
            DirReadFile::Tokio(file) => file,
            file @ DirReadFile::Sync(_) => {
                return self.sync_range_body(file, start, content_length).await;
            }
        };

        file.seek(SeekFrom::Start(start)).await.map_err(|e| {
            server_err!(ServerErrorCode::IOError, "Failed to seek file range: {}", e)
        })?;

        if self.should_inline_file_body(content_length) {
            let len = content_length as usize;
            let mut buf = vec![0u8; len];
            file.read_exact(&mut buf).await.map_err(|e| {
                server_err!(ServerErrorCode::IOError, "Failed to read file range: {}", e)
            })?;

            return Ok(Full::new(Bytes::from(buf))
                .map_err(|e| match e {})
                .boxed_unsync());
        }

        let stream = ReaderStream::with_capacity(
            file.take(content_length),
            Self::file_stream_buffer_size(self.file_read_buffer_size, content_length),
        )
        .map_ok(Frame::data);

        Ok(BodyExt::map_err(StreamBody::new(stream), |e| {
            server_err!(ServerErrorCode::IOError, "Failed to read file range: {}", e)
        })
        .boxed_unsync())
    }

    async fn sync_range_body(
        &self,
        file: DirReadFile,
        start: u64,
        content_length: u64,
    ) -> ServerResult<UnsyncBoxBody<Bytes, ServerError>> {
        let DirReadFile::Sync(mut file) = file else {
            unreachable!("sync_range_body only accepts sync files");
        };
        std::io::Seek::seek(&mut file, std::io::SeekFrom::Start(start)).map_err(|e| {
            server_err!(ServerErrorCode::IOError, "Failed to seek sync file range: {}", e)
        })?;

        if self.should_inline_file_body(content_length) {
            let len = content_length as usize;
            let mut buf = vec![0u8; len];
            std::io::Read::read_exact(&mut file, &mut buf).map_err(|e| {
                server_err!(
                    ServerErrorCode::IOError,
                    "Failed to read sync file range: {}",
                    e
                )
            })?;

            return Ok(Full::new(Bytes::from(buf))
                .map_err(|e| match e {})
                .boxed_unsync());
        }

        Ok(Self::sync_file_stream_body(
            file,
            content_length,
            Self::file_stream_buffer_size(self.file_read_buffer_size, content_length),
            "Failed to read sync file range stream",
        ))
    }

    fn sync_file_stream_body(
        file: std::fs::File,
        content_length: u64,
        buffer_size: usize,
        error_message: &'static str,
    ) -> UnsyncBoxBody<Bytes, ServerError> {
        let stream = SyncFileBodyStream::new(file, content_length, buffer_size);
        BodyExt::map_err(StreamBody::new(stream), move |e| {
            server_err!(ServerErrorCode::IOError, "{}: {}", error_message, e)
        })
        .boxed_unsync()
    }

    /// Classify a single Range header (e.g., "bytes=start-end", "bytes=start-", "bytes=-suffix").
    fn classify_range(&self, range: &str, file_size: u64) -> DirRangeRequest {
        let Some((unit, range)) = range.split_once('=') else {
            return if range
                .trim_ascii_start()
                .as_bytes()
                .get(..5)
                .map(|prefix| prefix.eq_ignore_ascii_case(b"bytes"))
                .unwrap_or(false)
            {
                DirRangeRequest::Reject
            } else {
                DirRangeRequest::Ignore
            };
        };
        if !unit.eq_ignore_ascii_case("bytes") {
            return if unit.trim_ascii().eq_ignore_ascii_case("bytes") {
                DirRangeRequest::Reject
            } else {
                DirRangeRequest::Ignore
            };
        };

        let range = range.trim_ascii();
        if range.is_empty() {
            return DirRangeRequest::Reject;
        }

        if file_size == 0 {
            return DirRangeRequest::Ignore;
        }

        if range.contains(',') {
            return if range
                .split(',')
                .map(str::trim_ascii)
                .all(Self::byte_range_part_is_well_formed)
            {
                DirRangeRequest::Ignore
            } else {
                DirRangeRequest::Reject
            };
        }

        if range.bytes().any(|b| b.is_ascii_whitespace()) {
            return DirRangeRequest::Reject;
        }

        let Some((start_part, end_part)) = range.split_once('-') else {
            return DirRangeRequest::Reject;
        };

        if start_part.is_empty() {
            let Ok(suffix_len) = end_part.parse::<u64>() else {
                return DirRangeRequest::Reject;
            };
            if suffix_len == 0 {
                return DirRangeRequest::Reject;
            }

            let start = file_size.saturating_sub(suffix_len);
            return DirRangeRequest::Apply {
                start,
                end: file_size - 1,
            };
        }

        let Ok(start) = start_part.parse::<u64>() else {
            return DirRangeRequest::Reject;
        };
        if start >= file_size {
            return DirRangeRequest::Reject;
        }

        let end = if end_part.is_empty() {
            file_size - 1
        } else {
            let Ok(end) = end_part.parse::<u64>() else {
                return DirRangeRequest::Reject;
            };
            end.min(file_size - 1)
        };

        if start > end {
            return DirRangeRequest::Reject;
        }

        DirRangeRequest::Apply { start, end }
    }

    fn byte_range_part_is_well_formed(range: &str) -> bool {
        if range.is_empty() || range.bytes().any(|b| b.is_ascii_whitespace()) {
            return false;
        }

        let Some((start_part, end_part)) = range.split_once('-') else {
            return false;
        };
        if end_part.contains('-') {
            return false;
        }

        if start_part.is_empty() {
            return end_part.parse::<u64>().is_ok();
        }

        let Ok(start) = start_part.parse::<u64>() else {
            return false;
        };
        if end_part.is_empty() {
            return true;
        }

        matches!(end_part.parse::<u64>(), Ok(end) if start <= end)
    }

    /// Serve a file from the local directory
    async fn serve_file(
        &self,
        file_path: &Path,
        req_info: &DirFileRequestInfo,
    ) -> ServerResult<http::Response<UnsyncBoxBody<Bytes, ServerError>>> {
        let opened_file = self.open_file_for_read(file_path).await.map_err(|e| {
            warn!("Failed to open file: {:?}, error: {}", file_path, e);
            server_err!(ServerErrorCode::IOError, "Failed to open file: {}", e)
        })?;
        self.serve_opened_file(file_path, opened_file, req_info)
            .await
    }

    async fn serve_opened_file_if_regular(
        &self,
        file_path: &Path,
        opened_file: OpenedDirFile,
        req_info: &DirFileRequestInfo,
        log_message: &str,
    ) -> ServerResult<Result<http::Response<UnsyncBoxBody<Bytes, ServerError>>, OpenedDirFile>> {
        if !opened_file.metadata.is_file() {
            return Ok(Err(opened_file));
        }

        info!("{}: {:?}", log_message, file_path);
        self.serve_opened_file(file_path, opened_file, req_info)
            .await
            .map(Ok)
    }

    fn path_forbidden_response(
        &self,
        file_path: &Path,
    ) -> http::Response<UnsyncBoxBody<Bytes, ServerError>> {
        warn!("Path traversal attempt: {:?}", file_path);
        self.build_text_response(StatusCode::FORBIDDEN, "Forbidden")
    }

    async fn serve_opened_file(
        &self,
        file_path: &Path,
        opened_file: OpenedDirFile,
        req_info: &DirFileRequestInfo,
    ) -> ServerResult<http::Response<UnsyncBoxBody<Bytes, ServerError>>> {
        let file = opened_file.file.ok_or_else(|| {
            server_err!(
                ServerErrorCode::InvalidParam,
                "opened path is not a regular file"
            )
        })?;
        let file_meta = opened_file.metadata;
        let file_size = file_meta.len();
        let mime_type = mime_guess::from_path(&file_path).first_or_octet_stream();
        let last_modified = file_meta.modified().ok();
        let etag = if self.etag {
            Self::build_etag(&file_meta)
        } else {
            None
        };

        if self.request_not_modified(req_info, etag.as_deref(), last_modified) {
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

        let applied_range = if req_info.is_get {
            if req_info.range_header_count > 1 {
                None
            } else if req_info.invalid_range_header {
                return http::Response::builder()
                    .status(StatusCode::RANGE_NOT_SATISFIABLE)
                    .header("Content-Range", format!("bytes */{}", file_size))
                    .header("Accept-Ranges", "bytes")
                    .body(Self::empty_body())
                    .map_err(|e| {
                        server_err!(ServerErrorCode::IOError, "Failed to build response: {}", e)
                    });
            } else {
                match req_info.range_header.as_deref() {
                    Some(range_str) => {
                        if !Self::can_apply_if_range(req_info, etag.as_deref()) {
                            None
                        } else {
                            match self.classify_range(range_str, file_size) {
                                DirRangeRequest::Apply { start, end } => Some((start, end)),
                                DirRangeRequest::Ignore => None,
                                DirRangeRequest::Reject => {
                                    return http::Response::builder()
                                        .status(StatusCode::RANGE_NOT_SATISFIABLE)
                                        .header("Content-Range", format!("bytes */{}", file_size))
                                        .header("Accept-Ranges", "bytes")
                                        .body(Self::empty_body())
                                        .map_err(|e| {
                                            server_err!(
                                                ServerErrorCode::IOError,
                                                "Failed to build response: {}",
                                                e
                                            )
                                        });
                                }
                            }
                        }
                    }
                    None => None,
                }
            }
        } else {
            None
        };

        // Handle applicable Range requests
        if let Some((start, end)) = applied_range {
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

            let body = if req_info.is_head {
                Self::empty_body()
            } else {
                self.range_body(file, start, content_length).await?
            };
            return response_builder.body(body).map_err(|e| {
                server_err!(ServerErrorCode::IOError, "Failed to build response: {}", e)
            });
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

        let body = if req_info.is_head {
            Self::empty_body()
        } else {
            self.full_or_stream_body(file, file_size).await?
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
    ) -> http::Response<UnsyncBoxBody<Bytes, ServerError>> {
        http::Response::builder()
            .status(status)
            .body(
                Full::new(body.into())
                    .map_err(|e| match e {})
                    .boxed_unsync(),
            )
            .unwrap()
    }

    fn build_html_response(
        &self,
        status: StatusCode,
        body: String,
    ) -> http::Response<UnsyncBoxBody<Bytes, ServerError>> {
        http::Response::builder()
            .status(status)
            .header("Content-Type", "text/html; charset=utf-8")
            .body(
                Full::new(Bytes::from(body))
                    .map_err(|e| match e {})
                    .boxed_unsync(),
            )
            .unwrap()
    }

    async fn ensure_path_in_root(&self, path: &Path) -> ServerResult<PathBuf> {
        let canonical_path = Self::fs_canonicalize(self.file_io_mode, path).await.map_err(|e| {
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
    ) -> ServerResult<http::Response<UnsyncBoxBody<Bytes, ServerError>>> {
        let req_base = if req_path.ends_with('/') {
            req_path.to_string()
        } else {
            format!("{}/", req_path)
        };

        let mut entries = self.collect_directory_entries(dir_path, req_base).await?;
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

    async fn collect_directory_entries(
        &self,
        dir_path: &Path,
        req_base: String,
    ) -> ServerResult<Vec<DirectoryListingEntry>> {
        if self.file_io_mode == DirServerFileIoMode::Sync {
            let mut entries = Vec::new();
            for entry in std::fs::read_dir(dir_path).map_err(|e| {
                server_err!(
                    ServerErrorCode::IOError,
                    "Failed to read directory: {}",
                    e
                )
            })? {
                let entry = entry.map_err(|e| {
                    server_err!(
                        ServerErrorCode::IOError,
                        "Failed to read directory entry: {}",
                        e
                    )
                })?;
                let name = entry.file_name().to_string_lossy().to_string();
                let metadata = entry.metadata().map_err(|e| {
                    server_err!(ServerErrorCode::IOError, "Failed to read metadata: {}", e)
                })?;
                if let Some(entry) = DirServer::directory_listing_entry(name, metadata, &req_base) {
                    entries.push(entry);
                }
            }
            return Ok(entries);
        }

        let mut entries = Vec::new();
        let mut read_dir = tokio::fs::read_dir(dir_path).await.map_err(|e| {
            server_err!(ServerErrorCode::IOError, "Failed to read directory: {}", e)
        })?;

        while let Some(entry) = read_dir.next_entry().await.map_err(|e| {
            server_err!(
                ServerErrorCode::IOError,
                "Failed to read directory entry: {}",
                e
            )
        })? {
            let file_name = entry.file_name();
            let name = file_name.to_string_lossy().to_string();
            let metadata = entry.metadata().await.map_err(|e| {
                server_err!(ServerErrorCode::IOError, "Failed to read metadata: {}", e)
            })?;
            if let Some(entry) = Self::directory_listing_entry(name, metadata, &req_base) {
                entries.push(entry);
            }
        }

        Ok(entries)
    }

    fn directory_listing_entry(
        name: String,
        metadata: std::fs::Metadata,
        req_base: &str,
    ) -> Option<DirectoryListingEntry> {
        if name.starts_with('.') {
            return None;
        }

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

        Some(DirectoryListingEntry {
            name,
            href,
            is_dir,
            modified,
            size,
        })
    }
}

struct DirectoryListingEntry {
    name: String,
    href: String,
    is_dir: bool,
    modified: String,
    size: String,
}

#[async_trait::async_trait(?Send)]
impl HttpServer for DirServer {
    async fn serve_request(
        &self,
        req: http::Request<UnsyncBoxBody<Bytes, ServerError>>,
        _info: StreamInfo,
    ) -> ServerResult<http::Response<UnsyncBoxBody<Bytes, ServerError>>> {
        let req_path = req.uri().path();
        let req_method = req.method();
        let req_info = DirFileRequestInfo::from_request(&req);

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
        let mut file_stat_from_open = false;
        let mut file_stat = match self.open_path_in_root_cached(&file_path).await {
            Ok(opened_file) => match self
                .serve_opened_file_if_regular(&file_path, opened_file, &req_info, "Serving file")
                .await?
            {
                Ok(response) => return Ok(response),
                Err(opened_file) => {
                    opened_canonical_path = opened_file.canonical_path;
                    file_stat_from_open = true;
                    DirPathStat::Opened(opened_file.metadata)
                }
            },
            Err(e) if e.kind() == ErrorKind::PermissionDenied => {
                return Ok(self.path_forbidden_response(&file_path));
            }
            Err(e) if e.kind() == ErrorKind::NotFound => DirPathStat::Error(e),
            Err(_) => {
                let file_stat = self.stat_path(&file_path).await;
                if file_stat.is_file() {
                    info!("Serving file: {:?}", file_path);
                    return self.serve_file(&file_path, &req_info).await;
                }
                file_stat
            }
        };
        if file_stat.exists() {
            file_path = match opened_canonical_path.take() {
                Some(path) => path,
                None => match self.ensure_path_in_root(&file_path).await {
                    Ok(path) => path,
                    Err(_) => {
                        return Ok(self.path_forbidden_response(&file_path));
                    }
                },
            };
            if !file_stat_from_open {
                file_stat = match file_stat {
                    DirPathStat::Found(_) | DirPathStat::Opened(_) => file_stat,
                    DirPathStat::Error(_) => self.stat_path(&file_path).await,
                };
            }
        }

        if file_stat.is_dir() {
            let index_path = file_path.join(&self.index_file);
            match self.open_path_in_root_cached(&index_path).await {
                Ok(opened_file) => {
                    if let Ok(response) = self
                        .serve_opened_file_if_regular(
                            &index_path,
                            opened_file,
                            &req_info,
                            "Serving index file",
                        )
                        .await?
                    {
                        return Ok(response);
                    }
                }
                Err(e) if e.kind() == ErrorKind::PermissionDenied => {
                    return Ok(self.path_forbidden_response(&index_path));
                }
                Err(_) => {}
            }

            if self.autoindex {
                info!("Serving directory listing: {:?}", file_path);
                return self.serve_directory_listing(req_path, &file_path).await;
            }
        }

        warn!("File not found: {:?}", file_path);
        if let Some(fallback_file) = &self.fallback_file {
            let fallback_path = self.root_dir.join(fallback_file);
            match self.open_path_in_root_cached(&fallback_path).await {
                Ok(opened_file) => {
                    if let Ok(response) = self
                        .serve_opened_file_if_regular(
                            &fallback_path,
                            opened_file,
                            &req_info,
                            "Fallback to file",
                        )
                        .await?
                    {
                        return Ok(response);
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
        Ok(self.build_text_response(StatusCode::NOT_FOUND, "Not found"))
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_io_mode: Option<DirServerFileIoMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_read_buffer_size: Option<usize>,
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
        if let Some(file_io_mode) = config.file_io_mode {
            builder = builder.file_io_mode(file_io_mode);
        }
        if let Some(file_read_buffer_size) = config.file_read_buffer_size {
            builder = builder.file_read_buffer_size(file_read_buffer_size);
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

    #[test]
    fn test_large_file_stream_buffer_uses_configured_size() {
        assert_eq!(
            DirServer::file_stream_buffer_size(DEFAULT_FILE_READ_BUFFER_SIZE, 128 * 1024),
            64 * 1024
        );
        assert_eq!(DEFAULT_FILE_READ_BUFFER_SIZE, 64 * 1024);
    }

    #[test]
    fn test_large_file_stream_buffer_does_not_exceed_content_length() {
        assert_eq!(
            DirServer::file_stream_buffer_size(DEFAULT_FILE_READ_BUFFER_SIZE, 8 * 1024),
            8 * 1024
        );
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

    #[tokio::test(flavor = "local")]
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

        tokio::task::spawn_local(async move {
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

    #[tokio::test(flavor = "local")]
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

        tokio::task::spawn_local(async move {
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
            file_io_mode: None,
            file_read_buffer_size: None,
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

    #[test]
    fn test_dir_server_file_io_mode_config_deserializes_values() {
        let config: DirServerConfig = serde_json::from_value(serde_json::json!({
            "id": "test",
            "type": "dir",
            "root_path": "/tmp",
            "file_io_mode": "sync"
        }))
        .unwrap();
        assert_eq!(config.file_io_mode, Some(DirServerFileIoMode::Sync));

        let config: DirServerConfig = serde_json::from_value(serde_json::json!({
            "id": "test",
            "type": "dir",
            "root_path": "/tmp",
            "file_io_mode": "async"
        }))
        .unwrap();
        assert_eq!(config.file_io_mode, Some(DirServerFileIoMode::Async));
    }

    #[test]
    fn test_dir_server_file_io_mode_rejects_invalid_value() {
        let result = serde_json::from_value::<DirServerConfig>(serde_json::json!({
            "id": "test",
            "type": "dir",
            "root_path": "/tmp",
            "file_io_mode": "blocking"
        }));
        assert!(result.is_err());
    }

    #[test]
    fn test_dir_server_file_read_buffer_size_config_deserializes_value() {
        let config: DirServerConfig = serde_json::from_value(serde_json::json!({
            "id": "test",
            "type": "dir",
            "root_path": "/tmp",
            "file_read_buffer_size": 131072
        }))
        .unwrap();

        assert_eq!(config.file_read_buffer_size, Some(128 * 1024));
    }

    #[tokio::test]
    async fn test_dir_server_file_io_mode_defaults_to_sync() {
        let temp_dir = tempfile::tempdir().unwrap();
        let server = DirServer::builder()
            .id("test")
            .root_path(temp_dir.path().to_path_buf())
            .build()
            .await
            .unwrap();

        assert_eq!(server.file_io_mode, DirServerFileIoMode::Sync);
        assert_eq!(server.file_read_buffer_size, DEFAULT_FILE_READ_BUFFER_SIZE);
    }

    #[tokio::test]
    async fn test_dir_server_file_read_buffer_size_config_selects_value() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config: DirServerConfig = serde_json::from_value(serde_json::json!({
            "id": "test",
            "type": "dir",
            "root_path": temp_dir.path().to_string_lossy(),
            "file_read_buffer_size": 131072
        }))
        .unwrap();

        let server = DirServer::builder()
            .id(config.id)
            .root_path(PathBuf::from(config.root_path))
            .file_read_buffer_size(config.file_read_buffer_size.unwrap())
            .build()
            .await
            .unwrap();
        assert_eq!(server.file_read_buffer_size, 128 * 1024);
    }

    #[tokio::test]
    async fn test_dir_server_file_read_buffer_size_rejects_zero() {
        let temp_dir = tempfile::tempdir().unwrap();
        let result = DirServer::builder()
            .id("test")
            .root_path(temp_dir.path().to_path_buf())
            .file_read_buffer_size(0)
            .build()
            .await;

        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(e.code(), ServerErrorCode::InvalidConfig);
        }
    }

    #[tokio::test]
    async fn test_dir_server_file_io_mode_config_selects_sync() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config: DirServerConfig = serde_json::from_value(serde_json::json!({
            "id": "test",
            "type": "dir",
            "root_path": temp_dir.path().to_string_lossy(),
            "file_io_mode": "sync"
        }))
        .unwrap();

        let server = DirServer::builder()
            .id(config.id)
            .root_path(PathBuf::from(config.root_path))
            .file_io_mode(config.file_io_mode.unwrap())
            .build()
            .await
            .unwrap();
        assert_eq!(server.file_io_mode, DirServerFileIoMode::Sync);
    }

    #[tokio::test]
    async fn test_dir_server_sync_file_io_serves_full_range_and_head() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("sync.txt");
        tokio::fs::write(&file_path, b"0123456789abcdef")
            .await
            .unwrap();

        let server = DirServer::builder()
            .id("test")
            .root_path(temp_dir.path().to_path_buf())
            .file_io_mode(DirServerFileIoMode::Sync)
            .file_read_buffer_size(4)
            .build()
            .await
            .unwrap();

        let req = http::Request::builder()
            .method("GET")
            .uri("http://localhost/sync.txt")
            .body(
                Full::new(Bytes::new())
                    .map_err(|e| match e {})
                    .boxed_unsync(),
            )
            .unwrap();
        let req_info = DirFileRequestInfo::from_request(&req);
        let resp = server.serve_file(&file_path, &req_info).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get("Content-Length").unwrap(), "16");
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body.as_ref(), b"0123456789abcdef");

        let req = http::Request::builder()
            .method("GET")
            .uri("http://localhost/sync.txt")
            .header(RANGE, "bytes=4-9")
            .body(
                Full::new(Bytes::new())
                    .map_err(|e| match e {})
                    .boxed_unsync(),
            )
            .unwrap();
        let req_info = DirFileRequestInfo::from_request(&req);
        let resp = server.serve_file(&file_path, &req_info).await.unwrap();
        assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(resp.headers().get("Content-Length").unwrap(), "6");
        assert_eq!(
            resp.headers().get("Content-Range").unwrap(),
            "bytes 4-9/16"
        );
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body.as_ref(), b"456789");

        let req = http::Request::builder()
            .method("HEAD")
            .uri("http://localhost/sync.txt")
            .body(
                Full::new(Bytes::new())
                    .map_err(|e| match e {})
                    .boxed_unsync(),
            )
            .unwrap();
        let req_info = DirFileRequestInfo::from_request(&req);
        let resp = server.serve_file(&file_path, &req_info).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get("Content-Length").unwrap(), "16");
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert!(body.is_empty());
    }

    async fn serve_range_request(
        server: &DirServer,
        file_path: &Path,
        range: &str,
    ) -> http::Response<UnsyncBoxBody<Bytes, ServerError>> {
        serve_range_request_with(server, file_path, "GET", Some(range), None).await
    }

    async fn serve_range_request_with(
        server: &DirServer,
        file_path: &Path,
        method: &str,
        range: Option<&str>,
        if_range: Option<&str>,
    ) -> http::Response<UnsyncBoxBody<Bytes, ServerError>> {
        let mut builder = http::Request::builder()
            .method(method)
            .uri("http://localhost/range.txt");
        if let Some(range) = range {
            builder = builder.header(RANGE, range);
        }
        if let Some(if_range) = if_range {
            builder = builder.header(IF_RANGE, if_range);
        }
        let req = builder
            .body(
                Full::new(Bytes::new())
                    .map_err(|e| match e {})
                    .boxed_unsync(),
            )
            .unwrap();
        let req_info = DirFileRequestInfo::from_request(&req);
        server.serve_file(file_path, &req_info).await.unwrap()
    }

    async fn serve_duplicate_range_request(
        server: &DirServer,
        file_path: &Path,
    ) -> http::Response<UnsyncBoxBody<Bytes, ServerError>> {
        let mut req = http::Request::builder()
            .method("GET")
            .uri("http://localhost/range.txt")
            .body(
                Full::new(Bytes::new())
                    .map_err(|e| match e {})
                    .boxed_unsync(),
            )
            .unwrap();
        req.headers_mut()
            .append(RANGE, http::HeaderValue::from_static("bytes=0-1"));
        req.headers_mut()
            .append(RANGE, http::HeaderValue::from_static("bytes=4-5"));

        let req_info = DirFileRequestInfo::from_request(&req);
        server.serve_file(file_path, &req_info).await.unwrap()
    }

    async fn serve_invalid_range_header_request(
        server: &DirServer,
        file_path: &Path,
    ) -> http::Response<UnsyncBoxBody<Bytes, ServerError>> {
        let mut req = http::Request::builder()
            .method("GET")
            .uri("http://localhost/range.txt")
            .body(
                Full::new(Bytes::new())
                    .map_err(|e| match e {})
                    .boxed_unsync(),
            )
            .unwrap();
        req.headers_mut()
            .insert(RANGE, http::HeaderValue::from_bytes(b"bytes=\xff").unwrap());

        let req_info = DirFileRequestInfo::from_request(&req);
        server.serve_file(file_path, &req_info).await.unwrap()
    }

    #[tokio::test]
    async fn test_dir_server_range_parses_supported_forms_and_rejects_invalid_ranges() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("range.txt");
        tokio::fs::write(&file_path, b"0123456789abcdef")
            .await
            .unwrap();

        let server = DirServer::builder()
            .id("test")
            .root_path(temp_dir.path().to_path_buf())
            .file_read_buffer_size(4)
            .build()
            .await
            .unwrap();

        let resp = serve_range_request(&server, &file_path, "bytes=4-9").await;
        assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(resp.headers().get("Content-Range").unwrap(), "bytes 4-9/16");
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body.as_ref(), b"456789");

        let resp = serve_range_request(&server, &file_path, "bytes=4-").await;
        assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            resp.headers().get("Content-Range").unwrap(),
            "bytes 4-15/16"
        );
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body.as_ref(), b"456789abcdef");

        let resp = serve_range_request(&server, &file_path, "bytes=-4").await;
        assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            resp.headers().get("Content-Range").unwrap(),
            "bytes 12-15/16"
        );
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body.as_ref(), b"cdef");

        for (range, content_range, expected_body) in [
            ("Bytes=4-9", "bytes 4-9/16", b"456789".as_slice()),
            ("BYTES=-4", "bytes 12-15/16", b"cdef".as_slice()),
            ("bytes= 4-9", "bytes 4-9/16", b"456789".as_slice()),
            ("bytes=4-9 ", "bytes 4-9/16", b"456789".as_slice()),
            ("bytes=\t4-9\t", "bytes 4-9/16", b"456789".as_slice()),
        ] {
            let resp = serve_range_request(&server, &file_path, range).await;
            assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
            assert_eq!(resp.headers().get("Content-Range").unwrap(), content_range);
            let body = resp.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(body.as_ref(), expected_body);
        }

        for range in [
            "bytes",
            "bytes 4-9",
            "bytes=4 -9",
            "bytes=4- 9",
            "bytes=16-",
            "bytes=abc",
            "bytes=0-1,abc",
        ] {
            let resp = serve_range_request(&server, &file_path, range).await;
            assert_eq!(resp.status(), StatusCode::RANGE_NOT_SATISFIABLE);
            assert_eq!(resp.headers().get("Content-Range").unwrap(), "bytes */16");
            let body = resp.into_body().collect().await.unwrap().to_bytes();
            assert!(body.is_empty());
        }

        let resp = serve_invalid_range_header_request(&server, &file_path).await;
        assert_eq!(resp.status(), StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(resp.headers().get("Content-Range").unwrap(), "bytes */16");
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert!(body.is_empty());

        for range in ["items=4-9", "bytes=0-1,4-5", "bytes=0-1, 4-5"] {
            let resp = serve_range_request(&server, &file_path, range).await;
            assert_eq!(resp.status(), StatusCode::OK);
            assert_eq!(resp.headers().get("Content-Length").unwrap(), "16");
            assert!(resp.headers().get("Content-Range").is_none());
            let body = resp.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(body.as_ref(), b"0123456789abcdef");
        }

        let resp = serve_duplicate_range_request(&server, &file_path).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get("Content-Length").unwrap(), "16");
        assert!(resp.headers().get("Content-Range").is_none());
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body.as_ref(), b"0123456789abcdef");

        let resp =
            serve_range_request_with(&server, &file_path, "HEAD", Some("bytes=4-9"), None).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get("Content-Length").unwrap(), "16");
        assert!(resp.headers().get("Content-Range").is_none());
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert!(body.is_empty());

        let resp = serve_range_request_with(&server, &file_path, "GET", None, None).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let etag = resp
            .headers()
            .get(ETAG)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        let last_modified = resp
            .headers()
            .get(LAST_MODIFIED)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body.as_ref(), b"0123456789abcdef");

        let resp =
            serve_range_request_with(&server, &file_path, "GET", Some("bytes=4-9"), Some(&etag))
                .await;
        assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(resp.headers().get("Content-Range").unwrap(), "bytes 4-9/16");
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body.as_ref(), b"456789");

        let resp = serve_range_request_with(
            &server,
            &file_path,
            "GET",
            Some("bytes=4-9"),
            Some(&last_modified),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get("Content-Length").unwrap(), "16");
        assert!(resp.headers().get("Content-Range").is_none());
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body.as_ref(), b"0123456789abcdef");

        for if_range in ["\"not-matching-etag\"", "Wed, 21 Oct 2015 07:28:00 GMT"] {
            let resp = serve_range_request_with(
                &server,
                &file_path,
                "GET",
                Some("bytes=4-9"),
                Some(if_range),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::OK);
            assert_eq!(resp.headers().get("Content-Length").unwrap(), "16");
            assert!(resp.headers().get("Content-Range").is_none());
            let body = resp.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(body.as_ref(), b"0123456789abcdef");
        }

        let resp = serve_range_request_with(
            &server,
            &file_path,
            "GET",
            Some("bytes=abc"),
            Some("\"not-matching-etag\""),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get("Content-Length").unwrap(), "16");
        assert!(resp.headers().get("Content-Range").is_none());
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body.as_ref(), b"0123456789abcdef");

        let empty_file_path = temp_dir.path().join("empty-range.txt");
        tokio::fs::write(&empty_file_path, b"").await.unwrap();
        for range in ["bytes=0-", "bytes=-1", "bytes=abc"] {
            let resp = serve_range_request(&server, &empty_file_path, range).await;
            assert_eq!(resp.status(), StatusCode::OK);
            assert_eq!(resp.headers().get("Content-Length").unwrap(), "0");
            assert!(resp.headers().get("Content-Range").is_none());
            let body = resp.into_body().collect().await.unwrap().to_bytes();
            assert!(body.is_empty());
        }
    }

    #[tokio::test]
    async fn test_dir_server_sync_file_io_uses_sync_stat_open_and_listing() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("sync-listing.txt");
        std::fs::write(&file_path, b"sync-listing").unwrap();
        std::fs::write(temp_dir.path().join(".hidden.txt"), b"hidden").unwrap();

        let server = DirServer::builder()
            .id("test")
            .root_path(temp_dir.path().to_path_buf())
            .file_io_mode(DirServerFileIoMode::Sync)
            .build()
            .await
            .unwrap();

        let stat = server.stat_path(&file_path).await;
        assert!(stat.is_file());
        assert_eq!(stat.metadata().unwrap().len(), 12);

        let opened = server.open_file_for_read(&file_path).await.unwrap();
        assert!(opened.metadata.is_file());
        assert!(matches!(opened.file, Some(DirReadFile::Sync(_))));

        let entries = server
            .collect_directory_entries(temp_dir.path(), "/".to_string())
            .await
            .unwrap();
        assert!(entries.iter().any(|entry| entry.name == "sync-listing.txt"));
        assert!(!entries.iter().any(|entry| entry.name == ".hidden.txt"));
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

    #[tokio::test]
    async fn test_open_file_cache_min_uses_and_error_cache() {
        let temp_dir = tempfile::tempdir().unwrap();
        let missing_path = temp_dir.path().join("missing.txt");
        let cache = OpenFileCache::new(OpenFileCacheSettings {
            max: 16,
            inactive: Duration::from_secs(60),
            valid: Duration::from_secs(60),
            min_uses: 2,
            errors: true,
        });

        assert!(cache
            .stat_path(&missing_path, DirServerFileIoMode::Async)
            .await
            .is_not_found());
        assert!(cache.stat_cache.get(&missing_path).is_none());

        assert!(cache
            .stat_path(&missing_path, DirServerFileIoMode::Async)
            .await
            .is_not_found());
        assert!(cache.stat_cache.get(&missing_path).is_some());
    }

    #[tokio::test]
    async fn test_open_file_cache_keeps_only_path_metadata_after_min_uses() {
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
        assert_eq!(
            cache
                .stat_path(&file_path, DirServerFileIoMode::Async)
                .await
                .metadata()
                .unwrap()
                .len(),
            6
        );
        assert!(cache.stat_cache.get(&file_path).is_none());
        let cached = cache.stat_path(&file_path, DirServerFileIoMode::Async).await;
        assert_eq!(cached.metadata().unwrap().len(), 6);
        assert!(cache.stat_cache.get(&file_path).is_some());
    }

    #[tokio::test]
    async fn test_open_file_cache_promotes_cached_stat_without_file_handle() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("cached.txt");
        std::fs::write(&file_path, b"old").unwrap();

        let stat = DirPathStat::from_path(&file_path, DirServerFileIoMode::Async).await;
        std::fs::write(&file_path, b"new-content").unwrap();

        let cached = CachedPathStat::from(&stat).into_stat();
        assert_eq!(cached.metadata().unwrap().len(), 3);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_open_file_cache_records_linux_opened_file_metadata() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("opened.txt");
        tokio::fs::write(&file_path, b"opened-meta").await.unwrap();

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
        assert!(cache.stat_cache.get(&file_path).is_none());

        let opened = server.open_file_for_read(&file_path).await.unwrap();
        assert!(opened.metadata.is_file());

        let cached = cache.stat_cache.get(&file_path).unwrap().into_stat();
        assert_eq!(cached.metadata().unwrap().len(), 11);
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
            .body(
                Full::new(Bytes::new())
                    .map_err(|e| match e {})
                    .boxed_unsync(),
            )
            .unwrap();
        let req_info = DirFileRequestInfo::from_request(&req);
        let resp = server.serve_file(&file_path, &req_info).await.unwrap();

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
            .body(
                Full::new(Bytes::new())
                    .map_err(|e| match e {})
                    .boxed_unsync(),
            )
            .unwrap();
        let req_info = DirFileRequestInfo::from_request(&req);
        let resp = server.serve_file(&file_path, &req_info).await.unwrap();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body.as_ref(), b"old-body");

        tokio::fs::write(&file_path, b"new-body").await.unwrap();

        let req = http::Request::builder()
            .method("GET")
            .uri("http://localhost/cached-body.txt")
            .body(
                Full::new(Bytes::new())
                    .map_err(|e| match e {})
                    .boxed_unsync(),
            )
            .unwrap();
        let req_info = DirFileRequestInfo::from_request(&req);
        let resp = server.serve_file(&file_path, &req_info).await.unwrap();
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
            .body(
                Full::new(Bytes::new())
                    .map_err(|e| match e {})
                    .boxed_unsync(),
            )
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
            .body(
                Full::new(Bytes::new())
                    .map_err(|e| match e {})
                    .boxed_unsync(),
            )
            .unwrap();
        let resp = server
            .serve_request(req, StreamInfo::default())
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_open_file_cache_errors_off_does_not_cache_missing_path() {
        let temp_dir = tempfile::tempdir().unwrap();
        let missing_path = temp_dir.path().join("missing.txt");
        let cache = OpenFileCache::new(OpenFileCacheSettings {
            max: 16,
            inactive: Duration::from_secs(60),
            valid: Duration::from_secs(60),
            min_uses: 1,
            errors: false,
        });

        assert!(cache
            .stat_path(&missing_path, DirServerFileIoMode::Async)
            .await
            .is_not_found());
        assert!(cache.stat_cache.get(&missing_path).is_none());
    }

    #[tokio::test(flavor = "local")]
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

        tokio::task::spawn_local(async move {
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

    #[tokio::test(flavor = "local")]
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

        tokio::task::spawn_local(async move {
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

    #[tokio::test(flavor = "local")]
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
        tokio::task::spawn_local(async move {
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
        let _ = first_resp.collect().await.unwrap().to_bytes();

        let second_req = http::Request::builder()
            .method("GET")
            .uri("http://localhost/etag.txt")
            .header(IF_NONE_MATCH, etag)
            .body(Full::new(Bytes::new()))
            .unwrap();

        let second_resp = sender.send_request(second_req).await.unwrap();
        assert_eq!(second_resp.status(), StatusCode::NOT_MODIFIED);
    }

    #[tokio::test(flavor = "local")]
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
        tokio::task::spawn_local(async move {
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

    #[tokio::test(flavor = "local")]
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
        tokio::task::spawn_local(async move {
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

    #[tokio::test(flavor = "local")]
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
        tokio::task::spawn_local(async move {
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
