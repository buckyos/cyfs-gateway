use std::collections::HashMap;
use std::io;

use async_compression::tokio::bufread::{
    BrotliDecoder, BrotliEncoder, DeflateDecoder, DeflateEncoder, GzipDecoder, GzipEncoder,
};
use async_compression::Level;
use futures_util::TryStreamExt;
use http::{header, HeaderMap, HeaderValue, Method, StatusCode, Version};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, StreamBody};
use hyper::body::{Bytes, Frame};
use regex::Regex;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, BufReader, ReadBuf};
use tokio_util::io::{ReaderStream, StreamReader};

use super::{server_err, ServerError, ServerErrorCode, ServerResult};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Encoding {
    Gzip,
    Brotli,
    Deflate,
}

impl Encoding {
    pub fn as_str(&self) -> &'static str {
        match self {
            Encoding::Gzip => "gzip",
            Encoding::Brotli => "br",
            Encoding::Deflate => "deflate",
        }
    }
}

#[derive(Clone)]
pub struct CompressionRequestInfo {
    pub method: Method,
    pub version: Version,
    pub accept_encoding: Option<String>,
    pub user_agent: Option<String>,
}

impl CompressionRequestInfo {
    pub fn from_request(req: &http::Request<BoxBody<Bytes, ServerError>>) -> Self {
        let accept_encoding = req
            .headers()
            .get(header::ACCEPT_ENCODING)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.to_string());
        let user_agent = req
            .headers()
            .get(header::USER_AGENT)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.to_string());
        Self {
            method: req.method().clone(),
            version: req.version(),
            accept_encoding,
            user_agent,
        }
    }
}

#[derive(Clone)]
pub struct HttpCompressionSettings {
    pub gzip: bool,
    pub gzip_request: bool,
    pub gzip_types: Vec<String>,
    pub gzip_min_length: u64,
    pub gzip_comp_level: u32,
    pub gzip_http_version: Version,
    pub gzip_vary: bool,
    pub gzip_disable: Option<Regex>,
    pub brotli: bool,
    pub brotli_types: Vec<String>,
    pub brotli_min_length: u64,
    pub brotli_comp_level: u32,
}

struct SyncRead<R> {
    inner: std::sync::Mutex<R>,
}

impl<R> SyncRead<R> {
    fn new(reader: R) -> Self {
        Self {
            inner: std::sync::Mutex::new(reader),
        }
    }
}

impl<R: AsyncRead + Unpin + Send> AsyncRead for SyncRead<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut guard = match self.inner.lock() {
            Ok(guard) => guard,
            Err(_) => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Reader mutex poisoned",
                )))
            }
        };
        Pin::new(&mut *guard).poll_read(cx, buf)
    }
}

impl Default for HttpCompressionSettings {
    fn default() -> Self {
        Self {
            gzip: false,
            gzip_request: false,
            gzip_types: Vec::new(),
            gzip_min_length: 20,
            gzip_comp_level: 1,
            gzip_http_version: Version::HTTP_11,
            gzip_vary: false,
            gzip_disable: None,
            brotli: false,
            brotli_types: Vec::new(),
            brotli_min_length: 20,
            brotli_comp_level: 4,
        }
    }
}

pub fn apply_request_decompression(
    req: http::Request<BoxBody<Bytes, ServerError>>,
    settings: &HttpCompressionSettings,
) -> Result<http::Request<BoxBody<Bytes, ServerError>>, ServerError> {
    if !settings.gzip_request {
        return Ok(req);
    }

    let encoding_header = match req.headers().get(header::CONTENT_ENCODING) {
        Some(value) => value,
        None => return Ok(req),
    };

    let encoding_value = encoding_header.to_str().map_err(|_| {
        server_err!(
            ServerErrorCode::BadRequest,
            "Invalid Content-Encoding header"
        )
    })?;

    let encodings = parse_content_encoding(encoding_value);
    if encodings.is_empty() {
        return Ok(req);
    }

    let mut decoded = Vec::new();
    for encoding in encodings {
        match encoding.as_str() {
            "identity" => {}
            "gzip" => decoded.push(Encoding::Gzip),
            "deflate" => decoded.push(Encoding::Deflate),
            "br" => decoded.push(Encoding::Brotli),
            _ => {
                return Err(server_err!(
                    ServerErrorCode::BadRequest,
                    "Unsupported Content-Encoding: {}",
                    encoding
                ))
            }
        }
    }

    if decoded.is_empty() {
        return Ok(req);
    }

    let (mut parts, body) = req.into_parts();
    let decoded_body = decode_body(body, &decoded);
    parts.headers.remove(header::CONTENT_ENCODING);
    parts.headers.remove(header::CONTENT_LENGTH);
    Ok(http::Request::from_parts(parts, decoded_body))
}

pub fn apply_response_compression(
    resp: http::Response<BoxBody<Bytes, ServerError>>,
    req_info: &CompressionRequestInfo,
    settings: &HttpCompressionSettings,
) -> ServerResult<http::Response<BoxBody<Bytes, ServerError>>> {
    let (mut parts, body) = resp.into_parts();

    if settings.gzip_vary {
        ensure_vary_accept_encoding(&mut parts.headers);
    }

    if !settings.gzip && !settings.brotli {
        return Ok(http::Response::from_parts(parts, body));
    }

    if parts.headers.contains_key(header::CONTENT_ENCODING) {
        return Ok(http::Response::from_parts(parts, body));
    }

    if req_info.method == Method::HEAD {
        return Ok(http::Response::from_parts(parts, body));
    }

    if !is_status_compressible(parts.status) {
        return Ok(http::Response::from_parts(parts, body));
    }

    if !allows_http_version(req_info.version, settings.gzip_http_version) {
        return Ok(http::Response::from_parts(parts, body));
    }

    if let Some(disable) = &settings.gzip_disable {
        if let Some(ua) = &req_info.user_agent {
            if disable.is_match(ua) {
                return Ok(http::Response::from_parts(parts, body));
            }
        }
    }

    let encoding = select_encoding(req_info.accept_encoding.as_deref(), settings);
    let encoding = match encoding {
        Some(encoding) => encoding,
        None => return Ok(http::Response::from_parts(parts, body)),
    };

    let (types, min_length, comp_level) = match encoding {
        Encoding::Brotli => (
            &settings.brotli_types,
            settings.brotli_min_length,
            settings.brotli_comp_level,
        ),
        Encoding::Gzip => (
            &settings.gzip_types,
            settings.gzip_min_length,
            settings.gzip_comp_level,
        ),
        Encoding::Deflate => (
            &settings.gzip_types,
            settings.gzip_min_length,
            settings.gzip_comp_level,
        ),
    };

    if !is_content_type_allowed(parts.headers.get(header::CONTENT_TYPE), types) {
        return Ok(http::Response::from_parts(parts, body));
    }

    if let Some(length) = content_length(&parts.headers) {
        if length < min_length {
            return Ok(http::Response::from_parts(parts, body));
        }
    }

    let compressed_body = encode_body(body, &encoding, comp_level);
    parts.headers.remove(header::CONTENT_LENGTH);
    parts.headers.insert(
        header::CONTENT_ENCODING,
        HeaderValue::from_static(encoding.as_str()),
    );

    Ok(http::Response::from_parts(parts, compressed_body))
}

fn parse_content_encoding(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(|item| item.trim())
        .filter(|item| !item.is_empty())
        .map(|item| item.to_ascii_lowercase())
        .collect()
}

fn decode_body(
    body: BoxBody<Bytes, ServerError>,
    encodings: &[Encoding],
) -> BoxBody<Bytes, ServerError> {
    let stream = body.into_data_stream().map_err(map_body_err);
    let reader = StreamReader::new(stream);
    let mut reader: Box<dyn AsyncRead + Send + Unpin> = Box::new(reader);

    for encoding in encodings.iter().rev() {
        reader = wrap_decoder(reader, encoding);
    }

    let stream = ReaderStream::new(SyncRead::new(reader));
    let stream_body = StreamBody::new(stream.map_ok(Frame::data));
    BodyExt::map_err(stream_body, |e| {
        server_err!(ServerErrorCode::StreamError, "Stream error: {}", e)
    })
    .boxed()
}

fn encode_body(
    body: BoxBody<Bytes, ServerError>,
    encoding: &Encoding,
    comp_level: u32,
) -> BoxBody<Bytes, ServerError> {
    let stream = body.into_data_stream().map_err(map_body_err);
    let reader = StreamReader::new(stream);
    let mut reader: Box<dyn AsyncRead + Send + Unpin> = Box::new(reader);
    let level = Level::Precise(comp_level as i32);

    reader = match encoding {
        Encoding::Gzip => Box::new(GzipEncoder::with_quality(BufReader::new(reader), level)),
        Encoding::Brotli => Box::new(BrotliEncoder::with_quality(BufReader::new(reader), level)),
        Encoding::Deflate => Box::new(DeflateEncoder::with_quality(BufReader::new(reader), level)),
    };

    let stream = ReaderStream::new(SyncRead::new(reader));
    let stream_body = StreamBody::new(stream.map_ok(Frame::data));
    BodyExt::map_err(stream_body, |e| {
        server_err!(ServerErrorCode::StreamError, "Stream error: {}", e)
    })
    .boxed()
}

fn wrap_decoder(
    reader: Box<dyn AsyncRead + Send + Unpin>,
    encoding: &Encoding,
) -> Box<dyn AsyncRead + Send + Unpin> {
    match encoding {
        Encoding::Gzip => Box::new(GzipDecoder::new(BufReader::new(reader))),
        Encoding::Brotli => Box::new(BrotliDecoder::new(BufReader::new(reader))),
        Encoding::Deflate => Box::new(DeflateDecoder::new(BufReader::new(reader))),
    }
}

fn map_body_err(err: ServerError) -> io::Error {
    io::Error::new(io::ErrorKind::Other, err.msg().to_string())
}

fn parse_accept_encoding(value: &str) -> HashMap<String, f32> {
    let mut result = HashMap::new();
    for item in value.split(',') {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }

        let mut parts = item.split(';');
        let encoding = parts.next().unwrap().trim().to_ascii_lowercase();
        let mut quality = 1.0_f32;
        for param in parts {
            let param = param.trim();
            if let Some(qval) = param.strip_prefix("q=") {
                if let Ok(value) = qval.parse::<f32>() {
                    quality = value;
                }
            }
        }

        result
            .entry(encoding)
            .and_modify(|v| {
                if quality > *v {
                    *v = quality;
                }
            })
            .or_insert(quality);
    }
    result
}

fn select_encoding(
    accept_encoding: Option<&str>,
    settings: &HttpCompressionSettings,
) -> Option<Encoding> {
    let accept_encoding = accept_encoding?;
    let map = parse_accept_encoding(accept_encoding);

    let mut candidates = Vec::new();
    if settings.brotli {
        candidates.push(Encoding::Brotli);
    }
    if settings.gzip {
        candidates.push(Encoding::Gzip);
    }

    for encoding in candidates {
        if is_encoding_acceptable(&map, encoding.as_str()) {
            return Some(encoding);
        }
    }
    None
}

fn is_encoding_acceptable(map: &HashMap<String, f32>, encoding: &str) -> bool {
    if let Some(q) = map.get(encoding) {
        return *q > 0.0;
    }
    if let Some(q) = map.get("*") {
        return *q > 0.0;
    }
    false
}

fn allows_http_version(req_version: Version, min_version: Version) -> bool {
    version_rank(req_version) >= version_rank(min_version)
}

fn version_rank(version: Version) -> u8 {
    match version {
        Version::HTTP_09 => 0,
        Version::HTTP_10 => 1,
        Version::HTTP_11 => 2,
        Version::HTTP_2 => 3,
        Version::HTTP_3 => 4,
        _ => 255,
    }
}

fn is_status_compressible(status: StatusCode) -> bool {
    if status.is_informational() {
        return false;
    }
    status != StatusCode::NO_CONTENT && status != StatusCode::NOT_MODIFIED
}

fn content_length(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
}

fn is_content_type_allowed(content_type: Option<&HeaderValue>, extra_types: &[String]) -> bool {
    let content_type = match content_type {
        Some(value) => value,
        None => return false,
    };

    let content_type = match content_type.to_str() {
        Ok(value) => value,
        Err(_) => return false,
    };
    let content_type = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();

    if content_type.is_empty() {
        return false;
    }

    if content_type == "text/html" {
        return true;
    }

    for pattern in extra_types {
        if matches_mime(pattern, &content_type) {
            return true;
        }
    }

    false
}

fn matches_mime(pattern: &str, content_type: &str) -> bool {
    let pattern = pattern.trim().to_ascii_lowercase();
    if pattern.is_empty() {
        return false;
    }
    if pattern == "*/*" || pattern == "*" {
        return true;
    }

    let (p_type, p_sub) = match pattern.split_once('/') {
        Some(parts) => parts,
        None => return pattern == content_type,
    };
    let (c_type, c_sub) = match content_type.split_once('/') {
        Some(parts) => parts,
        None => return false,
    };

    (p_type == "*" || p_type == c_type) && (p_sub == "*" || p_sub == c_sub)
}

fn ensure_vary_accept_encoding(headers: &mut HeaderMap) {
    let value = headers
        .get(header::VARY)
        .and_then(|value| value.to_str().ok());

    let needs_append = match value {
        Some(current) => !current
            .split(',')
            .any(|item| item.trim().eq_ignore_ascii_case("accept-encoding")),
        None => true,
    };

    if !needs_append {
        return;
    }

    let new_value = match value {
        Some(current) if !current.trim().is_empty() => {
            format!("{}, Accept-Encoding", current.trim())
        }
        _ => "Accept-Encoding".to_string(),
    };

    if let Ok(value) = HeaderValue::from_str(&new_value) {
        headers.insert(header::VARY, value);
    } else {
        headers.insert(header::VARY, HeaderValue::from_static("Accept-Encoding"));
    }
}
