mod io_dump_frame;
mod io_dump_size;
mod io_dump_writer;

pub use io_dump_frame::*;
pub use io_dump_size::*;
pub use io_dump_writer::*;

use buckyos_kit::get_buckyos_service_data_dir;
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Mutex as AsyncMutex;

const DEFAULT_ROTATE_SIZE: u64 = 1024 * 1024 * 1024;
const DEFAULT_CONN_UPLOAD_BYTES: u64 = 1024 * 1024;
const DEFAULT_CONN_DOWNLOAD_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Debug)]
pub struct IoDumpConnLimit {
    pub max_upload_bytes: u64,
    pub max_download_bytes: u64,
}

#[derive(Clone, Debug)]
pub struct IoDumpStackConfig {
    pub stack_id: String,
    pub writer: IoDumpWriter,
    pub conn_limit: IoDumpConnLimit,
}

lazy_static::lazy_static! {
    static ref WRITER_MAP: AsyncMutex<HashMap<PathBuf, (IoDumpResolvedConfig, IoDumpWriter)>> = AsyncMutex::new(HashMap::new());
}

pub async fn create_io_dump_stack_config(
    stack_id: &str,
    io_dump_file: Option<&str>,
    io_dump_rotate_size: Option<&str>,
    io_dump_rotate_max_files: Option<u32>,
    io_dump_max_upload_bytes_per_conn: Option<&str>,
    io_dump_max_download_bytes_per_conn: Option<&str>,
) -> Result<Option<IoDumpStackConfig>, String> {
    let Some(file) = io_dump_file else {
        return Ok(None);
    };

    let rotate_size = match io_dump_rotate_size {
        Some(v) => parse_io_dump_size(v)?,
        None => DEFAULT_ROTATE_SIZE,
    };
    let max_upload_bytes = match io_dump_max_upload_bytes_per_conn {
        Some(v) => parse_io_dump_size(v)?,
        None => DEFAULT_CONN_UPLOAD_BYTES,
    };
    let max_download_bytes = match io_dump_max_download_bytes_per_conn {
        Some(v) => parse_io_dump_size(v)?,
        None => DEFAULT_CONN_DOWNLOAD_BYTES,
    };

    let resolved = IoDumpResolvedConfig {
        file_path: resolve_io_dump_path(file),
        rotate_size,
        rotate_max_files: io_dump_rotate_max_files,
    };
    let writer = get_or_create_writer(stack_id, resolved.clone()).await;
    Ok(Some(IoDumpStackConfig {
        stack_id: stack_id.to_string(),
        writer,
        conn_limit: IoDumpConnLimit {
            max_upload_bytes,
            max_download_bytes,
        },
    }))
}

async fn get_or_create_writer(stack_id: &str, config: IoDumpResolvedConfig) -> IoDumpWriter {
    let mut map = WRITER_MAP.lock().await;
    if let Some((old_cfg, writer)) = map.get(&config.file_path) {
        if old_cfg != &config {
            log::warn!(
                "io dump file '{}' already has writer created with rotate config {:?}; stack '{}' config {:?} is ignored",
                config.file_path.display(),
                old_cfg,
                stack_id,
                config
            );
        }
        return writer.clone();
    }
    let writer = IoDumpWriter::new(config.clone());
    map.insert(config.file_path.clone(), (config, writer.clone()));
    writer
}

pub fn resolve_io_dump_path(io_dump_file: &str) -> PathBuf {
    let path = Path::new(io_dump_file);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        get_buckyos_service_data_dir("cyfs_gateway")
            .join("dumps")
            .join(path)
    }
}

pub struct DumpStream<S> {
    inner: S,
    session: Arc<Mutex<IoDumpSession>>,
}

impl<S> DumpStream<S> {
    pub fn new(inner: S, stack_config: IoDumpStackConfig, src_addr: String, dst_addr: String) -> Self {
        Self {
            inner,
            session: Arc::new(Mutex::new(IoDumpSession::new(
                stack_config,
                src_addr,
                dst_addr,
            ))),
        }
    }

    pub fn raw_stream(&self) -> &S {
        &self.inner
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for DumpStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let prev_len = buf.filled().len();
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let curr_len = buf.filled().len();
                if curr_len > prev_len {
                    let data = &buf.filled()[prev_len..curr_len];
                    if let Ok(mut session) = self.session.lock() {
                        session.on_upload(data);
                    }
                }
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for DumpStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        match Pin::new(&mut self.inner).poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => {
                if n > 0 {
                    if let Ok(mut session) = self.session.lock() {
                        session.on_download(&buf[..n]);
                    }
                }
                Poll::Ready(Ok(n))
            }
            other => other,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl<S> Drop for DumpStream<S> {
    fn drop(&mut self) {
        if let Ok(mut session) = self.session.lock() {
            session.on_close();
        }
    }
}

pub fn dump_single_datagram(
    stack_config: &IoDumpStackConfig,
    src_addr: String,
    dst_addr: String,
    upload: Vec<u8>,
    download: Vec<u8>,
) {
    let frame = IoDumpFrame {
        connect_timestamp_ms: IoDumpFrame::now_ms(),
        write_timestamp_ms: IoDumpFrame::now_ms(),
        src_ip: src_addr,
        dst_ip: dst_addr,
        upload,
        download,
    };
    stack_config.writer.submit(frame);
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SessionMode {
    Unknown,
    HttpByRequest,
    RawPair,
}

struct IoDumpSession {
    stack: IoDumpStackConfig,
    src_addr: String,
    dst_addr: String,
    connect_timestamp_ms: u64,
    mode: SessionMode,

    upload_dumped_bytes: u64,
    download_dumped_bytes: u64,

    raw_upload: Vec<u8>,
    raw_download: Vec<u8>,

    pending_requests: VecDeque<Vec<u8>>,
    pending_responses: VecDeque<Vec<u8>>,
    upload_http_buf: Vec<u8>,
    download_http_buf: Vec<u8>,
    closed: bool,
}

impl IoDumpSession {
    fn new(stack: IoDumpStackConfig, src_addr: String, dst_addr: String) -> Self {
        Self {
            stack,
            src_addr,
            dst_addr,
            connect_timestamp_ms: IoDumpFrame::now_ms(),
            mode: SessionMode::Unknown,
            upload_dumped_bytes: 0,
            download_dumped_bytes: 0,
            raw_upload: Vec::new(),
            raw_download: Vec::new(),
            pending_requests: VecDeque::new(),
            pending_responses: VecDeque::new(),
            upload_http_buf: Vec::new(),
            download_http_buf: Vec::new(),
            closed: false,
        }
    }

    fn on_upload(&mut self, data: &[u8]) {
        let Some((data, reached_limit)) = self.take_upload_with_limit(data) else {
            return;
        };

        match self.mode {
            SessionMode::Unknown => {
                self.raw_upload.extend_from_slice(data.as_slice());
                self.try_resolve_unknown_mode();
            }
            SessionMode::HttpByRequest => {
                self.upload_http_buf.extend_from_slice(data.as_slice());
                while let Some(msg) = try_parse_http_message(&mut self.upload_http_buf) {
                    self.pending_requests.push_back(msg);
                    self.try_emit_http_pairs();
                }
            }
            SessionMode::RawPair => {
                self.raw_upload.extend_from_slice(data.as_slice());
            }
        }

        if reached_limit {
            self.flush_on_limit();
        }
    }

    fn on_download(&mut self, data: &[u8]) {
        let Some((data, reached_limit)) = self.take_download_with_limit(data) else {
            return;
        };

        match self.mode {
            SessionMode::Unknown => {
                self.raw_download.extend_from_slice(data.as_slice());
                self.try_resolve_unknown_mode();
            }
            SessionMode::HttpByRequest => {
                self.download_http_buf.extend_from_slice(data.as_slice());
                while let Some(msg) = try_parse_http_message(&mut self.download_http_buf) {
                    self.pending_responses.push_back(msg);
                    self.try_emit_http_pairs();
                }
            }
            SessionMode::RawPair => {
                self.raw_download.extend_from_slice(data.as_slice());
            }
        }

        if reached_limit {
            self.flush_on_limit();
        }
    }

    fn take_upload_with_limit(&mut self, data: &[u8]) -> Option<(Vec<u8>, bool)> {
        if self.upload_dumped_bytes >= self.stack.conn_limit.max_upload_bytes {
            return None;
        }
        let remain = self.stack.conn_limit.max_upload_bytes - self.upload_dumped_bytes;
        let taken = data[..std::cmp::min(data.len(), remain as usize)].to_vec();
        self.upload_dumped_bytes += taken.len() as u64;
        let reached_limit = self.upload_dumped_bytes >= self.stack.conn_limit.max_upload_bytes;
        Some((taken, reached_limit))
    }

    fn take_download_with_limit(&mut self, data: &[u8]) -> Option<(Vec<u8>, bool)> {
        if self.download_dumped_bytes >= self.stack.conn_limit.max_download_bytes {
            return None;
        }
        let remain = self.stack.conn_limit.max_download_bytes - self.download_dumped_bytes;
        let taken = data[..std::cmp::min(data.len(), remain as usize)].to_vec();
        self.download_dumped_bytes += taken.len() as u64;
        let reached_limit = self.download_dumped_bytes >= self.stack.conn_limit.max_download_bytes;
        Some((taken, reached_limit))
    }

    fn flush_raw(&mut self) {
        let upload = std::mem::take(&mut self.raw_upload);
        let download = std::mem::take(&mut self.raw_download);
        if upload.is_empty() && download.is_empty() {
            return;
        }
        self.emit_frame(upload, download);
    }

    fn try_emit_http_pairs(&mut self) {
        loop {
            let req = self.pending_requests.pop_front();
            let resp = self.pending_responses.pop_front();
            match (req, resp) {
                (Some(upload), Some(download)) => self.emit_frame(upload, download),
                (Some(upload), None) => {
                    self.pending_requests.push_front(upload);
                    break;
                }
                (None, Some(download)) => {
                    self.pending_responses.push_front(download);
                    break;
                }
                (None, None) => break,
            }
        }
    }

    fn flush_on_limit(&mut self) {
        if self.mode == SessionMode::Unknown {
            self.try_resolve_unknown_mode();
        }
        match self.mode {
            SessionMode::HttpByRequest => self.flush_http_remaining(),
            SessionMode::RawPair | SessionMode::Unknown => self.flush_raw(),
        }
    }

    fn on_close(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;
        if self.mode == SessionMode::Unknown {
            self.try_resolve_unknown_mode();
        }
        match self.mode {
            SessionMode::HttpByRequest => self.flush_http_remaining(),
            SessionMode::RawPair | SessionMode::Unknown => self.flush_raw(),
        }
    }

    fn try_resolve_unknown_mode(&mut self) {
        if looks_like_http_request(self.raw_upload.as_slice())
            || looks_like_http_response(self.raw_download.as_slice())
        {
            self.mode = SessionMode::HttpByRequest;
            self.upload_http_buf.extend_from_slice(self.raw_upload.as_slice());
            self.download_http_buf
                .extend_from_slice(self.raw_download.as_slice());
            self.raw_upload.clear();
            self.raw_download.clear();
            while let Some(msg) = try_parse_http_message(&mut self.upload_http_buf) {
                self.pending_requests.push_back(msg);
            }
            while let Some(msg) = try_parse_http_message(&mut self.download_http_buf) {
                self.pending_responses.push_back(msg);
            }
            self.try_emit_http_pairs();
            return;
        }

        if !maybe_http_request(self.raw_upload.as_slice()) && !maybe_http_response(self.raw_download.as_slice()) {
            self.mode = SessionMode::RawPair;
        }
    }

    fn flush_http_remaining(&mut self) {
        while let Some(msg) = try_parse_http_message(&mut self.upload_http_buf) {
            self.pending_requests.push_back(msg);
        }
        while let Some(msg) = try_parse_http_message(&mut self.download_http_buf) {
            self.pending_responses.push_back(msg);
        }

        if !self.upload_http_buf.is_empty() {
            self.pending_requests.push_back(std::mem::take(&mut self.upload_http_buf));
        }
        if !self.download_http_buf.is_empty() {
            self.pending_responses.push_back(std::mem::take(&mut self.download_http_buf));
        }

        self.try_emit_http_pairs();

        loop {
            let upload = self.pending_requests.pop_front().unwrap_or_default();
            let download = self.pending_responses.pop_front().unwrap_or_default();
            if upload.is_empty() && download.is_empty() {
                break;
            }
            self.emit_frame(upload, download);
        }
    }

    fn emit_frame(&self, upload: Vec<u8>, download: Vec<u8>) {
        self.stack.writer.submit(IoDumpFrame {
            connect_timestamp_ms: self.connect_timestamp_ms,
            write_timestamp_ms: IoDumpFrame::now_ms(),
            src_ip: self.src_addr.clone(),
            dst_ip: self.dst_addr.clone(),
            upload,
            download,
        });
    }
}

fn looks_like_http_request(bytes: &[u8]) -> bool {
    const METHODS: [&[u8]; 9] = [
        b"GET ",
        b"POST ",
        b"PUT ",
        b"DELETE ",
        b"PATCH ",
        b"HEAD ",
        b"OPTIONS ",
        b"CONNECT ",
        b"TRACE ",
    ];
    METHODS.iter().any(|m| bytes.starts_with(m))
}

fn maybe_http_request(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return true;
    }
    const METHODS: [&[u8]; 9] = [
        b"GET ",
        b"POST ",
        b"PUT ",
        b"DELETE ",
        b"PATCH ",
        b"HEAD ",
        b"OPTIONS ",
        b"CONNECT ",
        b"TRACE ",
    ];
    METHODS.iter().any(|m| {
        let probe_len = std::cmp::min(bytes.len(), m.len());
        m.starts_with(&bytes[..probe_len])
    })
}

fn looks_like_http_response(bytes: &[u8]) -> bool {
    bytes.starts_with(b"HTTP/")
}

fn maybe_http_response(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return true;
    }
    let probe_len = std::cmp::min(bytes.len(), 5);
    b"HTTP/".starts_with(&bytes[..probe_len])
}

fn try_parse_http_message(buf: &mut Vec<u8>) -> Option<Vec<u8>> {
    let header_end = find_subsequence(buf, b"\r\n\r\n")?;
    let body_start = header_end + 4;
    let header = &buf[..header_end];
    let content_len = parse_content_length(header).unwrap_or(0);
    let full_len = body_start + content_len;
    if buf.len() < full_len {
        return None;
    }
    let msg = buf[..full_len].to_vec();
    buf.drain(..full_len);
    Some(msg)
}

fn parse_content_length(header: &[u8]) -> Option<usize> {
    let text = String::from_utf8_lossy(header);
    for line in text.lines() {
        if let Some((name, value)) = line.split_once(':')
            && name.trim().eq_ignore_ascii_case("content-length")
        {
            if let Ok(v) = value.trim().parse::<usize>() {
                return Some(v);
            }
        }
    }
    None
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedIoDumpFrame {
    pub connect_timestamp_ms: u64,
    pub write_timestamp_ms: u64,
    pub src_ip: String,
    pub dst_ip: String,
    pub upload: Vec<u8>,
    pub download: Vec<u8>,
}

#[cfg(test)]
pub fn decode_io_dump_frames(mut data: &[u8]) -> Result<Vec<DecodedIoDumpFrame>, String> {
    let mut frames = Vec::new();
    while !data.is_empty() {
        if data.len() < 9 {
            return Err("truncated frame header".to_string());
        }
        if &data[0..4] != b"CGDP" {
            return Err("invalid frame magic".to_string());
        }
        if data[4] != 1 {
            return Err(format!("unsupported frame version: {}", data[4]));
        }
        let frame_len = u32::from_le_bytes(data[5..9].try_into().unwrap()) as usize;
        if frame_len < 9 || frame_len > data.len() {
            return Err("invalid frame length".to_string());
        }

        let frame = &data[9..frame_len];
        let mut offset = 0usize;

        fn take<'a>(buf: &'a [u8], offset: &mut usize, len: usize) -> Result<&'a [u8], String> {
            if *offset + len > buf.len() {
                return Err("truncated frame payload".to_string());
            }
            let part = &buf[*offset..*offset + len];
            *offset += len;
            Ok(part)
        }

        let connect_timestamp_ms = u64::from_le_bytes(take(frame, &mut offset, 8)?.try_into().unwrap());
        let write_timestamp_ms = u64::from_le_bytes(take(frame, &mut offset, 8)?.try_into().unwrap());

        let src_len = u16::from_le_bytes(take(frame, &mut offset, 2)?.try_into().unwrap()) as usize;
        let src_ip = String::from_utf8(take(frame, &mut offset, src_len)?.to_vec())
            .map_err(|_| "invalid src ip utf8".to_string())?;

        let dst_len = u16::from_le_bytes(take(frame, &mut offset, 2)?.try_into().unwrap()) as usize;
        let dst_ip = String::from_utf8(take(frame, &mut offset, dst_len)?.to_vec())
            .map_err(|_| "invalid dst ip utf8".to_string())?;

        let upload_len = u32::from_le_bytes(take(frame, &mut offset, 4)?.try_into().unwrap()) as usize;
        let upload = take(frame, &mut offset, upload_len)?.to_vec();

        let download_len = u32::from_le_bytes(take(frame, &mut offset, 4)?.try_into().unwrap()) as usize;
        let download = take(frame, &mut offset, download_len)?.to_vec();

        frames.push(DecodedIoDumpFrame {
            connect_timestamp_ms,
            write_timestamp_ms,
            src_ip,
            dst_ip,
            upload,
            download,
        });

        data = &data[frame_len..];
    }

    Ok(frames)
}
