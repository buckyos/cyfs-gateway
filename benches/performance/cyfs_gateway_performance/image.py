from __future__ import annotations

import json
from pathlib import Path

from .model import BenchmarkPlan, CommandPlan, ConfigError


FIXTURE_CARGO_TOML = """[package]
name = "cyfs-perf-reverse-proxy-fixture"
version = "0.1.0"
edition = "2021"

[workspace]

[dependencies]
bytes = "1"
futures-util = "0.3"
http-body-util = "0.1"
hyper = { version = "1", features = ["http1", "server"] }
hyper-util = { version = "0.1", features = ["tokio"] }
libc = "0.2"
tokio = { version = "1", features = ["fs", "io-util", "macros", "net", "rt-multi-thread"] }
tokio-util = { version = "0.7", features = ["io"] }
"""


FIXTURE_MAIN_RS = r'''use bytes::Bytes;
use futures_util::TryStreamExt;
use http_body_util::combinators::{BoxBody, UnsyncBoxBody};
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::header::{ETAG, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED, RANGE};
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::convert::Infallible;
use std::ffi::CString;
use std::env;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncSeekExt, SeekFrom};
use tokio::net::TcpListener as TokioTcpListener;
use tokio_util::io::ReaderStream;

const HYPER_STATIC_SMALL_FILE_INLINE_LIMIT: u64 = 64 * 1024;
const HYPER_STATIC_MIN_STREAM_BUFFER_SIZE: usize = 16 * 1024;
const HYPER_STATIC_MAX_STREAM_BUFFER_SIZE: usize = 64 * 1024;
type HyperStaticBody = BoxBody<Bytes, std::io::Error>;

struct HyperStaticRoot {
    root_dir_file: std::fs::File,
}

struct OpenedHyperStaticFile {
    file: tokio::fs::File,
    metadata: std::fs::Metadata,
}

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let http_addr = listen_addr("HTTP_PORT", "0.0.0.0:8080");
    let stream_addr = listen_addr("STREAM_PORT", "0.0.0.0:9000");
    let hyper_static_addr = listen_addr("HYPER_STATIC_PORT", "0.0.0.0:10080");
    let static_root = env::var("STATIC_ROOT").unwrap_or_else(|_| "/etc/cyfs-perf/static".to_owned());
    let hyper_static_enabled = env::var("HYPER_STATIC_ENABLED")
        .map(|value| value != "0")
        .unwrap_or(true);

    let http_thread = thread::spawn(move || serve_http(&http_addr));
    let stream_thread = thread::spawn(move || serve_stream(&stream_addr));
    let hyper_thread = if hyper_static_enabled {
        Some(thread::spawn(move || serve_hyper_static(&hyper_static_addr, PathBuf::from(static_root))))
    } else {
        None
    };

    http_thread.join().expect("http fixture thread panicked")?;
    stream_thread.join().expect("stream fixture thread panicked")?;
    if let Some(hyper_thread) = hyper_thread {
        hyper_thread.join().expect("hyper static fixture thread panicked")?;
    }
    Ok(())
}

fn listen_addr(port_var: &str, default_addr: &str) -> String {
    match env::var(port_var) {
        Ok(port) if port.contains(':') => port,
        Ok(port) if !port.is_empty() => format!("0.0.0.0:{port}"),
        _ => default_addr.to_owned(),
    }
}

fn serve_http(addr: &str) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                thread::spawn(move || {
                    let _ = handle_http(stream);
                });
            }
            Err(err) => eprintln!("http accept failed: {err}"),
        }
    }
    Ok(())
}

fn handle_http(mut stream: TcpStream) -> std::io::Result<()> {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 4096];
    let header_end;

    loop {
        let read = stream.read(&mut buffer)?;
        if read == 0 {
            return Ok(());
        }
        request.extend_from_slice(&buffer[..read]);
        if let Some(pos) = find_header_end(&request) {
            header_end = pos;
            break;
        }
        if request.len() > 1024 * 1024 {
            header_end = request.len();
            break;
        }
    }

    let content_length = parse_content_length(&request[..header_end]).unwrap_or(0);
    while request.len() < header_end + content_length {
        let read = stream.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        request.extend_from_slice(&buffer[..read]);
    }

    let received_body = if request.len() > header_end {
        &request[header_end..]
    } else {
        &[]
    };
    let response_body = if received_body.is_empty() {
        request.as_slice()
    } else {
        received_body
    };
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response_body.len()
    )?;
    stream.write_all(response_body)?;
    stream.flush()?;
    let _ = stream.shutdown(Shutdown::Both);
    Ok(())
}

fn serve_stream(addr: &str) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                thread::spawn(move || {
                    let _ = handle_stream(stream);
                });
            }
            Err(err) => eprintln!("stream accept failed: {err}"),
        }
    }
    Ok(())
}

fn handle_stream(mut stream: TcpStream) -> std::io::Result<()> {
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = stream.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        stream.write_all(&buffer[..read])?;
    }
    let _ = stream.shutdown(Shutdown::Both);
    Ok(())
}

fn find_header_end(data: &[u8]) -> Option<usize> {
    data.windows(4).position(|window| window == b"\r\n\r\n").map(|pos| pos + 4)
}

fn parse_content_length(headers: &[u8]) -> Option<usize> {
    let text = std::str::from_utf8(headers).ok()?;
    for line in text.lines() {
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                return value.trim().parse().ok();
            }
        }
    }
    None
}

fn serve_hyper_static(
    addr: &str,
    static_root: PathBuf,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let static_root = static_root.canonicalize()?;
    let root_dir_file = std::fs::File::open(&static_root)?;
    let static_root = Arc::new(HyperStaticRoot { root_dir_file });
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async move {
        let listener = TokioTcpListener::bind(addr).await?;
        loop {
            let (stream, _) = listener.accept().await?;
            stream.set_nodelay(true)?;
            let static_root = static_root.clone();
            tokio::spawn(async move {
                let service = service_fn(move |request| {
                    let static_root = static_root.clone();
                    async move { serve_hyper_static_request(request, static_root).await }
                });
                if let Err(err) = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await
                {
                    eprintln!("hyper static connection failed: {err}");
                }
            });
        }
    })
}

async fn serve_hyper_static_request(
    request: Request<Incoming>,
    static_root: Arc<HyperStaticRoot>,
) -> Result<Response<HyperStaticBody>, Infallible> {
    if request.method() != Method::GET && request.method() != Method::HEAD {
        return Ok(text_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed"));
    }

    let Some(path) = normalized_request_path(request.uri().path()) else {
        return Ok(text_response(StatusCode::FORBIDDEN, "forbidden"));
    };
    let file_path = PathBuf::from(path.trim_start_matches('/'));
    let opened = match open_hyper_static_file(&static_root, &file_path) {
        Ok(opened) if opened.metadata.is_file() => opened,
        Ok(_) => return Ok(text_response(StatusCode::NOT_FOUND, "not found")),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(text_response(StatusCode::NOT_FOUND, "not found"));
        }
        Err(err) => {
            eprintln!("hyper static openat failed for {}: {err}", file_path.display());
            return Ok(text_response(StatusCode::INTERNAL_SERVER_ERROR, "open error"));
        }
    };

    let content_length = opened.metadata.len();
    let response_body = if request.method() == Method::HEAD {
        empty_body()
    } else {
        match hyper_static_body(opened.file, content_length).await {
            Ok(body) => body,
            Err(err) => {
                eprintln!("hyper static read failed for {}: {err}", file_path.display());
                return Ok(text_response(StatusCode::INTERNAL_SERVER_ERROR, "read error"));
            }
        }
    };

    Ok(ok_response(content_length, response_body))
}

fn open_hyper_static_file(
    static_root: &HyperStaticRoot,
    file_path: &Path,
) -> std::io::Result<OpenedHyperStaticFile> {
    let path = CString::new(path_bytes_without_nul(file_path)?).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path contains interior nul byte")
    })?;
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.flags = (libc::O_RDONLY | libc::O_CLOEXEC) as u64;
    how.resolve = (libc::RESOLVE_BENEATH | libc::RESOLVE_NO_MAGICLINKS) as u64;

    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            static_root.root_dir_file.as_raw_fd(),
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
    Ok(OpenedHyperStaticFile {
        file: tokio::fs::File::from_std(file),
        metadata,
    })
}

fn path_bytes_without_nul(file_path: &Path) -> std::io::Result<Vec<u8>> {
    use std::os::unix::ffi::OsStrExt;

    if file_path.as_os_str().is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "empty static file path",
        ));
    }
    Ok(file_path.as_os_str().as_bytes().to_vec())
}

fn hyper_static_stream_buffer_size(content_length: u64) -> usize {
    content_length.clamp(
        HYPER_STATIC_MIN_STREAM_BUFFER_SIZE as u64,
        HYPER_STATIC_MAX_STREAM_BUFFER_SIZE as u64,
    ) as usize
}

async fn hyper_static_body(
    mut file: tokio::fs::File,
    content_length: u64,
) -> std::io::Result<HyperStaticBody> {
    if content_length <= HYPER_STATIC_SMALL_FILE_INLINE_LIMIT {
        let mut body = Vec::with_capacity(content_length as usize);
        file.read_to_end(&mut body).await?;
        return Ok(Full::new(Bytes::from(body))
            .map_err(|err| match err {})
            .boxed());
    }

    let stream = ReaderStream::with_capacity(file, hyper_static_stream_buffer_size(content_length))
        .map_ok(Frame::data);
    Ok(BodyExt::map_err(StreamBody::new(stream), |err| err).boxed())
}

fn ok_response(content_length: u64, body: HyperStaticBody) -> Response<HyperStaticBody> {
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/octet-stream")
        .header("Content-Length", content_length.to_string())
        .body(body)
        .unwrap_or_else(|_| text_response(StatusCode::INTERNAL_SERVER_ERROR, "response error"))
}

fn normalized_request_path(path: &str) -> Option<String> {
    if path == "/" {
        return Some("/index.html".to_owned());
    }
    let mut normalized = PathBuf::from("/");
    for component in Path::new(path).components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(part) => normalized.push(part),
            Component::ParentDir | Component::Prefix(_) => return None,
        }
    }
    normalized.to_str().map(|path| path.to_owned())
}

fn empty_body() -> HyperStaticBody {
    Full::new(Bytes::new())
        .map_err(|err| match err {})
        .boxed()
}

fn text_response(status: StatusCode, text: &'static str) -> Response<HyperStaticBody> {
    Response::builder()
        .status(status)
        .header("Content-Length", text.len().to_string())
        .body(
            Full::new(Bytes::from_static(text.as_bytes()))
                .map_err(|err| match err {})
                .boxed()
        )
        .unwrap()
}
'''


REUSEPORT_STATIC_CARGO_TOML = """[package]
name = "cyfs-perf-reuseport-static-fixture"
version = "0.1.0"
edition = "2021"

[workspace]

[dependencies]
bytes = "1"
futures-util = "0.3"
http-body-util = "0.1"
hyper = { version = "1", features = ["http1", "server"] }
hyper-util = { version = "0.1", features = ["tokio"] }
libc = "0.2"
sfo-reuseport = "0.3"
socket2 = "0.6"
tokio = { version = "1", features = ["fs", "io-util", "net", "rt"] }
tokio-uring = "0.5"
tokio-util = { version = "0.7", features = ["io"] }
"""


REUSEPORT_STATIC_MAIN_RS = r'''use bytes::Bytes;
use futures_util::TryStreamExt;
use http_body_util::combinators::{BoxBody, UnsyncBoxBody};
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::header::{ETAG, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED, RANGE};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use sfo_reuseport::{
    Error as ReuseportError, ServerRuntime, ServerRuntimeConfig, SocketOptions, TcpServer,
    TcpServiceConfig, TransparentMode,
};
use socket2::{Domain, Protocol, Socket, Type};
use std::convert::Infallible;
use std::env;
use std::ffi::CString;
use std::net::{SocketAddr, ToSocketAddrs};
use std::os::fd::{AsRawFd, FromRawFd};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::thread;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_uring::net::{TcpListener as UringTcpListener, TcpStream as UringTcpStream};
use tokio_util::io::ReaderStream;

const HYPER_STATIC_SMALL_FILE_INLINE_LIMIT: u64 = 64 * 1024;
const HYPER_STATIC_MIN_STREAM_BUFFER_SIZE: usize = 16 * 1024;
const HYPER_STATIC_MAX_STREAM_BUFFER_SIZE: usize = 64 * 1024;
const URING_STATIC_BODY_WRITE_CHUNK_SIZE: usize = 64 * 1024;
type HyperStaticBody = BoxBody<Bytes, std::io::Error>;

struct HyperStaticRoot {
    root_dir_file: std::fs::File,
}

struct UringStaticRoot {
    root_dir_file: std::fs::File,
}

#[derive(Clone, Copy)]
enum StaticRuntimeMode {
    Tokio,
    TokioCustom,
    TokioUring,
}

struct OpenedHyperStaticFile {
    file: tokio::fs::File,
    metadata: std::fs::Metadata,
}

struct OpenedStdStaticFile {
    file: std::fs::File,
    metadata: std::fs::Metadata,
}

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr = listen_addr("REUSEPORT_STATIC_PORT", "0.0.0.0:10081");
    let addr = resolve_addr(&addr)?;
    let static_root = env::var("STATIC_ROOT").unwrap_or_else(|_| "/etc/cyfs-perf/static".to_owned());
    let static_root = PathBuf::from(static_root).canonicalize()?;
    let threads = configured_threads()?;
    let runtime_mode = configured_runtime_mode()?;

    match runtime_mode {
        StaticRuntimeMode::Tokio | StaticRuntimeMode::TokioCustom => {
            serve_sfo_reuseport_static(addr, static_root, threads, runtime_mode)?;
        }
        StaticRuntimeMode::TokioUring => {
            let mut handles = Vec::with_capacity(threads);
            for thread_index in 0..threads {
                let static_root = static_root.clone();
                handles.push(thread::spawn(move || serve_tokio_uring_reuseport_worker(thread_index, addr, static_root)));
            }

            for handle in handles {
                handle.join().expect("reuseport static tokio_uring worker panicked")?;
            }
        }
    }
    Ok(())
}

fn listen_addr(port_var: &str, default_addr: &str) -> String {
    match env::var(port_var) {
        Ok(port) if port.contains(':') => port,
        Ok(port) if !port.is_empty() => format!("0.0.0.0:{port}"),
        _ => default_addr.to_owned(),
    }
}

fn configured_threads() -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
    if let Ok(raw) = env::var("REUSEPORT_STATIC_THREADS") {
        let parsed = raw.parse::<usize>()?;
        if parsed > 0 {
            return Ok(parsed);
        }
    }
    Ok(thread::available_parallelism().map(|value| value.get()).unwrap_or(1))
}

fn configured_runtime_mode() -> Result<StaticRuntimeMode, Box<dyn std::error::Error + Send + Sync>> {
    match env::var("REUSEPORT_STATIC_RUNTIME")
        .unwrap_or_else(|_| "tokio".to_owned())
        .as_str()
    {
        "tokio" => Ok(StaticRuntimeMode::Tokio),
        "tokio_custom" => Ok(StaticRuntimeMode::TokioCustom),
        "tokio_uring" => Ok(StaticRuntimeMode::TokioUring),
        other => Err(format!("unsupported REUSEPORT_STATIC_RUNTIME: {other}").into()),
    }
}

fn resolve_addr(addr: &str) -> std::io::Result<SocketAddr> {
    addr.to_socket_addrs()?
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "empty listen address"))
}

fn serve_sfo_reuseport_static(
    addr: SocketAddr,
    static_root: PathBuf,
    threads: usize,
    runtime_mode: StaticRuntimeMode,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let runtime = ServerRuntime::start(ServerRuntimeConfig::new().with_workers(threads))?;
    let service_config = TcpServiceConfig::new(addr).with_socket_options(SocketOptions {
        reuse_address: true,
        ipv4_transparent: TransparentMode::Disabled,
        ipv6_transparent: TransparentMode::Disabled,
    });

    let _server = match runtime_mode {
        StaticRuntimeMode::Tokio => {
            let root_dir_file = std::fs::File::open(&static_root)?;
            let static_root = Arc::new(HyperStaticRoot { root_dir_file });
            TcpServer::serve(&runtime, service_config, move |stream| {
                let static_root = static_root.clone();
                async move {
                    stream.set_nodelay(true)?;
                    let service = service_fn(move |request| {
                        let static_root = static_root.clone();
                        async move { serve_hyper_static_request(request, static_root).await }
                    });
                    http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await
                        .map_err(|err| ReuseportError::Handler(format!("reuseport static connection failed: {err}")))
                }
            })?
        }
        StaticRuntimeMode::TokioCustom => {
            let root_dir_file = std::fs::File::open(&static_root)?;
            let static_root = Arc::new(HyperStaticRoot { root_dir_file });
            TcpServer::serve(&runtime, service_config, move |mut stream| {
                let static_root = static_root.clone();
                async move {
                    stream.set_nodelay(true)?;
                    serve_tokio_custom_static_connection(&mut stream, static_root)
                        .await
                        .map_err(|err| ReuseportError::Handler(format!("reuseport static tokio_custom connection failed: {err}")))
                }
            })?
        }
        StaticRuntimeMode::TokioUring => unreachable!("tokio_uring keeps its dedicated listener path"),
    };
    eprintln!("reuseport static {runtime_mode_name} server listening on {addr} with {threads} sfo-reuseport workers", runtime_mode_name = runtime_mode.name());
    loop {
        thread::park();
    }
}

impl StaticRuntimeMode {
    fn name(self) -> &'static str {
        match self {
            StaticRuntimeMode::Tokio => "tokio",
            StaticRuntimeMode::TokioCustom => "tokio_custom",
            StaticRuntimeMode::TokioUring => "tokio_uring",
        }
    }
}

fn serve_tokio_uring_reuseport_worker(
    thread_index: usize,
    addr: SocketAddr,
    static_root: PathBuf,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let root_dir_file = std::fs::File::open(&static_root)?;
    let static_root = Arc::new(UringStaticRoot { root_dir_file });
    let std_listener = bind_reuseport_listener(addr)?;

    tokio_uring::start(async move {
        let listener = UringTcpListener::from_std(std_listener);
        eprintln!("reuseport static tokio_uring worker {thread_index} listening on {addr}");
        loop {
            let (stream, _) = listener.accept().await?;
            stream.set_nodelay(true)?;
            let static_root = static_root.clone();
            tokio_uring::spawn(async move {
                if let Err(err) = serve_uring_static_connection(stream, static_root).await {
                    eprintln!("reuseport static tokio_uring connection failed: {err}");
                }
            });
        }
    })
}

fn bind_reuseport_listener(addr: SocketAddr) -> std::io::Result<std::net::TcpListener> {
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(4096)?;
    Ok(socket.into())
}

async fn serve_hyper_static_request(
    request: Request<Incoming>,
    static_root: Arc<HyperStaticRoot>,
) -> Result<Response<HyperStaticBody>, Infallible> {
    if request.method() != Method::GET && request.method() != Method::HEAD {
        return Ok(text_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed"));
    }

    let Some(path) = normalized_request_path(request.uri().path()) else {
        return Ok(text_response(StatusCode::FORBIDDEN, "forbidden"));
    };
    let file_path = PathBuf::from(path.trim_start_matches('/'));
    let opened = match open_hyper_static_file(&static_root, &file_path) {
        Ok(opened) if opened.metadata.is_file() => opened,
        Ok(_) => return Ok(text_response(StatusCode::NOT_FOUND, "not found")),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(text_response(StatusCode::NOT_FOUND, "not found"));
        }
        Err(err) => {
            eprintln!("reuseport static openat failed for {}: {err}", file_path.display());
            return Ok(text_response(StatusCode::INTERNAL_SERVER_ERROR, "open error"));
        }
    };

    let content_length = opened.metadata.len();
    let response_body = if request.method() == Method::HEAD {
        empty_body()
    } else {
        match hyper_static_body(opened.file, content_length).await {
            Ok(body) => body,
            Err(err) => {
                eprintln!("reuseport static read failed for {}: {err}", file_path.display());
                return Ok(text_response(StatusCode::INTERNAL_SERVER_ERROR, "read error"));
            }
        }
    };

    Ok(ok_response(content_length, response_body))
}

fn open_hyper_static_file(
    static_root: &HyperStaticRoot,
    file_path: &Path,
) -> std::io::Result<OpenedHyperStaticFile> {
    let opened = open_std_hyper_static_file(static_root, file_path)?;
    Ok(OpenedHyperStaticFile {
        file: tokio::fs::File::from_std(opened.file),
        metadata: opened.metadata,
    })
}

fn open_std_hyper_static_file(
    static_root: &HyperStaticRoot,
    file_path: &Path,
) -> std::io::Result<OpenedStdStaticFile> {
    let path = CString::new(path_bytes_without_nul(file_path)?).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path contains interior nul byte")
    })?;
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.flags = (libc::O_RDONLY | libc::O_CLOEXEC) as u64;
    how.resolve = (libc::RESOLVE_BENEATH | libc::RESOLVE_NO_MAGICLINKS) as u64;

    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            static_root.root_dir_file.as_raw_fd(),
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
    Ok(OpenedStdStaticFile { file, metadata })
}

fn path_bytes_without_nul(file_path: &Path) -> std::io::Result<Vec<u8>> {
    use std::os::unix::ffi::OsStrExt;

    if file_path.as_os_str().is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "empty static file path",
        ));
    }
    Ok(file_path.as_os_str().as_bytes().to_vec())
}

fn hyper_static_stream_buffer_size(content_length: u64) -> usize {
    content_length.clamp(
        HYPER_STATIC_MIN_STREAM_BUFFER_SIZE as u64,
        HYPER_STATIC_MAX_STREAM_BUFFER_SIZE as u64,
    ) as usize
}

async fn hyper_static_body(
    mut file: tokio::fs::File,
    content_length: u64,
) -> std::io::Result<HyperStaticBody> {
    if content_length <= HYPER_STATIC_SMALL_FILE_INLINE_LIMIT {
        let mut body = Vec::with_capacity(content_length as usize);
        file.read_to_end(&mut body).await?;
        return Ok(Full::new(Bytes::from(body))
            .map_err(|err| match err {})
            .boxed());
    }

    let stream = ReaderStream::with_capacity(file, hyper_static_stream_buffer_size(content_length))
        .map_ok(Frame::data);
    Ok(BodyExt::map_err(StreamBody::new(stream), |err| err).boxed())
}

async fn serve_tokio_custom_static_connection(
    stream: &mut tokio::net::TcpStream,
    static_root: Arc<HyperStaticRoot>,
) -> std::io::Result<()> {
    let request = read_tokio_http_request(stream).await?;
    match custom_request_line(&request) {
        Some((method, path)) if method == "GET" || method == "HEAD" => {
            match write_tokio_custom_static_response(stream, &static_root, method, path).await {
                Ok(()) => Ok(()),
                Err(err) => {
                    eprintln!("reuseport static tokio_custom request failed for {path}: {err}");
                    write_tokio_response(stream, custom_text_response(StatusCode::INTERNAL_SERVER_ERROR, "read error")).await
                }
            }
        }
        Some(_) => write_tokio_response(stream, custom_text_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed")).await,
        None => write_tokio_response(stream, custom_text_response(StatusCode::BAD_REQUEST, "bad request")).await,
    }
}

async fn read_tokio_http_request(stream: &mut tokio::net::TcpStream) -> std::io::Result<Vec<u8>> {
    let mut request = Vec::with_capacity(1024);
    let mut buffer = [0_u8; 4096];
    loop {
        let read = stream.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        request.extend_from_slice(&buffer[..read]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") || request.len() >= 8192 {
            break;
        }
    }
    Ok(request)
}

fn custom_request_line(request: &[u8]) -> Option<(&str, &str)> {
    let text = std::str::from_utf8(request).ok()?;
    let line = text.split("\r\n").next()?;
    let mut parts = line.split_whitespace();
    let method = parts.next()?;
    let path = parts.next()?;
    Some((method, path))
}

async fn write_tokio_custom_static_response(
    stream: &mut tokio::net::TcpStream,
    static_root: &HyperStaticRoot,
    method: &str,
    request_path: &str,
) -> std::io::Result<()> {
    let Some(path) = normalized_request_path(request_path) else {
        return write_tokio_response(stream, custom_text_response(StatusCode::FORBIDDEN, "forbidden")).await;
    };
    let file_path = PathBuf::from(path.trim_start_matches('/'));
    let opened = match open_hyper_static_file(static_root, &file_path) {
        Ok(opened) if opened.metadata.is_file() => opened,
        Ok(_) => return write_tokio_response(stream, custom_text_response(StatusCode::NOT_FOUND, "not found")).await,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return write_tokio_response(stream, custom_text_response(StatusCode::NOT_FOUND, "not found")).await;
        }
        Err(err) => return Err(err),
    };

    let content_length = opened.metadata.len();
    let headers = status_line_and_headers(
        StatusCode::OK,
        "application/octet-stream",
        content_length,
        false,
    );
    if method == "HEAD" {
        return write_tokio_response(stream, headers).await;
    }
    write_tokio_file_body(stream, headers, opened.file, content_length).await
}

async fn write_tokio_file_body(
    stream: &mut tokio::net::TcpStream,
    headers: Vec<u8>,
    mut file: tokio::fs::File,
    content_length: u64,
) -> std::io::Result<()> {
    stream.write_all(&headers).await?;
    let mut buffer = vec![0_u8; hyper_static_stream_buffer_size(content_length)];
    loop {
        let read = file.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        stream.write_all(&buffer[..read]).await?;
    }
    Ok(())
}

async fn serve_uring_static_connection(
    stream: UringTcpStream,
    static_root: Arc<UringStaticRoot>,
) -> std::io::Result<()> {
    let request = read_uring_http_request(&stream).await?;
    match uring_request_line(&request) {
        Some((method, path)) if method == "GET" || method == "HEAD" => {
            match write_uring_static_response(&stream, &static_root, method, path).await {
                Ok(()) => Ok(()),
                Err(err) => {
                    eprintln!("reuseport static tokio_uring request failed for {path}: {err}");
                    write_uring_response(&stream, uring_text_response(StatusCode::INTERNAL_SERVER_ERROR, "read error")).await
                }
            }
        }
        Some(_) => write_uring_response(&stream, uring_text_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed")).await,
        None => write_uring_response(&stream, uring_text_response(StatusCode::BAD_REQUEST, "bad request")).await,
    }
}

async fn read_uring_http_request(stream: &UringTcpStream) -> std::io::Result<Vec<u8>> {
    let mut request = Vec::with_capacity(1024);
    let mut buffer = vec![0; 4096];
    loop {
        let (result, next_buffer) = stream.read(buffer).await;
        buffer = next_buffer;
        let read = result?;
        if read == 0 {
            break;
        }
        request.extend_from_slice(&buffer[..read]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") || request.len() >= 8192 {
            break;
        }
    }
    Ok(request)
}

fn uring_request_line(request: &[u8]) -> Option<(&str, &str)> {
    let text = std::str::from_utf8(request).ok()?;
    let line = text.split("\r\n").next()?;
    let mut parts = line.split_whitespace();
    let method = parts.next()?;
    let path = parts.next()?;
    Some((method, path))
}

async fn write_uring_static_response(
    stream: &UringTcpStream,
    static_root: &UringStaticRoot,
    method: &str,
    request_path: &str,
) -> std::io::Result<()> {
    let Some(path) = normalized_request_path(request_path) else {
        return write_uring_response(stream, uring_text_response(StatusCode::FORBIDDEN, "forbidden")).await;
    };
    let file_path = PathBuf::from(path.trim_start_matches('/'));
    let mut opened = match open_uring_static_file(static_root, &file_path) {
        Ok(opened) if opened.metadata.is_file() => opened,
        Ok(_) => return write_uring_response(stream, uring_text_response(StatusCode::NOT_FOUND, "not found")).await,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return write_uring_response(stream, uring_text_response(StatusCode::NOT_FOUND, "not found")).await;
        }
        Err(err) => return Err(err),
    };

    let content_length = opened.metadata.len();
    let headers = status_line_and_headers(
        StatusCode::OK,
        "application/octet-stream",
        content_length,
        false,
    );
    if method == "HEAD" {
        return write_uring_response(stream, headers).await;
    }
    write_uring_file_body(stream, headers, &mut opened.file, content_length).await
}

fn open_uring_static_file(
    static_root: &UringStaticRoot,
    file_path: &Path,
) -> std::io::Result<OpenedStdStaticFile> {
    let hyper_root = HyperStaticRoot {
        root_dir_file: static_root.root_dir_file.try_clone()?,
    };
    open_std_hyper_static_file(&hyper_root, file_path)
}

async fn write_uring_file_body(
    stream: &UringTcpStream,
    headers: Vec<u8>,
    file: &mut std::fs::File,
    content_length: u64,
) -> std::io::Result<()> {
    let (result, _) = stream.write_all(headers).await;
    result?;

    let mut body = Vec::with_capacity(content_length as usize);
    std::io::Read::read_to_end(file, &mut body)?;
    for chunk in body.chunks(URING_STATIC_BODY_WRITE_CHUNK_SIZE) {
        let (result, _) = stream.write_all(chunk.to_vec()).await;
        result?;
    }

    Ok(())
}

fn uring_text_response(status: StatusCode, text: &'static str) -> Vec<u8> {
    let mut response = status_line_and_headers(status, "text/plain", text.len() as u64, true);
    response.extend_from_slice(text.as_bytes());
    response
}

fn custom_text_response(status: StatusCode, text: &'static str) -> Vec<u8> {
    let mut response = status_line_and_headers(status, "text/plain", text.len() as u64, true);
    response.extend_from_slice(text.as_bytes());
    response
}

fn status_line_and_headers(
    status: StatusCode,
    content_type: &str,
    content_length: u64,
    close: bool,
) -> Vec<u8> {
    let connection = if close { "Connection: close\r\n" } else { "" };
    format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\n{}\r\n",
        status.as_u16(),
        status.canonical_reason().unwrap_or("unknown"),
        content_type,
        content_length,
        connection,
    )
    .into_bytes()
}

async fn write_uring_response(stream: &UringTcpStream, response: Vec<u8>) -> std::io::Result<()> {
    let (result, _) = stream.write_all(response).await;
    result
}

async fn write_tokio_response(stream: &mut tokio::net::TcpStream, response: Vec<u8>) -> std::io::Result<()> {
    stream.write_all(&response).await
}

fn ok_response(content_length: u64, body: HyperStaticBody) -> Response<HyperStaticBody> {
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/octet-stream")
        .header("Content-Length", content_length.to_string())
        .body(body)
        .unwrap_or_else(|_| text_response(StatusCode::INTERNAL_SERVER_ERROR, "response error"))
}

fn normalized_request_path(path: &str) -> Option<String> {
    if path == "/" {
        return Some("/index.html".to_owned());
    }
    let mut normalized = PathBuf::from("/");
    for component in Path::new(path).components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(part) => normalized.push(part),
            Component::ParentDir | Component::Prefix(_) => return None,
        }
    }
    normalized.to_str().map(|path| path.to_owned())
}

fn empty_body() -> HyperStaticBody {
    Full::new(Bytes::new())
        .map_err(|err| match err {})
        .boxed()
}

fn text_response(status: StatusCode, text: &'static str) -> Response<HyperStaticBody> {
    Response::builder()
        .status(status)
        .header("Content-Length", text.len().to_string())
        .body(
            Full::new(Bytes::from_static(text.as_bytes()))
                .map_err(|err| match err {})
                .boxed()
        )
        .unwrap()
}
'''


REUSEPORT_DIRSERVER_MAIN_RS = r'''use bytes::Bytes;
use cyfs_gateway_lib::{
    hyper_serve_http1, DirServer, DirServerFileIoMode, HttpServer, ServerError, ServerErrorCode,
    ServerResult, StreamInfo,
};
use hyper::http::{self, HeaderName};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use sfo_reuseport::{
    spawn_local, Error as ReuseportError, ServerRuntime, ServerRuntimeConfig, SocketOptions, TcpServer,
    TcpServiceConfig, TransparentMode,
};
use std::env;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr = listen_addr("REUSEPORT_DIRSERVER_PORT", "0.0.0.0:10082");
    let addr = resolve_addr(&addr)?;
    let static_root = env::var("STATIC_ROOT").unwrap_or_else(|_| "/etc/cyfs-perf/static".to_owned());
    let static_root = PathBuf::from(static_root).canonicalize()?;
    let threads = configured_threads()?;
    let file_io_mode = configured_file_io_mode()?;
    let proxy_prefix = env::var("REUSEPORT_DIRSERVER_PROXY_PREFIX").unwrap_or_else(|_| "/proxy".to_owned());
    let proxy_upstream = env::var("REUSEPORT_DIRSERVER_PROXY_UPSTREAM").unwrap_or_else(|_| "127.0.0.1:8080".to_owned());

    serve_reuseport_dirserver(addr, static_root, threads, file_io_mode, proxy_prefix, proxy_upstream)
}

fn listen_addr(port_var: &str, default_addr: &str) -> String {
    match env::var(port_var) {
        Ok(port) if port.contains(':') => port,
        Ok(port) if !port.is_empty() => format!("0.0.0.0:{port}"),
        _ => default_addr.to_owned(),
    }
}

fn configured_threads() -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
    if let Ok(raw) = env::var("REUSEPORT_DIRSERVER_THREADS") {
        let parsed = raw.parse::<usize>()?;
        if parsed > 0 {
            return Ok(parsed);
        }
    }
    Ok(thread::available_parallelism().map(|value| value.get()).unwrap_or(1))
}

fn configured_file_io_mode() -> Result<DirServerFileIoMode, Box<dyn std::error::Error + Send + Sync>> {
    match env::var("REUSEPORT_DIRSERVER_FILE_IO_MODE").as_deref() {
        Ok("sync") => Ok(DirServerFileIoMode::Sync),
        Ok("async") | Err(_) => Ok(DirServerFileIoMode::Async),
        Ok(value) => Err(format!("REUSEPORT_DIRSERVER_FILE_IO_MODE must be async or sync, got {value}").into()),
    }
}

fn resolve_addr(addr: &str) -> std::io::Result<SocketAddr> {
    addr.to_socket_addrs()?
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "empty listen address"))
}

fn serve_reuseport_dirserver(
    addr: SocketAddr,
    static_root: PathBuf,
    threads: usize,
    file_io_mode: DirServerFileIoMode,
    proxy_prefix: String,
    proxy_upstream: String,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let runtime = ServerRuntime::start(ServerRuntimeConfig::new().with_workers(threads))?;
    let service_config = TcpServiceConfig::new(addr).with_socket_options(SocketOptions {
        reuse_address: true,
        ipv4_transparent: TransparentMode::Disabled,
        ipv6_transparent: TransparentMode::Disabled,
    });
    let server = build_proxy_dir_server(static_root, file_io_mode, proxy_prefix.clone(), proxy_upstream.clone())?;
    let _server = TcpServer::serve(&runtime, service_config, move |stream| {
        let server = server.clone();
        async move {
            stream.set_nodelay(true)?;
            spawn_local(async move {
                if let Err(err) = hyper_serve_http1(Box::new(stream), server, StreamInfo::default()).await {
                    eprintln!("reuseport DirServer connection failed: {err}");
                }
            })
            .map_err(|err| ReuseportError::Runtime(format!("spawn reuseport DirServer connection task failed: {err}")))?;
            Ok(())
        }
    })?;

    eprintln!(
        "reuseport DirServer fixture listening on {addr} with {threads} sfo-reuseport workers, {file_io_mode:?} file IO, and reverse proxy {proxy_prefix}/ -> {proxy_upstream}"
    );
    loop {
        thread::park();
    }
}

fn build_dir_server(
    static_root: PathBuf,
    file_io_mode: DirServerFileIoMode,
) -> Result<Arc<DirServer>, Box<dyn std::error::Error + Send + Sync>> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let server = runtime.block_on(async move {
        DirServer::builder()
            .id("perf_reuseport_dirserver")
            .root_path(static_root)
            .index_file("index.html")
            .version("HTTP/1.1")
            .autoindex(true)
            .etag(true)
            .file_io_mode(file_io_mode)
            .build()
            .await
    })?;
    Ok(Arc::new(server))
}

fn build_proxy_dir_server(
    static_root: PathBuf,
    file_io_mode: DirServerFileIoMode,
    proxy_prefix: String,
    proxy_upstream: String,
) -> Result<Arc<dyn HttpServer>, Box<dyn std::error::Error + Send + Sync>> {
    let dir_server = build_dir_server(static_root, file_io_mode)?;
    Ok(Arc::new(ReverseProxyDirServer {
        dir_server,
        proxy_prefix: normalize_proxy_prefix(proxy_prefix),
        proxy_upstream,
    }))
}

struct ReverseProxyDirServer {
    dir_server: Arc<DirServer>,
    proxy_prefix: String,
    proxy_upstream: String,
}

#[async_trait::async_trait(?Send)]
impl HttpServer for ReverseProxyDirServer {
    async fn serve_request(
        &self,
        req: Request<UnsyncBoxBody<Bytes, ServerError>>,
        info: StreamInfo,
    ) -> ServerResult<Response<UnsyncBoxBody<Bytes, ServerError>>> {
        if path_matches_proxy(req.uri().path(), &self.proxy_prefix) {
            return Ok(reverse_proxy(req, &self.proxy_upstream).await);
        }
        self.dir_server.serve_request(req, info).await
    }

    fn id(&self) -> String {
        "perf_reuseport_dirserver_proxy".to_owned()
    }

    fn http_version(&self) -> hyper::Version {
        self.dir_server.http_version()
    }

    fn http3_port(&self) -> Option<u16> {
        self.dir_server.http3_port()
    }
}

fn normalize_proxy_prefix(prefix: String) -> String {
    let trimmed = prefix.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        "/proxy".to_owned()
    } else if trimmed.starts_with('/') {
        trimmed.to_owned()
    } else {
        format!("/{trimmed}")
    }
}

fn path_matches_proxy(path: &str, prefix: &str) -> bool {
    path == prefix || path.starts_with(&format!("{prefix}/"))
}

async fn reverse_proxy(
    req: Request<UnsyncBoxBody<Bytes, ServerError>>,
    upstream: &str,
) -> Response<UnsyncBoxBody<Bytes, ServerError>> {
    match reverse_proxy_inner(req, upstream).await {
        Ok(response) => response,
        Err(err) => text_response(StatusCode::BAD_GATEWAY, format!("reverse proxy failed: {err}")),
    }
}

async fn reverse_proxy_inner(
    req: Request<UnsyncBoxBody<Bytes, ServerError>>,
    upstream: &str,
) -> Result<Response<UnsyncBoxBody<Bytes, ServerError>>, Box<dyn std::error::Error + Send + Sync>> {
    let (parts, body) = req.into_parts();
    let body = body
        .map_err(|err| Box::new(err) as Box<dyn std::error::Error + Send + Sync>)
        .boxed_unsync();
    let path = parts
        .uri
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");
    let request_url = format!("http://{upstream}{path}");
    let tcp_stream = tokio::net::TcpStream::connect(upstream).await?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp_stream)).await?;
    spawn_local(async move {
        if let Err(err) = conn.await {
            eprintln!("reuseport DirServer reverse proxy upstream connection closed with error: {err}");
        }
    })?;

    let mut upstream_req = Request::builder()
        .method(parts.method)
        .uri(request_url)
        .body(body)?;
    set_minimal_upstream_headers(upstream_req.headers_mut(), &parts.headers, upstream)?;

    let mut response = sender.send_request(upstream_req).await?;
    strip_hop_by_hop_headers(response.headers_mut());
    Ok(response.map(|body| {
        body.map_err(|err| ServerError::new(ServerErrorCode::StreamError, format!("{:?}", err)))
            .boxed_unsync()
    }))
}

fn set_minimal_upstream_headers(
    upstream_headers: &mut http::HeaderMap,
    original_headers: &http::HeaderMap,
    upstream: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    upstream_headers.insert(http::header::HOST, upstream.parse()?);
    if let Some(value) = original_headers.get(http::header::CONTENT_LENGTH) {
        upstream_headers.insert(http::header::CONTENT_LENGTH, value.clone());
    }
    if let Some(value) = original_headers.get(http::header::CONTENT_TYPE) {
        upstream_headers.insert(http::header::CONTENT_TYPE, value.clone());
    }
    Ok(())
}

fn strip_hop_by_hop_headers(header: &mut http::HeaderMap) {
    let mut connection_tokens = Vec::new();
    for value in header.get_all(http::header::CONNECTION).iter() {
        let Ok(value) = value.to_str() else {
            continue;
        };
        for token in value.split(',') {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }
            if let Ok(name) = HeaderName::from_bytes(token.as_bytes()) {
                connection_tokens.push(name);
            }
        }
    }

    for name in connection_tokens {
        header.remove(name);
    }

    for name in [
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ] {
        header.remove(name);
    }
}

fn text_response(status: StatusCode, body: impl Into<Bytes>) -> Response<UnsyncBoxBody<Bytes, ServerError>> {
    let body = body.into();
    Response::builder()
        .status(status)
        .header("Content-Type", "text/plain")
        .header("Content-Length", body.len().to_string())
        .body(full_body(body))
        .expect("build text response")
}

fn full_body(body: impl Into<Bytes>) -> UnsyncBoxBody<Bytes, ServerError> {
    Full::new(body.into())
        .map_err(|never| match never {})
        .boxed_unsync()
}
'''


def _write_candidate_configs(plan: BenchmarkPlan, image_key: str, config_dir: Path) -> None:
    http_port = int((plan.upstream.get("http_fixture") or {}).get("port") or 8080)
    stream_port = int((plan.upstream.get("stream_fixture") or {}).get("port") or 9000)
    hyper_static_port = int((plan.upstream.get("hyper_static_fixture") or {}).get("port") or 10080)
    proxy_prefix = _reverse_proxy_prefix(plan)
    common_name = _tls_common_name(plan)
    if image_key == "nginx":
        (config_dir / "default.conf").write_text(
            f"""server {{
    listen 80;
    root /etc/cyfs-perf/static;

    location {proxy_prefix}/ {{
        proxy_pass http://127.0.0.1:{http_port};
    }}

    location / {{
        try_files $uri =404;
    }}
}}

server {{
    listen 443 ssl;
    server_name {common_name};
    root /etc/cyfs-perf/static;
    ssl_certificate /etc/cyfs-perf/tls.crt;
    ssl_certificate_key /etc/cyfs-perf/tls.key;

    location {proxy_prefix}/ {{
        proxy_pass http://127.0.0.1:{http_port};
    }}

    location / {{
        try_files $uri =404;
    }}
}}
""",
            encoding="utf-8",
        )
        (config_dir / "nginx.conf").write_text(
            f"""events {{
    worker_connections 4096;
}}

http {{
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    sendfile off;
    include /etc/nginx/conf.d/*.conf;
}}

stream {{
    server {{
        listen 9080;
        proxy_pass 127.0.0.1:{hyper_static_port};
    }}

    server {{
        listen 9443 ssl;
        ssl_certificate /etc/cyfs-perf/tls.crt;
        ssl_certificate_key /etc/cyfs-perf/tls.key;
        proxy_pass 127.0.0.1:{hyper_static_port};
    }}
}}
""",
            encoding="utf-8",
        )
    else:
        (config_dir / "gateway.yaml").write_text(
            f"""stacks:
  perf_http:
    bind: 0.0.0.0:80
    protocol: tcp
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              http-probe && return "server perf_http_server";
              reject;
  perf_https:
    bind: 0.0.0.0:443
    protocol: tls
    certs:
      - domain: "{common_name}"
        cert_path: /etc/cyfs-perf/tls.crt
        key_path: /etc/cyfs-perf/tls.key
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              return "server perf_http_server";
  perf_stream_tcp:
    bind: 0.0.0.0:9080
    protocol: tcp
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              return "forward tcp:///127.0.0.1:{hyper_static_port}";
  perf_stream_tls:
    bind: 0.0.0.0:9443
    protocol: tls
    certs:
      - domain: "{common_name}"
        cert_path: /etc/cyfs-perf/tls.crt
        key_path: /etc/cyfs-perf/tls.key
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              return "forward tcp:///127.0.0.1:{hyper_static_port}";

servers:
  perf_http_server:
    type: http
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              starts-with ${{REQ.path}} "{proxy_prefix}/" && forward http://127.0.0.1:{http_port};
              call-server perf_static_files;
  perf_static_files:
    type: dir
    root_path: /etc/cyfs-perf/static
    index_file: index.html
    autoindex: false
    etag: true
""",
            encoding="utf-8",
        )


def _tls_common_name(plan: BenchmarkPlan) -> str:
    tls = (plan.generated_config.get("tls") or {}) if isinstance(plan.generated_config, dict) else {}
    return str(tls.get("common_name") or "perf.local")


def _reverse_proxy_prefix(plan: BenchmarkPlan) -> str:
    proxy = plan.scenarios.get("http_reverse_proxy") or {}
    paths = proxy.get("paths")
    if isinstance(paths, list) and paths:
        first_path = str(paths[0])
    else:
        first_path = str(proxy.get("path") or "/proxy/payload")
    prefix = first_path.rsplit("/", 1)[0] or "/proxy"
    return prefix.rstrip("/") or "/proxy"


def _static_file_specs(plan: BenchmarkPlan) -> list[dict]:
    static_cfg = (plan.generated_config.get("static_files") or {}) if isinstance(plan.generated_config, dict) else {}
    files = static_cfg.get("files")
    if not isinstance(files, list) or not files:
        return [{"path": "index.html", "size_bytes": 4096}]
    return [item for item in files if isinstance(item, dict)]


def write_static_files(plan: BenchmarkPlan, config_dir: Path) -> dict:
    static_dir = config_dir / "static"
    static_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for item in _static_file_specs(plan):
        rel_path = str(item.get("path") or "index.html").lstrip("/")
        size = int(item.get("size_bytes") or 0)
        if size <= 0:
            size = 4096
        target = static_dir / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        seed = f"cyfs performance static file: {rel_path}\n".encode("utf-8")
        data = (seed * ((size // len(seed)) + 1))[:size]
        target.write_bytes(data)
        written.append({"path": rel_path, "size_bytes": size, "output": str(target)})
    return {"root": str(static_dir), "files": written}


def tls_certificate_commands(plan: BenchmarkPlan, context: Path) -> list[CommandPlan]:
    common_name = _tls_common_name(plan)
    generated = context / "generated"
    return [
        CommandPlan(
            "generate test tls certificate",
            (
                "openssl",
                "req",
                "-x509",
                "-nodes",
                "-newkey",
                "rsa:2048",
                "-keyout",
                str(generated / "tls.key"),
                "-out",
                str(generated / "tls.crt"),
                "-days",
                "7",
                "-subj",
                f"/CN={common_name}",
                "-addext",
                f"subjectAltName=DNS:{common_name},IP:127.0.0.1",
            ),
        )
    ]


def image_build_plan(plan: BenchmarkPlan, image_key: str, output: Path) -> tuple[Path, list[CommandPlan]]:
    if image_key not in plan.images:
        raise ConfigError(f"unknown image: {image_key}")
    context = output / "docker" / image_key
    dockerfile = context / "Dockerfile.generated"
    image = plan.images[image_key]
    command = ("docker", "build", "-t", image.image_ref, "-f", str(dockerfile), str(context))
    commands = [
        *fixture_build_commands(context),
        *fixture_package_commands(context),
        *tls_certificate_commands(plan, context),
    ]
    if image_key == "cyfs_gateway":
        commands.extend(cyfs_gateway_package_commands(plan, context))
    commands.append(CommandPlan(f"build {image_key} image", command))
    return dockerfile, commands


def fixture_build_commands(context: Path) -> list[CommandPlan]:
    fixture_dir = context / "reverse_proxy_fixture"
    reuseport_static_dir = context / "reuseport_static_fixture"
    reuseport_dirserver_dir = context / "reuseport_dirserver_fixture"
    return [
        CommandPlan(
            "build reverse_proxy_fixture binary",
            ("cargo", "build", "--release"),
            cwd=str(fixture_dir),
        ),
        CommandPlan(
            "build reuseport_static_fixture binary",
            ("cargo", "build", "--release"),
            cwd=str(reuseport_static_dir),
        ),
        CommandPlan(
            "build reuseport_dirserver_fixture binary",
            ("cargo", "build", "--release"),
            cwd=str(reuseport_dirserver_dir),
        ),
    ]


def fixture_package_commands(context: Path) -> list[CommandPlan]:
    binary = fixture_build_binary(context)
    packaged = fixture_packaged_binary(context)
    static_binary = reuseport_static_build_binary(context)
    static_packaged = reuseport_static_packaged_binary(context)
    dirserver_binary = reuseport_dirserver_build_binary(context)
    dirserver_packaged = reuseport_dirserver_packaged_binary(context)
    return [
        CommandPlan(
            "package reverse_proxy_fixture binary",
            ("install", "-m", "0755", str(binary), str(packaged)),
        ),
        CommandPlan(
            "package reuseport_static_fixture binary",
            ("install", "-m", "0755", str(static_binary), str(static_packaged)),
        ),
        CommandPlan(
            "package reuseport_dirserver_fixture binary",
            ("install", "-m", "0755", str(dirserver_binary), str(dirserver_packaged)),
        ),
    ]


def cyfs_gateway_source(plan: BenchmarkPlan) -> dict:
    raw = {}
    # ImageConfig intentionally exposes only public image fields today; keep source
    # settings under generated profile data until the model grows a stable field.
    images_cfg = plan.generated_config.get("_raw_images") if isinstance(plan.generated_config, dict) else None
    if isinstance(images_cfg, dict):
        raw = dict((images_cfg.get("cyfs_gateway") or {}).get("source") or {})
    profile_dir = plan.profile_path.parent
    default_root = next((parent for parent in profile_dir.parents if (parent / "src" / "Cargo.toml").exists()), profile_dir)
    manifest = Path(raw.get("cargo_manifest") or str(default_root / "src" / "Cargo.toml"))
    repo_root = Path(raw.get("repo_root") or str(default_root))
    if not manifest.is_absolute():
        manifest = (profile_dir / manifest).resolve()
    if not repo_root.is_absolute():
        repo_root = (profile_dir / repo_root).resolve()
    package = str(raw.get("package") or "cyfs_gateway")
    build_profile = str(raw.get("build_profile") or "release")
    if build_profile not in {"debug", "release"}:
        raise ConfigError("images.cyfs_gateway.source.build_profile must be debug or release")
    target = raw.get("target", "x86_64-unknown-linux-gnu")
    if target is not None and not isinstance(target, str):
        raise ConfigError("images.cyfs_gateway.source.target must be a string when provided")
    return {
        "repo_root": str(repo_root),
        "cargo_manifest": str(manifest),
        "package": package,
        "build_profile": build_profile,
        "target": target,
    }


def source_build_commands(plan: BenchmarkPlan, context: Path) -> list[CommandPlan]:
    source = cyfs_gateway_source(plan)
    target_dir = cyfs_gateway_cargo_target_dir(context)
    command = [
        "cargo",
        "build",
        "--manifest-path",
        source["cargo_manifest"],
        "--package",
        source["package"],
        "--target-dir",
        str(target_dir),
    ]
    if source["build_profile"] == "release":
        command.append("--release")
    if source["target"]:
        command.extend(["--target", source["target"]])
    return [
        CommandPlan(
            "build cyfs_gateway from current source",
            tuple(command),
            cwd=source["repo_root"],
        )
    ]


def cyfs_gateway_binary_paths(plan: BenchmarkPlan, context: Path) -> tuple[Path, Path]:
    source = cyfs_gateway_source(plan)
    target_dir = cyfs_gateway_cargo_target_dir(context)
    if source["target"]:
        target_dir = target_dir / source["target"]
    profile_dir = "release" if source["build_profile"] == "release" else "debug"
    target_dir = target_dir / profile_dir
    return target_dir / "cyfs_gateway", context / "generated" / "cyfs_gateway"


def cyfs_gateway_cargo_target_dir(context: Path) -> Path:
    return context.parent.parent / "cargo-target" / "cyfs_gateway"


def cyfs_gateway_package_commands(plan: BenchmarkPlan, context: Path) -> list[CommandPlan]:
    binary, packaged = cyfs_gateway_binary_paths(plan, context)
    return [
        CommandPlan(
            "package cyfs_gateway binary",
            ("install", "-m", "0755", str(binary), str(packaged)),
        )
    ]


def cyfs_gateway_binary_metadata(plan: BenchmarkPlan, context: Path) -> dict:
    source = cyfs_gateway_source(plan)
    binary, packaged = cyfs_gateway_binary_paths(plan, context)
    binary_size = binary.stat().st_size if binary.exists() else 0
    packaged_size = packaged.stat().st_size if packaged.exists() else 0
    return {
        **source,
        "target_dir": str(cyfs_gateway_cargo_target_dir(context)),
        "expected_binary": str(binary),
        "expected_binary_exists": binary.exists(),
        "expected_binary_size": binary_size,
        "packaged_binary": str(packaged),
        "packaged_binary_exists": packaged.exists(),
        "packaged_binary_size": packaged_size,
    }


def cyfs_gateway_lib_path(plan: BenchmarkPlan) -> Path:
    source = cyfs_gateway_source(plan)
    return Path(source["repo_root"]) / "src" / "components" / "cyfs-gateway-lib"


def reuseport_dirserver_release_lto(plan: BenchmarkPlan) -> bool:
    fixture = reuseport_dirserver_config(plan)
    return bool(fixture.get("release_lto", False))


def reuseport_dirserver_cargo_toml(plan: BenchmarkPlan) -> str:
    lib_path = str(cyfs_gateway_lib_path(plan)).replace("\\", "\\\\")
    release_profile = """
[profile.release]
lto = "fat"
codegen-units = 1
strip = true
""" if reuseport_dirserver_release_lto(plan) else ""
    return f"""[package]
name = "cyfs-perf-reuseport-dirserver-fixture"
version = "0.1.0"
edition = "2021"

[workspace]

[dependencies]
async-trait = "0.1"
bytes = "1"
cyfs-gateway-lib = {{ path = "{lib_path}" }}
http-body-util = "0.1"
hyper = {{ version = "1", features = ["http1"] }}
hyper-util = {{ version = "0.1", features = ["tokio"] }}
sfo-reuseport = {{ version = "0.3", features = ["quinn"] }}
tokio = {{ version = "1", features = ["io-util", "net", "rt"] }}
{release_profile}
"""


REUSEPORT_DIRSERVER_CARGO_CONFIG_TOML = """[target.'cfg(target_os = "linux")']
rustflags = ["--cfg", "tokio_unstable"]
"""


def reuseport_dirserver_tokio_unstable(plan: BenchmarkPlan) -> bool:
    return True


def write_fixture_sources(plan: BenchmarkPlan, context: Path) -> dict:
    fixture_dir = context / "reverse_proxy_fixture"
    src = fixture_dir / "src"
    src.mkdir(parents=True, exist_ok=True)
    (fixture_dir / "Cargo.toml").write_text(FIXTURE_CARGO_TOML, encoding="utf-8")
    (src / "main.rs").write_text(FIXTURE_MAIN_RS, encoding="utf-8")
    static_fixture_dir = context / "reuseport_static_fixture"
    static_src = static_fixture_dir / "src"
    static_src.mkdir(parents=True, exist_ok=True)
    (static_fixture_dir / "Cargo.toml").write_text(REUSEPORT_STATIC_CARGO_TOML, encoding="utf-8")
    (static_src / "main.rs").write_text(REUSEPORT_STATIC_MAIN_RS, encoding="utf-8")
    dirserver_fixture_dir = context / "reuseport_dirserver_fixture"
    dirserver_src = dirserver_fixture_dir / "src"
    dirserver_cargo_dir = dirserver_fixture_dir / ".cargo"
    dirserver_src.mkdir(parents=True, exist_ok=True)
    dirserver_cargo_dir.mkdir(parents=True, exist_ok=True)
    (dirserver_fixture_dir / "Cargo.toml").write_text(reuseport_dirserver_cargo_toml(plan), encoding="utf-8")
    if reuseport_dirserver_tokio_unstable(plan):
        (dirserver_cargo_dir / "config.toml").write_text(REUSEPORT_DIRSERVER_CARGO_CONFIG_TOML, encoding="utf-8")
    (dirserver_src / "main.rs").write_text(REUSEPORT_DIRSERVER_MAIN_RS, encoding="utf-8")
    return {
        "cargo_toml": str(fixture_dir / "Cargo.toml"),
        "main_rs": str(src / "main.rs"),
        **fixture_binary_metadata(context),
    }


def write_reuseport_static_sources_metadata(context: Path) -> dict:
    fixture_dir = context / "reuseport_static_fixture"
    return {
        "cargo_toml": str(fixture_dir / "Cargo.toml"),
        "main_rs": str(fixture_dir / "src" / "main.rs"),
        **reuseport_static_binary_metadata(context),
    }


def write_reuseport_dirserver_sources_metadata(context: Path) -> dict:
    fixture_dir = context / "reuseport_dirserver_fixture"
    return {
        "cargo_toml": str(fixture_dir / "Cargo.toml"),
        "cargo_config_toml": str(fixture_dir / ".cargo" / "config.toml"),
        "main_rs": str(fixture_dir / "src" / "main.rs"),
        **reuseport_dirserver_binary_metadata(context),
    }


def fixture_binary_metadata(context: Path) -> dict:
    binary = fixture_build_binary(context)
    packaged = fixture_packaged_binary(context)
    return {
        "build_binary": str(binary),
        "build_binary_exists": binary.exists(),
        "packaged_binary": str(packaged),
        "packaged_binary_exists": packaged.exists(),
    }


def fixture_build_binary(context: Path) -> Path:
    return context / "reverse_proxy_fixture" / "target" / "release" / "cyfs-perf-reverse-proxy-fixture"


def fixture_packaged_binary(context: Path) -> Path:
    return context / "generated" / "cyfs-perf-reverse-proxy-fixture"


def reuseport_static_binary_metadata(context: Path) -> dict:
    binary = reuseport_static_build_binary(context)
    packaged = reuseport_static_packaged_binary(context)
    return {
        "build_binary": str(binary),
        "build_binary_exists": binary.exists(),
        "packaged_binary": str(packaged),
        "packaged_binary_exists": packaged.exists(),
    }


def reuseport_static_build_binary(context: Path) -> Path:
    return context / "reuseport_static_fixture" / "target" / "release" / "cyfs-perf-reuseport-static-fixture"


def reuseport_static_packaged_binary(context: Path) -> Path:
    return context / "generated" / "cyfs-perf-reuseport-static-fixture"


def reuseport_dirserver_binary_metadata(context: Path) -> dict:
    binary = reuseport_dirserver_build_binary(context)
    packaged = reuseport_dirserver_packaged_binary(context)
    return {
        "build_binary": str(binary),
        "build_binary_exists": binary.exists(),
        "packaged_binary": str(packaged),
        "packaged_binary_exists": packaged.exists(),
    }


def reuseport_dirserver_build_binary(context: Path) -> Path:
    return context / "reuseport_dirserver_fixture" / "target" / "release" / "cyfs-perf-reuseport-dirserver-fixture"


def reuseport_dirserver_packaged_binary(context: Path) -> Path:
    return context / "generated" / "cyfs-perf-reuseport-dirserver-fixture"


def reuseport_static_config(plan: BenchmarkPlan) -> dict:
    fixture = plan.upstream.get("reuseport_static_fixture") if isinstance(plan.upstream, dict) else None
    return fixture if isinstance(fixture, dict) else {}


def reuseport_static_enabled(plan: BenchmarkPlan) -> bool:
    return bool(reuseport_static_config(plan).get("enabled", False))


def reuseport_static_threads(plan: BenchmarkPlan) -> int | None:
    fixture = reuseport_static_config(plan)
    if not fixture:
        return None
    threads = fixture.get("threads")
    return threads if isinstance(threads, int) and threads > 0 else None


def reuseport_static_runtime(plan: BenchmarkPlan) -> str:
    runtime = reuseport_static_config(plan).get("runtime")
    return runtime if runtime in {"tokio", "tokio_custom", "tokio_uring"} else "tokio"


def reuseport_dirserver_config(plan: BenchmarkPlan) -> dict:
    fixture = plan.upstream.get("reuseport_dirserver_fixture") if isinstance(plan.upstream, dict) else None
    return fixture if isinstance(fixture, dict) else {}


def reuseport_dirserver_enabled(plan: BenchmarkPlan) -> bool:
    return bool(reuseport_dirserver_config(plan).get("enabled", False))


def reuseport_dirserver_threads(plan: BenchmarkPlan) -> int | None:
    fixture = reuseport_dirserver_config(plan)
    if not fixture:
        return None
    threads = fixture.get("threads")
    return threads if isinstance(threads, int) and threads > 0 else None


def reuseport_dirserver_file_io_mode(plan: BenchmarkPlan) -> str:
    mode = reuseport_dirserver_config(plan).get("file_io_mode")
    return mode if mode in {"async", "sync"} else "async"


def dockerfile_env_lines(plan: BenchmarkPlan, image_key: str) -> str:
    docker_cfg = (plan.generated_config.get("docker") or {}) if isinstance(plan.generated_config, dict) else {}
    env_cfg = docker_cfg.get(f"{image_key}_env") or {}
    if not isinstance(env_cfg, dict):
        return ""

    lines: list[str] = []
    for key in sorted(env_cfg):
        value = env_cfg[key]
        if value is None:
            continue
        escaped = str(value).replace("\\", "\\\\").replace('"', '\\"')
        lines.append(f'ENV {key}="{escaped}"\n')
    return "".join(lines)


def dockerfile_cmd(shell_script: str) -> str:
    return f"CMD {json.dumps(['/bin/sh', '-c', shell_script])}\n"


def docker_base_image(plan: BenchmarkPlan, image_key: str, default: str) -> str:
    images_cfg = plan.generated_config.get("_raw_images") if isinstance(plan.generated_config, dict) else None
    raw_image = (images_cfg.get(image_key) or {}) if isinstance(images_cfg, dict) else {}
    raw_docker = raw_image.get("docker") or {}
    if not isinstance(raw_docker, dict):
        return default
    return str(raw_docker.get("base_image") or default)


def write_image_context(plan: BenchmarkPlan, image_key: str, output: Path) -> dict:
    dockerfile, commands = image_build_plan(plan, image_key, output)
    dockerfile.parent.mkdir(parents=True, exist_ok=True)
    config_dir = dockerfile.parent / "generated"
    config_dir.mkdir(parents=True, exist_ok=True)
    (config_dir / "README.txt").write_text(
        f"Generated benchmark context for {image_key} from profile {plan.profile_path}\n",
        encoding="utf-8",
    )
    _write_candidate_configs(plan, image_key, config_dir)
    static_files = write_static_files(plan, config_dir)
    fixture = write_fixture_sources(plan, dockerfile.parent)
    reuseport_static_fixture = write_reuseport_static_sources_metadata(dockerfile.parent)
    reuseport_dirserver_fixture = write_reuseport_dirserver_sources_metadata(dockerfile.parent)
    http_port = int((plan.upstream.get("http_fixture") or {}).get("port") or 8080)
    stream_port = int((plan.upstream.get("stream_fixture") or {}).get("port") or 9000)
    hyper_static_port = int((plan.upstream.get("hyper_static_fixture") or {}).get("port") or 10080)
    reuseport_static_port = int(reuseport_static_config(plan).get("port") or 10081)
    reuseport_dirserver_port = int(reuseport_dirserver_config(plan).get("port") or 10082)
    reuseport_enabled = reuseport_static_enabled(plan)
    reuseport_dirserver_is_enabled = reuseport_dirserver_enabled(plan)
    hyper_static_threads = reuseport_static_threads(plan)
    dirserver_threads = reuseport_dirserver_threads(plan)
    dirserver_file_io_mode = reuseport_dirserver_file_io_mode(plan)
    reuseport_runtime = reuseport_static_runtime(plan)
    proxy_prefix = _reverse_proxy_prefix(plan)
    candidate_env = dockerfile_env_lines(plan, image_key)
    hyper_static_thread_env = f"ENV REUSEPORT_STATIC_THREADS={hyper_static_threads}\n" if hyper_static_threads else ""
    dirserver_thread_env = f"ENV REUSEPORT_DIRSERVER_THREADS={dirserver_threads}\n" if dirserver_threads else ""
    reuseport_start = "if [ x$REUSEPORT_STATIC_ENABLED = x1 ]; then cyfs-perf-reuseport-static-fixture & fi; "
    dirserver_start = "if [ x$REUSEPORT_DIRSERVER_ENABLED = x1 ]; then cyfs-perf-reuseport-dirserver-fixture & fi; "
    fixture_env = (
        "COPY generated/cyfs-perf-reverse-proxy-fixture /usr/local/bin/cyfs-perf-reverse-proxy-fixture\n"
        "COPY generated/cyfs-perf-reuseport-static-fixture /usr/local/bin/cyfs-perf-reuseport-static-fixture\n"
        "COPY generated/cyfs-perf-reuseport-dirserver-fixture /usr/local/bin/cyfs-perf-reuseport-dirserver-fixture\n"
        "RUN chmod +x /usr/local/bin/cyfs-perf-reverse-proxy-fixture\n"
        "RUN chmod +x /usr/local/bin/cyfs-perf-reuseport-static-fixture\n"
        "RUN chmod +x /usr/local/bin/cyfs-perf-reuseport-dirserver-fixture\n"
        f"ENV HTTP_PORT={http_port}\n"
        f"ENV STREAM_PORT={stream_port}\n"
        f"ENV HYPER_STATIC_PORT={hyper_static_port}\n"
        f"ENV REUSEPORT_STATIC_PORT={reuseport_static_port}\n"
        f"ENV REUSEPORT_STATIC_ENABLED={1 if reuseport_enabled else 0}\n"
        f"ENV REUSEPORT_STATIC_RUNTIME={reuseport_runtime}\n"
        + hyper_static_thread_env
        + f"ENV REUSEPORT_DIRSERVER_PORT={reuseport_dirserver_port}\n"
        + f"ENV REUSEPORT_DIRSERVER_ENABLED={1 if reuseport_dirserver_is_enabled else 0}\n"
        + f"ENV REUSEPORT_DIRSERVER_FILE_IO_MODE={dirserver_file_io_mode}\n"
        + f"ENV REUSEPORT_DIRSERVER_PROXY_PREFIX={proxy_prefix}\n"
        + f"ENV REUSEPORT_DIRSERVER_PROXY_UPSTREAM=127.0.0.1:{http_port}\n"
        + dirserver_thread_env
        + "ENV STATIC_ROOT=/etc/cyfs-perf/static\n"
        + f"EXPOSE 80 443 9080 9443 {http_port} {stream_port} {hyper_static_port} {reuseport_static_port} {reuseport_dirserver_port}\n"
    )
    source_build = None
    if image_key == "cyfs_gateway":
        source_build = cyfs_gateway_binary_metadata(plan, dockerfile.parent)

    if image_key == "nginx":
        base_image = docker_base_image(plan, image_key, "nginx:stable")
        body = (
            f"FROM {base_image}\nCOPY generated/ /etc/cyfs-perf/\n"
            + "COPY generated/default.conf /etc/nginx/conf.d/default.conf\n"
            + "COPY generated/nginx.conf /etc/nginx/nginx.conf\n"
            + fixture_env
            + candidate_env
            + dockerfile_cmd(f"cyfs-perf-reverse-proxy-fixture & {reuseport_start}{dirserver_start}exec nginx -g 'daemon off;'")
        )
    else:
        base_image = docker_base_image(plan, image_key, "ubuntu:22.04")
        body = (
            f"FROM {base_image}\nCOPY generated/ /etc/cyfs-perf/\n"
            + "COPY generated/cyfs_gateway /usr/local/bin/cyfs_gateway\n"
            + "RUN chmod +x /usr/local/bin/cyfs_gateway\n"
            + fixture_env
            + candidate_env
            + dockerfile_cmd(
                f"cyfs-perf-reverse-proxy-fixture & {reuseport_start}{dirserver_start}exec cyfs_gateway --config_file /etc/cyfs-perf/gateway.yaml"
            )
        )
    dockerfile.write_text(body, encoding="utf-8")
    return {
        "image": image_key,
        "dockerfile": str(dockerfile),
        "image_ref": plan.images[image_key].image_ref,
        "static_files": static_files,
        "tls": {
            "mode": "generated",
            "common_name": _tls_common_name(plan),
            "cert_path": str(config_dir / "tls.crt"),
            "key_path": str(config_dir / "tls.key"),
        },
        "packaged_reverse_proxy_fixture": {
            **fixture,
            "ports": {
                "http": http_port,
                "stream": stream_port,
                "hyper_static": hyper_static_port,
            },
        },
        "packaged_reuseport_static_fixture": {
            **reuseport_static_fixture,
            "ports": {
                "reuseport_static": reuseport_static_port,
            },
            "enabled": reuseport_enabled,
            "threads": hyper_static_threads or "available_parallelism",
            "runtime": reuseport_runtime,
        },
        "packaged_reuseport_dirserver_fixture": {
            **reuseport_dirserver_fixture,
            "ports": {
                "reuseport_dirserver": reuseport_dirserver_port,
            },
            "enabled": reuseport_dirserver_is_enabled,
            "threads": dirserver_threads or "available_parallelism",
            "file_io_mode": dirserver_file_io_mode,
            "cyfs_gateway_lib": str(cyfs_gateway_lib_path(plan)),
        },
        "commands": [list(command.command) for command in commands],
        "source_build": source_build,
    }


def push_plan(plan: BenchmarkPlan, image_key: str) -> list[CommandPlan]:
    if image_key not in plan.images:
        raise ConfigError(f"unknown image: {image_key}")
    if not plan.registry_push:
        return []
    image = plan.images[image_key]
    return [
        CommandPlan(f"push {image_key} image", ("docker", "push", image.image_ref)),
    ]
