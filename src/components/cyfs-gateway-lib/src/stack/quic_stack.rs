use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use std::future::poll_fn;
use std::io;
use std::io::Read;
use std::pin::Pin;
use std::sync::{Arc, Mutex, RwLock};
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use buckyos_kit::AsyncStream;
use futures::Stream;
use h3::error::Code;
use h3::quic;
use h3::quic::{BidiStream, ConnectionErrorIncoming, OpenStreams, RecvStream, SendStream, StreamErrorIncoming, StreamId, WriteBuf};
use h3::server::{RequestStream};
use http_body_util::BodyExt;
use hyper::body::{Body, Buf, Bytes, Frame};
use pin_project::pin_project;
use quinn::crypto::rustls::{HandshakeData, QuicServerConfig};
use quinn::Incoming;
use rustls::{ServerConfig};
use rustls::server::{ResolvesServerCert};
use rustls::sign::CertifiedKey;
use sfo_io::{LimitRead, LimitStream, LimitWrite, SfoSpeedStat, SimpleAsyncWrite, SimpleAsyncWriteHolder, SpeedTracker, StatRead, StatStream, StatWrite};
use tokio::io::{AsyncRead, ReadBuf, Take};
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio_util::io::ReaderStream;
use cyfs_acme::{AcmeCertManagerRef, AcmeItem, ChallengeType};
use cyfs_process_chain::{CollectionValue, CommandControl, MemoryMapCollection, ProcessChainLibExecutor};
use crate::{into_stack_err, stack_err, ProcessChainConfigs, Stack, StackContext, StackErrorCode, StackProtocol, StackResult, ServerManagerRef, TlsDomainConfig, Server, server_err, ServerErrorCode, ServerError, ConnectionManagerRef, ConnectionInfo, HandleConnectionController, ConnectionController, TunnelManager, StackConfig, ProcessChainConfig, StackCertConfig, load_key, load_certs, StackRef, StackFactory, StreamInfo, get_external_commands, LimiterManagerRef, StatManagerRef, get_stat_info, ComposedSpeedStat, SelfCertMgrRef, GlobalCollectionManagerRef, JsExternalsManagerRef};
use crate::global_process_chains::{create_process_chain_executor, execute_chain, GlobalProcessChainsRef};
use crate::stack::limiter::Limiter;
use crate::stack::{get_limit_info, stream_forward, TlsCertResolver};
use crate::stack::tls_cert_resolver::ResolvesServerCertUsingSni;

#[derive(Clone)]
pub struct QuicStackContext {
    pub servers: ServerManagerRef,
    pub tunnel_manager: TunnelManager,
    pub limiter_manager: LimiterManagerRef,
    pub stat_manager: StatManagerRef,
    pub acme_manager: AcmeCertManagerRef,
    pub self_cert_mgr: SelfCertMgrRef,
    pub global_process_chains: Option<GlobalProcessChainsRef>,
    pub global_collection_manager: Option<GlobalCollectionManagerRef>,
    pub js_externals: Option<JsExternalsManagerRef>,
}

impl QuicStackContext {
    pub fn new(
        servers: ServerManagerRef,
        tunnel_manager: TunnelManager,
        limiter_manager: LimiterManagerRef,
        stat_manager: StatManagerRef,
        acme_manager: AcmeCertManagerRef,
        self_cert_mgr: SelfCertMgrRef,
        global_process_chains: Option<GlobalProcessChainsRef>,
        global_collection_manager: Option<GlobalCollectionManagerRef>,
        js_externals: Option<JsExternalsManagerRef>,
    ) -> Self {
        Self {
            servers,
            tunnel_manager,
            limiter_manager,
            stat_manager,
            acme_manager,
            self_cert_mgr,
            global_process_chains,
            global_collection_manager,
            js_externals,
        }
    }
}

impl StackContext for QuicStackContext {
    fn stack_protocol(&self) -> StackProtocol {
        StackProtocol::Quic
    }
}

struct QuicConnectionHandler {
    env: Arc<QuicStackContext>,
    executor: ProcessChainLibExecutor,
    connection_manager: Option<ConnectionManagerRef>,
}

impl QuicConnectionHandler {
    async fn create(
        hook_point: ProcessChainConfigs,
        env: Arc<QuicStackContext>,
        connection_manager: Option<ConnectionManagerRef>,
    ) -> StackResult<Self> {
        let (executor, _) = create_process_chain_executor(
            &hook_point,
            env.global_process_chains.clone(),
            env.global_collection_manager.clone(),
            Some(get_external_commands(Arc::downgrade(&env.servers))),
            env.js_externals.clone(),
        )
            .await
            .map_err(into_stack_err!(StackErrorCode::InvalidConfig))?;
        Ok(Self {
            env,
            executor,
            connection_manager,
        })
    }

    fn build_cert_resolver(
        certs: Vec<TlsDomainConfig>,
        env: &QuicStackContext,
    ) -> StackResult<Arc<dyn ResolvesServerCert>> {
        let crypto_provider = rustls::crypto::ring::default_provider();
        let external_resolver = Some(env.acme_manager.clone() as Arc<dyn ResolvesServerCert>);
        let cert_resolver = Arc::new(ResolvesServerCertUsingSni::new(external_resolver));
        let mut self_cert = false;
        for cert_config in certs.into_iter() {
            if cert_config.domain == "*" {
                self_cert = true;
                continue;
            }
            if let (Some(certs), Some(key)) = (cert_config.certs, cert_config.key) {
                let cert_key = CertifiedKey::from_der(certs, key, &crypto_provider)
                    .map_err(into_stack_err!(StackErrorCode::InvalidTlsCert, "parse {} cert failed", cert_config.domain))?;
                cert_resolver
                    .add(&cert_config.domain, cert_key)
                    .map_err(|e| stack_err!(StackErrorCode::InvalidConfig, "add {} cert failed.err {}", cert_config.domain, e))?;
            } else {
                env.acme_manager
                    .add_acme_item(AcmeItem::new(
                        cert_config.domain,
                        cert_config.acme_type.unwrap_or(ChallengeType::TlsAlpn01),
                        cert_config.data,
                    ))
                    .map_err(|e| stack_err!(StackErrorCode::InvalidConfig, "{e}"))?;
            }
        }
        let cert: Arc<dyn ResolvesServerCert> = if self_cert {
            Arc::new(TlsCertResolver::new(cert_resolver, Some(env.self_cert_mgr.clone())))
        } else {
            cert_resolver
        };
        Ok(cert)
    }

    async fn accept(&self, conn: Incoming, local_addr: SocketAddr) -> StackResult<()> {
        let connection = conn.await.map_err(into_stack_err!(StackErrorCode::QuicError))?;
        let server_name = {
            let handshake_data = connection.handshake_data();
            if handshake_data.is_none() {
                return Err(stack_err!(StackErrorCode::QuicError, "handshake data is None"));
            }
            let handshake_data = handshake_data.as_ref().unwrap().as_ref().downcast_ref::<HandshakeData>();
            if handshake_data.is_none() {
                return Err(stack_err!(StackErrorCode::QuicError, "handshake data is None"));
            }

            let server_name = handshake_data.unwrap().server_name.as_ref();
            if server_name.is_none() {
                return Err(stack_err!(StackErrorCode::QuicError, "server name is None"));
            }
            server_name.unwrap().to_string()
        };

        let remote_addr = connection.remote_address();
        log::info!("quic accept: {} -> {}", remote_addr, local_addr);
        let map = MemoryMapCollection::new_ref();
        map.insert("dest_host", CollectionValue::String(server_name)).await.map_err(|e| stack_err!(StackErrorCode::ProcessChainError, "{e}"))?;
        map.insert("source_addr", CollectionValue::String(remote_addr.to_string())).await.map_err(|e| stack_err!(StackErrorCode::ProcessChainError, "{e}"))?;

        let executor = self.executor.fork();
        let global_env = executor.global_env().clone();
        let ret = execute_chain(executor, map)
            .await
            .map_err(into_stack_err!(StackErrorCode::ProcessChainError))?;
        if ret.is_control() {
            if ret.is_drop() {
                connection.close(0u32.into(), "".as_bytes());
                return Ok(());
            } else if ret.is_reject() {
                connection.close(0u32.into(), "".as_bytes());
                return Ok(());
            }

            if let Some(CommandControl::Return(ret)) = ret.as_control() {
                if let Some(list) = shlex::split(ret.value.as_str()) {
                    if list.is_empty() {
                        return Ok(());
                    }

                    let (limiter_id, down_speed, up_speed) = get_limit_info(global_env.clone()).await?;
                    let upper = if limiter_id.is_some() {
                        self.env.limiter_manager.get_limiter(limiter_id.unwrap())
                    } else {
                        None
                    };
                    let limiter = if down_speed.is_some() && up_speed.is_some() {
                        Some(Limiter::new(upper, Some(1), down_speed.map(|v| v as u32), up_speed.map(|v| v as u32)))
                    } else {
                        upper
                    };

                    let stat_group_ids = get_stat_info(global_env).await?;
                    let speed_groups = self.env.stat_manager.get_speed_stats(stat_group_ids.as_slice());
                    let speed_stat = ComposedSpeedStat::new(speed_groups);
                    let cmd = list[0].as_str();
                    match cmd {
                        "forward" => {
                            if list.len() < 2 {
                                return Err(stack_err!(
                                    StackErrorCode::InvalidConfig,
                                    "invalid forward command"
                                ));
                            }
                            let speed_stat = speed_stat.clone();
                            loop {
                                let (send, recv) = connection.accept_bi().await.map_err(into_stack_err!(StackErrorCode::QuicError))?;
                                log::info!("quic accept bi: {} -> {}", remote_addr, local_addr);
                                let stream = sfo_split::Splittable::new(recv, send);
                                let stat_stream = StatStream::new_with_tracker(stream, speed_stat.clone());
                                let speed = stat_stream.get_speed_stat();
                                let target = list[1].clone();
                                let stream: Box<dyn AsyncStream> = if limiter.is_some() {
                                    let (read_limit, write_limit) = limiter.as_ref().unwrap().new_limit_session();
                                    let limit_stream = LimitStream::new(stat_stream, read_limit, write_limit);
                                    Box::new(limit_stream)
                                } else {
                                    Box::new(stat_stream)
                                };
                                let tunnel_manager = self.env.tunnel_manager.clone();
                                let handle = tokio::spawn(async move {
                                    if let Err(e) = stream_forward(stream, target.as_str(), &tunnel_manager).await {
                                        log::error!("stream forward error: {}", e);
                                    }
                                });
                                if let Some(connection_manager) = self.connection_manager.as_ref() {
                                    let controller = HandleConnectionController::new(handle);
                                    connection_manager.add_connection(ConnectionInfo::new(remote_addr.to_string(), local_addr.to_string(), StackProtocol::Quic, speed, controller));
                                }
                            }
                        }
                        "server" => {
                            if list.len() < 2 {
                                return Err(stack_err!(
                                    StackErrorCode::InvalidConfig,
                                    "invalid server command"
                                ));
                            }
                            let server_name = list[1].as_str();
                            let speed_stat = speed_stat.clone();
                            if let Some(server) = self.env.servers.get_server(server_name) {
                                match server {
                                    Server::Http(server) => {
                                        let mut h3_conn = match h3::server::Connection::<_, Bytes>::new(
                                            Http3Connection::new(
                                                h3_quinn::Connection::new(connection),
                                                local_addr,
                                                remote_addr,
                                                self.connection_manager.clone()))
                                            .await {
                                            Ok(h3_conn) => h3_conn,
                                            Err(e) => {
                                                return if e.is_h3_no_error() {
                                                    Ok(())
                                                } else {
                                                    Err(stack_err!(StackErrorCode::QuicError, "h3 new error: {e}"))
                                                }
                                            }
                                        };
                                        loop {
                                            let resolver = match h3_conn.accept().await {
                                                Ok(resolver) => resolver,
                                                Err(e) => {
                                                    if e.is_h3_no_error() {
                                                        break;
                                                    } else {
                                                        return Err(stack_err!(StackErrorCode::QuicError, "h3 accept error: {e}"))
                                                    }
                                                }
                                            };
                                            if resolver.is_none() {
                                                break;
                                            }
                                            let speed = speed_stat.clone();
                                            let limiter = limiter.clone();
                                            let server = server.clone();
                                            let speed_stat = speed_stat.clone();
                                            let handle = tokio::spawn(async move {
                                                let ret: StackResult<()> = async move {
                                                    let (req, stream) = resolver.unwrap().resolve_request().await
                                                        .map_err(into_stack_err!(StackErrorCode::QuicError, "h3 resolve request error"))?;
                                                    let (parts, _) = req.into_parts();
                                                    let (mut send, recv) = stream.split();
                                                    let recv_stream = StatRead::new_with_tracker(Http3Recv::new(recv), speed_stat.clone());
                                                    let (read_limit, write_limit) = if limiter.is_some() {
                                                        let (read_limit, write_limit) = limiter.as_ref().unwrap().new_limit_session();
                                                        (Some(read_limit), Some(write_limit))
                                                    } else {
                                                        (None, None)
                                                    };

                                                    let body = if read_limit.is_some() {
                                                        AsyncReadBody::with_capacity(LimitRead::new(recv_stream, read_limit.unwrap()), 4096)
                                                            .map_err(|e| server_err!(ServerErrorCode::IOError, "async read body error: {e}")).boxed()
                                                    } else {
                                                        AsyncReadBody::with_capacity(recv_stream, 4096)
                                                            .map_err(|e| server_err!(ServerErrorCode::IOError, "async read body error: {e}")).boxed()
                                                    };
                                                    let req = http::Request::from_parts(parts, body);
                                                    log::info!("recv http request:remote {} method {} host {} path {}",
                                                        remote_addr,
                                                        req.method().to_string(),
                                                        req.headers().get("host").map(|h| h.to_str().unwrap_or("none")).unwrap_or("none"),
                                                        req.uri().to_string());
                                                    let resp = server
                                                        .serve_request(req, StreamInfo::new(remote_addr.to_string()))
                                                        .await
                                                        .map_err(into_stack_err!(StackErrorCode::InvalidConfig))?;
                                                    let (parts, mut body) = resp.into_parts();

                                                    send.send_response(http::Response::from_parts(parts, ())).await
                                                        .map_err(into_stack_err!(StackErrorCode::QuicError, "h3 send response error"))?;

                                                    let send_stream = StatWrite::new_with_tracker(SimpleAsyncWriteHolder::new(Http3Send::new(send)), speed_stat.clone());
                                                    let mut send: Box<dyn AsyncWrite + Unpin + Send> = if write_limit.is_some() {
                                                        Box::new(LimitWrite::new(send_stream, write_limit.unwrap()))
                                                    } else {
                                                        Box::new(send_stream)
                                                    };
                                                    loop {
                                                        let mut pin_body = Pin::new(&mut body);
                                                        let data = poll_fn(move |cx| {
                                                            pin_body.as_mut().poll_frame(cx)
                                                        }).await;
                                                        match data {
                                                            Some(data) => {
                                                                let data = data.map_err(into_stack_err!(StackErrorCode::QuicError, "h3 map error"))?;
                                                                send.write_all(data.into_data()
                                                                    .map_err(|_e| stack_err!(StackErrorCode::QuicError, "h3 data error"))?.as_ref()).await
                                                                    .map_err(into_stack_err!(StackErrorCode::QuicError, "h3 send data error"))?;
                                                            }
                                                            None => {
                                                                break;
                                                            }
                                                        }
                                                    }
                                                    send.shutdown().await
                                                        .map_err(into_stack_err!(StackErrorCode::QuicError, "h3 finish error"))?;
                                                    Ok(())
                                                }.await;
                                                if let Err(e) = ret {
                                                    log::error!("server error: {}", e);
                                                }
                                            });

                                            if let Some(connection_manager) = self.connection_manager.as_ref() {
                                                let controller = HandleConnectionController::new(handle);
                                                connection_manager.add_connection(ConnectionInfo::new(remote_addr.to_string(), local_addr.to_string(), StackProtocol::Quic, speed, controller));
                                            }
                                        }
                                    }
                                    Server::Stream(server) => {
                                        loop {
                                            let (send, recv) = connection.accept_bi().await.map_err(into_stack_err!(StackErrorCode::QuicError))?;
                                            log::info!("quic accept bi: {} -> {}", remote_addr, local_addr);
                                            let server = server.clone();
                                            let stream = sfo_split::Splittable::new(recv, send);
                                            let stat_stream = StatStream::new_with_tracker(stream, speed_stat.clone());
                                            let speed = stat_stream.get_speed_stat();
                                            let stream: Box<dyn AsyncStream> = if limiter.is_some() {
                                                let (read_limit, write_limit) = limiter.as_ref().unwrap().new_limit_session();
                                                let limit_stream = LimitStream::new(stat_stream, read_limit, write_limit);
                                                Box::new(limit_stream)
                                            } else {
                                                Box::new(stat_stream)
                                            };
                                            let handle = tokio::spawn(async move {
                                                if let Err(e) = server.serve_connection(stream, StreamInfo::new(remote_addr.to_string())).await {
                                                    log::error!("server error: {}", e);
                                                }
                                            });
                                            if let Some(connection_manager) = self.connection_manager.as_ref() {
                                                let controller = HandleConnectionController::new(handle);
                                                connection_manager.add_connection(ConnectionInfo::new(remote_addr.to_string(), local_addr.to_string(), StackProtocol::Quic, speed, controller));
                                            }
                                        }
                                    }
                                    _ => {
                                        return Err(stack_err!(
                                            StackErrorCode::InvalidConfig,
                                            "Unsupport server type"
                                        ));
                                    }
                                }
                            }
                        }
                        v => {
                            log::error!("unknown command: {}", v);
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

async fn build_tls_domain_configs(
    certs: &[StackCertConfig],
) -> StackResult<Vec<TlsDomainConfig>> {
    let mut cert_list = Vec::with_capacity(certs.len());
    for cert_config in certs.iter() {
        if cert_config.cert_path.is_some() && cert_config.key_path.is_some() {
            let certs = load_certs(cert_config.cert_path.as_deref().unwrap()).await?;
            let key = load_key(cert_config.key_path.as_deref().unwrap()).await?;
            cert_list.push(TlsDomainConfig {
                domain: cert_config.domain.clone(),
                acme_type: None,
                certs: Some(certs),
                key: Some(key),
                data: None,
            });
        } else {
            cert_list.push(TlsDomainConfig {
                domain: cert_config.domain.clone(),
                acme_type: cert_config.acme_type.clone(),
                certs: None,
                key: None,
                data: cert_config.data.clone(),
            });
        }
    }
    Ok(cert_list)
}

pub struct Http3Body<S, B> {
    stream: RequestStream<S, B>,
}

impl<S, B> Http3Body<S, B> {
    pub fn new(stream: RequestStream<S, B>) -> Self {
        Self {
            stream,
        }
    }
}

impl<S, B> Body for Http3Body<S, B>
where
    S: quic::RecvStream + 'static,
    B: Buf + 'static,
{
    type Data = Bytes;
    type Error = ServerError;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.stream.poll_recv_data(cx) {
            Poll::Ready(ret) => {
                match ret {
                    Ok(Some(mut ret)) => {
                        Poll::Ready(Some(Ok(Frame::data(ret.copy_to_bytes(ret.remaining())))))
                    }
                    Ok(None) => {
                        Poll::Ready(None)
                    }
                    Err(e) => {
                        Poll::Ready(Some(Err(server_err!(ServerErrorCode::IOError, "{}", e))))
                    }
                }
            }
            Poll::Pending => {
                Poll::Pending
            }
        }
    }
}

#[pin_project]
#[derive(Debug)]
pub struct AsyncReadBody<T> {
    #[pin]
    reader: ReaderStream<T>,
}

impl<T> AsyncReadBody<T>
where
    T: AsyncRead + Send + 'static,
{
    /// Create a new [`AsyncReadBody`] wrapping the given reader,
    /// with a specific read buffer capacity
    pub(crate) fn with_capacity(read: T, capacity: usize) -> Self {
        Self {
            reader: ReaderStream::with_capacity(read, capacity),
        }
    }

    pub(crate) fn with_capacity_limited(
        read: T,
        capacity: usize,
        max_read_bytes: u64,
    ) -> AsyncReadBody<Take<T>> {
        AsyncReadBody {
            reader: ReaderStream::with_capacity(read.take(max_read_bytes), capacity),
        }
    }

    pub fn raw_stream(&mut self) -> &mut ReaderStream<T> {
        &mut self.reader
    }
}

impl<T> Body for AsyncReadBody<T>
where
    T: AsyncRead,
{
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match std::task::ready!(self.project().reader.poll_next(cx)) {
            Some(Ok(chunk)) => Poll::Ready(Some(Ok(Frame::data(chunk)))),
            Some(Err(err)) => Poll::Ready(Some(Err(err))),
            None => Poll::Ready(None),
        }
    }
}

pub struct Http3Recv<B: Buf + 'static + Send, R: quic::RecvStream + 'static> {
    recv: RequestStream<R, B>,
    cache: Option<Box<dyn Read + Send + Sync>>,
}

impl<B: Buf + 'static + Send,
    R: quic::RecvStream + 'static, > Http3Recv<B, R> {
    pub fn new(recv: RequestStream<R, B>) -> Self {
        Self {
            recv,
            cache: None,
        }
    }
}

impl<B: Buf + 'static + Send,
    R: quic::RecvStream + 'static> AsyncRead for Http3Recv<B, R>
{
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        if let Some(reader) = self.cache.as_mut() {
            let buf_ref = buf.initialize_unfilled();
            match reader.read(buf_ref) {
                Ok(n) => {
                    buf.advance(n);
                    if n == 0 {
                        self.cache = None;
                    } else {
                        return Poll::Ready(Ok(()));
                    }
                }
                Err(e) => {
                    return Poll::Ready(Err(e));
                }
            }
        }
        match self.recv.poll_recv_data(cx) {
            Poll::Ready(ret) => {
                match ret {
                    Ok(Some(ret)) => {
                        let remaining = ret.remaining();
                        let mut reader = Box::new(ret.reader());
                        let buf_ref = buf.initialize_unfilled();
                        match reader.read(buf_ref) {
                            Ok(n) => {
                                buf.advance(n);
                                if n < remaining {
                                    self.cache = Some(reader);
                                }
                            }
                            Err(e) => {
                                return Poll::Ready(Err(e));
                            }
                        }
                        Poll::Ready(Ok(()))
                    }
                    Ok(None) => {
                        Poll::Ready(Ok(()))
                    }
                    Err(e) => {
                        Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, e)))
                    }
                }
            }
            Poll::Pending => {
                Poll::Pending
            }
        }
    }
}

pub struct Http3Send<B: Buf + 'static + Send, S: quic::SendStream<B> + 'static> {
    send: RequestStream<S, B>,
}

impl<B: Buf + 'static + Send,
    S: quic::SendStream<B> + 'static, > Http3Send<B, S> {
    pub fn new(send: RequestStream<S, B>) -> Self {
        Self {
            send,
        }
    }

    pub fn raw_stream(&mut self) -> &mut RequestStream<S, B> {
        &mut self.send
    }
}

#[async_trait::async_trait]
impl<S: quic::SendStream<Bytes> + Send + Unpin + 'static, > SimpleAsyncWrite for Http3Send<Bytes, S> {
    async fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let static_buf = unsafe { std::mem::transmute::<&[u8], &'static [u8]>(buf) };
        match self.send.send_data(Bytes::from(static_buf)).await {
            Ok(()) => {
                Ok(buf.len())
            }
            Err(e) => {
                Err(std::io::Error::new(std::io::ErrorKind::Other, e))
            }
        }
    }

    async fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        self.send.finish().await.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }
}

pub struct Http3RecvStream {
    recv: h3_quinn::RecvStream,
    speed_tracker: Arc<dyn SpeedTracker>,
    notify: Arc<Notify>,
    has_stopped: Arc<AtomicBool>,
}

impl Drop for Http3RecvStream {
    fn drop(&mut self) {
        self.notify.notify_one();
    }
}

impl Http3RecvStream {
    pub fn new(recv: h3_quinn::RecvStream,
               speed_tracker: Arc<dyn SpeedTracker>,
               notify: Arc<Notify>,
               has_stopped: Arc<AtomicBool>, ) -> Self {
        Self {
            recv,
            speed_tracker,
            notify,
            has_stopped,
        }
    }
}

impl quic::RecvStream for Http3RecvStream {
    type Buf = Bytes;

    fn poll_data(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Self::Buf>, StreamErrorIncoming>> {
        if self.has_stopped.load(Ordering::Relaxed) {
            return Poll::Ready(Err(StreamErrorIncoming::ConnectionErrorIncoming { connection_error: ConnectionErrorIncoming::InternalError("user stopped".to_string()) }));
        }

        match self.recv.poll_data(cx) {
            Poll::Ready(Ok(Some(ret))) => {
                self.speed_tracker.add_read_data_size(ret.len() as u64);
                Poll::Ready(Ok(Some(ret)))
            }
            Poll::Ready(Ok(None)) => {
                Poll::Ready(Ok(None))
            }
            Poll::Ready(Err(e)) => {
                Poll::Ready(Err(e))
            }
            Poll::Pending => {
                Poll::Pending
            }
        }
    }

    fn stop_sending(&mut self, error_code: u64) {
        self.recv.stop_sending(error_code);
    }

    fn recv_id(&self) -> StreamId {
        self.recv.recv_id()
    }
}

pub struct Http3SendStream<B: Buf> {
    send: h3_quinn::SendStream<B>,
    speed_tracker: Arc<dyn SpeedTracker>,
    notify: Arc<Notify>,
    has_stopped: Arc<AtomicBool>,
}

impl<B: Buf> Drop for Http3SendStream<B> {
    fn drop(&mut self) {
        self.notify.notify_waiters();
    }
}

impl<B: Buf> Http3SendStream<B> {
    pub fn new(send: h3_quinn::SendStream<B>,
               speed_tracker: Arc<dyn SpeedTracker>,
               notify: Arc<Notify>,
               has_stopped: Arc<AtomicBool>, ) -> Self {
        Self {
            send,
            speed_tracker,
            notify,
            has_stopped,
        }
    }
}

impl<B: Buf> quic::SendStream<B> for Http3SendStream<B> {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.send.poll_ready(cx)
    }

    fn send_data<T: Into<WriteBuf<B>>>(&mut self, data: T) -> Result<(), StreamErrorIncoming> {
        if self.has_stopped.load(Ordering::Relaxed) {
            return Err(StreamErrorIncoming::ConnectionErrorIncoming { connection_error: ConnectionErrorIncoming::InternalError("user stopped".to_string()) });
        }

        let buf = data.into();
        self.speed_tracker.add_write_data_size(buf.remaining() as u64);
        self.send.send_data(buf)
    }

    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.send.poll_finish(cx)
    }

    fn reset(&mut self, reset_code: u64) {
        self.send.reset(reset_code);
    }

    fn send_id(&self) -> StreamId {
        self.send.send_id()
    }
}

pub struct Http3BidiStream<B: Buf> {
    send: Http3SendStream<B>,
    recv: Http3RecvStream,
}

impl<B: Buf> Http3BidiStream<B> {
    pub fn new(stream: h3_quinn::BidiStream<B>,
               speed_tracker: Arc<dyn SpeedTracker>,
               notify: Arc<Notify>,
               has_stopped: Arc<AtomicBool>, ) -> Self {
        let (send, recv) = stream.split();
        Self {
            send: Http3SendStream::new(send, speed_tracker.clone(), notify.clone(), has_stopped.clone()),
            recv: Http3RecvStream::new(recv, speed_tracker, notify, has_stopped),
        }
    }
}

impl<B: Buf> SendStream<B> for Http3BidiStream<B> {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.send.poll_ready(cx)
    }

    fn send_data<T: Into<WriteBuf<B>>>(&mut self, data: T) -> Result<(), StreamErrorIncoming> {
        self.send.send_data(data.into())
    }

    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.send.poll_finish(cx)
    }

    fn reset(&mut self, reset_code: u64) {
        self.send.reset(reset_code);
    }

    fn send_id(&self) -> StreamId {
        self.send.send_id()
    }
}

impl<B: Buf> RecvStream for Http3BidiStream<B> {
    type Buf = Bytes;

    fn poll_data(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Self::Buf>, StreamErrorIncoming>> {
        self.recv.poll_data(cx)
    }

    fn stop_sending(&mut self, error_code: u64) {
        self.recv.stop_sending(error_code);
    }

    fn recv_id(&self) -> StreamId {
        self.recv.recv_id()
    }
}

impl<B: Buf> quic::BidiStream<B> for Http3BidiStream<B> {
    type SendStream = Http3SendStream<B>;
    type RecvStream = Http3RecvStream;

    fn split(self) -> (Self::SendStream, Self::RecvStream) {
        (self.send, self.recv)
    }
}

pub struct Http3OpenStreams {
    streams: h3_quinn::OpenStreams,
    speed_tracker: Arc<dyn SpeedTracker>,
    notify: Arc<Notify>,
    has_stopped: Arc<AtomicBool>,
}

impl Http3OpenStreams {
    pub fn new(streams: h3_quinn::OpenStreams,
               speed_tracker: Arc<dyn SpeedTracker>,
               notify: Arc<Notify>,
               has_stopped: Arc<AtomicBool>, ) -> Self {
        Self {
            streams,
            speed_tracker,
            notify,
            has_stopped,
        }
    }
}

impl<B: Buf> quic::OpenStreams<B> for Http3OpenStreams {
    type BidiStream = Http3BidiStream<B>;
    type SendStream = Http3SendStream<B>;

    fn poll_open_bidi(&mut self, cx: &mut Context<'_>) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
        match self.streams.poll_open_bidi(cx) {
            Poll::Ready(Ok(stream)) => {
                Poll::Ready(Ok(Http3BidiStream::new(stream, self.speed_tracker.clone(), self.notify.clone(), self.has_stopped.clone())))
            }
            Poll::Ready(Err(e)) => {
                Poll::Ready(Err(e))
            }
            Poll::Pending => {
                Poll::Pending
            }
        }
    }

    fn poll_open_send(&mut self, cx: &mut Context<'_>) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
        match self.streams.poll_open_send(cx) {
            Poll::Ready(Ok(stream)) => {
                Poll::Ready(Ok(Http3SendStream::new(stream, self.speed_tracker.clone(), self.notify.clone(), self.has_stopped.clone())))
            }
            Poll::Ready(Err(e)) => {
                Poll::Ready(Err(e))
            }
            Poll::Pending => {
                Poll::Pending
            }
        }
    }

    fn close(&mut self, code: Code, reason: &[u8]) {
        <h3_quinn::OpenStreams as OpenStreams<B>>::close(&mut self.streams, code, reason);
    }
}

struct Http3ConnectionController {
    is_stopped: Arc<AtomicBool>,
    notify: Arc<Notify>,
    stopped: AtomicBool,
}

impl Http3ConnectionController {
    pub fn new(is_stopped: Arc<AtomicBool>,
               notify: Arc<Notify>) -> Self {
        Self {
            is_stopped,
            notify,
            stopped: AtomicBool::new(false),
        }
    }
}

#[async_trait::async_trait]
impl ConnectionController for Http3ConnectionController {
    fn stop_connection(&self) {
        self.is_stopped.store(true, Ordering::Relaxed);
    }

    async fn wait_stop(&self) {
        self.notify.notified().await;
        self.stopped.store(true, Ordering::Relaxed);
    }

    fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::Relaxed)
    }
}

pub struct Http3Connection {
    conn: h3_quinn::Connection,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    connection_manager: Option<ConnectionManagerRef>,
}

impl Http3Connection {
    pub fn new(conn: h3_quinn::Connection,
               local_addr: SocketAddr,
               remote_addr: SocketAddr,
               connection_manager: Option<ConnectionManagerRef>) -> Self {
        Self {
            conn,
            local_addr,
            remote_addr,
            connection_manager,
        }
    }
}

impl<B: Buf> OpenStreams<B> for Http3Connection {
    type BidiStream = Http3BidiStream<B>;
    type SendStream = Http3SendStream<B>;

    fn poll_open_bidi(&mut self, cx: &mut Context<'_>) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
        match self.conn.poll_open_bidi(cx) {
            Poll::Ready(Ok(stream)) => {
                let speed_tracker = Arc::new(SfoSpeedStat::new());
                let notify = Arc::new(Notify::new());
                let has_stopped = Arc::new(AtomicBool::new(false));
                if let Some(connection_manager) = &self.connection_manager {
                    let controller = Arc::new(Http3ConnectionController::new(has_stopped.clone(), notify.clone()));
                    connection_manager.add_connection(ConnectionInfo::new(self.remote_addr.to_string(), self.local_addr.to_string(), StackProtocol::Quic, speed_tracker.clone(), controller));
                }
                Poll::Ready(Ok(Http3BidiStream::new(stream, speed_tracker.clone(), notify.clone(), has_stopped.clone())))
            }
            Poll::Ready(Err(e)) => {
                Poll::Ready(Err(e))
            }
            Poll::Pending => {
                Poll::Pending
            }
        }
    }

    fn poll_open_send(&mut self, cx: &mut Context<'_>) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
        match self.conn.poll_open_send(cx) {
            Poll::Ready(Ok(stream)) => {
                let speed_tracker = Arc::new(SfoSpeedStat::new());
                let notify = Arc::new(Notify::new());
                let has_stopped = Arc::new(AtomicBool::new(false));
                if let Some(connection_manager) = &self.connection_manager {
                    let controller = Arc::new(Http3ConnectionController::new(has_stopped.clone(), notify.clone()));
                    connection_manager.add_connection(ConnectionInfo::new(self.remote_addr.to_string(), self.local_addr.to_string(), StackProtocol::Quic, speed_tracker.clone(), controller));
                }
                Poll::Ready(Ok(Http3SendStream::new(stream, speed_tracker.clone(), notify.clone(), has_stopped.clone())))
            }
            Poll::Ready(Err(e)) => {
                Poll::Ready(Err(e))
            }
            Poll::Pending => {
                Poll::Pending
            }
        }
    }

    fn close(&mut self, code: Code, reason: &[u8]) {
        <h3_quinn::Connection as OpenStreams<B>>::close(&mut self.conn, code, reason);
    }
}

impl<B: Buf> quic::Connection<B> for Http3Connection {
    type RecvStream = Http3RecvStream;
    type OpenStreams = Http3OpenStreams;

    fn poll_accept_recv(&mut self, cx: &mut Context<'_>) -> Poll<Result<Self::RecvStream, ConnectionErrorIncoming>> {
        match <h3_quinn::Connection as h3::quic::Connection<B>>::poll_accept_recv(&mut self.conn, cx) {
            Poll::Ready(Ok(stream)) => {
                let speed_tracker = Arc::new(SfoSpeedStat::new());
                let notify = Arc::new(Notify::new());
                let has_stopped = Arc::new(AtomicBool::new(false));
                if let Some(connection_manager) = &self.connection_manager {
                    let controller = Arc::new(Http3ConnectionController::new(has_stopped.clone(), notify.clone()));
                    connection_manager.add_connection(ConnectionInfo::new(self.remote_addr.to_string(), self.local_addr.to_string(), StackProtocol::Quic, speed_tracker.clone(), controller));
                }
                Poll::Ready(Ok(Http3RecvStream::new(stream, speed_tracker.clone(), notify.clone(), has_stopped.clone())))
            }
            Poll::Ready(Err(e)) => {
                Poll::Ready(Err(e))
            }
            Poll::Pending => {
                Poll::Pending
            }
        }
    }

    fn poll_accept_bidi(&mut self, cx: &mut Context<'_>) -> Poll<Result<Self::BidiStream, ConnectionErrorIncoming>> {
        match self.conn.poll_accept_bidi(cx) {
            Poll::Ready(Ok(stream)) => {
                let speed_tracker = Arc::new(SfoSpeedStat::new());
                let notify = Arc::new(Notify::new());
                let has_stopped = Arc::new(AtomicBool::new(false));
                if let Some(connection_manager) = &self.connection_manager {
                    let controller = Arc::new(Http3ConnectionController::new(has_stopped.clone(), notify.clone()));
                    connection_manager.add_connection(ConnectionInfo::new(self.remote_addr.to_string(), self.local_addr.to_string(), StackProtocol::Quic, speed_tracker.clone(), controller));
                }
                Poll::Ready(Ok(Http3BidiStream::new(stream, speed_tracker.clone(), notify.clone(), has_stopped.clone())))
            }
            Poll::Ready(Err(e)) => {
                Poll::Ready(Err(e))
            }
            Poll::Pending => {
                Poll::Pending
            }
        }
    }

    fn opener(&self) -> Self::OpenStreams {
        let speed_tracker = Arc::new(SfoSpeedStat::new());
        let notify = Arc::new(Notify::new());
        let has_stopped = Arc::new(AtomicBool::new(false));
        if let Some(connection_manager) = &self.connection_manager {
            let controller = Arc::new(Http3ConnectionController::new(has_stopped.clone(), notify.clone()));
            connection_manager.add_connection(ConnectionInfo::new(self.remote_addr.to_string(), self.local_addr.to_string(), StackProtocol::Quic, speed_tracker.clone(), controller));
        }
        Http3OpenStreams::new(<h3_quinn::Connection as h3::quic::Connection<B>>::opener(&self.conn), speed_tracker.clone(), notify.clone(), has_stopped.clone())
    }
}

struct QuicStackInner {
    id: String,
    bind_addr: String,
    concurrency: u32,
    certs: Arc<dyn ResolvesServerCert>,
    alpn_protocols: Vec<Vec<u8>>,
    connection_manager: Option<ConnectionManagerRef>,
    handler: Arc<RwLock<Arc<QuicConnectionHandler>>>,
}

impl QuicStackInner {
    async fn start(self: &Arc<Self>) -> StackResult<JoinHandle<()>> {
        let mut server_config = ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
            .with_protocol_versions(rustls::DEFAULT_VERSIONS)
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(self.certs.clone());
        server_config.alpn_protocols = self.alpn_protocols.clone();
        server_config.max_early_data_size = u32::MAX;
        let server_config = quinn::ServerConfig::with_crypto(
            Arc::new(QuicServerConfig::try_from(server_config)

                .map_err(into_stack_err!(StackErrorCode::InvalidConfig))?));
        let endpoint = quinn::Endpoint::server(server_config,
                                               self.bind_addr.parse()
                                                   .map_err(into_stack_err!(StackErrorCode::InvalidConfig))?)
            .map_err(|e| {
                println!("{}", e);
                into_stack_err!(StackErrorCode::InvalidConfig)(e)
            })?;

        let this = self.clone();
        let handle = tokio::spawn(async move {
            loop {
                match endpoint.accept().await {
                    None => {
                        log::error!("quic endpoint accept error");
                        break;
                    }
                    Some(conn) => {
                        if endpoint.open_connections() > this.concurrency as usize {
                            conn.refuse();
                            continue;
                        }
                        let this = this.clone();
                        tokio::spawn(async move {
                            if let Err(e) = this.accept(conn).await {
                                log::error!("quic accept error: {}", e);
                            }
                        });
                    }
                }
            }
        });
        Ok(handle)
    }

    async fn accept(self: &Arc<Self>, conn: Incoming) -> StackResult<()> {
        let local_addr: SocketAddr = self.bind_addr.parse()
            .map_err(into_stack_err!(StackErrorCode::InvalidConfig))?;
        let handler_snapshot = {
            let handler = self.handler.read().unwrap();
            handler.clone()
        };
        handler_snapshot.accept(conn, local_addr).await
    }
}

pub struct QuicStack {
    inner: Arc<QuicStackInner>,
    prepare_handler: Arc<RwLock<Option<Arc<QuicConnectionHandler>>>>,
    handle: Mutex<Option<JoinHandle<()>>>,
}

impl Drop for QuicStack {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.lock().unwrap().take() {
            handle.abort();
        }
    }
}

impl QuicStack {
    pub fn builder() -> QuicStackBuilder {
        QuicStackBuilder::new()
    }

    async fn create(mut builder: QuicStackBuilder) -> StackResult<Self> {
        if builder.id.is_none() {
            return Err(stack_err!(StackErrorCode::InvalidConfig, "id is required"));
        }
        if builder.bind.is_none() {
            return Err(stack_err!(StackErrorCode::InvalidConfig, "bind is required"));
        }
        if builder.hook_point.is_none() {
            return Err(stack_err!(StackErrorCode::InvalidConfig, "hook_point is required"));
        }
        if builder.stack_context.is_none() {
            return Err(stack_err!(StackErrorCode::InvalidConfig, "stack_context is required"));
        }

        let stack_context = builder.stack_context.unwrap();

        let handler = QuicConnectionHandler::create(
            builder.hook_point.take().unwrap(),
            stack_context.clone(),
            builder.connection_manager.clone(),
        )
            .await?;
        let handler = Arc::new(RwLock::new(Arc::new(handler)));
        let certs = QuicConnectionHandler::build_cert_resolver(builder.certs, stack_context.as_ref())?;

        Ok(QuicStack {
            inner: Arc::new(QuicStackInner {
                id: builder.id.take().unwrap(),
                bind_addr: builder.bind.take().unwrap(),
                concurrency: builder.concurrency,
                certs,
                alpn_protocols: builder.alpn_protocols,
                connection_manager: builder.connection_manager.clone(),
                handler,
            }),
            prepare_handler: Arc::new(Default::default()),
            handle: Mutex::new(None),
        })
    }
}

#[async_trait::async_trait]
impl Stack for QuicStack {
    fn id(&self) -> String {
        self.inner.id.clone()
    }

    fn stack_protocol(&self) -> StackProtocol {
        StackProtocol::Quic
    }

    fn get_bind_addr(&self) -> String {
        self.inner.bind_addr.clone()
    }

    async fn start(&self) -> StackResult<()> {
        {
            if self.handle.lock().unwrap().is_some() {
                return Ok(());
            }
        }
        let handle = self.inner.start().await?;
        *self.handle.lock().unwrap() = Some(handle);
        Ok(())
    }

    async fn prepare_update(&self, config: Arc<dyn StackConfig>, context: Option<Arc<dyn StackContext>>) -> StackResult<()> {
        let config = config.as_ref().as_any().downcast_ref::<QuicStackConfig>()
            .ok_or(stack_err!(StackErrorCode::InvalidConfig, "invalid quic stack config"))?;

        if config.id != self.inner.id {
            return Err(stack_err!(StackErrorCode::InvalidConfig, "id unmatch"));
        }

        if config.bind.to_string() != self.inner.bind_addr {
            return Err(stack_err!(StackErrorCode::BindUnmatched, "bind unmatch"));
        }

        let env = match context {
            Some(context) => {
                let quic_context = context.as_ref().as_any().downcast_ref::<QuicStackContext>()
                    .ok_or(stack_err!(StackErrorCode::InvalidConfig, "invalid quic stack context"))?;
                Arc::new(quic_context.clone())
            }
            None => self.inner.handler.read().unwrap().env.clone(),
        };

        let new_handler = QuicConnectionHandler::create(
            config.hook_point.clone(),
            env,
            self.inner.connection_manager.clone(),
        ).await?;
        *self.prepare_handler.write().unwrap() = Some(Arc::new(new_handler));
        Ok(())
    }

    async fn commit_update(&self) {
        if let Some(handler) = self.prepare_handler.write().unwrap().take() {
            *self.inner.handler.write().unwrap() = handler;
        }
    }

    async fn rollback_update(&self) {
        self.prepare_handler.write().unwrap().take();
    }
}

pub struct QuicStackBuilder {
    id: Option<String>,
    bind: Option<String>,
    hook_point: Option<ProcessChainConfigs>,
    certs: Vec<TlsDomainConfig>,
    alpn_protocols: Vec<Vec<u8>>,
    concurrency: u32,
    connection_manager: Option<ConnectionManagerRef>,
    stack_context: Option<Arc<QuicStackContext>>,
}

impl QuicStackBuilder {
    fn new() -> Self {
        QuicStackBuilder {
            id: None,
            bind: None,
            hook_point: None,
            certs: vec![],
            concurrency: 1024,
            alpn_protocols: vec![],
            connection_manager: None,
            stack_context: None,
        }
    }

    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }
    pub fn bind(mut self, bind: &str) -> Self {
        self.bind = Some(bind.to_string());
        self
    }

    pub fn hook_point(mut self, hook_point: ProcessChainConfigs) -> Self {
        self.hook_point = Some(hook_point);
        self
    }

    pub fn add_certs(mut self, certs: Vec<TlsDomainConfig>) -> Self {
        self.certs = certs;
        self
    }

    pub fn concurrency(mut self, concurrency: u32) -> Self {
        if concurrency == 0 {
            self.concurrency = u32::MAX;
        } else {
            self.concurrency = concurrency;
        }
        self
    }

    pub fn alpn_protocols(mut self, alpn: Vec<Vec<u8>>) -> Self {
        self.alpn_protocols = alpn;
        self
    }

    pub fn connection_manager(mut self, connection_manager: ConnectionManagerRef) -> Self {
        self.connection_manager = Some(connection_manager);
        self
    }

    pub fn stack_context(mut self, stack_context: Arc<QuicStackContext>) -> Self {
        self.stack_context = Some(stack_context);
        self
    }

    pub async fn build(self) -> StackResult<QuicStack> {
        QuicStack::create(self).await
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct QuicStackConfig {
    pub id: String,
    pub protocol: StackProtocol,
    pub bind: SocketAddr,
    pub concurrency: Option<u32>,
    pub hook_point: Vec<ProcessChainConfig>,
    pub certs: Vec<StackCertConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alpn_protocols: Option<Vec<String>>,
}

impl StackConfig for QuicStackConfig {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn stack_protocol(&self) -> StackProtocol {
        StackProtocol::Quic
    }

    fn get_config_json(&self) -> String {
        serde_json::to_string(self).unwrap()
    }
}

pub struct QuicStackFactory {
    connection_manager: ConnectionManagerRef,
}

impl QuicStackFactory {
    pub fn new(
        connection_manager: ConnectionManagerRef,
    ) -> Self {
        Self {
            connection_manager,
        }
    }
}

#[async_trait::async_trait]
impl StackFactory for QuicStackFactory {
    async fn create(
        &self,
        config: Arc<dyn StackConfig>,
        context: Arc<dyn StackContext>,
    ) -> StackResult<StackRef> {
        let config = config
            .as_any()
            .downcast_ref::<QuicStackConfig>()
            .ok_or(stack_err!(StackErrorCode::InvalidConfig, "invalid quic stack config"))?;
        let cert_list = build_tls_domain_configs(&config.certs).await?;
        let stack_context = context
            .as_ref()
            .as_any()
            .downcast_ref::<QuicStackContext>()
            .ok_or(stack_err!(StackErrorCode::InvalidConfig, "invalid quic stack context"))?;
        let stack_context = Arc::new(stack_context.clone());
        let stack = QuicStack::builder()
            .id(config.id.clone())
            .bind(config.bind.to_string().as_str())
            .connection_manager(self.connection_manager.clone())
            .hook_point(config.hook_point.clone())
            .add_certs(cert_list)
            .alpn_protocols(config.alpn_protocols.clone().unwrap_or(vec![]).iter().map(|s| s.as_bytes().to_vec()).collect())
            .concurrency(config.concurrency.unwrap_or(1024))
            .stack_context(stack_context)
            .build()
            .await?;
        Ok(Arc::new(stack))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use buckyos_kit::{AsyncStream};
    use h3::error::{ConnectionError, StreamError};
    use quinn::crypto::rustls::QuicClientConfig;
    use quinn::Endpoint;
    use rcgen::generate_simple_self_signed;
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::{ClientConfig, DigitallySignedStruct, Error, SignatureScheme};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use crate::{AcmeCertManager, AcmeCertManagerRef, ConnectionManager, DefaultLimiterManager, GlobalCollectionManager, GlobalCollectionManagerRef, LimiterManagerRef, ProcessChainConfigs, ProcessChainHttpServer, QuicStack, QuicStackConfig, QuicStackContext, QuicStackFactory, SelfCertMgr, SelfCertMgrRef, SelfCertConfig, Server, ServerManager, ServerManagerRef, ServerResult, Stack, StackContext, StackFactory, StackProtocol, StatManager, StatManagerRef, StreamInfo, StreamServer, TlsDomainConfig, TunnelManager, CertManagerConfig};
    use crate::global_process_chains::{GlobalProcessChains, GlobalProcessChainsRef};

    fn build_quic_context(
        servers: ServerManagerRef,
        tunnel_manager: TunnelManager,
        limiter_manager: LimiterManagerRef,
        stat_manager: StatManagerRef,
        acme_manager: AcmeCertManagerRef,
        self_cert_mgr: SelfCertMgrRef,
        global_process_chains: Option<GlobalProcessChainsRef>,
        global_collection_manager: Option<GlobalCollectionManagerRef>,
    ) -> Arc<QuicStackContext> {
        Arc::new(QuicStackContext::new(
            servers,
            tunnel_manager,
            limiter_manager,
            stat_manager,
            acme_manager,
            self_cert_mgr,
            global_process_chains,
            global_collection_manager,
        ))
    }

    #[tokio::test]
    async fn test_quic_stack_creation() {
        let subject_alt_names = vec!["www.buckyos.com".to_string(), "127.0.0.1".to_string()];
        let cert_key = generate_simple_self_signed(subject_alt_names).unwrap();
        let result = QuicStack::builder().build().await;
        assert!(result.is_err());
        let result = QuicStack::builder().bind("127.0.0.1:9080").build().await;
        assert!(result.is_err());
        let result = QuicStack::builder()
            .id("test")
            .bind("127.0.0.1:9080")
            .build()
            .await;
        assert!(result.is_err());
        let result = QuicStack::builder()
            .id("test")
            .bind("127.0.0.1:9080")
            .hook_point(vec![])
            .build()
            .await;
        assert!(result.is_err());
        let servers = Arc::new(ServerManager::new());
        let tunnel_manager = TunnelManager::new();
        let limiter_manager = Arc::new(DefaultLimiterManager::new());
        let stat_manager = StatManager::new();
        let acme_manager = AcmeCertManager::create(CertManagerConfig::default()).await.unwrap();
        let self_cert_mgr = SelfCertMgr::create(SelfCertConfig::default()).await.unwrap();
        let stack_context = build_quic_context(
            servers.clone(),
            tunnel_manager.clone(),
            limiter_manager.clone(),
            stat_manager.clone(),
            acme_manager.clone(),
            self_cert_mgr.clone(),
            None,
            None,
        );
        let result = QuicStack::builder()
            .id("test")
            .bind("127.0.0.1:9080")
            .hook_point(vec![])
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());
        let stack_context = build_quic_context(
            servers.clone(),
            tunnel_manager.clone(),
            limiter_manager.clone(),
            stat_manager.clone(),
            acme_manager.clone(),
            self_cert_mgr.clone(),
            Some(Arc::new(GlobalProcessChains::new())),
            None,
        );
        let result = QuicStack::builder()
            .id("test")
            .bind("127.0.0.1:9080")
            .hook_point(vec![])
            .add_certs(vec![TlsDomainConfig {
                domain: "www.buckyos.com".to_string(),
                acme_type: None,
                certs: Some(vec![cert_key.cert.der().clone()]),
                key: Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    cert_key.signing_key.serialize_der()),
                )),
                data: None,
            }])
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_quic_stack_reject() {
        let subject_alt_names = vec!["www.buckyos.com".to_string(), "127.0.0.1".to_string()];
        let cert_key = generate_simple_self_signed(subject_alt_names).unwrap();
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        reject;
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let stack_context = build_quic_context(
            Arc::new(ServerManager::new()),
            TunnelManager::new(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            AcmeCertManager::create(CertManagerConfig::default()).await.unwrap(),
            SelfCertMgr::create(SelfCertConfig::default()).await.unwrap(),
            Some(Arc::new(GlobalProcessChains::new())),
            None,
        );
        let result = QuicStack::builder()
            .id("test")
            .bind("127.0.0.1:9180")
            .hook_point(chains)
            .add_certs(vec![TlsDomainConfig {
                domain: "www.buckyos.com".to_string(),
                acme_type: None,
                certs: Some(vec![cert_key.cert.der().clone()]),
                key: Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    cert_key.signing_key.serialize_der()),
                )),
                data: None,
            }])
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());
        let stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());

        let mut config = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(rustls::DEFAULT_VERSIONS).unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();
        config.enable_early_data = true;
        // config.alpn_protocols = vec![b"h3".to_vec()];
        let client_config =
            quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(config).unwrap()));
        let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(client_config);
        let ret = endpoint.connect("127.0.0.1:9180".parse().unwrap(), "www.buckyos.com").unwrap();
        let ret = ret.await.unwrap();
        let (mut send, mut recv) = ret.open_bi().await.unwrap();
        let result = send
            .write_all(b"GET / HTTP/1.1\r\nHost: httpbin.org\r\n\r\n")
            .await;
        assert!(result.is_ok());
        let ret = recv.read(&mut [0; 1024]).await;
        assert!(ret.is_err());
    }

    #[tokio::test]
    async fn test_quic_stack_drop() {
        let subject_alt_names = vec!["www.buckyos.com".to_string(), "127.0.0.1".to_string()];
        let cert_key = generate_simple_self_signed(subject_alt_names).unwrap();
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        drop;
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let stack_context = build_quic_context(
            Arc::new(ServerManager::new()),
            TunnelManager::new(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            AcmeCertManager::create(CertManagerConfig::default()).await.unwrap(),
            SelfCertMgr::create(SelfCertConfig::default()).await.unwrap(),
            Some(Arc::new(GlobalProcessChains::new())),
            None,
        );
        let result = QuicStack::builder()
            .id("test")
            .bind("127.0.0.1:9181")
            .hook_point(chains)
            .add_certs(vec![TlsDomainConfig {
                domain: "www.buckyos.com".to_string(),
                acme_type: None,
                certs: Some(vec![cert_key.cert.der().clone()]),
                key: Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    cert_key.signing_key.serialize_der()),
                )),
                data: None,
            }])
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());
        let stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());

        let mut config = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(rustls::DEFAULT_VERSIONS).unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();
        config.enable_early_data = true;
        // config.alpn_protocols = vec![b"h3".to_vec()];
        let client_config =
            quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(config).unwrap()));
        let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(client_config);
        let ret = endpoint.connect("127.0.0.1:9181".parse().unwrap(), "www.buckyos.com").unwrap();
        let ret = ret.await.unwrap();
        let (mut send, mut recv) = ret.open_bi().await.unwrap();
        let result = send
            .write_all(b"GET / HTTP/1.1\r\nHost: httpbin.org\r\n\r\n")
            .await;
        assert!(result.is_ok());
        let ret = recv.read(&mut [0; 1024]).await;
        assert!(ret.is_err());
    }

    #[tokio::test]
    async fn test_quic_stack_self_cert() {
        let _subject_alt_names = vec!["www.buckyos.com".to_string(), "127.0.0.1".to_string()];
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        drop;
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let tls_self_certs_path = tempfile::env::temp_dir().join("quic_self_certs").to_string_lossy().to_string();
        let mut self_cert_config = SelfCertConfig::default();
        self_cert_config.store_path = tls_self_certs_path.clone();

        let stack_context = build_quic_context(
            Arc::new(ServerManager::new()),
            TunnelManager::new(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            AcmeCertManager::create(CertManagerConfig::default()).await.unwrap(),
            SelfCertMgr::create(self_cert_config).await.unwrap(),
            Some(Arc::new(GlobalProcessChains::new())),
            None,
        );
        let result = QuicStack::builder()
            .id("test")
            .bind("127.0.0.1:9193")
            .hook_point(chains)
            .add_certs(vec![TlsDomainConfig {
                domain: "*".to_string(),
                acme_type: None,
                certs: None,
                key: None,
                data: None,
            }])
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());
        let stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());
        tokio::time::sleep(Duration::from_secs(1)).await;

        let mut config = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(rustls::DEFAULT_VERSIONS).unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();
        config.enable_early_data = true;
        // config.alpn_protocols = vec![b"h3".to_vec()];
        let client_config =
            quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(config).unwrap()));
        let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(client_config);
        let ret = endpoint.connect("127.0.0.1:9193".parse().unwrap(), "www.buckyos.com").unwrap();
        let ret = ret.await.unwrap();
        let (mut send, mut recv) = ret.open_bi().await.unwrap();
        let result = send
            .write_all(b"GET / HTTP/1.1\r\nHost: httpbin.org\r\n\r\n")
            .await;
        assert!(result.is_ok());
        let ret = recv.read(&mut [0; 1024]).await;
        assert!(ret.is_err());

        tokio::fs::remove_dir_all(tls_self_certs_path).await.unwrap();
    }

    pub struct MockServer {
        id: String,
    }

    impl MockServer {
        pub fn new(id: String) -> Self {
            MockServer { id }
        }
    }

    #[async_trait::async_trait]
    impl StreamServer for MockServer {
        async fn serve_connection(&self, mut stream: Box<dyn AsyncStream>, _info: StreamInfo) -> ServerResult<()> {
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"test");
            stream.write_all("recv".as_bytes()).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            Ok(())
        }

        fn id(&self) -> String {
            self.id.clone()
        }
    }
    #[derive(Debug)]
    struct NoVerifier;

    impl ServerCertVerifier for NoVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer,
            _intermediates: &[CertificateDer],
            _server_name: &ServerName,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
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

    #[tokio::test]
    async fn test_quic_stack_server() {
        let subject_alt_names = vec!["www.buckyos.com".to_string(), "127.0.0.1".to_string()];
        let cert_key = generate_simple_self_signed(subject_alt_names).unwrap();
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "server www.buckyos.com";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let tunnel_manager = TunnelManager::new();

        let server_manager = Arc::new(ServerManager::new());
        let _ = server_manager.add_server(Server::Stream(Arc::new(MockServer::new("www.buckyos.com".to_string()))));
        let stack_context = build_quic_context(
            server_manager.clone(),
            tunnel_manager,
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            AcmeCertManager::create(CertManagerConfig::default()).await.unwrap(),
            SelfCertMgr::create(SelfCertConfig::default()).await.unwrap(),
            Some(Arc::new(GlobalProcessChains::new())),
            None,
        );
        let result = QuicStack::builder()
            .id("test")
            .bind("127.0.0.1:9185")
            .hook_point(chains)
            .add_certs(vec![TlsDomainConfig {
                domain: "www.buckyos.com".to_string(),
                acme_type: None,
                certs: Some(vec![cert_key.cert.der().clone()]),
                key: Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    cert_key.signing_key.serialize_der()),
                )),
                data: None,
            }])
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());
        let stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let mut config = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(rustls::DEFAULT_VERSIONS).unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();
        config.enable_early_data = true;
        // config.alpn_protocols = vec![b"h3".to_vec()];
        let client_config =
            quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(config).unwrap()));
        let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(client_config);
        let ret = endpoint.connect("127.0.0.1:9185".parse().unwrap(), "www.buckyos.com").unwrap();
        let ret = ret.await.unwrap();
        let (mut send, mut recv) = ret.open_bi().await.unwrap();
        let result = send.write_all(b"test").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 4];
        let ret = recv.read_exact(&mut buf).await;
        assert!(ret.is_ok());
        assert_eq!(&buf, b"recv");

        let ret = endpoint.connect("127.0.0.1:9185".parse().unwrap(), "www.buckyos.com").unwrap();
        let ret = ret.await.unwrap();
        let (mut send, mut recv) = ret.open_bi().await.unwrap();
        let result = send.write_all(b"test").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 4];
        let ret = recv.read_exact(&mut buf).await;
        assert!(ret.is_ok());
        assert_eq!(&buf, b"recv");
    }

    #[tokio::test]
    async fn test_http3_server() {
        let subject_alt_names = vec!["www.buckyos.com".to_string(), "127.0.0.1".to_string()];
        let cert_key = generate_simple_self_signed(subject_alt_names).unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        reject;
        "#;
        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let server_mgr = Arc::new(ServerManager::new());
        let http_server = ProcessChainHttpServer::builder()
            .id("www.buckyos.com")
            .version("HTTP/3")
            .h3_port(9186)
            .hook_point(chains)
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .server_mgr(Arc::downgrade(&server_mgr))
            .tunnel_manager(TunnelManager::new())
            .build().await.unwrap();

        let server_manager = Arc::new(ServerManager::new());
        let _ = server_manager.add_server(Server::Http(Arc::new(http_server)));

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "server www.buckyos.com";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let tunnel_manager = TunnelManager::new();
        let stack_context = build_quic_context(
            server_manager.clone(),
            tunnel_manager,
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            AcmeCertManager::create(CertManagerConfig::default()).await.unwrap(),
            SelfCertMgr::create(SelfCertConfig::default()).await.unwrap(),
            Some(Arc::new(GlobalProcessChains::new())),
            None,
        );
        let result = QuicStack::builder()
            .id("test")
            .bind("127.0.0.1:9186")
            .hook_point(chains)
            .add_certs(vec![TlsDomainConfig {
                domain: "www.buckyos.com".to_string(),
                acme_type: None,
                certs: Some(vec![cert_key.cert.der().clone()]),
                key: Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    cert_key.signing_key.serialize_der()),
                )),
                data: None,
            }])
            .alpn_protocols(vec![b"h2".to_vec(), b"h3".to_vec()])
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());
        let stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let mut config = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(rustls::DEFAULT_VERSIONS).unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();
        config.alpn_protocols = vec![b"h3".to_vec()];
        let client_config =
            quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(config).unwrap()));
        let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(client_config);
        let ret = endpoint.connect("127.0.0.1:9186".parse().unwrap(), "www.buckyos.com").unwrap();
        let ret = ret.await.unwrap();
        let quinn_conn = h3_quinn::Connection::new(ret);
        let (mut driver, mut send_request) = h3::client::new(quinn_conn).await.unwrap();
        let drive = async move {
            return Err::<(), ConnectionError>(std::future::poll_fn(|cx| driver.poll_close(cx)).await);
        };

        let request = async move {
            let req = http::Request::builder().uri("https://www.buckyos.com/").body(()).unwrap();
            let mut stream = send_request.send_request(req).await?;

            stream.finish().await?;
            let resp = stream.recv_response().await?;

            assert_eq!(resp.status(), http::StatusCode::FORBIDDEN);
            assert_eq!(resp.version(), http::Version::HTTP_3);

            Ok::<_, StreamError>(())
        };

        let (req_res, _drive_res) = tokio::join!(request, drive);

        assert!(req_res.is_ok());


        let ret = endpoint.connect("127.0.0.1:9186".parse().unwrap(), "www.buckyos.com").unwrap();
        let ret = ret.await.unwrap();
        let quinn_conn = h3_quinn::Connection::new(ret);
        let (mut driver, mut send_request) = h3::client::new(quinn_conn).await.unwrap();
        let drive = async move {
            return Err::<(), ConnectionError>(std::future::poll_fn(|cx| driver.poll_close(cx)).await);
        };

        let request = async move {
            let req = http::Request::builder().uri("https://www.buckyos.com/").body(()).unwrap();
            let mut stream = send_request.send_request(req).await?;

            stream.finish().await?;
            let resp = stream.recv_response().await?;

            assert_eq!(resp.status(), http::StatusCode::FORBIDDEN);
            assert_eq!(resp.version(), http::Version::HTTP_3);

            Ok::<_, StreamError>(())
        };

        let (req_res, _drive_res) = tokio::join!(request, drive);

        assert!(req_res.is_ok());
    }

    #[tokio::test]
    async fn test_quic_server_forward() {
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "forward tcp:///127.0.0.1:9183";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let subject_alt_names = vec!["www.buckyos.com".to_string(), "127.0.0.1".to_string()];
        let cert_key = generate_simple_self_signed(subject_alt_names).unwrap();
        let server_manager = Arc::new(ServerManager::new());
        let tunnel_manager = TunnelManager::new();
        let stack_context = build_quic_context(
            server_manager.clone(),
            tunnel_manager,
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            AcmeCertManager::create(CertManagerConfig::default()).await.unwrap(),
            SelfCertMgr::create(SelfCertConfig::default()).await.unwrap(),
            Some(Arc::new(GlobalProcessChains::new())),
            None,
        );
        let result = QuicStack::builder()
            .id("test")
            .bind("127.0.0.1:9188")
            .hook_point(chains)
            .add_certs(vec![TlsDomainConfig {
                domain: "www.buckyos.com".to_string(),
                acme_type: None,
                certs: Some(vec![cert_key.cert.der().clone()]),
                key: Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    cert_key.signing_key.serialize_der()),
                )),
                data: None,
            }])
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());
        let stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());


        tokio::spawn(async move {
            let tcp_listener = TcpListener::bind("127.0.0.1:9183").await.unwrap();
            if let Ok((mut tcp_stream, _)) = tcp_listener.accept().await {
                let mut buf = [0u8; 4];
                tcp_stream.read_exact(&mut buf).await.unwrap();
                assert_eq!(&buf, b"test");
                tcp_stream.write_all("recv".as_bytes()).await.unwrap();
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        });

        let mut config = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(rustls::DEFAULT_VERSIONS).unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();
        config.enable_early_data = true;
        let client_config =
            quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(config).unwrap()));
        let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(client_config);
        let ret = endpoint.connect("127.0.0.1:9188".parse().unwrap(), "www.buckyos.com").unwrap();
        let ret = ret.await.unwrap();
        let (mut send, mut recv) = ret.open_bi().await.unwrap();
        let result = send.write_all(b"test").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 4];
        let ret = recv.read_exact(&mut buf).await;
        assert!(ret.is_ok());
        assert_eq!(&buf, b"recv");
    }

    #[tokio::test]
    async fn test_quic_stack_stat_server() {
        let subject_alt_names = vec!["www.buckyos.com".to_string(), "127.0.0.1".to_string()];
        let cert_key = generate_simple_self_signed(subject_alt_names).unwrap();
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        set-stat test;
        return "server www.buckyos.com";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let tunnel_manager = TunnelManager::new();

        let stat_manager = StatManager::new();
        let server_manager = Arc::new(ServerManager::new());
        server_manager.add_server(Server::Stream(Arc::new(MockServer::new("www.buckyos.com".to_string())))).unwrap();
        let stack_context = build_quic_context(
            server_manager.clone(),
            tunnel_manager,
            Arc::new(DefaultLimiterManager::new()),
            stat_manager.clone(),
            AcmeCertManager::create(CertManagerConfig::default()).await.unwrap(),
            SelfCertMgr::create(SelfCertConfig::default()).await.unwrap(),
            Some(Arc::new(GlobalProcessChains::new())),
            None,
        );
        let result = QuicStack::builder()
            .id("test")
            .bind("127.0.0.1:9189")
            .hook_point(chains)
            .add_certs(vec![TlsDomainConfig {
                domain: "www.buckyos.com".to_string(),
                acme_type: None,
                certs: Some(vec![cert_key.cert.der().clone()]),
                key: Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    cert_key.signing_key.serialize_der()),
                )),
                data: None,
            }])
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());
        let stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let mut config = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(rustls::DEFAULT_VERSIONS).unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();
        config.enable_early_data = true;
        // config.alpn_protocols = vec![b"h3".to_vec()];
        let client_config =
            quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(config).unwrap()));
        let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(client_config);
        let ret = endpoint.connect("127.0.0.1:9189".parse().unwrap(), "www.buckyos.com").unwrap();
        let ret = ret.await.unwrap();
        let (mut send, mut recv) = ret.open_bi().await.unwrap();
        let result = send.write_all(b"test").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 4];
        let ret = recv.read_exact(&mut buf).await;
        assert!(ret.is_ok());
        assert_eq!(&buf, b"recv");
        let test_stat = stat_manager.get_speed_stat("test");
        assert!(test_stat.is_some());
        let test_stat = test_stat.unwrap();
        assert_eq!(test_stat.get_read_sum_size(), 4);
        assert_eq!(test_stat.get_write_sum_size(), 4);

        let ret = endpoint.connect("127.0.0.1:9189".parse().unwrap(), "www.buckyos.com").unwrap();
        let ret = ret.await.unwrap();
        let (mut send, mut recv) = ret.open_bi().await.unwrap();
        let result = send.write_all(b"test").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 4];
        let ret = recv.read_exact(&mut buf).await;
        assert!(ret.is_ok());
        assert_eq!(&buf, b"recv");
        assert_eq!(test_stat.get_read_sum_size(), 8);
        assert_eq!(test_stat.get_write_sum_size(), 8);
    }

    #[tokio::test]
    async fn test_quic_stack_stat_limit_server() {
        let subject_alt_names = vec!["www.buckyos.com".to_string(), "127.0.0.1".to_string()];
        let cert_key = generate_simple_self_signed(subject_alt_names).unwrap();
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        set-stat test;
        set-limit "2B/s" "2B/s";
        return "server www.buckyos.com";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let tunnel_manager = TunnelManager::new();

        let stat_manager = StatManager::new();
        let server_manager = Arc::new(ServerManager::new());
        server_manager.add_server(Server::Stream(Arc::new(MockServer::new("www.buckyos.com".to_string())))).unwrap();
        let stack_context = build_quic_context(
            server_manager.clone(),
            tunnel_manager,
            Arc::new(DefaultLimiterManager::new()),
            stat_manager.clone(),
            AcmeCertManager::create(CertManagerConfig::default()).await.unwrap(),
            SelfCertMgr::create(SelfCertConfig::default()).await.unwrap(),
            Some(Arc::new(GlobalProcessChains::new())),
            None,
        );
        let result = QuicStack::builder()
            .id("test")
            .bind("127.0.0.1:9190")
            .hook_point(chains)
            .add_certs(vec![TlsDomainConfig {
                domain: "www.buckyos.com".to_string(),
                acme_type: None,
                certs: Some(vec![cert_key.cert.der().clone()]),
                key: Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    cert_key.signing_key.serialize_der()),
                )),
                data: None,
            }])
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());
        let stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let mut config = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(rustls::DEFAULT_VERSIONS).unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();
        config.enable_early_data = true;
        // config.alpn_protocols = vec![b"h3".to_vec()];
        let client_config =
            quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(config).unwrap()));
        let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(client_config);
        let ret = endpoint.connect("127.0.0.1:9190".parse().unwrap(), "www.buckyos.com").unwrap();
        let ret = ret.await.unwrap();
        let (mut send, mut recv) = ret.open_bi().await.unwrap();
        let start = Instant::now();
        let result = send.write_all(b"test").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 4];
        let ret = recv.read_exact(&mut buf).await;
        ret.unwrap();
        // assert!(ret.is_ok());
        assert_eq!(&buf, b"recv");
        let test_stat = stat_manager.get_speed_stat("test");
        assert!(test_stat.is_some());
        let test_stat = test_stat.unwrap();
        assert_eq!(test_stat.get_read_sum_size(), 4);
        assert_eq!(test_stat.get_write_sum_size(), 4);
        assert!(start.elapsed().as_millis() > 1800);
        assert!(start.elapsed().as_millis() < 2500);

        let ret = endpoint.connect("127.0.0.1:9190".parse().unwrap(), "www.buckyos.com").unwrap();
        let ret = ret.await.unwrap();
        let (mut send, mut recv) = ret.open_bi().await.unwrap();
        let result = send.write_all(b"test").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 4];
        let ret = recv.read_exact(&mut buf).await;
        assert!(ret.is_ok());
        assert_eq!(&buf, b"recv");
        assert_eq!(test_stat.get_read_sum_size(), 8);
        assert_eq!(test_stat.get_write_sum_size(), 8);
        assert!(start.elapsed().as_millis() > 3800);
        assert!(start.elapsed().as_millis() < 4500);
    }

    #[tokio::test]
    async fn test_quic_stack_stat_group_limit_server() {
        let subject_alt_names = vec!["www.buckyos.com".to_string(), "127.0.0.1".to_string()];
        let cert_key = generate_simple_self_signed(subject_alt_names).unwrap();
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        set-stat test;
        set-limit test;
        return "server www.buckyos.com";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let tunnel_manager = TunnelManager::new();

        let stat_manager = StatManager::new();
        let mut limiter_manager = DefaultLimiterManager::new();
        let _ = limiter_manager.new_limiter("test".to_string(), None::<String>, Some(1), Some(2), Some(2));
        let limiter_manager = Arc::new(limiter_manager);
        let server_manager = Arc::new(ServerManager::new());
        server_manager.add_server(Server::Stream(Arc::new(MockServer::new("www.buckyos.com".to_string())))).unwrap();
        let stack_context = build_quic_context(
            server_manager.clone(),
            tunnel_manager,
            limiter_manager,
            stat_manager.clone(),
            AcmeCertManager::create(CertManagerConfig::default()).await.unwrap(),
            SelfCertMgr::create(SelfCertConfig::default()).await.unwrap(),
            Some(Arc::new(GlobalProcessChains::new())),
            None,
        );
        let result = QuicStack::builder()
            .id("test")
            .bind("127.0.0.1:9191")
            .hook_point(chains)
            .add_certs(vec![TlsDomainConfig {
                domain: "www.buckyos.com".to_string(),
                acme_type: None,
                certs: Some(vec![cert_key.cert.der().clone()]),
                key: Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    cert_key.signing_key.serialize_der()),
                )),
                data: None,
            }])
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());
        let stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let mut config = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(rustls::DEFAULT_VERSIONS).unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();
        config.enable_early_data = true;
        // config.alpn_protocols = vec![b"h3".to_vec()];
        let client_config =
            quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(config).unwrap()));
        let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(client_config);
        let ret = endpoint.connect("127.0.0.1:9191".parse().unwrap(), "www.buckyos.com").unwrap();
        let ret = ret.await.unwrap();
        let (mut send, mut recv) = ret.open_bi().await.unwrap();
        let start = Instant::now();
        let result = send.write_all(b"test").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 4];
        let ret = recv.read_exact(&mut buf).await;
        ret.unwrap();
        // assert!(ret.is_ok());
        assert_eq!(&buf, b"recv");
        let test_stat = stat_manager.get_speed_stat("test");
        assert!(test_stat.is_some());
        let test_stat = test_stat.unwrap();
        assert_eq!(test_stat.get_read_sum_size(), 4);
        assert_eq!(test_stat.get_write_sum_size(), 4);
        assert!(start.elapsed().as_millis() > 1800);
        assert!(start.elapsed().as_millis() < 2500);

        let ret = endpoint.connect("127.0.0.1:9191".parse().unwrap(), "www.buckyos.com").unwrap();
        let ret = ret.await.unwrap();
        let (mut send, mut recv) = ret.open_bi().await.unwrap();
        let result = send.write_all(b"test").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 4];
        let ret = recv.read_exact(&mut buf).await;
        assert!(ret.is_ok());
        assert_eq!(&buf, b"recv");
        assert_eq!(test_stat.get_read_sum_size(), 8);
        assert_eq!(test_stat.get_write_sum_size(), 8);
        assert!(start.elapsed().as_millis() > 3800);
        assert!(start.elapsed().as_millis() < 4500);
    }

    #[tokio::test]
    async fn test_quic_stack_stat_group_limit_server2() {
        let subject_alt_names = vec!["www.buckyos.com".to_string(), "127.0.0.1".to_string()];
        let cert_key = generate_simple_self_signed(subject_alt_names).unwrap();
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        set-stat test;
        set-limit test "10KB/s" "10KB/s";
        return "server www.buckyos.com";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let tunnel_manager = TunnelManager::new();

        let stat_manager = StatManager::new();
        let mut limiter_manager = DefaultLimiterManager::new();
        let _ = limiter_manager.new_limiter("test".to_string(), None::<String>, Some(1), Some(2), Some(2));
        let limiter_manager = Arc::new(limiter_manager);
        let server_manager = Arc::new(ServerManager::new());
        server_manager.add_server(Server::Stream(Arc::new(MockServer::new("www.buckyos.com".to_string())))).unwrap();
        let stack_context = build_quic_context(
            server_manager.clone(),
            tunnel_manager,
            limiter_manager,
            stat_manager.clone(),
            AcmeCertManager::create(CertManagerConfig::default()).await.unwrap(),
            SelfCertMgr::create(SelfCertConfig::default()).await.unwrap(),
            Some(Arc::new(GlobalProcessChains::new())),
            None,
        );
        let result = QuicStack::builder()
            .id("test")
            .bind("127.0.0.1:9192")
            .hook_point(chains)
            .add_certs(vec![TlsDomainConfig {
                domain: "www.buckyos.com".to_string(),
                acme_type: None,
                certs: Some(vec![cert_key.cert.der().clone()]),
                key: Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    cert_key.signing_key.serialize_der()),
                )),
                data: None,
            }])
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());
        let stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let mut config = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(rustls::DEFAULT_VERSIONS).unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();
        config.enable_early_data = true;
        // config.alpn_protocols = vec![b"h3".to_vec()];
        let client_config =
            quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(config).unwrap()));
        let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(client_config);
        let ret = endpoint.connect("127.0.0.1:9192".parse().unwrap(), "www.buckyos.com").unwrap();
        let ret = ret.await.unwrap();
        let (mut send, mut recv) = ret.open_bi().await.unwrap();
        let start = Instant::now();
        let result = send.write_all(b"test").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 4];
        let ret = recv.read_exact(&mut buf).await;
        ret.unwrap();
        // assert!(ret.is_ok());
        assert_eq!(&buf, b"recv");
        let test_stat = stat_manager.get_speed_stat("test");
        assert!(test_stat.is_some());
        let test_stat = test_stat.unwrap();
        assert_eq!(test_stat.get_read_sum_size(), 4);
        assert_eq!(test_stat.get_write_sum_size(), 4);
        assert!(start.elapsed().as_millis() > 1800);
        assert!(start.elapsed().as_millis() < 2500);

        let ret = endpoint.connect("127.0.0.1:9192".parse().unwrap(), "www.buckyos.com").unwrap();
        let ret = ret.await.unwrap();
        let (mut send, mut recv) = ret.open_bi().await.unwrap();
        let result = send.write_all(b"test").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 4];
        let ret = recv.read_exact(&mut buf).await;
        assert!(ret.is_ok());
        assert_eq!(&buf, b"recv");
        assert_eq!(test_stat.get_read_sum_size(), 8);
        assert_eq!(test_stat.get_write_sum_size(), 8);
        assert!(start.elapsed().as_millis() > 3800);
        assert!(start.elapsed().as_millis() < 4500);
    }

    #[tokio::test]
    async fn test_factory() {
        let mut cert_config = CertManagerConfig::default();
        let data_dir = tempfile::tempdir().unwrap();
        cert_config.keystore_path = data_dir.path().to_string_lossy().to_string();
        let cert_manager = AcmeCertManager::create(cert_config).await.unwrap();
        let self_cert_mgr = SelfCertMgr::create(SelfCertConfig::default()).await.unwrap();
        let server_manager = Arc::new(ServerManager::new());
        let global_process_chains = Arc::new(GlobalProcessChains::new());
        let tunnel_manager = TunnelManager::new();
        let limiter_manager = Arc::new(DefaultLimiterManager::new());
        let stat_manager = StatManager::new();
        let collection_manager = GlobalCollectionManager::create(vec![]).await.unwrap();

        let factory = QuicStackFactory::new(ConnectionManager::new());

        let config = QuicStackConfig {
            id: "test".to_string(),
            protocol: StackProtocol::Quic,
            bind: "127.0.0.1:3345".parse().unwrap(),
            concurrency: None,
            hook_point: vec![],
            certs: vec![],
            alpn_protocols: None,
        };
        let stack_context: Arc<dyn StackContext> = Arc::new(QuicStackContext::new(
            server_manager,
            tunnel_manager,
            limiter_manager,
            stat_manager,
            cert_manager,
            self_cert_mgr,
            Some(global_process_chains),
            Some(collection_manager),
        ));
        let ret = factory.create(Arc::new(config), stack_context).await;
        assert!(ret.is_ok());
    }
}
