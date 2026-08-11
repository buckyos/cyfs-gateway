use super::udp::UdpClient;
use crate::TunnelResult;
use crate::tunnel::*;
use crate::tunnel_mgr::now_ms;
use crate::tunnel_url_status::{
    TunnelProbeOptions, TunnelUrlProber, TunnelUrlProberRef, TunnelUrlStatus,
    TunnelUrlStatusSource, normalize_tunnel_url, reachable_status, unreachable_status,
};
use async_trait::async_trait;
use buckyos_kit::AsyncStream;
use name_client::resolve_ip;
use percent_encoding::percent_decode;
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use rustls_platform_verifier::BuilderVerifierExt;
use std::io::Error;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio_rustls::TlsConnector;
use url::Url;

#[derive(Clone)]
pub struct IPTunnel {
    pub ip_stack_id: Option<String>,
}

impl IPTunnel {
    pub fn new(ip_stack_id: Option<&str>) -> IPTunnel {
        IPTunnel {
            ip_stack_id: ip_stack_id.map(|s| s.to_string()),
        }
    }

    async fn open_tcp_stream_by_dest(
        &self,
        dest_port: u16,
        dest_host: Option<String>,
    ) -> Result<Box<dyn AsyncStream>, std::io::Error> {
        let dest_addr = match dest_host {
            Some(host) => format!("{}:{}", host, dest_port),
            None => {
                if self.ip_stack_id.is_none() {
                    format!("127.0.0.1:{}", dest_port)
                } else {
                    format!("{}:{}", self.ip_stack_id.as_ref().unwrap(), dest_port)
                }
            }
        };

        let stream;
        if self.ip_stack_id.is_none() {
            debug!("use any tcp client addr for open_stream : {}", dest_addr);
            stream = tokio::net::TcpStream::connect(dest_addr).await?;
        } else {
            let bind_addr = self.ip_stack_id.as_ref().unwrap();
            let is_ipv4 = is_ipv4_addr_str(bind_addr)?;
            let socket;
            if is_ipv4 {
                socket = tokio::net::TcpSocket::new_v4().unwrap();
            } else {
                socket = tokio::net::TcpSocket::new_v6().unwrap();
            }
            let local_bind_addr: SocketAddr = format!("{}:0", bind_addr)
                .parse()
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "invalid bind addr"))?;
            socket.bind(local_bind_addr)?;
            debug!(
                "use {:?} tcp client addr for open_stream : {}",
                local_bind_addr, dest_addr
            );
            let dest_addr: SocketAddr = dest_addr
                .parse()
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "invalid dest addr"))?;
            stream = socket.connect(dest_addr).await?;
        }

        Ok(Box::new(stream))
    }

    async fn open_tls_stream_by_dest(
        &self,
        dest_port: u16,
        dest_host: Option<String>,
    ) -> Result<Box<dyn AsyncStream>, std::io::Error> {
        if dest_host.is_none() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "invalid dest host",
            ));
        }

        // Resolve IP address
        let ip = resolve_ip(dest_host.as_ref().unwrap().as_str())
            .await
            .map_err(|e| Error::new(std::io::ErrorKind::Other, e))?;

        let dest_addr = format!("{}:{}", ip, dest_port);
        let stream;
        if self.ip_stack_id.is_none() {
            debug!("use any tcp client addr for open_stream : {}", dest_addr);
            stream = tokio::net::TcpStream::connect(dest_addr).await?;
        } else {
            let bind_addr = self.ip_stack_id.as_ref().unwrap();
            let is_ipv4 = is_ipv4_addr_str(bind_addr)?;
            let socket;
            if is_ipv4 {
                socket = tokio::net::TcpSocket::new_v4().unwrap();
            } else {
                socket = tokio::net::TcpSocket::new_v6().unwrap();
            }
            let local_bind_addr: SocketAddr = format!("{}:0", bind_addr)
                .parse()
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "invalid bind addr"))?;
            socket.bind(local_bind_addr)?;
            debug!(
                "use {:?} tcp client addr for open_stream : {}",
                local_bind_addr, dest_addr
            );
            let dest_addr: SocketAddr = dest_addr
                .parse()
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "invalid dest addr"))?;
            stream = socket.connect(dest_addr).await?;
        }

        // Configure TLS
        let mut config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .map_err(|e| Error::new(std::io::ErrorKind::Other, e))?
                .with_platform_verifier()
                .map_err(|e| Error::new(std::io::ErrorKind::Other, e))?
                .with_no_client_auth();

        // Enable early data if needed
        config.enable_early_data = true;

        let connector = TlsConnector::from(Arc::new(config));
        let domain = ServerName::try_from(dest_host.as_ref().unwrap().to_string())
            .map_err(|e| Error::new(std::io::ErrorKind::Other, e))?;

        // Establish TLS connection
        let tls_stream = connector
            .connect(domain, stream)
            .await
            .map_err(|e| Error::new(std::io::ErrorKind::Other, e))?;

        Ok(Box::new(tls_stream))
    }
}

#[async_trait]
impl Tunnel for IPTunnel {
    async fn ping(&self) -> Result<(), std::io::Error> {
        warn!("IP tunnel's ping not implemented");
        Ok(())
    }

    async fn open_stream_by_dest(
        &self,
        dest_port: u16,
        dest_host: Option<String>,
    ) -> Result<Box<dyn AsyncStream>, Error> {
        self.open_tcp_stream_by_dest(dest_port, dest_host).await
    }

    async fn open_stream(&self, stream_id: &str) -> Result<Box<dyn AsyncStream>, std::io::Error> {
        let stream_id = percent_decode(stream_id.as_bytes())
            .decode_utf8()
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "invalid stream id"))?
            .to_string();
        debug!("ip_tunnel open_stream: {}", stream_id);
        let stream_id = stream_id.trim_start_matches('/');
        // 检测stream_id中是否有协议头
        if !has_scheme(stream_id) {
            let (dest_host, dest_port) = get_dest_info_from_url_path(stream_id)?;
            self.open_tcp_stream_by_dest(dest_port, dest_host).await
        } else {
            match Url::parse(&stream_id) {
                Ok(url) => {
                    if url.port().is_none() {
                        let msg = format!("none dest port, dest_id: {}", stream_id);
                        log::error!("{}", msg.as_str());
                        return Err(std::io::Error::new(std::io::ErrorKind::Other, msg));
                    }

                    if url.scheme() == "tcp" {
                        self.open_tcp_stream_by_dest(
                            url.port().unwrap(),
                            url.host().map(|h| h.to_string()),
                        )
                        .await
                    } else if url.scheme() == "tls" {
                        self.open_tls_stream_by_dest(
                            url.port().unwrap(),
                            url.host().map(|h| h.to_string()),
                        )
                        .await
                    } else {
                        let msg = format!("unsupported protocol: {}", url.scheme());
                        log::error!("{}", msg.as_str());
                        return Err(std::io::Error::new(std::io::ErrorKind::Other, msg));
                    }
                }
                Err(e) => {
                    let msg = format!("parse url {} error: {}", stream_id, e);
                    log::error!("{}", msg.as_str());
                    Err(std::io::Error::new(std::io::ErrorKind::Other, msg))
                }
            }
        }
    }

    async fn create_datagram_client_by_dest(
        &self,
        dest_port: u16,
        dest_host: Option<String>,
    ) -> Result<Box<dyn DatagramClientBox>, Error> {
        let real_dest_host;
        if dest_host.is_none() {
            if self.ip_stack_id.is_none() {
                real_dest_host = "127.0.0.1".to_string();
            } else {
                real_dest_host = self.ip_stack_id.as_ref().unwrap().to_string();
            }
        } else {
            real_dest_host = dest_host.unwrap();
        }

        let client = UdpClient::new(real_dest_host, dest_port, self.ip_stack_id.clone()).await?;
        Ok(Box::new(client))
    }

    async fn create_datagram_client(
        &self,
        session_id: &str,
    ) -> Result<Box<dyn DatagramClientBox>, std::io::Error> {
        let (dest_host, dest_port) = get_dest_info_from_url_path(session_id)?;
        self.create_datagram_client_by_dest(dest_port, dest_host)
            .await
    }
}

pub struct IPTunnelBuilder {
    // `udp` reuses this builder. UDP has no generic reachability, so we
    // skip the prober for that scheme and let TunnelManager fall back to
    // `Unsupported`.
    enable_prober: bool,
}

impl IPTunnelBuilder {
    pub fn new() -> IPTunnelBuilder {
        IPTunnelBuilder {
            enable_prober: true,
        }
    }

    pub fn new_no_prober() -> IPTunnelBuilder {
        IPTunnelBuilder {
            enable_prober: false,
        }
    }
}

#[async_trait]
impl TunnelBuilder for IPTunnelBuilder {
    async fn create_tunnel(&self, target_id: Option<&str>) -> TunnelResult<Box<dyn TunnelBox>> {
        Ok(Box::new(IPTunnel::new(target_id)))
    }

    fn url_prober(&self) -> Option<TunnelUrlProberRef> {
        if !self.enable_prober {
            return None;
        }
        Some(Arc::new(TcpUrlProber {}))
    }
}

/// Lightweight TCP connect probe. Resolves the target host, attempts a
/// TCP handshake within `options.timeout_ms`, then drops the socket.
/// RTT is the connect duration — *not* business first-byte latency, and
/// not directly comparable to RTCP ping RTT (per requirement §10.1).
pub struct TcpUrlProber;

#[async_trait]
impl TunnelUrlProber for TcpUrlProber {
    async fn probe_url(
        &self,
        url: &Url,
        options: &TunnelProbeOptions,
    ) -> TunnelResult<TunnelUrlStatus> {
        let normalized = normalize_tunnel_url(url);
        let now = now_ms();
        let (host, port) = match extract_host_port(url) {
            Some(p) => p,
            None => {
                return Ok(unreachable_status(
                    url,
                    &normalized,
                    now,
                    TunnelUrlStatusSource::FreshProbe,
                    "tcp url has no resolvable host:port".to_string(),
                ));
            }
        };
        let timeout_dur = Duration::from_millis(options.timeout_ms_or_default());
        let started = Instant::now();
        let connect = async {
            let ip = resolve_ip(host.as_str())
                .await
                .map_err(|e| format!("resolve {}: {}", host, e))?;
            let addr = format!("{}:{}", ip, port);
            tokio::net::TcpStream::connect(&addr)
                .await
                .map_err(|e| format!("connect {}: {}", addr, e))
        };
        match tokio::time::timeout(timeout_dur, connect).await {
            Ok(Ok(_stream)) => Ok(reachable_status(
                url,
                &normalized,
                now,
                TunnelUrlStatusSource::FreshProbe,
                Some(started.elapsed().as_millis() as u64),
            )),
            Ok(Err(reason)) => Ok(unreachable_status(
                url,
                &normalized,
                now,
                TunnelUrlStatusSource::FreshProbe,
                reason,
            )),
            Err(_) => Ok(unreachable_status(
                url,
                &normalized,
                now,
                TunnelUrlStatusSource::FreshProbe,
                "tcp_connect_timeout".to_string(),
            )),
        }
    }
}

/// Extract `(host, port)` from a tunnel URL. The path encodes the target
/// for IP-style schemes (e.g. `tcp:///host:port` or `tcp://bind/:port`).
/// Falls back to the URL authority when the path is empty.
pub fn extract_host_port(url: &Url) -> Option<(String, u16)> {
    let path = url.path().trim_start_matches('/');
    if !path.is_empty() {
        if let Ok((h, p)) = get_dest_info_from_url_path(path) {
            let host = h.unwrap_or_else(|| {
                url.host_str()
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "127.0.0.1".to_string())
            });
            return Some((host, p));
        }
    }
    let host = url.host_str()?;
    let port = url.port()?;
    Some((host.to_string(), port))
}
