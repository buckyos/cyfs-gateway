use super::udp::SocksUdpClient;
use crate::ip::UdpClient;
use crate::tunnel::*;
use crate::tunnel_mgr::now_ms;
use crate::tunnel_url_status::{
    TunnelProbeOptions, TunnelUrlProber, TunnelUrlProberRef, TunnelUrlStatus,
    TunnelUrlStatusSource, normalize_tunnel_url, reachable_status, unreachable_status,
};
use crate::{TunnelError, TunnelResult};
use async_trait::async_trait;
use buckyos_kit::AsyncStream;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio_socks::tcp::Socks5Stream;
use url::Url;

enum SocksAuth {
    None,
    UsernamePassword(String, String),
}

struct SocksServerInfo {
    host: String,
    port: u16,
    auth: SocksAuth,
}

impl SocksServerInfo {
    pub fn server(&self) -> (&str, u16) {
        (self.host.as_str(), self.port)
    }

    pub fn from_target(target_id: &str) -> TunnelResult<Self> {
        let target = format!("socks://{}", target_id);
        debug!("socks target: {}", target);
        let url = Url::parse(target.as_str()).map_err(|e| {
            let msg = format!("Invalid socks target url: {}", e);
            error!("{}", msg);
            TunnelError::UrlParseError(target.to_owned(), msg)
        })?;

        let host = url.host_str().ok_or_else(|| {
            let msg = format!("Invalid socks target host");
            error!("{}", msg);
            TunnelError::UrlParseError(target.to_owned(), msg)
        })?;

        let port = url.port().unwrap_or(1080);

        // Parse auth
        let username = url.username().to_string();
        let password = url.password().map(|p| p.to_string());
        let auth = if username.is_empty() {
            SocksAuth::None
        } else {
            SocksAuth::UsernamePassword(username, password.unwrap_or_default())
        };

        Ok(Self {
            host: host.to_string(),
            port,
            auth,
        })
    }
}

#[derive(Clone)]
pub struct SocksTunnel {
    socks_server: Option<Arc<SocksServerInfo>>,
}

impl SocksTunnel {
    pub async fn new(target_id: Option<&str>) -> TunnelResult<Self> {
        let socks_server = match target_id {
            Some(target) => {
                let socks_server = SocksServerInfo::from_target(target)?;
                Some(socks_server)
            }
            None => None,
        };

        Ok(Self {
            socks_server: socks_server.map(|s| Arc::new(s)),
        })
    }
}

#[async_trait::async_trait]
impl Tunnel for SocksTunnel {
    async fn ping(&self) -> Result<(), std::io::Error> {
        warn!("Socks tunnel's ping not implemented");
        Ok(())
    }

    async fn open_stream_by_dest(
        &self,
        dest_port: u16,
        dest_host: Option<String>,
    ) -> Result<Box<dyn AsyncStream>, std::io::Error> {
        debug!(
            "socks_tunnel open_stream_by_dest: {:?}:{}",
            dest_host, dest_port
        );
        // FIXME what should we do if dest_host is None or the port is 0?
        let dest_host = dest_host.unwrap_or("127.0.0.1".to_string());
        let dest_port = if dest_port == 0 { 80 } else { dest_port };

        match self.socks_server {
            Some(ref socks_server) => {
                // Establish a SOCKS5 tunnel with optional username and password
                let ret = match socks_server.auth {
                    SocksAuth::UsernamePassword(ref username, ref password) => {
                        Socks5Stream::connect_with_password(
                            (socks_server.host.as_str(), socks_server.port),
                            (dest_host.as_str(), dest_port),
                            &username,
                            &password,
                        )
                        .await
                    }
                    SocksAuth::None => {
                        Socks5Stream::connect(
                            (socks_server.host.as_str(), socks_server.port),
                            (dest_host.as_str(), dest_port),
                        )
                        .await
                    }
                };

                ret.as_ref().map_err(|e| {
                    let msg = format!(
                        "Failed to establish SOCKS5 tunnel: {:?}, {}",
                        socks_server.server(),
                        e
                    );
                    error!("{}", msg);
                    std::io::Error::new(std::io::ErrorKind::Other, msg)
                })?;

                let stream = ret.unwrap();
                Ok(Box::new(stream))
            }
            None => {
                let dest_addr = format!("{}:{}", dest_host, dest_port);
                let stream = tokio::net::TcpStream::connect(&dest_addr)
                    .await
                    .map_err(|e| {
                        let msg = format!("Failed to connect to target: {}, {}", dest_addr, e);
                        error!("{}", msg);
                        std::io::Error::new(std::io::ErrorKind::Other, msg)
                    })?;

                Ok(Box::new(stream))
            }
        }
    }

    async fn open_stream(&self, stream_id: &str) -> Result<Box<dyn AsyncStream>, std::io::Error> {
        debug!("socks_tunnel open_stream: {}", stream_id);
        let (dest_host, dest_port) = get_dest_info_from_url_path(stream_id)?;
        self.open_stream_by_dest(dest_port, dest_host).await
    }

    async fn create_datagram_client_by_dest(
        &self,
        dest_port: u16,
        dest_host: Option<String>,
    ) -> Result<Box<dyn DatagramClientBox>, std::io::Error> {
        // FIXME what should we do if dest_host is None or the port is 0?
        let dest_host = dest_host.unwrap_or("0.0.0.0".to_string());
        let dest_port = if dest_port == 0 { 80 } else { dest_port };

        match self.socks_server {
            Some(ref socks_server) => {
                let client =
                    libsocks_client::SocksClientBuilder::new(&socks_server.host, socks_server.port)
                        .socks5();
                let client = match socks_server.auth {
                    SocksAuth::UsernamePassword(ref username, ref password) => {
                        client.username(username).password(password)
                    }
                    SocksAuth::None => client,
                };

                let mut client = client.build_udp_client();
                client.udp_associate("0.0.0.0", 0).await.map_err(|e| {
                    let msg = format!(
                        "Failed to establish SOCKS5 UDP tunnel: {:?}, {:?}, {}",
                        socks_server.server(),
                        (&dest_host, dest_port),
                        e
                    );
                    error!("{}", msg);
                    std::io::Error::new(std::io::ErrorKind::Other, msg)
                })?;

                let socket: libsocks_client::SocksUdpSocket =
                    client.get_udp_socket("0.0.0.0:0").await.map_err(|e| {
                        let msg = format!(
                            "Failed to get UDP socket for SOCKS5 UDP tunnel: {:?}, {:?}, {}",
                            socks_server.server(),
                            (&dest_host, dest_port),
                            e
                        );
                        error!("{}", msg);
                        std::io::Error::new(std::io::ErrorKind::Other, msg)
                    })?;

                let client = SocksUdpClient::new(socket, dest_host, dest_port);
                Ok(Box::new(client))
            }
            None => {
                let client = UdpClient::new(dest_host, dest_port, None).await?;
                Ok(Box::new(client))
            }
        }
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

pub struct SocksTunnelBuilder {}

impl SocksTunnelBuilder {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl TunnelBuilder for SocksTunnelBuilder {
    async fn create_tunnel(
        &self,
        tunnel_stack_id: Option<&str>,
    ) -> TunnelResult<Box<dyn TunnelBox>> {
        debug!(
            "socks_tunnel_builder create_tunnel: {}",
            tunnel_stack_id.unwrap_or("")
        );
        let tunnel = SocksTunnel::new(tunnel_stack_id).await?;
        Ok(Box::new(tunnel))
    }

    fn url_prober(&self) -> Option<TunnelUrlProberRef> {
        Some(Arc::new(SocksUrlProber {}))
    }
}

/// SOCKS5 CONNECT probe: connects through the SOCKS server in the URL
/// authority, asks it to CONNECT to the target encoded in the URL path,
/// then drops the stream. Verifies both proxy availability and target
/// reachability through the proxy (per requirement §10.3).
struct SocksUrlProber;

#[async_trait]
impl TunnelUrlProber for SocksUrlProber {
    async fn probe_url(
        &self,
        url: &Url,
        options: &TunnelProbeOptions,
    ) -> TunnelResult<TunnelUrlStatus> {
        let normalized = normalize_tunnel_url(url);
        let now = now_ms();
        let auth = url.authority();
        if auth.is_empty() {
            return Ok(unreachable_status(
                url,
                &normalized,
                now,
                TunnelUrlStatusSource::FreshProbe,
                "socks url has no proxy authority".to_string(),
            ));
        }
        let server = match SocksServerInfo::from_target(auth) {
            Ok(s) => s,
            Err(e) => {
                return Ok(unreachable_status(
                    url,
                    &normalized,
                    now,
                    TunnelUrlStatusSource::FreshProbe,
                    format!("socks server parse: {}", e),
                ));
            }
        };
        let path = url.path().trim_start_matches('/');
        let (dest_host, dest_port) = match get_dest_info_from_url_path(path) {
            Ok((Some(h), p)) => (h, p),
            Ok((None, _)) => {
                return Ok(unreachable_status(
                    url,
                    &normalized,
                    now,
                    TunnelUrlStatusSource::FreshProbe,
                    "socks target requires explicit host".to_string(),
                ));
            }
            Err(e) => {
                return Ok(unreachable_status(
                    url,
                    &normalized,
                    now,
                    TunnelUrlStatusSource::FreshProbe,
                    format!("socks target parse: {}", e),
                ));
            }
        };
        let timeout_dur = Duration::from_millis(options.timeout_ms_or_default());
        let started = Instant::now();
        let probe = async {
            match &server.auth {
                SocksAuth::UsernamePassword(u, p) => {
                    Socks5Stream::connect_with_password(
                        (server.host.as_str(), server.port),
                        (dest_host.as_str(), dest_port),
                        u,
                        p,
                    )
                    .await
                }
                SocksAuth::None => {
                    Socks5Stream::connect(
                        (server.host.as_str(), server.port),
                        (dest_host.as_str(), dest_port),
                    )
                    .await
                }
            }
        };
        match tokio::time::timeout(timeout_dur, probe).await {
            Ok(Ok(_stream)) => Ok(reachable_status(
                url,
                &normalized,
                now,
                TunnelUrlStatusSource::FreshProbe,
                Some(started.elapsed().as_millis() as u64),
            )),
            Ok(Err(e)) => Ok(unreachable_status(
                url,
                &normalized,
                now,
                TunnelUrlStatusSource::FreshProbe,
                format!("socks_connect: {}", e),
            )),
            Err(_) => Ok(unreachable_status(
                url,
                &normalized,
                now,
                TunnelUrlStatusSource::FreshProbe,
                "socks_connect_timeout".to_string(),
            )),
        }
    }
}
