use crate::ip::extract_host_port;
use crate::tunnel_mgr::now_ms;
use crate::tunnel_url_status::{
    TunnelProbeOptions, TunnelUrlProber, TunnelUrlProberRef, TunnelUrlStatus,
    TunnelUrlStatusSource, normalize_tunnel_url, reachable_status, unreachable_status,
};
use crate::{
    DatagramClientBox, Tunnel, TunnelBox, TunnelBuilder, TunnelResult, get_dest_info_from_url_path,
};
use async_trait::async_trait;
use buckyos_kit::AsyncStream;
use name_client::resolve_ip;
use rustls::{ClientConfig, pki_types::ServerName};
use rustls_platform_verifier::BuilderVerifierExt;
use std::io::Error;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use url::Url;

#[derive(Clone)]
pub struct TlsTunnel {}
impl TlsTunnel {
    pub fn new() -> Self {
        TlsTunnel {}
    }
}

#[async_trait::async_trait]
impl Tunnel for TlsTunnel {
    async fn ping(&self) -> Result<(), Error> {
        warn!("Tls tunnel's ping not implemented");
        Ok(())
    }

    async fn open_stream_by_dest(
        &self,
        dest_port: u16,
        dest_host: Option<String>,
    ) -> Result<Box<dyn AsyncStream>, Error> {
        if dest_host.is_none() {
            return Err(Error::new(std::io::ErrorKind::Other, "dest_host is None"));
        }

        // Resolve IP address
        let ip = resolve_ip(dest_host.as_ref().unwrap().as_str())
            .await
            .map_err(|e| Error::new(std::io::ErrorKind::Other, e))?;

        // Create TCP connection
        let tcp_stream = TcpStream::connect(format!("{}:{}", ip, dest_port))
            .await
            .map_err(|e| Error::new(std::io::ErrorKind::Other, e))?;

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
            .connect(domain, tcp_stream)
            .await
            .map_err(|e| Error::new(std::io::ErrorKind::Other, e))?;

        Ok(Box::new(tls_stream))
    }

    async fn open_stream(&self, stream_id: &str) -> Result<Box<dyn AsyncStream>, Error> {
        let (dest_host, dest_port) = get_dest_info_from_url_path(stream_id)?;
        self.open_stream_by_dest(dest_port, dest_host).await
    }

    async fn create_datagram_client_by_dest(
        &self,
        _dest_port: u16,
        _dest_host: Option<String>,
    ) -> Result<Box<dyn DatagramClientBox>, Error> {
        unreachable!()
    }

    async fn create_datagram_client(
        &self,
        _session_id: &str,
    ) -> Result<Box<dyn DatagramClientBox>, Error> {
        unreachable!()
    }
}

pub struct TlsTunnelBuilder {}

impl TlsTunnelBuilder {
    pub fn new() -> Self {
        TlsTunnelBuilder {}
    }
}

#[async_trait]
impl TunnelBuilder for TlsTunnelBuilder {
    async fn create_tunnel(
        &self,
        _tunnel_stack_id: Option<&str>,
    ) -> TunnelResult<Box<dyn TunnelBox>> {
        Ok(Box::new(TlsTunnel::new()))
    }

    fn url_prober(&self) -> Option<TunnelUrlProberRef> {
        Some(Arc::new(TlsUrlProber {}))
    }
}

/// TLS handshake probe. RTT here covers TCP connect + TLS handshake; it
/// is *not* directly comparable to a plain TCP connect or RTCP control-
/// plane RTT. Per requirement §10.1 we only allow same-scheme RTT
/// comparisons in sort.
struct TlsUrlProber;

#[async_trait]
impl TunnelUrlProber for TlsUrlProber {
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
                    "tls url has no resolvable host:port".to_string(),
                ));
            }
        };
        let timeout_dur = Duration::from_millis(options.timeout_ms_or_default());
        let started = Instant::now();
        let probe = async move {
            let ip = resolve_ip(host.as_str())
                .await
                .map_err(|e| format!("resolve {}: {}", host, e))?;
            let tcp = TcpStream::connect(format!("{}:{}", ip, port))
                .await
                .map_err(|e| format!("tcp_connect: {}", e))?;
            let mut config = ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .map_err(|e| format!("tls_provider: {}", e))?
            .with_platform_verifier()
            .map_err(|e| format!("tls_verifier: {}", e))?
            .with_no_client_auth();
            config.enable_early_data = true;
            let connector = TlsConnector::from(Arc::new(config));
            let domain = ServerName::try_from(host.clone())
                .map_err(|e| format!("server_name: {}", e))?;
            let _tls = connector
                .connect(domain, tcp)
                .await
                .map_err(|e| format!("tls_handshake: {}", e))?;
            Ok::<(), String>(())
        };
        match tokio::time::timeout(timeout_dur, probe).await {
            Ok(Ok(())) => Ok(reachable_status(
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
                "tls_handshake_timeout".to_string(),
            )),
        }
    }
}
