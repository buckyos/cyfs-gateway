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
use quinn::crypto::rustls::QuicClientConfig;
use rustls::ClientConfig;
use rustls_platform_verifier::BuilderVerifierExt;
use sfo_split::Splittable;
use std::io::Error;
use std::sync::Arc;
use std::time::{Duration, Instant};
use url::Url;

#[derive(Clone)]
pub struct QuicTunnel {}
impl QuicTunnel {
    pub fn new() -> Self {
        QuicTunnel {}
    }
}

#[async_trait::async_trait]
impl Tunnel for QuicTunnel {
    async fn ping(&self) -> Result<(), Error> {
        warn!("Quic tunnel's ping not implemented");
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
        let mut config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_platform_verifier()
                .unwrap()
                .with_no_client_auth();
        config.enable_early_data = true;
        let client_config =
            quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(config).unwrap()));

        let ip = resolve_ip(dest_host.as_ref().unwrap().as_str())
            .await
            .map_err(|e| Error::new(std::io::ErrorKind::Other, e))?;
        let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())
            .map_err(|e| Error::new(std::io::ErrorKind::Other, e))?;
        endpoint.set_default_client_config(client_config);
        let connecting = endpoint
            .connect(
                format!("{}:{}", ip.to_string(), dest_port).parse().unwrap(),
                dest_host.as_ref().unwrap().as_str(),
            )
            .map_err(|e| Error::new(std::io::ErrorKind::Other, e))?;
        let connection = connecting
            .await
            .map_err(|e| Error::new(std::io::ErrorKind::Other, e))?;
        let (send, recv) = connection
            .open_bi()
            .await
            .map_err(|e| Error::new(std::io::ErrorKind::Other, e))?;
        Ok(Box::new(Splittable::new(recv, send)))
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

pub struct QuicTunnelBuilder {}

impl QuicTunnelBuilder {
    pub fn new() -> Self {
        QuicTunnelBuilder {}
    }
}

#[async_trait]
impl TunnelBuilder for QuicTunnelBuilder {
    async fn create_tunnel(
        &self,
        _tunnel_stack_id: Option<&str>,
    ) -> TunnelResult<Box<dyn TunnelBox>> {
        Ok(Box::new(QuicTunnel::new()))
    }

    fn url_prober(&self) -> Option<TunnelUrlProberRef> {
        Some(Arc::new(QuicUrlProber {}))
    }
}

/// QUIC handshake probe: opens a connection, then closes immediately.
/// RTT covers the QUIC handshake (1-RTT or 0-RTT depending on session
/// state) — same caveat as TLS, only same-scheme RTT comparison is
/// meaningful in sort.
struct QuicUrlProber;

#[async_trait]
impl TunnelUrlProber for QuicUrlProber {
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
                    "quic url has no resolvable host:port".to_string(),
                ));
            }
        };
        let timeout_dur = Duration::from_millis(options.timeout_ms_or_default());
        let started = Instant::now();
        let probe = async move {
            let mut config = ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .map_err(|e| format!("tls_provider: {}", e))?
            .with_platform_verifier()
            .map_err(|e| format!("tls_verifier: {}", e))?
            .with_no_client_auth();
            config.enable_early_data = true;
            let client_config = quinn::ClientConfig::new(Arc::new(
                QuicClientConfig::try_from(config).map_err(|e| format!("quic_cfg: {}", e))?,
            ));
            let ip = resolve_ip(host.as_str())
                .await
                .map_err(|e| format!("resolve {}: {}", host, e))?;
            let mut endpoint = quinn::Endpoint::client(
                "0.0.0.0:0"
                    .parse()
                    .map_err(|e: std::net::AddrParseError| format!("bind: {}", e))?,
            )
            .map_err(|e| format!("endpoint: {}", e))?;
            endpoint.set_default_client_config(client_config);
            let connecting = endpoint
                .connect(
                    format!("{}:{}", ip, port)
                        .parse()
                        .map_err(|e: std::net::AddrParseError| format!("addr: {}", e))?,
                    host.as_str(),
                )
                .map_err(|e| format!("quic_connect_init: {}", e))?;
            let conn = connecting
                .await
                .map_err(|e| format!("quic_handshake: {}", e))?;
            conn.close(0u32.into(), b"probe_done");
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
                "quic_handshake_timeout".to_string(),
            )),
        }
    }
}
