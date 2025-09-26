use std::io::Error;
use std::sync::Arc;
use buckyos_kit::AsyncStream;
use name_client::{DnsProvider, NsProvider};
use quinn::crypto::rustls::QuicClientConfig;
use rustls::ClientConfig;
use rustls_platform_verifier::BuilderVerifierExt;
use sfo_split::Splittable;
use url::Url;
use crate::{get_dest_info_from_url_path, DatagramClientBox, DatagramServerBox, StreamListener, Tunnel, TunnelBox, TunnelBuilder, TunnelResult};

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
        warn!("IP tunnel's ping not implemented");
        Ok(())
    }

    async fn open_stream_by_dest(&self, dest_port: u16, dest_host: Option<String>) -> Result<Box<dyn AsyncStream>, Error> {
        if dest_host.is_none() {
            return Err(Error::new(std::io::ErrorKind::Other, "dest_host is None"));
        }
        let mut config = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions().unwrap()
            .with_platform_verifier().unwrap()
            .with_no_client_auth();
        config.enable_early_data = true;
        let client_config =
            quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(config).unwrap()));

        let dns_provider = DnsProvider::new(None);
        let name_info = dns_provider.query(dest_host.as_ref().unwrap().as_str(), None, None).await
            .map_err(|e| Error::new(std::io::ErrorKind::Other, e))?;
        if name_info.address.len() == 0 {
            return Err(Error::new(std::io::ErrorKind::Other, "dns query no ip"));
        }
        let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap()).map_err(|e| Error::new(std::io::ErrorKind::Other, e))?;
        endpoint.set_default_client_config(client_config);
        let connecting = endpoint.connect(format!("{}:{}", name_info.address[0].to_string(), dest_port).parse().unwrap(),
                                          dest_host.as_ref().unwrap().as_str()).map_err(|e| Error::new(std::io::ErrorKind::Other, e))?;
        let connection = connecting.await.map_err(|e| Error::new(std::io::ErrorKind::Other, e))?;
        let (send, recv) = connection.open_bi().await.map_err(|e| Error::new(std::io::ErrorKind::Other, e))?;
        Ok(Box::new(Splittable::new(recv, send)))
    }

    async fn open_stream(&self, stream_id: &str) -> Result<Box<dyn AsyncStream>, Error> {
        let (dest_host, dest_port) = get_dest_info_from_url_path(stream_id)?;
        self.open_stream_by_dest(dest_port, dest_host).await
    }

    async fn create_datagram_client_by_dest(&self, _dest_port: u16, _dest_host: Option<String>) -> Result<Box<dyn DatagramClientBox>, Error> {
        unreachable!()
    }

    async fn create_datagram_client(&self, _session_id: &str) -> Result<Box<dyn DatagramClientBox>, Error> {
        unreachable!()
    }
}

pub struct QuicTunnelBuilder {}

impl QuicTunnelBuilder {
    pub fn new() -> Self {
        QuicTunnelBuilder {}
    }
}

#[async_trait::async_trait]
impl TunnelBuilder for QuicTunnelBuilder {
    async fn create_tunnel(&self, tunnel_stack_id: Option<&str>) -> TunnelResult<Box<dyn TunnelBox>> {
        Ok(Box::new(QuicTunnel::new()))
    }

    async fn create_stream_listener(&self, bind_stream_id: &Url) -> TunnelResult<Box<dyn StreamListener>> {
        todo!()
    }

    async fn create_datagram_server(&self, bind_session_id: &Url) -> TunnelResult<Box<dyn DatagramServerBox>> {
        todo!()
    }
}
