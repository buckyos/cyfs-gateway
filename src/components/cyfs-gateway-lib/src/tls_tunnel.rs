use crate::{
    DatagramClientBox, Tunnel, TunnelBox, TunnelBuilder, TunnelClientCertManagerRef, TunnelOptions,
    TunnelResult, get_dest_info_from_url_path, resolve_host_ip_with_options,
};
use buckyos_kit::AsyncStream;
use rustls::{ClientConfig, pki_types::ServerName};
use rustls_platform_verifier::BuilderVerifierExt;
use std::io::Error;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

#[derive(Clone)]
pub struct TlsTunnel {
    options: Option<TunnelOptions>,
    client_cert_manager: TunnelClientCertManagerRef,
}
impl TlsTunnel {
    pub fn new(
        options: Option<TunnelOptions>,
        client_cert_manager: TunnelClientCertManagerRef,
    ) -> Self {
        TlsTunnel {
            options,
            client_cert_manager,
        }
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
        let ip = resolve_host_ip_with_options(
            dest_host.as_ref().unwrap().as_str(),
            self.options.as_ref(),
        )
        .await?;

        // Create TCP connection
        let tcp_stream = TcpStream::connect(format!("{}:{}", ip, dest_port))
            .await
            .map_err(|e| Error::new(std::io::ErrorKind::Other, e))?;

        let builder =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .map_err(|e| Error::new(std::io::ErrorKind::Other, e))?
                .with_platform_verifier()
                .map_err(|e| Error::new(std::io::ErrorKind::Other, e))?;

        let mut config = if let Some(alias) = self
            .options
            .as_ref()
            .and_then(TunnelOptions::client_cert_alias)
        {
            let material = self
                .client_cert_manager
                .resolve_material(alias)
                .map_err(|e| Error::new(std::io::ErrorKind::Other, e.to_string()))?;
            builder
                .with_client_auth_cert(material.certs, material.private_key)
                .map_err(|e| Error::new(std::io::ErrorKind::Other, e))?
        } else {
            builder.with_no_client_auth()
        };

        // Enable early data if needed
        config.enable_early_data = true;

        let connector = TlsConnector::from(Arc::new(config));
        let sni_host = self
            .options
            .as_ref()
            .and_then(TunnelOptions::sni)
            .unwrap_or(dest_host.as_ref().unwrap().as_str());
        let domain = ServerName::try_from(sni_host.to_string())
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

pub struct TlsTunnelBuilder {
    client_cert_manager: TunnelClientCertManagerRef,
}

impl TlsTunnelBuilder {
    pub fn new(client_cert_manager: TunnelClientCertManagerRef) -> Self {
        TlsTunnelBuilder {
            client_cert_manager,
        }
    }
}

#[async_trait::async_trait]
impl TunnelBuilder for TlsTunnelBuilder {
    async fn create_tunnel(
        &self,
        _tunnel_stack_id: Option<&str>,
        options: Option<TunnelOptions>,
    ) -> TunnelResult<Box<dyn TunnelBox>> {
        Ok(Box::new(TlsTunnel::new(
            options,
            self.client_cert_manager.clone(),
        )))
    }
}
