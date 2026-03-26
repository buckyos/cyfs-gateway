use crate::{
    DatagramClientBox, Tunnel, TunnelBox, TunnelBuilder, TunnelClientCertManagerRef, TunnelOptions,
    TunnelResult, get_dest_info_from_url_path, resolve_host_ip_with_options,
};
use buckyos_kit::AsyncStream;
use quinn::crypto::rustls::QuicClientConfig;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as TlsError, SignatureScheme};
use rustls_platform_verifier::BuilderVerifierExt;
use sfo_split::Splittable;
use std::io::Error;
use std::sync::Arc;

const QUIC_TUNNEL_OPTION_CLIENT_CERT: &str = "client_cert";
const QUIC_TUNNEL_OPTION_SNI: &str = "sni";
const QUIC_TUNNEL_OPTION_INSECURE: &str = "insecure";

#[derive(Clone, Default)]
struct QuicTunnelOptions {
    client_cert_alias: Option<String>,
    sni: Option<String>,
    insecure: bool,
}

impl QuicTunnelOptions {
    fn from_tunnel_options(options: Option<&TunnelOptions>) -> Self {
        let client_cert_alias = options
            .and_then(|options| options.get(QUIC_TUNNEL_OPTION_CLIENT_CERT))
            .map(str::to_owned);
        let sni = options
            .and_then(|options| options.get(QUIC_TUNNEL_OPTION_SNI))
            .map(str::to_owned);
        let insecure = options
            .and_then(|options| options.get(QUIC_TUNNEL_OPTION_INSECURE))
            .map(|value| {
                value.is_empty()
                    || matches!(
                        value.to_ascii_lowercase().as_str(),
                        "1" | "true" | "yes" | "on"
                    )
            })
            .unwrap_or(false);

        Self {
            client_cert_alias,
            sni,
            insecure,
        }
    }
}

#[derive(Debug)]
struct NoCertificateVerifier;

impl ServerCertVerifier for NoCertificateVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer,
        _intermediates: &[CertificateDer],
        _server_name: &ServerName,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
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

#[derive(Clone)]
pub struct QuicTunnel {
    options: Option<TunnelOptions>,
    quic_options: QuicTunnelOptions,
    client_cert_manager: TunnelClientCertManagerRef,
}
impl QuicTunnel {
    pub fn new(
        options: Option<TunnelOptions>,
        client_cert_manager: TunnelClientCertManagerRef,
    ) -> Self {
        let quic_options = QuicTunnelOptions::from_tunnel_options(options.as_ref());
        QuicTunnel {
            options,
            quic_options,
            client_cert_manager,
        }
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
        let builder =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .map_err(|e| Error::new(std::io::ErrorKind::Other, e))?;
        let mut config = if self.quic_options.insecure {
            let builder = builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoCertificateVerifier));
            if let Some(alias) = self.quic_options.client_cert_alias.as_deref() {
                let material = self
                    .client_cert_manager
                    .resolve_material(alias)
                    .map_err(|e| Error::new(std::io::ErrorKind::Other, e.to_string()))?;
                builder
                    .with_client_auth_cert(material.certs, material.private_key)
                    .map_err(|e| Error::new(std::io::ErrorKind::Other, e))?
            } else {
                builder.with_no_client_auth()
            }
        } else {
            let builder = builder
                .with_platform_verifier()
                .map_err(|e| Error::new(std::io::ErrorKind::Other, e))?;
            if let Some(alias) = self.quic_options.client_cert_alias.as_deref() {
                let material = self
                    .client_cert_manager
                    .resolve_material(alias)
                    .map_err(|e| Error::new(std::io::ErrorKind::Other, e.to_string()))?;
                builder
                    .with_client_auth_cert(material.certs, material.private_key)
                    .map_err(|e| Error::new(std::io::ErrorKind::Other, e))?
            } else {
                builder.with_no_client_auth()
            }
        };
        config.enable_early_data = true;
        let client_config = quinn::ClientConfig::new(Arc::new(
            QuicClientConfig::try_from(config)
                .map_err(|e| Error::new(std::io::ErrorKind::Other, e))?,
        ));

        let ip = resolve_host_ip_with_options(
            dest_host.as_ref().unwrap().as_str(),
            self.options.as_ref(),
        )
        .await?;
        let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())
            .map_err(|e| Error::new(std::io::ErrorKind::Other, e))?;
        endpoint.set_default_client_config(client_config);
        let sni_host = self
            .quic_options
            .sni
            .as_deref()
            .unwrap_or(dest_host.as_ref().unwrap().as_str());
        let connecting = endpoint
            .connect(
                format!("{}:{}", ip.to_string(), dest_port).parse().unwrap(),
                sni_host,
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

pub struct QuicTunnelBuilder {
    client_cert_manager: TunnelClientCertManagerRef,
}

impl QuicTunnelBuilder {
    pub fn new(client_cert_manager: TunnelClientCertManagerRef) -> Self {
        QuicTunnelBuilder {
            client_cert_manager,
        }
    }
}

#[async_trait::async_trait]
impl TunnelBuilder for QuicTunnelBuilder {
    async fn create_tunnel(
        &self,
        _tunnel_stack_id: Option<&str>,
        options: Option<TunnelOptions>,
    ) -> TunnelResult<Box<dyn TunnelBox>> {
        Ok(Box::new(QuicTunnel::new(
            options,
            self.client_cert_manager.clone(),
        )))
    }
}
