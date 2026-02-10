use std::io::Error;
use std::net::{IpAddr, SocketAddr};

use async_trait::async_trait;
use buckyos_kit::AsyncStream;
use percent_encoding::percent_decode;
use tokio::io::AsyncWriteExt;

use crate::{DatagramClientBox, Tunnel, TunnelBox, TunnelBuilder, TunnelError, TunnelResult};

#[derive(Clone)]
pub struct ProxyTcpTunnel {
    source_addr: SocketAddr,
}

impl ProxyTcpTunnel {
    pub fn new(source_addr: SocketAddr) -> Self {
        Self { source_addr }
    }

    async fn open_stream_by_target(&self, target: &str) -> Result<Box<dyn AsyncStream>, std::io::Error> {
        let stream = percent_decode(target.as_bytes())
            .decode_utf8()
            .map_err(|e| Error::new(std::io::ErrorKind::InvalidInput, e))?
            .trim_start_matches('/')
            .to_owned();

        if stream.is_empty() {
            return Err(Error::new(
                std::io::ErrorKind::InvalidInput,
                "empty ptcp target",
            ));
        }

        let mut tcp = tokio::net::TcpStream::connect(stream.as_str()).await?;
        let dest_addr = tcp.peer_addr()?;
        let header = build_proxy_v1_header(self.source_addr, dest_addr);
        tcp.write_all(header.as_bytes()).await?;

        Ok(Box::new(tcp))
    }
}

fn build_proxy_v1_header(source_addr: SocketAddr, dest_addr: SocketAddr) -> String {
    let transport = match (source_addr.ip(), dest_addr.ip()) {
        (IpAddr::V4(_), IpAddr::V4(_)) => "TCP4",
        (IpAddr::V6(_), IpAddr::V6(_)) => "TCP6",
        _ => return "PROXY UNKNOWN\r\n".to_string(),
    };

    format!(
        "PROXY {} {} {} {} {}\r\n",
        transport,
        source_addr.ip(),
        dest_addr.ip(),
        source_addr.port(),
        dest_addr.port()
    )
}

#[async_trait]
impl Tunnel for ProxyTcpTunnel {
    async fn ping(&self) -> Result<(), std::io::Error> {
        Ok(())
    }

    async fn open_stream_by_dest(
        &self,
        _dest_port: u16,
        _dest_host: Option<String>,
    ) -> Result<Box<dyn AsyncStream>, std::io::Error> {
        Err(Error::new(
            std::io::ErrorKind::Unsupported,
            "ptcp requires a full target address in stream_id",
        ))
    }

    async fn open_stream(&self, stream_id: &str) -> Result<Box<dyn AsyncStream>, std::io::Error> {
        self.open_stream_by_target(stream_id).await
    }

    async fn create_datagram_client_by_dest(
        &self,
        _dest_port: u16,
        _dest_host: Option<String>,
    ) -> Result<Box<dyn DatagramClientBox>, std::io::Error> {
        Err(Error::new(
            std::io::ErrorKind::Unsupported,
            "ptcp does not support datagram client",
        ))
    }

    async fn create_datagram_client(
        &self,
        _session_id: &str,
    ) -> Result<Box<dyn DatagramClientBox>, std::io::Error> {
        Err(Error::new(
            std::io::ErrorKind::Unsupported,
            "ptcp does not support datagram client",
        ))
    }
}

pub struct ProxyTcpTunnelBuilder;

impl ProxyTcpTunnelBuilder {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl TunnelBuilder for ProxyTcpTunnelBuilder {
    async fn create_tunnel(&self, target_id: Option<&str>) -> TunnelResult<Box<dyn TunnelBox>> {
        let source_addr = target_id
            .ok_or_else(|| TunnelError::InvalidState("ptcp source addr is required".to_string()))?
            .parse::<SocketAddr>()
            .map_err(|e| TunnelError::InvalidState(format!("invalid ptcp source addr: {}", e)))?;

        Ok(Box::new(ProxyTcpTunnel::new(source_addr)))
    }
}

#[cfg(test)]
mod tests {
    use super::build_proxy_v1_header;
    use std::net::SocketAddr;

    #[test]
    fn test_build_proxy_v1_header_ipv4() {
        let source = "192.168.1.10:52314".parse::<SocketAddr>().unwrap();
        let dest = "10.0.0.8:443".parse::<SocketAddr>().unwrap();
        let header = build_proxy_v1_header(source, dest);
        assert_eq!(
            header,
            "PROXY TCP4 192.168.1.10 10.0.0.8 52314 443\r\n".to_string()
        );
    }

    #[test]
    fn test_build_proxy_v1_header_ipv6() {
        let source = "[2001:db8::10]:52314".parse::<SocketAddr>().unwrap();
        let dest = "[2001:db8::20]:443".parse::<SocketAddr>().unwrap();
        let header = build_proxy_v1_header(source, dest);
        assert_eq!(
            header,
            "PROXY TCP6 2001:db8::10 2001:db8::20 52314 443\r\n".to_string()
        );
    }
}
