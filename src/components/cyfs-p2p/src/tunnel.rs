use crate::stream::P2pAsyncStream;
use buckyos_kit::AsyncStream;
use cyfs_gateway_lib::{
    DatagramClient, DatagramClientBox, Tunnel, TunnelBox, TunnelBuilder, TunnelError, TunnelResult,
};
use p2p_frame::endpoint::{Endpoint, Protocol};
use p2p_frame::networks::{
    TunnelManagerRef as P2pTunnelManagerRef, TunnelPurpose, TunnelRef as P2pTunnelRef,
};
use p2p_frame::p2p_identity::P2pId;
use percent_encoding::percent_decode_str;
use std::io;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::Mutex;

const PURPOSE_WIRE_MAGIC: &[u8] = b"cgp2p\0";
const PURPOSE_WIRE_STREAM: u8 = 1;
const PURPOSE_WIRE_DATAGRAM: u8 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum P2pTransportKind {
    Stream,
    Datagram,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ParsedP2pAuthority {
    pub remote_id: Option<P2pId>,
    pub remote_endpoint: Option<Endpoint>,
}

#[derive(Clone)]
pub(crate) struct CyfsP2pTunnelBuilder {
    tunnel_manager: P2pTunnelManagerRef,
    transport: P2pTransportKind,
}

#[derive(Clone)]
struct CyfsP2pTunnel {
    tunnel: P2pTunnelRef,
    transport: P2pTransportKind,
}

#[derive(Clone)]
pub(crate) struct P2pDatagramClient {
    send: Arc<Mutex<WriteHalf<Box<dyn AsyncStream>>>>,
    recv: Arc<Mutex<ReadHalf<Box<dyn AsyncStream>>>>,
}

impl CyfsP2pTunnelBuilder {
    pub(crate) fn new(tunnel_manager: P2pTunnelManagerRef, transport: P2pTransportKind) -> Self {
        Self {
            tunnel_manager,
            transport,
        }
    }
}

impl CyfsP2pTunnel {
    fn new(tunnel: P2pTunnelRef, transport: P2pTransportKind) -> Self {
        Self { tunnel, transport }
    }

    async fn open_wire_stream(&self, payload: &str) -> io::Result<Box<dyn AsyncStream>> {
        let purpose = encode_wire_purpose(self.transport, payload)
            .map_err(|err| io::Error::other(err.to_string()))?;
        let (read, write) = self
            .tunnel
            .open_stream(purpose)
            .await
            .map_err(|err| io::Error::other(err.to_string()))?;
        Ok(Box::new(P2pAsyncStream::new(read, write)))
    }
}

impl P2pDatagramClient {
    pub(crate) fn new(stream: Box<dyn AsyncStream>) -> Self {
        let (recv, send) = tokio::io::split(stream);
        Self {
            send: Arc::new(Mutex::new(send)),
            recv: Arc::new(Mutex::new(recv)),
        }
    }
}

#[async_trait::async_trait]
impl DatagramClient for P2pDatagramClient {
    async fn recv_datagram(&self, buffer: &mut [u8]) -> io::Result<usize> {
        let mut stream = self.recv.lock().await;
        let mut len_buffer = [0u8; 4];
        stream.read_exact(&mut len_buffer).await?;
        let datagram_len = u32::from_be_bytes(len_buffer) as usize;
        if datagram_len > buffer.len() {
            return Err(io::Error::other(format!(
                "recv datagram buffer too small: datagram_len={}, buffer_len={}",
                datagram_len,
                buffer.len()
            )));
        }
        stream.read_exact(&mut buffer[..datagram_len]).await?;
        Ok(datagram_len)
    }

    async fn send_datagram(&self, buffer: &[u8]) -> io::Result<usize> {
        let len =
            u32::try_from(buffer.len()).map_err(|_| io::Error::other("datagram too large"))?;
        let mut stream = self.send.lock().await;
        stream.write_all(&len.to_be_bytes()).await?;
        stream.write_all(buffer).await?;
        Ok(buffer.len())
    }
}

#[async_trait::async_trait]
impl Tunnel for CyfsP2pTunnel {
    async fn ping(&self) -> io::Result<()> {
        Ok(())
    }

    async fn open_stream_by_dest(
        &self,
        dest_port: u16,
        dest_host: Option<String>,
    ) -> io::Result<Box<dyn AsyncStream>> {
        let payload = dest_payload(dest_port, dest_host)?;
        self.open_wire_stream(payload.as_str()).await
    }

    async fn open_stream(&self, stream_id: &str) -> io::Result<Box<dyn AsyncStream>> {
        let payload = decode_path_payload(stream_id)?;
        self.open_wire_stream(payload.as_str()).await
    }

    async fn create_datagram_client_by_dest(
        &self,
        dest_port: u16,
        dest_host: Option<String>,
    ) -> io::Result<Box<dyn DatagramClientBox>> {
        let payload = dest_payload(dest_port, dest_host)?;
        let stream = self.open_wire_stream(payload.as_str()).await?;
        Ok(Box::new(P2pDatagramClient::new(stream)))
    }

    async fn create_datagram_client(
        &self,
        session_id: &str,
    ) -> io::Result<Box<dyn DatagramClientBox>> {
        let payload = decode_path_payload(session_id)?;
        let stream = self.open_wire_stream(payload.as_str()).await?;
        Ok(Box::new(P2pDatagramClient::new(stream)))
    }
}

#[async_trait::async_trait]
impl TunnelBuilder for CyfsP2pTunnelBuilder {
    async fn create_tunnel(
        &self,
        tunnel_stack_id: Option<&str>,
    ) -> TunnelResult<Box<dyn TunnelBox>> {
        let authority = tunnel_stack_id.ok_or_else(|| {
            TunnelError::ReasonError("sp2p/up2p authority is required".to_string())
        })?;
        let parsed = parse_p2p_authority(authority)?;
        let tunnel = match (parsed.remote_id.clone(), parsed.remote_endpoint.clone()) {
            (Some(remote_id), Some(remote_endpoint)) => {
                match self
                    .tunnel_manager
                    .open_direct_tunnel(vec![remote_endpoint], Some(remote_id.clone()))
                    .await
                {
                    Ok(tunnel) => tunnel,
                    Err(err) => {
                        log::debug!(
                            "open direct p2p tunnel failed for {}, fallback to remote id: {:?}",
                            authority,
                            err
                        );
                        self.tunnel_manager
                            .open_tunnel_from_id(&remote_id)
                            .await
                            .map_err(|err| TunnelError::ConnectError(err.to_string()))?
                    }
                }
            }
            (Some(remote_id), None) => self
                .tunnel_manager
                .open_tunnel_from_id(&remote_id)
                .await
                .map_err(|err| TunnelError::ConnectError(err.to_string()))?,
            (None, Some(remote_endpoint)) => self
                .tunnel_manager
                .open_direct_tunnel(vec![remote_endpoint], None)
                .await
                .map_err(|err| TunnelError::ConnectError(err.to_string()))?,
            (None, None) => {
                return Err(TunnelError::ReasonError(format!(
                    "invalid p2p authority {}",
                    authority
                )));
            }
        };

        Ok(Box::new(CyfsP2pTunnel::new(tunnel, self.transport)))
    }
}

pub(crate) fn parse_wire_purpose(purpose: &TunnelPurpose) -> (P2pTransportKind, String) {
    if let Some((transport, payload)) = decode_wire_purpose(purpose.as_bytes()) {
        return (transport, payload);
    }

    let value = purpose
        .decode_as::<String>()
        .unwrap_or_else(|_| format!("0x{}", hex::encode(purpose.as_bytes())));
    (P2pTransportKind::Stream, value)
}

pub(crate) fn decode_path_payload(path: &str) -> io::Result<String> {
    percent_decode_str(path.trim_start_matches('/'))
        .decode_utf8()
        .map(|value| value.to_string())
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))
}

fn encode_wire_purpose(
    transport: P2pTransportKind,
    payload: &str,
) -> p2p_frame::error::P2pResult<TunnelPurpose> {
    let kind = match transport {
        P2pTransportKind::Stream => PURPOSE_WIRE_STREAM,
        P2pTransportKind::Datagram => PURPOSE_WIRE_DATAGRAM,
    };
    let mut raw = Vec::with_capacity(PURPOSE_WIRE_MAGIC.len() + 1 + payload.len());
    raw.extend_from_slice(PURPOSE_WIRE_MAGIC);
    raw.push(kind);
    raw.extend_from_slice(payload.as_bytes());
    Ok(TunnelPurpose::from_bytes(raw))
}

fn decode_wire_purpose(raw: &[u8]) -> Option<(P2pTransportKind, String)> {
    if raw.len() < PURPOSE_WIRE_MAGIC.len() + 1 || !raw.starts_with(PURPOSE_WIRE_MAGIC) {
        return None;
    }

    let transport = match raw[PURPOSE_WIRE_MAGIC.len()] {
        PURPOSE_WIRE_STREAM => P2pTransportKind::Stream,
        PURPOSE_WIRE_DATAGRAM => P2pTransportKind::Datagram,
        _ => return None,
    };
    let payload = std::str::from_utf8(&raw[PURPOSE_WIRE_MAGIC.len() + 1..])
        .ok()?
        .to_string();
    Some((transport, payload))
}

fn dest_payload(dest_port: u16, dest_host: Option<String>) -> io::Result<String> {
    if dest_port == 0 {
        return dest_host.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "dest_host is required when dest_port=0",
            )
        });
    }

    Ok(match dest_host {
        Some(dest_host) => format!("{}:{}", dest_host, dest_port),
        None => format!(":{}", dest_port),
    })
}

pub(crate) fn parse_p2p_authority(value: &str) -> TunnelResult<ParsedP2pAuthority> {
    let (remote_id, remote_endpoint) = match value.split_once('@') {
        Some((remote_id, remote_endpoint)) => {
            let remote_id = if remote_id.is_empty() {
                None
            } else {
                Some(parse_remote_id(remote_id)?)
            };
            let remote_endpoint = if remote_endpoint.is_empty() {
                None
            } else {
                Some(parse_remote_endpoint(remote_endpoint)?)
            };
            (remote_id, remote_endpoint)
        }
        None => {
            if let Ok(remote_endpoint) = parse_remote_endpoint(value) {
                (None, Some(remote_endpoint))
            } else {
                (Some(parse_remote_id(value)?), None)
            }
        }
    };

    if remote_id.is_none() && remote_endpoint.is_none() {
        return Err(TunnelError::ReasonError(format!(
            "invalid p2p authority {}",
            value
        )));
    }

    Ok(ParsedP2pAuthority {
        remote_id,
        remote_endpoint,
    })
}

fn parse_remote_id(value: &str) -> TunnelResult<P2pId> {
    P2pId::from_str(value).map_err(|err| {
        TunnelError::ReasonError(format!("invalid remote device id {}: {}", value, err))
    })
}

fn parse_remote_endpoint(value: &str) -> TunnelResult<Endpoint> {
    let addr = SocketAddr::from_str(value).map_err(|err| {
        TunnelError::ReasonError(format!("invalid remote endpoint {}: {}", value, err))
    })?;
    Ok(Endpoint::from((Protocol::Quic, addr)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_p2p_id(seed: u8) -> P2pId {
        P2pId::from(vec![seed; 32])
    }

    #[test]
    fn parse_authority_supports_device_id_only() {
        let remote_id = test_p2p_id(7);
        let parsed = parse_p2p_authority(remote_id.to_string().as_str()).unwrap();
        assert_eq!(parsed.remote_id, Some(remote_id));
        assert_eq!(parsed.remote_endpoint, None);
    }

    #[test]
    fn parse_authority_supports_endpoint_only() {
        let parsed = parse_p2p_authority("127.0.0.1:3201").unwrap();
        assert_eq!(parsed.remote_id, None);
        assert_eq!(
            parsed.remote_endpoint.unwrap().addr(),
            &SocketAddr::from(([127, 0, 0, 1], 3201))
        );
    }

    #[test]
    fn parse_authority_supports_device_id_and_endpoint() {
        let remote_id = test_p2p_id(8);
        let authority = format!("{}@127.0.0.1:3202", remote_id);
        let parsed = parse_p2p_authority(authority.as_str()).unwrap();
        assert_eq!(parsed.remote_id, Some(remote_id));
        assert_eq!(
            parsed.remote_endpoint.unwrap().addr(),
            &SocketAddr::from(([127, 0, 0, 1], 3202))
        );
    }

    #[test]
    fn parse_authority_supports_ipv6_endpoint() {
        let parsed = parse_p2p_authority("[::1]:3203").unwrap();
        assert_eq!(parsed.remote_id, None);
        assert_eq!(
            parsed.remote_endpoint.unwrap().addr(),
            &SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 3203))
        );
    }

    #[test]
    fn parse_wire_purpose_supports_sp2p_and_up2p() {
        let purpose = encode_wire_purpose(P2pTransportKind::Stream, "service").unwrap();
        assert_eq!(
            parse_wire_purpose(&purpose),
            (P2pTransportKind::Stream, "service".to_string())
        );

        let purpose = encode_wire_purpose(P2pTransportKind::Datagram, "udp://echo:53").unwrap();
        assert_eq!(
            parse_wire_purpose(&purpose),
            (P2pTransportKind::Datagram, "udp://echo:53".to_string())
        );

        let purpose = TunnelPurpose::from_value(&"plain-purpose".to_string()).unwrap();
        assert_eq!(
            parse_wire_purpose(&purpose),
            (P2pTransportKind::Stream, "plain-purpose".to_string())
        );
    }

    #[test]
    fn decode_path_payload_supports_embedded_url() {
        let encoded = "/rtcp%3A%2F%2Fdevice%2Ftcp%3A%2F%2F127.0.0.1%3A80";
        assert_eq!(
            decode_path_payload(encoded).unwrap(),
            "rtcp://device/tcp://127.0.0.1:80"
        );
    }
}
