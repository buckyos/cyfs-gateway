use buckyos_kit::AsyncStream;
use cyfs_gateway_lib::{
    Server, ServerConfig, ServerContextRef, ServerErrorCode, ServerFactory, ServerResult,
    StreamInfo, StreamServer, server_err,
};
use p2p_frame::endpoint::{Endpoint, Protocol};
use p2p_frame::error::{P2pError, P2pErrorCode};
use p2p_frame::p2p_identity::{EncodedP2pIdentityCert, P2pId, P2pIdentityCertFactoryRef};
use p2p_frame::sn::protocol::{ReceiptWithSignature, SnServiceReceipt};
use p2p_frame::sn::service::{
    IsAcceptClient, ReceiptRequestTime, SnService, SnServiceContractServer, SnServiceRef,
};
use p2p_frame::sn::types::{SnTunnelRead, SnTunnelWrite};
use p2p_frame::x509::X509IdentityCertFactory;
use serde::{Deserialize, Serialize};
use sfo_cmd_server::CmdTunnel;
use sfo_cmd_server::server::CmdTunnelService;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct P2pStreamExtra {
    pub source_device_id: String,
    pub dest_device_id: String,
    pub source_endpoint: Option<String>,
    pub dest_endpoint: Option<String>,
    pub transport_protocol: String,
    pub tunnel_id: String,
    pub candidate_id: String,
    pub purpose: String,
    pub is_reverse: bool,
    pub tunnel_form: String,
}

impl P2pStreamExtra {
    pub(crate) fn encode(&self) -> ServerResult<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| {
            server_err!(
                ServerErrorCode::EncodeError,
                "encode p2p stream extra failed: {}",
                e
            )
        })
    }

    pub(crate) fn decode(extra: &[u8]) -> ServerResult<Self> {
        if extra.is_empty() {
            return Err(server_err!(
                ServerErrorCode::InvalidParam,
                "missing p2p stream extra"
            ));
        }

        serde_json::from_slice(extra).map_err(|e| {
            server_err!(
                ServerErrorCode::InvalidParam,
                "decode p2p stream extra failed: {}",
                e
            )
        })
    }

    fn source_id(&self) -> ServerResult<P2pId> {
        P2pId::from_str(self.source_device_id.as_str()).map_err(|e| {
            server_err!(
                ServerErrorCode::InvalidParam,
                "invalid source_device_id {}: {}",
                self.source_device_id,
                e
            )
        })
    }

    fn dest_id(&self) -> ServerResult<P2pId> {
        P2pId::from_str(self.dest_device_id.as_str()).map_err(|e| {
            server_err!(
                ServerErrorCode::InvalidParam,
                "invalid dest_device_id {}: {}",
                self.dest_device_id,
                e
            )
        })
    }

    fn source_endpoint(&self) -> ServerResult<Endpoint> {
        parse_optional_endpoint(self.source_endpoint.as_deref()).map_err(|e| {
            server_err!(
                ServerErrorCode::InvalidParam,
                "invalid source_endpoint {:?}: {}",
                self.source_endpoint,
                e
            )
        })
    }

    fn dest_endpoint(&self) -> ServerResult<Endpoint> {
        parse_optional_endpoint(self.dest_endpoint.as_deref()).map_err(|e| {
            server_err!(
                ServerErrorCode::InvalidParam,
                "invalid dest_endpoint {:?}: {}",
                self.dest_endpoint,
                e
            )
        })
    }
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct P2pSnServerConfig {
    pub id: String,
}

impl ServerConfig for P2pSnServerConfig {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn server_type(&self) -> String {
        "p2p_sn".to_string()
    }

    fn get_config_json(&self) -> String {
        serde_json::to_string(self).unwrap()
    }
}

struct DefaultP2pSnContract;

impl SnServiceContractServer for DefaultP2pSnContract {
    fn check_receipt(
        &self,
        _client_peer_desc: &EncodedP2pIdentityCert,
        _local_receipt: &SnServiceReceipt,
        _client_receipt: &Option<ReceiptWithSignature>,
        _last_request_time: &ReceiptRequestTime,
    ) -> IsAcceptClient {
        IsAcceptClient::Accept(false)
    }

    fn verify_auth(&self, _client_peer_id: &P2pId) -> IsAcceptClient {
        IsAcceptClient::Accept(false)
    }
}

pub struct P2pSnServer {
    id: String,
    sn_service: SnServiceRef,
}

impl P2pSnServer {
    async fn new(id: impl Into<String>, _config: &P2pSnServerConfig) -> ServerResult<Self> {
        let cert_factory: P2pIdentityCertFactoryRef = Arc::new(X509IdentityCertFactory);
        let sn_service = SnService::new(cert_factory, Box::new(DefaultP2pSnContract));

        Ok(Self {
            id: id.into(),
            sn_service,
        })
    }
}

#[async_trait::async_trait]
impl StreamServer for P2pSnServer {
    async fn serve_connection(
        &self,
        stream: Box<dyn AsyncStream>,
        info: StreamInfo,
    ) -> ServerResult<()> {
        let extra = P2pStreamExtra::decode(info.extra.as_slice())?;
        let local_ep = extra.dest_endpoint()?;
        let remote_ep = extra.source_endpoint()?;
        let local_id = extra.dest_id()?;
        let remote_id = extra.source_id()?;

        let (read, write) = tokio::io::split(stream);
        let tunnel = CmdTunnel::new(
            SnTunnelRead::new(
                Box::pin(read),
                local_ep,
                remote_ep,
                local_id.clone(),
                remote_id.clone(),
            ),
            SnTunnelWrite::new(Box::pin(write), local_ep, remote_ep, local_id, remote_id),
        );

        self.sn_service.handle_tunnel(tunnel).await.map_err(|e| {
            server_err!(
                ServerErrorCode::StreamError,
                "handle p2p sn tunnel failed: {}",
                e
            )
        })?;

        Ok(())
    }

    fn id(&self) -> String {
        self.id.clone()
    }
}

pub struct P2pSnServerFactory;

impl P2pSnServerFactory {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl ServerFactory for P2pSnServerFactory {
    async fn create(
        &self,
        config: Arc<dyn ServerConfig>,
        _context: Option<ServerContextRef>,
    ) -> ServerResult<Vec<Server>> {
        let config = config
            .as_any()
            .downcast_ref::<P2pSnServerConfig>()
            .ok_or(server_err!(
                ServerErrorCode::InvalidConfig,
                "invalid p2p sn server config"
            ))?;
        let server = P2pSnServer::new(config.id.clone(), config).await?;
        Ok(vec![Server::Stream(Arc::new(server))])
    }
}

fn parse_optional_endpoint(value: Option<&str>) -> Result<Endpoint, p2p_frame::error::P2pError> {
    match value {
        Some(value) => parse_endpoint(value),
        None => Ok(Endpoint::default()),
    }
}

fn parse_endpoint(value: &str) -> Result<Endpoint, p2p_frame::error::P2pError> {
    let first = value.chars().next();
    if matches!(first, Some('L' | 'D' | 'W' | 'M')) {
        Endpoint::from_str(value)
    } else {
        let addr = SocketAddr::from_str(value).map_err(|_| {
            P2pError::new(
                P2pErrorCode::InvalidInput,
                format!("invalid endpoint {}", value),
            )
        })?;
        Ok(Endpoint::from((Protocol::Quic, addr)))
    }
}
