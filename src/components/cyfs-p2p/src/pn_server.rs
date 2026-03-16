use crate::sn_server::P2pStreamExtra;
use buckyos_kit::AsyncStream;
use cyfs_gateway_lib::{
    Server, ServerConfig, ServerContextRef, ServerErrorCode, ServerFactory, ServerResult,
    StreamInfo, StreamServer, server_err,
};
use p2p_frame::error::P2pResult;
use p2p_frame::networks::{
    TunnelManagerRef as P2pTunnelManagerRef, TunnelPurpose, TunnelStreamRead, TunnelStreamWrite,
};
use p2p_frame::p2p_identity::P2pId;
use p2p_frame::pn::{
    PROXY_SERVICE, PnService, PnServiceRef, PnTargetStreamFactory, PnTargetStreamFactoryRef,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{Arc, Mutex, OnceLock};

#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct P2pPnServerConfig {
    pub id: String,
}

impl ServerConfig for P2pPnServerConfig {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn server_type(&self) -> String {
        "p2p_pn".to_string()
    }

    fn get_config_json(&self) -> String {
        serde_json::to_string(self).unwrap()
    }
}

struct TunnelManagerPnTargetStreamFactory {
    tunnel_manager: P2pTunnelManagerRef,
}

impl TunnelManagerPnTargetStreamFactory {
    fn new(tunnel_manager: P2pTunnelManagerRef) -> Self {
        Self { tunnel_manager }
    }
}

#[async_trait::async_trait]
impl PnTargetStreamFactory for TunnelManagerPnTargetStreamFactory {
    async fn open_target_stream(
        &self,
        target: &P2pId,
    ) -> P2pResult<(TunnelStreamRead, TunnelStreamWrite)> {
        let tunnel = self.tunnel_manager.open_tunnel_from_id(target).await?;
        let purpose = TunnelPurpose::from_value(&PROXY_SERVICE.to_string())?;
        tunnel.open_stream(purpose).await
    }
}

fn pn_service_registry() -> &'static Mutex<HashMap<String, PnServiceRef>> {
    static REGISTRY: OnceLock<Mutex<HashMap<String, PnServiceRef>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

pub(crate) fn register_pn_service(local_id: &P2pId, tunnel_manager: P2pTunnelManagerRef) {
    let target_stream_factory: PnTargetStreamFactoryRef =
        Arc::new(TunnelManagerPnTargetStreamFactory::new(tunnel_manager));
    let service = PnService::new(target_stream_factory);
    pn_service_registry()
        .lock()
        .unwrap()
        .insert(local_id.to_string(), service);
}

pub(crate) fn unregister_pn_service(local_id: &P2pId) {
    pn_service_registry()
        .lock()
        .unwrap()
        .remove(local_id.to_string().as_str());
}

fn get_pn_service(local_id: &str) -> Option<PnServiceRef> {
    pn_service_registry().lock().unwrap().get(local_id).cloned()
}

pub struct P2pPnServer {
    id: String,
}

impl P2pPnServer {
    async fn new(id: impl Into<String>, _config: &P2pPnServerConfig) -> ServerResult<Self> {
        Ok(Self { id: id.into() })
    }
}

#[async_trait::async_trait]
impl StreamServer for P2pPnServer {
    async fn serve_connection(
        &self,
        stream: Box<dyn AsyncStream>,
        info: StreamInfo,
    ) -> ServerResult<()> {
        let extra = P2pStreamExtra::decode(info.extra.as_slice())?;
        let from = P2pId::from_str(extra.source_device_id.as_str()).map_err(|e| {
            server_err!(
                ServerErrorCode::InvalidParam,
                "invalid source_device_id {}: {}",
                extra.source_device_id,
                e
            )
        })?;
        let service = get_pn_service(extra.dest_device_id.as_str()).ok_or(server_err!(
            ServerErrorCode::NotFound,
            "no p2p pn runtime for dest_device_id {}",
            extra.dest_device_id
        ))?;

        let (read, write) = tokio::io::split(stream);
        service
            .handle_proxy_connection(
                from,
                Box::pin(read) as TunnelStreamRead,
                Box::pin(write) as TunnelStreamWrite,
            )
            .await;
        Ok(())
    }

    fn id(&self) -> String {
        self.id.clone()
    }
}

pub struct P2pPnServerFactory;

impl P2pPnServerFactory {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl ServerFactory for P2pPnServerFactory {
    async fn create(
        &self,
        config: Arc<dyn ServerConfig>,
        _context: Option<ServerContextRef>,
    ) -> ServerResult<Vec<Server>> {
        let config = config
            .as_any()
            .downcast_ref::<P2pPnServerConfig>()
            .ok_or(server_err!(
                ServerErrorCode::InvalidConfig,
                "invalid p2p pn server config"
            ))?;
        let server = P2pPnServer::new(config.id.clone(), config).await?;
        Ok(vec![Server::Stream(Arc::new(server))])
    }
}
