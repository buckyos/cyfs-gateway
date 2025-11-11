use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use crate::ip::IPTunnelBuilder;
use crate::DatagramClientBox;
use crate::{
    TunnelBox, TunnelBuilder, TunnelError, TunnelResult,
};
use buckyos_kit::AsyncStream;
use log::*;
use url::Url;
use crate::quic_tunnel::QuicTunnelBuilder;

#[derive(Debug, PartialEq, Eq)]
pub enum ProtocolCategory {
    Stream,
    Datagram,
    //Named Object
}

pub fn get_protocol_category(str_protocol: &str) -> TunnelResult<ProtocolCategory> {
    //lowercase
    let str_protocol = str_protocol.to_lowercase();
    match str_protocol.as_str() {
        "tcp" => Ok(ProtocolCategory::Stream),
        "rtcp" => Ok(ProtocolCategory::Stream),
        "udp" => Ok(ProtocolCategory::Datagram),
        "rudp" => Ok(ProtocolCategory::Datagram),
        "socks" => Ok(ProtocolCategory::Stream),
        _ => {
            let msg = format!("Unknown protocol: {}", str_protocol);
            error!("{}", msg);
            Err(TunnelError::UnknownProtocol(msg))
        }
    }
}

#[derive(Clone)]
pub struct TunnelManager {
    tunnel_builder_manager: Arc<Mutex<HashMap<String, Arc<dyn TunnelBuilder>>>>,
}

impl Default for TunnelManager {
    fn default() -> Self {
        Self::new()
    }
}

impl TunnelManager {
    pub fn new() -> Self {
        let this = Self {
            tunnel_builder_manager: Arc::new(Mutex::new(Default::default())),
        };
        this.register_tunnel_builder("tcp", Arc::new(IPTunnelBuilder::new()));
        this.register_tunnel_builder("udp", Arc::new(IPTunnelBuilder::new()));
        this.register_tunnel_builder("quic", Arc::new(QuicTunnelBuilder::new()));

        this
    }

    pub fn register_tunnel_builder(&self, protocol: &str, builder: Arc<dyn TunnelBuilder>) {
        self.tunnel_builder_manager.lock().unwrap().insert(protocol.to_string(), builder);
    }

    pub fn remove_tunnel_builder(&self, protocol: &str) {
        self.tunnel_builder_manager.lock().unwrap().remove(protocol);
    }

    pub async fn get_tunnel_builder_by_protocol(
        &self,
        protocol: &str,
    ) -> TunnelResult<Arc<dyn TunnelBuilder>> {
        let tunnel_builder_manager = self.tunnel_builder_manager.lock().unwrap();
        if let Some(builder) = tunnel_builder_manager.get(protocol) {
            Ok(builder.clone())
        } else {
            let msg = format!("Unknown protocol: {}", protocol);
            error!("{}", msg);
            Err(TunnelError::UnknownProtocol(msg))
        }
    }

    pub async fn get_tunnel(
        &self,
        target_url: &Url,
        _enable_tunnel: Option<Vec<String>>,
    ) -> TunnelResult<Box<dyn TunnelBox>> {
        let builder = self
            .get_tunnel_builder_by_protocol(target_url.scheme())
            .await.map_err(|e| {
                error!("Get tunnel builder by protocol failed: {:?}", e);
                e
            })?;
        let tunnel = builder.create_tunnel(target_url.host_str())
            .await.map_err(|e| {
                error!("create_tunnel to {} failed: {:?}", target_url, e);
                e
            })?;

        info!("Get tunnel for {} success", target_url);
        return Ok(tunnel);
    }

    //$tunnel_schema://$tunnel_stack_id/$target_stream_id
    pub async fn open_stream_by_url(&self, url: &Url) -> TunnelResult<Box<dyn AsyncStream>> {
        let builder = self.get_tunnel_builder_by_protocol(url.scheme()).await?;
        let auth_str = url.authority();
        let tunnel;
        if auth_str.is_empty() {
            tunnel = builder.create_tunnel(None).await?;
        } else {
            tunnel = builder.create_tunnel(Some(auth_str)).await?;
        }
        let path = url.path();
        debug!("Open stream by url.path: {}", path);
        let stream = tunnel.open_stream(path).await.map_err(|e| {
            error!("Open stream by url {} failed: {}", url.to_string(), e);
            TunnelError::ConnectError(format!("Open stream by url failed: {}", e))
        })?;

        return Ok(stream);
    }

    pub async fn create_datagram_client_by_url(
        &self,
        url: &Url,
    ) -> TunnelResult<Box<dyn DatagramClientBox>> {
        let builder = self.get_tunnel_builder_by_protocol(url.scheme()).await?;
        let auth_str = url.authority();
        let tunnel = if auth_str.is_empty() {
            builder.create_tunnel(None).await?
        } else {
            builder.create_tunnel(Some(auth_str)).await?
        };
        let client = tunnel
            .create_datagram_client(url.path())
            .await
            .map_err(|e| {
                error!("Create datagram client by url failed: {}", e);
                TunnelError::ConnectError(format!("Create datagram client by url failed: {}", e))
            })?;
        return Ok(client);
    }
}
