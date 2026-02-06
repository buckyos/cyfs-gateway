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
use crate::socks::SocksTunnelBuilder;
use crate::tls_tunnel::TlsTunnelBuilder;

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
        "tls" => Ok(ProtocolCategory::Stream),
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
        this.register_tunnel_builder("tls", Arc::new(TlsTunnelBuilder::new()));
        this.register_tunnel_builder("socks", Arc::new(SocksTunnelBuilder::new()));

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
            let auth = target_url.authority();
        let tunnel_stack_id = if auth.is_empty() {
                None
            } else {
                Some(auth)
        };
        let tunnel = builder.create_tunnel(tunnel_stack_id)
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

    pub fn get_instance() -> &'static Self {
        unimplemented!()
    }
}


mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::io;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct MockTunnel {
    }

    #[async_trait]
    impl crate::Tunnel for MockTunnel {
        async fn ping(&self) -> Result<(), io::Error> {
            Ok(())
        }

        async fn open_stream_by_dest(
            &self,
            _dest_port: u16,
            _dest_host: Option<String>,
        ) -> Result<Box<dyn AsyncStream>, io::Error> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "not used in test"))
        }

        async fn open_stream(&self, _stream_id: &str) -> Result<Box<dyn AsyncStream>, io::Error> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "not used in test"))
        }

        async fn create_datagram_client_by_dest(
            &self,
            _dest_port: u16,
            _dest_host: Option<String>,
        ) -> Result<Box<dyn crate::DatagramClientBox>, io::Error> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "not used in test"))
        }

        async fn create_datagram_client(
            &self,
            _session_id: &str,
        ) -> Result<Box<dyn crate::DatagramClientBox>, io::Error> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "not used in test"))
        }
    }

    #[derive(Clone)]
    struct MockTunnelBuilder {
        captured: Arc<Mutex<Option<String>>>,
    }

    #[async_trait]
    impl TunnelBuilder for MockTunnelBuilder {
        async fn create_tunnel(&self, tunnel_stack_id: Option<&str>) -> TunnelResult<Box<dyn TunnelBox>> {
            *self.captured.lock().unwrap() = tunnel_stack_id.map(|s| s.to_string());
            Ok(Box::new(MockTunnel::default()))
        }
    }



    #[tokio::test]
    async fn test_tunnel_url_in_stream_id() {
        use url::Url;
        use percent_encoding::{utf8_percent_encode, percent_decode_str, NON_ALPHANUMERIC};
        
        let tunnel_url = "rtcp://sn.buckyos.ai/google.com:443";
        let url = Url::parse(tunnel_url).unwrap();
        let stream_id = url.path();
        println!("stream_id: {}", stream_id);
        assert_eq!(stream_id, "/google.com:443");

        // 在 path 中嵌入另一个完整的 URL，需要进行 URL 编码
        // 因为嵌入的 URL 包含特殊字符（://、/ 等），必须编码以避免破坏外层 URL 结构
        let embedded_url = "rtcp://sn.buckyos.io/google.com:443/";
        let encoded_url = utf8_percent_encode(embedded_url, NON_ALPHANUMERIC).to_string();
        
        let mut url2 = url.clone();
        let new_path = format!("/{}", encoded_url);
        url2.set_path(&new_path);
        let url2_str = url2.to_string();
        
        println!("embedded_url: {}", embedded_url);
        println!("encoded in path: {}", encoded_url);
        println!("final url: {}", url2_str);
        
        // 验证可以正确解码回原始 URL
        let decoded_path = percent_decode_str(url2.path().trim_start_matches('/'))
            .decode_utf8()
            .unwrap();
        println!("decoded_path: {}", decoded_path);
        assert_eq!(decoded_path, embedded_url);

    }

    #[tokio::test]
    async fn test_get_tunnel_preserves_socks_authority() {
        let manager = TunnelManager::new();
        let captured = Arc::new(Mutex::new(None));
        let builder = MockTunnelBuilder {
            captured: captured.clone(),
        };
        manager.register_tunnel_builder("socks", Arc::new(builder));

        let url = Url::parse("socks://u:p@127.0.0.1:12345").unwrap();
        let ret = manager.get_tunnel(&url, None).await;
        assert!(ret.is_ok());

        let value = captured.lock().unwrap().clone();
        assert_eq!(value.as_deref(), Some("u:p@127.0.0.1:12345"));
    }

    #[tokio::test]
    async fn test_get_tunnel_non_socks_keeps_host_only_behavior() {
        let manager = TunnelManager::new();
        let captured = Arc::new(Mutex::new(None));
        let builder = MockTunnelBuilder {
            captured: captured.clone(),
        };
        manager.register_tunnel_builder("tcp", Arc::new(builder));

        let url = Url::parse("tcp://127.0.0.1:18080").unwrap();
        let ret = manager.get_tunnel(&url, None).await;
        assert!(ret.is_ok());

        let value = captured.lock().unwrap().clone();
        assert_eq!(value.as_deref(), Some("127.0.0.1:18080"));
    }
}
