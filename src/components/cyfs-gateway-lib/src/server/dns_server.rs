use std::sync::Arc;
use crate::{InnerDnsServiceManager, ServerConfig, ServerResult};
use super::DatagramServer;

pub struct DnsServer {
    inner_dns_services: Arc<InnerDnsServiceManager>,
}

#[async_trait::async_trait]
impl DatagramServer for DnsServer {
    async fn serve_datagram(&self, _buf: &[u8]) -> ServerResult<Vec<u8>> {
        Ok(vec![])
    }

    async fn update_config(&self, config: Arc<dyn ServerConfig>) -> ServerResult<()> {
        todo!()
    }
}
