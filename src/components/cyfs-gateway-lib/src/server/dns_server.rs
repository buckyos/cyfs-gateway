use std::sync::Arc;
use crate::{InnerServiceManagerRef, ServerConfig, ServerResult};
use super::DatagramServer;

pub struct DnsServer {
    inner_dns_services: InnerServiceManagerRef,
}

#[async_trait::async_trait]
impl DatagramServer for DnsServer {
    async fn serve_datagram(&self, _buf: &[u8]) -> ServerResult<Vec<u8>> {
        Ok(vec![])
    }

    fn id(&self) -> String {
        todo!()
    }

    async fn update_config(&self, config: Arc<dyn ServerConfig>) -> ServerResult<()> {
        todo!()
    }
}
