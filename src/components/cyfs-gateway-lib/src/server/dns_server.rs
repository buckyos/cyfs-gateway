use std::sync::Arc;
use crate::{InnerDnsServiceManager, ServerResult};
use super::DatagramServer;

pub struct DnsServer {
    inner_dns_services: Arc<InnerDnsServiceManager>,
}

#[async_trait::async_trait]
impl DatagramServer for DnsServer {
    async fn serve_datagram(&self, _buf: &mut [u8]) -> ServerResult<Vec<u8>> {
        Ok(vec![])
    }
}
