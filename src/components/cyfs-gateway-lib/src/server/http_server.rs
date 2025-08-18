use std::sync::Arc;
use buckyos_kit::AsyncStream;
use cyfs_process_chain::HookPoint;
use crate::{InnerHttpServiceManager, ServerResult, StreamServer};

pub struct HttpServerConfig {
    
}

pub struct HttpServer {
    hook_point: Arc<HookPoint>,
    inner_services: Arc<InnerHttpServiceManager>,
}

#[async_trait::async_trait]
impl StreamServer for HttpServer {
    async fn serve_connection(&self, _stream: Box<dyn AsyncStream>) -> ServerResult<()> {
        Ok(())
    }
}
