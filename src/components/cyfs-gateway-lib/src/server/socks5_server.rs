use std::sync::Arc;
use buckyos_kit::AsyncStream;
use cyfs_process_chain::HookPoint;
use crate::{ServerResult, StreamInfo, StreamServer};

pub struct Socks5Server {
    hook_point: Arc<HookPoint>,
}

#[async_trait::async_trait]
impl StreamServer for Socks5Server {
    async fn serve_connection(&self, _stream: Box<dyn AsyncStream>, _info: StreamInfo) -> ServerResult<()> {
        Ok(())
    }

    fn id(&self) -> String {
        todo!()
    }
}
