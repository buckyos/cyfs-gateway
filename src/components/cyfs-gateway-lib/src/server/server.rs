use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use buckyos_kit::AsyncStream;
use crate::ServerResult;

// 流处理服务
#[async_trait::async_trait]
pub trait StreamServer: Send + Sync + 'static {
    async fn serve_connection(&self, stream: Box<dyn AsyncStream>) -> ServerResult<()>;
}


#[async_trait::async_trait]
pub trait DatagramServer: Send + Sync + 'static {
    async fn serve_datagram(&self, buf: &mut [u8]) -> ServerResult<Vec<u8>>;
}

pub struct StreamServerManager {
    servers: Mutex<HashMap<String, Arc<dyn StreamServer>>>
}

impl StreamServerManager {
    pub fn new() -> Self {
        StreamServerManager {
            servers: Mutex::new(HashMap::new()),
        }
    }
    pub fn add_server(&self, name: String, server: Arc<dyn StreamServer>) {
        self.servers.lock().unwrap().insert(name, server);
    }
    pub fn get_server(&self, name: &str) -> Option<Arc<dyn StreamServer>> {
        self.servers.lock().unwrap().get(name).cloned()
    }
    
}

pub type StreamServerManagerRef = Arc<StreamServerManager>;

pub struct DatagramServerManager {
    servers: HashMap<String, Arc<dyn DatagramServer>>,
}
pub type DatagramServerManagerRef = Arc<DatagramServerManager>;
