use std::sync::{Arc, Mutex};
use crate::CyfsServerConfig;
use crate::server::cyfs_server::{CyfsServer, ServerResult};

pub struct CyfsServerManager {
    servers: Mutex<Vec<CyfsServer>>
}
pub type CyfsServerManagerRef = Arc<CyfsServerManager>;

impl CyfsServerManager {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            servers: Mutex::new(vec![]),
        })
    }
    
    pub async fn start_server(&self, servers: Vec<CyfsServerConfig>) -> ServerResult<()> { 
        for server in servers.iter() {
            let server = CyfsServer::create_server(server.clone()).await?;
            self.servers.lock().unwrap().push(server);
        }
        Ok(())
    }
}
