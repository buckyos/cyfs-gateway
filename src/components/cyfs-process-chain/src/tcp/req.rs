use std::sync::{Arc, Mutex};
use std::net::SocketAddr; 
use buckyos_kit::AsyncStream;

#[derive(Clone)]
pub struct StreamRequest {
    pub dest_port : u16,
    pub dest_host : Option<String>, 
    pub dest_addr : Option<SocketAddr>,
    pub app_protocol: Option<String>,
    pub dest_url : Option<String>,

    pub source_addr : Option<SocketAddr>,
    pub source_mac : Option<String>,
    pub source_device_id: Option<String>,
    pub source_app_id: Option<String>,
    pub source_user_id: Option<String>, 

    pub incoming_stream: Arc<Mutex<Option<Box<dyn AsyncStream>>>>,
}