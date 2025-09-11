use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use http::{Request, Response};
use http_body_util::combinators::BoxBody;
use hyper::body::Bytes;
use name_client::{NameInfo, RecordType};
use name_lib::{EncodedDocument, DID};

#[async_trait::async_trait]
pub trait InnerHttpService: Send + Sync {
    async fn handle(&self, request: Request<BoxBody<Bytes, ()>>) -> Response<BoxBody<Bytes, ()>>;
}

pub struct InnerHttpServiceManager {
    services: HashMap<String, Arc<dyn InnerHttpService>>,
}
pub type InnerHttpServiceManagerRef = Arc<InnerHttpServiceManager>;


impl InnerHttpServiceManager {
    pub fn new() -> Self {
        Self {
            services: HashMap::new(),
        }
    }
}

#[async_trait::async_trait]
pub trait InnerDnsService: Send + Sync {
    async fn query(&self, name: &str, record_type: Option<RecordType>, from_ip: Option<IpAddr>) -> Result<NameInfo, ()>;
    async fn query_did(&self, did: &DID, fragment: Option<&str>, from_ip: Option<IpAddr>) -> Result<EncodedDocument, ()>;
}

pub struct InnerDnsServiceManager {
    services: HashMap<String, Arc<dyn InnerDnsService>>,
}
