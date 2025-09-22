use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use as_any::AsAny;
use http::{Request, Response};
use http_body_util::combinators::BoxBody;
use hyper::body::Bytes;
use name_client::{NameInfo, RecordType};
use name_lib::{EncodedDocument, DID};

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ServiceErrorCode {
    Failed,
    UnknownService,
}
pub type ServiceResult<T> = sfo_result::Result<T, ServiceErrorCode>;
pub type ServiceError = sfo_result::Error<ServiceErrorCode>;

pub trait InnerService: Send + Sync {
    fn service_type(&self) -> String;
}

pub trait InnerServiceConfig: AsAny + Send + Sync {
    fn service_type(&self) -> String;
}

#[async_trait::async_trait]
pub trait InnerServiceFactory: Send + Sync {
    async fn create(&self, config: Arc<dyn InnerServiceConfig>) -> ServiceResult<Arc<dyn InnerService>>;
}

pub struct CyfsInnerServiceFactory {
    service_factory: Mutex<HashMap<String, Arc<dyn InnerServiceFactory>>>,
}

impl Default for CyfsInnerServiceFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl CyfsInnerServiceFactory {
    pub fn new() -> Self {
        Self {
            service_factory: Mutex::new(HashMap::new()),
        }
    }
    pub fn register(&self, service_type: String, factory: Arc<dyn InnerServiceFactory>) {
        self.service_factory.lock().unwrap().insert(service_type, factory);
    }
}

#[async_trait::async_trait]
impl InnerServiceFactory for CyfsInnerServiceFactory {
    async fn create(&self, config: Arc<dyn InnerServiceConfig>) -> ServiceResult<Arc<dyn InnerService>> {
        let factory = {
            self.service_factory.lock().unwrap().get(&config.service_type()).cloned()
        };
        if let Some(factory) = factory {
            factory.create(config).await
        } else {
            Err(ServiceError::new(
                ServiceErrorCode::UnknownService,
                format!("InnerServiceFactory not support service_type: {}", config.service_type()),
            ))
        }
    }
}
#[async_trait::async_trait]
pub trait InnerHttpService: Send + Sync {
    async fn handle(&self, request: Request<BoxBody<Bytes, ()>>) -> Response<BoxBody<Bytes, ()>>;
}

pub struct InnerHttpServiceManager {
    services: HashMap<String, Arc<dyn InnerHttpService>>,
}
pub type InnerHttpServiceManagerRef = Arc<InnerHttpServiceManager>;


impl Default for InnerHttpServiceManager {
    fn default() -> Self {
        Self::new()
    }
}

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
