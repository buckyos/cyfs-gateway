use std::collections::HashMap;
pub use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use as_any::AsAny;
pub use http::{Request, Response};
pub use http_body_util::combinators::BoxBody;
pub use hyper::body::Bytes;
pub use name_client::{NameInfo, RecordType};
use name_lib::{EncodedDocument, DID};
pub use sfo_result::err as service_err;
pub use sfo_result::into_err as into_service_err;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ServiceErrorCode {
    Failed,
    UnknownService,
    InvalidConfig,
    DnsQueryError,
}
pub type ServiceResult<T> = sfo_result::Result<T, ServiceErrorCode>;
pub type ServiceError = sfo_result::Error<ServiceErrorCode>;

#[derive(Clone)]
pub enum InnerService {
    HttpService(Arc<dyn InnerHttpService>),
    DnsService(Arc<dyn InnerDnsService>),
}

impl InnerService {
    pub fn id(&self) -> String {
        match self {
            InnerService::HttpService(service) => service.id(),
            InnerService::DnsService(service) => service.id(),
        }
    }
}

pub trait InnerServiceConfig: AsAny + Send + Sync {
    fn id(&self) -> String;
    fn service_type(&self) -> String;
    fn get_config_json(&self) -> String;
}

#[async_trait::async_trait]
pub trait InnerServiceFactory: Send + Sync {
    async fn create(&self, config: Arc<dyn InnerServiceConfig>) -> ServiceResult<Vec<InnerService>>;
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
    async fn create(&self, config: Arc<dyn InnerServiceConfig>) -> ServiceResult<Vec<InnerService>> {
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
    fn id(&self) -> String;
    async fn handle(&self, request: Request<BoxBody<Bytes, ()>>) -> Response<BoxBody<Bytes, ()>>;
}

pub struct InnerServiceManager {
    services: Mutex<HashMap<String, InnerService>>,
}
pub type InnerServiceManagerRef = Arc<InnerServiceManager>;


impl Default for InnerServiceManager {
    fn default() -> Self {
        Self::new()
    }
}

impl InnerServiceManager {
    pub fn new() -> Self {
        Self {
            services: Mutex::new(HashMap::new()),
        }
    }

    pub fn add_service(&self, service_impl: InnerService) {
        self.services.lock().unwrap().insert(service_impl.id(), service_impl);
    }

    pub fn get_service(&self, service: &str) -> Option<InnerService> {
        self.services.lock().unwrap().get(service).cloned()
    }

    pub fn get_http_service(&self, service: &str) -> Option<Arc<dyn InnerHttpService>> {
        self.get_service(service).and_then(|service| {
            match service {
                InnerService::HttpService(service) => Some(service.clone()),
                _ => None,
            }
        })
    }

    pub fn get_dns_service(&self, service: &str) -> Option<Arc<dyn InnerDnsService>> {
        self.get_service(service).and_then(|service| {
            match service {
                InnerService::DnsService(service) => Some(service.clone()),
                _ => None,
            }
        })
    }
}

#[async_trait::async_trait]
pub trait InnerDnsService: Send + Sync {
    fn id(&self) -> String;
    async fn query(&self, name: &str, record_type: Option<RecordType>, from_ip: Option<IpAddr>) -> ServiceResult<NameInfo>;
    async fn query_did(&self, did: &DID, fragment: Option<&str>, from_ip: Option<IpAddr>) -> ServiceResult<EncodedDocument>;
}
