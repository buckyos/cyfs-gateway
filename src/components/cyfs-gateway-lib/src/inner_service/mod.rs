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
use crate::StreamInfo;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ServiceErrorCode {
    Failed,
    UnknownService,
    InvalidConfig,
    DnsQueryError,
    AlreadyExists,
    NotFound,
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

    pub fn is_http_service(&self) -> bool {
        match self {
            InnerService::HttpService(_) => true,
            _ => false,
        }
    }

    pub fn is_dns_service(&self) -> bool {
        match self {
            InnerService::DnsService(_) => true,
            _ => false,
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
pub type CyfsInnerServiceFactoryRef = Arc<CyfsInnerServiceFactory>;

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
    async fn handle(&self, request: Request<BoxBody<Bytes, ()>>, info: StreamInfo) -> Response<BoxBody<Bytes, ()>>;
}

pub struct InnerServiceManager {
    services: Mutex<HashMap<String, Vec<InnerService>>>,
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

    pub fn add_service(&self, service_impl: Vec<InnerService>) -> ServiceResult<()> {
        if service_impl.is_empty() {
            return Ok(())
        }
        let id = service_impl.first().unwrap().id();
        if self.get_service(id.as_str()).is_some() {
            return Err(service_err!(ServiceErrorCode::AlreadyExists, "service {} already exists", id))
        }
        self.services.lock().unwrap().insert(id, service_impl);
        Ok(())
    }

    pub fn replace_service(&self, service_impl: Vec<InnerService>) {
        let mut services = self.services.lock().unwrap();
        if service_impl.is_empty() {
            return;
        }
        let id = service_impl.first().unwrap().id();
        services.insert(id, service_impl);
    }

    pub fn get_service(&self, service: &str) -> Option<Vec<InnerService>> {
        self.services.lock().unwrap().get(service).cloned()
    }

    pub fn get_http_service(&self, service: &str) -> Option<Arc<dyn InnerHttpService>> {
        let services = self.get_service(service);
        if services.is_none() {
            return None;
        }
        
        let services = services.unwrap();
        for service in services {
            match service {
                InnerService::HttpService(service) => return Some(service.clone()),
                _ => continue,
            }
        }
        None
    }

    pub fn get_dns_service(&self, service: &str) -> Option<Arc<dyn InnerDnsService>> {
        let services = self.get_service(service);
        if services.is_none() {
            return None;
        }

        let services = services.unwrap();
        for service in services {
            match service {
                InnerService::DnsService(service) => return Some(service.clone()),
                _ => continue,
            }
        }
        None
    }

    pub fn retain(&self, f: impl Fn(&str) -> bool) {
        self.services.lock().unwrap().retain(|k, _| {
            f(k)
        });
    }
}

#[async_trait::async_trait]
pub trait InnerDnsService: Send + Sync {
    fn id(&self) -> String;
    async fn query(&self, name: &str, record_type: Option<RecordType>, from_ip: Option<IpAddr>) -> ServiceResult<NameInfo>;
    async fn query_did(&self, did: &DID, fragment: Option<&str>, from_ip: Option<IpAddr>) -> ServiceResult<EncodedDocument>;
}
