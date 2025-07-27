use super::req::HTTP_REQUEST_HEADER_VARS;
use crate::chain::EnvRef;
use crate::collection::*;
use hyper::{Uri, header::HeaderName};
use std::sync::Arc;
use tokio::sync::RwLock;

type Request = hyper::Request<hyper::Body>;

#[derive(Clone)]
pub struct HyperHttpRequestHeaderMap {
    request: Arc<RwLock<Request>>,
}

impl HyperHttpRequestHeaderMap {
    pub fn new(request: Request) -> Self {
        Self {
            request: Arc::new(RwLock::new(request)),
        }
    }

    pub fn into_request(self) -> Result<Request, String> {
        let req = Arc::try_unwrap(self.request)
            .map_err(|_| {
                let msg = "Failed to unwrap HyperHttpRequestHeaderMap".to_string();
                error!("{}", msg);
                msg
            })?
            .into_inner();

        Ok(req)
    }

    pub async fn register_visitors(&self, env: &EnvRef) -> Result<(), String> {
        // First register visitors for var in header
        let coll = Arc::new(Box::new(self.clone()) as Box<dyn MapCollection>);
        let mut wrapper = VariableVisitorWrapperForMapCollection::new(coll);

        for item in HTTP_REQUEST_HEADER_VARS {
            wrapper.add_variable(item.0, item.1, item.2);
        }

        let visitor = Arc::new(Box::new(wrapper) as Box<dyn VariableVisitor>);
        for (id, _, _) in HTTP_REQUEST_HEADER_VARS {
            env.create(*id, CollectionValue::Visitor(Arc::clone(&visitor)))
                .await?;
        }

        // Url visitor
        let url_visitor = HyperHttpRequestUrlVisitor::new(self.request.clone(), false);
        let visitor = Arc::new(Box::new(url_visitor) as Box<dyn VariableVisitor>);
        env.create("REQ_url", CollectionValue::Visitor(visitor))
            .await?;

        Ok(())
    }
}

#[async_trait::async_trait]
impl MapCollection for HyperHttpRequestHeaderMap {
    async fn insert_new(&self, key: &str, value: CollectionValue) -> Result<bool, String> {
        let mut request = self.request.write().await;
        let header = value.try_as_str()?.parse().map_err(|e| {
            let msg = format!("Invalid header value '{}': {}", value, e);
            warn!("{}", msg);
            msg
        })?;

        let name = HeaderName::from_bytes(key.as_bytes()).map_err(|e| {
            let msg = format!("Invalid header name '{}': {}", key, e);
            warn!("{}", msg);
            msg.to_string()
        })?;

        if request.headers().contains_key(&name) {
            let msg = format!("Header '{}' already exists", key);
            warn!("{}", msg);
            return Ok(false);
        }

        request.headers_mut().insert(name, header);
        Ok(true)
    }

    async fn insert(
        &self,
        key: &str,
        value: CollectionValue,
    ) -> Result<Option<CollectionValue>, String> {
        let mut request = self.request.write().await;
        let header = value.try_as_str()?.parse().map_err(|e| {
            let msg = format!("Invalid header value '{}': {}", value, e);
            warn!("{}", msg);
            msg
        })?;

        let name = HeaderName::from_bytes(key.as_bytes()).map_err(|e| {
            let msg = format!("Invalid header name '{}': {}", key, e);
            warn!("{}", msg);
            msg.to_string()
        })?;

        let prev = request.headers_mut().insert(name, header);
        if let Some(prev_value) = prev {
            let prev = match prev_value.to_str() {
                Ok(s) => s.to_string(),
                Err(_) => {
                    let msg = format!("Header value for '{}' is not valid UTF-8", key);
                    warn!("{}", msg);
                    "".to_string()
                }
            };
            Ok(Some(CollectionValue::String(prev)))
        } else {
            Ok(None)
        }
    }

    async fn get(&self, key: &str) -> Result<Option<CollectionValue>, String> {
        let request = self.request.read().await;
        let ret = request.headers().get(key);
        if let Some(value) = ret {
            if let Ok(value_str) = value.to_str() {
                Ok(Some(CollectionValue::String(value_str.to_string())))
            } else {
                warn!("Header value for '{}' is not valid UTF-8", key);
                Ok(Some(CollectionValue::String("".to_string())))
            }
        } else {
            warn!("Header '{}' not found", key);
            Ok(None)
        }
    }

    async fn contains_key(&self, key: &str) -> Result<bool, String> {
        let request = self.request.read().await;
        Ok(request.headers().get(key).is_some())
    }

    async fn remove(&self, key: &str) -> Result<Option<CollectionValue>, String> {
        let mut request = self.request.write().await;
        let prev = request.headers_mut().remove(key);
        if let Some(prev_value) = prev {
            let prev = match prev_value.to_str() {
                Ok(s) => s.to_string(),
                Err(_) => {
                    let msg = format!("Header value for '{}' is not valid UTF-8", key);
                    warn!("{}", msg);
                    "".to_string()
                }
            };
            Ok(Some(CollectionValue::String(prev)))
        } else {
            Ok(None)
        }
    }

    async fn dump(&self) -> Result<Vec<(String, CollectionValue)>, String> {
        let request = self.request.read().await;
        let mut result = Vec::new();
        for (key, value) in request.headers().iter() {
            if let Ok(value_str) = value.to_str() {
                result.push((key.as_str().to_string(), CollectionValue::String(value_str.to_string())));
            } else {
                warn!("Header value for '{}' is not valid UTF-8", key);
            }
        }
        Ok(result)
    }
}

// Url visitor for HTTP requests
#[derive(Clone)]
pub struct HyperHttpRequestUrlVisitor {
    request: Arc<RwLock<Request>>,
    read_only: bool,
}

impl HyperHttpRequestUrlVisitor {
    pub fn new(request: Arc<RwLock<Request>>, read_only: bool) -> Self {
        Self { request, read_only }
    }
}

#[async_trait::async_trait]
impl VariableVisitor for HyperHttpRequestUrlVisitor {
    async fn get(&self, _id: &str) -> Result<CollectionValue, String> {
        let request = self.request.read().await;
        let ret = request.uri().to_string();

        Ok(CollectionValue::String(ret))
    }

    async fn set(
        &self,
        id: &str,
        value: CollectionValue,
    ) -> Result<Option<CollectionValue>, String> {
        if self.read_only {
            let msg = format!("Cannot set read-only variable '{}'", id);
            warn!("{}", msg);
            return Err(msg);
        }

        let new_url = value.try_as_str()?.parse::<Uri>().map_err(|e| {
            let msg = format!("Invalid URL '{}': {}", value, e);
            warn!("{}", msg);
            msg
        })?;

        let mut request = self.request.write().await;
        let old_value = request.uri().to_string();
        *request.uri_mut() = new_url;

        info!("Set request url variable '{}' to '{}'", id, value);
        Ok(Some(CollectionValue::String(old_value)))
    }
}
