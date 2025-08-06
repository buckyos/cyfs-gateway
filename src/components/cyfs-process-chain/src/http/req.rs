use crate::chain::Env;
use crate::collection::*;
use http_types::{Request, Url};
use std::sync::Arc;
use tokio::sync::RwLock;

pub const HTTP_REQUEST_HEADER_VARS: &[(&str, &str, bool)] = &[
    ("REQ_host", "host", true),
    ("REQ_method", "method", true),
    ("REQ_content_length", "content-length", true),
    ("REQ_content_type", "content-type", true),
    ("REQ_user_agent", "user-agent", true),
];

#[derive(Clone)]
pub struct HttpRequestHeaderMap {
    request: Arc<RwLock<Request>>,
}

impl HttpRequestHeaderMap {
    pub fn new(request: Request) -> Self {
        Self {
            request: Arc::new(RwLock::new(request)),
        }
    }

    pub fn into_request(self) -> Result<Request, String> {
        let req = Arc::try_unwrap(self.request)
            .map_err(|_| "Failed to unwrap HyperHttpRequestHeaderMap".to_string())?
            .into_inner();

        Ok(req)
    }

    pub async fn register_visitors(&self, env: &Env) -> Result<(), String> {
        // First register visitors for var in header
        let coll = Arc::new(Box::new(self.clone()) as Box<dyn MapCollection>);
        let mut wrapper = VariableVisitorWrapperForMapCollection::new(coll);

        for item in HTTP_REQUEST_HEADER_VARS {
            wrapper.add_variable(item.0, item.1, item.2);
        }

        let visitor = Arc::new(Box::new(wrapper) as Box<dyn VariableVisitor>);
        for (id, _, _) in HTTP_REQUEST_HEADER_VARS {
            env.create(*id, CollectionValue::Visitor(visitor.clone()))
                .await?;
        }

        // Url visitor
        let url_visitor = HttpRequestUrlVisitor::new(self.request.clone(), false);
        let visitor = Arc::new(Box::new(url_visitor) as Box<dyn VariableVisitor>);
        env.create("REQ_url", CollectionValue::Visitor(visitor))
            .await?;

        Ok(())
    }
}

#[async_trait::async_trait]
impl MapCollection for HttpRequestHeaderMap {
    async fn len(&self) -> Result<usize, String> {
        // FIXME: The performance of this is not optimal, as it reads the entire request, and is O(n).
        // Consider optimizing this if necessary. maybe we just return a constant value such as 0?
        let request = self.request.read().await;
        Ok(request.header_names().count())
    }

    async fn insert_new(&self, key: &str, value: CollectionValue) -> Result<bool, String> {
        let mut request = self.request.write().await;
        if request.header(key).is_some() {
            let msg = format!("Header '{}' already exists", key);
            warn!("{}", msg);
            return Ok(false);
        }

        request.insert_header(key, value.try_as_str()?);
        Ok(true)
    }

    async fn insert(
        &self,
        key: &str,
        value: CollectionValue,
    ) -> Result<Option<CollectionValue>, String> {
        let mut request = self.request.write().await;
        let prev = request.insert_header(key, value.try_as_str()?);
        if let Some(prev_value) = prev {
            Ok(Some(CollectionValue::String(prev_value.to_string())))
        } else {
            Ok(None)
        }
    }

    async fn get(&self, key: &str) -> Result<Option<CollectionValue>, String> {
        let request = self.request.read().await;
        let prev = request.header(key).map(|h| h.to_string());
        Ok(prev.map(|v| CollectionValue::String(v)))
    }

    async fn contains_key(&self, key: &str) -> Result<bool, String> {
        let request = self.request.read().await;
        Ok(request.header(key).is_some())
    }

    async fn remove(&self, key: &str) -> Result<Option<CollectionValue>, String> {
        let mut request = self.request.write().await;
        let prev = request.remove_header(key);
        if let Some(prev_value) = prev {
            Ok(Some(CollectionValue::String(prev_value.to_string())))
        } else {
            Ok(None)
        }
    }

    async fn dump(&self) -> Result<Vec<(String, CollectionValue)>, String> {
        let request = self.request.read().await;
        let mut result = Vec::new();
        for (key, value) in request.iter() {
            result.push((key.to_string(), CollectionValue::String(value.to_string())));
        }
        Ok(result)
    }
}

// Url visitor for HTTP requests
#[derive(Clone)]
pub struct HttpRequestUrlVisitor {
    request: Arc<RwLock<Request>>,
    read_only: bool,
}

impl HttpRequestUrlVisitor {
    pub fn new(request: Arc<RwLock<Request>>, read_only: bool) -> Self {
        Self { request, read_only }
    }
}

#[async_trait::async_trait]
impl VariableVisitor for HttpRequestUrlVisitor {
    async fn get(&self, _id: &str) -> Result<CollectionValue, String> {
        let request = self.request.read().await;
        let ret = request.url().to_string();

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

        let new_url = Url::parse(value.try_as_str()?).map_err(|e| {
            let msg = format!("Invalid URL '{}': {}", value, e);
            warn!("{}", msg);
            msg
        })?;

        let mut request = self.request.write().await;
        let old_value = request.url().to_string();
        *request.url_mut() = new_url;

        info!("Set request url variable '{}' to '{}'", id, value);
        Ok(Some(CollectionValue::String(old_value)))
    }
}
