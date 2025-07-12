use crate::collection::*;
use http_types::{Request, Url};
use std::sync::Arc;
use tokio::sync::RwLock;

const HTTP_REQUEST_HEADER_VARS: &[(&str, &str, bool)] = &[
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

    pub async fn register_visitors(
        &self,
        visitor_manager: &VariableVisitorManager,
    ) -> Result<(), String> {
        // First register visitors for var in header
        let coll = Arc::new(Box::new(self.clone()) as Box<dyn MapCollection>);
        let mut wrapper = VariableVisitorWrapperForMapCollection::new(coll);

        for item in HTTP_REQUEST_HEADER_VARS {
            wrapper.add_variable(item.0, item.1, item.2);
        }

        let visitor = Arc::new(Box::new(wrapper) as Box<dyn VariableVisitor>);
        for (id, _, _) in HTTP_REQUEST_HEADER_VARS {
            visitor_manager.add_visitor(*id, visitor.clone()).await?;
        }

        // Url visitor
        let url_visitor = HttpRequestUrlVisitor::new(self.request.clone(), false);
        visitor_manager
            .add_visitor(
                "REQ_url",
                Arc::new(Box::new(url_visitor) as Box<dyn VariableVisitor>),
            )
            .await?;

        Ok(())
    }
}

#[async_trait::async_trait]
impl MapCollection for HttpRequestHeaderMap {
    async fn insert(&self, key: &str, value: &str) -> Result<Option<String>, String> {
        let mut request = self.request.write().await;
        let prev = request.insert_header(key, value);
        if let Some(prev_value) = prev {
            Ok(Some(prev_value.to_string()))
        } else {
            Ok(None)
        }
    }

    async fn get(&self, key: &str) -> Result<Option<String>, String> {
        let request = self.request.read().await;
        Ok(request.header(key).map(|h| h.to_string()))
    }

    async fn contains_key(&self, key: &str) -> Result<bool, String> {
        let request = self.request.read().await;
        Ok(request.header(key).is_some())
    }

    async fn remove(&self, key: &str) -> Result<Option<String>, String> {
        let mut request = self.request.write().await;
        let prev = request.remove_header(key);
        if let Some(prev_value) = prev {
            Ok(Some(prev_value.to_string()))
        } else {
            Ok(None)
        }
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
    async fn get(&self, _id: &str) -> Result<String, String> {
        let request = self.request.read().await;
        let ret = request.url().to_string();

        Ok(ret)
    }

    async fn set(&self, id: &str, value: &str) -> Result<Option<String>, String> {
        if self.read_only {
            let msg = format!("Cannot set read-only variable '{}'", id);
            warn!("{}", msg);
            return Err(msg);
        }

        let new_url = Url::parse(value).map_err(|e| {
            let msg = format!("Invalid URL '{}': {}", value, e);
            warn!("{}", msg);
            msg
        })?;

        let mut request = self.request.write().await;
        let old_value = request.url().to_string();
        *request.url_mut() = new_url;

        info!("Set request url variable '{}' to '{}'", id, value);
        Ok(Some(old_value))
    }
}
