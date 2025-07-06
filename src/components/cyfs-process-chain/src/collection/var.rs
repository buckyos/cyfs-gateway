use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[async_trait::async_trait]
pub trait VariableVisitor: Send + Sync {
    /// Visits a set collection with the given id.
    async fn get(&self, id: &str) -> Result<String, String>;

    /// Visits a map collection with the given id.
    async fn set(&self, value: &str) -> Result<Option<String>, String>;
}

pub type VariableVisitorRef = Arc<Box<dyn VariableVisitor>>;

#[derive(Clone)]
pub struct VariableVisitorManager {
    visitors: Arc<RwLock<HashMap<String, VariableVisitorRef>>>,
}

impl VariableVisitorManager {
    pub fn new() -> Self {
        Self {
            visitors: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn add_visitor(&self, id: &str, visitor: VariableVisitorRef) -> Result<(), String> {
        let mut visitors = self.visitors.write().await;
        if visitors.contains_key(id) {
            let msg = format!("Visitor with id '{}' already exists", id);
            warn!("{}", msg);
            return Err(msg);
        }

        info!("Adding visitor with id '{}'", id);
        visitors.insert(id.to_string(), visitor);

        Ok(())
    }

    pub async fn remove_visitor(&self, id: &str) -> Option<VariableVisitorRef> {
        let mut visitors = self.visitors.write().await;
        if let Some(visitor) = visitors.remove(id) {
            info!("Removed visitor with id '{}'", id);
            Some(visitor)
        } else {
            warn!("Visitor with id '{}' not found", id);
            None
        }
    }

    pub async fn get_visitor(&self, id: &str) -> Option<VariableVisitorRef> {
        let visitors = self.visitors.read().await;
        if let Some(visitor) = visitors.get(id) {
            Some(visitor.clone())
        } else {
            None
        }
    }

    pub async fn has_visitor(&self, id: &str) -> bool {
        let visitors = self.visitors.read().await;
        visitors.contains_key(id)
    }

    pub async fn get_value(&self, id: &str) -> Result<Option<String>, String> {
        let visitor = self.get_visitor(id).await;
        if let Some(visitor) = visitor {
            let ret = visitor
                .get(id)
                .await?;
            Ok(Some(ret))
        } else {
            Ok(None)
        }
    }

    pub async fn set_value(&self, id: &str, value: &str) -> Result<(bool, Option<String>), String> {
        let visitor = self.get_visitor(id).await;
        if let Some(visitor) = visitor {
            let ret=  visitor.set(value).await?;
            Ok((true, ret))
        } else {
            Ok((false, None))
        }
    }
}
