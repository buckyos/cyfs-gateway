use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[async_trait::async_trait]
pub trait VariableVisitor: Send + Sync {
    /// Visits variable with the given id.
    async fn get(&self, id: &str) -> Result<String, String>;

    /// Sets the value for the variable with the given id.
    /// Returns the previous value if it exists.
    /// If the variable is read-only, it should return an error.
    async fn set(&self, id: &str, value: &str) -> Result<Option<String>, String>;
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
            let ret = visitor.get(id).await?;
            Ok(Some(ret))
        } else {
            Ok(None)
        }
    }

    pub async fn set_value(&self, id: &str, value: &str) -> Result<(bool, Option<String>), String> {
        let visitor = self.get_visitor(id).await;
        if let Some(visitor) = visitor {
            let ret = visitor.set(id, value).await?;
            Ok((true, ret))
        } else {
            Ok((false, None))
        }
    }
}

use crate::collection::MapCollectionRef;

#[derive(Debug, Clone)]
pub struct VariableVisitorItem {
    pub id: String,
    pub key: String,
    pub read_only: bool,
}

pub struct VariableVisitorWrapperForMapCollection {
    collection: MapCollectionRef,
    vars: HashMap<String, VariableVisitorItem>,
}

impl VariableVisitorWrapperForMapCollection {
    pub fn new(collection: MapCollectionRef) -> Self {
        Self {
            collection,
            vars: HashMap::new(),
        }
    }

    pub fn add_variable(&mut self, id: &str, key: &str, read_only: bool) {
        self.vars.insert(
            id.to_string(),
            VariableVisitorItem {
                id: id.to_string(),
                key: key.to_string(),
                read_only,
            },
        );
    }
}

#[async_trait::async_trait]
impl VariableVisitor for VariableVisitorWrapperForMapCollection {
    async fn get(&self, id: &str) -> Result<String, String> {
        if let Some(item) = self.vars.get(id) {
            match self.collection.get(&item.key).await? {
                Some(value) => Ok(value),
                None => Ok("".to_string()),
            }
        } else {
            // FIXME: Should not reach here if the variable is registered?
            let msg = format!("Variable '{}' not registered", id);
            warn!("{}", msg);
            Err(msg)
        }
    }

    async fn set(&self, id: &str, value: &str) -> Result<Option<String>, String> {
        if let Some(item) = self.vars.get(id) {
            if item.read_only {
                let msg = format!("Cannot set read-only variable '{}'", id);
                warn!("{}", msg);
                return Err(msg);
            }

            self.collection.insert(&item.key, value).await
        } else {
            // FIXME: Should not reach here if the variable is registered?
            let msg = format!("Variable '{}' not registered", id);
            warn!("{}", msg);
            Err(msg)
        }
    }
}
