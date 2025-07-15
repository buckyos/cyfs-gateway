use std::collections::HashMap;
use std::sync::Arc;
use super::coll::CollectionValue;

#[async_trait::async_trait]
pub trait VariableVisitor: Send + Sync {
    /// Visits variable with the given id.
    async fn get(&self, id: &str) -> Result<CollectionValue, String>;

    /// Sets the value for the variable with the given id.
    /// Returns the previous value if it exists.
    /// If the variable is read-only, it should return an error.
    async fn set(&self, id: &str, value: CollectionValue) -> Result<Option<CollectionValue>, String>;
}

pub type VariableVisitorRef = Arc<Box<dyn VariableVisitor>>;


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
    async fn get(&self, id: &str) -> Result<CollectionValue, String> {
        if let Some(item) = self.vars.get(id) {
            match self.collection.get(&item.key).await? {
                Some(value) => Ok(value),
                None => {
                    let msg = format!("Variable '{}' not found in visitor collection", id);
                    warn!("{}", msg);
                    Err(msg)
                }
            }
        } else {
            // FIXME: Should not reach here if the variable is registered?
            let msg = format!("Variable '{}' not registered", id);
            warn!("{}", msg);
            Err(msg)
        }
    }

    async fn set(&self, id: &str, value: CollectionValue) -> Result<Option<CollectionValue>, String> {
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
