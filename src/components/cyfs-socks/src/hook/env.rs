use super::req::SocksRequestMap;
use cyfs_process_chain::*;
use std::sync::Arc;

pub struct SocksRequestEnv {
    req: MapCollectionRef,
}

impl SocksRequestEnv {
    pub fn new(req: SocksRequestMap) -> Self {
        let req = Arc::new(Box::new(req) as Box<dyn MapCollection>);
        Self { req }
    }
}

#[async_trait::async_trait]
impl EnvExternal for SocksRequestEnv {
    async fn contains(&self, key: &str) -> Result<bool, String> {
        match key {
            "REQ" => Ok(true),
            _ => Ok(false),
        }
    }

    async fn get(&self, key: &str) -> Result<Option<CollectionValue>, String> {
        match key {
            "REQ" => Ok(Some(CollectionValue::Map(self.req.clone()))),
            _ => Ok(None),
        }
    }

    async fn set(
        &self,
        id: &str,
        _value: CollectionValue,
    ) -> Result<Option<CollectionValue>, String> {
        let msg = format!("SocksRequestEnv is read-only, cannot set value: {}", id);
        warn!("{}", msg);
        Err(msg)
    }

    async fn remove(&self, id: &str) -> Result<Option<CollectionValue>, String> {
        let msg = format!("SocksRequestEnv is read-only, cannot remove value: {}", id);
        warn!("{}", msg);
        Err(msg)
    }
}
