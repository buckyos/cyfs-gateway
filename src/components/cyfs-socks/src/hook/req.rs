use cyfs_process_chain::{CollectionValue, MapCollection, MapCollectionTraverseCallBackRef};
use fast_socks5::util::target_addr::TargetAddr;
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Clone)]
pub struct SocketAddrMap {
    addr: SocketAddr,
}

#[async_trait::async_trait]
impl MapCollection for SocketAddrMap {
    async fn len(&self) -> Result<usize, String> {
        Ok(3)
    }

    async fn insert_new(&self, key: &str, _value: CollectionValue) -> Result<bool, String> {
        let msg = format!("Cannot insert new key '{}' into SocketAddrMap", key);
        warn!("{}", msg);
        Err(msg)
    }

    async fn insert(
        &self,
        key: &str,
        _value: CollectionValue,
    ) -> Result<Option<CollectionValue>, String> {
        let msg = format!("Cannot insert key '{}' into SocketAddrMap", key);
        warn!("{}", msg);
        Err(msg)
    }

    async fn get(&self, key: &str) -> Result<Option<CollectionValue>, String> {
        match key {
            "ip" => Ok(Some(CollectionValue::String(self.addr.ip().to_string()))),
            "port" => Ok(Some(CollectionValue::String(self.addr.port().to_string()))),
            "addr" => Ok(Some(CollectionValue::String(self.addr.to_string()))),
            _ => {
                warn!("Key '{}' not found in SocketAddrMap", key);
                Ok(None)
            }
        }
    }

    async fn contains_key(&self, key: &str) -> Result<bool, String> {
        match key {
            "ip" | "port" | "addr" => Ok(true),
            _ => Ok(false),
        }
    }

    async fn remove(&self, key: &str) -> Result<Option<CollectionValue>, String> {
        let msg = format!("Cannot remove key '{}' from SocketAddrMap", key);
        warn!("{}", msg);
        Err(msg)
    }

    async fn traverse(&self, callback: MapCollectionTraverseCallBackRef) -> Result<(), String> {
        callback
            .call("ip", &CollectionValue::String(self.addr.ip().to_string()))
            .await?;
        callback
            .call(
                "port",
                &CollectionValue::String(self.addr.port().to_string()),
            )
            .await?;
        callback
            .call("addr", &CollectionValue::String(self.addr.to_string()))
            .await?;

        Ok(())
    }

    async fn dump(&self) -> Result<Vec<(String, CollectionValue)>, String> {
        Ok(vec![
            (
                "ip".to_string(),
                CollectionValue::String(self.addr.ip().to_string()),
            ),
            (
                "port".to_string(),
                CollectionValue::String(self.addr.port().to_string()),
            ),
            (
                "addr".to_string(),
                CollectionValue::String(self.addr.to_string()),
            ),
        ])
    }
}

#[derive(Clone)]
pub struct RequestTargetDomainMap {
    host: String,
    port: u16,
}

#[async_trait::async_trait]
impl MapCollection for RequestTargetDomainMap {
    async fn len(&self) -> Result<usize, String> {
        Ok(2)
    }

    async fn insert_new(&self, key: &str, _value: CollectionValue) -> Result<bool, String> {
        let msg = format!(
            "Cannot insert new key '{}' into RequestTargetDomainMap",
            key
        );
        warn!("{}", msg);
        Err(msg)
    }

    async fn insert(
        &self,
        key: &str,
        _value: CollectionValue,
    ) -> Result<Option<CollectionValue>, String> {
        let msg = format!("Cannot insert key '{}' into RequestTargetDomainMap", key);
        warn!("{}", msg);
        Err(msg)
    }

    async fn get(&self, key: &str) -> Result<Option<CollectionValue>, String> {
        match key {
            "host" => Ok(Some(CollectionValue::String(self.host.clone()))),
            "port" => Ok(Some(CollectionValue::String(self.port.to_string()))),
            _ => {
                warn!("Key '{}' not found in RequestTargetDomainMap", key);
                Ok(None)
            }
        }
    }

    async fn contains_key(&self, key: &str) -> Result<bool, String> {
        match key {
            "host" | "port" => Ok(true),
            _ => Ok(false),
        }
    }

    async fn remove(&self, key: &str) -> Result<Option<CollectionValue>, String> {
        let msg = format!("Cannot remove key '{}' from RequestTargetDomainMap", key);
        warn!("{}", msg);
        Err(msg)
    }

    async fn traverse(&self, callback: MapCollectionTraverseCallBackRef) -> Result<(), String> {
        callback
            .call("host", &CollectionValue::String(self.host.clone()))
            .await?;
        callback
            .call("port", &CollectionValue::String(self.port.to_string()))
            .await?;

        Ok(())
    }

    async fn dump(&self) -> Result<Vec<(String, CollectionValue)>, String> {
        Ok(vec![
            (
                "host".to_string(),
                CollectionValue::String(self.host.clone()),
            ),
            (
                "port".to_string(),
                CollectionValue::String(self.port.to_string()),
            ),
        ])
    }
}

#[derive(Clone)]
pub struct TargetAddrMap {
    target_addr: TargetAddr,
}

#[async_trait::async_trait]
impl MapCollection for TargetAddrMap {
    async fn len(&self) -> Result<usize, String> {
        Ok(4)
    }

    async fn insert_new(&self, key: &str, _value: CollectionValue) -> Result<bool, String> {
        let msg = format!("Cannot insert new key '{}' into TargetAddrMap", key);
        warn!("{}", msg);
        Err(msg)
    }

    async fn insert(
        &self,
        key: &str,
        _value: CollectionValue,
    ) -> Result<Option<CollectionValue>, String> {
        let msg = format!("Cannot insert key '{}' into TargetAddrMap", key);
        warn!("{}", msg);
        Err(msg)
    }

    async fn get(&self, key: &str) -> Result<Option<CollectionValue>, String> {
        match &self.target_addr {
            TargetAddr::Ip(addr) => match key {
                "type" => Ok(Some(CollectionValue::String("ip".to_string()))),
                "ip" => Ok(Some(CollectionValue::String(addr.ip().to_string()))),
                "port" => Ok(Some(CollectionValue::String(addr.port().to_string()))),
                "addr" => Ok(Some(CollectionValue::String(addr.to_string()))),
                _ => {
                    warn!("Key '{}' not found in TargetAddrMap", key);
                    Ok(None)
                }
            },
            TargetAddr::Domain(domain, port) => match key {
                "type" => Ok(Some(CollectionValue::String("domain".to_string()))),
                "host" => Ok(Some(CollectionValue::String(domain.clone()))),
                "port" => Ok(Some(CollectionValue::String(port.to_string()))),
                "addr" => Ok(Some(CollectionValue::String(format!(
                    "{}:{}",
                    domain, port
                )))),
                _ => {
                    warn!("Key '{}' not found in TargetAddrMap", key);
                    Ok(None)
                }
            },
        }
    }

    async fn contains_key(&self, key: &str) -> Result<bool, String> {
        match &self.target_addr {
            TargetAddr::Ip(_) => match key {
                "type" | "ip" | "port" | "addr" => Ok(true),
                _ => Ok(false),
            },
            TargetAddr::Domain(_, _) => match key {
                "type" | "host" | "port" | "addr" => Ok(true),
                _ => Ok(false),
            },
        }
    }

    async fn remove(&self, key: &str) -> Result<Option<CollectionValue>, String> {
        let msg = format!("Cannot remove key '{}' from TargetAddrMap", key);
        warn!("{}", msg);
        Err(msg)
    }

    async fn traverse(&self, callback: MapCollectionTraverseCallBackRef) -> Result<(), String> {
        match &self.target_addr {
            TargetAddr::Ip(addr) => {
                callback
                    .call("type", &CollectionValue::String("ip".to_string()))
                    .await?;
                callback
                    .call("ip", &CollectionValue::String(addr.ip().to_string()))
                    .await?;
                callback
                    .call("port", &CollectionValue::String(addr.port().to_string()))
                    .await?;
                callback
                    .call("addr", &CollectionValue::String(addr.to_string()))
                    .await?;
            }
            TargetAddr::Domain(domain, port) => {
                callback
                    .call("type", &CollectionValue::String("domain".to_string()))
                    .await?;
                callback
                    .call("host", &CollectionValue::String(domain.clone()))
                    .await?;
                callback
                    .call("port", &CollectionValue::String(port.to_string()))
                    .await?;
                callback
                    .call(
                        "addr",
                        &CollectionValue::String(format!("{}:{}", domain, port)),
                    )
                    .await?;
            }
        }

        Ok(())
    }

    async fn dump(&self) -> Result<Vec<(String, CollectionValue)>, String> {
        match &self.target_addr {
            TargetAddr::Ip(addr) => Ok(vec![
                (
                    "type".to_string(),
                    CollectionValue::String("ip".to_string()),
                ),
                (
                    "ip".to_string(),
                    CollectionValue::String(addr.ip().to_string()),
                ),
                (
                    "port".to_string(),
                    CollectionValue::String(addr.port().to_string()),
                ),
                (
                    "addr".to_string(),
                    CollectionValue::String(addr.to_string()),
                ),
            ]),
            TargetAddr::Domain(domain, port) => Ok(vec![
                (
                    "type".to_string(),
                    CollectionValue::String("domain".to_string()),
                ),
                ("host".to_string(), CollectionValue::String(domain.clone())),
                (
                    "port".to_string(),
                    CollectionValue::String(port.to_string()),
                ),
                (
                    "addr".to_string(),
                    CollectionValue::String(format!("{}:{}", domain, port)),
                ),
            ]),
        }
    }
}

#[derive(Clone)]
pub struct SocksRequestMap {
    inbound_addr: Option<String>,
    target_addr: TargetAddr,
}

impl SocksRequestMap {
    pub fn new(inbound_addr: Option<String>, target_addr: TargetAddr) -> Self {
        Self {
            inbound_addr,
            target_addr,
        }
    }

    fn inbound_addr_value(&self) -> CollectionValue {
        let str = match &self.inbound_addr {
            Some(addr) => addr.clone(),
            None => "".to_string(),
        };

        CollectionValue::String(str)
    }

    fn target_addr_value(&self) -> CollectionValue {
        let map = TargetAddrMap {
            target_addr: self.target_addr.clone(),
        };
        let map = Arc::new(Box::new(map) as Box<dyn MapCollection>);
        CollectionValue::Map(map)
    }
}

#[async_trait::async_trait]
impl MapCollection for SocksRequestMap {
    async fn len(&self) -> Result<usize, String> {
        Ok(2)
    }

    async fn insert_new(&self, key: &str, _value: CollectionValue) -> Result<bool, String> {
        let msg = format!("Cannot insert new key '{}' into SocksRequestMap", key);
        warn!("{}", msg);
        Err(msg)
    }

    async fn insert(
        &self,
        key: &str,
        _value: CollectionValue,
    ) -> Result<Option<CollectionValue>, String> {
        let msg = format!("Cannot insert key '{}' into SocksRequestMap", key);
        warn!("{}", msg);
        Err(msg)
    }

    async fn get(&self, key: &str) -> Result<Option<CollectionValue>, String> {
        match key {
            "inbound" => Ok(Some(self.inbound_addr_value())),
            "target" => Ok(Some(self.target_addr_value())),
            _ => {
                warn!("Key '{}' not found in SocksRequestMap", key);
                Ok(None)
            }
        }
    }

    async fn contains_key(&self, key: &str) -> Result<bool, String> {
        match key {
            "inbound" | "target" => Ok(true),
            _ => Ok(false),
        }
    }

    async fn remove(&self, key: &str) -> Result<Option<CollectionValue>, String> {
        let msg = format!("Cannot remove key '{}' from SocksRequestMap", key);
        warn!("{}", msg);
        Err(msg)
    }

    async fn traverse(&self, callback: MapCollectionTraverseCallBackRef) -> Result<(), String> {
        callback.call("inbound", &self.inbound_addr_value()).await?;
        callback.call("target", &self.target_addr_value()).await?;

        Ok(())
    }

    async fn dump(&self) -> Result<Vec<(String, CollectionValue)>, String> {
        Ok(vec![
            ("inbound".to_string(), self.inbound_addr_value()),
            ("target".to_string(), self.target_addr_value()),
        ])
    }
}
