use std::collections::{HashMap, HashSet};
use std::sync::Arc;

#[async_trait::async_trait]
pub trait HostStorage: Send + Sync {
    fn add_host(&mut self, host: &str, labels: HashSet<String>);
    fn get_labels(&self, host: &str) -> Option<String>;
    fn set_label(&mut self, host: &str, label: &str);
    fn has_host(&self, host: &str) -> bool;
}

pub type HostStorageRef = Arc<Box<dyn HostStorage>>;

pub fn new_memory_host_storage() -> HostStorageRef {
    Arc::new(Box::new(MemoryHostStorage::new()))
}

pub struct MemoryHostStorage {
    hosts: HashMap<String, HashSet<String>>,
}

impl MemoryHostStorage {
    pub fn new() -> Self {
        Self {
            hosts: HashMap::new(),
        }
    }
}

#[async_trait::async_trait]
impl HostStorage for MemoryHostStorage {
    fn add_host(&mut self, host: &str, labels: HashSet<String>) {
        self.hosts.insert(host.to_string(), labels);
    }

    fn get_labels(&self, host: &str) -> Option<String> {
        let labels = self.hosts.get(host);
        if labels.is_none() {
            return None;
        }

        let labels = labels.unwrap();
        let result: String = labels.iter().map(|s| s.as_str()).collect::<Vec<&str>>().join(",");
        Some(result)
    }

    fn set_label(&mut self, host: &str, label: &str) {
        let labels = self.hosts.entry(host.to_string()).or_insert(HashSet::new());
        labels.insert(label.to_string());
    }

    fn has_host(&self, host: &str) -> bool {
        self.hosts.contains_key(host)
    }
}

// TODO: SQLite based host storage
pub struct HostStorageSQLite {}