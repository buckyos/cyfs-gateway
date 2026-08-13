use serde::Serialize;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone)]
pub(crate) struct RemoteReadCache {
    inner: Arc<Mutex<HashMap<String, RemoteReadCacheEntry>>>,
    ttl: Duration,
    capacity: usize,
}

#[derive(Clone)]
struct RemoteReadCacheEntry {
    value: Value,
    expires_at: Instant,
}

impl RemoteReadCache {
    pub(crate) fn new(ttl: Duration, capacity: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            ttl,
            capacity,
        }
    }

    pub(crate) fn key<Req: Serialize>(
        method: &str,
        req: &Req,
    ) -> Result<String, serde_json::Error> {
        serde_json::to_string(req).map(|params| format!("{method}\n{params}"))
    }

    pub(crate) fn get(&self, key: &str) -> Option<Value> {
        if self.ttl.is_zero() || self.capacity == 0 {
            return None;
        }

        let now = Instant::now();
        let mut entries = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        match entries.get(key) {
            Some(entry) if entry.expires_at > now => Some(entry.value.clone()),
            Some(_) => {
                entries.remove(key);
                None
            }
            None => None,
        }
    }

    pub(crate) fn insert(&self, key: String, value: Value) {
        if self.ttl.is_zero() || self.capacity == 0 {
            return;
        }

        let now = Instant::now();
        let mut entries = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if entries.len() >= self.capacity {
            entries.retain(|_, entry| entry.expires_at > now);
        }
        if entries.len() >= self.capacity && !entries.contains_key(&key) {
            if let Some(oldest_key) = entries
                .iter()
                .min_by_key(|(_, entry)| entry.expires_at)
                .map(|(key, _)| key.clone())
            {
                entries.remove(oldest_key.as_str());
            }
        }
        entries.insert(
            key,
            RemoteReadCacheEntry {
                value,
                expires_at: now + self.ttl,
            },
        );
    }

    pub(crate) fn clear(&self) {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn caches_and_clears_values() {
        let cache = RemoteReadCache::new(Duration::from_secs(60), 4);
        let key = RemoteReadCache::key("read", &json!({"id": "a"})).unwrap();
        cache.insert(key.clone(), json!({"ok": true}));

        assert_eq!(cache.get(key.as_str()), Some(json!({"ok": true})));

        cache.clear();
        assert_eq!(cache.get(key.as_str()), None);
    }
}
