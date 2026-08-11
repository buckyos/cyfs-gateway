use name_client::{NameInfo, RecordType};
use std::collections::HashMap;
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{Duration, Instant};

pub const DEFAULT_NAME_INFO_CACHE_TTL_SECS: u32 = 60;
pub const MIN_NAME_INFO_CACHE_TTL_SECS: u32 = 60;

pub type NameInfoCacheRef = Arc<NameInfoCache>;

#[derive(Clone, Debug)]
pub enum NameInfoCacheQueryResult {
    Hit(NameInfo),
    Tombstone,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct NameInfoCacheKey {
    name: String,
    record_type: String,
}

#[derive(Clone, Debug)]
enum NameInfoCacheValue {
    Hit(NameInfo),
    Tombstone,
}

#[derive(Clone, Debug)]
struct NameInfoCacheEntry {
    value: NameInfoCacheValue,
    expires_at: Instant,
}

#[derive(Debug)]
pub struct NameInfoCache {
    items: RwLock<HashMap<NameInfoCacheKey, NameInfoCacheEntry>>,
    min_ttl: Duration,
}

impl Default for NameInfoCache {
    fn default() -> Self {
        Self::new()
    }
}

impl NameInfoCache {
    pub fn new() -> Self {
        Self::with_min_ttl(Duration::from_secs(MIN_NAME_INFO_CACHE_TTL_SECS as u64))
    }

    pub fn new_ref() -> NameInfoCacheRef {
        Arc::new(Self::new())
    }

    pub fn query(&self, name: &str, record_type: RecordType) -> Option<NameInfoCacheQueryResult> {
        let key = Self::make_key(name, record_type);
        let now = Instant::now();

        if let Some(result) = self.query_without_cleanup(&key, now) {
            return Some(result);
        }

        self.remove_if_expired(&key, now);
        None
    }

    pub fn add(
        &self,
        name: &str,
        record_type: RecordType,
        name_info: NameInfo,
        cache_ttl_secs: Option<u32>,
    ) {
        self.insert(
            name,
            record_type,
            NameInfoCacheValue::Hit(name_info),
            cache_ttl_secs,
        );
    }

    pub fn add_tombstone(&self, name: &str, record_type: RecordType, cache_ttl_secs: Option<u32>) {
        self.insert(
            name,
            record_type,
            NameInfoCacheValue::Tombstone,
            cache_ttl_secs,
        );
    }

    pub fn remove(&self, name: &str, record_type: RecordType) -> bool {
        let key = Self::make_key(name, record_type);
        self.write_items().remove(&key).is_some()
    }

    pub(crate) fn remove_matching_names(&self, mut matches: impl FnMut(&str) -> bool) -> usize {
        let mut items = self.write_items();
        let previous_len = items.len();
        items.retain(|key, _| !matches(key.name.as_str()));
        previous_len - items.len()
    }

    pub fn clear(&self) {
        self.write_items().clear();
    }

    fn with_min_ttl(min_ttl: Duration) -> Self {
        Self {
            items: RwLock::new(HashMap::new()),
            min_ttl,
        }
    }

    fn query_without_cleanup(
        &self,
        key: &NameInfoCacheKey,
        now: Instant,
    ) -> Option<NameInfoCacheQueryResult> {
        let items = self.read_items();
        let entry = items.get(key)?;
        if entry.expires_at <= now {
            return None;
        }

        match &entry.value {
            NameInfoCacheValue::Hit(name_info) => {
                Some(NameInfoCacheQueryResult::Hit(name_info.clone()))
            }
            NameInfoCacheValue::Tombstone => Some(NameInfoCacheQueryResult::Tombstone),
        }
    }

    fn remove_if_expired(&self, key: &NameInfoCacheKey, now: Instant) {
        let mut items = self.write_items();
        let should_remove = items
            .get(key)
            .map(|entry| entry.expires_at <= now)
            .unwrap_or(false);
        if should_remove {
            items.remove(key);
        }
    }

    fn insert(
        &self,
        name: &str,
        record_type: RecordType,
        value: NameInfoCacheValue,
        cache_ttl_secs: Option<u32>,
    ) {
        let cache_ttl = self.effective_ttl(cache_ttl_secs);
        let entry = NameInfoCacheEntry {
            value,
            expires_at: Instant::now() + cache_ttl,
        };

        self.write_items()
            .insert(Self::make_key(name, record_type), entry);
    }

    fn effective_ttl(&self, cache_ttl_secs: Option<u32>) -> Duration {
        let requested = cache_ttl_secs.unwrap_or(DEFAULT_NAME_INFO_CACHE_TTL_SECS);
        let requested = Duration::from_secs(requested as u64);
        requested.max(self.min_ttl)
    }

    fn make_key(name: &str, record_type: RecordType) -> NameInfoCacheKey {
        NameInfoCacheKey {
            name: Self::normalize_name(name),
            record_type: record_type.to_string(),
        }
    }

    fn normalize_name(name: &str) -> String {
        name.trim().trim_end_matches('.').to_lowercase()
    }

    fn read_items(&self) -> RwLockReadGuard<'_, HashMap<NameInfoCacheKey, NameInfoCacheEntry>> {
        match self.items.read() {
            Ok(items) => items,
            Err(err) => err.into_inner(),
        }
    }

    fn write_items(&self) -> RwLockWriteGuard<'_, HashMap<NameInfoCacheKey, NameInfoCacheEntry>> {
        match self.items.write() {
            Ok(items) => items,
            Err(err) => err.into_inner(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::thread::sleep;

    #[test]
    fn query_returns_cached_name_info_before_expiration() {
        let cache = NameInfoCache::with_min_ttl(Duration::from_millis(1));
        let name_info =
            NameInfo::from_address("Example.COM.", IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));

        cache.add("Example.COM.", RecordType::A, name_info, Some(60));

        match cache.query("example.com", RecordType::A) {
            Some(NameInfoCacheQueryResult::Hit(name_info)) => {
                assert_eq!(
                    name_info.address,
                    vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))]
                );
            }
            other => panic!("unexpected cache result: {:?}", other),
        }
    }

    #[test]
    fn query_treats_expired_entry_as_miss() {
        let cache = NameInfoCache::with_min_ttl(Duration::from_millis(1));
        let name_info =
            NameInfo::from_address("example.com", IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));

        cache.add("example.com", RecordType::A, name_info, Some(0));
        sleep(Duration::from_millis(5));

        assert!(cache.query("example.com", RecordType::A).is_none());
    }

    #[test]
    fn tombstone_is_distinct_from_miss() {
        let cache = NameInfoCache::with_min_ttl(Duration::from_millis(1));

        cache.add_tombstone("missing.example.com", RecordType::TXT, Some(60));

        assert!(matches!(
            cache.query("missing.example.com.", RecordType::TXT),
            Some(NameInfoCacheQueryResult::Tombstone)
        ));
        assert!(cache.query("other.example.com", RecordType::TXT).is_none());
    }

    #[test]
    fn effective_ttl_defaults_and_clamps_to_minimum() {
        let cache = NameInfoCache::new();

        assert_eq!(
            cache.effective_ttl(None),
            Duration::from_secs(DEFAULT_NAME_INFO_CACHE_TTL_SECS as u64)
        );
        assert_eq!(
            cache.effective_ttl(Some(1)),
            Duration::from_secs(MIN_NAME_INFO_CACHE_TTL_SECS as u64)
        );
        assert_eq!(cache.effective_ttl(Some(120)), Duration::from_secs(120));
    }

    #[test]
    fn remove_matching_names_removes_all_record_types_and_subdomains() {
        let cache = NameInfoCache::new();
        let info = NameInfo::from_address(
            "alice.web3.example.com",
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        );
        cache.add(
            "alice.web3.example.com",
            RecordType::A,
            info.clone(),
            Some(600),
        );
        cache.add(
            "home.alice.web3.example.com",
            RecordType::TXT,
            info.clone(),
            Some(600),
        );
        cache.add("bob.web3.example.com", RecordType::A, info, Some(600));

        let removed = cache.remove_matching_names(|name| {
            name == "alice.web3.example.com" || name.ends_with(".alice.web3.example.com")
        });

        assert_eq!(removed, 2);
        assert!(cache
            .query("alice.web3.example.com", RecordType::A)
            .is_none());
        assert!(cache
            .query("home.alice.web3.example.com", RecordType::TXT)
            .is_none());
        assert!(cache.query("bob.web3.example.com", RecordType::A).is_some());
    }
}
