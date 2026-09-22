use super::*;
use crate::{UserDnsChange, UserDnsChangeOperation};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

#[derive(Default)]
struct ChangeFeed {
    calls: AtomicUsize,
    revision: AtomicU64,
    earliest: AtomicU64,
    fail: AtomicBool,
    hang: AtomicBool,
    fail_on_call: AtomicUsize,
}

#[async_trait]
impl SnAuthReader for ChangeFeed {
    async fn get_user_info(&self, _: &str) -> SnResolverResult<Option<SNUserInfo>> { Ok(None) }
    async fn get_user_by_domain(&self, _: &str) -> SnResolverResult<Option<SNUserInfo>> { Ok(None) }
    async fn get_zone_info(&self, _: &str) -> SnResolverResult<Option<ZoneInfo>> { Ok(None) }

    async fn list_user_dns_changes(&self, after: u64, limit: usize) -> SnResolverResult<UserDnsChangePage> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        tokio::task::yield_now().await;
        if self.hang.load(Ordering::SeqCst) {
            std::future::pending::<()>().await;
        }
        if self.fail.load(Ordering::SeqCst) || self.fail_on_call.load(Ordering::SeqCst) == call {
            return Err(SnResolverError::backend("injected auth_db failure"));
        }
        let current = self.revision.load(Ordering::SeqCst);
        Ok(UserDnsChangePage {
            changes: ((after + 1)..=current.min(after + limit as u64)).map(|revision| UserDnsChange {
                revision,
                name: "alice.example".into(),
                record_type: Some(UserDnsRecordType::A),
                operation: UserDnsChangeOperation::UpsertRrset,
            }).collect(),
            current_revision: current,
            earliest_available_revision: self.earliest.load(Ordering::SeqCst).max(1),
        })
    }
}

fn resolver() -> (Arc<SnResolver>, Arc<ChangeFeed>) {
    let feed = Arc::new(ChangeFeed::default());
    let config = SnResolverConfig::new("example", None, None, None, vec![]);
    (Arc::new(SnResolver::new(config, feed.clone())), feed)
}

fn cache_name(resolver: &SnResolver, name: &str) {
    resolver.cache.insert_authoritative_dns(name, "A", SnAuthoritativeDnsResult::NotManaged, 60);
}

#[tokio::test(start_paused = true)]
async fn hot_cached_queries_and_concurrent_queries_share_one_poll_per_interval() {
    let (resolver, feed) = resolver();
    cache_name(&resolver, "alice.example");
    for _ in 0..1000 {
        assert!(matches!(resolver.resolve_authoritative_dns_cached("alice.example", "A").await.unwrap(),
            SnAuthoritativeDnsResult::NotManaged));
    }
    assert_eq!(feed.calls.load(Ordering::SeqCst), 1);
    tokio::time::advance(USER_DNS_SYNC_INTERVAL).await;
    let mut tasks = Vec::new();
    for _ in 0..64 {
        let resolver = resolver.clone();
        tasks.push(tokio::spawn(async move { resolver.poll_user_dns_changes().await }));
    }
    for task in tasks { assert_eq!(task.await.unwrap().unwrap(), 0); }
    assert_eq!(feed.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test(start_paused = true)]
async fn remote_changes_invalidate_cache_at_next_poll_and_writes_force_refresh() {
    let (resolver, feed) = resolver();
    assert_eq!(resolver.poll_user_dns_changes().await.unwrap(), 0);
    cache_name(&resolver, "alice.example");
    cache_name(&resolver, "bob.example");
    feed.revision.store(1, Ordering::SeqCst);
    assert_eq!(resolver.poll_user_dns_changes().await.unwrap(), 0);
    assert!(resolver.cache.query_authoritative_dns("alice.example", "A").is_some());
    tokio::time::advance(USER_DNS_SYNC_INTERVAL).await;
    assert_eq!(resolver.poll_user_dns_changes().await.unwrap(), 1);
    assert!(resolver.cache.query_authoritative_dns("alice.example", "A").is_none());
    assert!(resolver.cache.query_authoritative_dns("bob.example", "A").is_some());
    cache_name(&resolver, "alice.example");
    feed.revision.store(2, Ordering::SeqCst);
    assert_eq!(resolver.synchronize_user_dns_changes().await.unwrap(), 2);
    assert!(resolver.cache.query_authoritative_dns("alice.example", "A").is_none());
    assert_eq!(feed.calls.load(Ordering::SeqCst), 3);
}

#[tokio::test(start_paused = true)]
async fn failure_backoff_is_shared_bounded_and_resets_after_recovery() {
    let (resolver, feed) = resolver();
    feed.fail.store(true, Ordering::SeqCst);
    for (attempt, delay) in [1, 2, 4, 8, 16, 30, 30].into_iter().enumerate() {
        assert!(resolver.poll_user_dns_changes().await.is_err());
        for _ in 0..100 {
            assert!(resolver.poll_user_dns_changes().await.is_err());
            assert!(resolver.synchronize_user_dns_changes().await.is_err());
        }
        assert_eq!(feed.calls.load(Ordering::SeqCst), attempt + 1);
        tokio::time::advance(Duration::from_secs(delay) - Duration::from_millis(1)).await;
        assert!(resolver.poll_user_dns_changes().await.is_err());
        assert_eq!(feed.calls.load(Ordering::SeqCst), attempt + 1);
        tokio::time::advance(Duration::from_millis(1)).await;
    }
    feed.fail.store(false, Ordering::SeqCst);
    assert_eq!(resolver.poll_user_dns_changes().await.unwrap(), 0);
    assert_eq!(resolver.user_dns_sync.lock().await.failures, 0);
    tokio::time::advance(USER_DNS_SYNC_INTERVAL).await;
    assert_eq!(resolver.poll_user_dns_changes().await.unwrap(), 0);
    assert_eq!(feed.calls.load(Ordering::SeqCst), 9);
}

#[tokio::test(start_paused = true)]
async fn timeout_and_cancellation_do_not_report_success_or_retry_immediately() {
    let (resolver, feed) = resolver();
    feed.hang.store(true, Ordering::SeqCst);
    let error = resolver.poll_user_dns_changes().await.unwrap_err();
    assert!(error.message().contains("timed out"));
    assert!(resolver.poll_user_dns_changes().await.is_err());
    assert_eq!(feed.calls.load(Ordering::SeqCst), 1);
    tokio::time::advance(USER_DNS_SYNC_INTERVAL).await;
    let other = resolver.clone();
    let task = tokio::spawn(async move { other.poll_user_dns_changes().await });
    while feed.calls.load(Ordering::SeqCst) < 2 { tokio::task::yield_now().await; }
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(resolver.poll_user_dns_changes().await.unwrap_err().message().contains("interrupted"));
    assert_eq!(feed.calls.load(Ordering::SeqCst), 2);
    feed.hang.store(false, Ordering::SeqCst);
    tokio::time::advance(USER_DNS_SYNC_TIMEOUT + USER_DNS_SYNC_INTERVAL).await;
    assert_eq!(resolver.poll_user_dns_changes().await.unwrap(), 0);
}

#[tokio::test(start_paused = true)]
async fn pagination_resumes_after_partial_failure_and_revision_gap_clears_cache() {
    let (resolver, feed) = resolver();
    feed.revision.store(300, Ordering::SeqCst);
    feed.fail_on_call.store(2, Ordering::SeqCst);
    cache_name(&resolver, "alice.example");
    assert!(resolver.poll_user_dns_changes().await.is_err());
    assert_eq!(resolver.user_dns_sync.lock().await.revision, 256);
    assert!(resolver.cache.query_authoritative_dns("alice.example", "A").is_none());
    tokio::time::advance(USER_DNS_SYNC_INTERVAL).await;
    assert_eq!(resolver.poll_user_dns_changes().await.unwrap(), 300);
    assert_eq!(feed.calls.load(Ordering::SeqCst), 3);
    cache_name(&resolver, "bob.example");
    feed.earliest.store(400, Ordering::SeqCst);
    feed.revision.store(500, Ordering::SeqCst);
    assert_eq!(resolver.synchronize_user_dns_changes().await.unwrap(), 500);
    assert!(resolver.cache.query_authoritative_dns("bob.example", "A").is_none());
}
