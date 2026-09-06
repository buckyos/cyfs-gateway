use super::*;
use crate::{ProcessChainHttpServer, ServerManager, TunnelManager};
use http_body_util::{Full, StreamBody};
use hyper::body::{Bytes, Frame};
use std::sync::atomic::{AtomicUsize, Ordering};
use tempfile::TempDir;

fn config(dir: &TempDir) -> NamedInboxCacheServerConfig {
    serde_json::from_value(serde_json::json!({
        "id": "alice-inbox", "type": "named-inbox-cache", "target_zone": "alice.example",
        "accepted_paths": ["/inbox", "/second"], "cache_path": dir.path().join("cache"),
        "retry_backoff": ["10ms", "20ms"], "poll_interval": "10ms", "upstream_timeout": "80ms",
        "max_entries": 2, "max_bytes": 100, "max_object_bytes": 50
    }))
    .unwrap()
}

fn request(body: &'static [u8], path: &str, principal: Option<&str>) -> Request<DispatchBody> {
    let mut request = Request::builder()
        .method("PUT")
        .uri(path)
        .header("host", "alice.example")
        .header("content-type", CYFS_CONTENT_TYPE_NAMED_OBJECT_JSON)
        .header("cyfs-original-user", "did:bns:forged")
        .body(
            Full::new(Bytes::from_static(body))
                .map_err(|e| match e {})
                .boxed(),
        )
        .unwrap();
    if let Some(principal) = principal {
        request.extensions_mut().insert(VerifiedDispatchContext {
            principal: principal.into(),
            target: normalize_cyfs_dispatch_target("alice.example", path).unwrap(),
            credentials: vec![("cyfs-proofs".into(), "original-proof".into())],
            received_at_ms: now_ms(),
            ingress: "test-auth".into(),
        });
    }
    request
}

async fn call(
    server: &NamedInboxCacheServer,
    body: &'static [u8],
    path: &str,
) -> Response<DispatchBody> {
    server
        .serve_request(
            request(body, path, Some("did:bns:bob")),
            StreamInfo::default(),
        )
        .await
        .unwrap()
}

fn assert_status(response: &Response<DispatchBody>, status: u16, dispatch: &str) {
    assert_eq!(response.status().as_u16(), status);
    assert_eq!(
        response.headers().get(CYFS_HEADER_DISPATCH_STATUS).unwrap(),
        dispatch
    );
    assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
}

struct Upstream {
    url: String,
    mode: Arc<AtomicUsize>,
    calls: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl Drop for Upstream {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Upstream {
    async fn new(mode: usize) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let mode = Arc::new(AtomicUsize::new(mode));
        let calls = Arc::new(AtomicUsize::new(0));
        let task_mode = mode.clone();
        let task_calls = calls.clone();
        let task = tokio::spawn(async move {
            loop {
                let (socket, _) = listener.accept().await.unwrap();
                let mode = task_mode.clone();
                let calls = task_calls.clone();
                tokio::spawn(async move {
                    let service =
                        hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
                            let mode = mode.clone();
                            let calls = calls.clone();
                            async move {
                                calls.fetch_add(1, Ordering::SeqCst);
                                assert_eq!(req.headers()["host"], "alice.example");
                                assert_eq!(req.headers()["cyfs-original-user"], "did:bns:bob");
                                assert_eq!(req.headers()["cyfs-proofs"], "original-proof");
                                let path = req.uri().path().to_string();
                                let claimed = req.headers()[CYFS_HEADER_OBJ_ID]
                                    .to_str()
                                    .unwrap()
                                    .to_string();
                                let body = req.into_body().collect().await.unwrap().to_bytes();
                                let id =
                                    validate_cyfs_dispatch_object(&body, Some(&claimed)).unwrap();
                                let target =
                                    normalize_cyfs_dispatch_target("alice.example", &path).unwrap();
                                let mode = mode.load(Ordering::SeqCst);
                                if mode == 5 {
                                    tokio::time::sleep(Duration::from_millis(300)).await;
                                }
                                let status = match mode {
                                    1 | 2 => CyfsDispatchStatus::Rejected,
                                    6 => CyfsDispatchStatus::Cached,
                                    _ => CyfsDispatchStatus::Accepted,
                                };
                                let result = if status == CyfsDispatchStatus::Rejected {
                                    CyfsDispatchResult::rejected(
                                        Some(id),
                                        target,
                                        "acl-denied",
                                        mode == 1,
                                    )
                                } else {
                                    CyfsDispatchResult::new(Some(id), target, status)
                                };
                                let http = match mode {
                                    1 => StatusCode::SERVICE_UNAVAILABLE,
                                    2 => StatusCode::FORBIDDEN,
                                    4 => StatusCode::INTERNAL_SERVER_ERROR,
                                    6 => StatusCode::ACCEPTED,
                                    _ => StatusCode::OK,
                                };
                                let mut response = dispatch_response(http, &result);
                                if mode == 3 || mode == 4 {
                                    response.headers_mut().remove(CYFS_HEADER_DISPATCH_STATUS);
                                }
                                Ok::<_, std::convert::Infallible>(response)
                            }
                        });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(hyper_util::rt::TokioIo::new(socket), service)
                        .await;
                });
            }
        });
        Self {
            url,
            mode,
            calls,
            task,
        }
    }
}

#[tokio::test]
async fn named_inbox_pure_cache_atomic_quotas_identity_and_recovery() {
    let dir = TempDir::new().unwrap();
    let config = config(&dir);
    let server = NamedInboxCacheServer::new(config.clone()).await.unwrap();
    let results =
        futures_util::future::join_all((0..20).map(|_| call(&server, b"{}", "/inbox"))).await;
    for response in results {
        assert_status(&response, 202, "cached");
    }
    assert_status(&call(&server, b"{}", "/second").await, 202, "cached");
    assert_status(
        &call(&server, br#"{"n":1}"#, "/inbox").await,
        503,
        "rejected",
    );
    assert_eq!(server.inner.store.state.lock().await.entries.len(), 2);
    assert_eq!(server.inner.store.state.lock().await.bytes, 4);
    drop(server);
    let server = NamedInboxCacheServer::new(config).await.unwrap();
    assert_eq!(server.inner.store.state.lock().await.entries.len(), 2);
    assert_status(&call(&server, b"{}", "/inbox").await, 202, "cached");
    assert!(server.worker.is_none());
}

#[tokio::test]
async fn named_inbox_principal_quota_and_concurrent_distinct_writes() {
    let dir = TempDir::new().unwrap();
    let mut config = config(&dir);
    config.max_entries = 10;
    config.per_principal_quota = Some(NamedInboxPrincipalQuota {
        max_entries: 1,
        max_bytes: 50,
    });
    let server = NamedInboxCacheServer::new(config).await.unwrap();
    let (a, b) = tokio::join!(
        call(&server, b"{}", "/inbox"),
        call(&server, b"{}", "/second")
    );
    let mut codes = [a.status().as_u16(), b.status().as_u16()];
    codes.sort();
    assert_eq!(codes, [202, 503]);
    let resp = server
        .inner
        .handle(request(br#"{"n":1}"#, "/inbox", Some("did:bns:carol")))
        .await;
    assert_status(&resp, 202, "cached");
    assert_eq!(server.inner.store.state.lock().await.entries.len(), 2);
}

#[tokio::test]
async fn named_inbox_validates_before_upstream_or_storage() {
    let upstream = Upstream::new(0).await;
    let dir = TempDir::new().unwrap();
    let mut config = config(&dir);
    config.upstream = Some(upstream.url.clone());
    let server = NamedInboxCacheServer::new(config).await.unwrap();
    assert_status(
        &server.inner.handle(request(b"{}", "/inbox", None)).await,
        401,
        "rejected",
    );
    assert_status(&call(&server, b"{}", "/other").await, 404, "rejected");
    assert_status(
        &call(&server, br#"{ "n":1}"#, "/inbox").await,
        400,
        "rejected",
    );
    let mut req = request(b"{}", "/inbox", Some("did:bns:bob"));
    *req.uri_mut() = "/inbox/@/field".parse().unwrap();
    assert_status(&server.inner.handle(req).await, 400, "rejected");
    let mut req = request(b"{}", "/inbox", Some("did:bns:bob"));
    *req.body_mut() = BodyExt::boxed(StreamBody::new(stream::iter(vec![
        Ok::<_, crate::ServerError>(Frame::data(Bytes::from(vec![b' '; 30]))),
        Ok(Frame::data(Bytes::from(vec![b' '; 30]))),
    ])));
    assert_status(&server.inner.handle(req).await, 413, "rejected");
    assert_eq!(upstream.calls.load(Ordering::SeqCst), 0);
    assert!(!server.inner.config.cache_path.exists());
}

#[tokio::test]
async fn named_inbox_upstream_first_even_when_full_or_storage_broken() {
    let upstream = Upstream::new(0).await;
    let dir = TempDir::new().unwrap();
    let mut config = config(&dir);
    config.upstream = Some(upstream.url.clone());
    config.drain_enabled = Some(false);
    std::fs::write(&config.cache_path, b"not a directory").unwrap();
    let server = NamedInboxCacheServer::new(config).await.unwrap();
    assert_status(&call(&server, b"{}", "/inbox").await, 200, "accepted");
    assert_eq!(
        std::fs::read(&server.inner.config.cache_path).unwrap(),
        b"not a directory"
    );
    assert_eq!(server.inner.store.state.lock().await.entries.len(), 0);
    assert_eq!(upstream.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn named_inbox_business_rejections_and_invalid_http_never_fallback() {
    let upstream = Upstream::new(1).await;
    let dir = TempDir::new().unwrap();
    let mut config = config(&dir);
    config.upstream = Some(upstream.url.clone());
    config.drain_enabled = Some(false);
    let server = NamedInboxCacheServer::new(config).await.unwrap();
    assert_status(&call(&server, b"{}", "/inbox").await, 503, "rejected");
    upstream.mode.store(2, Ordering::SeqCst);
    assert_status(&call(&server, b"{}", "/inbox").await, 403, "rejected");
    for mode in [3, 4, 6] {
        upstream.mode.store(mode, Ordering::SeqCst);
        let response = call(&server, b"{}", "/inbox").await;
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert!(!response.headers().contains_key(CYFS_HEADER_DISPATCH_STATUS));
    }
    assert!(!server.inner.config.cache_path.exists());
}

#[tokio::test]
async fn named_inbox_fallback_write_failure_preserves_unknown_outcome() {
    let upstream = Upstream::new(5).await;
    let dir = TempDir::new().unwrap();
    let mut config = config(&dir);
    config.upstream = Some(upstream.url.clone());
    config.drain_enabled = Some(false);
    std::fs::write(&config.cache_path, b"not a directory").unwrap();
    let server = NamedInboxCacheServer::new(config.clone()).await.unwrap();
    let response = call(&server, b"{}", "/inbox").await;
    assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
    assert_eq!(
        response.headers()[CYFS_HEADER_DISPATCH_ERROR],
        CYFS_DISPATCH_ERROR_OUTCOME_UNKNOWN
    );
    assert!(!response.headers().contains_key(CYFS_HEADER_DISPATCH_STATUS));
    drop(server);
    config.upstream = None;
    let server = NamedInboxCacheServer::new(config).await.unwrap();
    assert_status(&call(&server, b"{}", "/inbox").await, 503, "rejected");
}

#[tokio::test]
async fn named_inbox_offline_and_recovery_drains_without_inbound_traffic() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let unavailable = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    let dir = TempDir::new().unwrap();
    let mut config = config(&dir);
    config.upstream = Some(unavailable);
    config.drain_enabled = Some(false);
    let server = NamedInboxCacheServer::new(config.clone()).await.unwrap();
    assert_status(&call(&server, b"{}", "/inbox").await, 202, "cached");
    drop(server);
    let upstream = Upstream::new(0).await;
    config.upstream = Some(upstream.url.clone());
    config.drain_enabled = None;
    let server = NamedInboxCacheServer::new(config).await.unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if server.inner.store.state.lock().await.entries.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(upstream.calls.load(Ordering::SeqCst), 1);
    assert_status(&call(&server, b"{}", "/inbox").await, 200, "accepted");
    assert_eq!(upstream.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn named_inbox_worker_retains_cached_and_retryable_but_cleans_permanent_rejection() {
    let upstream = Upstream::new(5).await;
    let dir = TempDir::new().unwrap();
    let mut config = config(&dir);
    config.upstream = Some(upstream.url.clone());
    config.drain_enabled = Some(false);
    let server = NamedInboxCacheServer::new(config).await.unwrap();
    assert_status(&call(&server, b"{}", "/inbox").await, 202, "cached");
    for mode in [6, 1, 3] {
        upstream.mode.store(mode, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(25)).await;
        server.inner.drain().await;
        assert_eq!(server.inner.store.state.lock().await.entries.len(), 1);
    }
    upstream.mode.store(2, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(25)).await;
    server.inner.drain().await;
    assert!(server.inner.store.state.lock().await.entries.is_empty());
}

#[tokio::test]
async fn named_inbox_expiry_and_missing_records_do_not_count_as_cached() {
    let dir = TempDir::new().unwrap();
    let mut config = config(&dir);
    config.cache_ttl = Some("10ms".into());
    let server = NamedInboxCacheServer::new(config.clone()).await.unwrap();
    assert_status(&call(&server, b"{}", "/inbox").await, 202, "cached");
    tokio::time::sleep(Duration::from_millis(15)).await;
    drop(server);
    let server = NamedInboxCacheServer::new(config).await.unwrap();
    assert!(server.inner.store.state.lock().await.entries.is_empty());
    assert_status(&call(&server, b"{}", "/inbox").await, 202, "cached");
    let key = server
        .inner
        .store
        .state
        .lock()
        .await
        .entries
        .keys()
        .next()
        .unwrap()
        .clone();
    tokio::fs::remove_file(server.inner.path(&key))
        .await
        .unwrap();
    assert_status(&call(&server, b"{}", "/inbox").await, 202, "cached");
    assert!(
        server
            .inner
            .read_entry(&server.inner.path(&key))
            .await
            .is_ok()
    );
}

async fn gateway(
    chain: &str,
    server: Arc<NamedInboxCacheServer>,
) -> (ProcessChainHttpServer, Arc<ServerManager>) {
    let manager = Arc::new(ServerManager::new());
    manager.add_server(Server::Http(server)).unwrap();
    let chains = serde_json::from_value(serde_json::json!([{
        "id":"main", "priority":1, "blocks":[{"id":"main", "priority":1,"block":chain}]
    }]))
    .unwrap();
    let http = ProcessChainHttpServer::builder()
        .id("zone-http")
        .version("HTTP/1.1")
        .hook_point(chains)
        .tunnel_manager(TunnelManager::new())
        .server_mgr(Arc::downgrade(&manager))
        .build()
        .await
        .unwrap();
    (http, manager)
}

#[tokio::test]
async fn named_inbox_call_server_trust_and_dispatch_control_mapping() {
    let dir = TempDir::new().unwrap();
    let server = Arc::new(NamedInboxCacheServer::new(config(&dir)).await.unwrap());
    for (chain, code, status) in [
        ("call-server alice-inbox;", 401, "rejected"),
        ("reject;", 403, "rejected"),
        ("drop;", 403, "rejected"),
        ("error 404 no-handler;", 404, "rejected"),
        (
            "export AUTH_principal=did:bns:bob; call-server alice-inbox;",
            202,
            "cached",
        ),
    ] {
        let (http, _manager) = gateway(chain, server.clone()).await;
        let mut req = request(b"{}", "/inbox", None);
        req.headers_mut()
            .insert("AUTH_principal", "did:bns:forged".parse().unwrap());
        req.headers_mut()
            .insert("cyfs-proofs", "original-proof".parse().unwrap());
        let response = http
            .serve_request(req, StreamInfo::default())
            .await
            .unwrap();
        assert_status(&response, code, status);
    }
    let state = server.inner.store.state.lock().await;
    let entry = state.entries.values().next().unwrap();
    assert_eq!(entry.context.principal, "did:bns:bob");
    assert_eq!(
        entry.context.credentials,
        [("cyfs-proofs".into(), "original-proof".into())]
    );
}

#[tokio::test]
async fn named_inbox_reload_shares_atomic_capacity_and_stops_worker() {
    let dir = TempDir::new().unwrap();
    let config = config(&dir);
    let first = NamedInboxCacheServer::new(config.clone()).await.unwrap();
    assert_status(&call(&first, b"{}", "/inbox").await, 202, "cached");
    let second = NamedInboxCacheServer::new(config.clone()).await.unwrap();
    assert!(Arc::ptr_eq(&first.inner.store, &second.inner.store));
    let upstream = Upstream::new(1).await;
    let mut config = config;
    config.upstream = Some(upstream.url.clone());
    let worker = NamedInboxCacheServer::new(config).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    drop(worker);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let count = upstream.calls.load(Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(60)).await;
    assert_eq!(upstream.calls.load(Ordering::SeqCst), count);
}

#[tokio::test]
async fn named_inbox_full_cache_still_allows_synchronous_acceptance() {
    let dir = TempDir::new().unwrap();
    let mut cfg = config(&dir);
    cfg.max_entries = 1;
    let pure = NamedInboxCacheServer::new(cfg.clone()).await.unwrap();
    assert_status(&call(&pure, b"{}", "/inbox").await, 202, "cached");
    let upstream = Upstream::new(0).await;
    cfg.upstream = Some(upstream.url.clone());
    cfg.drain_enabled = Some(false);
    let server = NamedInboxCacheServer::new(cfg).await.unwrap();
    assert_status(
        &call(&server, br#"{"n":1}"#, "/second").await,
        200,
        "accepted",
    );
    assert_eq!(server.inner.store.state.lock().await.entries.len(), 1);
}

#[tokio::test]
async fn named_inbox_direct_forward_does_not_use_cache() {
    let upstream = Upstream::new(0).await;
    let dir = TempDir::new().unwrap();
    let cfg = config(&dir);
    let cache_path = cfg.cache_path.clone();
    let server = Arc::new(NamedInboxCacheServer::new(cfg).await.unwrap());
    let (http, _manager) = gateway(&format!("forward {};", upstream.url), server).await;
    let mut req = request(b"{}", "/inbox", None);
    req.headers_mut()
        .insert("cyfs-original-user", "did:bns:bob".parse().unwrap());
    req.headers_mut()
        .insert("cyfs-proofs", "original-proof".parse().unwrap());
    req.headers_mut().insert(
        CYFS_HEADER_OBJ_ID,
        validate_cyfs_dispatch_object(b"{}", None)
            .unwrap()
            .to_string()
            .parse()
            .unwrap(),
    );
    assert_status(
        &http
            .serve_request(req, StreamInfo::default())
            .await
            .unwrap(),
        200,
        "accepted",
    );
    assert!(!cache_path.exists());
}

#[tokio::test]
async fn named_inbox_auth_context_does_not_leak_between_requests() {
    let dir = TempDir::new().unwrap();
    let server = Arc::new(NamedInboxCacheServer::new(config(&dir)).await.unwrap());
    let (http, _manager) = gateway("if $REQ.x-test-auth == verified then\n export AUTH_principal=did:bns:bob;\nend\ncall-server alice-inbox;", server).await;
    let mut verified = request(b"{}", "/inbox", None);
    verified
        .headers_mut()
        .insert("x-test-auth", "verified".parse().unwrap());
    assert_status(
        &http
            .serve_request(verified, StreamInfo::default())
            .await
            .unwrap(),
        202,
        "cached",
    );
    assert_status(
        &http
            .serve_request(request(b"{}", "/inbox", None), StreamInfo::default())
            .await
            .unwrap(),
        401,
        "rejected",
    );
}

#[tokio::test]
async fn named_inbox_retries_refresh_credentials_without_double_charging() {
    let dir = TempDir::new().unwrap();
    let server = NamedInboxCacheServer::new(config(&dir)).await.unwrap();
    assert_status(&call(&server, b"{}", "/inbox").await, 202, "cached");
    let mut retry = request(b"{}", "/inbox", Some("did:bns:bob"));
    retry
        .extensions_mut()
        .get_mut::<VerifiedDispatchContext>()
        .unwrap()
        .credentials = vec![("authorization".into(), "Bearer refreshed".into())];
    assert_status(&server.inner.handle(retry).await, 202, "cached");
    let state = server.inner.store.state.lock().await;
    assert_eq!(state.entries.len(), 1);
    assert_eq!(state.bytes, 2);
    let entry = state.entries.values().next().unwrap();
    assert_eq!(
        server
            .inner
            .read_entry(&server.inner.path(&entry.key()))
            .await
            .unwrap()
            .context
            .credentials[0]
            .1,
        "Bearer refreshed"
    );
}

#[tokio::test]
async fn named_inbox_cancelled_client_does_not_leave_unaccounted_writes() {
    let dir = TempDir::new().unwrap();
    let mut cfg = config(&dir);
    cfg.max_entries = 1;
    let server = NamedInboxCacheServer::new(cfg).await.unwrap();
    let guard = server.inner.store.state.lock().await;
    let inner = server.inner.clone();
    let request = tokio::spawn(async move {
        inner
            .handle(request(b"{}", "/inbox", Some("did:bns:bob")))
            .await
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        while Arc::strong_count(&server.inner) < 3 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    request.abort();
    let _ = request.await;
    drop(guard);
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if server.inner.store.state.lock().await.entries.len() == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_status(&call(&server, b"{}", "/second").await, 503, "rejected");
}
