use crate::DatagramClientBox;
use crate::ip::{IPTunnelBuilder, ProxyTcpTunnelBuilder};
use crate::quic_tunnel::QuicTunnelBuilder;
use crate::socks::SocksTunnelBuilder;
use crate::tls_tunnel::TlsTunnelBuilder;
use crate::tunnel_url_status::{
    TunnelProbeOptions, TunnelProbeResult, TunnelStatusStoreConfig, TunnelUrlHistory,
    TunnelUrlState, TunnelUrlStatus, TunnelUrlStatusSource, mask_tunnel_url, normalize_tunnel_url,
    protocol_category_for_scheme, reachable_status, sort_urls, unknown_status, unreachable_status,
    unsupported_status,
};
use crate::{TunnelBox, TunnelBuilder, TunnelError, TunnelResult};
use buckyos_kit::{AsyncStream, buckyos_get_unix_timestamp};
use futures::FutureExt;
use futures::future::BoxFuture;
use log::*;
use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};
use tokio::sync::{Mutex as AsyncMutex, RwLock, Semaphore};
use url::Url;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtocolCategory {
    Stream,
    Datagram,
    //Named Object
}

pub fn get_protocol_category(str_protocol: &str) -> TunnelResult<ProtocolCategory> {
    //lowercase
    let str_protocol = str_protocol.to_lowercase();
    match str_protocol.as_str() {
        "tcp" => Ok(ProtocolCategory::Stream),
        "ptcp" => Ok(ProtocolCategory::Stream),
        "rtcp" => Ok(ProtocolCategory::Stream),
        "udp" => Ok(ProtocolCategory::Datagram),
        "rudp" => Ok(ProtocolCategory::Datagram),
        "socks" => Ok(ProtocolCategory::Stream),
        "tls" => Ok(ProtocolCategory::Stream),
        "quic" => Ok(ProtocolCategory::Stream),
        _ => {
            let msg = format!("Unknown protocol: {}", str_protocol);
            error!("{}", msg);
            Err(TunnelError::UnknownProtocol(msg))
        }
    }
}

// `Shared` allows multiple awaiters of the same probe future. The single
// task that polls it first does the network work and holds the semaphore
// permit; subsequent awaiters just receive the cloned `TunnelUrlStatus`.
type SharedProbeFuture =
    futures::future::Shared<BoxFuture<'static, TunnelUrlStatus>>;

#[derive(Clone)]
pub struct TunnelManager {
    inner: Arc<TunnelManagerInner>,
}

struct TunnelManagerInner {
    tunnel_builder_manager: StdMutex<HashMap<String, Arc<dyn TunnelBuilder>>>,
    tunnel_history: RwLock<HashMap<String, TunnelUrlHistory>>,
    in_flight_probes: AsyncMutex<HashMap<String, SharedProbeFuture>>,
    probe_limiter: Arc<Semaphore>,
    config: StdMutex<TunnelStatusStoreConfig>,
}

impl Default for TunnelManager {
    fn default() -> Self {
        Self::new()
    }
}

impl TunnelManager {
    pub fn new() -> Self {
        Self::with_config(TunnelStatusStoreConfig::default())
    }

    pub fn with_config(config: TunnelStatusStoreConfig) -> Self {
        let limiter = Arc::new(Semaphore::new(config.probe_concurrency.max(1)));
        let inner = TunnelManagerInner {
            tunnel_builder_manager: StdMutex::new(HashMap::new()),
            tunnel_history: RwLock::new(HashMap::new()),
            in_flight_probes: AsyncMutex::new(HashMap::new()),
            probe_limiter: limiter,
            config: StdMutex::new(config),
        };
        let this = Self {
            inner: Arc::new(inner),
        };
        this.register_tunnel_builder("tcp", Arc::new(IPTunnelBuilder::new()));
        this.register_tunnel_builder("ptcp", Arc::new(ProxyTcpTunnelBuilder::new()));
        this.register_tunnel_builder("udp", Arc::new(IPTunnelBuilder::new()));
        this.register_tunnel_builder("quic", Arc::new(QuicTunnelBuilder::new()));
        this.register_tunnel_builder("tls", Arc::new(TlsTunnelBuilder::new()));
        this.register_tunnel_builder("socks", Arc::new(SocksTunnelBuilder::new()));
        this
    }

    pub fn register_tunnel_builder(&self, protocol: &str, builder: Arc<dyn TunnelBuilder>) {
        self.inner
            .tunnel_builder_manager
            .lock()
            .unwrap()
            .insert(protocol.to_string(), builder);
    }

    pub fn remove_tunnel_builder(&self, protocol: &str) {
        self.inner
            .tunnel_builder_manager
            .lock()
            .unwrap()
            .remove(protocol);
    }

    pub fn config(&self) -> TunnelStatusStoreConfig {
        self.inner.config.lock().unwrap().clone()
    }

    pub fn set_config(&self, config: TunnelStatusStoreConfig) {
        *self.inner.config.lock().unwrap() = config;
    }

    pub async fn get_tunnel_builder_by_protocol(
        &self,
        protocol: &str,
    ) -> TunnelResult<Arc<dyn TunnelBuilder>> {
        let m = self.inner.tunnel_builder_manager.lock().unwrap();
        if let Some(builder) = m.get(protocol) {
            Ok(builder.clone())
        } else {
            let msg = format!("Unknown protocol: {}", protocol);
            error!("{}", msg);
            Err(TunnelError::UnknownProtocol(msg))
        }
    }

    pub async fn get_tunnel(
        &self,
        target_url: &Url,
        _enable_tunnel: Option<Vec<String>>,
    ) -> TunnelResult<Box<dyn TunnelBox>> {
        let builder = self
            .get_tunnel_builder_by_protocol(target_url.scheme())
            .await
            .map_err(|e| {
                error!("Get tunnel builder by protocol failed: {:?}", e);
                e
            })?;
        let auth = target_url.authority();
        let tunnel_stack_id = if auth.is_empty() { None } else { Some(auth) };
        let tunnel = builder.create_tunnel(tunnel_stack_id).await.map_err(|e| {
            error!("create_tunnel to {} failed: {:?}", target_url, e);
            e
        })?;

        debug!("Get tunnel for {} success", target_url);
        Ok(tunnel)
    }

    //$tunnel_schema://$tunnel_stack_id/$target_stream_id
    pub async fn open_stream_by_url(&self, url: &Url) -> TunnelResult<Box<dyn AsyncStream>> {
        let builder = self.get_tunnel_builder_by_protocol(url.scheme()).await?;
        let auth_str = url.authority();
        let tunnel = if auth_str.is_empty() {
            builder.create_tunnel(None).await?
        } else {
            builder.create_tunnel(Some(auth_str)).await?
        };
        let path = url.path();
        debug!("Open stream by url.path: {}", path);
        let res = tunnel.open_stream(path).await;
        match res {
            Ok(stream) => {
                self.record_business_connect(url, true, None).await;
                Ok(stream)
            }
            Err(e) => {
                let reason = format!("open stream failed: {}", e);
                self.record_business_connect(url, false, Some(reason.clone()))
                    .await;
                error!("Open stream by url {} failed: {}", url, e);
                Err(TunnelError::ConnectError(format!(
                    "Open stream by url failed: {}",
                    e
                )))
            }
        }
    }

    pub async fn create_datagram_client_by_url(
        &self,
        url: &Url,
    ) -> TunnelResult<Box<dyn DatagramClientBox>> {
        let builder = self.get_tunnel_builder_by_protocol(url.scheme()).await?;
        let auth_str = url.authority();
        let tunnel = if auth_str.is_empty() {
            builder.create_tunnel(None).await?
        } else {
            builder.create_tunnel(Some(auth_str)).await?
        };
        let res = tunnel.create_datagram_client(url.path()).await;
        match res {
            Ok(client) => {
                self.record_business_connect(url, true, None).await;
                Ok(client)
            }
            Err(e) => {
                let reason = format!("create datagram client failed: {}", e);
                self.record_business_connect(url, false, Some(reason.clone()))
                    .await;
                error!("Create datagram client by url failed: {}", e);
                Err(TunnelError::ConnectError(format!(
                    "Create datagram client by url failed: {}",
                    e
                )))
            }
        }
    }

    pub fn get_instance() -> &'static Self {
        unimplemented!()
    }

    // ------------------------------------------------------------------
    // URL state query API
    // ------------------------------------------------------------------

    /// Query the status of a single tunnel URL. May return cached history,
    /// join an in-flight probe, or kick off a fresh probe depending on
    /// freshness and `options.force_probe`.
    pub async fn query_tunnel_url_status(
        &self,
        url: &Url,
        options: TunnelProbeOptions,
    ) -> TunnelResult<TunnelUrlStatus> {
        let normalized = normalize_tunnel_url(url);
        let now_ms = now_ms();

        // 1. Try fresh history (unless force_probe).
        if !options.force_probe {
            if let Some(status) =
                self.history_status_if_fresh(&normalized, &options, now_ms).await
            {
                return Ok(status);
            }
        }

        // 2. Join in-flight probe if one exists for the same URL.
        let in_flight = self.maybe_get_in_flight(&normalized).await;
        if let Some(fut) = in_flight {
            let timeout_ms = options.timeout_ms_or_default();
            return Ok(self.await_in_flight(fut, &normalized, url, now_ms, timeout_ms).await);
        }

        // 3. Start a fresh probe.
        let status = self.start_and_await_probe(url, &normalized, options).await;
        Ok(status)
    }

    /// Query a batch of tunnel URLs. A single URL's failure becomes a per-URL
    /// `Unreachable` / `Unsupported` status; the call as a whole does not fail.
    pub async fn query_tunnel_url_statuses(
        &self,
        urls: &[Url],
        options: TunnelProbeOptions,
    ) -> TunnelResult<TunnelProbeResult> {
        if urls.is_empty() {
            return Ok(TunnelProbeResult {
                statuses: Vec::new(),
                sorted_urls: Vec::new(),
            });
        }

        // Run queries in parallel. Each per-URL future is independent.
        let mut futures = Vec::with_capacity(urls.len());
        for url in urls {
            let mgr = self.clone();
            let url = url.clone();
            let opt = options.clone();
            futures.push(async move {
                match mgr.query_tunnel_url_status(&url, opt).await {
                    Ok(s) => s,
                    Err(e) => {
                        let normalized = normalize_tunnel_url(&url);
                        unreachable_status(
                            &url,
                            &normalized,
                            now_ms(),
                            TunnelUrlStatusSource::FreshProbe,
                            format!("query failed: {}", e),
                        )
                    }
                }
            });
        }
        let statuses: Vec<TunnelUrlStatus> = futures::future::join_all(futures).await;

        let priorities = options.caller_priorities.as_deref();
        let sorted_urls = sort_urls(
            &statuses,
            options.sort,
            priorities,
            options.include_unsupported,
        );

        Ok(TunnelProbeResult {
            statuses,
            sorted_urls,
        })
    }

    /// Drop the cached status for a single URL.
    pub async fn invalidate_tunnel_url_status(&self, url: &Url) {
        let normalized = normalize_tunnel_url(url);
        self.inner.tunnel_history.write().await.remove(&normalized);
    }

    /// Drop all cached URL status history.
    pub async fn clear_tunnel_url_status_cache(&self) {
        self.inner.tunnel_history.write().await.clear();
    }

    /// Pin a URL so that LRU eviction will not drop its history.
    pub async fn pin_tunnel_url(&self, url: &Url) {
        let normalized = normalize_tunnel_url(url);
        let mut hist = self.inner.tunnel_history.write().await;
        if let Some(h) = hist.get_mut(&normalized) {
            h.pinned = true;
        } else {
            let now = now_ms();
            let unknown = unknown_status(url, &normalized, now, TunnelUrlStatusSource::CachedProbe);
            hist.insert(
                normalized.clone(),
                TunnelUrlHistory {
                    normalized_url: normalized.clone(),
                    scheme: url.scheme().to_lowercase(),
                    category: protocol_category_for_scheme(url.scheme()),
                    current: unknown,
                    last_reachable: None,
                    last_unreachable: None,
                    recent_rtt_ms: Vec::new(),
                    success_count: 0,
                    failure_count: 0,
                    updated_at_ms: now,
                    persisted_at_ms: None,
                    pinned: true,
                    runtime_tunnel_key: None,
                },
            );
        }
    }

    /// Snapshot the current in-memory history (for diagnostics/persistence).
    pub async fn list_tunnel_url_history(&self) -> Vec<TunnelUrlHistory> {
        self.inner
            .tunnel_history
            .read()
            .await
            .values()
            .cloned()
            .collect()
    }

    /// Apply an external observation (e.g. from `keep_tunnel`, business
    /// connect feedback, or a direct attempt) to URL history.
    pub async fn record_status_observation(&self, status: TunnelUrlStatus) {
        let mut hist = self.inner.tunnel_history.write().await;
        Self::merge_into_history(&mut hist, status);
        let limit = self.inner.config.lock().unwrap().max_memory_history_entries;
        Self::evict_if_needed(&mut hist, limit);
    }

    /// Apply a status update to every URL history whose runtime tunnel key
    /// matches `tunnel_key`. Used by RTCP for tunnel-level events
    /// (handshake failure, control-plane ping timeout, tunnel close) that
    /// affect every URL sharing the same RTCP tunnel.
    pub async fn record_tunnel_level_event(
        &self,
        tunnel_key: &str,
        is_reachable: bool,
        rtt_ms: Option<u64>,
        reason: Option<String>,
        source: TunnelUrlStatusSource,
    ) {
        let now = now_ms();
        let mut hist = self.inner.tunnel_history.write().await;
        let matches: Vec<String> = hist
            .values()
            .filter(|h| h.runtime_tunnel_key.as_deref() == Some(tunnel_key))
            .map(|h| h.normalized_url.clone())
            .collect();
        for normalized in matches {
            // Synthesize a URL from the normalized form for the status
            // builder. Fall back to skipping if the normalized form fails
            // to round-trip (shouldn't happen for previously valid URLs).
            let url_for_status = match Url::parse(&normalized) {
                Ok(u) => u,
                Err(_) => continue,
            };
            let mut status = if is_reachable {
                reachable_status(&url_for_status, &normalized, now, source, rtt_ms)
            } else {
                unreachable_status(
                    &url_for_status,
                    &normalized,
                    now,
                    source,
                    reason.clone()
                        .unwrap_or_else(|| "tunnel_level_failure".to_string()),
                )
            };
            status.runtime_tunnel_key = Some(tunnel_key.to_string());
            if let Some(h) = hist.get_mut(&normalized) {
                h.merge(status);
            }
        }
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    async fn record_business_connect(&self, url: &Url, success: bool, reason: Option<String>) {
        let normalized = normalize_tunnel_url(url);
        let now = now_ms();
        let status = if success {
            reachable_status(
                url,
                &normalized,
                now,
                TunnelUrlStatusSource::BusinessConnect,
                None,
            )
        } else {
            unreachable_status(
                url,
                &normalized,
                now,
                TunnelUrlStatusSource::BusinessConnect,
                reason.unwrap_or_else(|| "business_connect_failed".to_string()),
            )
        };
        self.record_status_observation(status).await;
    }

    async fn history_status_if_fresh(
        &self,
        normalized: &str,
        options: &TunnelProbeOptions,
        now_ms: u64,
    ) -> Option<TunnelUrlStatus> {
        let hist = self.inner.tunnel_history.read().await;
        let entry = hist.get(normalized)?;
        let cur = &entry.current;
        let cfg = self.inner.config.lock().unwrap().clone();
        let ttl = cfg.ttl_for(cur.state);
        let max_age = options.max_age_ms.unwrap_or(ttl);
        let age = now_ms.saturating_sub(cur.observed_at_ms);
        if age <= max_age && age <= ttl {
            let mut s = cur.clone();
            s.cached = true;
            return Some(s);
        }
        None
    }

    async fn maybe_get_in_flight(&self, normalized: &str) -> Option<SharedProbeFuture> {
        let map = self.inner.in_flight_probes.lock().await;
        map.get(normalized).cloned()
    }

    async fn await_in_flight(
        &self,
        fut: SharedProbeFuture,
        normalized: &str,
        url: &Url,
        now_ms: u64,
        timeout_ms: u64,
    ) -> TunnelUrlStatus {
        match tokio::time::timeout(std::time::Duration::from_millis(timeout_ms), fut).await {
            Ok(s) => {
                let mut s = s;
                s.cached = true;
                s
            }
            Err(_) => {
                // Probe still running; return the cached/unknown status with
                // a `cached = true` flag if we have any history, otherwise
                // a probing/unknown sentinel.
                if let Some(hist) = self
                    .inner
                    .tunnel_history
                    .read()
                    .await
                    .get(normalized)
                    .cloned()
                {
                    let mut s = hist.current.clone();
                    s.cached = true;
                    s
                } else {
                    let mut s = unknown_status(
                        url,
                        normalized,
                        now_ms,
                        TunnelUrlStatusSource::CachedProbe,
                    );
                    s.state = TunnelUrlState::Probing;
                    s
                }
            }
        }
    }

    async fn start_and_await_probe(
        &self,
        url: &Url,
        normalized: &str,
        options: TunnelProbeOptions,
    ) -> TunnelUrlStatus {
        let scheme = url.scheme().to_lowercase();
        let prober = {
            let m = self.inner.tunnel_builder_manager.lock().unwrap();
            m.get(&scheme).and_then(|b| b.url_prober())
        };
        let prober = match prober {
            Some(p) => p,
            None => {
                let now = now_ms();
                let status = unsupported_status(
                    url,
                    normalized,
                    now,
                    Some(format!("no prober for scheme '{}'", scheme)),
                );
                self.record_status_observation(status.clone()).await;
                return status;
            }
        };

        let limiter = self.inner.probe_limiter.clone();
        let url_owned = url.clone();
        let normalized_owned = normalized.to_string();
        let masked = mask_tunnel_url(url);
        let opts_for_probe = options.clone();
        let timeout_ms = options.timeout_ms_or_default();
        let mgr = self.clone();

        // Build the probe future that we will share among all awaiters of
        // this URL while it is in flight.
        let probe_future: BoxFuture<'static, TunnelUrlStatus> = Box::pin(async move {
            let _permit = match limiter.acquire().await {
                Ok(p) => p,
                Err(_) => {
                    return unreachable_status(
                        &url_owned,
                        &normalized_owned,
                        now_ms(),
                        TunnelUrlStatusSource::FreshProbe,
                        "probe_limiter_closed".to_string(),
                    );
                }
            };
            let probe_call = prober.probe_url(&url_owned, &opts_for_probe);
            let status = match tokio::time::timeout(
                std::time::Duration::from_millis(timeout_ms),
                probe_call,
            )
            .await
            {
                Ok(Ok(mut s)) => {
                    s.url = masked.clone();
                    s.normalized_url = normalized_owned.clone();
                    s
                }
                Ok(Err(e)) => unreachable_status(
                    &url_owned,
                    &normalized_owned,
                    now_ms(),
                    TunnelUrlStatusSource::FreshProbe,
                    format!("probe error: {}", e),
                ),
                Err(_) => unreachable_status(
                    &url_owned,
                    &normalized_owned,
                    now_ms(),
                    TunnelUrlStatusSource::FreshProbe,
                    "probe timeout".to_string(),
                ),
            };
            mgr.record_status_observation(status.clone()).await;
            mgr.remove_in_flight(&normalized_owned).await;
            status
        });
        let shared: SharedProbeFuture = probe_future.shared();

        // Insert into the in-flight map atomically; if someone else beat us
        // to it, drop our future and use theirs (this can happen when two
        // callers race past the freshness check).
        {
            let mut map = self.inner.in_flight_probes.lock().await;
            if let Some(existing) = map.get(normalized).cloned() {
                drop(map);
                return existing.await;
            }
            map.insert(normalized.to_string(), shared.clone());
        }

        shared.await
    }

    async fn remove_in_flight(&self, normalized: &str) {
        let mut map = self.inner.in_flight_probes.lock().await;
        map.remove(normalized);
    }

    fn merge_into_history(
        hist: &mut HashMap<String, TunnelUrlHistory>,
        status: TunnelUrlStatus,
    ) {
        let key = status.normalized_url.clone();
        if let Some(entry) = hist.get_mut(&key) {
            entry.merge(status);
        } else {
            let now = status.observed_at_ms;
            let scheme = status.scheme.clone();
            let category = status.category;
            let entry = TunnelUrlHistory {
                normalized_url: key.clone(),
                scheme,
                category,
                current: status.clone(),
                last_reachable: if status.state == TunnelUrlState::Reachable {
                    Some(status.clone())
                } else {
                    None
                },
                last_unreachable: if status.state == TunnelUrlState::Unreachable {
                    Some(status.clone())
                } else {
                    None
                },
                recent_rtt_ms: status.rtt_ms.map(|r| vec![r]).unwrap_or_default(),
                success_count: if status.state == TunnelUrlState::Reachable {
                    1
                } else {
                    0
                },
                failure_count: if status.state == TunnelUrlState::Unreachable {
                    1
                } else {
                    0
                },
                updated_at_ms: now,
                persisted_at_ms: None,
                pinned: false,
                runtime_tunnel_key: status.runtime_tunnel_key.clone(),
            };
            hist.insert(key, entry);
        }
    }

    fn evict_if_needed(hist: &mut HashMap<String, TunnelUrlHistory>, limit: usize) {
        if limit == 0 || hist.len() <= limit {
            return;
        }
        // Collect non-pinned entries sorted by updated_at_ms ASC and drop
        // the oldest ones until we are back within the limit.
        let mut candidates: Vec<(String, u64)> = hist
            .iter()
            .filter(|(_, h)| !h.pinned)
            .map(|(k, h)| (k.clone(), h.updated_at_ms))
            .collect();
        candidates.sort_by_key(|(_, t)| *t);
        let mut to_drop = hist.len().saturating_sub(limit);
        for (k, _) in candidates.into_iter() {
            if to_drop == 0 {
                break;
            }
            hist.remove(&k);
            to_drop -= 1;
        }
    }
}

pub(crate) fn now_ms() -> u64 {
    // buckyos_get_unix_timestamp returns seconds; convert to millis.
    buckyos_get_unix_timestamp().saturating_mul(1_000)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tunnel_url_status::{TunnelUrlProber, TunnelUrlSortPolicy};
    use async_trait::async_trait;
    use std::io;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Clone, Default)]
    struct MockTunnel {}

    #[async_trait]
    impl crate::Tunnel for MockTunnel {
        async fn ping(&self) -> Result<(), io::Error> {
            Ok(())
        }

        async fn open_stream_by_dest(
            &self,
            _dest_port: u16,
            _dest_host: Option<String>,
        ) -> Result<Box<dyn AsyncStream>, io::Error> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "not used in test",
            ))
        }

        async fn open_stream(&self, _stream_id: &str) -> Result<Box<dyn AsyncStream>, io::Error> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "not used in test",
            ))
        }

        async fn create_datagram_client_by_dest(
            &self,
            _dest_port: u16,
            _dest_host: Option<String>,
        ) -> Result<Box<dyn crate::DatagramClientBox>, io::Error> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "not used in test",
            ))
        }

        async fn create_datagram_client(
            &self,
            _session_id: &str,
        ) -> Result<Box<dyn crate::DatagramClientBox>, io::Error> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "not used in test",
            ))
        }
    }

    #[derive(Clone)]
    struct MockTunnelBuilder {
        captured: Arc<StdMutex<Option<String>>>,
    }

    #[async_trait]
    impl TunnelBuilder for MockTunnelBuilder {
        async fn create_tunnel(
            &self,
            tunnel_stack_id: Option<&str>,
        ) -> TunnelResult<Box<dyn TunnelBox>> {
            *self.captured.lock().unwrap() = tunnel_stack_id.map(|s| s.to_string());
            Ok(Box::new(MockTunnel::default()))
        }
    }

    // ------------------------------------------------------------------
    // Probe-API test fixtures
    // ------------------------------------------------------------------

    struct CountingProber {
        scheme: String,
        rtt_ms: Option<u64>,
        reachable: bool,
        delay_ms: u64,
        call_count: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl TunnelUrlProber for CountingProber {
        async fn probe_url(
            &self,
            url: &Url,
            _options: &TunnelProbeOptions,
        ) -> TunnelResult<TunnelUrlStatus> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            if self.delay_ms > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(self.delay_ms)).await;
            }
            let now = now_ms();
            let normalized = normalize_tunnel_url(url);
            if self.reachable {
                Ok(reachable_status(
                    url,
                    &normalized,
                    now,
                    TunnelUrlStatusSource::FreshProbe,
                    self.rtt_ms,
                ))
            } else {
                Ok(unreachable_status(
                    url,
                    &normalized,
                    now,
                    TunnelUrlStatusSource::FreshProbe,
                    "mock_unreachable".to_string(),
                ))
            }
        }
    }

    #[derive(Clone)]
    struct ProberBuilder {
        prober: Arc<CountingProber>,
    }

    #[async_trait]
    impl TunnelBuilder for ProberBuilder {
        async fn create_tunnel(
            &self,
            _tunnel_stack_id: Option<&str>,
        ) -> TunnelResult<Box<dyn TunnelBox>> {
            Ok(Box::new(MockTunnel::default()))
        }

        fn url_prober(&self) -> Option<crate::tunnel_url_status::TunnelUrlProberRef> {
            Some(self.prober.clone())
        }
    }

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[tokio::test]
    async fn test_tunnel_url_in_stream_id() {
        use percent_encoding::{NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};
        use url::Url;

        let tunnel_url = "rtcp://sn.buckyos.ai/google.com:443";
        let url = Url::parse(tunnel_url).unwrap();
        let stream_id = url.path();
        assert_eq!(stream_id, "/google.com:443");

        let embedded_url = "rtcp://sn.buckyos.io/google.com:443/";
        let encoded_url = utf8_percent_encode(embedded_url, NON_ALPHANUMERIC).to_string();

        let mut url2 = url.clone();
        let new_path = format!("/{}", encoded_url);
        url2.set_path(&new_path);

        let decoded_path = percent_decode_str(url2.path().trim_start_matches('/'))
            .decode_utf8()
            .unwrap();
        assert_eq!(decoded_path, embedded_url);
    }

    #[tokio::test]
    async fn test_get_tunnel_preserves_socks_authority() {
        let manager = TunnelManager::new();
        let captured = Arc::new(StdMutex::new(None));
        let builder = MockTunnelBuilder {
            captured: captured.clone(),
        };
        manager.register_tunnel_builder("socks", Arc::new(builder));

        let url = Url::parse("socks://u:p@127.0.0.1:12345").unwrap();
        let ret = manager.get_tunnel(&url, None).await;
        assert!(ret.is_ok());

        let value = captured.lock().unwrap().clone();
        assert_eq!(value.as_deref(), Some("u:p@127.0.0.1:12345"));
    }

    #[tokio::test]
    async fn test_get_tunnel_non_socks_keeps_host_only_behavior() {
        let manager = TunnelManager::new();
        let captured = Arc::new(StdMutex::new(None));
        let builder = MockTunnelBuilder {
            captured: captured.clone(),
        };
        manager.register_tunnel_builder("tcp", Arc::new(builder));

        let url = Url::parse("tcp://127.0.0.1:18080").unwrap();
        let ret = manager.get_tunnel(&url, None).await;
        assert!(ret.is_ok());

        let value = captured.lock().unwrap().clone();
        assert_eq!(value.as_deref(), Some("127.0.0.1:18080"));
    }

    // ------------------------------------------------------------------
    // URL state query tests
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn unsupported_scheme_returns_unsupported() {
        let mgr = TunnelManager::new();
        // udp has no prober
        let u = url("udp://127.0.0.1:9000/");
        let s = mgr
            .query_tunnel_url_status(&u, TunnelProbeOptions::default())
            .await
            .unwrap();
        assert_eq!(s.state, TunnelUrlState::Unsupported);
    }

    #[tokio::test]
    async fn fresh_probe_then_cache_hit() {
        let mgr = TunnelManager::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let prober = Arc::new(CountingProber {
            scheme: "tcp".to_string(),
            rtt_ms: Some(15),
            reachable: true,
            delay_ms: 0,
            call_count: calls.clone(),
        });
        mgr.register_tunnel_builder(
            "tcp",
            Arc::new(ProberBuilder { prober }),
        );

        let u = url("tcp://127.0.0.1:18001/");
        let s1 = mgr
            .query_tunnel_url_status(&u, TunnelProbeOptions::default())
            .await
            .unwrap();
        assert_eq!(s1.state, TunnelUrlState::Reachable);
        assert_eq!(s1.rtt_ms, Some(15));
        assert!(!s1.cached);

        // second call within TTL must be a cache hit
        let s2 = mgr
            .query_tunnel_url_status(&u, TunnelProbeOptions::default())
            .await
            .unwrap();
        assert!(s2.cached, "expected cached hit");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn force_probe_bypasses_cache() {
        let mgr = TunnelManager::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let prober = Arc::new(CountingProber {
            scheme: "tcp".to_string(),
            rtt_ms: Some(10),
            reachable: true,
            delay_ms: 0,
            call_count: calls.clone(),
        });
        mgr.register_tunnel_builder(
            "tcp",
            Arc::new(ProberBuilder { prober }),
        );

        let u = url("tcp://127.0.0.1:18002/");
        let _ = mgr
            .query_tunnel_url_status(&u, TunnelProbeOptions::default())
            .await
            .unwrap();
        let opt = TunnelProbeOptions {
            force_probe: true,
            ..Default::default()
        };
        let _ = mgr.query_tunnel_url_status(&u, opt).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn invalidate_url_drops_cache() {
        let mgr = TunnelManager::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let prober = Arc::new(CountingProber {
            scheme: "tcp".to_string(),
            rtt_ms: Some(1),
            reachable: true,
            delay_ms: 0,
            call_count: calls.clone(),
        });
        mgr.register_tunnel_builder(
            "tcp",
            Arc::new(ProberBuilder { prober }),
        );

        let u = url("tcp://127.0.0.1:18003/");
        let _ = mgr
            .query_tunnel_url_status(&u, TunnelProbeOptions::default())
            .await
            .unwrap();
        mgr.invalidate_tunnel_url_status(&u).await;
        let _ = mgr
            .query_tunnel_url_status(&u, TunnelProbeOptions::default())
            .await
            .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn batch_query_returns_per_url_status() {
        let mgr = TunnelManager::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let tcp_prober = Arc::new(CountingProber {
            scheme: "tcp".to_string(),
            rtt_ms: Some(5),
            reachable: true,
            delay_ms: 0,
            call_count: calls.clone(),
        });
        mgr.register_tunnel_builder(
            "tcp",
            Arc::new(ProberBuilder { prober: tcp_prober }),
        );

        let urls = vec![
            url("tcp://127.0.0.1:18010/"),
            url("udp://127.0.0.1:18011/"),
            url("tcp://127.0.0.1:18012/"),
        ];
        let opts = TunnelProbeOptions {
            sort: TunnelUrlSortPolicy::ReachableFirst,
            ..Default::default()
        };
        let res = mgr
            .query_tunnel_url_statuses(&urls, opts)
            .await
            .unwrap();
        assert_eq!(res.statuses.len(), 3);
        // udp is unsupported, must sink to last
        assert_eq!(
            res.sorted_urls.last().unwrap(),
            &normalize_tunnel_url(&urls[1])
        );
    }

    #[tokio::test]
    async fn in_flight_probe_is_merged() {
        let mgr = TunnelManager::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let prober = Arc::new(CountingProber {
            scheme: "tcp".to_string(),
            rtt_ms: Some(7),
            reachable: true,
            delay_ms: 100,
            call_count: calls.clone(),
        });
        mgr.register_tunnel_builder(
            "tcp",
            Arc::new(ProberBuilder { prober }),
        );

        let u = url("tcp://127.0.0.1:18020/");
        let mgr1 = mgr.clone();
        let mgr2 = mgr.clone();
        let u1 = u.clone();
        let u2 = u.clone();
        let h1 = tokio::spawn(async move {
            mgr1.query_tunnel_url_status(&u1, TunnelProbeOptions::default()).await
        });
        // small delay to ensure h1 starts the probe first
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        let h2 = tokio::spawn(async move {
            mgr2.query_tunnel_url_status(&u2, TunnelProbeOptions::default()).await
        });
        let r1 = h1.await.unwrap().unwrap();
        let r2 = h2.await.unwrap().unwrap();
        assert_eq!(r1.state, TunnelUrlState::Reachable);
        assert_eq!(r2.state, TunnelUrlState::Reachable);
        // The prober is invoked exactly once even though two concurrent
        // queries hit the same URL.
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn lru_eviction_respects_pinned() {
        let mut cfg = TunnelStatusStoreConfig::default();
        cfg.max_memory_history_entries = 3;
        let mgr = TunnelManager::with_config(cfg);
        let calls = Arc::new(AtomicUsize::new(0));
        let prober = Arc::new(CountingProber {
            scheme: "tcp".to_string(),
            rtt_ms: Some(1),
            reachable: true,
            delay_ms: 0,
            call_count: calls.clone(),
        });
        mgr.register_tunnel_builder(
            "tcp",
            Arc::new(ProberBuilder { prober }),
        );

        let pin_url = url("tcp://127.0.0.1:18030/");
        mgr.pin_tunnel_url(&pin_url).await;
        // probe pinned URL once
        let _ = mgr
            .query_tunnel_url_status(&pin_url, TunnelProbeOptions::default())
            .await
            .unwrap();
        // fill with more URLs to force eviction
        for i in 1..=5 {
            let u = url(&format!("tcp://127.0.0.1:1804{}/", i));
            let _ = mgr
                .query_tunnel_url_status(&u, TunnelProbeOptions::default())
                .await
                .unwrap();
        }
        let entries = mgr.list_tunnel_url_history().await;
        assert!(entries.len() <= 3);
        // pinned URL must survive
        assert!(
            entries
                .iter()
                .any(|h| h.normalized_url == normalize_tunnel_url(&pin_url))
        );
    }

    #[tokio::test]
    async fn business_connect_failure_records_history() {
        let mgr = TunnelManager::new();
        let captured = Arc::new(StdMutex::new(None));
        let builder = MockTunnelBuilder { captured };
        // tcp builder that returns a tunnel whose open_stream errors.
        mgr.register_tunnel_builder("tcp", Arc::new(builder));
        let u = url("tcp://127.0.0.1:18050/somepath");
        // This call will fail because MockTunnel::open_stream returns Unsupported.
        let _ = mgr.open_stream_by_url(&u).await;
        let entries = mgr.list_tunnel_url_history().await;
        let h = entries
            .into_iter()
            .find(|h| h.normalized_url == normalize_tunnel_url(&u))
            .expect("history entry for failed business connect");
        assert_eq!(h.current.state, TunnelUrlState::Unreachable);
        assert_eq!(h.current.source, TunnelUrlStatusSource::BusinessConnect);
    }

    #[tokio::test]
    async fn record_status_observation_persists_after_invalidation_until_clear() {
        let mgr = TunnelManager::new();
        let u = url("rtcp://device.dev.did/:80");
        let normalized = normalize_tunnel_url(&u);
        let now = now_ms();
        mgr.record_status_observation(reachable_status(
            &u,
            &normalized,
            now,
            TunnelUrlStatusSource::KeepAlive,
            Some(20),
        ))
        .await;
        let entries = mgr.list_tunnel_url_history().await;
        assert_eq!(entries.len(), 1);
        assert!(entries[0].last_reachable.is_some());
        // A tunnel-instance close must not remove URL history.
        // Instead, a follow-up Unreachable observation only updates current.
        mgr.record_status_observation(unreachable_status(
            &u,
            &normalized,
            now + 100,
            TunnelUrlStatusSource::KeepAlive,
            "ping_timeout".to_string(),
        ))
        .await;
        let entries = mgr.list_tunnel_url_history().await;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].current.state, TunnelUrlState::Unreachable);
        assert!(entries[0].last_reachable.is_some(), "history kept");
    }
}
