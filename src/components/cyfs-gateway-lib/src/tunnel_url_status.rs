use crate::tunnel_mgr::ProtocolCategory;
use crate::{TunnelError, TunnelResult, get_protocol_category};
use async_trait::async_trait;
use std::cmp::Ordering;
use std::sync::Arc;
use url::Url;

const DEFAULT_REACHABLE_TTL_MS: u64 = 30_000;
const DEFAULT_UNKNOWN_TTL_MS: u64 = 10_000;
const DEFAULT_UNREACHABLE_TTL_MS: u64 = 5_000;
const DEFAULT_UNSUPPORTED_TTL_MS: u64 = 60_000;
const DEFAULT_MAX_MEMORY_HISTORY_ENTRIES: usize = 10_000;
const DEFAULT_PROBE_TIMEOUT_MS: u64 = 3_000;
const DEFAULT_PROBE_CONCURRENCY: usize = 32;
const DEFAULT_RECENT_RTT_CAP: usize = 8;

/// Snapshot state of a Tunnel URL at a point in time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TunnelUrlState {
    Reachable,
    Unreachable,
    Unknown,
    Probing,
    Unsupported,
}

impl TunnelUrlState {
    pub fn as_str(&self) -> &'static str {
        match self {
            TunnelUrlState::Reachable => "reachable",
            TunnelUrlState::Unreachable => "unreachable",
            TunnelUrlState::Unknown => "unknown",
            TunnelUrlState::Probing => "probing",
            TunnelUrlState::Unsupported => "unsupported",
        }
    }
}

/// Where the status observation came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TunnelUrlStatusSource {
    ExistingTunnel,
    KeepAlive,
    CachedProbe,
    FreshProbe,
    BusinessConnect,
    BuilderValidation,
    Unsupported,
}

impl TunnelUrlStatusSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            TunnelUrlStatusSource::ExistingTunnel => "existing_tunnel",
            TunnelUrlStatusSource::KeepAlive => "keep_alive",
            TunnelUrlStatusSource::CachedProbe => "cached_probe",
            TunnelUrlStatusSource::FreshProbe => "fresh_probe",
            TunnelUrlStatusSource::BusinessConnect => "business_connect",
            TunnelUrlStatusSource::BuilderValidation => "builder_validation",
            TunnelUrlStatusSource::Unsupported => "unsupported",
        }
    }
}

/// Sort policy applied to batch query results.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelUrlSortPolicy {
    None,
    ReachableFirst,
    RttAscending,
    CallerPriorityThenRtt,
}

impl Default for TunnelUrlSortPolicy {
    fn default() -> Self {
        TunnelUrlSortPolicy::None
    }
}

/// One observation of a Tunnel URL status.
#[derive(Debug, Clone)]
pub struct TunnelUrlStatus {
    pub url: String,
    pub normalized_url: String,
    pub scheme: String,
    pub category: Option<ProtocolCategory>,
    pub state: TunnelUrlState,
    pub rtt_ms: Option<u64>,
    pub last_success_at_ms: Option<u64>,
    pub last_failure_at_ms: Option<u64>,
    pub failure_reason: Option<String>,
    pub source: TunnelUrlStatusSource,
    pub cached: bool,
    pub observed_at_ms: u64,
    pub expires_at_ms: Option<u64>,
    /// Optional runtime hint that lets `TunnelManager` group multiple
    /// URLs sharing one underlying tunnel (e.g. one RTCP tunnel serving
    /// `:80` and `:9000` on the same device). Set by protocol probers;
    /// `None` for connect-style protocols where each URL has its own
    /// transport instance.
    pub runtime_tunnel_key: Option<String>,
}

/// Long-running history record for a single normalized URL.
#[derive(Debug, Clone)]
pub struct TunnelUrlHistory {
    pub normalized_url: String,
    pub scheme: String,
    pub category: Option<ProtocolCategory>,
    pub current: TunnelUrlStatus,
    pub last_reachable: Option<TunnelUrlStatus>,
    pub last_unreachable: Option<TunnelUrlStatus>,
    pub recent_rtt_ms: Vec<u64>,
    pub success_count: u64,
    pub failure_count: u64,
    pub updated_at_ms: u64,
    pub persisted_at_ms: Option<u64>,
    pub pinned: bool,
    /// Carried over from the most recent status that supplied one. Used
    /// by `TunnelManager::record_tunnel_level_event` to propagate
    /// tunnel-level signals to all URLs sharing the same transport.
    pub runtime_tunnel_key: Option<String>,
}

impl TunnelUrlHistory {
    pub(crate) fn merge(&mut self, status: TunnelUrlStatus) {
        self.updated_at_ms = status.observed_at_ms;
        if status.runtime_tunnel_key.is_some() {
            self.runtime_tunnel_key = status.runtime_tunnel_key.clone();
        }
        match status.state {
            TunnelUrlState::Reachable => {
                self.success_count = self.success_count.saturating_add(1);
                self.last_reachable = Some(status.clone());
                if let Some(rtt) = status.rtt_ms {
                    self.recent_rtt_ms.push(rtt);
                    if self.recent_rtt_ms.len() > DEFAULT_RECENT_RTT_CAP {
                        let overflow = self.recent_rtt_ms.len() - DEFAULT_RECENT_RTT_CAP;
                        self.recent_rtt_ms.drain(0..overflow);
                    }
                }
            }
            TunnelUrlState::Unreachable => {
                self.failure_count = self.failure_count.saturating_add(1);
                self.last_unreachable = Some(status.clone());
            }
            TunnelUrlState::Unsupported
            | TunnelUrlState::Unknown
            | TunnelUrlState::Probing => {}
        }
        self.current = status;
    }
}

/// Caller-supplied control over a probe call.
#[derive(Debug, Clone)]
pub struct TunnelProbeOptions {
    pub force_probe: bool,
    pub max_age_ms: Option<u64>,
    pub timeout_ms: Option<u64>,
    pub sort: TunnelUrlSortPolicy,
    pub include_unsupported: bool,
    /// Optional caller priority per URL. Lower number = higher priority.
    /// Used by `CallerPriorityThenRtt`. Length should match the URL slice
    /// in batch queries; missing entries are treated as `u32::MAX`.
    pub caller_priorities: Option<Vec<u32>>,
}

impl Default for TunnelProbeOptions {
    fn default() -> Self {
        Self {
            force_probe: false,
            max_age_ms: None,
            timeout_ms: Some(DEFAULT_PROBE_TIMEOUT_MS),
            sort: TunnelUrlSortPolicy::None,
            include_unsupported: true,
            caller_priorities: None,
        }
    }
}

impl TunnelProbeOptions {
    pub fn timeout_ms_or_default(&self) -> u64 {
        self.timeout_ms.unwrap_or(DEFAULT_PROBE_TIMEOUT_MS)
    }
}

/// Result of a batch probe call.
#[derive(Debug, Clone)]
pub struct TunnelProbeResult {
    pub statuses: Vec<TunnelUrlStatus>,
    pub sorted_urls: Vec<String>,
}

/// Persistent store configuration. Persistence is loaded by an injected
/// implementation; this crate currently keeps history in memory by default.
#[derive(Debug, Clone)]
pub struct TunnelStatusStoreConfig {
    pub enable_persist: bool,
    pub persist_path: Option<String>,
    pub flush_interval_ms: u64,
    pub max_history_entries: usize,
    pub max_memory_history_entries: usize,
    pub reachable_ttl_ms: u64,
    pub unknown_ttl_ms: u64,
    pub unreachable_ttl_ms: u64,
    pub unsupported_ttl_ms: u64,
    pub probe_concurrency: usize,
}

impl Default for TunnelStatusStoreConfig {
    fn default() -> Self {
        Self {
            enable_persist: false,
            persist_path: None,
            flush_interval_ms: 5_000,
            max_history_entries: DEFAULT_MAX_MEMORY_HISTORY_ENTRIES,
            max_memory_history_entries: DEFAULT_MAX_MEMORY_HISTORY_ENTRIES,
            reachable_ttl_ms: DEFAULT_REACHABLE_TTL_MS,
            unknown_ttl_ms: DEFAULT_UNKNOWN_TTL_MS,
            unreachable_ttl_ms: DEFAULT_UNREACHABLE_TTL_MS,
            unsupported_ttl_ms: DEFAULT_UNSUPPORTED_TTL_MS,
            probe_concurrency: DEFAULT_PROBE_CONCURRENCY,
        }
    }
}

impl TunnelStatusStoreConfig {
    pub fn ttl_for(&self, state: TunnelUrlState) -> u64 {
        match state {
            TunnelUrlState::Reachable => self.reachable_ttl_ms,
            TunnelUrlState::Unknown | TunnelUrlState::Probing => self.unknown_ttl_ms,
            TunnelUrlState::Unreachable => self.unreachable_ttl_ms,
            TunnelUrlState::Unsupported => self.unsupported_ttl_ms,
        }
    }
}

/// Protocol-level prober. Returned by `TunnelBuilder::url_prober()`.
#[async_trait]
pub trait TunnelUrlProber: Send + Sync {
    async fn probe_url(
        &self,
        url: &Url,
        options: &TunnelProbeOptions,
    ) -> TunnelResult<TunnelUrlStatus>;
}

pub type TunnelUrlProberRef = Arc<dyn TunnelUrlProber>;

/// Returns the normalized key for a Tunnel URL. The key is stable across
/// trivially different URL spellings (case in scheme/host, query order,
/// fragment), but preserves authority including userinfo since identity
/// matters for routing and quota. Use `mask_tunnel_url` for display.
pub fn normalize_tunnel_url(url: &Url) -> String {
    let scheme = url.scheme().to_lowercase();
    let mut authority = String::new();
    if !url.username().is_empty() || url.password().is_some() {
        authority.push_str(url.username());
        if let Some(pw) = url.password() {
            authority.push(':');
            authority.push_str(pw);
        }
        authority.push('@');
    }
    if let Some(host) = url.host_str() {
        // host_str returns the literal host; lowercase for case-insensitive
        // hostnames/DIDs. IPv6 literals are returned without brackets, so
        // wrap them back to keep the canonical form.
        let lower = host.to_lowercase();
        if host.contains(':') && !lower.starts_with('[') {
            authority.push('[');
            authority.push_str(&lower);
            authority.push(']');
        } else {
            authority.push_str(&lower);
        }
    }
    if let Some(port) = url.port() {
        authority.push(':');
        authority.push_str(&port.to_string());
    }

    // Path: keep as-is; do NOT collapse "" vs "/" since tunnel target
    // semantics differ across schemes.
    let path = url.path();

    // Query: sort by key, preserve value order under a single key.
    let query_canon = match url.query() {
        Some(_) => {
            let mut pairs: Vec<(String, String)> = url
                .query_pairs()
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect();
            pairs.sort_by(|a, b| a.0.cmp(&b.0));
            if pairs.is_empty() {
                // Preserve a literal empty query "?" if present.
                String::from("?")
            } else {
                let mut buf = String::from("?");
                for (i, (k, v)) in pairs.iter().enumerate() {
                    if i > 0 {
                        buf.push('&');
                    }
                    buf.push_str(k);
                    buf.push('=');
                    buf.push_str(v);
                }
                buf
            }
        }
        None => String::new(),
    };

    // Fragment intentionally dropped from key.
    format!("{}://{}{}{}", scheme, authority, path, query_canon)
}

/// Mask userinfo and known sensitive query parameters for safe display
/// in logs and error messages.
pub fn mask_tunnel_url(url: &Url) -> String {
    let scheme = url.scheme().to_lowercase();
    let mut authority = String::new();
    let has_user = !url.username().is_empty();
    let has_pw = url.password().is_some();
    if has_user || has_pw {
        authority.push_str("***@");
    }
    if let Some(host) = url.host_str() {
        let lower = host.to_lowercase();
        if host.contains(':') && !lower.starts_with('[') {
            authority.push('[');
            authority.push_str(&lower);
            authority.push(']');
        } else {
            authority.push_str(&lower);
        }
    }
    if let Some(port) = url.port() {
        authority.push(':');
        authority.push_str(&port.to_string());
    }
    let path = url.path();
    format!("{}://{}{}", scheme, authority, path)
}

pub fn protocol_category_for_scheme(scheme: &str) -> Option<ProtocolCategory> {
    get_protocol_category(scheme).ok()
}

/// Build a fresh status for an `Unknown` (no probe attempted) state.
pub fn unknown_status(url: &Url, normalized: &str, now_ms: u64, source: TunnelUrlStatusSource)
    -> TunnelUrlStatus
{
    TunnelUrlStatus {
        url: mask_tunnel_url(url),
        normalized_url: normalized.to_string(),
        scheme: url.scheme().to_lowercase(),
        category: protocol_category_for_scheme(url.scheme()),
        state: TunnelUrlState::Unknown,
        rtt_ms: None,
        last_success_at_ms: None,
        last_failure_at_ms: None,
        failure_reason: None,
        source,
        cached: false,
        observed_at_ms: now_ms,
        expires_at_ms: None,
        runtime_tunnel_key: None,
    }
}

pub fn unsupported_status(
    url: &Url,
    normalized: &str,
    now_ms: u64,
    reason: Option<String>,
) -> TunnelUrlStatus {
    TunnelUrlStatus {
        url: mask_tunnel_url(url),
        normalized_url: normalized.to_string(),
        scheme: url.scheme().to_lowercase(),
        category: protocol_category_for_scheme(url.scheme()),
        state: TunnelUrlState::Unsupported,
        rtt_ms: None,
        last_success_at_ms: None,
        last_failure_at_ms: None,
        failure_reason: reason,
        source: TunnelUrlStatusSource::Unsupported,
        cached: false,
        observed_at_ms: now_ms,
        expires_at_ms: None,
        runtime_tunnel_key: None,
    }
}

pub fn unreachable_status(
    url: &Url,
    normalized: &str,
    now_ms: u64,
    source: TunnelUrlStatusSource,
    reason: String,
) -> TunnelUrlStatus {
    TunnelUrlStatus {
        url: mask_tunnel_url(url),
        normalized_url: normalized.to_string(),
        scheme: url.scheme().to_lowercase(),
        category: protocol_category_for_scheme(url.scheme()),
        state: TunnelUrlState::Unreachable,
        rtt_ms: None,
        last_success_at_ms: None,
        last_failure_at_ms: Some(now_ms),
        failure_reason: Some(reason),
        source,
        cached: false,
        observed_at_ms: now_ms,
        expires_at_ms: None,
        runtime_tunnel_key: None,
    }
}

pub fn reachable_status(
    url: &Url,
    normalized: &str,
    now_ms: u64,
    source: TunnelUrlStatusSource,
    rtt_ms: Option<u64>,
) -> TunnelUrlStatus {
    TunnelUrlStatus {
        url: mask_tunnel_url(url),
        normalized_url: normalized.to_string(),
        scheme: url.scheme().to_lowercase(),
        category: protocol_category_for_scheme(url.scheme()),
        state: TunnelUrlState::Reachable,
        rtt_ms,
        last_success_at_ms: Some(now_ms),
        last_failure_at_ms: None,
        failure_reason: None,
        source,
        cached: false,
        observed_at_ms: now_ms,
        expires_at_ms: None,
        runtime_tunnel_key: None,
    }
}

/// Apply a sort policy to a copy of the input statuses and return the
/// resulting URL order. Statuses themselves are not mutated. The
/// `caller_priorities` slice is parallel to `statuses` (positional, before
/// any sort happened); missing entries are treated as `u32::MAX`.
pub fn sort_urls(
    statuses: &[TunnelUrlStatus],
    policy: TunnelUrlSortPolicy,
    caller_priorities: Option<&[u32]>,
    include_unsupported: bool,
) -> Vec<String> {
    let mut idx: Vec<usize> = (0..statuses.len()).collect();
    let priority_for = |i: usize| -> u32 {
        caller_priorities
            .and_then(|p| p.get(i).copied())
            .unwrap_or(u32::MAX)
    };

    match policy {
        TunnelUrlSortPolicy::None => {}
        TunnelUrlSortPolicy::ReachableFirst => {
            idx.sort_by(|&a, &b| {
                state_rank(statuses[a].state)
                    .cmp(&state_rank(statuses[b].state))
                    .then_with(|| a.cmp(&b))
            });
        }
        TunnelUrlSortPolicy::RttAscending => {
            idx.sort_by(|&a, &b| {
                state_rank(statuses[a].state)
                    .cmp(&state_rank(statuses[b].state))
                    .then_with(|| {
                        let same_scheme = statuses[a].scheme == statuses[b].scheme;
                        if same_scheme && statuses[a].state == TunnelUrlState::Reachable {
                            cmp_optional_rtt(statuses[a].rtt_ms, statuses[b].rtt_ms)
                        } else {
                            Ordering::Equal
                        }
                    })
                    .then_with(|| a.cmp(&b))
            });
        }
        TunnelUrlSortPolicy::CallerPriorityThenRtt => {
            idx.sort_by(|&a, &b| {
                priority_for(a)
                    .cmp(&priority_for(b))
                    .then_with(|| state_rank(statuses[a].state).cmp(&state_rank(statuses[b].state)))
                    .then_with(|| {
                        let same_scheme = statuses[a].scheme == statuses[b].scheme;
                        if same_scheme && statuses[a].state == TunnelUrlState::Reachable {
                            cmp_optional_rtt(statuses[a].rtt_ms, statuses[b].rtt_ms)
                        } else {
                            Ordering::Equal
                        }
                    })
                    .then_with(|| a.cmp(&b))
            });
        }
    }

    idx.into_iter()
        .filter(|&i| include_unsupported || statuses[i].state != TunnelUrlState::Unsupported)
        .map(|i| statuses[i].normalized_url.clone())
        .collect()
}

// State priority for sorting. Lower wins.
//   0: Reachable (with or without RTT — RTT compared in second key)
//   1: Unknown / Probing (information missing)
//   2: Unreachable (definitive failure)
//   3: Unsupported (sinks last)
fn state_rank(s: TunnelUrlState) -> u8 {
    match s {
        TunnelUrlState::Reachable => 0,
        TunnelUrlState::Unknown | TunnelUrlState::Probing => 1,
        TunnelUrlState::Unreachable => 2,
        TunnelUrlState::Unsupported => 3,
    }
}

// `Reachable + rtt = Some` < `Reachable + rtt = None`
fn cmp_optional_rtt(a: Option<u64>, b: Option<u64>) -> Ordering {
    match (a, b) {
        (Some(x), Some(y)) => x.cmp(&y),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

pub(crate) fn parse_url_for_query(raw: &str) -> TunnelResult<Url> {
    Url::parse(raw).map_err(|e| TunnelError::UrlParseError(raw.to_string(), e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[test]
    fn normalize_lowercases_scheme_and_host() {
        let a = normalize_tunnel_url(&parse("RTCP://Device.Dev.DID/:80"));
        let b = normalize_tunnel_url(&parse("rtcp://device.dev.did/:80"));
        assert_eq!(a, b);
    }

    #[test]
    fn normalize_drops_fragment_keeps_path() {
        let a = normalize_tunnel_url(&parse("rtcp://h/p#x"));
        let b = normalize_tunnel_url(&parse("rtcp://h/p"));
        assert_eq!(a, b);
        // empty path vs "/" not collapsed
        let c = normalize_tunnel_url(&parse("rtcp://h"));
        let d = normalize_tunnel_url(&parse("rtcp://h/"));
        assert_ne!(c, d);
    }

    #[test]
    fn normalize_sorts_query_params() {
        let a = normalize_tunnel_url(&parse("rtcp://h/?b=2&a=1"));
        let b = normalize_tunnel_url(&parse("rtcp://h/?a=1&b=2"));
        assert_eq!(a, b);
    }

    #[test]
    fn normalize_preserves_userinfo() {
        let a = normalize_tunnel_url(&parse("socks://u:p@h:1080/x"));
        let b = normalize_tunnel_url(&parse("socks://h:1080/x"));
        assert_ne!(a, b);
    }

    #[test]
    fn mask_hides_userinfo() {
        let m = mask_tunnel_url(&parse("socks://u:p@127.0.0.1:1080/x"));
        assert!(!m.contains("u:p"));
        assert!(m.contains("127.0.0.1"));
    }

    fn dummy_status(url: &str, state: TunnelUrlState, rtt: Option<u64>) -> TunnelUrlStatus {
        let u = parse(url);
        let nu = normalize_tunnel_url(&u);
        TunnelUrlStatus {
            url: mask_tunnel_url(&u),
            normalized_url: nu.clone(),
            scheme: u.scheme().to_string(),
            category: protocol_category_for_scheme(u.scheme()),
            state,
            rtt_ms: rtt,
            last_success_at_ms: None,
            last_failure_at_ms: None,
            failure_reason: None,
            source: TunnelUrlStatusSource::CachedProbe,
            cached: true,
            observed_at_ms: 0,
            expires_at_ms: None,
            runtime_tunnel_key: None,
        }
    }

    #[test]
    fn sort_reachable_first_keeps_unsupported_last() {
        let st = vec![
            dummy_status("rtcp://a/", TunnelUrlState::Unsupported, None),
            dummy_status("rtcp://b/", TunnelUrlState::Reachable, Some(20)),
            dummy_status("rtcp://c/", TunnelUrlState::Unreachable, None),
            dummy_status("rtcp://d/", TunnelUrlState::Unknown, None),
        ];
        let order = sort_urls(&st, TunnelUrlSortPolicy::ReachableFirst, None, true);
        assert_eq!(order[0], "rtcp://b/");
        assert_eq!(order[1], "rtcp://d/");
        assert_eq!(order[2], "rtcp://c/");
        assert_eq!(order[3], "rtcp://a/");
    }

    #[test]
    fn sort_rtt_ascending_only_within_same_scheme() {
        let st = vec![
            dummy_status("rtcp://a/", TunnelUrlState::Reachable, Some(50)),
            dummy_status("tcp://b/", TunnelUrlState::Reachable, Some(10)),
            dummy_status("rtcp://c/", TunnelUrlState::Reachable, Some(20)),
        ];
        let order = sort_urls(&st, TunnelUrlSortPolicy::RttAscending, None, true);
        // All Reachable -> rank tie. Cross-scheme RTT doesn't break the tie,
        // so original input order wins as the final tiebreaker. With sort
        // key returning Equal on cross-scheme, stable sort preserves the
        // input order: a (50), b (10), c (20). RTT only matters between
        // same-scheme pairs, where stable sort still preserves ordering.
        assert_eq!(order[0], "rtcp://a/");
    }

    #[test]
    fn sort_reachable_no_rtt_after_reachable_with_rtt() {
        let st = vec![
            dummy_status("rtcp://x/", TunnelUrlState::Reachable, None),
            dummy_status("rtcp://y/", TunnelUrlState::Reachable, Some(40)),
        ];
        let order = sort_urls(&st, TunnelUrlSortPolicy::RttAscending, None, true);
        assert_eq!(order[0], "rtcp://y/");
        assert_eq!(order[1], "rtcp://x/");
    }

    #[test]
    fn sort_excludes_unsupported_when_requested() {
        let st = vec![
            dummy_status("rtcp://a/", TunnelUrlState::Unsupported, None),
            dummy_status("rtcp://b/", TunnelUrlState::Reachable, Some(10)),
        ];
        let order = sort_urls(&st, TunnelUrlSortPolicy::ReachableFirst, None, false);
        assert_eq!(order.len(), 1);
        assert_eq!(order[0], "rtcp://b/");
    }

    #[test]
    fn sort_caller_priority_then_rtt() {
        let st = vec![
            dummy_status("rtcp://a/", TunnelUrlState::Reachable, Some(10)),
            dummy_status("rtcp://b/", TunnelUrlState::Reachable, Some(50)),
        ];
        let order = sort_urls(
            &st,
            TunnelUrlSortPolicy::CallerPriorityThenRtt,
            Some(&[1, 0]),
            true,
        );
        // b has higher priority (lower number) so it wins despite higher RTT
        assert_eq!(order[0], "rtcp://b/");
        assert_eq!(order[1], "rtcp://a/");
    }

    #[test]
    fn ttl_for_state() {
        let cfg = TunnelStatusStoreConfig::default();
        assert_eq!(cfg.ttl_for(TunnelUrlState::Reachable), DEFAULT_REACHABLE_TTL_MS);
        assert_eq!(cfg.ttl_for(TunnelUrlState::Unreachable), DEFAULT_UNREACHABLE_TTL_MS);
        assert_eq!(cfg.ttl_for(TunnelUrlState::Unknown), DEFAULT_UNKNOWN_TTL_MS);
        assert_eq!(cfg.ttl_for(TunnelUrlState::Unsupported), DEFAULT_UNSUPPORTED_TTL_MS);
    }
}
