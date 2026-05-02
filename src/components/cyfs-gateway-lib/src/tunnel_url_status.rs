use crate::tunnel_mgr::ProtocolCategory;
use crate::{TunnelError, TunnelResult, get_protocol_category};
use async_trait::async_trait;
pub use cyfs_gateway_api::{TunnelProbeOptions, TunnelUrlSortPolicy};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use url::Url;

const DEFAULT_REACHABLE_TTL_MS: u64 = 30_000;
const DEFAULT_UNKNOWN_TTL_MS: u64 = 10_000;
const DEFAULT_UNREACHABLE_TTL_MS: u64 = 5_000;
const DEFAULT_UNSUPPORTED_TTL_MS: u64 = 60_000;
const DEFAULT_MAX_MEMORY_HISTORY_ENTRIES: usize = 10_000;
const DEFAULT_PROBE_CONCURRENCY: usize = 32;
const DEFAULT_RECENT_RTT_CAP: usize = 8;

/// Snapshot state of a Tunnel URL at a point in time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
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

/// Unified failure-reason classification used by both business-connect
/// writeback (§6.7.3 of `forward机制升级需求.md`) and protocol probers.
/// Prober failure_reason strings should start with the canonical
/// `as_str()` prefix so that grep/dashboards can compare business and
/// probe signals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TunnelFailureReason {
    PreConnectDns,
    PreConnectRoute,
    ConnectRefused,
    ConnectTimeout,
    TlsHandshake,
    TunnelOpen,
    UnsupportedScheme,
    Other,
}

impl TunnelFailureReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            TunnelFailureReason::PreConnectDns => "pre_connect_dns",
            TunnelFailureReason::PreConnectRoute => "pre_connect_route",
            TunnelFailureReason::ConnectRefused => "connect_refused",
            TunnelFailureReason::ConnectTimeout => "connect_timeout",
            TunnelFailureReason::TlsHandshake => "tls_handshake",
            TunnelFailureReason::TunnelOpen => "tunnel_open",
            TunnelFailureReason::UnsupportedScheme => "unsupported_scheme",
            TunnelFailureReason::Other => "other",
        }
    }

    /// Compose a `failure_reason` string suitable for `TunnelUrlStatus`.
    /// Always prefixed with the canonical category so dashboards can
    /// `starts_with` to bucket entries; an optional detail follows after
    /// `: `.
    pub fn format_reason(&self, detail: Option<&str>) -> String {
        match detail {
            Some(d) if !d.is_empty() => format!("{}: {}", self.as_str(), d),
            _ => self.as_str().to_string(),
        }
    }
}

/// One observation of a Tunnel URL status.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
            TunnelUrlState::Unsupported | TunnelUrlState::Unknown | TunnelUrlState::Probing => {}
        }
        self.current = status;
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
        // Persistence defaults to ON so a Gateway restart can reuse
        // recent RTT/success-rate data (per requirement §8.1 + §16
        // verification "URL history 默认落盘"). With `persist_path =
        // None` the flush/load steps are no-ops, so callers must set a
        // path to actually use disk; flipping the default still matters
        // because production wiring respects the flag.
        Self {
            enable_persist: true,
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

/// Redact userinfo from a normalized URL string. Persisted snapshots
/// must not retain plaintext credentials (§11 + §8.1). The output keeps
/// the scheme/host/path/query stable so it remains a valid lookup key
/// for non-userinfo URLs; URLs with userinfo will load back keyed by
/// the redacted form, which is the intended trade-off (we lose
/// per-identity caching across restarts but never leak credentials).
pub fn redact_url_for_persist(s: &str) -> String {
    // Find scheme separator.
    let scheme_end = match s.find("://") {
        Some(i) => i + 3,
        None => return s.to_string(),
    };
    let after_scheme = &s[scheme_end..];
    // Authority ends at first `/`, `?`, or `#`.
    let auth_end = after_scheme
        .find(|c: char| c == '/' || c == '?' || c == '#')
        .unwrap_or(after_scheme.len());
    let authority = &after_scheme[..auth_end];
    let rest = &after_scheme[auth_end..];
    let host_part = match authority.rfind('@') {
        Some(i) => &authority[i + 1..],
        None => authority,
    };
    let mut out = String::with_capacity(s.len());
    out.push_str(&s[..scheme_end]);
    if authority != host_part {
        out.push_str("***@");
    }
    out.push_str(host_part);
    out.push_str(rest);
    out
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

    // Query: sort by raw key, preserve original percent-encoding so that
    // values containing `%26` / `%3D` / nested URLs round-trip unchanged.
    // Splitting the raw query string (vs. `query_pairs()` which decodes)
    // is what makes this reversible — the requirement explicitly asks
    // for stable ordering without breaking nested-URL semantics.
    let query_canon = match url.query() {
        Some(raw) if raw.is_empty() => String::from("?"),
        Some(raw) => {
            let mut parts: Vec<(usize, &str, &str)> = raw
                .split('&')
                .enumerate()
                .map(|(idx, part)| {
                    let (k, v) = match part.find('=') {
                        Some(i) => (&part[..i], &part[i..]), // include '='
                        None => (part, ""),
                    };
                    (idx, k, v)
                })
                .collect();
            // Stable sort by raw key bytes; entries with the same key keep
            // their original input order via the index tiebreaker.
            parts.sort_by(|a, b| {
                a.1.as_bytes()
                    .cmp(b.1.as_bytes())
                    .then_with(|| a.0.cmp(&b.0))
            });
            let mut buf = String::with_capacity(raw.len() + 1);
            buf.push('?');
            for (i, (_, k, v)) in parts.iter().enumerate() {
                if i > 0 {
                    buf.push('&');
                }
                buf.push_str(k);
                buf.push_str(v);
            }
            buf
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
pub fn unknown_status(
    url: &Url,
    normalized: &str,
    now_ms: u64,
    source: TunnelUrlStatusSource,
) -> TunnelUrlStatus {
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
///
/// To stay total-ordered across mixed-scheme inputs, RTT-aware policies
/// group entries by scheme using each scheme's first-appearance index in
/// the input. Within a scheme group the comparator falls through to RTT;
/// across groups callers see their original scheme order preserved. This
/// avoids the transitivity violation that arises from emitting `Equal`
/// for every cross-scheme pair while still ranking same-scheme pairs.
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

    // Build a stable scheme → first-appearance-index map. Comparing two
    // entries by their scheme group (rather than scheme name) keeps the
    // output deterministic and tied to caller-supplied input order.
    let mut scheme_first: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for (i, s) in statuses.iter().enumerate() {
        scheme_first.entry(s.scheme.as_str()).or_insert(i);
    }
    let scheme_group = |i: usize| -> usize {
        scheme_first
            .get(statuses[i].scheme.as_str())
            .copied()
            .unwrap_or(usize::MAX)
    };
    // Sort key for RTT under a Reachable state: Some(rtt) < None < non-Reachable.
    // Wrapped into u128 so the whole tuple stays a total Ord without
    // needing custom comparator branches.
    let rtt_sort_key = |i: usize| -> u128 {
        match (statuses[i].state, statuses[i].rtt_ms) {
            (TunnelUrlState::Reachable, Some(rtt)) => rtt as u128,
            (TunnelUrlState::Reachable, None) => (u64::MAX as u128) + 1,
            _ => (u64::MAX as u128) + 2,
        }
    };

    match policy {
        TunnelUrlSortPolicy::None => {}
        TunnelUrlSortPolicy::ReachableFirst => {
            idx.sort_by_key(|&i| (state_rank(statuses[i].state) as u32, i as u32));
        }
        TunnelUrlSortPolicy::RttAscending => {
            idx.sort_by(|&a, &b| {
                state_rank(statuses[a].state)
                    .cmp(&state_rank(statuses[b].state))
                    .then_with(|| scheme_group(a).cmp(&scheme_group(b)))
                    .then_with(|| rtt_sort_key(a).cmp(&rtt_sort_key(b)))
                    .then_with(|| a.cmp(&b))
            });
        }
        TunnelUrlSortPolicy::CallerPriorityThenRtt => {
            idx.sort_by(|&a, &b| {
                priority_for(a)
                    .cmp(&priority_for(b))
                    .then_with(|| state_rank(statuses[a].state).cmp(&state_rank(statuses[b].state)))
                    .then_with(|| scheme_group(a).cmp(&scheme_group(b)))
                    .then_with(|| rtt_sort_key(a).cmp(&rtt_sort_key(b)))
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
    fn normalize_preserves_query_percent_encoding() {
        // Values containing `%26`, `%3D`, or nested URLs must round-trip
        // unchanged — decoding+rejoining would corrupt nested URL boundaries
        // (e.g. `relay=rtcp%3A%2F%2Fpeer%2F%3A80` would become
        // `relay=rtcp://peer/:80` with extra `&`/`=` characters appearing
        // inside the value, breaking the canonical key).
        let raw = "rtcp://h/?relay=rtcp%3A%2F%2Fpeer%2F%3A80&token=a%26b%3Dc";
        let n = normalize_tunnel_url(&parse(raw));
        assert!(n.contains("relay=rtcp%3A%2F%2Fpeer%2F%3A80"));
        assert!(n.contains("token=a%26b%3Dc"));
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
        // Cross-scheme uses caller order via first-appearance index:
        // rtcp appears first so its group sorts before tcp. Within rtcp,
        // RTT decides: c (20) < a (50). The tcp entry's lower RTT does
        // not let it overtake any rtcp entry (cross-scheme RTT is
        // intentionally not comparable here).
        assert_eq!(order, vec!["rtcp://c/", "rtcp://a/", "tcp://b/"]);
    }

    #[test]
    fn sort_rtt_ascending_is_total_order_under_mixed_scheme() {
        // Regression: a non-total comparator can violate transitivity for
        // mixed-scheme inputs, leading sort_by to leave reachable URLs in
        // an unstable interleaved order. Verify that repeating the sort on
        // the previous output yields the same sequence.
        let st = vec![
            dummy_status("rtcp://r1/", TunnelUrlState::Reachable, Some(80)),
            dummy_status("tcp://t1/", TunnelUrlState::Reachable, Some(5)),
            dummy_status("rtcp://r2/", TunnelUrlState::Reachable, Some(10)),
            dummy_status("tcp://t2/", TunnelUrlState::Reachable, Some(15)),
            dummy_status("rtcp://r3/", TunnelUrlState::Reachable, Some(30)),
        ];
        let order1 = sort_urls(&st, TunnelUrlSortPolicy::RttAscending, None, true);
        // Build a permuted statuses list matching `order1` and verify the
        // sort is idempotent — a hallmark of total ordering.
        let mut by_url: std::collections::HashMap<String, TunnelUrlStatus> = st
            .into_iter()
            .map(|s| (s.normalized_url.clone(), s))
            .collect();
        let permuted: Vec<TunnelUrlStatus> =
            order1.iter().map(|u| by_url.remove(u).unwrap()).collect();
        let order2 = sort_urls(&permuted, TunnelUrlSortPolicy::RttAscending, None, true);
        assert_eq!(order1, order2);
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
    fn redact_strips_userinfo() {
        assert_eq!(
            redact_url_for_persist("socks://u:p@127.0.0.1:1080/example.com:443"),
            "socks://***@127.0.0.1:1080/example.com:443"
        );
        // No userinfo → unchanged.
        assert_eq!(
            redact_url_for_persist("rtcp://device.dev.did/:80"),
            "rtcp://device.dev.did/:80"
        );
    }

    #[test]
    fn ttl_for_state() {
        let cfg = TunnelStatusStoreConfig::default();
        assert_eq!(
            cfg.ttl_for(TunnelUrlState::Reachable),
            DEFAULT_REACHABLE_TTL_MS
        );
        assert_eq!(
            cfg.ttl_for(TunnelUrlState::Unreachable),
            DEFAULT_UNREACHABLE_TTL_MS
        );
        assert_eq!(cfg.ttl_for(TunnelUrlState::Unknown), DEFAULT_UNKNOWN_TTL_MS);
        assert_eq!(
            cfg.ttl_for(TunnelUrlState::Unsupported),
            DEFAULT_UNSUPPORTED_TTL_MS
        );
    }
}
