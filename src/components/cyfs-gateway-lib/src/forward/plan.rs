use std::time::Duration;

use base64::Engine;
use serde::{Deserialize, Serialize};

pub const FORWARD_GROUP_CMD: &str = "forward-group";
pub const FORWARD_CMD: &str = "forward";

pub const DEFAULT_MAX_FAILS: u32 = 1;
pub const DEFAULT_FAIL_TIMEOUT_MS: u64 = 10_000;
pub const DEFAULT_TRIES: u32 = 1;
pub const DEFAULT_MAX_BODY_BUFFER_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum BalanceMethod {
    RoundRobin,
    IpHash,
    /// `hash $key`. Uses the literal string `key` to pick a candidate by
    /// weighted modulo. The key value is captured at process-chain time.
    Hash { key: String },
    /// `consistent_hash $key`. Like `Hash`, but tolerates candidate set
    /// changes by mapping into a hashed ring.
    ConsistentHash { key: String },
    /// Pick the candidate with the lowest observed RTT according to the
    /// `tunnel_mgr` URL history (§4.1, §6.7). Selection happens at the
    /// executor when it has access to a `TunnelManager`.
    LeastTime,
}

impl Default for BalanceMethod {
    fn default() -> Self {
        BalanceMethod::RoundRobin
    }
}

impl BalanceMethod {
    /// Parse a balance method spec. The spec follows the Nginx-style
    /// keyword form: `round_robin`, `ip_hash`, `least_time`, or
    /// `hash:<key>` / `consistent_hash:<key>`.
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "round_robin" | "rr" => Ok(BalanceMethod::RoundRobin),
            "ip_hash" => Ok(BalanceMethod::IpHash),
            "least_time" => Ok(BalanceMethod::LeastTime),
            other => {
                if let Some(rest) = other.strip_prefix("hash:") {
                    if rest.is_empty() {
                        return Err("hash balance method requires a key".to_string());
                    }
                    return Ok(BalanceMethod::Hash {
                        key: rest.to_string(),
                    });
                }
                if let Some(rest) = other.strip_prefix("consistent_hash:") {
                    if rest.is_empty() {
                        return Err("consistent_hash balance method requires a key".to_string());
                    }
                    return Ok(BalanceMethod::ConsistentHash {
                        key: rest.to_string(),
                    });
                }
                Err(format!(
                    "unsupported balance method '{}': expected round_robin, ip_hash, least_time, hash:<key>, or consistent_hash:<key>",
                    other
                ))
            }
        }
    }

    pub fn requires_tunnel_manager(&self) -> bool {
        matches!(self, BalanceMethod::LeastTime)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NextUpstreamCondition {
    Error,
    Timeout,
    /// Any 5xx HTTP status from the upstream. Mirrors Nginx's
    /// `proxy_next_upstream http_5xx`.
    Http5xx,
    /// Specific 5xx codes for finer control: `http_502`, `http_503`,
    /// `http_504`. We model the four most common ones explicitly so
    /// callers can opt into the safer subset (only retry on 502/504,
    /// which are typically connect-side faults at the upstream).
    Http502,
    Http503,
    Http504,
    /// Reserved for future use (e.g. malformed upstream response). Kept
    /// to avoid breaking the wire format when added.
    InvalidHeader,
    /// `non_idempotent`: when present, retry is allowed for
    /// non-idempotent methods too. Default is to retry only for
    /// idempotent methods (GET/HEAD/PUT/DELETE/OPTIONS/TRACE).
    NonIdempotent,
}

impl NextUpstreamCondition {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "error" => Ok(NextUpstreamCondition::Error),
            "timeout" => Ok(NextUpstreamCondition::Timeout),
            "http_5xx" => Ok(NextUpstreamCondition::Http5xx),
            "http_502" => Ok(NextUpstreamCondition::Http502),
            "http_503" => Ok(NextUpstreamCondition::Http503),
            "http_504" => Ok(NextUpstreamCondition::Http504),
            "invalid_header" => Ok(NextUpstreamCondition::InvalidHeader),
            "non_idempotent" => Ok(NextUpstreamCondition::NonIdempotent),
            "off" => Err("'off' is not a condition; pass next_upstream=off instead".to_string()),
            _ => Err(format!(
                "unsupported next_upstream condition '{}': expected one of error, timeout, http_5xx, http_502, http_503, http_504, invalid_header, non_idempotent",
                s
            )),
        }
    }

    /// True if this condition triggers retry on a connect-stage failure.
    pub fn is_connect_failure(&self) -> bool {
        matches!(self, NextUpstreamCondition::Error | NextUpstreamCondition::Timeout)
    }

    /// True if this condition triggers retry on an HTTP response
    /// status from a successfully connected upstream.
    pub fn is_http_status(&self) -> bool {
        matches!(
            self,
            NextUpstreamCondition::Http5xx
                | NextUpstreamCondition::Http502
                | NextUpstreamCondition::Http503
                | NextUpstreamCondition::Http504
                | NextUpstreamCondition::InvalidHeader
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct NextUpstreamPolicy {
    pub conditions: Vec<NextUpstreamCondition>,
    #[serde(default)]
    pub tries: u32,
    #[serde(default, with = "duration_ms_opt")]
    pub timeout: Option<Duration>,
    /// Per-attempt body buffering cap. When the request body exceeds
    /// this many bytes the body cannot be replayed, so HTTP-status retry
    /// is suppressed for that request even if the policy would allow it.
    /// Connect-stage retry still works because no body has been sent.
    /// `0` means no buffering at all (HTTP-status retry disabled).
    #[serde(default)]
    pub max_body_buffer_bytes: u64,
}

impl NextUpstreamPolicy {
    pub fn off() -> Self {
        Self {
            conditions: Vec::new(),
            tries: 1,
            timeout: None,
            max_body_buffer_bytes: 0,
        }
    }

    pub fn is_enabled(&self) -> bool {
        !self.conditions.is_empty() && self.tries > 1
    }

    pub fn allows(&self, cond: NextUpstreamCondition) -> bool {
        if self.conditions.contains(&cond) {
            return true;
        }
        // `Http5xx` is an umbrella that implies the specific 5xx codes.
        if self.conditions.contains(&NextUpstreamCondition::Http5xx)
            && matches!(
                cond,
                NextUpstreamCondition::Http502
                    | NextUpstreamCondition::Http503
                    | NextUpstreamCondition::Http504
            )
        {
            return true;
        }
        false
    }

    /// True if any HTTP status condition is enabled. Used by the HTTP
    /// executor to decide whether to bother buffering the body.
    pub fn any_http_status(&self) -> bool {
        self.conditions.iter().any(|c| c.is_http_status())
    }

    /// True if the policy authorizes retry for non-idempotent methods.
    /// Defaults to false to mirror Nginx's safer behavior.
    pub fn allow_non_idempotent(&self) -> bool {
        self.conditions
            .contains(&NextUpstreamCondition::NonIdempotent)
    }

    /// Whether retry should fire for the given upstream HTTP status.
    pub fn matches_http_status(&self, status: u16) -> bool {
        match status {
            502 if self.allows(NextUpstreamCondition::Http502) => true,
            503 if self.allows(NextUpstreamCondition::Http503) => true,
            504 if self.allows(NextUpstreamCondition::Http504) => true,
            500..=599 if self.allows(NextUpstreamCondition::Http5xx) => true,
            _ => false,
        }
    }

    pub fn parse_conditions(spec: &str) -> Result<(Vec<NextUpstreamCondition>, bool), String> {
        let trimmed = spec.trim();
        if trimmed.is_empty() {
            return Ok((Vec::new(), true));
        }
        if trimmed.eq_ignore_ascii_case("off") {
            return Ok((Vec::new(), true));
        }
        let mut out = Vec::new();
        for part in trimmed.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            out.push(NextUpstreamCondition::parse(part)?);
        }
        Ok((out, false))
    }
}

/// Idempotency classification used to gate HTTP-status retry. Bodies for
/// methods classified as `NotIdempotent` are only replayed when the
/// policy explicitly opted in via `non_idempotent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethodClass {
    Idempotent,
    NotIdempotent,
}

impl HttpMethodClass {
    /// RFC 7231 §4.2.2 — the safe / idempotent methods. Anything outside
    /// this list is treated as non-idempotent (including POST, PATCH,
    /// custom verbs).
    pub fn classify(method: &str) -> Self {
        let upper = method.to_ascii_uppercase();
        match upper.as_str() {
            "GET" | "HEAD" | "PUT" | "DELETE" | "OPTIONS" | "TRACE" => HttpMethodClass::Idempotent,
            _ => HttpMethodClass::NotIdempotent,
        }
    }

    pub fn is_idempotent(&self) -> bool {
        matches!(self, HttpMethodClass::Idempotent)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForwardTarget {
    pub url: String,
    #[serde(default = "default_weight")]
    pub weight: u32,
    #[serde(default)]
    pub backup: bool,
    #[serde(default = "default_max_fails")]
    pub max_fails: u32,
    #[serde(default = "default_fail_timeout", with = "duration_ms")]
    pub fail_timeout: Duration,
    /// Optional logical server / provider id, populated when the
    /// candidate originated from a `ForwardServer.routes[]` flatten.
    /// The selector uses this to keep all routes of one provider
    /// adjacent in the attempt order.
    #[serde(default)]
    pub server_id: Option<String>,
}

fn default_weight() -> u32 {
    1
}
fn default_max_fails() -> u32 {
    DEFAULT_MAX_FAILS
}
fn default_fail_timeout() -> Duration {
    Duration::from_millis(DEFAULT_FAIL_TIMEOUT_MS)
}

impl ForwardTarget {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            weight: 1,
            backup: false,
            max_fails: DEFAULT_MAX_FAILS,
            fail_timeout: default_fail_timeout(),
            server_id: None,
        }
    }

    pub fn with_weight(mut self, weight: u32) -> Self {
        self.weight = weight;
        self
    }

    pub fn as_backup(mut self) -> Self {
        self.backup = true;
        self
    }

    pub fn with_server_id(mut self, sid: impl Into<String>) -> Self {
        self.server_id = Some(sid.into());
        self
    }
}

/// Provider-first routing model from §5 of the design doc:
/// `hash key -> server -> route`. A `ForwardServer` is one logical
/// provider with one weight; its `routes` are alternate transport
/// addresses (direct, relay, backup) for the same provider. The
/// executor expands this to a flat candidate list before dispatching,
/// but failure between routes of the same server stays inside that
/// server unless `next_upstream.server: on` is set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForwardServer {
    pub id: String,
    #[serde(default = "default_weight")]
    pub weight: u32,
    #[serde(default)]
    pub backup: bool,
    pub routes: Vec<ForwardTarget>,
    #[serde(default = "default_max_fails")]
    pub max_fails: u32,
    #[serde(default = "default_fail_timeout", with = "duration_ms")]
    pub fail_timeout: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ProviderRouteRetry {
    /// Routes inside one server failover automatically; failure across
    /// servers needs explicit `next_upstream.server: on`. This is the
    /// safe default, suitable for stateful services.
    #[default]
    RoutesOnly,
    /// Routes failover, and on full server exhaustion attempts the
    /// next server too. Suitable for stateless service pools.
    AcrossServers,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ProviderPolicy {
    /// How retry crosses the server / route boundary.
    #[serde(default)]
    pub retry_scope: ProviderRouteRetry,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForwardPlan {
    #[serde(default)]
    pub group: Option<String>,
    #[serde(default)]
    pub balance: BalanceMethod,
    #[serde(default)]
    pub next_upstream: NextUpstreamPolicy,
    pub candidates: Vec<ForwardTarget>,
    /// Resolved value of the hash key, captured at process-chain time
    /// so the selector doesn't need access to the request env. Only
    /// meaningful when `balance` is `Hash` or `ConsistentHash`.
    #[serde(default)]
    pub hash_key_value: Option<String>,
    /// Optional provider-first servers (§5). When present the executor
    /// uses these to constrain retry crossing. The flat `candidates`
    /// list is still authoritative for execution order; producers must
    /// keep them consistent (servers expand into candidates).
    #[serde(default)]
    pub servers: Vec<ForwardServer>,
    #[serde(default)]
    pub provider_policy: ProviderPolicy,
}

impl ForwardPlan {
    /// Build a plan equivalent to `forward "<url>"`: a single candidate, no retry.
    pub fn single_url(url: impl Into<String>) -> Self {
        Self {
            group: None,
            balance: BalanceMethod::RoundRobin,
            next_upstream: NextUpstreamPolicy::off(),
            candidates: vec![ForwardTarget::new(url)],
            hash_key_value: None,
            servers: Vec::new(),
            provider_policy: ProviderPolicy::default(),
        }
    }

    pub fn is_single_url(&self) -> bool {
        self.candidates.len() == 1
            && !self.next_upstream.is_enabled()
            && !self.candidates[0].backup
    }

    /// Encode to a single token suitable for embedding in a chain return string.
    /// Format: base64(JSON). The receiver uses `decode` to recover the plan.
    pub fn encode(&self) -> Result<String, String> {
        let json = serde_json::to_string(self)
            .map_err(|e| format!("encode forward plan: {}", e))?;
        Ok(base64::engine::general_purpose::STANDARD_NO_PAD.encode(json.as_bytes()))
    }

    pub fn decode(encoded: &str) -> Result<Self, String> {
        let bytes = base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(encoded.as_bytes())
            .map_err(|e| format!("decode forward plan base64: {}", e))?;
        let plan: ForwardPlan = serde_json::from_slice(&bytes)
            .map_err(|e| format!("decode forward plan json: {}", e))?;
        plan.validate()?;
        Ok(plan)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.candidates.is_empty() {
            return Err("forward plan has no candidates".to_string());
        }
        for c in &self.candidates {
            if c.url.is_empty() {
                return Err("forward plan candidate has empty url".to_string());
            }
            if c.weight == 0 {
                return Err(format!(
                    "forward plan candidate '{}' has zero weight",
                    c.url
                ));
            }
        }
        // hash variants require a captured key value or an empty string
        // (empty key produces a deterministic constant hash, which is
        // legal but worth noting in tests).
        match &self.balance {
            BalanceMethod::Hash { .. } | BalanceMethod::ConsistentHash { .. } => {
                if self.hash_key_value.is_none() {
                    return Err(
                        "hash / consistent_hash balance requires hash_key_value to be set"
                            .to_string(),
                    );
                }
            }
            _ => {}
        }
        for s in &self.servers {
            if s.id.is_empty() {
                return Err("forward server has empty id".to_string());
            }
            if s.routes.is_empty() {
                return Err(format!("forward server '{}' has no routes", s.id));
            }
        }
        Ok(())
    }

    /// Stable identity of this group, used as a key for failure state.
    /// Falls back to a content hash of the candidate set when no name is given.
    pub fn failure_state_key(&self) -> String {
        if let Some(name) = &self.group {
            return format!("named:{}", name);
        }
        let mut urls: Vec<&str> = self.candidates.iter().map(|c| c.url.as_str()).collect();
        urls.sort();
        let joined = urls.join("|");
        let digest = simple_hash(&joined);
        format!("auto:{:016x}", digest)
    }

    /// Flatten a provider-first server list into a flat candidate list,
    /// preserving server-id grouping so a downstream selector can keep
    /// routes of one provider adjacent in the attempt order.
    pub fn candidates_from_servers(servers: &[ForwardServer]) -> Vec<ForwardTarget> {
        let mut out = Vec::new();
        for s in servers {
            for r in &s.routes {
                let target = ForwardTarget {
                    url: r.url.clone(),
                    weight: if r.weight == 0 { s.weight } else { r.weight },
                    backup: s.backup || r.backup,
                    max_fails: r.max_fails,
                    fail_timeout: r.fail_timeout,
                    server_id: Some(s.id.clone()),
                };
                out.push(target);
            }
        }
        out
    }
}

fn simple_hash(s: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    s.hash(&mut h);
    h.finish()
}

mod duration_ms {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(d: &Duration, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        s.serialize_u64(d.as_millis() as u64)
    }

    pub fn deserialize<'de, D>(d: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let v = u64::deserialize(d)?;
        Ok(Duration::from_millis(v))
    }
}

mod duration_ms_opt {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(d: &Option<Duration>, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match d {
            Some(d) => s.serialize_some(&(d.as_millis() as u64)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(d: D) -> Result<Option<Duration>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let v = Option::<u64>::deserialize(d)?;
        Ok(v.map(Duration::from_millis))
    }
}

/// Parse a duration string like "10s", "500ms", "2m" or a bare integer (treated as ms).
pub fn parse_duration_str(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty duration".to_string());
    }
    let (num_part, unit) = if let Some(idx) = s.find(|c: char| !c.is_ascii_digit() && c != '.') {
        (&s[..idx], &s[idx..])
    } else {
        (s, "ms")
    };
    let value: f64 = num_part
        .parse()
        .map_err(|e| format!("invalid duration '{}': {}", s, e))?;
    if !value.is_finite() || value < 0.0 {
        return Err(format!("invalid duration '{}': must be non-negative", s));
    }
    let ms = match unit {
        "ms" | "" => value,
        "s" => value * 1_000.0,
        "m" => value * 60_000.0,
        "h" => value * 3_600_000.0,
        other => return Err(format!("unsupported duration unit '{}'", other)),
    };
    if !ms.is_finite() || ms > u64::MAX as f64 {
        return Err(format!("duration '{}' overflows", s));
    }
    Ok(Duration::from_millis(ms as u64))
}

/// Parse a byte-size string like "64KB", "1MB", "2048", "512K". Bare
/// integers are treated as bytes. Suffixes are case-insensitive and
/// must be one of K/KB, M/MB, G/GB.
pub fn parse_size_str(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty size".to_string());
    }
    let (num_part, unit) = if let Some(idx) = s.find(|c: char| !c.is_ascii_digit() && c != '.') {
        (&s[..idx], &s[idx..])
    } else {
        (s, "")
    };
    let value: f64 = num_part
        .parse()
        .map_err(|e| format!("invalid size '{}': {}", s, e))?;
    if !value.is_finite() || value < 0.0 {
        return Err(format!("invalid size '{}': must be non-negative", s));
    }
    let multiplier: f64 = match unit.to_ascii_lowercase().as_str() {
        "" | "b" => 1.0,
        "k" | "kb" => 1024.0,
        "m" | "mb" => 1024.0 * 1024.0,
        "g" | "gb" => 1024.0 * 1024.0 * 1024.0,
        other => return Err(format!("unsupported size unit '{}'", other)),
    };
    let total = value * multiplier;
    if !total.is_finite() || total > u64::MAX as f64 {
        return Err(format!("size '{}' overflows", s));
    }
    Ok(total as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_plan() {
        let plan = ForwardPlan {
            group: Some("control-panel".to_string()),
            balance: BalanceMethod::RoundRobin,
            next_upstream: NextUpstreamPolicy {
                conditions: vec![NextUpstreamCondition::Error, NextUpstreamCondition::Timeout],
                tries: 3,
                timeout: Some(Duration::from_secs(5)),
                max_body_buffer_bytes: 0,
            },
            candidates: vec![
                ForwardTarget::new("rtcp://ood1.example.zone/:3202").with_weight(100),
                ForwardTarget::new("rtcp://relay-a/ood1.example.zone/:3202")
                    .with_weight(100)
                    .as_backup(),
            ],
            hash_key_value: None,
            servers: Vec::new(),
            provider_policy: ProviderPolicy::default(),
        };
        let encoded = plan.encode().unwrap();
        let decoded = ForwardPlan::decode(&encoded).unwrap();
        assert_eq!(plan, decoded);
    }

    #[test]
    fn parse_duration_basic() {
        assert_eq!(parse_duration_str("10s").unwrap(), Duration::from_secs(10));
        assert_eq!(parse_duration_str("500ms").unwrap(), Duration::from_millis(500));
        assert_eq!(parse_duration_str("2m").unwrap(), Duration::from_secs(120));
        assert_eq!(parse_duration_str("250").unwrap(), Duration::from_millis(250));
        assert!(parse_duration_str("-1s").is_err());
        assert!(parse_duration_str("abc").is_err());
    }

    #[test]
    fn parse_size_basic() {
        assert_eq!(parse_size_str("64KB").unwrap(), 64 * 1024);
        assert_eq!(parse_size_str("1mb").unwrap(), 1024 * 1024);
        assert_eq!(parse_size_str("2048").unwrap(), 2048);
        assert_eq!(parse_size_str("512K").unwrap(), 512 * 1024);
        assert!(parse_size_str("-1").is_err());
        assert!(parse_size_str("3xb").is_err());
    }

    #[test]
    fn next_upstream_conditions_parse_off_and_list() {
        let (cs, off) = NextUpstreamPolicy::parse_conditions("off").unwrap();
        assert!(cs.is_empty());
        assert!(off);

        let (cs, _) = NextUpstreamPolicy::parse_conditions("error,timeout").unwrap();
        assert_eq!(
            cs,
            vec![NextUpstreamCondition::Error, NextUpstreamCondition::Timeout]
        );

        assert!(NextUpstreamPolicy::parse_conditions("error,foo").is_err());
    }

    #[test]
    fn next_upstream_status_conditions_parse() {
        let (cs, _) =
            NextUpstreamPolicy::parse_conditions("error,http_5xx,non_idempotent").unwrap();
        assert!(cs.contains(&NextUpstreamCondition::Http5xx));
        assert!(cs.contains(&NextUpstreamCondition::NonIdempotent));
    }

    #[test]
    fn http_5xx_implies_specific_codes() {
        let policy = NextUpstreamPolicy {
            conditions: vec![NextUpstreamCondition::Http5xx],
            tries: 3,
            timeout: None,
            max_body_buffer_bytes: 0,
        };
        assert!(policy.matches_http_status(502));
        assert!(policy.matches_http_status(503));
        assert!(policy.matches_http_status(504));
        assert!(policy.matches_http_status(500));
        assert!(!policy.matches_http_status(404));
    }

    #[test]
    fn explicit_http_502_does_not_match_503() {
        let policy = NextUpstreamPolicy {
            conditions: vec![NextUpstreamCondition::Http502],
            tries: 3,
            timeout: None,
            max_body_buffer_bytes: 0,
        };
        assert!(policy.matches_http_status(502));
        assert!(!policy.matches_http_status(503));
        assert!(!policy.matches_http_status(504));
    }

    #[test]
    fn http_method_class_classification() {
        assert!(HttpMethodClass::classify("GET").is_idempotent());
        assert!(HttpMethodClass::classify("HEAD").is_idempotent());
        assert!(HttpMethodClass::classify("PUT").is_idempotent());
        assert!(!HttpMethodClass::classify("POST").is_idempotent());
        assert!(!HttpMethodClass::classify("PATCH").is_idempotent());
        assert!(!HttpMethodClass::classify("FOO").is_idempotent());
    }

    #[test]
    fn balance_method_parse_hash_variants() {
        let m = BalanceMethod::parse("hash:$cookie_session_id").unwrap();
        assert!(matches!(m, BalanceMethod::Hash { .. }));
        let m = BalanceMethod::parse("consistent_hash:$user_id").unwrap();
        assert!(matches!(m, BalanceMethod::ConsistentHash { .. }));
        let m = BalanceMethod::parse("least_time").unwrap();
        assert!(matches!(m, BalanceMethod::LeastTime));
        assert!(BalanceMethod::parse("hash:").is_err());
        assert!(BalanceMethod::parse("consistent_hash:").is_err());
    }

    #[test]
    fn single_url_helper() {
        let plan = ForwardPlan::single_url("http://127.0.0.1:80");
        assert!(plan.is_single_url());
        assert_eq!(plan.candidates.len(), 1);
        assert_eq!(plan.candidates[0].url, "http://127.0.0.1:80");
    }

    #[test]
    fn validate_rejects_zero_weight() {
        let mut plan = ForwardPlan::single_url("http://x");
        plan.candidates[0].weight = 0;
        assert!(plan.validate().is_err());
    }

    #[test]
    fn validate_requires_hash_key_for_hash_methods() {
        let mut plan = ForwardPlan::single_url("http://x");
        plan.balance = BalanceMethod::Hash {
            key: "$cookie_session_id".to_string(),
        };
        assert!(plan.validate().is_err());
        plan.hash_key_value = Some("user-42".to_string());
        assert!(plan.validate().is_ok());
    }

    #[test]
    fn failure_state_key_is_stable_for_unnamed_group() {
        let p1 = ForwardPlan {
            group: None,
            candidates: vec![
                ForwardTarget::new("http://a"),
                ForwardTarget::new("http://b"),
            ],
            ..ForwardPlan::single_url("http://a")
        };
        let p2 = ForwardPlan {
            group: None,
            candidates: vec![
                ForwardTarget::new("http://b"),
                ForwardTarget::new("http://a"),
            ],
            ..ForwardPlan::single_url("http://b")
        };
        assert_eq!(p1.failure_state_key(), p2.failure_state_key());
    }

    #[test]
    fn candidates_from_servers_flattens_routes() {
        let servers = vec![
            ForwardServer {
                id: "node-a".to_string(),
                weight: 100,
                backup: false,
                max_fails: 1,
                fail_timeout: Duration::from_secs(10),
                routes: vec![
                    ForwardTarget::new("rtcp://node-a.example.zone/:7001"),
                    ForwardTarget::new("rtcp://relay-a/node-a.example.zone/:7001").as_backup(),
                ],
            },
            ForwardServer {
                id: "node-b".to_string(),
                weight: 100,
                backup: false,
                max_fails: 1,
                fail_timeout: Duration::from_secs(10),
                routes: vec![ForwardTarget::new("rtcp://node-b.example.zone/:7001")],
            },
        ];
        let flat = ForwardPlan::candidates_from_servers(&servers);
        assert_eq!(flat.len(), 3);
        assert_eq!(flat[0].server_id.as_deref(), Some("node-a"));
        assert!(!flat[0].backup);
        assert_eq!(flat[1].server_id.as_deref(), Some("node-a"));
        assert!(flat[1].backup);
        assert_eq!(flat[2].server_id.as_deref(), Some("node-b"));
    }
}
