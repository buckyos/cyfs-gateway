use std::time::Duration;

use base64::Engine;
use serde::{Deserialize, Serialize};

pub const FORWARD_GROUP_CMD: &str = "forward-group";
pub const FORWARD_CMD: &str = "forward";

pub const DEFAULT_MAX_FAILS: u32 = 1;
pub const DEFAULT_FAIL_TIMEOUT_MS: u64 = 10_000;
pub const DEFAULT_TRIES: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BalanceMethod {
    RoundRobin,
    IpHash,
}

impl Default for BalanceMethod {
    fn default() -> Self {
        BalanceMethod::RoundRobin
    }
}

impl BalanceMethod {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "round_robin" | "rr" => Ok(BalanceMethod::RoundRobin),
            "ip_hash" => Ok(BalanceMethod::IpHash),
            _ => Err(format!(
                "unsupported balance method '{}': expected round_robin or ip_hash",
                s
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NextUpstreamCondition {
    Error,
    Timeout,
}

impl NextUpstreamCondition {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "error" => Ok(NextUpstreamCondition::Error),
            "timeout" => Ok(NextUpstreamCondition::Timeout),
            "off" => Err("'off' is not a condition; pass next_upstream=off instead".to_string()),
            _ => Err(format!(
                "unsupported next_upstream condition '{}': expected error or timeout",
                s
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct NextUpstreamPolicy {
    pub conditions: Vec<NextUpstreamCondition>,
    #[serde(default)]
    pub tries: u32,
    #[serde(default, with = "duration_ms_opt")]
    pub timeout: Option<Duration>,
}

impl NextUpstreamPolicy {
    pub fn off() -> Self {
        Self {
            conditions: Vec::new(),
            tries: 1,
            timeout: None,
        }
    }

    pub fn is_enabled(&self) -> bool {
        !self.conditions.is_empty() && self.tries > 1
    }

    pub fn allows(&self, cond: NextUpstreamCondition) -> bool {
        self.conditions.contains(&cond)
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
}

impl ForwardPlan {
    /// Build a plan equivalent to `forward "<url>"`: a single candidate, no retry.
    pub fn single_url(url: impl Into<String>) -> Self {
        Self {
            group: None,
            balance: BalanceMethod::RoundRobin,
            next_upstream: NextUpstreamPolicy::off(),
            candidates: vec![ForwardTarget::new(url)],
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
            },
            candidates: vec![
                ForwardTarget::new("rtcp://ood1.example.zone/:3202").with_weight(100),
                ForwardTarget::new("rtcp://relay-a/ood1.example.zone/:3202")
                    .with_weight(100)
                    .as_backup(),
            ],
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
}
