use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Per-(group, candidate) failure tracking.
///
/// This is the "max_fails / fail_timeout" state described in
/// `forward机制升级需求.md` §6.6. Scope is intentionally process-local; it
/// does not persist and does not feed tunnel_mgr URL history (that lives in
/// §6.7 and is intentionally a separate, global view).
#[derive(Debug, Clone, Copy)]
pub struct CandidateState {
    pub fail_count: u32,
    pub last_failure_at: Option<Instant>,
    pub ejected_until: Option<Instant>,
}

impl Default for CandidateState {
    fn default() -> Self {
        Self {
            fail_count: 0,
            last_failure_at: None,
            ejected_until: None,
        }
    }
}

impl CandidateState {
    pub fn is_ejected(&self, now: Instant) -> bool {
        match self.ejected_until {
            Some(deadline) => now < deadline,
            None => false,
        }
    }
}

#[derive(Debug, Default)]
pub struct ForwardFailureRegistry {
    inner: Mutex<HashMap<String, CandidateState>>,
}

impl ForwardFailureRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn global() -> &'static ForwardFailureRegistry {
        static REGISTRY: OnceLock<ForwardFailureRegistry> = OnceLock::new();
        REGISTRY.get_or_init(ForwardFailureRegistry::new)
    }

    fn make_key(group_key: &str, candidate_url: &str) -> String {
        let mut s = String::with_capacity(group_key.len() + 1 + candidate_url.len());
        s.push_str(group_key);
        s.push('|');
        s.push_str(candidate_url);
        s
    }

    pub fn snapshot(&self, group_key: &str, candidate_url: &str) -> CandidateState {
        let key = Self::make_key(group_key, candidate_url);
        let guard = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        guard.get(&key).copied().unwrap_or_default()
    }

    pub fn is_ejected(&self, group_key: &str, candidate_url: &str, now: Instant) -> bool {
        self.snapshot(group_key, candidate_url).is_ejected(now)
    }

    pub fn record_success(&self, group_key: &str, candidate_url: &str) {
        let key = Self::make_key(group_key, candidate_url);
        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        guard.remove(&key);
    }

    /// Record one connect-stage failure for the candidate.
    /// When `fail_count` reaches `max_fails`, the candidate is marked
    /// ejected for `fail_timeout`.
    pub fn record_failure(
        &self,
        group_key: &str,
        candidate_url: &str,
        max_fails: u32,
        fail_timeout: Duration,
    ) {
        let key = Self::make_key(group_key, candidate_url);
        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let now = Instant::now();
        let entry = guard.entry(key).or_insert_with(CandidateState::default);
        // Clear stale ejection window so counts don't accumulate forever.
        if let Some(deadline) = entry.ejected_until {
            if now >= deadline {
                entry.fail_count = 0;
                entry.ejected_until = None;
            }
        }
        entry.fail_count = entry.fail_count.saturating_add(1);
        entry.last_failure_at = Some(now);
        let threshold = max_fails.max(1);
        if entry.fail_count >= threshold {
            entry.ejected_until = Some(now + fail_timeout);
        }
    }

    #[cfg(test)]
    pub fn clear(&self) {
        if let Ok(mut g) = self.inner.lock() {
            g.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ejects_after_max_fails() {
        let reg = ForwardFailureRegistry::new();
        reg.record_failure("g", "url", 2, Duration::from_secs(60));
        assert!(!reg.is_ejected("g", "url", Instant::now()));
        reg.record_failure("g", "url", 2, Duration::from_secs(60));
        assert!(reg.is_ejected("g", "url", Instant::now()));
    }

    #[test]
    fn success_clears_state() {
        let reg = ForwardFailureRegistry::new();
        reg.record_failure("g", "url", 1, Duration::from_secs(60));
        assert!(reg.is_ejected("g", "url", Instant::now()));
        reg.record_success("g", "url");
        assert!(!reg.is_ejected("g", "url", Instant::now()));
    }

    #[test]
    fn ejection_expires() {
        let reg = ForwardFailureRegistry::new();
        reg.record_failure("g", "url", 1, Duration::from_millis(0));
        std::thread::sleep(Duration::from_millis(2));
        assert!(!reg.is_ejected("g", "url", Instant::now()));
    }
}
