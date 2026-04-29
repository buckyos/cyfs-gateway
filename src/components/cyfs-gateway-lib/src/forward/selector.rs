use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use super::failure_state::ForwardFailureRegistry;
use super::plan::{BalanceMethod, ForwardPlan, ForwardTarget};

/// Build an ordered candidate list to attempt for one forward request.
///
/// Ordering rules (matches §4.4 of the design doc):
/// - primary peers come before backup peers;
/// - peers currently inside their `fail_timeout` ejection window are
///   pushed to the very end (we don't fully drop them so single-peer
///   groups still attempt the only option);
/// - within the primary / backup tier, ordering is determined by
///   `balance` (round_robin / ip_hash / hash / consistent_hash). The
///   `least_time` variant is RTT-aware and is applied separately by the
///   executor through `apply_least_time_order` before invoking this
///   selector, so by the time we get here the candidate order already
///   reflects RTT and we degrade to round_robin for tier ordering.
/// - for provider-first plans (§5), all routes that share the same
///   `server_id` are kept adjacent in the attempt order so that
///   intra-server failover happens before crossing a server boundary.
pub struct ForwardSelector {
    rr_counter: AtomicUsize,
}

impl Default for ForwardSelector {
    fn default() -> Self {
        Self::new()
    }
}

impl ForwardSelector {
    pub fn new() -> Self {
        Self {
            rr_counter: AtomicUsize::new(0),
        }
    }

    pub fn select(
        &self,
        plan: &ForwardPlan,
        registry: &ForwardFailureRegistry,
        source_ip: Option<IpAddr>,
    ) -> Vec<ForwardTarget> {
        let group_key = plan.failure_state_key();
        let now = Instant::now();

        let mut healthy_primary = Vec::new();
        let mut healthy_backup = Vec::new();
        let mut ejected_primary = Vec::new();
        let mut ejected_backup = Vec::new();
        for c in &plan.candidates {
            let ejected = registry.is_ejected(&group_key, &c.url, now);
            match (c.backup, ejected) {
                (false, false) => healthy_primary.push(c.clone()),
                (true, false) => healthy_backup.push(c.clone()),
                (false, true) => ejected_primary.push(c.clone()),
                (true, true) => ejected_backup.push(c.clone()),
            }
        }

        let hash_key = plan.hash_key_value.as_deref().unwrap_or("");
        order_tier(
            &mut healthy_primary,
            &plan.balance,
            &self.rr_counter,
            source_ip,
            hash_key,
        );
        order_tier(
            &mut healthy_backup,
            &plan.balance,
            &self.rr_counter,
            source_ip,
            hash_key,
        );

        // Provider-first server adjacency: if any candidate carries a
        // `server_id`, group them so all routes of one server are visited
        // before crossing to the next server. The first-appearance order
        // of each server is preserved (already determined by balance
        // method above through the leader rotation).
        group_by_server_id(&mut healthy_primary);
        group_by_server_id(&mut healthy_backup);

        let mut out = Vec::with_capacity(plan.candidates.len());
        out.extend(healthy_primary);
        out.extend(healthy_backup);
        out.extend(ejected_primary);
        out.extend(ejected_backup);
        out
    }
}

fn order_tier(
    targets: &mut Vec<ForwardTarget>,
    method: &BalanceMethod,
    rr_counter: &AtomicUsize,
    source_ip: Option<IpAddr>,
    hash_key: &str,
) {
    if targets.len() <= 1 {
        return;
    }

    let leader = match method {
        // LeastTime is applied earlier by the executor; the order is
        // already RTT-sorted, so we keep it.
        BalanceMethod::LeastTime => None,
        BalanceMethod::RoundRobin => pick_weighted_round_robin(targets, rr_counter),
        BalanceMethod::IpHash => pick_ip_hash(targets, source_ip),
        BalanceMethod::Hash { .. } => pick_hash(targets, hash_key),
        BalanceMethod::ConsistentHash { .. } => pick_consistent_hash(targets, hash_key),
    };

    if let Some(idx) = leader {
        targets[..].rotate_left(idx);
    }
}

/// Reorder so candidates with the same `server_id` are adjacent. The
/// first occurrence of each `server_id` (and `None`) determines the
/// position of the group. Within a group, order is preserved.
fn group_by_server_id(targets: &mut Vec<ForwardTarget>) {
    if targets.iter().all(|t| t.server_id.is_none()) {
        return;
    }

    let mut order: Vec<Option<String>> = Vec::new();
    for t in targets.iter() {
        if !order.iter().any(|s| s == &t.server_id) {
            order.push(t.server_id.clone());
        }
    }

    let mut buckets: std::collections::HashMap<Option<String>, Vec<ForwardTarget>> =
        std::collections::HashMap::new();
    for t in targets.drain(..) {
        buckets.entry(t.server_id.clone()).or_default().push(t);
    }
    for sid in order {
        if let Some(bucket) = buckets.remove(&sid) {
            targets.extend(bucket);
        }
    }
}

fn pick_weighted_round_robin(targets: &[ForwardTarget], rr_counter: &AtomicUsize) -> Option<usize> {
    if targets.is_empty() {
        return None;
    }
    let total: usize = targets.iter().map(|t| t.weight as usize).sum();
    if total == 0 {
        return Some(0);
    }
    let cursor = rr_counter.fetch_add(1, Ordering::Relaxed) % total;
    let mut acc = 0usize;
    for (i, t) in targets.iter().enumerate() {
        acc = acc.saturating_add(t.weight as usize);
        if cursor < acc {
            return Some(i);
        }
    }
    Some(0)
}

fn pick_ip_hash(targets: &[ForwardTarget], ip: Option<IpAddr>) -> Option<usize> {
    let ip = ip?;
    let total: usize = targets.iter().map(|t| t.weight as usize).sum();
    if total == 0 {
        return Some(0);
    }
    let mut cursor = nginx_ip_hash(&ip) % total;
    for (i, t) in targets.iter().enumerate() {
        let w = t.weight as usize;
        if cursor < w {
            return Some(i);
        }
        cursor -= w;
    }
    Some(0)
}

fn pick_hash(targets: &[ForwardTarget], key: &str) -> Option<usize> {
    if targets.is_empty() {
        return None;
    }
    let total: usize = targets.iter().map(|t| t.weight as usize).sum();
    if total == 0 {
        return Some(0);
    }
    let h = string_hash(key) as usize;
    let mut cursor = h % total;
    for (i, t) in targets.iter().enumerate() {
        let w = t.weight as usize;
        if cursor < w {
            return Some(i);
        }
        cursor -= w;
    }
    Some(0)
}

/// Ketama-style consistent hash: build a virtual-node ring keyed on
/// `server_id` (or url) and pick the candidate whose virtual node is
/// the smallest one >= H(key). This is stable under candidate set
/// changes — adding or removing one candidate only reshuffles a small
/// fraction of keys.
fn pick_consistent_hash(targets: &[ForwardTarget], key: &str) -> Option<usize> {
    if targets.is_empty() {
        return None;
    }
    // Build a ring: for each candidate, place `weight * VNODE_FACTOR`
    // virtual nodes at hash(`{id}#{idx}`).
    const VNODE_FACTOR: u32 = 40;
    let mut ring: Vec<(u64, usize)> = Vec::with_capacity(targets.len() * VNODE_FACTOR as usize);
    for (i, t) in targets.iter().enumerate() {
        let id = t.server_id.as_deref().unwrap_or(&t.url);
        let n = (t.weight.max(1)).saturating_mul(VNODE_FACTOR);
        for j in 0..n {
            let mark = format!("{}#{}", id, j);
            ring.push((string_hash(&mark), i));
        }
    }
    if ring.is_empty() {
        return Some(0);
    }
    ring.sort_by_key(|&(h, _)| h);
    let key_hash = string_hash(key);
    // Binary-search for first ring node >= key_hash; wrap if past end.
    let pos = ring.partition_point(|&(h, _)| h < key_hash);
    let pos = if pos == ring.len() { 0 } else { pos };
    Some(ring[pos].1)
}

fn string_hash(s: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    s.hash(&mut h);
    h.finish()
}

fn nginx_ip_hash_key(ip: &IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            vec![o[0], o[1], o[2]]
        }
        IpAddr::V6(v6) => v6.octets().to_vec(),
    }
}

fn nginx_ip_hash(ip: &IpAddr) -> usize {
    let key = nginx_ip_hash_key(ip);
    let mut hash = 89usize;
    for b in key {
        hash = (hash * 113 + b as usize) % 6271;
    }
    hash
}

/// Reorder a plan's `candidates` so URLs with lower observed RTT (per
/// `tunnel_mgr` URL history) come first. Used by the executor when
/// `balance == LeastTime` so that the subsequent `ForwardSelector`
/// keeps that order. RTT data is not available inside this crate
/// without a `TunnelManager`, so this helper accepts a sorted URL
/// list (as returned by `query_tunnel_url_statuses`) and applies it
/// in-place. Candidates whose URL does not appear in `sorted_urls`
/// keep their relative order at the end.
pub fn apply_least_time_order(plan: &mut ForwardPlan, sorted_normalized_urls: &[String]) {
    if plan.candidates.is_empty() || sorted_normalized_urls.is_empty() {
        return;
    }
    // Build a lookup for normalized URL → preferred index.
    let mut rank: std::collections::HashMap<&str, usize> =
        std::collections::HashMap::with_capacity(sorted_normalized_urls.len());
    for (i, u) in sorted_normalized_urls.iter().enumerate() {
        rank.insert(u.as_str(), i);
    }
    let unknown_rank = sorted_normalized_urls.len();
    plan.candidates.sort_by_key(|c| {
        // Match by raw URL string. Callers normalize on both sides so
        // direct string match is enough.
        rank.get(c.url.as_str()).copied().unwrap_or(unknown_rank)
    });
}

#[cfg(test)]
mod tests {
    use super::super::failure_state::ForwardFailureRegistry;
    use super::super::plan::{
        BalanceMethod, ForwardPlan, ForwardTarget, NextUpstreamPolicy, ProviderPolicy,
    };
    use super::*;
    use std::time::Duration;

    fn plan_with(candidates: Vec<ForwardTarget>) -> ForwardPlan {
        ForwardPlan {
            group: Some("test".to_string()),
            balance: BalanceMethod::RoundRobin,
            next_upstream: NextUpstreamPolicy::off(),
            candidates,
            hash_key_value: None,
            servers: Vec::new(),
            provider_policy: ProviderPolicy::default(),
        }
    }

    #[test]
    fn primary_before_backup() {
        let plan = plan_with(vec![
            ForwardTarget::new("rtcp://relay/").as_backup(),
            ForwardTarget::new("rtcp://primary/"),
        ]);
        let reg = ForwardFailureRegistry::new();
        let selector = ForwardSelector::new();
        let order = selector.select(&plan, &reg, None);
        assert_eq!(order[0].url, "rtcp://primary/");
        assert_eq!(order[1].url, "rtcp://relay/");
        assert!(order[1].backup);
    }

    #[test]
    fn ejected_primary_pushed_after_backup() {
        let plan = plan_with(vec![
            ForwardTarget::new("rtcp://primary/"),
            ForwardTarget::new("rtcp://relay/").as_backup(),
        ]);
        let reg = ForwardFailureRegistry::new();
        reg.record_failure(
            &plan.failure_state_key(),
            "rtcp://primary/",
            1,
            Duration::from_secs(60),
        );
        let selector = ForwardSelector::new();
        let order = selector.select(&plan, &reg, None);
        assert_eq!(order[0].url, "rtcp://relay/");
        assert_eq!(order[1].url, "rtcp://primary/");
    }

    #[test]
    fn round_robin_rotates_leader() {
        let plan = plan_with(vec![
            ForwardTarget::new("a").with_weight(1),
            ForwardTarget::new("b").with_weight(1),
        ]);
        let reg = ForwardFailureRegistry::new();
        let selector = ForwardSelector::new();
        let first = selector.select(&plan, &reg, None);
        let second = selector.select(&plan, &reg, None);
        assert_ne!(first[0].url, second[0].url);
    }

    #[test]
    fn hash_picks_same_candidate_for_same_key() {
        let mut plan = plan_with(vec![
            ForwardTarget::new("a").with_weight(1),
            ForwardTarget::new("b").with_weight(1),
            ForwardTarget::new("c").with_weight(1),
        ]);
        plan.balance = BalanceMethod::Hash {
            key: "$user_id".to_string(),
        };
        plan.hash_key_value = Some("user-42".to_string());
        let reg = ForwardFailureRegistry::new();
        let selector = ForwardSelector::new();
        let first = selector.select(&plan, &reg, None);
        let second = selector.select(&plan, &reg, None);
        assert_eq!(first[0].url, second[0].url);
    }

    #[test]
    fn consistent_hash_is_stable_for_same_key() {
        let mut plan = plan_with(vec![
            ForwardTarget::new("a").with_weight(1),
            ForwardTarget::new("b").with_weight(1),
            ForwardTarget::new("c").with_weight(1),
        ]);
        plan.balance = BalanceMethod::ConsistentHash {
            key: "$user_id".to_string(),
        };
        plan.hash_key_value = Some("user-42".to_string());
        let reg = ForwardFailureRegistry::new();
        let selector = ForwardSelector::new();
        let first = selector.select(&plan, &reg, None);
        let second = selector.select(&plan, &reg, None);
        assert_eq!(first[0].url, second[0].url);
    }

    #[test]
    fn server_id_groups_routes_adjacently() {
        let plan = plan_with(vec![
            ForwardTarget::new("rtcp://node-a/direct").with_server_id("node-a"),
            ForwardTarget::new("rtcp://node-b/direct").with_server_id("node-b"),
            ForwardTarget::new("rtcp://node-a/relay").with_server_id("node-a"),
        ]);
        let reg = ForwardFailureRegistry::new();
        let selector = ForwardSelector::new();
        let order = selector.select(&plan, &reg, None);
        // node-a appears first in input, so its routes should be 0,1.
        assert_eq!(order[0].server_id.as_deref(), Some("node-a"));
        assert_eq!(order[1].server_id.as_deref(), Some("node-a"));
        assert_eq!(order[2].server_id.as_deref(), Some("node-b"));
    }

    #[test]
    fn least_time_uses_externally_supplied_order() {
        let mut plan = plan_with(vec![
            ForwardTarget::new("rtcp://slow/"),
            ForwardTarget::new("rtcp://fast/"),
        ]);
        plan.balance = BalanceMethod::LeastTime;
        apply_least_time_order(
            &mut plan,
            &["rtcp://fast/".to_string(), "rtcp://slow/".to_string()],
        );
        let reg = ForwardFailureRegistry::new();
        let selector = ForwardSelector::new();
        let order = selector.select(&plan, &reg, None);
        assert_eq!(order[0].url, "rtcp://fast/");
        assert_eq!(order[1].url, "rtcp://slow/");
    }
}
