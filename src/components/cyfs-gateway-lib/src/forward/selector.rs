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
///   `balance` (round_robin or ip_hash) to spread load across attempts.
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

        order_tier(&mut healthy_primary, plan.balance, &self.rr_counter, source_ip);
        order_tier(&mut healthy_backup, plan.balance, &self.rr_counter, source_ip);

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
    method: BalanceMethod,
    rr_counter: &AtomicUsize,
    source_ip: Option<IpAddr>,
) {
    if targets.len() <= 1 {
        return;
    }

    match method {
        BalanceMethod::RoundRobin => {
            let leader = pick_weighted_round_robin(targets, rr_counter);
            if let Some(idx) = leader {
                targets[..].rotate_left(idx);
            }
        }
        BalanceMethod::IpHash => {
            let leader = pick_ip_hash(targets, source_ip);
            if let Some(idx) = leader {
                targets[..].rotate_left(idx);
            }
        }
    }
}

fn pick_weighted_round_robin(
    targets: &[ForwardTarget],
    rr_counter: &AtomicUsize,
) -> Option<usize> {
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

#[cfg(test)]
mod tests {
    use super::super::failure_state::ForwardFailureRegistry;
    use super::super::plan::{
        BalanceMethod, ForwardPlan, ForwardTarget, NextUpstreamPolicy,
    };
    use super::*;
    use std::time::Duration;

    fn plan_with(candidates: Vec<ForwardTarget>) -> ForwardPlan {
        ForwardPlan {
            group: Some("test".to_string()),
            balance: BalanceMethod::RoundRobin,
            next_upstream: NextUpstreamPolicy::off(),
            candidates,
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
}
