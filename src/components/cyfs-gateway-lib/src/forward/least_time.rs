//! RTT-aware reordering for `BalanceMethod::LeastTime` (§4.1, §6.7,
//! §8 stage 4 of `forward机制升级需求.md`).
//!
//! The forward selector itself is sync and has no access to
//! `TunnelManager`. This helper bridges the gap: at executor entry the
//! caller invokes [`apply_least_time_via_tunnel_mgr`] before iterating
//! the candidate list. It calls `query_tunnel_url_statuses` once with
//! `RttAscending` sort. Callers whose candidates are logical upstream
//! names can use [`apply_least_time_via_tunnel_mgr_with_resolved_urls`]
//! so history lookup uses concrete URLs while the logical names remain
//! available for connection-pool selection.
//!
//! The helper is intentionally a no-op for non-`LeastTime` plans so
//! callers can drop it on the front of their forward path without
//! branching on the balance method.

use std::time::Duration;

use url::Url;

use super::plan::{BalanceMethod, ForwardPlan};
use crate::tunnel_mgr::TunnelManager;
use crate::tunnel_url_status::{TunnelProbeOptions, TunnelUrlSortPolicy, normalize_tunnel_url};

/// Reorder `plan.candidates` to favor candidates with the lowest
/// observed RTT according to tunnel_mgr URL history.
///
/// Returns silently when `plan.balance` is not `LeastTime` so callers
/// don't need to branch. On any tunnel_mgr failure we keep the
/// existing order — best-effort, never blocking.
pub async fn apply_least_time_via_tunnel_mgr(
    plan: &mut ForwardPlan,
    tunnel_manager: &TunnelManager,
) {
    if !matches!(plan.balance, BalanceMethod::LeastTime) {
        return;
    }
    if plan.candidates.len() <= 1 {
        return;
    }

    // Parse each candidate URL. Bad URLs stay where they are.
    let mut urls: Vec<Url> = Vec::with_capacity(plan.candidates.len());
    for c in &plan.candidates {
        match Url::parse(&c.url) {
            Ok(u) => urls.push(u),
            Err(_) => {
                log::debug!(
                    "least_time: candidate '{}' is not a valid URL, skipping RTT sort",
                    c.url
                );
                return;
            }
        }
    }

    apply_least_time_via_tunnel_mgr_with_resolved_urls(plan, &urls, tunnel_manager).await;
}

/// Reorder `plan.candidates` using concrete URLs that correspond by index
/// to the candidates, without replacing the candidate strings themselves.
///
/// This is used by HTTP named upstreams: `resolved_urls` supplies the URL
/// history key, while `plan.candidates[*].url` remains the logical upstream
/// name needed to acquire its configured connection pool.
pub async fn apply_least_time_via_tunnel_mgr_with_resolved_urls(
    plan: &mut ForwardPlan,
    resolved_urls: &[Url],
    tunnel_manager: &TunnelManager,
) {
    if !matches!(plan.balance, BalanceMethod::LeastTime) {
        return;
    }
    if plan.candidates.len() <= 1 {
        return;
    }
    if resolved_urls.len() != plan.candidates.len() {
        log::debug!(
            "least_time: resolved URL count {} does not match candidate count {}, keeping order",
            resolved_urls.len(),
            plan.candidates.len()
        );
        return;
    }

    // Per §6.7.5: business path must not block on tunnel_mgr work. Cap
    // the lookup to a small budget so a slow probe never adds latency
    // to the request itself; on timeout we keep the existing order.
    const LEAST_TIME_LOOKUP_BUDGET: Duration = Duration::from_millis(50);

    let opts = TunnelProbeOptions {
        // Don't trigger a fresh probe — only use already-known history.
        force_probe: false,
        max_age_ms: None,
        timeout_ms: Some(LEAST_TIME_LOOKUP_BUDGET.as_millis() as u64),
        sort: TunnelUrlSortPolicy::RttAscending,
        include_unsupported: true,
        caller_priorities: None,
    };

    let lookup = tunnel_manager.query_tunnel_url_statuses(resolved_urls, opts);
    let result = match tokio::time::timeout(LEAST_TIME_LOOKUP_BUDGET, lookup).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            log::debug!("least_time: tunnel_mgr query failed, keeping order: {}", e);
            return;
        }
        Err(_) => {
            log::debug!(
                "least_time: tunnel_mgr query exceeded {}ms, keeping order",
                LEAST_TIME_LOOKUP_BUDGET.as_millis()
            );
            return;
        }
    };

    // `sorted_urls` are normalized; map them back to the original
    // candidate `url` strings via normalize.
    if result.sorted_urls.is_empty() {
        return;
    }

    let unknown_rank = result.sorted_urls.len();
    let mut rank = std::collections::HashMap::with_capacity(unknown_rank);
    for (index, normalized) in result.sorted_urls.into_iter().enumerate() {
        // Multiple logical upstreams may intentionally resolve to the same
        // concrete URL. Give them the same rank and preserve their input order.
        rank.entry(normalized).or_insert(index);
    }
    let candidates = std::mem::take(&mut plan.candidates);
    let mut indexed_candidates: Vec<_> = candidates.into_iter().enumerate().collect();
    indexed_candidates.sort_by_key(|(original_index, _)| {
        let normalized = normalize_tunnel_url(&resolved_urls[*original_index]);
        (
            rank.get(&normalized).copied().unwrap_or(unknown_rank),
            *original_index,
        )
    });
    plan.candidates = indexed_candidates
        .into_iter()
        .map(|(_, candidate)| candidate)
        .collect();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forward::ForwardTarget;
    use crate::tunnel_mgr::TunnelManager;
    use crate::tunnel_url_status::{TunnelUrlState, TunnelUrlStatusSource, reachable_status};

    #[tokio::test]
    async fn no_op_when_not_least_time() {
        let mgr = TunnelManager::new();
        let mut plan = ForwardPlan::single_url("rtcp://a/");
        plan.candidates
            .push(ForwardTarget::new("rtcp://b/").with_weight(1));
        let before = plan.candidates.clone();
        apply_least_time_via_tunnel_mgr(&mut plan, &mgr).await;
        assert_eq!(plan.candidates, before);
    }

    #[tokio::test]
    async fn applies_rtt_sort_when_history_present() {
        let mgr = TunnelManager::new();

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        // Seed history: b is fast (10ms), a is slow (100ms). Use a
        // recent timestamp so `query_tunnel_url_status` returns the
        // cached entry instead of trying to fresh-probe (which would
        // fail for these synthetic URLs).
        for (raw, rtt) in [("rtcp://a/", 100u64), ("rtcp://b/", 10u64)] {
            let url = Url::parse(raw).unwrap();
            let normalized = normalize_tunnel_url(&url);
            let mut status = reachable_status(
                &url,
                &normalized,
                now_ms,
                TunnelUrlStatusSource::BusinessConnect,
                Some(rtt),
            );
            status.state = TunnelUrlState::Reachable;
            mgr.record_status_observation(status).await;
        }

        let mut plan = ForwardPlan {
            group: Some("g".to_string()),
            balance: BalanceMethod::LeastTime,
            next_upstream: Default::default(),
            candidates: vec![
                ForwardTarget::new("rtcp://a/"),
                ForwardTarget::new("rtcp://b/"),
            ],
            hash_key_value: None,
            servers: Vec::new(),
            provider_policy: Default::default(),
        };

        apply_least_time_via_tunnel_mgr(&mut plan, &mgr).await;

        assert_eq!(plan.candidates[0].url, "rtcp://b/");
        assert_eq!(plan.candidates[1].url, "rtcp://a/");
    }

    #[tokio::test]
    async fn applies_rtt_sort_to_logical_names_using_resolved_urls() {
        let mgr = TunnelManager::new();
        let slow_url = Url::parse("http://slow.example/").unwrap();
        let fast_url = Url::parse("http://fast.example/").unwrap();
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        for (url, rtt) in [(&slow_url, 100u64), (&fast_url, 10u64)] {
            let normalized = normalize_tunnel_url(url);
            let status = reachable_status(
                url,
                &normalized,
                now_ms,
                TunnelUrlStatusSource::BusinessConnect,
                Some(rtt),
            );
            mgr.record_status_observation(status).await;
        }

        let mut plan = ForwardPlan {
            group: Some("named-http".to_string()),
            balance: BalanceMethod::LeastTime,
            next_upstream: Default::default(),
            candidates: vec![
                ForwardTarget::new("api_slow"),
                ForwardTarget::new("api_fast"),
            ],
            hash_key_value: None,
            servers: Vec::new(),
            provider_policy: Default::default(),
        };

        apply_least_time_via_tunnel_mgr_with_resolved_urls(&mut plan, &[slow_url, fast_url], &mgr)
            .await;

        assert_eq!(plan.candidates[0].url, "api_fast");
        assert_eq!(plan.candidates[1].url, "api_slow");
    }
}
