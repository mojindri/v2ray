//! Load-balancer outbound — pick the best member from a pool of outbounds.
//!
//! # How it works
//!
//! Routing can send traffic to a balancer tag instead of a single outbound.
//! The balancer chooses one member outbound per connection using a strategy:
//!
//!   - **Latency** — prefer the alive member with the lowest probe latency
//!   - **RoundRobin** — rotate through alive members in order
//!   - **Random** — pick a random alive member
//!   - **Adaptive** — score profiles by success rate, latency, stability, and
//!     cooldown state
//!
//! Dead members (marked by `HealthChecker`) are skipped. Adaptive profiles also
//! cool down after repeated probe/connect failures and use a switch margin to
//! avoid flapping on minor jitter.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use smallvec::SmallVec;
use tracing::{debug, info, warn};

use blackwire_common::{Address, BoxedStream, ProxyError};
use blackwire_config::schema::{AdaptiveBalancerConfig, BalancerConfig};

use crate::context::Context;
use crate::features::OutboundHandler;
use crate::health::HealthStates;
use crate::{metrics, runtime_stats};

/// How the balancer picks among alive member outbounds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Strategy {
    /// Pick the alive outbound with the lowest measured latency.
    Latency,
    /// Rotate through alive outbounds in fixed order.
    RoundRobin,
    /// Pick a random alive outbound.
    Random,
    /// Score profiles by observed success, latency, and health stability.
    Adaptive,
}

impl From<&str> for Strategy {
    fn from(s: &str) -> Self {
        match s {
            "roundRobin" => Strategy::RoundRobin,
            "random" => Strategy::Random,
            "adaptive" => Strategy::Adaptive,
            _ => Strategy::Latency,
        }
    }
}

struct BalancerMember {
    profile: String,
    outbound_tag: String,
    outbound: Arc<dyn OutboundHandler>,
    stat_selected: String,
    stat_cooldowns: String,
    stat_connect_success: String,
    stat_connect_failure: String,
}

#[derive(Clone, Debug)]
struct AdaptiveState {
    attempts: u64,
    successes: u64,
    consecutive_failures: u32,
    ewma_latency_ms: Option<f64>,
    last_selected: Option<Instant>,
    cooldown_until: Option<Instant>,
}

impl AdaptiveState {
    fn new() -> Self {
        Self {
            attempts: 0,
            successes: 0,
            consecutive_failures: 0,
            ewma_latency_ms: None,
            last_selected: None,
            cooldown_until: None,
        }
    }

    fn success_rate(&self) -> f64 {
        if self.attempts == 0 {
            1.0
        } else {
            self.successes as f64 / self.attempts as f64
        }
    }

    fn is_in_cooldown(&self, now: Instant) -> bool {
        self.cooldown_until.is_some_and(|until| until > now)
    }
}

#[derive(Debug)]
struct AdaptiveRuntime {
    members: Vec<AdaptiveState>,
    current: Option<usize>,
}

/// Outbound handler that load-balances across several member outbounds.
pub struct Balancer {
    tag: String,
    members: Vec<BalancerMember>,
    states: HealthStates,
    strategy: Strategy,
    adaptive_config: AdaptiveBalancerConfig,
    adaptive: Mutex<AdaptiveRuntime>,
    rr_counter: AtomicUsize,
}

impl Balancer {
    /// Build a balancer from config, member outbounds, and shared health state.
    pub fn new(
        config: &BalancerConfig,
        outbounds: Vec<(String, Arc<dyn OutboundHandler>)>,
        states: HealthStates,
    ) -> Arc<Self> {
        let members = outbounds
            .into_iter()
            .map(|(tag, outbound)| {
                let profile = config
                    .profiles
                    .iter()
                    .find(|profile| profile.outbound_tag == tag)
                    .map(|profile| profile.name.clone())
                    .unwrap_or_else(|| tag.clone());
                let stat_prefix = format!("balancer>>>{}>>>profile>>>{profile}", config.tag);
                BalancerMember {
                    profile,
                    outbound_tag: tag,
                    outbound,
                    stat_selected: format!("{stat_prefix}>>>selected"),
                    stat_cooldowns: format!("{stat_prefix}>>>cooldowns"),
                    stat_connect_success: format!("{stat_prefix}>>>connect>>>success"),
                    stat_connect_failure: format!("{stat_prefix}>>>connect>>>failure"),
                }
            })
            .collect::<Vec<_>>();
        let adaptive = Mutex::new(AdaptiveRuntime {
            members: vec![AdaptiveState::new(); members.len()],
            current: None,
        });
        Arc::new(Self {
            tag: config.tag.clone(),
            members,
            states,
            strategy: Strategy::from(config.strategy.as_str()),
            adaptive_config: config.adaptive.unwrap_or_default(),
            adaptive,
            rr_counter: AtomicUsize::new(0),
        })
    }

    #[cfg(test)]
    fn pick(&self) -> Option<Arc<dyn OutboundHandler>> {
        self.pick_member_index()
            .map(|idx| Arc::clone(&self.members[idx].outbound))
    }

    fn pick_member_index(&self) -> Option<usize> {
        match self.strategy {
            Strategy::Latency => self.pick_latency_index(),
            Strategy::RoundRobin => {
                let alive = self.alive_count();
                if alive == 0 {
                    warn!(balancer = %self.tag, "all outbounds dead; falling back to first");
                    return self.first_member_index();
                }
                let slot = self.rr_counter.fetch_add(1, Ordering::Relaxed) % alive;
                self.nth_alive_index(slot)
            }
            Strategy::Random => {
                let alive = self.alive_count();
                if alive == 0 {
                    warn!(balancer = %self.tag, "all outbounds dead; falling back to first");
                    return self.first_member_index();
                }
                let slot = self
                    .rr_counter
                    .fetch_add(1, Ordering::Relaxed)
                    .wrapping_mul(0x9E37_79B9_7F4A_7C15)
                    % alive;
                self.nth_alive_index(slot)
            }
            Strategy::Adaptive => self.pick_adaptive_index(),
        }
    }

    fn first_member_index(&self) -> Option<usize> {
        if self.members.is_empty() {
            None
        } else {
            Some(0)
        }
    }

    fn alive_count(&self) -> usize {
        self.members
            .iter()
            .filter(|member| self.is_alive(&member.outbound_tag))
            .count()
    }

    fn is_alive(&self, tag: &str) -> bool {
        self.states.get(tag).map(|s| s.alive).unwrap_or(true)
    }

    fn nth_alive_index(&self, n: usize) -> Option<usize> {
        let mut idx = 0;
        for (member_idx, member) in self.members.iter().enumerate() {
            if !self.is_alive(&member.outbound_tag) {
                continue;
            }
            if idx == n {
                return Some(member_idx);
            }
            idx += 1;
        }
        None
    }

    fn pick_latency_index(&self) -> Option<usize> {
        let mut best: Option<(u64, usize)> = None;
        for (idx, member) in self.members.iter().enumerate() {
            if !self.is_alive(&member.outbound_tag) {
                continue;
            }
            let latency = self
                .states
                .get(member.outbound_tag.as_str())
                .map(|s| s.latency_ms)
                .unwrap_or(u64::MAX);
            if best
                .as_ref()
                .is_none_or(|(best_lat, _)| latency < *best_lat)
            {
                best = Some((latency, idx));
            }
        }
        if best.is_none() {
            warn!(balancer = %self.tag, "all outbounds dead; falling back to first");
        }
        best.map(|(_, idx)| idx)
            .or_else(|| self.first_member_index())
    }

    fn pick_adaptive_index(&self) -> Option<usize> {
        let now = Instant::now();
        let mut adaptive = self.adaptive.lock().expect("adaptive state poisoned");
        let cooldowns = self.apply_probe_cooldowns(&mut adaptive.members, now);

        let mut best_available: Option<(usize, f64)> = None;
        let mut scores: SmallVec<[(usize, f64); 4]> = SmallVec::new();
        for (idx, member) in self.members.iter().enumerate() {
            let alive = self.is_alive(&member.outbound_tag);
            if !alive {
                continue;
            }
            let score = self.adaptive_score(idx, &adaptive.members[idx]);
            scores.push((idx, score));
            if adaptive.members[idx].is_in_cooldown(now) {
                continue;
            }
            if best_available.is_none_or(|(_, best_score)| score > best_score) {
                best_available = Some((idx, score));
            }
        }

        let previous_current = adaptive.current;
        let selected = if let Some((best_idx, best_score)) = best_available {
            if let Some(current_idx) = adaptive.current {
                if current_idx < self.members.len()
                    && self.is_alive(&self.members[current_idx].outbound_tag)
                    && !adaptive.members[current_idx].is_in_cooldown(now)
                {
                    let current_score =
                        self.adaptive_score(current_idx, &adaptive.members[current_idx]);
                    if current_score + self.adaptive_config.switch_margin >= best_score {
                        current_idx
                    } else {
                        best_idx
                    }
                } else {
                    best_idx
                }
            } else {
                best_idx
            }
        } else {
            warn!(balancer = %self.tag, "all adaptive profiles unavailable; falling back to first configured outbound");
            0
        };

        if selected < adaptive.members.len() {
            adaptive.members[selected].last_selected = Some(now);
            adaptive.current = Some(selected);
        }
        drop(adaptive);

        for idx in cooldowns {
            if let Some(member) = self.members.get(idx) {
                metrics::record_adaptive_balancer_cooldown(&self.tag, &member.profile);
                runtime_stats::increment(&member.stat_cooldowns, 1);
                warn!(
                    balancer = %self.tag,
                    profile = %member.profile,
                    outbound = %member.outbound_tag,
                    cooldown_secs = self.adaptive_config.cooldown_secs,
                    "adaptive balancer profile entered cooldown after health probe failures"
                );
            }
        }
        for (idx, score) in scores {
            if let Some(member) = self.members.get(idx) {
                metrics::record_adaptive_balancer_score(&self.tag, &member.profile, score);
            }
        }
        if let Some(member) = self.members.get(selected) {
            metrics::record_adaptive_balancer_selection(&self.tag, &member.profile);
            runtime_stats::increment(&member.stat_selected, 1);
            if previous_current.is_some_and(|previous| previous != selected) {
                let previous = previous_current.and_then(|idx| self.members.get(idx));
                info!(
                    balancer = %self.tag,
                    profile = %member.profile,
                    outbound = %member.outbound_tag,
                    previous_profile = previous.map(|member| member.profile.as_str()).unwrap_or("unknown"),
                    switch_margin = self.adaptive_config.switch_margin,
                    "adaptive balancer switched profile"
                );
            }
            debug!(
                balancer = %self.tag,
                profile = %member.profile,
                outbound = %member.outbound_tag,
                "adaptive balancer selected profile"
            );
        }
        self.members.get(selected).map(|_| selected)
    }

    fn apply_probe_cooldowns(
        &self,
        state: &mut [AdaptiveState],
        now: Instant,
    ) -> SmallVec<[usize; 4]> {
        let mut cooldowns = SmallVec::new();
        for (idx, member) in self.members.iter().enumerate() {
            let probe_failures = self
                .states
                .get(member.outbound_tag.as_str())
                .map(|s| s.consecutive_failures)
                .unwrap_or_default();
            if probe_failures >= self.adaptive_config.failure_threshold
                && !state[idx].is_in_cooldown(now)
            {
                state[idx].cooldown_until =
                    Some(now + Duration::from_secs(self.adaptive_config.cooldown_secs));
                cooldowns.push(idx);
            }
        }
        cooldowns
    }

    fn adaptive_score(&self, idx: usize, state: &AdaptiveState) -> f64 {
        let member = &self.members[idx];
        let health = self.states.get(member.outbound_tag.as_str());
        let latency_ms = state
            .ewma_latency_ms
            .or_else(|| health.as_ref().map(|s| s.latency_ms as f64))
            .filter(|latency| latency.is_finite() && *latency < u64::MAX as f64)
            .unwrap_or(5000.0);
        let latency_score = 1.0 - (latency_ms / 5000.0).clamp(0.0, 1.0);
        let health_failures = health.as_ref().map(|s| s.consecutive_failures).unwrap_or(0);
        let connect_failures = state.consecutive_failures;
        let failure_budget = self.adaptive_config.failure_threshold.max(1) as f64;
        let stability_score =
            1.0 - ((health_failures + connect_failures) as f64 / failure_budget).clamp(0.0, 1.0);

        (0.50 * state.success_rate()) + (0.30 * latency_score) + (0.20 * stability_score)
    }

    fn observe_connect_result(&self, idx: usize, elapsed: Duration, ok: bool) {
        if self.strategy != Strategy::Adaptive {
            return;
        }
        let Some(member) = self.members.get(idx) else {
            return;
        };
        let mut recovered_from_failures = false;
        let entered_cooldown = {
            let mut adaptive = self.adaptive.lock().expect("adaptive state poisoned");
            let Some(entry) = adaptive.members.get_mut(idx) else {
                return;
            };
            entry.attempts = entry.attempts.saturating_add(1);
            if ok {
                entry.successes = entry.successes.saturating_add(1);
                recovered_from_failures = entry.consecutive_failures > 0;
                entry.consecutive_failures = 0;
                let sample = elapsed.as_secs_f64() * 1000.0;
                let alpha = self.adaptive_config.ewma_alpha.clamp(0.01, 1.0);
                entry.ewma_latency_ms = Some(match entry.ewma_latency_ms {
                    Some(prev) => (alpha * sample) + ((1.0 - alpha) * prev),
                    None => sample,
                });
                false
            } else {
                entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
                if entry.consecutive_failures >= self.adaptive_config.failure_threshold {
                    entry.cooldown_until = Some(
                        Instant::now() + Duration::from_secs(self.adaptive_config.cooldown_secs),
                    );
                    true
                } else {
                    false
                }
            }
        };

        if ok {
            metrics::record_adaptive_balancer_connect_success(&self.tag, &member.profile);
            runtime_stats::increment(&member.stat_connect_success, 1);
            if recovered_from_failures {
                info!(
                    balancer = %self.tag,
                    profile = %member.profile,
                    outbound = %member.outbound_tag,
                    latency_ms = elapsed.as_millis(),
                    "adaptive balancer profile recovered after connect failure"
                );
            }
        } else {
            metrics::record_adaptive_balancer_connect_failure(&self.tag, &member.profile);
            runtime_stats::increment(&member.stat_connect_failure, 1);
            if entered_cooldown {
                metrics::record_adaptive_balancer_cooldown(&self.tag, &member.profile);
                runtime_stats::increment(&member.stat_cooldowns, 1);
                warn!(
                    balancer = %self.tag,
                    profile = %member.profile,
                    outbound = %member.outbound_tag,
                    cooldown_secs = self.adaptive_config.cooldown_secs,
                    "adaptive balancer profile entered cooldown after connect failures"
                );
            } else {
                debug!(
                    balancer = %self.tag,
                    profile = %member.profile,
                    outbound = %member.outbound_tag,
                    "adaptive balancer connect failed"
                );
            }
        }
    }
}

#[async_trait]
impl OutboundHandler for Balancer {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn connect(&self, ctx: &Context, dest: &Address) -> Result<BoxedStream, ProxyError> {
        let idx = self
            .pick_member_index()
            .ok_or_else(|| ProxyError::Protocol("balancer has no outbounds".into()))?;
        let outbound = Arc::clone(&self.members[idx].outbound);
        let start = Instant::now();
        let result = outbound.connect(ctx, dest).await;
        self.observe_connect_result(idx, start.elapsed(), result.is_ok());
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::health::OutboundState;
    use blackwire_common::Address;
    use blackwire_config::schema::{AdaptiveBalancerConfig, BalancerConfig, BalancerProfileConfig};
    use tokio::io::duplex;

    struct MockOutbound {
        tag: String,
    }

    #[async_trait]
    impl OutboundHandler for MockOutbound {
        fn tag(&self) -> &str {
            &self.tag
        }

        async fn connect(
            &self,
            _ctx: &Context,
            _dest: &Address,
        ) -> Result<BoxedStream, ProxyError> {
            let (stream, _peer) = duplex(64);
            Ok(Box::new(stream))
        }
    }

    fn mock(tag: &str) -> (String, Arc<dyn OutboundHandler>) {
        (
            tag.to_string(),
            Arc::new(MockOutbound {
                tag: tag.to_string(),
            }),
        )
    }

    fn states(entries: &[(&str, bool, u64)]) -> HealthStates {
        let states = HealthStates::default();
        for (tag, alive, latency_ms) in entries {
            states.insert(
                (*tag).to_string(),
                OutboundState {
                    alive: *alive,
                    latency_ms: *latency_ms,
                    ..Default::default()
                },
            );
        }
        states
    }

    fn config(strategy: &str) -> BalancerConfig {
        BalancerConfig {
            tag: "auto".into(),
            selector: vec!["a".into(), "b".into()],
            strategy: strategy.into(),
            profiles: Vec::new(),
            adaptive: None,
            health_check: None,
        }
    }

    fn adaptive_config() -> BalancerConfig {
        BalancerConfig {
            tag: "auto".into(),
            selector: vec!["a".into(), "b".into()],
            strategy: "adaptive".into(),
            profiles: vec![
                BalancerProfileConfig {
                    name: "stable".into(),
                    outbound_tag: "a".into(),
                },
                BalancerProfileConfig {
                    name: "backup".into(),
                    outbound_tag: "b".into(),
                },
            ],
            adaptive: Some(AdaptiveBalancerConfig {
                failure_threshold: 2,
                cooldown_secs: 30,
                ewma_alpha: 0.2,
                switch_margin: 0.15,
            }),
            health_check: None,
        }
    }

    #[test]
    fn latency_strategy_chooses_lowest_latency_alive_outbound() {
        let balancer = Balancer::new(
            &config("latency"),
            vec![mock("a"), mock("b")],
            states(&[("a", true, 100), ("b", true, 10)]),
        );

        assert_eq!(balancer.pick().unwrap().tag(), "b");
    }

    #[test]
    fn dead_outbounds_are_filtered_before_selection() {
        let balancer = Balancer::new(
            &config("latency"),
            vec![mock("a"), mock("b")],
            states(&[("a", false, 1), ("b", true, 100)]),
        );

        assert_eq!(balancer.pick().unwrap().tag(), "b");
    }

    #[test]
    fn all_dead_falls_back_to_first_configured_outbound() {
        let balancer = Balancer::new(
            &config("latency"),
            vec![mock("a"), mock("b")],
            states(&[("a", false, 1), ("b", false, 2)]),
        );

        assert_eq!(balancer.pick().unwrap().tag(), "a");
    }

    #[test]
    fn round_robin_rotates_alive_outbounds() {
        let balancer = Balancer::new(
            &config("roundRobin"),
            vec![mock("a"), mock("b")],
            states(&[("a", true, 1), ("b", true, 2)]),
        );

        assert_eq!(balancer.pick().unwrap().tag(), "a");
        assert_eq!(balancer.pick().unwrap().tag(), "b");
        assert_eq!(balancer.pick().unwrap().tag(), "a");
    }

    #[test]
    fn adaptive_strategy_chooses_highest_scoring_alive_profile() {
        let balancer = Balancer::new(
            &adaptive_config(),
            vec![mock("a"), mock("b")],
            states(&[("a", true, 4000), ("b", true, 50)]),
        );

        assert_eq!(balancer.pick().unwrap().tag(), "b");
    }

    #[test]
    fn adaptive_strategy_prefers_best_profile_over_worst_profile() {
        let balancer = Balancer::new(
            &adaptive_config(),
            vec![mock("a"), mock("b")],
            states(&[("a", true, 5000), ("b", true, 10)]),
        );
        {
            let mut adaptive = balancer.adaptive.lock().unwrap();
            adaptive.members[0].attempts = 20;
            adaptive.members[0].successes = 0;
            adaptive.members[0].consecutive_failures = 1;
            adaptive.members[0].ewma_latency_ms = Some(5000.0);
            adaptive.members[1].attempts = 20;
            adaptive.members[1].successes = 20;
            adaptive.members[1].consecutive_failures = 0;
            adaptive.members[1].ewma_latency_ms = Some(10.0);
        }

        assert_eq!(balancer.pick().unwrap().tag(), "b");
    }

    #[test]
    fn adaptive_strategy_routes_around_degraded_primary_on_unstable_network() {
        let balancer = Balancer::new(
            &adaptive_config(),
            vec![mock("a"), mock("b")],
            states(&[("a", true, 4500), ("b", true, 180)]),
        );
        {
            let mut adaptive = balancer.adaptive.lock().unwrap();
            adaptive.members[0].attempts = 30;
            adaptive.members[0].successes = 12;
            adaptive.members[0].consecutive_failures = 1;
            adaptive.members[0].ewma_latency_ms = Some(4500.0);
            adaptive.members[1].attempts = 30;
            adaptive.members[1].successes = 28;
            adaptive.members[1].consecutive_failures = 0;
            adaptive.members[1].ewma_latency_ms = Some(180.0);
        }

        assert_eq!(balancer.pick().unwrap().tag(), "b");
    }

    #[test]
    fn adaptive_strategy_keeps_current_profile_during_minor_jitter() {
        let balancer = Balancer::new(
            &adaptive_config(),
            vec![mock("a"), mock("b")],
            states(&[("a", true, 220), ("b", true, 170)]),
        );
        {
            let mut adaptive = balancer.adaptive.lock().unwrap();
            adaptive.current = Some(0);
            adaptive.members[0].attempts = 50;
            adaptive.members[0].successes = 49;
            adaptive.members[0].consecutive_failures = 0;
            adaptive.members[0].ewma_latency_ms = Some(220.0);
            adaptive.members[1].attempts = 50;
            adaptive.members[1].successes = 50;
            adaptive.members[1].consecutive_failures = 0;
            adaptive.members[1].ewma_latency_ms = Some(170.0);
        }

        assert_eq!(balancer.pick().unwrap().tag(), "a");
    }

    #[test]
    fn adaptive_strategy_skips_dead_and_cooldown_profiles() {
        let balancer = Balancer::new(
            &adaptive_config(),
            vec![mock("a"), mock("b")],
            states(&[("a", false, 1), ("b", true, 100)]),
        );
        assert_eq!(balancer.pick().unwrap().tag(), "b");

        let balancer = Balancer::new(
            &adaptive_config(),
            vec![mock("a"), mock("b")],
            states(&[("a", true, 1), ("b", true, 100)]),
        );
        {
            let mut adaptive = balancer.adaptive.lock().unwrap();
            adaptive.members[0].cooldown_until = Some(Instant::now() + Duration::from_secs(60));
        }
        assert_eq!(balancer.pick().unwrap().tag(), "b");
    }

    #[test]
    fn adaptive_strategy_all_dead_or_cooldown_falls_back_explicitly() {
        let balancer = Balancer::new(
            &adaptive_config(),
            vec![mock("a"), mock("b")],
            states(&[("a", false, 1), ("b", false, 2)]),
        );
        assert_eq!(balancer.pick().unwrap().tag(), "a");

        let balancer = Balancer::new(
            &adaptive_config(),
            vec![mock("a"), mock("b")],
            states(&[("a", true, 1), ("b", true, 2)]),
        );
        {
            let mut adaptive = balancer.adaptive.lock().unwrap();
            adaptive.members[0].cooldown_until = Some(Instant::now() + Duration::from_secs(60));
            adaptive.members[1].cooldown_until = Some(Instant::now() + Duration::from_secs(60));
        }
        assert_eq!(balancer.pick().unwrap().tag(), "a");

        let balancer = Balancer::new(
            &adaptive_config(),
            vec![mock("a"), mock("b")],
            states(&[("a", false, 1), ("b", true, 2)]),
        );
        {
            let mut adaptive = balancer.adaptive.lock().unwrap();
            adaptive.members[1].cooldown_until = Some(Instant::now() + Duration::from_secs(60));
        }
        assert_eq!(balancer.pick().unwrap().tag(), "a");
    }

    #[test]
    fn adaptive_strategy_switch_margin_prevents_flapping() {
        let balancer = Balancer::new(
            &adaptive_config(),
            vec![mock("a"), mock("b")],
            states(&[("a", true, 200), ("b", true, 50)]),
        );
        {
            let mut adaptive = balancer.adaptive.lock().unwrap();
            adaptive.current = Some(0);
            adaptive.members[0].attempts = 10;
            adaptive.members[0].successes = 10;
            adaptive.members[0].ewma_latency_ms = Some(200.0);
            adaptive.members[1].attempts = 10;
            adaptive.members[1].successes = 10;
            adaptive.members[1].ewma_latency_ms = Some(50.0);
        }

        assert_eq!(balancer.pick().unwrap().tag(), "a");
    }

    #[test]
    fn adaptive_strategy_uses_selector_tags_as_unnamed_profiles() {
        let balancer = Balancer::new(
            &config("adaptive"),
            vec![mock("a"), mock("b")],
            states(&[("a", true, 500), ("b", true, 10)]),
        );

        assert_eq!(balancer.members[0].profile, "a");
        assert_eq!(balancer.members[1].profile, "b");
        assert_eq!(balancer.pick().unwrap().tag(), "b");
    }
}
