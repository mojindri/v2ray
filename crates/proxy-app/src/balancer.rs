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
//!
//! Dead members (marked by `HealthChecker`) are skipped.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use tracing::warn;

use proxy_common::{Address, BoxedStream, ProxyError};
use proxy_config::schema::BalancerConfig;

use crate::context::Context;
use crate::features::OutboundHandler;
use crate::health::HealthStates;

/// How the balancer picks among alive member outbounds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Strategy {
    /// Pick the alive outbound with the lowest measured latency.
    Latency,
    /// Rotate through alive outbounds in fixed order.
    RoundRobin,
    /// Pick a random alive outbound.
    Random,
}

impl From<&str> for Strategy {
    fn from(s: &str) -> Self {
        match s {
            "roundRobin" => Strategy::RoundRobin,
            "random" => Strategy::Random,
            _ => Strategy::Latency,
        }
    }
}

/// Outbound handler that load-balances across several member outbounds.
pub struct Balancer {
    tag: String,
    outbounds: Vec<(String, Arc<dyn OutboundHandler>)>,
    states: HealthStates,
    strategy: Strategy,
    rr_counter: AtomicUsize,
}

impl Balancer {
    /// Build a balancer from config, member outbounds, and shared health state.
    pub fn new(
        config: &BalancerConfig,
        outbounds: Vec<(String, Arc<dyn OutboundHandler>)>,
        states: HealthStates,
    ) -> Arc<Self> {
        Arc::new(Self {
            tag: config.tag.clone(),
            outbounds,
            states,
            strategy: Strategy::from(config.strategy.as_str()),
            rr_counter: AtomicUsize::new(0),
        })
    }

    fn pick(&self) -> Option<Arc<dyn OutboundHandler>> {
        let alive: Vec<&(String, Arc<dyn OutboundHandler>)> = self
            .outbounds
            .iter()
            .filter(|(tag, _)| {
                self.states
                    .get(tag.as_str())
                    .map(|s| s.alive)
                    .unwrap_or(true)
            })
            .collect();

        if alive.is_empty() {
            warn!(balancer = %self.tag, "all outbounds dead; falling back to first");
            return self.outbounds.first().map(|(_, ob)| ob.clone());
        }

        match self.strategy {
            Strategy::Latency => alive
                .iter()
                .min_by_key(|(tag, _)| {
                    self.states
                        .get(tag.as_str())
                        .map(|s| s.latency_ms)
                        .unwrap_or(u64::MAX)
                })
                .map(|(_, ob)| ob.clone()),

            Strategy::RoundRobin => {
                let idx = self.rr_counter.fetch_add(1, Ordering::Relaxed) % alive.len();
                alive.get(idx).map(|(_, ob)| ob.clone())
            }

            Strategy::Random => {
                let seed = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .subsec_nanos() as usize;
                alive.get(seed % alive.len()).map(|(_, ob)| ob.clone())
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
        let outbound = self
            .pick()
            .ok_or_else(|| ProxyError::Protocol("balancer has no outbounds".into()))?;
        outbound.connect(ctx, dest).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::health::OutboundState;
    use proxy_common::Address;
    use proxy_config::schema::BalancerConfig;
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
}
