use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use tracing::warn;

use proxy_common::{Address, BoxedStream, ProxyError};
use proxy_config::schema::BalancerConfig;

use crate::context::Context;
use crate::features::OutboundHandler;
use crate::health::HealthStates;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Strategy {
    Latency,
    RoundRobin,
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

pub struct Balancer {
    tag: String,
    outbounds: Vec<(String, Arc<dyn OutboundHandler>)>,
    states: HealthStates,
    strategy: Strategy,
    rr_counter: AtomicUsize,
}

impl Balancer {
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
                self.states.get(tag.as_str()).map(|s| s.alive).unwrap_or(true)
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
                    self.states.get(tag.as_str()).map(|s| s.latency_ms).unwrap_or(u64::MAX)
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
