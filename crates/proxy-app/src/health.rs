use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;
use tracing::{info, warn};

use proxy_common::Address;
use proxy_config::schema::HealthCheckConfig;

use crate::context::Context;
use crate::features::OutboundHandler;

#[derive(Clone, Debug)]
pub struct OutboundState {
    pub alive: bool,
    pub latency_ms: u64,
    pub consecutive_failures: u32,
    pub last_check: Instant,
}

impl Default for OutboundState {
    fn default() -> Self {
        Self {
            alive: true,
            latency_ms: u64::MAX,
            consecutive_failures: 0,
            last_check: Instant::now(),
        }
    }
}

pub type HealthStates = Arc<DashMap<String, OutboundState>>;

pub struct HealthChecker {
    outbounds: Vec<(String, Arc<dyn OutboundHandler>)>,
    pub states: HealthStates,
    config: HealthCheckConfig,
}

impl HealthChecker {
    pub fn new(
        outbounds: Vec<(String, Arc<dyn OutboundHandler>)>,
        config: HealthCheckConfig,
    ) -> (Arc<Self>, HealthStates) {
        let states: HealthStates = Arc::new(DashMap::new());
        for (tag, _) in &outbounds {
            states.insert(tag.clone(), OutboundState::default());
        }
        let checker = Arc::new(Self { outbounds, states: states.clone(), config });
        (checker, states)
    }

    pub async fn run(self: Arc<Self>) {
        let mut interval = tokio::time::interval(Duration::from_secs(self.config.interval_secs));
        interval.tick().await;
        loop {
            interval.tick().await;
            let handles: Vec<_> = self
                .outbounds
                .iter()
                .map(|(tag, ob)| {
                    let tag = tag.clone();
                    let ob = ob.clone();
                    let checker = Arc::clone(&self);
                    tokio::spawn(async move { checker.probe(tag, ob).await })
                })
                .collect();
            for h in handles {
                let _ = h.await;
            }
        }
    }

    async fn probe(&self, tag: String, outbound: Arc<dyn OutboundHandler>) {
        let start = Instant::now();
        let dest = Address::Domain("www.gstatic.com".into(), 80);
        let ctx = Context::default();

        let result = timeout(
            Duration::from_secs(self.config.timeout_secs),
            outbound.connect(&ctx, &dest),
        )
        .await;

        let success = match result {
            Ok(Ok(mut stream)) => {
                let req = b"GET /generate_204 HTTP/1.1\r\nHost: www.gstatic.com\r\nConnection: close\r\n\r\n";
                async {
                    stream.write_all(req).await?;
                    let mut resp = [0u8; 32];
                    stream.read(&mut resp).await?;
                    Ok::<bool, std::io::Error>(resp.starts_with(b"HTTP"))
                }
                .await
                .unwrap_or(false)
            }
            _ => false,
        };

        let mut entry = self.states.entry(tag.clone()).or_default();
        entry.last_check = Instant::now();

        if success {
            let was_dead = !entry.alive;
            entry.alive = true;
            entry.latency_ms = start.elapsed().as_millis() as u64;
            entry.consecutive_failures = 0;
            if was_dead {
                info!(tag = %tag, latency_ms = entry.latency_ms, "outbound recovered");
            }
        } else {
            entry.consecutive_failures += 1;
            if entry.consecutive_failures >= self.config.max_failures && entry.alive {
                entry.alive = false;
                warn!(tag = %tag, failures = entry.consecutive_failures, "outbound marked dead");
            }
        }
    }
}
