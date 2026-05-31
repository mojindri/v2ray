//! Outbound health checking — probe members and mark them alive or dead.
//!
//! # How it works
//!
//! When a routing balancer references several outbounds, `HealthChecker` runs
//! periodic HTTP-style probes through each member. Results update `HealthStates`, which
//! the balancer reads to skip dead nodes.

use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;
use tracing::{info, warn};

use blackwire_common::{Address, ProxyError};
use blackwire_config::schema::HealthCheckConfig;

use crate::context::Context;
use crate::features::OutboundHandler;

/// Latest health snapshot for one outbound (updated by probe tasks).
#[derive(Clone, Debug)]
pub struct OutboundState {
    /// `false` after too many consecutive probe failures.
    pub alive: bool,
    /// Last successful probe latency in milliseconds (`u64::MAX` if never probed).
    pub latency_ms: u64,
    /// Probe failures in a row; resets on success.
    pub consecutive_failures: u32,
    /// When this outbound was last probed.
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

/// Shared map from outbound tag → latest health snapshot (updated by the checker task).
pub type HealthStates = Arc<DashMap<String, OutboundState>>;

/// Background task that probes outbounds on an interval.
pub struct HealthChecker {
    outbounds: Vec<(String, Arc<dyn OutboundHandler>)>,
    /// Live health table updated after each probe round.
    pub states: HealthStates,
    config: HealthCheckConfig,
    probe: HealthProbe,
}

#[derive(Clone, Debug)]
struct HealthProbe {
    dest: Address,
    request: String,
}

impl HealthChecker {
    /// Create a checker and an empty health table pre-filled for each outbound tag.
    pub fn new(
        outbounds: Vec<(String, Arc<dyn OutboundHandler>)>,
        config: HealthCheckConfig,
    ) -> Result<(Arc<Self>, HealthStates), ProxyError> {
        let probe = HealthProbe::parse(&config.url)?;
        let states: HealthStates = Arc::new(DashMap::new());
        for (tag, _) in &outbounds {
            states.insert(tag.clone(), OutboundState::default());
        }
        let checker = Arc::new(Self {
            outbounds,
            states: states.clone(),
            config,
            probe,
        });
        Ok((checker, states))
    }

    /// Run probe rounds forever until the task is cancelled.
    pub async fn run(self: Arc<Self>) {
        let mut interval = tokio::time::interval(Duration::from_secs(self.config.interval_secs));
        interval.tick().await;
        let mut handles = Vec::with_capacity(self.outbounds.len());
        loop {
            interval.tick().await;
            handles.clear();
            for (tag, ob) in &self.outbounds {
                let tag = tag.clone();
                let ob = ob.clone();
                let checker = Arc::clone(&self);
                handles.push(tokio::spawn(async move { checker.probe(tag, ob).await }));
            }
            for h in handles.drain(..) {
                let _ = h.await;
            }
        }
    }

    async fn probe(&self, tag: String, outbound: Arc<dyn OutboundHandler>) {
        let start = Instant::now();
        let success = self.run_probe(&outbound).await;

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

    /// Connect, send a minimal HTTP GET, and read the response — all under one timeout.
    async fn run_probe(&self, outbound: &Arc<dyn OutboundHandler>) -> bool {
        let ctx = Context::default();
        let probe_timeout = Duration::from_secs(self.config.timeout_secs);

        match timeout(probe_timeout, async {
            let mut stream = outbound
                .connect(&ctx, &self.probe.dest)
                .await
                .map_err(|e| anyhow::anyhow!("connect: {e}"))?;
            stream
                .write_all(self.probe.request.as_bytes())
                .await
                .map_err(|e| anyhow::anyhow!("write: {e}"))?;
            let mut resp = [0u8; 32];
            let n = stream
                .read(&mut resp)
                .await
                .map_err(|e| anyhow::anyhow!("read: {e}"))?;
            if n == 0 {
                anyhow::bail!("connection closed before response");
            }
            if !resp.starts_with(b"HTTP") {
                anyhow::bail!("response is not HTTP");
            }
            Ok(())
        })
        .await
        {
            Ok(Ok(())) => true,
            Ok(Err(e)) => {
                warn!(error = %e, "health probe failed");
                false
            }
            Err(_) => {
                warn!(?probe_timeout, "health probe timed out");
                false
            }
        }
    }
}

impl HealthProbe {
    fn parse(url: &str) -> Result<Self, ProxyError> {
        let rest = url.strip_prefix("http://").ok_or_else(|| {
            ProxyError::Protocol("health check only supports http:// URLs".into())
        })?;
        let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
        if authority.is_empty() {
            return Err(ProxyError::Protocol(
                "health check URL is missing a host".into(),
            ));
        }

        let path = format!("/{}", path);
        let (host, port) = parse_authority(authority)?;
        let host_header = if port == 80 {
            host.clone()
        } else {
            format!("{host}:{port}")
        };
        let mut request = String::with_capacity(path.len() + host_header.len() + 48);
        request.push_str("GET ");
        request.push_str(&path);
        request.push_str(" HTTP/1.1\r\nHost: ");
        request.push_str(&host_header);
        request.push_str("\r\nConnection: close\r\n\r\n");
        Ok(Self {
            dest: Address::Domain(host, port),
            request,
        })
    }
}

fn parse_authority(authority: &str) -> Result<(String, u16), ProxyError> {
    if let Some(host) = authority.strip_prefix('[') {
        let (host, rest) = host.split_once(']').ok_or_else(|| {
            ProxyError::Protocol("health check IPv6 host is missing closing ']'".into())
        })?;
        let port = match rest.strip_prefix(':') {
            Some(port) => parse_port(port)?,
            None if rest.is_empty() => 80,
            _ => {
                return Err(ProxyError::Protocol(
                    "invalid health check IPv6 authority".into(),
                ))
            }
        };
        return Ok((host.to_string(), port));
    }

    match authority.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => Ok((host.to_string(), parse_port(port)?)),
        Some(_) => Err(ProxyError::Protocol(
            "IPv6 health check hosts must use brackets".into(),
        )),
        None => Ok((authority.to_string(), 80)),
    }
}

fn parse_port(port: &str) -> Result<u16, ProxyError> {
    port.parse::<u16>()
        .map_err(|_| ProxyError::Protocol(format!("invalid health check URL port '{port}'")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use blackwire_common::BoxedStream;
    use blackwire_config::schema::HealthCheckConfig;
    use tokio::io::AsyncWriteExt;

    struct StallReadOutbound;

    #[async_trait]
    impl OutboundHandler for StallReadOutbound {
        fn tag(&self) -> &str {
            "stall"
        }

        async fn connect(
            &self,
            _ctx: &Context,
            _dest: &Address,
        ) -> Result<BoxedStream, ProxyError> {
            let (client, server) = tokio::io::duplex(64);
            tokio::spawn(async move {
                let _ = server;
                tokio::time::sleep(Duration::from_secs(3600)).await;
            });
            Ok(Box::new(client))
        }
    }

    #[tokio::test]
    async fn probe_times_out_when_peer_never_responds() {
        let checker = Arc::new(HealthChecker {
            outbounds: vec![(
                "stall".into(),
                Arc::new(StallReadOutbound) as Arc<dyn OutboundHandler>,
            )],
            states: HealthStates::default(),
            config: HealthCheckConfig {
                url: "http://127.0.0.1:1/".into(),
                interval_secs: 60,
                timeout_secs: 1,
                max_failures: 3,
            },
            probe: HealthProbe::parse("http://127.0.0.1:1/").unwrap(),
        });

        let start = Instant::now();
        let ok = checker.run_probe(&checker.outbounds[0].1).await;
        assert!(!ok);
        assert!(start.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn health_probe_parses_http_url_with_default_port() {
        let probe = HealthProbe::parse("http://example.com/generate_204").unwrap();
        assert_eq!(probe.dest, Address::Domain("example.com".into(), 80));
        assert_eq!(
            probe.request,
            "GET /generate_204 HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
        );
    }

    #[test]
    fn health_probe_parses_http_url_with_explicit_port() {
        let probe = HealthProbe::parse("http://example.com:8080/healthz").unwrap();
        assert_eq!(probe.dest, Address::Domain("example.com".into(), 8080));
        assert_eq!(
            probe.request,
            "GET /healthz HTTP/1.1\r\nHost: example.com:8080\r\nConnection: close\r\n\r\n"
        );
    }

    #[test]
    fn health_probe_rejects_unsupported_scheme() {
        assert!(HealthProbe::parse("https://example.com/healthz").is_err());
    }

    #[tokio::test]
    async fn probe_succeeds_on_http_response() {
        struct HttpOkOutbound;

        #[async_trait]
        impl OutboundHandler for HttpOkOutbound {
            fn tag(&self) -> &str {
                "ok"
            }

            async fn connect(
                &self,
                _ctx: &Context,
                _dest: &Address,
            ) -> Result<BoxedStream, ProxyError> {
                let (client, mut server) = tokio::io::duplex(128);
                tokio::spawn(async move {
                    let _ = server.write_all(b"HTTP/1.1 204 No Content\r\n\r\n").await;
                });
                Ok(Box::new(client))
            }
        }

        let checker = Arc::new(HealthChecker {
            outbounds: vec![("ok".into(), Arc::new(HttpOkOutbound))],
            states: HealthStates::default(),
            config: HealthCheckConfig {
                url: "http://127.0.0.1:1/".into(),
                interval_secs: 60,
                timeout_secs: 2,
                max_failures: 3,
            },
            probe: HealthProbe::parse("http://127.0.0.1:1/").unwrap(),
        });

        assert!(checker.run_probe(&checker.outbounds[0].1).await);
    }
}
