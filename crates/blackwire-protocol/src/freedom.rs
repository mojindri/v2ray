//! Freedom outbound — direct TCP connection to the destination.
//!
//! "Freedom" means no proxy protocol: the proxy connects directly to the
//! destination server without wrapping the traffic in any additional protocol.
//!
//! When the top-level `dns` block is configured (Xray/sing-box style), domain
//! lookups use that module (e.g. Docker embedded DNS). Otherwise freedom falls
//! back to `tokio::net::lookup_host` (OS resolver).

use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use dashmap::DashMap;
use parking_lot::Mutex;
use tokio::net::TcpStream;
use tracing::debug;

use blackwire_app::context::Context;
use blackwire_app::dns::DnsModule;
use blackwire_app::features::OutboundHandler;
use blackwire_common::{tcp_connect, Address, BoxedStream, ProxyError};

// ── Adaptive connection pool ─────────────────────────────────────────────────

/// Configuration for the adaptive TCP connection pool.
///
/// Pass to `FreedomOutbound::new_pooled` or `new_with_dns_pooled` to enable
/// pooling in Fast Profile. In Compat mode use `new` or `new_with_dns` (no pool).
pub struct PoolConfig {
    /// Ceiling per destination. Effective capacity starts at 0 and ramps
    /// geometrically with observed traffic; this value is never pre-allocated.
    pub max_per_dest: usize,
    /// Maximum total idle sockets across all destinations (soft global cap).
    pub max_global_idle: usize,
    /// Maximum number of distinct destination pools to maintain.
    pub max_dests: usize,
    /// Discard idle connections older than this (prevents stale-socket reuse).
    pub idle_ttl: Duration,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_per_dest: 32,
            max_global_idle: 512,
            max_dests: 256,
            idle_ttl: Duration::from_secs(30),
        }
    }
}

/// Per-destination pool state.
struct DestPool {
    addr: SocketAddr,
    /// Lifetime connections served; determines adaptive capacity tier.
    conn_count: AtomicU64,
    /// Background refill tasks currently in flight.
    /// Included in the refill budget: needed = cap - (idle.len + in_flight).
    in_flight: AtomicUsize,
    /// Idle pre-established connections with their last-use timestamps.
    idle: Mutex<VecDeque<(TcpStream, Instant)>>,
    /// Last time this pool was accessed; used for future LRU eviction.
    last_used: Mutex<Instant>,
}

impl DestPool {
    fn new(addr: SocketAddr) -> Arc<Self> {
        Arc::new(Self {
            addr,
            conn_count: AtomicU64::new(0),
            in_flight: AtomicUsize::new(0),
            idle: Mutex::new(VecDeque::new()),
            last_used: Mutex::new(Instant::now()),
        })
    }

    /// Effective pool capacity for this destination given the configured ceiling.
    ///
    /// Ramps geometrically with observed traffic so one-off destinations never
    /// hold pre-allocated sockets, while hot destinations fill up over time.
    fn effective_cap(&self, max: usize) -> usize {
        let seen = self.conn_count.load(Ordering::Relaxed);
        let tier = match seen {
            0 => 0,
            1..=3 => 1,
            4..=7 => 2,
            8..=15 => 4,
            16..=31 => 8,
            32..=63 => 16,
            _ => max,
        };
        tier.min(max)
    }

    /// Pop the next live, non-expired idle connection.
    ///
    /// Returns `(stream, stale_count)`:
    /// - `stream`: a usable pre-established connection, or `None` on miss.
    /// - `stale_count`: connections discarded (TTL-expired or dead peer).
    ///   The caller must subtract this from `AdaptivePool::global_idle`.
    fn try_take(&self, idle_ttl: Duration) -> (Option<TcpStream>, usize) {
        let mut guard = self.idle.lock();
        let now = Instant::now();
        let mut stale = 0usize;
        while let Some((stream, last_use)) = guard.pop_front() {
            if now.duration_since(last_use) > idle_ttl {
                stale += 1;
                continue;
            }
            // Non-blocking liveness probe: WouldBlock = alive and idle.
            let mut probe = [0u8; 1];
            match stream.try_read(&mut probe) {
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    *self.last_used.lock() = now;
                    return (Some(stream), stale);
                }
                _ => {
                    stale += 1; // Stale (EOF or error from peer).
                }
            }
        }
        (None, stale)
    }

    /// Spawn background tasks to refill this pool toward its effective capacity.
    ///
    /// Refill budget: `needed = effective_cap - (idle.len + in_flight)`.
    /// Including `in_flight` prevents duplicate spawning when earlier tasks are
    /// still connecting (the main fix over a naive `capacity - idle.len` formula).
    fn replenish(self: Arc<Self>, pool: Arc<AdaptivePool>) {
        let effective_cap = self.effective_cap(pool.max_per_dest);
        let (idle_len, in_flight) = {
            let guard = self.idle.lock();
            (guard.len(), self.in_flight.load(Ordering::Relaxed))
        };
        let global_idle = pool.global_idle.load(Ordering::Relaxed);
        let global_budget = (pool.max_global_idle as i64).saturating_sub(global_idle) as usize;
        let needed = effective_cap
            .saturating_sub(idle_len + in_flight)
            .min(global_budget);

        for _ in 0..needed {
            let dp = Arc::clone(&self);
            let p = Arc::clone(&pool);
            dp.in_flight.fetch_add(1, Ordering::Relaxed);
            tokio::spawn(async move {
                match tcp_connect(dp.addr).await {
                    Ok(stream) => {
                        let _ = stream.set_nodelay(true);
                        {
                            let mut guard = dp.idle.lock();
                            // Re-check per-dest and global budgets under lock.
                            if guard.len() < p.max_per_dest
                                && p.global_idle.load(Ordering::Relaxed)
                                    < p.max_global_idle as i64
                            {
                                guard.push_back((stream, Instant::now()));
                                p.global_idle.fetch_add(1, Ordering::Relaxed);
                            }
                            // Over budget: stream drops here, closing the connection.
                        }
                        dp.in_flight.fetch_sub(1, Ordering::Relaxed);
                    }
                    Err(_) => {
                        p.errors.fetch_add(1, Ordering::Relaxed);
                        dp.in_flight.fetch_sub(1, Ordering::Relaxed);
                    }
                }
            });
        }
    }
}

/// Global adaptive pool shared across all outbound requests in Fast Profile.
///
/// Capacity per destination starts at 0 and ramps with observed traffic.
/// Hard limits prevent runaway memory use; all metrics are lock-free counters.
struct AdaptivePool {
    dests: DashMap<SocketAddr, Arc<DestPool>>,
    max_per_dest: usize,
    max_global_idle: usize,
    max_dests: usize,
    idle_ttl: Duration,
    /// Net idle-socket count (incremented on push, decremented on pop/stale).
    /// Signed to tolerate transient races; treated as 0 if negative.
    global_idle: AtomicI64,
    hits: AtomicU64,
    misses: AtomicU64,
    stales: AtomicU64,
    errors: AtomicU64,
}

impl AdaptivePool {
    fn new(cfg: PoolConfig) -> Arc<Self> {
        Arc::new(Self {
            dests: DashMap::new(),
            max_per_dest: cfg.max_per_dest,
            max_global_idle: cfg.max_global_idle,
            max_dests: cfg.max_dests,
            idle_ttl: cfg.idle_ttl,
            global_idle: AtomicI64::new(0),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            stales: AtomicU64::new(0),
            errors: AtomicU64::new(0),
        })
    }

    /// Look up or lazily create the pool for `addr`.
    ///
    /// Returns `None` if the per-pool destination limit has been reached;
    /// callers should take the cold path (fresh connect) in that case.
    fn get_or_create(&self, addr: SocketAddr) -> Option<Arc<DestPool>> {
        if let Some(entry) = self.dests.get(&addr) {
            return Some(Arc::clone(&*entry));
        }
        // Don't create new pools if at the destination ceiling.
        if self.dests.len() >= self.max_dests {
            return None;
        }
        Some(Arc::clone(
            &*self
                .dests
                .entry(addr)
                .or_insert_with(|| DestPool::new(addr)),
        ))
    }
}

// ── FreedomOutbound ──────────────────────────────────────────────────────────

/// The freedom outbound: connects directly to the destination.
pub struct FreedomOutbound {
    tag: String,
    dns: Option<Arc<DnsModule>>,
    /// Present only in Fast Profile (pool disabled when `None`).
    pool: Option<Arc<AdaptivePool>>,
}

impl FreedomOutbound {
    /// Compat mode: no connection pooling.
    pub fn new(tag: impl Into<String>) -> Arc<Self> {
        Arc::new(Self { tag: tag.into(), dns: None, pool: None })
    }

    /// Fast Profile: adaptive connection pooling.
    pub fn new_pooled(tag: impl Into<String>, cfg: PoolConfig) -> Arc<Self> {
        Arc::new(Self { tag: tag.into(), dns: None, pool: Some(AdaptivePool::new(cfg)) })
    }

    /// Compat mode with custom DNS: no connection pooling.
    pub fn new_with_dns(tag: impl Into<String>, dns: Arc<DnsModule>) -> Arc<Self> {
        Arc::new(Self { tag: tag.into(), dns: Some(dns), pool: None })
    }

    /// Fast Profile with custom DNS: adaptive connection pooling.
    pub fn new_with_dns_pooled(
        tag: impl Into<String>,
        dns: Arc<DnsModule>,
        cfg: PoolConfig,
    ) -> Arc<Self> {
        Arc::new(Self {
            tag: tag.into(),
            dns: Some(dns),
            pool: Some(AdaptivePool::new(cfg)),
        })
    }

    async fn resolve(&self, dest: &Address) -> Result<SocketAddr, ProxyError> {
        match dest {
            Address::Ipv4(ip, port) => Ok(SocketAddr::new(IpAddr::V4(*ip), *port)),
            Address::Ipv6(ip, port) => Ok(SocketAddr::new(IpAddr::V6(*ip), *port)),
            Address::Domain(name, port) => {
                if let Some(dns) = &self.dns {
                    let ips = dns.resolve(name).await?;
                    let ip = ips.into_iter().next().ok_or_else(|| {
                        ProxyError::DnsResolutionFailed(format!("{name}: no records returned"))
                    })?;
                    return Ok(SocketAddr::new(ip, *port));
                }

                let addrs: Vec<SocketAddr> = tokio::net::lookup_host((name.as_str(), *port))
                    .await
                    .map_err(|e| ProxyError::DnsResolutionFailed(format!("{name}: {e}")))?
                    .collect();

                addrs
                    .into_iter()
                    .next()
                    .ok_or_else(|| ProxyError::DnsResolutionFailed(name.clone()))
            }
        }
    }
}

#[async_trait]
impl OutboundHandler for FreedomOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn connect(&self, _ctx: &Context, dest: &Address) -> Result<BoxedStream, ProxyError> {
        let addr = self.resolve(dest).await?;

        debug!(dest = %dest, resolved = %addr, "freedom: connecting");

        if let Some(pool) = &self.pool {
            if let Some(dest_pool) = pool.get_or_create(addr) {
                // Count this request toward adaptive capacity.
                dest_pool.conn_count.fetch_add(1, Ordering::Relaxed);

                let (taken, stale) = dest_pool.try_take(pool.idle_ttl);

                // Update the global idle counter for every popped slot.
                let total_popped = stale + if taken.is_some() { 1 } else { 0 };
                if total_popped > 0 {
                    pool.global_idle.fetch_sub(total_popped as i64, Ordering::Relaxed);
                }
                if stale > 0 {
                    pool.stales.fetch_add(stale as u64, Ordering::Relaxed);
                }

                // Trigger background refill (accounts for new conn_count tier).
                Arc::clone(&dest_pool).replenish(Arc::clone(pool));

                if let Some(stream) = taken {
                    pool.hits.fetch_add(1, Ordering::Relaxed);
                    return Ok(Box::new(stream));
                }
                pool.misses.fetch_add(1, Ordering::Relaxed);
            }
        }

        // Cold path: dial a fresh connection (pool disabled, at dest limit, or miss).
        let stream = tcp_connect(addr).await?;
        stream.set_nodelay(true)?;
        Ok(Box::new(stream))
    }
}
