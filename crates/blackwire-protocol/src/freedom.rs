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
/// Pass to `FreedomOutbound::new_pooled` / `new_with_dns_pooled` to enable
/// pooling in Fast Profile. In Compat mode use `new` / `new_with_dns` instead.
pub struct PoolConfig {
    /// Per-destination ceiling. Effective capacity starts at 0 and ramps
    /// geometrically with recent traffic; this is never pre-allocated.
    pub max_per_dest: usize,
    /// Maximum combined idle + in-flight-refill sockets across all destinations.
    pub max_global_idle: usize,
    /// Maximum number of distinct destination pools to maintain.
    /// When full, the least-recently-used pool is evicted.
    pub max_dests: usize,
    /// Discard idle connections older than this (prevents stale-socket reuse).
    pub idle_ttl: Duration,
    /// Length of the sliding window used to measure destination hotness.
    /// Traffic older than this fully decays; a destination with no traffic in
    /// 2× this window resets to cold (capacity 0).
    pub hotness_window: Duration,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_per_dest: 32,
            max_global_idle: 512,
            max_dests: 256,
            idle_ttl: Duration::from_secs(30),
            hotness_window: Duration::from_secs(60),
        }
    }
}

// ── Hotness meter ─────────────────────────────────────────────────────────────

/// Two-bucket sliding-window hit counter.
///
/// Divides time into windows of `window_duration`. On each `record_and_get`
/// call the current hit count is incremented; after one window elapses the
/// previous window's count contributes fully, after two windows the
/// destination is considered cold (count = 0). This lets hot destinations
/// cool naturally when traffic stops.
struct HotnessMeter {
    current: u64,
    previous: u64,
    window_start: Instant,
    window_duration: Duration,
}

impl HotnessMeter {
    fn new(window_duration: Duration) -> Self {
        Self {
            current: 0,
            previous: 0,
            window_start: Instant::now(),
            window_duration,
        }
    }

    /// Record one connection and return the current sliding-window hit count.
    fn record_and_get(&mut self) -> u64 {
        let now = Instant::now();
        let elapsed = now.duration_since(self.window_start);
        if elapsed >= self.window_duration * 2 {
            // More than 2 windows with no calls: fully cold.
            self.previous = 0;
            self.current = 1;
            self.window_start = now;
        } else if elapsed >= self.window_duration {
            // One window elapsed: rotate.
            self.previous = self.current;
            self.current = 1;
            self.window_start = now;
        } else {
            self.current += 1;
        }
        // Sliding estimate: previous + current covers the last full window.
        self.previous.saturating_add(self.current)
    }

    /// Return the sliding-window estimate without recording a hit.
    /// Used by `replenish` to read capacity without mutating state.
    fn estimate(&self) -> u64 {
        let elapsed = self.window_start.elapsed();
        if elapsed >= self.window_duration * 2 {
            0
        } else if elapsed >= self.window_duration {
            self.current
        } else {
            self.previous.saturating_add(self.current)
        }
    }
}

fn tier_from_count(count: u64, max: usize) -> usize {
    let tier = match count {
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

// ── Per-destination pool ───────────────────────────────────────────────────────

/// Check whether a `TcpStream` is in the `TCP_ESTABLISHED` state via
/// `getsockopt(TCP_INFO)`.
///
/// `try_read` returning `WouldBlock` only proves the receive buffer is empty;
/// it cannot distinguish an idle-but-alive socket from a half-open connection
/// (peer dead, no FIN/RST received yet). `TCP_INFO.tcpi_state` reflects the
/// kernel TCP state machine and catches the half-open case.
///
/// Falls back to `true` (assume alive) on non-Linux or if `getsockopt` fails,
/// so we never incorrectly discard a socket we cannot inspect.
fn tcp_is_established(stream: &TcpStream) -> bool {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        unsafe {
            let mut info: libc::tcp_info = std::mem::zeroed();
            let mut len = std::mem::size_of::<libc::tcp_info>() as libc::socklen_t;
            let rc = libc::getsockopt(
                stream.as_raw_fd(),
                libc::IPPROTO_TCP,
                libc::TCP_INFO,
                &mut info as *mut libc::tcp_info as *mut libc::c_void,
                &mut len,
            );
            // tcpi_state == 1 is TCP_ESTABLISHED in the Linux kernel tcp_states enum.
            rc == 0 && info.tcpi_state == 1
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = stream;
        true
    }
}

/// Epoch for `last_used_ms` — set once on first pool creation.
static POOL_EPOCH: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
fn pool_epoch() -> Instant {
    *POOL_EPOCH.get_or_init(Instant::now)
}
fn now_ms() -> u64 {
    pool_epoch().elapsed().as_millis() as u64
}

struct DestPool {
    addr: SocketAddr,
    /// Sliding-window hit count; drives adaptive capacity tier.
    hotness: Mutex<HotnessMeter>,
    /// Background refill tasks currently in flight (per-destination).
    in_flight: AtomicUsize,
    /// Idle pre-established connections with their last-use timestamps.
    idle: Mutex<VecDeque<(TcpStream, Instant)>>,
    /// Milliseconds since POOL_EPOCH of the last `try_take` call.
    /// Used for LRU eviction without locking.
    last_used_ms: AtomicU64,
}

impl DestPool {
    fn new(addr: SocketAddr, window_duration: Duration) -> Arc<Self> {
        Arc::new(Self {
            addr,
            hotness: Mutex::new(HotnessMeter::new(window_duration)),
            in_flight: AtomicUsize::new(0),
            idle: Mutex::new(VecDeque::new()),
            last_used_ms: AtomicU64::new(now_ms()),
        })
    }

    /// Record one connection and return the current effective pool capacity.
    fn record_and_cap(&self, max: usize) -> usize {
        let count = self.hotness.lock().record_and_get();
        tier_from_count(count, max)
    }

    /// Return the current effective capacity without recording a hit.
    fn current_cap(&self, max: usize) -> usize {
        let count = self.hotness.lock().estimate();
        tier_from_count(count, max)
    }

    /// Pop the next live, non-expired idle connection.
    ///
    /// Returns `(stream, stale_count)` where `stale_count` is the number of
    /// slots discarded; caller must subtract that from `AdaptivePool::global_idle`.
    fn try_take(&self, idle_ttl: Duration) -> (Option<TcpStream>, usize) {
        // Update LRU timestamp unconditionally so a destination with all-stale
        // or empty idle slots isn't treated as cold by evict_lru().
        self.last_used_ms.store(now_ms(), Ordering::Relaxed);
        let mut guard = self.idle.lock();
        let now = Instant::now();
        let mut stale = 0usize;
        while let Some((stream, last_use)) = guard.pop_front() {
            if now.duration_since(last_use) > idle_ttl {
                stale += 1;
                continue;
            }
            // Two-stage liveness probe:
            //
            // Stage 1 — try_read: catches closed connections (peer sent FIN/RST)
            // by reading any buffered data. WouldBlock means the socket is idle
            // and alive from the kernel's receive-buffer perspective.
            //
            // Stage 2 — TCP_INFO (Linux): checks the kernel TCP state machine.
            // Catches half-open connections where the peer is dead but no FIN/RST
            // has arrived yet (e.g. network partition, OS crash). try_read returns
            // WouldBlock in those cases because the receive buffer is empty, but
            // the TCP state will not be ESTABLISHED.
            let mut probe = [0u8; 1];
            let alive = match stream.try_read(&mut probe) {
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    tcp_is_established(&stream)
                }
                _ => false, // EOF or error: definitely stale.
            };
            if alive {
                return (Some(stream), stale);
            }
            stale += 1;
        }
        (None, stale)
    }

    /// Spawn background tasks to refill toward effective capacity.
    ///
    /// **Pre-reservation**: each slot to spawn is claimed in `global_idle`
    /// before the task is launched. This prevents two concurrent `replenish`
    /// calls from both passing the budget check and over-filling the pool.
    /// The task releases the reservation if it fails or the per-dest queue
    /// is already full.
    ///
    /// **Refill formula**: `needed = effective_cap − (idle.len + in_flight)`.
    /// Including `in_flight` prevents duplicate spawning when earlier tasks
    /// are still connecting.
    fn replenish(self: Arc<Self>, pool: Arc<AdaptivePool>) {
        let cap = self.current_cap(pool.max_per_dest);
        let (idle_len, in_flight) = {
            let guard = self.idle.lock();
            (guard.len(), self.in_flight.load(Ordering::Relaxed))
        };

        // global_idle counts both actual idle sockets AND reserved slots
        // (in-flight refills). This is the total "committed" count.
        let committed = pool.global_idle.load(Ordering::Relaxed);
        let global_budget = (pool.max_global_idle as i64)
            .saturating_sub(committed)
            .max(0) as usize;

        let needed = cap
            .saturating_sub(idle_len + in_flight)
            .min(global_budget);

        if needed == 0 {
            return;
        }

        // Pre-reserve slots with a CAS loop so two concurrent replenish() calls
        // can't both read the same global_idle and both claim the full budget.
        let to_spawn = loop {
            let cur = pool.global_idle.load(Ordering::Relaxed);
            let budget = (pool.max_global_idle as i64 - cur).max(0) as usize;
            let want = needed.min(budget);
            if want == 0 {
                return;
            }
            if pool
                .global_idle
                .compare_exchange(cur, cur + want as i64, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                break want;
            }
        };

        for _ in 0..to_spawn {
            let dp = Arc::clone(&self);
            let p = Arc::clone(&pool);
            dp.in_flight.fetch_add(1, Ordering::Relaxed);
            tokio::spawn(async move {
                match tcp_connect(dp.addr).await {
                    Ok(stream) => {
                        let _ = stream.set_nodelay(true);
                        {
                            let mut guard = dp.idle.lock();
                            if guard.len() < p.max_per_dest {
                                guard.push_back((stream, Instant::now()));
                                // Reservation held — no extra global_idle increment.
                            } else {
                                // Per-dest queue is full; release the reservation.
                                p.global_idle.fetch_sub(1, Ordering::Relaxed);
                                // Stream drops here, closing the connection.
                            }
                        }
                        dp.in_flight.fetch_sub(1, Ordering::Relaxed);
                    }
                    Err(_) => {
                        // Release reservation for this failed slot.
                        p.global_idle.fetch_sub(1, Ordering::Relaxed);
                        metrics::counter!(
                            "freedom_pool_errors_total",
                            "outbound" => p.tag.clone()
                        )
                        .increment(1);
                        dp.in_flight.fetch_sub(1, Ordering::Relaxed);
                    }
                }
            });
        }
    }
}

// ── Global pool manager ───────────────────────────────────────────────────────

/// Global adaptive pool shared across all outbound requests in Fast Profile.
///
/// Per-destination capacity ramps with recent traffic and decays when traffic
/// stops. Hard limits bound memory use. All metrics are exported via the
/// `metrics` crate (Prometheus-compatible).
///
/// Metrics emitted (tagged `outbound = <tag>`):
/// - `freedom_pool_hits_total`   — pre-established connection reused
/// - `freedom_pool_misses_total` — pool empty; fell through to cold connect
/// - `freedom_pool_stales_total` — idle connections discarded (TTL / dead peer)
/// - `freedom_pool_errors_total` — background refill connect failures
struct AdaptivePool {
    tag: String,
    dests: DashMap<SocketAddr, Arc<DestPool>>,
    max_per_dest: usize,
    max_global_idle: usize,
    max_dests: usize,
    idle_ttl: Duration,
    hotness_window: Duration,
    /// Committed slots: actual idle sockets + in-flight refill reservations.
    /// Signed to absorb transient races without wrapping.
    global_idle: AtomicI64,
}

impl AdaptivePool {
    fn new(tag: String, cfg: PoolConfig) -> Arc<Self> {
        Arc::new(Self {
            tag,
            dests: DashMap::new(),
            max_per_dest: cfg.max_per_dest,
            max_global_idle: cfg.max_global_idle,
            max_dests: cfg.max_dests,
            idle_ttl: cfg.idle_ttl,
            hotness_window: cfg.hotness_window,
            global_idle: AtomicI64::new(0),
        })
    }

    /// Return the pool for `addr`, creating it if needed.
    ///
    /// When `max_dests` is reached the least-recently-used pool is evicted
    /// to make room, freeing its idle sockets and global budget.
    fn get_or_create(&self, addr: SocketAddr) -> Arc<DestPool> {
        if let Some(entry) = self.dests.get(&addr) {
            return Arc::clone(&*entry);
        }
        if self.dests.len() >= self.max_dests {
            self.evict_lru();
        }
        Arc::clone(
            &*self
                .dests
                .entry(addr)
                .or_insert_with(|| DestPool::new(addr, self.hotness_window)),
        )
    }

    /// Remove the least-recently-used destination pool and return its idle
    /// sockets to the global budget.
    fn evict_lru(&self) {
        let lru_key = self
            .dests
            .iter()
            .min_by_key(|e| e.value().last_used_ms.load(Ordering::Relaxed))
            .map(|e| *e.key());

        if let Some(key) = lru_key {
            if let Some((_, evicted)) = self.dests.remove(&key) {
                // Slots in the idle queue were counted in global_idle; return them.
                let idle_count = evicted.idle.lock().len() as i64;
                if idle_count > 0 {
                    self.global_idle.fetch_sub(idle_count, Ordering::Relaxed);
                }
            }
        }
    }
}

// ── FreedomOutbound ───────────────────────────────────────────────────────────

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
        let tag = tag.into();
        let pool = AdaptivePool::new(tag.clone(), cfg);
        Arc::new(Self { tag, dns: None, pool: Some(pool) })
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
        let tag = tag.into();
        let pool = AdaptivePool::new(tag.clone(), cfg);
        Arc::new(Self { tag, dns: Some(dns), pool: Some(pool) })
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
            let dest_pool = pool.get_or_create(addr);

            // Record this connection, get current adaptive capacity tier.
            let _cap = dest_pool.record_and_cap(pool.max_per_dest);

            let (taken, stale) = dest_pool.try_take(pool.idle_ttl);

            // Stale pops held a reservation in global_idle; release them.
            if stale > 0 {
                pool.global_idle.fetch_sub(stale as i64, Ordering::Relaxed);
                metrics::counter!(
                    "freedom_pool_stales_total",
                    "outbound" => pool.tag.clone()
                )
                .increment(stale as u64);
            }

            // Trigger background refill regardless of hit/miss.
            Arc::clone(&dest_pool).replenish(Arc::clone(pool));

            if let Some(stream) = taken {
                // The socket was a real idle slot counted in global_idle; decrement
                // now that it has left the pool.
                pool.global_idle.fetch_sub(1, Ordering::Relaxed);
                metrics::counter!(
                    "freedom_pool_hits_total",
                    "outbound" => pool.tag.clone()
                )
                .increment(1);
                return Ok(Box::new(stream));
            }
            metrics::counter!(
                "freedom_pool_misses_total",
                "outbound" => pool.tag.clone()
            )
            .increment(1);
        }

        // Cold path: dial a fresh connection (pool disabled or miss).
        let stream = tcp_connect(addr).await?;
        stream.set_nodelay(true)?;
        Ok(Box::new(stream))
    }
}
