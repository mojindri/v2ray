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
use std::sync::Arc;

use async_trait::async_trait;
use dashmap::DashMap;
use parking_lot::Mutex;
use tokio::net::TcpStream;
use tracing::debug;

use blackwire_app::context::Context;
use blackwire_app::dns::DnsModule;
use blackwire_app::features::OutboundHandler;
use blackwire_common::{tcp_connect, Address, BoxedStream, ProxyError};

/// A small pool of pre-established TCP connections to a single remote address.
///
/// Connections are taken synchronously (no await required). After each take,
/// one background task is spawned to restore the pool to capacity. This keeps
/// the pool filled without blocking the caller.
struct TcpConnPool {
    addr: SocketAddr,
    capacity: usize,
    inner: Mutex<VecDeque<TcpStream>>,
}

impl TcpConnPool {
    fn new(addr: SocketAddr, capacity: usize) -> Arc<Self> {
        let pool = Arc::new(Self {
            addr,
            capacity,
            inner: Mutex::new(VecDeque::with_capacity(capacity)),
        });
        Arc::clone(&pool).replenish();
        pool
    }

    /// Returns an idle pre-established connection, or `None` if the pool is empty.
    ///
    /// Performs a non-blocking liveness check: connections closed by the peer
    /// (EOF or error) are silently discarded until a live one is found.
    fn try_take(&self) -> Option<TcpStream> {
        let mut guard = self.inner.lock();
        while let Some(stream) = guard.pop_front() {
            // Non-blocking peek: WouldBlock = alive and idle; anything else = stale.
            let mut probe = [0u8; 1];
            match stream.try_read(&mut probe) {
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Some(stream),
                _ => { /* stale — discard and try next */ }
            }
        }
        None
    }

    /// Spawns background tasks to refill the pool up to capacity.
    fn replenish(self: Arc<Self>) {
        let needed = {
            let guard = self.inner.lock();
            self.capacity.saturating_sub(guard.len())
        };
        for _ in 0..needed {
            let pool = Arc::clone(&self);
            tokio::spawn(async move {
                if let Ok(stream) = tcp_connect(pool.addr).await {
                    let _ = stream.set_nodelay(true);
                    let mut guard = pool.inner.lock();
                    if guard.len() < pool.capacity {
                        guard.push_back(stream);
                    }
                }
            });
        }
    }
}

/// The freedom outbound: connects directly to the destination.
pub struct FreedomOutbound {
    tag: String,
    dns: Option<Arc<DnsModule>>,
    pool_capacity: usize,
    pools: DashMap<SocketAddr, Arc<TcpConnPool>>,
}

impl FreedomOutbound {
    /// Create a freedom outbound using the OS resolver for domains.
    /// `pool_capacity` pre-established connections are maintained per destination.
    /// Pass `0` to disable pooling.
    pub fn new(tag: impl Into<String>, pool_capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            tag: tag.into(),
            dns: None,
            pool_capacity,
            pools: DashMap::new(),
        })
    }

    /// Create a freedom outbound that resolves domains via the configured DNS module.
    pub fn new_with_dns(
        tag: impl Into<String>,
        dns: Arc<DnsModule>,
        pool_capacity: usize,
    ) -> Arc<Self> {
        Arc::new(Self {
            tag: tag.into(),
            dns: Some(dns),
            pool_capacity,
            pools: DashMap::new(),
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

        if self.pool_capacity > 0 {
            // Fast path: grab a pre-established connection from the pool.
            let pool = Arc::clone(
                &*self
                    .pools
                    .entry(addr)
                    .or_insert_with(|| TcpConnPool::new(addr, self.pool_capacity)),
            );

            if let Some(stream) = pool.try_take() {
                Arc::clone(&pool).replenish();
                return Ok(Box::new(stream));
            }
            // Pool miss: trigger background refill and fall through to cold-path.
            Arc::clone(&pool).replenish();
        }

        // Cold path: dial fresh connection (pool disabled, or pool was empty).
        let stream = tcp_connect(addr).await?;
        stream.set_nodelay(true)?;
        Ok(Box::new(stream))
    }
}
