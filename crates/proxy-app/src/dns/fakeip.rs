//! FakeIP pool — assigns synthetic IP addresses to domain names.
//!
//! In TUN/transparent-proxy mode, the proxy intercepts all DNS queries and
//! returns a "fake" IP from a reserved range (`198.18.0.0/15` by default).
//! When traffic arrives at that fake IP, the proxy looks up the original domain
//! and connects to the real destination.
//!
//! # Pool management
//!
//! IPs are drawn from the configured CIDR. The pool uses two `DashMap`s for
//! O(1) bidirectional lookup plus an LRU list to evict the least-recently-used
//! domain when the pool is full.

use std::net::Ipv4Addr;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use dashmap::DashMap;
use ipnet::Ipv4Net;
use lru::LruCache;
use parking_lot::Mutex;

/// A pool of fake IPv4 addresses allocated to domain names.
pub struct FakeIpPool {
    network: Ipv4Net,
    next: Arc<AtomicU32>,
    pool_size: usize,
    forward: Arc<DashMap<String, Ipv4Addr>>,
    reverse: Arc<DashMap<u32, String>>,
    lru: Mutex<LruCache<String, ()>>,
    /// Serialises slow-path allocation (never call `forward` helpers under `entry()`).
    alloc_lock: Mutex<()>,
}

impl FakeIpPool {
    /// Create a new `FakeIpPool` from a CIDR range string.
    pub fn new(cidr: &str) -> anyhow::Result<Self> {
        let network: Ipv4Net = cidr
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid FakeIP CIDR '{cidr}': {e}"))?;
        let network_u32 = u32::from(network.network());
        let broadcast_u32 = u32::from(network.broadcast());
        let pool_size = (broadcast_u32 - network_u32).saturating_sub(1) as usize;
        let cap = NonZeroUsize::new(pool_size.max(1)).expect("pool capacity");
        Ok(Self {
            network,
            next: Arc::new(AtomicU32::new(network_u32 + 1)),
            pool_size: pool_size.max(1),
            forward: Arc::new(DashMap::new()),
            reverse: Arc::new(DashMap::new()),
            lru: Mutex::new(LruCache::new(cap)),
            alloc_lock: Mutex::new(()),
        })
    }

    /// Allocate or retrieve the fake IP for `domain`.
    pub fn allocate(&self, domain: &str) -> Ipv4Addr {
        if let Some(ip) = self.forward.get(domain) {
            self.lru.lock().get(&domain.to_string());
            return *ip;
        }

        let _guard = self.alloc_lock.lock();

        if let Some(ip) = self.forward.get(domain) {
            self.lru.lock().get(&domain.to_string());
            return *ip;
        }

        let ip = self.claim_ip();
        let domain_key = domain.to_string();
        self.forward.insert(domain_key.clone(), ip);
        self.reverse.insert(u32::from(ip), domain_key.clone());
        self.lru.lock().put(domain_key, ());
        ip
    }

    /// Return the domain name that was assigned `ip`, or `None`.
    pub fn reverse(&self, ip: Ipv4Addr) -> Option<String> {
        self.reverse.get(&u32::from(ip)).map(|v| v.clone())
    }

    /// Returns `true` if `ip` falls within this pool's CIDR range.
    pub fn is_fake(&self, ip: Ipv4Addr) -> bool {
        self.network.contains(&ip)
    }

    fn claim_ip(&self) -> Ipv4Addr {
        if self.forward.len() >= self.pool_size {
            let evicted = self.lru.lock().pop_lru().map(|(domain, _)| domain);
            if let Some(evicted) = evicted {
                if let Some((_, ip)) = self.forward.remove(&evicted) {
                    self.reverse.remove(&u32::from(ip));
                    return ip;
                }
            }
        }

        let network_u32 = u32::from(self.network.network());
        let broadcast_u32 = u32::from(self.network.broadcast());
        let raw = self
            .next
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                let next = if n >= broadcast_u32 {
                    network_u32 + 1
                } else {
                    n + 1
                };
                Some(next)
            })
            .unwrap_or_else(|current| current);

        let candidate = if raw < network_u32 + 1 || raw >= broadcast_u32 {
            network_u32 + 1
        } else {
            raw
        };

        let ip = Ipv4Addr::from(candidate);
        if let Some((_, old_domain)) = self.reverse.remove(&u32::from(ip)) {
            self.forward.remove(&old_domain);
            self.lru.lock().pop(&old_domain);
        }
        ip
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocate_returns_stable_ip() {
        let pool = FakeIpPool::new("198.18.0.0/15").unwrap();
        let ip1 = pool.allocate("example.com");
        let ip2 = pool.allocate("example.com");
        assert_eq!(ip1, ip2);
    }

    #[test]
    fn different_domains_different_ips() {
        let pool = FakeIpPool::new("198.18.0.0/15").unwrap();
        let ip1 = pool.allocate("a.com");
        let ip2 = pool.allocate("b.com");
        assert_ne!(ip1, ip2);
    }

    #[test]
    fn reverse_lookup() {
        let pool = FakeIpPool::new("198.18.0.0/15").unwrap();
        let ip = pool.allocate("reverse-test.com");
        assert_eq!(pool.reverse(ip).unwrap(), "reverse-test.com");
    }

    #[test]
    fn is_fake_in_range() {
        let pool = FakeIpPool::new("198.18.0.0/15").unwrap();
        assert!(pool.is_fake(Ipv4Addr::new(198, 18, 0, 1)));
        assert!(!pool.is_fake(Ipv4Addr::new(198, 20, 0, 1)));
    }

    #[test]
    fn pool_exhaustion_evicts_lru_domain() {
        let pool = FakeIpPool::new("198.18.0.0/30").unwrap();
        let ip_a = pool.allocate("a.com");
        let ip_b = pool.allocate("b.com");
        pool.allocate("a.com");
        let ip_c = pool.allocate("c.com");

        assert_eq!(pool.reverse(ip_a), Some("a.com".into()));
        assert_eq!(pool.reverse(ip_c), Some("c.com".into()));
        assert_eq!(ip_c, ip_b);
        // b.com was evicted; its former IP now belongs to c.com.
        assert_ne!(pool.allocate("b.com"), ip_b);
    }

    #[test]
    fn invalid_cidr_returns_error() {
        assert!(FakeIpPool::new("not-a-cidr").is_err());
    }

    #[test]
    fn concurrent_allocate_same_domain_is_stable() {
        use std::sync::Barrier;
        use std::thread;

        let pool = Arc::new(FakeIpPool::new("198.18.0.0/15").unwrap());
        let barrier = Arc::new(Barrier::new(32));
        let mut handles = Vec::new();
        for _ in 0..32 {
            let pool = Arc::clone(&pool);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                pool.allocate("race.com")
            }));
        }
        let ips: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert!(ips.iter().all(|ip| *ip == ips[0]));
    }
}
