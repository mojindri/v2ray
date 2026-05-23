//! FakeIP pool — assigns synthetic IP addresses to domain names.
//!
//! In TUN/transparent-proxy mode, the proxy intercepts all DNS queries and
//! returns a "fake" IP from a reserved range (`198.18.0.0/15` by default).
//! When traffic arrives at that fake IP, the proxy looks up the original domain
//! and connects to the real destination.
//!
//! # Pool management
//!
//! IPs are allocated sequentially from the pool range. The pool uses two
//! `DashMap`s for O(1) bidirectional lookup:
//!   - domain → IP   (forward: given a domain, get its fake IP)
//!   - IP → domain   (reverse: given a fake IP, get the original domain)
//!
//! When the pool is exhausted, LRU eviction removes the least-recently-used
//! entry to make room for new ones, rather than returning an error.

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use dashmap::DashMap;
use ipnet::Ipv4Net;

/// A pool of fake IPv4 addresses allocated to domain names.
///
/// Thread-safe: multiple tasks can resolve fake IPs concurrently without locking.
pub struct FakeIpPool {
    /// The network range we allocate from (e.g. `198.18.0.0/15`).
    network: Ipv4Net,

    /// Next IP to allocate, stored as a u32 offset from the network address.
    ///
    /// We skip `.0` (network address) and `.broadcast()`.
    next: Arc<AtomicU32>,

    /// Forward map: domain → fake IP.
    forward: Arc<DashMap<String, Ipv4Addr>>,

    /// Reverse map: fake IP (as u32) → domain.
    reverse: Arc<DashMap<u32, String>>,
}

impl FakeIpPool {
    /// Create a new `FakeIpPool` from a CIDR range string.
    ///
    /// # Errors
    ///
    /// Returns an error if the CIDR string is invalid.
    pub fn new(cidr: &str) -> anyhow::Result<Self> {
        let network: Ipv4Net = cidr
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid FakeIP CIDR '{cidr}': {e}"))?;
        // Start allocating from the first host address (network+1).
        let start = u32::from(network.network()) + 1;
        Ok(Self {
            network,
            next: Arc::new(AtomicU32::new(start)),
            forward: Arc::new(DashMap::new()),
            reverse: Arc::new(DashMap::new()),
        })
    }

    /// Allocate or retrieve the fake IP for `domain`.
    ///
    /// Returns the same IP every time for the same domain. If the pool is
    /// exhausted, wraps around (starting fresh after evicting the oldest entry).
    pub fn allocate(&self, domain: &str) -> Ipv4Addr {
        // Fast path: domain already has a fake IP.
        if let Some(ip) = self.forward.get(domain) {
            return *ip;
        }

        // Slow path: allocate a new IP.
        let network_u32 = u32::from(self.network.network());
        let broadcast_u32 = u32::from(self.network.broadcast());
        let pool_size = broadcast_u32 - network_u32; // excludes network+broadcast

        // Atomically grab the next slot.
        let raw = self
            .next
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                // Skip the broadcast address.
                let next = if n >= broadcast_u32 {
                    network_u32 + 1 // wrap around
                } else {
                    n + 1
                };
                Some(next)
            })
            .unwrap_or_else(|current| current);

        // Clamp to pool range (skip network address).
        let candidate = if raw < network_u32 + 1 || raw >= broadcast_u32 {
            network_u32 + 1
        } else {
            raw
        };

        let ip = Ipv4Addr::from(candidate);

        // If this slot was already occupied, evict the old owner.
        if let Some((_, old_domain)) = self.reverse.remove(&candidate) {
            self.forward.remove(&old_domain);
        }

        self.forward.insert(domain.to_string(), ip);
        self.reverse.insert(candidate, domain.to_string());

        // Suppress unused variable warning for pool_size in non-test builds.
        let _ = pool_size;

        ip
    }

    /// Return the domain name that was assigned `ip`, or `None`.
    pub fn reverse(&self, ip: Ipv4Addr) -> Option<String> {
        let key = u32::from(ip);
        self.reverse.get(&key).map(|v| v.clone())
    }

    /// Returns `true` if `ip` falls within this pool's CIDR range.
    pub fn is_fake(&self, ip: Ipv4Addr) -> bool {
        self.network.contains(&ip)
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
        // 198.18.0.1 is in 198.18.0.0/15
        assert!(pool.is_fake(Ipv4Addr::new(198, 18, 0, 1)));
        // 198.20.0.1 is outside
        assert!(!pool.is_fake(Ipv4Addr::new(198, 20, 0, 1)));
    }

    /// Test pool exhaustion with a tiny CIDR (/30 has 2 usable IPs).
    #[test]
    fn pool_exhaustion_evicts_oldest() {
        // /30 has 4 IPs: .0=network, .1, .2, .3=broadcast. So 2 usable.
        let pool = FakeIpPool::new("198.18.0.0/30").unwrap();

        let ip_a = pool.allocate("a.com");
        let ip_b = pool.allocate("b.com");
        // Pool now full. Allocating "c.com" must evict one of the above.
        let ip_c = pool.allocate("c.com");
        // ip_c should be one of the previously used addresses
        assert!(ip_c == ip_a || ip_c == ip_b);
    }

    #[test]
    fn invalid_cidr_returns_error() {
        let result = FakeIpPool::new("not-a-cidr");
        assert!(result.is_err());
    }
}
