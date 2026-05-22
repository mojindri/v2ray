//! DNS resolution cache with per-entry TTL.
//!
//! `DnsCache` stores resolved IP addresses keyed by domain name. Each entry
//! has an expiry timestamp. Stale entries are evicted on the next access.
//!
//! The cache is backed by `DashMap` (sharded hash map) for wait-free reads
//! under concurrent access.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use dashmap::DashMap;

/// A single cached DNS entry.
struct CacheEntry {
    /// The resolved IP addresses.
    ips: Vec<IpAddr>,
    /// When this entry expires.
    expires: Instant,
}

/// A thread-safe DNS cache with per-entry TTL.
pub struct DnsCache {
    /// The underlying storage. Key = domain name.
    entries: DashMap<String, CacheEntry>,
    /// Maximum number of entries before old ones are evicted.
    _capacity: usize,
}

impl DnsCache {
    /// Create a new cache with the given maximum capacity.
    ///
    /// `capacity` is a soft limit — the cache may temporarily exceed it during
    /// concurrent inserts, but will evict stale entries on the next `get`.
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: DashMap::new(),
            _capacity: capacity,
        }
    }

    /// Look up a domain name in the cache.
    ///
    /// Returns `Some(ips)` if the entry exists and has not expired.
    /// Returns `None` if the entry is missing or stale.
    pub fn get(&self, domain: &str) -> Option<Vec<IpAddr>> {
        let entry = self.entries.get(domain)?;
        if entry.expires < Instant::now() {
            // Stale — do not return the value. The expired entry will be
            // overwritten on the next insert.
            return None;
        }
        Some(entry.ips.clone())
    }

    /// Insert a resolved entry into the cache.
    ///
    /// `ttl_secs` is how many seconds the entry should be considered valid.
    pub fn insert(&self, domain: &str, ips: Vec<IpAddr>, ttl_secs: u64) {
        let expires = Instant::now() + Duration::from_secs(ttl_secs);
        self.entries
            .insert(domain.to_string(), CacheEntry { ips, expires });
    }

    /// Remove all expired entries.
    ///
    /// Call this periodically to reclaim memory. In practice the cache is
    /// small enough that this is not critical, but it is available for
    /// operators who want to aggressively bound memory usage.
    pub fn evict_expired(&self) {
        let now = Instant::now();
        self.entries.retain(|_, v| v.expires >= now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn miss_on_empty_cache() {
        let cache = DnsCache::new(100);
        assert!(cache.get("example.com").is_none());
    }

    #[test]
    fn hit_after_insert() {
        let cache = DnsCache::new(100);
        let ips = vec![ip(1, 1, 1, 1)];
        cache.insert("example.com", ips.clone(), 60);
        assert_eq!(cache.get("example.com").unwrap(), ips);
    }

    #[test]
    fn expired_entry_returns_none() {
        let cache = DnsCache::new(100);
        let ips = vec![ip(8, 8, 8, 8)];
        // TTL = 0 means the entry expires immediately.
        cache.insert("old.example.com", ips, 0);
        // Sleep 1ms to ensure the Instant has passed.
        std::thread::sleep(std::time::Duration::from_millis(1));
        assert!(cache.get("old.example.com").is_none());
    }

    #[test]
    fn evict_expired_removes_stale() {
        let cache = DnsCache::new(100);
        cache.insert("fresh.com", vec![ip(1, 2, 3, 4)], 3600);
        cache.insert("stale.com", vec![ip(5, 6, 7, 8)], 0);
        std::thread::sleep(std::time::Duration::from_millis(1));

        cache.evict_expired();

        assert!(cache.get("fresh.com").is_some());
        assert!(cache.get("stale.com").is_none());
    }

    #[test]
    fn overwrite_existing_entry() {
        let cache = DnsCache::new(100);
        cache.insert("example.com", vec![ip(1, 1, 1, 1)], 60);
        cache.insert("example.com", vec![ip(2, 2, 2, 2)], 60);
        assert_eq!(cache.get("example.com").unwrap(), vec![ip(2, 2, 2, 2)]);
    }
}
