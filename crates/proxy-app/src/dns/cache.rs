//! DNS resolution cache with per-entry TTL.
//!
//! `DnsCache` stores resolved IP addresses keyed by domain name. Each entry
//! has an expiry timestamp. Stale entries are removed on lookup.

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

/// A thread-safe DNS cache with per-entry TTL and a hard entry cap.
pub struct DnsCache {
    /// The underlying storage. Key = domain name.
    entries: DashMap<String, CacheEntry>,
    /// Maximum number of live entries before eviction runs on insert.
    capacity: usize,
}

impl DnsCache {
    /// Create a new cache with the given maximum capacity.
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: DashMap::new(),
            capacity: capacity.max(1),
        }
    }

    /// Look up a domain name in the cache.
    ///
    /// Returns `Some(ips)` if the entry exists and has not expired.
    /// Expired entries are removed during lookup.
    pub fn get(&self, domain: &str) -> Option<Vec<IpAddr>> {
        let entry = self.entries.get(domain)?;
        if entry.expires < Instant::now() {
            drop(entry);
            self.entries.remove(domain);
            return None;
        }
        Some(entry.ips.clone())
    }

    /// Insert a resolved entry into the cache.
    ///
    /// `ttl_secs` is how many seconds the entry should be considered valid.
    pub fn insert(&self, domain: &str, ips: Vec<IpAddr>, ttl_secs: u64) {
        if !self.entries.contains_key(domain) {
            self.evict_expired();
            while self.entries.len() >= self.capacity {
                if !self.evict_one_arbitrary() {
                    break;
                }
            }
        }

        let expires = Instant::now() + Duration::from_secs(ttl_secs);
        self.entries
            .insert(domain.to_string(), CacheEntry { ips, expires });
    }

    /// Remove all expired entries.
    pub fn evict_expired(&self) {
        let now = Instant::now();
        self.entries.retain(|_, v| v.expires >= now);
    }

    /// Returns the number of entries currently stored (including expired).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the cache has no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn evict_one_arbitrary(&self) -> bool {
        let key = self.entries.iter().next().map(|e| e.key().clone());
        if let Some(key) = key {
            self.entries.remove(&key);
            true
        } else {
            false
        }
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
    fn expired_entry_returns_none_and_is_removed() {
        let cache = DnsCache::new(100);
        let ips = vec![ip(8, 8, 8, 8)];
        cache.insert("old.example.com", ips, 0);
        std::thread::sleep(std::time::Duration::from_millis(1));
        assert!(cache.get("old.example.com").is_none());
        assert_eq!(cache.len(), 0);
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

    #[test]
    fn capacity_is_enforced() {
        let cache = DnsCache::new(2);
        cache.insert("a.com", vec![ip(1, 0, 0, 1)], 60);
        cache.insert("b.com", vec![ip(1, 0, 0, 2)], 60);
        cache.insert("c.com", vec![ip(1, 0, 0, 3)], 60);
        assert!(cache.len() <= 2);
        assert!(cache.get("c.com").is_some());
    }
}
