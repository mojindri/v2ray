//! DNS resolution cache with per-entry TTL and LRU eviction.
//!
//! `DnsCache` stores resolved IP addresses keyed by domain name. Each entry
//! has an expiry timestamp. Stale entries are removed on lookup.
//!
//! Eviction policy: when the cache is at capacity, the **least recently used**
//! entry is evicted — matching xray's `app/dns/fakedns` which uses an LRU map
//! (`lru.New(poolSize)`) with the same eviction semantics.

use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use lru::LruCache;

/// A single cached DNS entry.
struct CacheEntry {
    /// The resolved IP addresses.
    ips: Vec<IpAddr>,
    /// When this entry expires.
    expires: Instant,
}

/// A thread-safe DNS cache with per-entry TTL and LRU eviction.
///
/// Internally uses a `Mutex<LruCache>` so that `get` can promote entries to
/// "most recently used" — something a shared reference cannot do.
pub struct DnsCache {
    inner: Mutex<LruCache<String, CacheEntry>>,
}

impl DnsCache {
    /// Create a new cache with the given maximum capacity.
    pub fn new(capacity: usize) -> Self {
        let cap = NonZeroUsize::new(capacity.max(1)).expect("capacity >= 1");
        Self {
            inner: Mutex::new(LruCache::new(cap)),
        }
    }

    /// Look up a domain name in the cache.
    ///
    /// Returns `Some(ips)` if the entry exists and has not expired.
    /// Expired entries are removed during lookup (lazy TTL eviction).
    pub fn get(&self, domain: &str) -> Option<Vec<IpAddr>> {
        let mut cache = self.inner.lock().unwrap();
        // `LruCache::get` promotes the entry to MRU. We clone inside the map
        // closure so the borrow on `cache` ends before we might need `pop`.
        let result = cache.get(domain).map(|e| {
            if e.expires >= Instant::now() {
                Some(e.ips.clone())
            } else {
                None // expired
            }
        });
        match result {
            Some(Some(ips)) => Some(ips),
            Some(None) => {
                // Entry was expired: remove it and return cache miss.
                cache.pop(domain);
                None
            }
            None => None,
        }
    }

    /// Insert a resolved entry into the cache.
    ///
    /// `ttl_secs` is how many seconds the entry should be considered valid.
    /// When the cache is at capacity, the least-recently-used entry is evicted
    /// automatically by the underlying `LruCache`.
    pub fn insert(&self, domain: &str, ips: Vec<IpAddr>, ttl_secs: u64) {
        let expires = Instant::now() + Duration::from_secs(ttl_secs);
        self.inner
            .lock()
            .unwrap()
            .put(domain.to_string(), CacheEntry { ips, expires });
    }

    /// Remove all expired entries.
    ///
    /// Not required for correctness (TTL is checked on every `get`), but can
    /// be called periodically to reclaim memory from entries that were inserted
    /// but never read after their TTL elapsed.
    pub fn evict_expired(&self) {
        let now = Instant::now();
        let mut cache = self.inner.lock().unwrap();
        let expired: Vec<String> = cache
            .iter()
            .filter(|(_, v)| v.expires < now)
            .map(|(k, _)| k.clone())
            .collect();
        for key in expired {
            cache.pop(key.as_str());
        }
    }

    /// Returns the number of entries currently stored (including not-yet-expired).
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().len()
    }

    /// Returns `true` if the cache has no entries.
    pub fn is_empty(&self) -> bool {
        self.inner.lock().unwrap().is_empty()
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
    fn capacity_is_enforced_lru() {
        let cache = DnsCache::new(2);
        cache.insert("a.com", vec![ip(1, 0, 0, 1)], 60);
        cache.insert("b.com", vec![ip(1, 0, 0, 2)], 60);
        // Access a.com to make it MRU; b.com becomes LRU.
        assert!(cache.get("a.com").is_some());
        // Insert c.com — should evict b.com (LRU), not a.com.
        cache.insert("c.com", vec![ip(1, 0, 0, 3)], 60);
        assert!(cache.len() <= 2);
        assert!(cache.get("c.com").is_some());
        assert!(cache.get("a.com").is_some());
        assert!(cache.get("b.com").is_none()); // evicted
    }
}
