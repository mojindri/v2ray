//! SS-2022 salt-based anti-replay filter.
//!
//! Each SS-2022 session starts with a 32-byte random salt. The anti-replay
//! filter stores recently seen salts and rejects any connection that reuses a
//! salt (a replay attack).
//!
//! # Implementation
//!
//! - Uses a `DashMap<[u8;32], Instant>` for O(1) concurrent insert/lookup.
//! - A background task reaps entries older than `TTL_SECS`.
//! - `check_and_insert(salt)` returns `true` if the salt was NOT seen before
//!   (i.e. the connection is NOT a replay), `false` if it was already seen.
//!
//! # TTL
//!
//! Salts are kept for 60 seconds. V2ray-compatible servers use the same window.
//! Replays older than this TTL are not detected, but such attacks are impractical
//! because they require the attacker to replay within the one-minute window.

use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;

/// How long we keep salts in the replay filter.
const TTL_SECS: u64 = 60;

/// Reaping interval for the background cleanup task.
const REAP_INTERVAL_SECS: u64 = 30;

/// Salt-based anti-replay filter for SS-2022.
///
/// Thread-safe and clone-safe (backed by an `Arc<DashMap>`).
#[derive(Clone)]
pub struct SaltReplay {
    inner: Arc<DashMap<[u8; 32], Instant>>,
}

impl SaltReplay {
    /// Create a new empty anti-replay filter and start the background reaper.
    pub fn new() -> Self {
        let map: Arc<DashMap<[u8; 32], Instant>> = Arc::new(DashMap::new());
        let map_clone = Arc::clone(&map);

        // Spawn a background task to clean up expired entries.
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(REAP_INTERVAL_SECS));
            loop {
                interval.tick().await;
                let ttl = Duration::from_secs(TTL_SECS);
                let now = Instant::now();
                map_clone.retain(|_, ts| now.duration_since(*ts) < ttl);
            }
        });

        Self { inner: map }
    }

    /// Check whether `salt` is new and, if so, record it.
    ///
    /// Returns `true`  — salt not seen before → connection is allowed.
    /// Returns `false` — salt already seen   → connection is a replay (reject).
    pub fn check_and_insert(&self, salt: &[u8; 32]) -> bool {
        use dashmap::mapref::entry::Entry;
        match self.inner.entry(*salt) {
            Entry::Occupied(_) => false,
            Entry::Vacant(v) => {
                v.insert(Instant::now());
                true
            }
        }
    }

    /// Number of salts currently tracked (for testing).
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Whether the replay filter currently tracks no salts (for testing).
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl Default for SaltReplay {
    fn default() -> Self {
        Self::new()
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn first_salt_accepted() {
        let replay = SaltReplay::new();
        let salt = [0x11u8; 32];
        assert!(replay.check_and_insert(&salt));
    }

    #[tokio::test]
    async fn duplicate_salt_rejected() {
        let replay = SaltReplay::new();
        let salt = [0x22u8; 32];
        assert!(replay.check_and_insert(&salt));
        // Second attempt with the same salt must be rejected.
        assert!(!replay.check_and_insert(&salt));
    }

    #[tokio::test]
    async fn different_salts_both_accepted() {
        let replay = SaltReplay::new();
        let salt1 = [0x33u8; 32];
        let salt2 = [0x44u8; 32];
        assert!(replay.check_and_insert(&salt1));
        assert!(replay.check_and_insert(&salt2));
        assert_eq!(replay.len(), 2);
    }

    #[tokio::test]
    async fn replay_is_counted() {
        let replay = SaltReplay::new();
        let salt = [0x55u8; 32];
        replay.check_and_insert(&salt);
        // Third attempt — still rejected.
        assert!(!replay.check_and_insert(&salt));
    }
}
