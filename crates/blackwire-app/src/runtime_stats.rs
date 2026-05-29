//! In-process counters exposed through Xray `StatsService` gRPC.

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use dashmap::DashMap;
use once_cell::sync::Lazy;

static STARTED_AT: Lazy<Instant> = Lazy::new(Instant::now);
static COUNTERS: Lazy<DashMap<String, Arc<AtomicI64>>> = Lazy::new(DashMap::new);

fn counter(name: &str) -> Arc<AtomicI64> {
    COUNTERS
        .entry(name.to_string())
        .or_insert_with(|| Arc::new(AtomicI64::new(0)))
        .clone()
}

/// Add `delta` to a named counter (creating it if needed).
pub fn increment(name: &str, delta: i64) {
    counter(name).fetch_add(delta, Ordering::Relaxed);
}

/// Read a counter; optionally reset it after read.
pub fn get(name: &str, reset: bool) -> Option<i64> {
    let counter = COUNTERS.get(name)?.clone();
    let value = if reset {
        counter.swap(0, Ordering::Relaxed)
    } else {
        counter.load(Ordering::Relaxed)
    };
    Some(value)
}

/// Query counters whose names contain the pattern (wildcards stripped).
pub fn query(pattern: &str, reset: bool) -> Vec<(String, i64)> {
    let needle = pattern.trim_matches('*');
    COUNTERS
        .iter()
        .filter_map(|entry| {
            if !needle.is_empty() && !entry.key().contains(needle) {
                return None;
            }
            let value = if reset {
                entry.value().swap(0, Ordering::Relaxed)
            } else {
                entry.value().load(Ordering::Relaxed)
            };
            Some((entry.key().clone(), value))
        })
        .collect()
}

/// Process uptime in seconds (for SysStats).
pub fn uptime_secs() -> u32 {
    STARTED_AT.elapsed().as_secs().min(u32::MAX as u64) as u32
}

/// Resident set size (RSS) in bytes. Returns 0 if unavailable.
///
/// Reads `VmRSS` from `/proc/self/status` on Linux; uses `getrusage(RUSAGE_SELF)`
/// on other Unix systems (ru_maxrss is in bytes on Linux, kilobytes on macOS/BSD).
pub fn rss_bytes() -> u64 {
    #[cfg(target_os = "linux")]
    {
        if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if let Some(rest) = line.strip_prefix("VmRSS:") {
                    // Format: "VmRSS:\t 12345 kB"
                    if let Some(kb_str) = rest.split_whitespace().next() {
                        if let Ok(kb) = kb_str.parse::<u64>() {
                            return kb * 1024;
                        }
                    }
                }
            }
        }
        0
    }
    #[cfg(not(target_os = "linux"))]
    {
        0
    }
}

/// Number of live Tokio tasks (analogous to goroutine count). Returns 0 if
/// called outside a Tokio runtime context or if metrics are unavailable.
pub fn num_tasks() -> u64 {
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.metrics().num_alive_tasks() as u64
    } else {
        0
    }
}

/// Number of OS threads in this process. Returns 0 if unavailable.
pub fn num_threads() -> u64 {
    #[cfg(target_os = "linux")]
    {
        if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if let Some(rest) = line.strip_prefix("Threads:") {
                    if let Some(n_str) = rest.split_whitespace().next() {
                        if let Ok(n) = n_str.parse::<u64>() {
                            return n;
                        }
                    }
                }
            }
        }
        0
    }
    #[cfg(not(target_os = "linux"))]
    {
        0
    }
}

/// Increment connection counters for an accepted inbound session.
pub fn record_connection_accepted(inbound: &str, protocol: &str) {
    increment("connections>>>total", 1);
    increment(&format!("inbound>>>{inbound}>>>connections>>>total"), 1);
    increment(
        &format!("inbound>>>{inbound}>>>protocol>>>{protocol}>>>connections>>>total"),
        1,
    );
}

/// Record relay byte counts on inbound and optional user counters.
pub fn record_relay_traffic(inbound: &str, user: Option<&str>, rx_bytes: u64, tx_bytes: u64) {
    increment(
        &format!("inbound>>>{inbound}>>>traffic>>>uplink"),
        rx_bytes.min(i64::MAX as u64) as i64,
    );
    increment(
        &format!("inbound>>>{inbound}>>>traffic>>>downlink"),
        tx_bytes.min(i64::MAX as u64) as i64,
    );
    if let Some(user) = user {
        increment(
            &format!("user>>>{user}>>>traffic>>>uplink"),
            rx_bytes.min(i64::MAX as u64) as i64,
        );
        increment(
            &format!("user>>>{user}>>>traffic>>>downlink"),
            tx_bytes.min(i64::MAX as u64) as i64,
        );
    }
}

/// Record per-user uplink/downlink byte counters.
pub fn record_user_traffic(user: &str, rx_bytes: u64, tx_bytes: u64) {
    increment(
        &format!("user>>>{user}>>>traffic>>>uplink"),
        rx_bytes.min(i64::MAX as u64) as i64,
    );
    increment(
        &format!("user>>>{user}>>>traffic>>>downlink"),
        tx_bytes.min(i64::MAX as u64) as i64,
    );
}
