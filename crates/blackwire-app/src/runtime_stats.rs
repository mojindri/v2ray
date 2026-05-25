use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
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

pub fn increment(name: &str, delta: i64) {
    counter(name).fetch_add(delta, Ordering::Relaxed);
}

pub fn get(name: &str, reset: bool) -> Option<i64> {
    let counter = COUNTERS.get(name)?.clone();
    let value = if reset {
        counter.swap(0, Ordering::Relaxed)
    } else {
        counter.load(Ordering::Relaxed)
    };
    Some(value)
}

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

pub fn uptime_secs() -> u32 {
    STARTED_AT.elapsed().as_secs().min(u32::MAX as u64) as u32
}

pub fn record_connection_accepted(inbound: &str, protocol: &str) {
    increment("connections>>>total", 1);
    increment(&format!("inbound>>>{inbound}>>>connections>>>total"), 1);
    increment(&format!("inbound>>>{inbound}>>>protocol>>>{protocol}>>>connections>>>total"), 1);
}

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
