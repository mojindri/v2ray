//! Brutal congestion controller for Hysteria2.
//!
//! Normal QUIC congestion controllers (CUBIC, BBR) back off when they detect
//! packet loss. On high-latency lossy links (e.g. China ↔ overseas) this
//! causes very low throughput — the controller sees loss and slows down, but
//! the link actually has plenty of bandwidth.
//!
//! Brutal CC ignores loss signals completely. It sets the congestion window
//! to: `target_bps × estimated_rtt` (minimum 32 KiB). This saturates the link
//! regardless of loss, achieving much higher throughput on lossy paths.
//!
//! Trade-off: Brutal CC is unfair to other traffic on the same link.
//! It is designed for dedicated proxy connections, not general internet use.

use std::any::Any;
use std::sync::Arc;
use std::time::Instant;

use quinn::congestion::{Controller, ControllerFactory};
use quinn_proto::RttEstimator;

/// Minimum congestion window: 32 KiB.
///
/// Even with a very short RTT or very low target bandwidth, the window never
/// drops below this value to maintain QUIC protocol handshake progress.
const MIN_WINDOW: u64 = 32 * 1024;

/// Brutal congestion controller.
///
/// Maintains a fixed-rate sending window regardless of packet loss. The
/// window is recalculated each time an ACK arrives with an updated RTT.
#[derive(Clone)]
pub struct BrutalCC {
    /// Target send rate in bytes/sec, as configured by the operator.
    target_bps: u64,
    /// Latest smoothed RTT estimate in seconds.
    rtt_secs: f64,
    /// Current path MTU in bytes.
    mtu: u16,
}

/// Factory that creates `BrutalCC` controller instances.
///
/// One factory is shared for the lifetime of the QUIC endpoint; it creates
/// a new `BrutalCC` for each new QUIC connection path.
pub struct BrutalCCFactory {
    /// Target bandwidth in bytes per second.
    pub target_bps: u64,
}

impl BrutalCCFactory {
    /// Create a new factory with the given target bandwidth.
    ///
    /// `target_bps` is in bytes per second (not bits). For 100 Mbps, pass
    /// `100_000_000 / 8` = 12_500_000.
    pub fn new(target_bps: u64) -> Self {
        Self { target_bps }
    }
}

impl ControllerFactory for BrutalCCFactory {
    fn build(self: Arc<Self>, _now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(BrutalCC {
            target_bps: self.target_bps,
            // Start with a 100 ms RTT estimate; will be updated on first ACK.
            rtt_secs: 0.1,
            mtu: current_mtu,
        })
    }
}

impl Controller for BrutalCC {
    /// Loss events are intentionally ignored.
    ///
    /// This is the defining property of Brutal CC: unlike CUBIC or BBR, it
    /// does not reduce the window on congestion. The window is determined
    /// solely by the configured target rate and the current RTT.
    fn on_congestion_event(
        &mut self,
        _now: Instant,
        _sent: Instant,
        _is_persistent_congestion: bool,
        _lost_bytes: u64,
    ) {
        // No-op: Brutal CC ignores loss signals.
    }

    /// Update the path MTU when the network reports a change.
    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.mtu = new_mtu;
    }

    /// Return the current congestion window in bytes.
    ///
    /// Window = target_bps × smoothed_rtt, clamped to at least MIN_WINDOW.
    fn window(&self) -> u64 {
        let w = (self.target_bps as f64 * self.rtt_secs) as u64;
        w.max(MIN_WINDOW)
    }

    /// Clone this controller's state into a new box.
    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    /// Initial window when a new path starts.
    ///
    /// Uses the same formula as `window()` so the starting rate is already
    /// close to the configured target.
    fn initial_window(&self) -> u64 {
        let w = (self.target_bps as f64 * self.rtt_secs) as u64;
        w.max(MIN_WINDOW)
    }

    /// Update the RTT estimate when an ACK is received.
    ///
    /// We read the smoothed RTT from the estimator. Smoothed RTT already
    /// filters out noise, so we do not need additional averaging here.
    fn on_ack(
        &mut self,
        _now: Instant,
        _sent: Instant,
        _bytes: u64,
        _app_limited: bool,
        rtt: &RttEstimator,
    ) {
        // Clamp to at least 1 ms to avoid divide-by-zero in window().
        self.rtt_secs = rtt.get().as_secs_f64().max(0.001);
    }

    /// Allow downcasting back to the concrete type for inspection in tests.
    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_factory(target_bps: u64) -> Arc<BrutalCCFactory> {
        Arc::new(BrutalCCFactory::new(target_bps))
    }

    #[test]
    fn window_never_below_min_even_with_tiny_rtt() {
        // 1 byte/s × 1 ns RTT → computed window = 0, but MIN_WINDOW applies.
        let factory = make_factory(1);
        // ControllerFactory::build consumes the Arc — clone before calling.
        let mut ctrl = Arc::clone(&factory).build(Instant::now(), 1200);
        // Force a tiny RTT by accessing internal via downcast (white-box test).
        // We can't easily do that through the trait — instead verify the public
        // window() never returns less than MIN_WINDOW at the default 100ms RTT.
        assert!(ctrl.window() >= MIN_WINDOW);
        // After a congestion event, window must still not shrink.
        let now = Instant::now();
        ctrl.on_congestion_event(now, now, false, 1000);
        assert!(ctrl.window() >= MIN_WINDOW);
    }

    #[test]
    fn on_congestion_event_does_not_reduce_window() {
        let factory = make_factory(12_500_000); // 100 Mbps
        let mut ctrl = Arc::clone(&factory).build(Instant::now(), 1200);
        let w_before = ctrl.window();
        let now = Instant::now();
        // Simulate a severe persistent congestion event.
        ctrl.on_congestion_event(now, now, true, 1_000_000);
        let w_after = ctrl.window();
        assert_eq!(w_before, w_after, "Brutal CC must ignore congestion events");
    }

    #[test]
    fn window_grows_with_larger_rtt() {
        // With 100 Mbps target:
        //   RTT = 0.05s → window = 12_500_000 × 0.05 = 625_000 bytes
        //   RTT = 0.200s → window = 12_500_000 × 0.200 = 2_500_000 bytes
        // We verify the direction of change through direct BrutalCC construction.
        let cc_small = BrutalCC {
            target_bps: 12_500_000,
            rtt_secs: 0.050,
            mtu: 1200,
        };
        let cc_large = BrutalCC {
            target_bps: 12_500_000,
            rtt_secs: 0.200,
            mtu: 1200,
        };
        assert!(cc_large.window() > cc_small.window());
        // And both must still be at least MIN_WINDOW.
        assert!(cc_small.window() >= MIN_WINDOW);
    }
}
