#[cfg(target_os = "linux")]
use std::time::Duration;

use anyhow::Result;
#[cfg(target_os = "linux")]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(not(target_os = "linux"))]
use tokio::sync::watch;
#[cfg(target_os = "linux")]
use tokio::sync::{mpsc, watch};
#[cfg(target_os = "linux")]
use tracing::{debug, info, warn};

use super::device::{TunConfig, TunDevice};
#[cfg(target_os = "linux")]
use super::nat::{TunTx, UdpNatTable};
#[cfg(target_os = "linux")]
use super::packet::{parse_ip_packet, TransportProtocol};

use super::route::setup_runtime_routes;

/// How often to sweep idle NAT entries.
#[cfg(target_os = "linux")]
const EVICT_INTERVAL: Duration = Duration::from_secs(30);

/// Idle timeout for UDP NAT flows.
#[cfg(target_os = "linux")]
const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Depth of the internal TUN-write channel.
#[cfg(target_os = "linux")]
const WRITE_CHAN_CAP: usize = 1024;

/// The TUN packet processing runtime.
///
/// Owns the event loop that:
///   1. Reads raw IP packets from the TUN device.
///   2. Dispatches UDP flows via [`UdpNatTable`] (TCP is handled transparently
///      by iptables REDIRECT → the proxy's TCP listener).
///   3. Writes synthesized response packets back into the TUN device.
///
/// On Linux, `TunRuntime::run` also installs iptables/ip-rule entries through
/// the platform route backend before entering the loop and removes them on exit.
pub struct TunRuntime {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    config: TunConfig,
}

impl TunRuntime {
    /// Create a runtime from immutable TUN settings.
    pub fn new(config: TunConfig) -> Self {
        Self { config }
    }

    /// Run the packet loop until `shutdown` fires or the TUN device closes.
    ///
    /// On Linux, routing rules are installed before the loop and cleaned up
    /// unconditionally on exit (even if the loop returns an error).
    pub async fn run(self, device: TunDevice, shutdown: watch::Receiver<bool>) -> Result<()> {
        self.run_platform(device, shutdown).await
    }

    #[cfg(target_os = "linux")]
    async fn run_platform(self, device: TunDevice, shutdown: watch::Receiver<bool>) -> Result<()> {
        let routes = setup_runtime_routes(&self.config).await?;

        let result = self.packet_loop(device, shutdown).await;

        routes.cleanup().await;

        result
    }

    #[cfg(not(target_os = "linux"))]
    async fn run_platform(
        self,
        _device: TunDevice,
        _shutdown: watch::Receiver<bool>,
    ) -> Result<()> {
        setup_runtime_routes(&self.config).await?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    async fn packet_loop(
        &self,
        device: TunDevice,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<()> {
        let (mut reader, mut writer) = tokio::io::split(device);
        let (tun_tx, mut tun_rx) = mpsc::channel::<Vec<u8>>(WRITE_CHAN_CAP);
        let mut nat = UdpNatTable::with_defaults(self.config.bypass_mark, UDP_IDLE_TIMEOUT);
        let mut read_buf = vec![0u8; 65536];
        let mut evict_tick = tokio::time::interval(EVICT_INTERVAL);
        // Skip the immediate first tick so eviction doesn't run before any
        // flows are even established.
        evict_tick.tick().await;

        info!(name = %self.config.name, "TUN runtime started");

        loop {
            tokio::select! {
                // ── Read a packet from TUN ────────────────────────────────────
                result = reader.read(&mut read_buf) => {
                    match result {
                        Ok(0) => {
                            info!("TUN device EOF; stopping");
                            break;
                        }
                        Ok(n) => {
                            self.dispatch(&read_buf[..n], &mut nat, tun_tx.clone()).await;
                        }
                        Err(e) => {
                            warn!(%e, "TUN device read error; stopping");
                            break;
                        }
                    }
                }

                // ── Write synthesized response packets back to TUN ────────────
                Some(pkt) = tun_rx.recv() => {
                    if let Err(e) = writer.write_all(&pkt).await {
                        warn!(%e, "TUN device write error");
                    }
                }

                // ── Periodic idle NAT eviction ────────────────────────────────
                _ = evict_tick.tick() => {
                    let n = nat.evict_idle();
                    if n > 0 {
                        debug!(evicted = n, "removed idle UDP NAT flows");
                    }
                }

                // ── Graceful shutdown ─────────────────────────────────────────
                Ok(()) = shutdown.changed() => {
                    if *shutdown.borrow() {
                        info!("TUN runtime: shutdown signal received");
                        break;
                    }
                }
            }
        }

        info!(name = %self.config.name, "TUN runtime stopped");
        Ok(())
    }

    #[cfg(target_os = "linux")]
    async fn dispatch(&self, raw: &[u8], nat: &mut UdpNatTable, tun_tx: TunTx) {
        let Some(packet) = parse_ip_packet(raw) else {
            return;
        };

        if packet.protocol == TransportProtocol::Udp {
            // Port-53 DNS is redirected by iptables to the proxy's DNS
            // listener; the TUN device should not see it, but skip just
            // in case the kernel sends it before the iptables rule lands.
            if packet.dst_port == 53 {
                return;
            }
            if let Err(e) = nat.forward(&packet, raw, tun_tx).await {
                debug!(%e, src = %packet.src, dst = %packet.dst, "UDP NAT forward failed");
            }
        }
    }
}
