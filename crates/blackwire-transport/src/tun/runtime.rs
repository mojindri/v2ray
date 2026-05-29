#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use std::time::Duration;

use anyhow::Result;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
use tokio::sync::watch;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use tokio::sync::{mpsc, watch};
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use tracing::{debug, info, warn};

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
use super::backend::ensure_tun_runtime_supported;
#[cfg(target_os = "macos")]
use super::device::tun_device_name;
use super::device::{TunConfig, TunDevice};
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use super::nat::{TunTx, UdpNatTable};
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use super::packet::{parse_ip_packet, TransportProtocol};
#[cfg(target_os = "windows")]
use super::tcp::TcpBridgeTable;

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use super::route::setup_runtime_routes;

/// How often to sweep idle NAT entries.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
const EVICT_INTERVAL: Duration = Duration::from_secs(30);

/// Idle timeout for UDP NAT flows.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Idle timeout for Windows packet-level TCP bridge flows.
#[cfg(target_os = "windows")]
const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

/// Depth of the internal TUN-write channel.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
const WRITE_CHAN_CAP: usize = 1024;

/// The TUN packet processing runtime.
///
/// Owns the event loop that:
///   1. Reads raw IP packets from the TUN device.
///   2. Dispatches UDP flows via [`UdpNatTable`]. Linux/macOS redirect TCP in
///      the OS; Windows bridges TCP packets to the local SOCKS listener.
///   3. Writes synthesized response packets back into the TUN device.
///
/// On Linux/macOS, `TunRuntime::run` also installs platform route/redirection
/// state before entering the loop and removes it on exit.
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
    /// Platform routing rules are installed before the loop and cleaned up
    /// unconditionally on exit (even if the loop returns an error).
    pub async fn run(self, device: TunDevice, shutdown: watch::Receiver<bool>) -> Result<()> {
        self.run_platform(device, shutdown).await
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    async fn run_platform(
        mut self,
        device: TunDevice,
        shutdown: watch::Receiver<bool>,
    ) -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            self.config.name = tun_device_name(&device)?;
        }

        let routes = setup_runtime_routes(&self.config).await?;

        let result = self.packet_loop(device, shutdown).await;

        routes.cleanup().await;

        result
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    async fn run_platform(
        self,
        _device: TunDevice,
        _shutdown: watch::Receiver<bool>,
    ) -> Result<()> {
        let _ = self;
        ensure_tun_runtime_supported()
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    async fn packet_loop(
        &self,
        device: TunDevice,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<()> {
        let (mut reader, mut writer) = tokio::io::split(device);
        let (tun_tx, mut tun_rx) = mpsc::channel::<Vec<u8>>(WRITE_CHAN_CAP);
        let mut nat = UdpNatTable::with_defaults(self.config.bypass_mark, UDP_IDLE_TIMEOUT);
        #[cfg(target_os = "windows")]
        let mut tcp = TcpBridgeTable::with_defaults(self.config.redirect_port, TCP_IDLE_TIMEOUT);
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
                            self.dispatch(
                                &read_buf[..n],
                                &mut nat,
                                #[cfg(target_os = "windows")]
                                &mut tcp,
                                tun_tx.clone(),
                            ).await;
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
                    #[cfg(target_os = "windows")]
                    {
                        let n = tcp.evict_idle();
                        if n > 0 {
                            debug!(evicted = n, "removed idle TCP bridge flows");
                        }
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

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    async fn dispatch(
        &self,
        raw: &[u8],
        nat: &mut UdpNatTable,
        #[cfg(target_os = "windows")] tcp: &mut TcpBridgeTable,
        tun_tx: TunTx,
    ) {
        let Some(packet) = parse_ip_packet(raw) else {
            return;
        };

        match packet.protocol {
            TransportProtocol::Udp => {
                // Port-53 DNS is redirected by iptables/PF to the proxy's DNS
                // listener; the TUN device should not see it, but skip just
                // in case the kernel sends it before the redirect rule lands.
                if packet.dst_port == 53 {
                    return;
                }
                if let Err(e) = nat.forward(&packet, raw, tun_tx).await {
                    debug!(%e, src = %packet.src, dst = %packet.dst, "UDP NAT forward failed");
                }
            }
            TransportProtocol::Tcp =>
            {
                #[cfg(target_os = "windows")]
                if let Err(e) = tcp.forward(&packet, raw, tun_tx).await {
                    debug!(%e, src = %packet.src, dst = %packet.dst, "TCP bridge forward failed");
                }
            }
            TransportProtocol::Other(_) => {}
        }
    }
}
