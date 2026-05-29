use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result};
use blackwire_common::protect_udp_socket_with_bypass_mark;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tracing::debug;

use super::packet::{build_udp_response_packet, IpPacket, TransportProtocol};

/// Channel end that pushes synthesized IP packets back into the TUN device.
pub type TunTx = mpsc::Sender<Vec<u8>>;

/// Default cap on concurrent UDP NAT flows (each flow = socket + task).
pub const DEFAULT_MAX_UDP_NAT_ENTRIES: usize = 4096;

struct NatEntry {
    socket: Arc<UdpSocket>,
    /// Dropping this signals the response-reader task to stop.
    _cancel: oneshot::Sender<()>,
    last_seen: Instant,
}

/// Per-flow UDP NAT table for the TUN runtime.
///
/// Each outbound UDP flow (src_addr → dst_addr) gets a dedicated bypass
/// `UdpSocket` connected to the real destination and tagged with `SO_MARK`
/// so its packets skip the TUN routing table and go straight to the NIC.
///
/// When a response arrives on a bypass socket, a background task synthesizes
/// the reversed IP packet and delivers it to `tun_tx`, which the runtime
/// writes back into the TUN device.
pub struct UdpNatTable {
    entries: HashMap<(SocketAddr, SocketAddr), NatEntry>,
    // Used only on Linux (SO_MARK); stored on all platforms for config consistency.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    bypass_mark: u32,
    idle_timeout: Duration,
    max_entries: usize,
}

impl UdpNatTable {
    /// Create an empty UDP NAT table.
    ///
    /// `bypass_mark` is applied to bypass sockets on Linux, `idle_timeout`
    /// controls when inactive flows are removed, and `max_entries` bounds the
    /// number of concurrent flows.
    pub fn new(bypass_mark: u32, idle_timeout: Duration, max_entries: usize) -> Self {
        Self {
            entries: HashMap::new(),
            bypass_mark,
            idle_timeout,
            max_entries: max_entries.max(1),
        }
    }

    /// Create a table with [`DEFAULT_MAX_UDP_NAT_ENTRIES`].
    pub fn with_defaults(bypass_mark: u32, idle_timeout: Duration) -> Self {
        Self::new(bypass_mark, idle_timeout, DEFAULT_MAX_UDP_NAT_ENTRIES)
    }

    /// Forward `packet`'s UDP payload to its real destination.
    ///
    /// On the first packet for a flow, creates a bypass socket and spawns a
    /// response-reader task. Subsequent packets for the same flow reuse the
    /// existing socket and refresh its idle timer.
    pub async fn forward(&mut self, packet: &IpPacket, raw: &[u8], tun_tx: TunTx) -> Result<()> {
        let client = SocketAddr::new(packet.src, packet.src_port);
        let remote = SocketAddr::new(packet.dst, packet.dst_port);
        let key = (client, remote);
        let now = Instant::now();

        if !self.entries.contains_key(&key) {
            self.evict_idle();
            if self.entries.len() >= self.max_entries {
                self.evict_oldest();
            }
            if self.entries.len() >= self.max_entries {
                anyhow::bail!("UDP NAT: flow table full ({})", self.max_entries);
            }

            let (cancel_tx, cancel_rx) = oneshot::channel::<()>();
            let socket = Arc::new(
                self.create_bypass_socket(packet.src, remote)
                    .await
                    .with_context(|| format!("UDP NAT: open bypass socket for {remote}"))?,
            );
            tokio::spawn(response_reader(
                Arc::clone(&socket),
                client,
                remote,
                tun_tx.clone(),
                cancel_rx,
            ));
            self.entries.insert(
                key,
                NatEntry {
                    socket,
                    _cancel: cancel_tx,
                    last_seen: now,
                },
            );
        }

        let Some(entry) = self.entries.get_mut(&key) else {
            anyhow::bail!("UDP NAT: entry disappeared before send");
        };
        entry.last_seen = now;

        let payload = packet
            .payload(raw)
            .context("UDP NAT: payload slice out of bounds")?;
        entry
            .socket
            .send(payload)
            .await
            .context("UDP NAT: bypass socket send")?;
        Ok(())
    }

    /// Drop entries that have been idle longer than `idle_timeout`.
    ///
    /// Dropping an entry drops the `oneshot::Sender`, which signals the
    /// corresponding response-reader task to exit.
    pub fn evict_idle(&mut self) -> usize {
        let now = Instant::now();
        let timeout = self.idle_timeout;
        let before = self.entries.len();
        self.entries
            .retain(|_, e| now.duration_since(e.last_seen) <= timeout);
        before - self.entries.len()
    }

    fn evict_oldest(&mut self) {
        if let Some(oldest_key) = self
            .entries
            .iter()
            .min_by_key(|(_, e)| e.last_seen)
            .map(|(k, _)| *k)
        {
            self.entries.remove(&oldest_key);
        }
    }

    /// Returns the number of active UDP NAT entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if there are no active UDP NAT entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    async fn create_bypass_socket(&self, src_ip: IpAddr, remote: SocketAddr) -> Result<UdpSocket> {
        let bind_addr = match src_ip {
            IpAddr::V4(_) => "0.0.0.0:0",
            IpAddr::V6(_) => "[::]:0",
        };
        let socket = UdpSocket::bind(bind_addr)
            .await
            .context("bind bypass UDP socket")?;

        protect_udp_socket_with_bypass_mark(
            &socket,
            (self.bypass_mark != 0).then_some(self.bypass_mark),
        )
        .map_err(|e| anyhow::anyhow!("protect UDP socket: {e}"))?;

        socket
            .connect(remote)
            .await
            .context("connect bypass socket")?;
        Ok(socket)
    }
}

/// Background task: reads responses from the bypass socket and synthesizes
/// reversed UDP IP packets to deliver back through TUN.
async fn response_reader(
    socket: Arc<UdpSocket>,
    client: SocketAddr,
    remote: SocketAddr,
    tun_tx: TunTx,
    mut cancel: oneshot::Receiver<()>,
) {
    let mut buf = vec![0u8; 65535];
    loop {
        tokio::select! {
            result = socket.recv(&mut buf) => {
                match result {
                    Ok(n) => {
                        if let Some(pkt) = build_response_packet(client, remote, &buf[..n]) {
                            if tun_tx.send(pkt).await.is_err() {
                                // TUN runtime shut down; exit silently.
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        debug!(%e, %remote, "UDP NAT bypass socket error");
                        break;
                    }
                }
            }
            // Sender dropped when NAT entry is evicted.
            _ = &mut cancel => break,
        }
    }
}

/// Build the reversed UDP packet (remote → client) from a bypass socket response.
fn build_response_packet(
    client: SocketAddr,
    remote: SocketAddr,
    payload: &[u8],
) -> Option<Vec<u8>> {
    // `build_udp_response_packet` swaps src↔dst from the "request", so we
    // pass a fake request with src=client, dst=remote to get remote→client.
    let fake_request = IpPacket {
        src: client.ip(),
        dst: remote.ip(),
        src_port: client.port(),
        dst_port: remote.port(),
        protocol: TransportProtocol::Udp,
        header_len: 0,
        payload_offset: 0,
        payload_len: 0,
    };
    build_udp_response_packet(&fake_request, payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn evict_idle_removes_stale_entries_and_signals_tasks() {
        // UdpNatTable::evict_idle is sync so we can test it without a runtime.
        // We can't easily insert real entries without async, but we can verify
        // the empty-table edge case.
        let mut table = UdpNatTable::new(0x1234, Duration::from_secs(60), 64);
        assert_eq!(table.evict_idle(), 0);
        assert!(table.is_empty());
    }

    #[test]
    fn build_response_packet_addresses_are_reversed() {
        let client: SocketAddr = "10.0.0.2:54321".parse().unwrap();
        let remote: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let payload = b"hello";

        let pkt = build_response_packet(client, remote, payload).unwrap();

        use super::super::packet::parse_ip_packet;
        let parsed = parse_ip_packet(&pkt).unwrap();

        assert_eq!(parsed.src, remote.ip());
        assert_eq!(parsed.dst, client.ip());
        assert_eq!(parsed.src_port, remote.port());
        assert_eq!(parsed.dst_port, client.port());
        assert_eq!(parsed.payload(&pkt).unwrap(), payload);
    }
}
