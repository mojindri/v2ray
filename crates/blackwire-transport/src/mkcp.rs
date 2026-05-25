/// mKCP packet header disguises and helpers.
pub mod header;
/// Core KCP state machine used by mKCP.
pub mod kcp;
/// KCP wire-segment encode/decode primitives.
pub mod segment;
/// Async stream wrapper exposed to callers.
pub mod stream;

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use bytes::Bytes;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use self::header::HeaderType;
use self::kcp::Kcp;
use self::segment::Segment;
use self::stream::MkcpStream;

const SERVER_SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
/// Maximum concurrent mKCP sessions per server socket (matches Xray mKCP defaults).
const MAX_SERVER_SESSIONS: usize = 1024;

#[derive(Debug, Clone)]
/// Client-side settings for one mKCP connection.
pub struct MkcpClientConfig {
    /// UDP socket address of the remote mKCP server.
    pub server: SocketAddr,
    /// KCP conversation ID. Both peers must use the same value.
    pub conv: u32,
    /// Fake header style added to each UDP packet.
    pub header: HeaderType,
    /// How often (in milliseconds) the driver runs KCP update/flush.
    pub interval_ms: u64,
    /// Receive window size in KCP segments.
    pub rcv_wnd: u16,
    /// Send window size in KCP segments.
    pub snd_wnd: u16,
    /// If true, use low-latency KCP mode.
    pub nodelay: bool,
}

impl Default for MkcpClientConfig {
    fn default() -> Self {
        let server = match "0.0.0.0:0".parse() {
            Ok(v) => v,
            Err(_) => panic!("valid default mKCP server socket"),
        };
        Self {
            server,
            conv: 0,
            header: HeaderType::None,
            interval_ms: 50,
            rcv_wnd: 128,
            snd_wnd: 128,
            nodelay: true,
        }
    }
}

#[derive(Debug, Clone)]
/// Server-side settings for accepting mKCP sessions.
pub struct MkcpServerConfig {
    /// Local UDP socket address to bind and listen on.
    pub listen: SocketAddr,
    /// Fake header style expected on inbound packets.
    pub header: HeaderType,
    /// How often (in milliseconds) each session driver ticks.
    pub interval_ms: u64,
    /// Receive window size in KCP segments.
    pub rcv_wnd: u16,
    /// Send window size in KCP segments.
    pub snd_wnd: u16,
    /// If true, use low-latency KCP mode.
    pub nodelay: bool,
}

/// Open one outbound mKCP stream to the configured server.
pub async fn mkcp_connect(cfg: &MkcpClientConfig) -> Result<MkcpStream> {
    let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
    socket.connect(cfg.server).await?;

    let mut kcp = Kcp::new(cfg.conv);
    kcp.set_nodelay(cfg.nodelay);
    kcp.set_wndsize(cfg.snd_wnd, cfg.rcv_wnd);

    let (tx_to_driver, rx_from_user) = mpsc::channel::<Bytes>(256);
    let (tx_to_user, rx_from_driver) = mpsc::channel::<Bytes>(256);

    tokio::spawn(run_client_driver(
        kcp,
        socket,
        cfg.header,
        rx_from_user,
        tx_to_user,
        cfg.interval_ms,
        cfg.rcv_wnd as usize,
    ));

    Ok(MkcpStream::new(tx_to_driver, rx_from_driver))
}

/// Accept exactly one inbound mKCP stream, then return.
///
/// This is a small convenience wrapper around `mkcp_accept_sessions`.
pub async fn mkcp_accept_once(cfg: &MkcpServerConfig) -> Result<(MkcpStream, SocketAddr)> {
    let mut sessions = mkcp_accept_sessions(cfg).await?;
    sessions
        .recv()
        .await
        .ok_or_else(|| anyhow::anyhow!("mKCP listener stopped before accepting a session"))
}

/// Start a multi-peer mKCP listener and return accepted logical streams.
///
/// One UDP socket is shared by all peers. Each remote socket address gets its
/// own KCP state machine, and the listener removes the session when its stream
/// driver exits or idles out.
pub async fn mkcp_accept_sessions(
    cfg: &MkcpServerConfig,
) -> Result<mpsc::Receiver<(MkcpStream, SocketAddr)>> {
    let socket = Arc::new(UdpSocket::bind(cfg.listen).await?);
    let (session_tx, session_rx) = mpsc::channel::<(MkcpStream, SocketAddr)>(128);
    let cfg = cfg.clone();

    tokio::spawn(async move {
        run_server_listener(socket, cfg, session_tx).await;
    });

    Ok(session_rx)
}

async fn run_server_listener(
    socket: Arc<UdpSocket>,
    cfg: MkcpServerConfig,
    session_tx: mpsc::Sender<(MkcpStream, SocketAddr)>,
) {
    let mut udp_buf = vec![0u8; 65535];
    // Value is (conv, sender) so we can detect reconnects from the same SocketAddr
    // with a different conversation ID (stale-session eviction).
    let mut sessions = HashMap::<SocketAddr, (u32, mpsc::Sender<Vec<u8>>)>::new();
    let (cleanup_tx, mut cleanup_rx) = mpsc::unbounded_channel::<SocketAddr>();

    loop {
        tokio::select! {
            Some(peer) = cleanup_rx.recv() => {
                sessions.remove(&peer);
            }
            received = socket.recv_from(&mut udp_buf) => {
                let Ok((n, peer)) = received else {
                    return;
                };
                let packet = udp_buf[..n].to_vec();
                let Some(payload) = cfg.header.strip(&packet) else {
                    continue;
                };

                if let Some((stored_conv, tx_udp)) = sessions.get(&peer) {
                    // Peek the conv from the first 4 bytes (KCP wire: u32 LE).
                    let incoming_conv = peek_conv(payload);
                    if incoming_conv == Some(*stored_conv) {
                        let _ = tx_udp.try_send(payload.to_vec()); // drop if driver is busy
                        continue;
                    }
                    // Conv mismatch: peer reconnected with a new session. Evict
                    // the stale entry and fall through to create a fresh session.
                    sessions.remove(&peer);
                }

                if sessions.len() >= MAX_SERVER_SESSIONS {
                    continue; // drop packet — server is at capacity
                }
                if start_server_session(
                    Arc::clone(&socket),
                    peer,
                    payload,
                    &cfg,
                    &session_tx,
                    &cleanup_tx,
                    &mut sessions,
                )
                .await
                .is_err()
                {
                    return;
                }
            }
        }
    }
}

async fn start_server_session(
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
    payload: &[u8],
    cfg: &MkcpServerConfig,
    session_tx: &mpsc::Sender<(MkcpStream, SocketAddr)>,
    cleanup_tx: &mpsc::UnboundedSender<SocketAddr>,
    sessions: &mut HashMap<SocketAddr, (u32, mpsc::Sender<Vec<u8>>)>,
) -> Result<()> {
    let mut cursor = payload;
    let Some(first) = Segment::decode(&mut cursor) else {
        return Ok(());
    };

    let mut kcp = Kcp::new(first.conv);
    kcp.set_nodelay(cfg.nodelay);
    kcp.set_wndsize(cfg.snd_wnd, cfg.rcv_wnd);
    let _ = kcp.input(payload);

    let (tx_to_driver, rx_from_user) = mpsc::channel::<Bytes>(256);
    let (tx_to_user, rx_from_driver) = mpsc::channel::<Bytes>(256);
    // Bounded UDP→driver channel: excess packets are dropped (UDP is lossy by nature).
    // 1024 matches xray's udp.HubCapacity(1024) default.
    let (tx_udp, rx_udp) = mpsc::channel::<Vec<u8>>(1024);

    sessions.insert(peer, (first.conv, tx_udp));

    tokio::spawn(cleanup_on_exit(
        peer,
        cleanup_tx.clone(),
        run_server_driver(
            kcp,
            socket,
            peer,
            cfg.header,
            rx_from_user,
            rx_udp,
            tx_to_user,
            cfg.interval_ms,
            cfg.rcv_wnd as usize,
        ),
    ));

    if session_tx
        .send((MkcpStream::new(tx_to_driver, rx_from_driver), peer))
        .await
        .is_err()
    {
        sessions.remove(&peer);
        return Err(anyhow::anyhow!("mKCP session receiver closed"));
    }

    Ok(())
}

async fn cleanup_on_exit(
    peer: SocketAddr,
    cleanup_tx: mpsc::UnboundedSender<SocketAddr>,
    driver: impl Future<Output = ()>,
) {
    driver.await;
    let _ = cleanup_tx.send(peer);
}

#[allow(clippy::too_many_arguments)]
async fn run_server_driver(
    mut kcp: Kcp,
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
    header: HeaderType,
    mut rx_from_user: mpsc::Receiver<Bytes>,
    mut rx_from_udp: mpsc::Receiver<Vec<u8>>,
    tx_to_user: mpsc::Sender<Bytes>,
    interval_ms: u64,
    pending_cap: usize,
) {
    let mut ticker = tokio::time::interval(Duration::from_millis(interval_ms));
    let idle_timer = tokio::time::sleep(SERVER_SESSION_IDLE_TIMEOUT);
    tokio::pin!(idle_timer);
    let mut pending: VecDeque<Bytes> = VecDeque::new();

    loop {
        tokio::select! {
            // Send buffered KCP output to the user as soon as channel has room.
            // Using reserve() avoids blocking other arms when the channel is full.
            Ok(permit) = tx_to_user.reserve(), if !pending.is_empty() => {
                if let Some(item) = pending.pop_front() {
                    permit.send(item);
                }
            }
            _ = ticker.tick() => {
                kcp.update(now_ms());
                let mut out = Vec::new();
                kcp.flush(&mut out);
                if kcp.is_dead() {
                    return;
                }
                for seg in out {
                    let _ = socket.send_to(&header.encode(&seg), peer).await;
                }
                drain_kcp_recv_into(&mut kcp, &mut pending, pending_cap);
            }
            Some(data) = rx_from_user.recv() => {
                idle_timer.as_mut().reset(tokio::time::Instant::now() + SERVER_SESSION_IDLE_TIMEOUT);
                let _ = kcp.send(&data);
            }
            Some(packet) = rx_from_udp.recv() => {
                idle_timer.as_mut().reset(tokio::time::Instant::now() + SERVER_SESSION_IDLE_TIMEOUT);
                let _ = kcp.input(&packet);
                drain_kcp_recv_into(&mut kcp, &mut pending, pending_cap);
            }
            _ = &mut idle_timer => {
                return;
            }
            else => {
                return;
            }
        }
    }
}

async fn run_client_driver(
    mut kcp: Kcp,
    socket: Arc<UdpSocket>,
    header: HeaderType,
    mut rx_from_user: mpsc::Receiver<Bytes>,
    tx_to_user: mpsc::Sender<Bytes>,
    interval_ms: u64,
    pending_cap: usize,
) {
    let mut ticker = tokio::time::interval(Duration::from_millis(interval_ms));
    let mut udp_buf = vec![0u8; 65535];
    let mut pending: VecDeque<Bytes> = VecDeque::new();

    loop {
        tokio::select! {
            Ok(permit) = tx_to_user.reserve(), if !pending.is_empty() => {
                if let Some(item) = pending.pop_front() {
                    permit.send(item);
                }
            }
            _ = ticker.tick() => {
                kcp.update(now_ms());
                let mut out = Vec::new();
                kcp.flush(&mut out);
                if kcp.is_dead() {
                    return;
                }
                for seg in out {
                    let _ = socket.send(&header.encode(&seg)).await;
                }
                drain_kcp_recv_into(&mut kcp, &mut pending, pending_cap);
            }
            Some(data) = rx_from_user.recv() => {
                let _ = kcp.send(&data);
            }
            Ok(n) = socket.recv(&mut udp_buf) => {
                if let Some(payload) = header.strip(&udp_buf[..n]) {
                    let _ = kcp.input(payload);
                    drain_kcp_recv_into(&mut kcp, &mut pending, pending_cap);
                }
            }
            else => {
                return;
            }
        }
    }
}

/// Drain fully-reassembled KCP messages into `pending`, up to `max` messages.
///
/// Stopping at `max` means the KCP receive window stays full (segments are
/// not ACKed beyond what the application has consumed), which applies
/// backpressure on the sender — matching xray's window-bounded behaviour.
fn drain_kcp_recv_into(kcp: &mut Kcp, pending: &mut VecDeque<Bytes>, max: usize) {
    let mut recv_buf = vec![0u8; 65535];
    loop {
        if pending.len() >= max {
            break; // window full — stop ACKing so sender slows down
        }
        let n = kcp.recv(&mut recv_buf);
        if n <= 0 {
            break;
        }
        pending.push_back(Bytes::copy_from_slice(&recv_buf[..n as usize]));
    }
}

/// Peek the KCP conversation ID from the first 4 bytes of a segment payload.
fn peek_conv(payload: &[u8]) -> Option<u32> {
    if payload.len() < 4 {
        return None;
    }
    Some(u32::from_le_bytes([
        payload[0], payload[1], payload[2], payload[3],
    ]))
}

fn now_ms() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    (SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        & 0xFFFFFFFF) as u32
}
