pub mod header;
pub mod kcp;
pub mod segment;
pub mod stream;

use std::collections::HashMap;
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

#[derive(Debug, Clone)]
pub struct MkcpClientConfig {
    pub server: SocketAddr,
    pub conv: u32,
    pub header: HeaderType,
    pub interval_ms: u64,
    pub rcv_wnd: u16,
    pub snd_wnd: u16,
    pub nodelay: bool,
}

impl Default for MkcpClientConfig {
    fn default() -> Self {
        Self {
            server: "0.0.0.0:0".parse().unwrap(),
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
pub struct MkcpServerConfig {
    pub listen: SocketAddr,
    pub header: HeaderType,
    pub interval_ms: u64,
    pub rcv_wnd: u16,
    pub snd_wnd: u16,
    pub nodelay: bool,
}

pub async fn mkcp_connect(cfg: &MkcpClientConfig) -> Result<MkcpStream> {
    let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
    socket.connect(cfg.server).await?;

    let mut kcp = Kcp::new(cfg.conv);
    kcp.set_nodelay(cfg.nodelay);
    kcp.set_wndsize(cfg.snd_wnd, cfg.rcv_wnd);

    let (tx_to_driver, rx_from_user) = mpsc::unbounded_channel::<Bytes>();
    let (tx_to_user, rx_from_driver) = mpsc::channel::<Bytes>(256);

    tokio::spawn(run_client_driver(
        kcp,
        socket,
        cfg.header,
        rx_from_user,
        tx_to_user,
        cfg.interval_ms,
    ));

    Ok(MkcpStream::new(tx_to_driver, rx_from_driver))
}

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
    let mut sessions = HashMap::<SocketAddr, mpsc::UnboundedSender<Vec<u8>>>::new();
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

                if let Some(tx_udp) = sessions.get(&peer) {
                    let _ = tx_udp.send(payload.to_vec());
                    continue;
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
    sessions: &mut HashMap<SocketAddr, mpsc::UnboundedSender<Vec<u8>>>,
) -> Result<()> {
    let mut cursor = payload;
    let Some(first) = Segment::decode(&mut cursor) else {
        return Ok(());
    };

    let mut kcp = Kcp::new(first.conv);
    kcp.set_nodelay(cfg.nodelay);
    kcp.set_wndsize(cfg.snd_wnd, cfg.rcv_wnd);
    let _ = kcp.input(payload);

    let (tx_to_driver, rx_from_user) = mpsc::unbounded_channel::<Bytes>();
    let (tx_to_user, rx_from_driver) = mpsc::channel::<Bytes>(256);
    let (tx_udp, rx_udp) = mpsc::unbounded_channel::<Vec<u8>>();

    sessions.insert(peer, tx_udp);

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

async fn run_server_driver(
    mut kcp: Kcp,
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
    header: HeaderType,
    mut rx_from_user: mpsc::UnboundedReceiver<Bytes>,
    mut rx_from_udp: mpsc::UnboundedReceiver<Vec<u8>>,
    tx_to_user: mpsc::Sender<Bytes>,
    interval_ms: u64,
) {
    let mut ticker = tokio::time::interval(Duration::from_millis(interval_ms));
    let idle_timer = tokio::time::sleep(SERVER_SESSION_IDLE_TIMEOUT);
    tokio::pin!(idle_timer);

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                kcp.update(now_ms());
                let mut out = Vec::new();
                kcp.flush(&mut out);
                for seg in out {
                    let _ = socket.send_to(&header.encode(&seg), peer).await;
                }
                if drain_kcp_recv(&mut kcp, &tx_to_user).await.is_err() {
                    return;
                }
            }
            Some(data) = rx_from_user.recv() => {
                idle_timer.as_mut().reset(tokio::time::Instant::now() + SERVER_SESSION_IDLE_TIMEOUT);
                let _ = kcp.send(&data);
            }
            Some(packet) = rx_from_udp.recv() => {
                idle_timer.as_mut().reset(tokio::time::Instant::now() + SERVER_SESSION_IDLE_TIMEOUT);
                let _ = kcp.input(&packet);
                if drain_kcp_recv(&mut kcp, &tx_to_user).await.is_err() {
                    return;
                }
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
    mut rx_from_user: mpsc::UnboundedReceiver<Bytes>,
    tx_to_user: mpsc::Sender<Bytes>,
    interval_ms: u64,
) {
    let mut ticker = tokio::time::interval(Duration::from_millis(interval_ms));
    let mut udp_buf = vec![0u8; 65535];

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                kcp.update(now_ms());
                let mut out = Vec::new();
                kcp.flush(&mut out);
                for seg in out {
                    let _ = socket.send(&header.encode(&seg)).await;
                }
                if drain_kcp_recv(&mut kcp, &tx_to_user).await.is_err() {
                    return;
                }
            }
            Some(data) = rx_from_user.recv() => {
                let _ = kcp.send(&data);
            }
            Ok(n) = socket.recv(&mut udp_buf) => {
                if let Some(payload) = header.strip(&udp_buf[..n]) {
                    let _ = kcp.input(payload);
                    if drain_kcp_recv(&mut kcp, &tx_to_user).await.is_err() {
                        return;
                    }
                }
            }
            else => {
                return;
            }
        }
    }
}

async fn drain_kcp_recv(kcp: &mut Kcp, tx_to_user: &mpsc::Sender<Bytes>) -> Result<(), ()> {
    let mut recv_buf = vec![0u8; 65535];
    loop {
        let n = kcp.recv(&mut recv_buf);
        if n <= 0 {
            break;
        }
        let data = Bytes::copy_from_slice(&recv_buf[..n as usize]);
        if tx_to_user.send(data).await.is_err() {
            return Err(());
        }
    }
    Ok(())
}

fn now_ms() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    (SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        & 0xFFFFFFFF) as u32
}
