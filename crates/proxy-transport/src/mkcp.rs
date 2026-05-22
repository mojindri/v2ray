pub mod header;
pub mod kcp;
pub mod segment;
pub mod stream;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use bytes::Bytes;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use self::header::HeaderType;
use self::kcp::Kcp;
use self::stream::MkcpStream;

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

    let header = cfg.header;
    let interval = cfg.interval_ms;
    tokio::spawn(run_driver(kcp, socket, header, rx_from_user, tx_to_user, interval));

    Ok(MkcpStream::new(tx_to_driver, rx_from_driver))
}

async fn run_driver(
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
                let mut recv_buf = vec![0u8; 65535];
                loop {
                    let n = kcp.recv(&mut recv_buf);
                    if n <= 0 { break; }
                    let data = Bytes::copy_from_slice(&recv_buf[..n as usize]);
                    if tx_to_user.send(data).await.is_err() { return; }
                }
            }
            Some(data) = rx_from_user.recv() => {
                let _ = kcp.send(&data);
            }
            Ok(n) = socket.recv(&mut udp_buf) => {
                if let Some(payload) = header.strip(&udp_buf[..n]) {
                    let _ = kcp.input(payload);
                }
            }
        }
    }
}

fn now_ms() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    (SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() & 0xFFFFFFFF) as u32
}
