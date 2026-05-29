//! In-process e2e: SOCKS5 UDP ASSOCIATE (RFC 1928).
//!
//! Verifies that a SOCKS5 inbound correctly handles UDP ASSOCIATE:
//! binds a relay UDP socket, returns its address in the reply, and
//! round-trips a datagram through a UDP echo server.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

fn unused_tcp_port() -> u16 {
    std::net::TcpListener::bind(("127.0.0.1", 0))
        .expect("port reserve")
        .local_addr()
        .unwrap()
        .port()
}

fn parse_config(json: serde_json::Value) -> Arc<blackwire_config::schema::Config> {
    Arc::new(serde_json::from_value(json).expect("config parse"))
}

/// Bind a UDP echo server; returns its port and a join handle.
async fn spawn_udp_echo() -> (u16, tokio::task::JoinHandle<()>) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = sock.local_addr().unwrap().port();
    let handle = tokio::spawn(async move {
        let mut buf = [0u8; 65535];
        loop {
            let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
                break;
            };
            let _ = sock.send_to(&buf[..n], peer).await;
        }
    });
    (port, handle)
}

/// Build a SOCKS5 UDP datagram for IPv4 destination.
fn build_udp_datagram(dest_ip: Ipv4Addr, dest_port: u16, payload: &[u8]) -> Vec<u8> {
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&[0, 0, 0]); // RSV(2) + FRAG(1)
    pkt.push(0x01); // ATYP IPv4
    pkt.extend_from_slice(&dest_ip.octets());
    pkt.extend_from_slice(&dest_port.to_be_bytes());
    pkt.extend_from_slice(payload);
    pkt
}

/// Parse SOCKS5 UDP reply header; return (src_ip, src_port, payload_offset).
fn parse_udp_reply(buf: &[u8]) -> (Ipv4Addr, u16, usize) {
    assert!(buf.len() >= 10, "UDP reply too short");
    assert_eq!(&buf[..3], &[0, 0, 0], "RSV+FRAG must be zero");
    assert_eq!(buf[3], 0x01, "expected IPv4 ATYP in reply");
    let ip = Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
    let port = u16::from_be_bytes([buf[8], buf[9]]);
    (ip, port, 10)
}

/// SOCKS5 UDP ASSOCIATE round-trip: connect, associate, send datagram, receive echo.
#[tokio::test]
async fn socks5_udp_associate_roundtrip() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("error")
        .try_init();

    let socks_port = unused_tcp_port();

    let _srv = blackwire_core::Instance::from_config(parse_config(serde_json::json!({
        "inbounds": [{
            "tag": "socks-udp-in",
            "protocol": "socks",
            "listen": "127.0.0.1",
            "port": socks_port
        }],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}]
    })))
    .await
    .expect("server start");

    tokio::time::sleep(Duration::from_millis(40)).await;

    let (echo_port, _echo) = spawn_udp_echo().await;

    // ── TCP control connection + UDP ASSOCIATE handshake ──────────────────────

    let mut ctrl = TcpStream::connect(("127.0.0.1", socks_port))
        .await
        .expect("connect to SOCKS5 proxy");

    // Greeting: VER=5, NMETHODS=1, METHOD=0 (no auth)
    ctrl.write_all(&[5, 1, 0]).await.unwrap();
    let mut gresp = [0u8; 2];
    ctrl.read_exact(&mut gresp).await.unwrap();
    assert_eq!(gresp, [5, 0], "SOCKS5 method negotiation failed");

    // UDP ASSOCIATE request: VER=5, CMD=3, RSV=0, ATYP=1, DST=0.0.0.0:0
    ctrl.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();

    // Reply: VER=5, REP=0, RSV=0, ATYP=1, BND.ADDR(4), BND.PORT(2) — 10 bytes
    let mut reply = [0u8; 10];
    timeout(Duration::from_secs(3), ctrl.read_exact(&mut reply))
        .await
        .expect("UDP ASSOCIATE reply timed out")
        .expect("read failed");

    assert_eq!(reply[0], 5, "VER");
    assert_eq!(reply[1], 0, "REP must be success");
    assert_eq!(reply[3], 1, "ATYP must be IPv4");
    let relay_port = u16::from_be_bytes([reply[8], reply[9]]);
    assert_ne!(relay_port, 0, "relay port must be non-zero");

    // ── UDP round-trip ────────────────────────────────────────────────────────

    let client_udp = UdpSocket::bind("127.0.0.1:0").await.expect("UDP bind");
    let relay_addr: SocketAddr = format!("127.0.0.1:{relay_port}").parse().unwrap();

    let payload = b"socks5-udp-hello";
    let dgram = build_udp_datagram(Ipv4Addr::LOCALHOST, echo_port, payload);

    // The relay filters by client IP; send from loopback so it matches.
    client_udp
        .send_to(&dgram, relay_addr)
        .await
        .expect("UDP send");

    let mut buf = [0u8; 65535];
    let n = timeout(Duration::from_secs(4), client_udp.recv(&mut buf))
        .await
        .expect("UDP reply timed out")
        .expect("UDP recv failed");

    let (_src_ip, _src_port, off) = parse_udp_reply(&buf[..n]);
    assert_eq!(&buf[off..n], payload, "UDP echo payload mismatch");
}
