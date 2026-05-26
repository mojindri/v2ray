//! In-process e2e: Trojan UDP outbound (client role).
//!
//! Demonstrates blackwire acting as a Trojan UDP ASSOCIATE *client*:
//!   1. Starts a blackwire Trojan server instance.
//!   2. Starts a plain UDP echo server.
//!   3. Opens a TCP connection to the Trojan server and sends CMD_UDP_ASSOCIATE.
//!   4. Sends one datagram frame targeting the UDP echo server.
//!   5. Verifies the reply frame contains the echoed payload.

use std::sync::Arc;

use blackwire_common::Address;
use blackwire_protocol::trojan::codec::{encode_udp_datagram, parse_udp_datagram};
use blackwire_protocol::trojan::compute_token;
use blackwire_protocol::trojan::outbound::connect_trojan_on_stream_udp;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;

const PASSWORD: &str = "udp-outbound-test";

fn parse_config(json: String) -> Arc<blackwire_config::schema::Config> {
    Arc::new(serde_json::from_str(&json).expect("config parse"))
}

async fn spawn_udp_echo() -> (u16, tokio::task::JoinHandle<()>) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = sock.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
                break;
            };
            let _ = sock.send_to(&buf[..n], peer).await;
        }
    });
    (port, task)
}

/// Trojan UDP outbound: client opens CMD_UDP_ASSOCIATE, exchanges one datagram
/// via a blackwire Trojan server, and verifies the echo reply.
#[tokio::test]
async fn trojan_udp_outbound_client_roundtrip() {
    let (echo_port, echo_task) = spawn_udp_echo().await;

    let trojan_port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };

    let server = blackwire_core::Instance::from_config(parse_config(format!(
        r#"{{
            "inbounds": [{{
                "tag": "trojan-in",
                "protocol": "trojan",
                "listen": "127.0.0.1",
                "port": {trojan_port},
                "settings": {{ "clients": [{{ "password": "{PASSWORD}" }}] }}
            }}],
            "outbounds": [{{ "tag": "freedom", "protocol": "freedom" }}],
            "routing": {{ "rules": [{{ "outboundTag": "freedom" }}] }}
        }}"#
    )))
    .await
    .expect("server start");

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let token = compute_token(PASSWORD);
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", trojan_port))
        .await
        .unwrap();
    let initial_dest = Address::Ipv4(std::net::Ipv4Addr::UNSPECIFIED, 0);
    let mut stream =
        connect_trojan_on_stream_udp(Box::new(tcp), &token, &initial_dest)
            .await
            .unwrap();

    let echo_dest = Address::Ipv4(std::net::Ipv4Addr::LOCALHOST, echo_port);
    let payload = b"trojan-udp-outbound-ping";
    let frame = encode_udp_datagram(&echo_dest, payload).unwrap();
    stream.write_all(&frame).await.unwrap();
    stream.flush().await.unwrap();

    let mut acc = Vec::new();
    let mut buf = [0u8; 4096];
    for _ in 0..20 {
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            stream.read(&mut buf),
        )
        .await
        .expect("timed out waiting for datagram reply")
        .expect("read error");
        if n == 0 {
            break;
        }
        acc.extend_from_slice(&buf[..n]);
        // Try to parse the accumulated bytes as a datagram frame
        if let Ok((_dest, data, _consumed)) = parse_udp_datagram(&acc) {
            if data.windows(payload.len()).any(|w| w == payload) {
                drop(stream);
                drop(server);
                echo_task.abort();
                return;
            }
        }
        // Also accept the raw payload appearing in the buffer
        if acc.windows(payload.len()).any(|w| w == payload) {
            drop(stream);
            drop(server);
            echo_task.abort();
            return;
        }
    }

    panic!("echo payload not found in reply: {acc:?}");
}
