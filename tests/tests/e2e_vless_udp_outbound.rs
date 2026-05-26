//! In-process e2e: VLESS UDP outbound (client role).
//!
//! Demonstrates blackwire acting as a VLESS UDP *client* (CMD 0x02):
//!   1. Starts a blackwire VLESS server.
//!   2. Starts a plain UDP echo server.
//!   3. Opens a TCP connection and runs `connect_vless_on_stream()` with `Command::Udp`.
//!   4. Sends raw UDP payload (no datagram framing — VLESS CMD 0x02 is raw relay).
//!   5. Verifies the echo reply arrives.

use std::sync::Arc;

use blackwire_common::Address;
use blackwire_protocol::vless::codec::Command;
use blackwire_protocol::vless::outbound::connect_vless_on_stream;
use blackwire_protocol::vless::udp::{read_udp_header, read_udp_payload, write_udp_packet};
use tokio::net::UdpSocket;
use uuid::Uuid;

const TEST_UUID: &str = "b1c2d3e4-f5a6-7890-abcd-ef1234567890";

fn parse_uuid(s: &str) -> [u8; 16] {
    *Uuid::parse_str(s).expect("invalid test uuid").as_bytes()
}

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

/// VLESS UDP outbound: client sends CMD 0x02 to a blackwire VLESS server,
/// server relays to UDP echo, reply comes back through the stream.
#[tokio::test]
async fn vless_udp_outbound_client_roundtrip() {
    let (echo_port, echo_task) = spawn_udp_echo().await;

    let vless_port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };

    let server = blackwire_core::Instance::from_config(parse_config(format!(
        r#"{{
            "inbounds": [{{
                "tag": "vless-in",
                "protocol": "vless",
                "listen": "127.0.0.1",
                "port": {vless_port},
                "settings": {{ "clients": [{{ "id": "{TEST_UUID}" }}] }}
            }}],
            "outbounds": [{{ "tag": "freedom", "protocol": "freedom" }}],
            "routing": {{ "rules": [{{ "outboundTag": "freedom" }}] }}
        }}"#
    )))
    .await
    .expect("server start");

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let uuid = parse_uuid(TEST_UUID);
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", vless_port))
        .await
        .unwrap();
    let echo_dest = Address::Ipv4(std::net::Ipv4Addr::LOCALHOST, echo_port);
    let mut stream =
        connect_vless_on_stream(Box::new(tcp), &uuid, "", Command::Udp, &echo_dest)
            .await
            .unwrap();

    let payload = b"vless-udp-outbound-ping";

    // VLESS UDP framing: u16_be(addr_len) | address | payload
    write_udp_packet(&mut stream, &echo_dest, payload)
        .await
        .unwrap();

    // Read the reply frame
    let reply_dest = read_udp_header(&mut stream).await.unwrap();
    let reply_payload = read_udp_payload(&mut stream).await.unwrap();

    assert_eq!(reply_dest, echo_dest);
    assert_eq!(reply_payload, payload, "echo payload mismatch");

    drop(stream);
    drop(server);
    echo_task.abort();
}
