//! In-process e2e: SS2022 UDP relay (SIP022 / sing-box wire).

use std::net::Ipv4Addr;
use std::sync::Arc;

use blackwire_common::Address;
use blackwire_protocol::ss2022::password_to_psk;
use blackwire_protocol::ss2022::udp::{decode_server_packet, encode_client_packet};
use tokio::net::UdpSocket;

const PASSWORD: &str = "ss2022-udp-e2e-test";

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

/// SS2022 UDP in-process e2e: client sends encrypted packet, server relays to
/// UDP echo, verifies encrypted reply contains original payload.
#[tokio::test]
async fn ss2022_udp_relay_roundtrip() {
    let (echo_port, echo_task) = spawn_udp_echo().await;

    let server_port = {
        let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        s.local_addr().unwrap().port()
    };

    let _server = blackwire_core::Instance::from_config(parse_config(format!(
        r#"{{
            "inbounds": [{{
                "tag": "ss-udp-in",
                "protocol": "shadowsocks",
                "listen": "127.0.0.1",
                "port": {server_port},
                "settings": {{
                    "method": "2022-blake3-aes-256-gcm",
                    "password": "{PASSWORD}",
                    "network": "udp"
                }}
            }}],
            "outbounds": [{{ "tag": "freedom", "protocol": "freedom" }}],
            "routing": {{ "rules": [{{ "outboundTag": "freedom" }}] }}
        }}"#
    )))
    .await
    .expect("server start");

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let psk = password_to_psk(PASSWORD);
    let client_session_id = 0x1122_3344_5566_7788_u64;
    let packet_id = 0u64;
    let echo_dest = Address::Ipv4(Ipv4Addr::LOCALHOST, echo_port);
    let payload = b"ss2022-udp-ping";

    let client_pkt =
        encode_client_packet(&psk, client_session_id, packet_id, &echo_dest, payload).unwrap();

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client
        .send_to(&client_pkt, format!("127.0.0.1:{server_port}"))
        .await
        .unwrap();

    let mut buf = [0u8; 65535];
    let n = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        client.recv(&mut buf),
    )
    .await
    .expect("timed out waiting for SS2022 UDP reply")
    .expect("recv error");

    let plain = decode_server_packet(&buf[..n], &psk).expect("failed to decrypt server reply");

    assert_eq!(plain[0], 0x01, "type should be server (0x01)");
    assert!(
        plain.windows(payload.len()).any(|w| w == payload),
        "echo payload not found in decrypted reply: {:?}",
        &plain
    );

    drop(_server);
    echo_task.abort();
}
