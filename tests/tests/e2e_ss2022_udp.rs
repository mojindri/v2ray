//! In-process e2e: SS2022 UDP relay (SIP022).
//!
//! Starts a blackwire instance with `network: udp` SS2022 inbound,
//! starts a plain UDP echo server, then sends an encrypted SS2022 UDP packet
//! and verifies the encrypted reply contains the original payload.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::{
    aead::{generic_array::GenericArray, Aead},
    Aes256Gcm, KeyInit,
};
use blackwire_common::{write_socks5_address, Address};
use blackwire_protocol::ss2022::password_to_psk;
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

fn make_udp_nonce(packet_id: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..8].copy_from_slice(&packet_id.to_le_bytes());
    n
}

fn derive_udp_session_key(psk: &[u8; 32], session_id: &[u8; 8]) -> [u8; 32] {
    let mut material = [0u8; 40];
    material[..32].copy_from_slice(psk);
    material[32..].copy_from_slice(session_id);
    blake3::derive_key("shadowsocks 2022 session subkey", &material)
}

fn build_client_packet(
    psk: &[u8; 32],
    session_id: &[u8; 8],
    packet_id: u64,
    dest: &Address,
    payload: &[u8],
) -> Vec<u8> {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut plain = Vec::new();
    plain.push(0x00u8); // type: client
    plain.extend_from_slice(&ts.to_be_bytes());
    plain.extend_from_slice(&0u16.to_be_bytes()); // padding_len = 0
    let mut addr_buf = bytes::BytesMut::new();
    write_socks5_address(&mut addr_buf, dest).unwrap();
    plain.extend_from_slice(&addr_buf);
    plain.extend_from_slice(payload);

    let session_key = derive_udp_session_key(psk, session_id);
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&session_key));
    let nonce = make_udp_nonce(packet_id);
    let ct = cipher
        .encrypt(GenericArray::from_slice(&nonce), plain.as_slice())
        .unwrap();

    let mut pkt = Vec::new();
    pkt.extend_from_slice(session_id);
    pkt.extend_from_slice(&packet_id.to_le_bytes());
    pkt.extend_from_slice(&ct);
    pkt
}

fn decrypt_server_reply(
    psk: &[u8; 32],
    session_id: &[u8; 8],
    buf: &[u8],
) -> Option<Vec<u8>> {
    if buf.len() < 17 {
        return None;
    }
    let sid: [u8; 8] = buf[..8].try_into().ok()?;
    if sid != *session_id {
        return None;
    }
    let server_pkt_id = u64::from_le_bytes(buf[8..16].try_into().ok()?);
    let ciphertext = &buf[16..];

    let session_key = derive_udp_session_key(psk, session_id);
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&session_key));
    let nonce = make_udp_nonce(server_pkt_id);
    cipher
        .decrypt(GenericArray::from_slice(&nonce), ciphertext)
        .ok()
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
    let session_id = [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    let packet_id = 0u64;
    let echo_dest = Address::Ipv4(Ipv4Addr::LOCALHOST, echo_port);
    let payload = b"ss2022-udp-ping";

    let client_pkt = build_client_packet(&psk, &session_id, packet_id, &echo_dest, payload);

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

    let plain = decrypt_server_reply(&psk, &session_id, &buf[..n])
        .expect("failed to decrypt server reply");

    // plaintext: type(1)=1 | timestamp(8) | client_pkt_id(8) | padding_len(2) | padding | addr | payload
    assert_eq!(plain[0], 0x01, "type should be server (0x01)");
    assert!(
        plain.windows(payload.len()).any(|w| w == payload),
        "echo payload not found in decrypted reply: {:?}",
        &plain
    );

    drop(_server);
    echo_task.abort();
}
