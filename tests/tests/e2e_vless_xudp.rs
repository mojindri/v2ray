//! VLESS XUDP over Mux.Cool: session `0`, GlobalID, per-packet UDP Keep replies.

use std::net::Ipv4Addr;
use std::sync::Arc;

use blackwire_common::Address;
use blackwire_protocol::vless::codec::{encode_request, Command};
use blackwire_protocol::vless::mux::{
    encode_frame, encode_new_metadata_xudp, parse_frame, MUX_DOMAIN, OPT_DATA, SessionStatus,
    XUDP_SESSION_ID,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

const TEST_UUID: &str = "a3482e88-686a-4a58-8126-99c9df64b7bf";

fn parse_uuid(s: &str) -> [u8; 16] {
    let uuid = uuid::Uuid::parse_str(s).expect("invalid test uuid");
    *uuid.as_bytes()
}

fn unused_local_port() -> u16 {
    std::net::TcpListener::bind(("127.0.0.1", 0))
        .expect("bind")
        .local_addr()
        .unwrap()
        .port()
}

fn parse_config(json: String) -> Arc<blackwire_config::schema::Config> {
    Arc::new(serde_json::from_str(&json).expect("config parse failed"))
}

async fn spawn_udp_echo_server() -> (u16, tokio::task::JoinHandle<()>) {
    let sock = UdpSocket::bind(("127.0.0.1", 0))
        .await
        .expect("udp echo bind failed");
    let port = sock.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
                break;
            };
            if n == 0 {
                continue;
            }
            if sock.send_to(&buf[..n], peer).await.is_err() {
                break;
            }
        }
    });
    (port, task)
}

fn vless_server_config(vless_port: u16) -> Arc<blackwire_config::schema::Config> {
    parse_config(format!(
        r#"{{
            "inbounds": [{{
                "tag": "vless-in",
                "protocol": "vless",
                "listen": "127.0.0.1",
                "port": {vless_port},
                "settings": {{
                    "clients": [{{
                        "id": "{TEST_UUID}",
                        "email": "xudp@example.test"
                    }}]
                }}
            }}],
            "outbounds": [{{
                "tag": "freedom",
                "protocol": "freedom"
            }}],
            "routing": {{
                "rules": [{{ "outboundTag": "freedom" }}]
            }}
        }}"#
    ))
}

async fn read_mux_udp_reply(stream: &mut TcpStream, timeout: std::time::Duration) -> Vec<u8> {
    let mut acc = Vec::new();
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        let mut chunk = [0u8; 4096];
        match tokio::time::timeout(remaining, stream.read(&mut chunk)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => acc.extend_from_slice(&chunk[..n]),
            _ => break,
        }
        while !acc.is_empty() {
            match parse_frame(&acc) {
                Ok((meta, payload, consumed)) => {
                    acc.drain(..consumed);
                    if meta.session_id == XUDP_SESSION_ID
                        && meta.status == SessionStatus::Keep
                        && meta.target.is_some()
                    {
                        if let Some(p) = payload {
                            return p;
                        }
                    }
                }
                Err(_) => break,
            }
        }
    }
    acc
}

#[tokio::test]
async fn vless_xudp_echoes_udp_via_mux_session_zero() {
    let (udp_echo_port, udp_echo_task) = spawn_udp_echo_server().await;
    let vless_port = unused_local_port();
    let _server = blackwire_core::Instance::from_config(vless_server_config(vless_port))
        .await
        .expect("server start failed");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let mut stream = TcpStream::connect(("127.0.0.1", vless_port))
        .await
        .expect("vless connect failed");

    let uuid = parse_uuid(TEST_UUID);
    let header = encode_request(
        &uuid,
        "",
        Command::Mux,
        &Address::Domain(MUX_DOMAIN.into(), 0),
    )
    .expect("encode vless mux request");
    stream.write_all(&header).await.unwrap();
    let mut resp_hdr = [0u8; 2];
    stream.read_exact(&mut resp_hdr).await.unwrap();
    assert_eq!(resp_hdr, [0, 0]);

    let dest = Address::Ipv4(Ipv4Addr::LOCALHOST, udp_echo_port);
    let payload = b"XUDP-ECHO\n";
    let global_id = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    let meta = encode_new_metadata_xudp(&dest, &global_id, OPT_DATA).expect("xudp meta");
    let frame = encode_frame(&meta, Some(payload)).expect("xudp frame");
    stream.write_all(&frame).await.unwrap();

    let echoed = read_mux_udp_reply(&mut stream, std::time::Duration::from_secs(3)).await;
    assert_eq!(
        echoed.as_slice(),
        payload,
        "xudp UDP sub-stream did not echo (got {} bytes)",
        echoed.len()
    );

    udp_echo_task.abort();
}
