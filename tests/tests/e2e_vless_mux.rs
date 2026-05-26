//! VLESS Mux.Cool demux: one mux connection, one TCP sub-stream to an echo target.

use std::net::Ipv4Addr;
use std::sync::Arc;

use blackwire_common::Address;
use blackwire_protocol::vless::codec::{encode_request, Command};
use blackwire_protocol::vless::mux::{
    encode_frame, encode_new_metadata, parse_frame, MUX_DOMAIN, OPT_DATA, SessionStatus,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

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

async fn spawn_echo_server() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("echo bind failed");
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    let Ok(n) = stream.read(&mut buf).await else {
                        break;
                    };
                    if n == 0 {
                        break;
                    }
                    if stream.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
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
                        "email": "mux@example.test"
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

async fn read_mux_reply(stream: &mut TcpStream, timeout: std::time::Duration) -> Vec<u8> {
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
                    if meta.status == SessionStatus::Keep {
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
async fn vless_mux_cool_demuxes_tcp_subconnection() {
    let (echo_port, echo_task) = spawn_echo_server().await;
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

    let dest = Address::Ipv4(Ipv4Addr::LOCALHOST, echo_port);
    let payload = b"MUXPHASE2\n";
    let meta = encode_new_metadata(1, &dest, OPT_DATA).expect("mux meta");
    let frame = encode_frame(&meta, Some(payload)).expect("mux frame");
    stream.write_all(&frame).await.unwrap();

    let echoed = read_mux_reply(&mut stream, std::time::Duration::from_secs(3)).await;
    assert_eq!(
        echoed.as_slice(),
        payload,
        "mux sub-stream did not echo via freedom outbound (got {} bytes)",
        echoed.len()
    );

    echo_task.abort();
}
