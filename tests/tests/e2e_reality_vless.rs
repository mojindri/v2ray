//! End-to-end example: SOCKS5 -> VLESS over REALITY -> Freedom.
//!
//! This proves the local REALITY path transfers real bytes end to end.
//!
//! The outbound side now completes the Phase 3 TLS handshake, and the inbound
//! side unwraps REALITY plus a local TLS session before handing bytes to VLESS.
//! The test exercises the
//! localhost example topology rather than the live Xray interop harness.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const TEST_UUID: &str = "a3482e88-686a-4a58-8126-99c9df64b7bf";
const REALITY_PRIVATE_KEY: &str =
    "8cb13706aa547712de8f687dc32e66b0ec2e753ba310e734b72fb52ce5e6a4a8";
const REALITY_PUBLIC_KEY: &str = "bbf29cec98e1aff519fcd09456d90407804f91ae62be4b8aac48f6d676807865";
const REALITY_SHORT_ID: &str = "0123456789abcdef";

fn unused_local_port() -> u16 {
    let listener =
        std::net::TcpListener::bind(("127.0.0.1", 0)).expect("failed to reserve local port");
    listener.local_addr().unwrap().port()
}

async fn spawn_echo_server() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("echo bind failed");
    let port = listener.local_addr().unwrap().port();

    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("echo accept failed");
        let mut buf = [0u8; 1024];
        loop {
            let n = stream.read(&mut buf).await.expect("echo read failed");
            if n == 0 {
                break;
            }
            stream
                .write_all(&buf[..n])
                .await
                .expect("echo write failed");
        }
    });

    (port, task)
}

async fn socks5_connect(socks_port: u16, dest_host: &str, dest_port: u16) -> TcpStream {
    let mut stream = TcpStream::connect(("127.0.0.1", socks_port))
        .await
        .expect("SOCKS5 connect failed");

    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp, [5, 0]);

    let host_bytes = dest_host.as_bytes();
    let mut req = vec![5, 1, 0, 3, host_bytes.len() as u8];
    req.extend_from_slice(host_bytes);
    req.extend_from_slice(&dest_port.to_be_bytes());
    stream.write_all(&req).await.unwrap();

    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0, "SOCKS5 CONNECT failed: REP={:#x}", reply[1]);

    stream
}

fn parse_config(json: String) -> Arc<blackwire_config::schema::Config> {
    Arc::new(serde_json::from_str(&json).expect("config parse failed"))
}

fn server_config(vless_port: u16, fallback_port: u16) -> Arc<blackwire_config::schema::Config> {
    parse_config(format!(
        r#"{{
            "inbounds": [{{
                "tag": "vless-reality-in",
                "protocol": "vless",
                "listen": "127.0.0.1",
                "port": {vless_port},
                "settings": {{
                    "clients": [{{
                        "id": "{TEST_UUID}",
                        "email": "reality@example.test"
                    }}]
                }},
                "streamSettings": {{
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {{
                        "dest": "127.0.0.1:{fallback_port}",
                        "privateKey": "{REALITY_PRIVATE_KEY}",
                        "shortIds": ["{REALITY_SHORT_ID}"],
                        "serverName": "www.example.com",
                        "maxTimeDiff": 120
                    }}
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

fn client_config(socks_port: u16, vless_port: u16) -> Arc<blackwire_config::schema::Config> {
    parse_config(format!(
        r#"{{
            "inbounds": [{{
                "tag": "socks-in",
                "protocol": "socks",
                "listen": "127.0.0.1",
                "port": {socks_port}
            }}],
            "outbounds": [{{
                "tag": "vless-reality-out",
                "protocol": "vless",
                "settings": {{
                    "address": "127.0.0.1",
                    "port": {vless_port},
                    "users": [{{
                        "id": "{TEST_UUID}",
                        "flow": ""
                    }}]
                }},
                "streamSettings": {{
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {{
                        "publicKey": "{REALITY_PUBLIC_KEY}",
                        "shortId": "{REALITY_SHORT_ID}",
                        "serverName": "www.example.com",
                        "fingerprint": "chrome"
                    }}
                }}
            }}],
            "routing": {{
                "rules": [{{ "outboundTag": "vless-reality-out" }}]
            }}
        }}"#
    ))
}

#[tokio::test]
async fn reality_vless_to_freedom_transfers_data() {
    let (echo_port, echo_task) = spawn_echo_server().await;
    let socks_port = unused_local_port();
    let vless_port = unused_local_port();
    let fallback_port = unused_local_port();

    let _server = blackwire_core::Instance::from_config(server_config(vless_port, fallback_port))
        .await
        .expect("server instance failed");
    let _client = blackwire_core::Instance::from_config(client_config(socks_port, vless_port))
        .await
        .expect("client instance failed");

    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

    let mut stream = timeout(
        Duration::from_secs(5),
        socks5_connect(socks_port, "127.0.0.1", echo_port),
    )
    .await
    .expect("SOCKS5 connect path timed out");
    let payload = b"HELLO PHASE2 REALITY";
    timeout(Duration::from_secs(5), stream.write_all(payload))
        .await
        .expect("payload write timed out")
        .unwrap();

    let mut echoed = vec![0u8; payload.len()];
    timeout(Duration::from_secs(5), stream.read_exact(&mut echoed))
        .await
        .expect("echo read timed out")
        .unwrap();
    assert_eq!(echoed, payload);

    echo_task.abort();
}
