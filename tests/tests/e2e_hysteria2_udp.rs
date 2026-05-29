//! End-to-end: Hysteria2 UDP relay.
//!
//! Uses `Hysteria2UdpSession` (a raw QUIC-datagram client) to send a UDP
//! payload through the Hysteria2 server's datagram relay to a loopback UDP
//! echo server, then verifies the echoed response.

use std::net::Ipv4Addr;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::timeout;

const TEST_PASSWORD: &str = "hysteria2-udp-test-pw";

fn unused_local_port() -> u16 {
    std::net::TcpListener::bind(("127.0.0.1", 0))
        .expect("port reserve")
        .local_addr()
        .unwrap()
        .port()
}

async fn spawn_udp_echo_server() -> (u16, tokio::task::JoinHandle<()>) {
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

fn write_dev_cert_files() -> (String, String) {
    let (cert_pem, key_pem) = blackwire_transport::dev_self_signed().unwrap();
    let dir = std::env::temp_dir();
    let unique = format!(
        "blackwire-hysteria2-udp-{}-{}",
        std::process::id(),
        unused_local_port()
    );
    let cert_path = dir.join(format!("{unique}.cert.pem"));
    let key_path = dir.join(format!("{unique}.key.pem"));
    std::fs::write(&cert_path, cert_pem).expect("write cert");
    std::fs::write(&key_path, key_pem).expect("write key");
    (
        cert_path.to_string_lossy().into_owned(),
        key_path.to_string_lossy().into_owned(),
    )
}

fn parse_config(json: String) -> std::sync::Arc<blackwire_config::schema::Config> {
    std::sync::Arc::new(serde_json::from_str(&json).expect("config parse"))
}

fn server_config(
    hysteria_port: u16,
    cert_path: &str,
    key_path: &str,
) -> std::sync::Arc<blackwire_config::schema::Config> {
    parse_config(format!(
        r#"{{
            "inbounds": [{{
                "tag": "hysteria2-udp-in",
                "protocol": "hysteria2",
                "listen": "127.0.0.1",
                "port": {hysteria_port},
                "settings": {{
                    "auth": "{TEST_PASSWORD}",
                    "upMbps": 100,
                    "downMbps": 100
                }},
                "streamSettings": {{
                    "network": "quic",
                    "security": "tls",
                    "tlsSettings": {{
                        "certificateFile": "{cert_path}",
                        "keyFile": "{key_path}"
                    }}
                }}
            }}],
            "outbounds": [{{"tag": "freedom", "protocol": "freedom"}}]
        }}"#
    ))
}

/// Send a UDP datagram through the Hysteria2 tunnel, verify the echo.
#[tokio::test]
async fn hysteria2_udp_relay_roundtrip() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("error")
        .try_init();

    let hysteria_port = unused_local_port();
    let (cert_path, key_path) = write_dev_cert_files();

    let _server =
        blackwire_core::Instance::from_config(server_config(hysteria_port, &cert_path, &key_path))
            .await
            .expect("Hysteria2 server start");

    tokio::time::sleep(Duration::from_millis(100)).await;

    let (echo_port, _echo) = spawn_udp_echo_server().await;

    // Build a Hysteria2 UDP session directly (bypasses the SOCKS5 inbound).
    let config = blackwire_transport::Hysteria2ClientConfig {
        server: format!("127.0.0.1:{hysteria_port}").parse().unwrap(),
        server_name: "localhost".to_string(),
        password: TEST_PASSWORD.to_string(),
        up_mbps: 50,
        down_mbps: 50,
        skip_cert_verify: true,
    };

    let session = timeout(
        Duration::from_secs(5),
        blackwire_transport::Hysteria2UdpSession::connect(&config),
    )
    .await
    .expect("Hysteria2 UDP connect timed out")
    .expect("Hysteria2 UDP connect failed");

    let payload = b"hysteria2-udp-hello-world";
    let dest = blackwire_transport::UdpDestination::V4(Ipv4Addr::LOCALHOST, echo_port);

    session
        .send(dest, bytes::Bytes::from_static(payload))
        .expect("send UDP datagram");

    let response = timeout(Duration::from_secs(5), session.recv())
        .await
        .expect("UDP response timed out")
        .expect("recv datagram failed");

    assert_eq!(
        response.data.as_ref(),
        payload,
        "Hysteria2 UDP echo mismatch"
    );

    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);
}
