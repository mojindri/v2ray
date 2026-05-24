//! End-to-end example: SOCKS5 client proxy -> Hysteria2 server proxy -> Freedom.
//!
//! This proves the Phase 3 QUIC path transfers real TCP bytes.

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const TEST_PASSWORD: &str = "phase3-test-password";

fn unused_local_port() -> u16 {
    let listener =
        std::net::TcpListener::bind(("127.0.0.1", 0)).expect("failed to reserve local port");
    listener.local_addr().unwrap().port()
}

async fn spawn_echo_server() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("echo server bind failed");
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
        .expect("failed to connect to SOCKS5 proxy");

    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp, [5, 0], "SOCKS5 method negotiation failed");

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

fn write_dev_cert_files() -> (String, String) {
    let (cert_pem, key_pem) = proxy_transport::dev_self_signed().unwrap();
    let dir = std::env::temp_dir();
    let unique = format!(
        "blackwire-phase3-{}-{}",
        std::process::id(),
        unused_local_port()
    );
    let cert_path = dir.join(format!("{unique}.cert.pem"));
    let key_path = dir.join(format!("{unique}.key.pem"));

    std::fs::write(&cert_path, cert_pem).expect("write cert failed");
    std::fs::write(&key_path, key_pem).expect("write key failed");

    (
        cert_path.to_string_lossy().into_owned(),
        key_path.to_string_lossy().into_owned(),
    )
}

fn parse_config(json: String) -> Arc<proxy_config::schema::Config> {
    Arc::new(serde_json::from_str(&json).expect("config parse failed"))
}

fn server_config(
    hysteria_port: u16,
    cert_path: &str,
    key_path: &str,
) -> Arc<proxy_config::schema::Config> {
    parse_config(format!(
        r#"{{
            "inbounds": [{{
                "tag": "hysteria2-in",
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

fn client_config(socks_port: u16, hysteria_port: u16) -> Arc<proxy_config::schema::Config> {
    parse_config(format!(
        r#"{{
            "inbounds": [{{
                "tag": "socks-in",
                "protocol": "socks",
                "listen": "127.0.0.1",
                "port": {socks_port}
            }}],
            "outbounds": [{{
                "tag": "hysteria2-out",
                "protocol": "hysteria2",
                "settings": {{
                    "server": "127.0.0.1:{hysteria_port}",
                    "serverName": "localhost",
                    "auth": "{TEST_PASSWORD}",
                    "upMbps": 50,
                    "downMbps": 50,
                    "skipCertVerify": true
                }}
            }}],
            "routing": {{
                "rules": [{{ "outboundTag": "hysteria2-out" }}]
            }}
        }}"#
    ))
}

#[tokio::test]
async fn phase3_hysteria2_to_freedom_transfers_data() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    let (echo_port, echo_task) = spawn_echo_server().await;
    let socks_port = unused_local_port();
    let hysteria_port = unused_local_port();
    let (cert_path, key_path) = write_dev_cert_files();

    let _server =
        proxy_core::Instance::from_config(server_config(hysteria_port, &cert_path, &key_path))
            .await
            .expect("server proxy instance creation failed");
    let _client = proxy_core::Instance::from_config(client_config(socks_port, hysteria_port))
        .await
        .expect("client proxy instance creation failed");

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let mut stream = socks5_connect(socks_port, "127.0.0.1", echo_port).await;
    let payload = b"HELLO PHASE3 HYSTERIA2";
    stream.write_all(payload).await.unwrap();

    let mut echoed = vec![0u8; payload.len()];
    stream.read_exact(&mut echoed).await.unwrap();
    assert_eq!(echoed, payload, "proxy chain did not echo the payload");

    echo_task.abort();
    let _ = std::fs::remove_file(cert_path);
    let _ = std::fs::remove_file(key_path);
}
