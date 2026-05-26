//! Runnable mKCP example test: SOCKS5 -> VLESS -> mKCP -> Freedom.
//!
//! This covers the current mKCP runtime path, including multiple logical
//! sessions sharing one UDP listener.

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const TEST_UUID: &str = "a3482e88-686a-4a58-8126-99c9df64b7bf";

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
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    let n = stream.read(&mut buf).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }

                    let _ = stream.write_all(&buf[..n]).await;
                }
            });
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

fn server_config(vless_port: u16) -> Arc<blackwire_config::schema::Config> {
    parse_config(format!(
        r#"{{
            "log": {{ "level": "info", "json": false }},
            "inbounds": [{{
                "tag": "vless-mkcp-in",
                "protocol": "vless",
                "listen": "127.0.0.1",
                "port": {vless_port},
                "settings": {{
                    "clients": [{{ "id": "{TEST_UUID}", "email": "mkcp@example.test" }}]
                }},
                "streamSettings": {{
                    "network": "kcp",
                    "security": "none",
                    "kcpSettings": {{
                        "header": "none",
                        "tti": 10,
                        "read_buffer_size": 32,
                        "write_buffer_size": 32
                    }}
                }}
            }}],
            "outbounds": [{{ "tag": "freedom", "protocol": "freedom" }}],
            "routing": {{ "rules": [{{ "outboundTag": "freedom" }}] }}
        }}"#
    ))
}

fn client_config(socks_port: u16, vless_port: u16) -> Arc<blackwire_config::schema::Config> {
    parse_config(format!(
        r#"{{
            "log": {{ "level": "info", "json": false }},
            "inbounds": [{{
                "tag": "socks-in",
                "protocol": "socks",
                "listen": "127.0.0.1",
                "port": {socks_port}
            }}],
            "outbounds": [{{
                "tag": "vless-mkcp-out",
                "protocol": "vless",
                "settings": {{
                    "address": "127.0.0.1",
                    "port": {vless_port},
                    "users": [{{ "id": "{TEST_UUID}", "flow": "" }}]
                }},
                "streamSettings": {{
                    "network": "kcp",
                    "security": "none",
                    "kcpSettings": {{
                        "header": "none",
                        "tti": 10,
                        "read_buffer_size": 32,
                        "write_buffer_size": 32
                    }}
                }}
            }}],
            "routing": {{ "rules": [{{ "outboundTag": "vless-mkcp-out" }}] }}
        }}"#
    ))
}

#[tokio::test]
async fn vless_over_mkcp_transfers_data() {
    let _ = tracing_subscriber::fmt().with_env_filter("warn").try_init();

    let (echo_port, echo_task) = spawn_echo_server().await;
    let vless_port = unused_local_port();
    let socks_port = unused_local_port();

    let _server = blackwire_core::Instance::from_config(server_config(vless_port))
        .await
        .expect("server start failed");
    let _client = blackwire_core::Instance::from_config(client_config(socks_port, vless_port))
        .await
        .expect("client start failed");

    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    let mut stream = socks5_connect(socks_port, "127.0.0.1", echo_port).await;
    let payload = b"HELLO PHASE8 MKCP";
    stream.write_all(payload).await.unwrap();

    let mut echoed = vec![0u8; payload.len()];
    stream.read_exact(&mut echoed).await.unwrap();
    assert_eq!(echoed, payload);

    echo_task.abort();
}

#[tokio::test]
async fn vless_over_mkcp_accepts_concurrent_sessions() {
    let _ = tracing_subscriber::fmt().with_env_filter("warn").try_init();

    let (echo_port, echo_task) = spawn_echo_server().await;
    let vless_port = unused_local_port();
    let socks_port = unused_local_port();

    let _server = blackwire_core::Instance::from_config(server_config(vless_port))
        .await
        .expect("server start failed");
    let _client = blackwire_core::Instance::from_config(client_config(socks_port, vless_port))
        .await
        .expect("client start failed");

    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    let first = tokio::spawn(async move {
        let mut stream = socks5_connect(socks_port, "127.0.0.1", echo_port).await;
        let payload = b"MKCP SESSION ONE";
        stream.write_all(payload).await.unwrap();

        let mut echoed = vec![0u8; payload.len()];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, payload);
    });

    let second = tokio::spawn(async move {
        let mut stream = socks5_connect(socks_port, "127.0.0.1", echo_port).await;
        let payload = b"MKCP SESSION TWO";
        stream.write_all(payload).await.unwrap();

        let mut echoed = vec![0u8; payload.len()];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, payload);
    });

    first.await.unwrap();
    second.await.unwrap();
    echo_task.abort();
}
