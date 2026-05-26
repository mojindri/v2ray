//! Runnable HTTP/VMess/gRPC example test: HTTP CONNECT -> VMess -> gRPC -> Freedom.
//!
//! This mirrors `examples/http-vmess-grpc-local` and proves that real
//! bytes can cross the full HTTP/VMess/gRPC chain.

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const TEST_UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
const GRPC_SERVICE: &str = "demo.Gun";

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

async fn http_connect(proxy_port: u16, target_host: &str, target_port: u16) -> TcpStream {
    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port))
        .await
        .expect("failed to connect to HTTP CONNECT proxy");

    // Ask the HTTP inbound to open a TCP tunnel to the final destination.
    let req = format!(
        "CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}:{target_port}\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).await.unwrap();

    let mut response = Vec::new();
    let mut buf = [0u8; 1];
    loop {
        stream.read_exact(&mut buf).await.unwrap();
        response.push(buf[0]);
        if response.ends_with(b"\r\n\r\n") {
            break;
        }
        if response.len() > 512 {
            panic!("HTTP CONNECT response too long");
        }
    }

    let response = String::from_utf8_lossy(&response);
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "unexpected HTTP CONNECT response: {response:?}"
    );

    stream
}

fn parse_config(json: String) -> Arc<blackwire_config::schema::Config> {
    Arc::new(serde_json::from_str(&json).expect("config parse failed"))
}

fn server_config(vmess_port: u16) -> Arc<blackwire_config::schema::Config> {
    parse_config(format!(
        r#"{{
            "log": {{ "level": "info", "json": false }},
            "inbounds": [{{
                "tag": "vmess-grpc-in",
                "protocol": "vmess",
                "listen": "127.0.0.1",
                "port": {vmess_port},
                "settings": {{
                    "clients": [{{ "id": "{TEST_UUID}", "email": "vmess-grpc@example.test" }}]
                }},
                "streamSettings": {{
                    "network": "grpc",
                    "security": "none",
                    "grpcSettings": {{ "serviceName": "{GRPC_SERVICE}" }}
                }}
            }}],
            "outbounds": [{{ "tag": "freedom", "protocol": "freedom" }}],
            "routing": {{ "rules": [{{ "outboundTag": "freedom" }}] }}
        }}"#
    ))
}

fn client_config(http_port: u16, vmess_port: u16) -> Arc<blackwire_config::schema::Config> {
    parse_config(format!(
        r#"{{
            "log": {{ "level": "info", "json": false }},
            "inbounds": [{{
                "tag": "http-in",
                "protocol": "http",
                "listen": "127.0.0.1",
                "port": {http_port}
            }}],
            "outbounds": [{{
                "tag": "vmess-grpc-out",
                "protocol": "vmess",
                "settings": {{
                    "address": "127.0.0.1",
                    "port": {vmess_port},
                    "users": [{{ "id": "{TEST_UUID}" }}]
                }},
                "streamSettings": {{
                    "network": "grpc",
                    "security": "none",
                    "grpcSettings": {{ "serviceName": "{GRPC_SERVICE}" }}
                }}
            }}],
            "routing": {{ "rules": [{{ "outboundTag": "vmess-grpc-out" }}] }}
        }}"#
    ))
}

#[tokio::test]
async fn http_connect_vmess_grpc_transfers_data() {
    let _ = tracing_subscriber::fmt().with_env_filter("warn").try_init();

    let (echo_port, echo_task) = spawn_echo_server().await;
    let vmess_port = unused_local_port();
    let http_port = unused_local_port();

    let _server = blackwire_core::Instance::from_config(server_config(vmess_port))
        .await
        .expect("server start failed");
    let _client = blackwire_core::Instance::from_config(client_config(http_port, vmess_port))
        .await
        .expect("client start failed");

    tokio::time::sleep(tokio::time::Duration::from_millis(80)).await;

    let mut stream = http_connect(http_port, "127.0.0.1", echo_port).await;
    let payload = b"HELLO PHASE5 HTTP VMESS GRPC";
    stream.write_all(payload).await.unwrap();

    let mut echoed = vec![0u8; payload.len()];
    stream.read_exact(&mut echoed).await.unwrap();
    assert_eq!(echoed, payload);

    echo_task.abort();
}
