//! End-to-end example: SOCKS5 client proxy -> VLESS server proxy -> Freedom.
//!
//! This test spins up a complete basic VLESS proxy chain in a single process:
//!
//!   Test client
//!       -> SOCKS5 inbound on the client proxy
//!       -> VLESS outbound from the client proxy
//!       -> VLESS inbound on the server proxy
//!       -> Freedom outbound from the server proxy
//!       -> TCP echo server
//!
//! Data path: the test sends "HELLO PHASE1" through the SOCKS5 listener and
//! expects the echo server to return the exact same bytes.

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const TEST_UUID: &str = "a3482e88-686a-4a58-8126-99c9df64b7bf";

fn unused_local_port() -> u16 {
    let listener =
        std::net::TcpListener::bind(("127.0.0.1", 0)).expect("failed to reserve local port");
    listener
        .local_addr()
        .expect("failed to read local address")
        .port()
}

async fn spawn_echo_server() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("echo server bind failed");
    let port = listener
        .local_addr()
        .expect("failed to read echo server address")
        .port();

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

async fn spawn_http_server() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("HTTP server bind failed");
    let port = listener
        .local_addr()
        .expect("failed to read HTTP server address")
        .port();

    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("HTTP accept failed");
        let mut request = Vec::new();
        let mut buf = [0u8; 512];

        loop {
            let n = stream.read(&mut buf).await.expect("HTTP read failed");
            if n == 0 {
                break;
            }
            request.extend_from_slice(&buf[..n]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }

        let request = String::from_utf8(request).expect("HTTP request was not UTF-8");
        assert!(
            request.starts_with("GET /demo HTTP/1.1\r\n"),
            "unexpected HTTP request: {request:?}"
        );
        assert!(
            request.contains("Host: example.test\r\n"),
            "HTTP request did not preserve Host header: {request:?}"
        );

        let body = "demo http response\n";
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("HTTP write failed");
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

fn parse_config(json: String) -> Arc<blackwire_config::schema::Config> {
    Arc::new(serde_json::from_str(&json).expect("config parse failed"))
}

fn server_config(vless_port: u16) -> Arc<blackwire_config::schema::Config> {
    parse_config(format!(
        r#"{{
            "inbounds": [
                {{
                    "tag": "vless-in",
                    "protocol": "vless",
                    "listen": "127.0.0.1",
                    "port": {vless_port},
                    "settings": {{
                        "clients": [
                            {{
                                "id": "{TEST_UUID}",
                                "email": "server-user@example.test"
                            }}
                        ]
                    }}
                }}
            ],
            "outbounds": [
                {{
                    "tag": "freedom",
                    "protocol": "freedom"
                }}
            ],
            "routing": {{
                "rules": [
                    {{
                        "outboundTag": "freedom"
                    }}
                ]
            }}
        }}"#
    ))
}

fn client_config(socks_port: u16, vless_port: u16) -> Arc<blackwire_config::schema::Config> {
    parse_config(format!(
        r#"{{
            "inbounds": [
                {{
                    "tag": "socks-in",
                    "protocol": "socks",
                    "listen": "127.0.0.1",
                    "port": {socks_port}
                }}
            ],
            "outbounds": [
                {{
                    "tag": "vless-out",
                    "protocol": "vless",
                    "settings": {{
                        "address": "127.0.0.1",
                        "port": {vless_port},
                        "users": [
                            {{
                                "id": "{TEST_UUID}",
                                "flow": ""
                            }}
                        ]
                    }}
                }}
            ],
            "routing": {{
                "rules": [
                    {{
                        "outboundTag": "vless-out"
                    }}
                ]
            }}
        }}"#
    ))
}

async fn start_client_server_chain() -> (blackwire_core::Instance, blackwire_core::Instance, u16) {
    let socks_port = unused_local_port();
    let vless_port = unused_local_port();

    let server = blackwire_core::Instance::from_config(server_config(vless_port))
        .await
        .expect("server proxy instance creation failed");
    let client = blackwire_core::Instance::from_config(client_config(socks_port, vless_port))
        .await
        .expect("client proxy instance creation failed");

    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    (server, client, socks_port)
}

#[tokio::test]
async fn e2e_socks5_to_vless_to_freedom_transfers_data() {
    let (echo_port, echo_task) = spawn_echo_server().await;
    let (_server, _client, socks_port) = start_client_server_chain().await;

    let mut stream = socks5_connect(socks_port, "127.0.0.1", echo_port).await;
    let payload = b"HELLO PHASE1";
    stream.write_all(payload).await.unwrap();

    let mut echoed = vec![0u8; payload.len()];
    stream.read_exact(&mut echoed).await.unwrap();

    assert_eq!(echoed, payload, "proxy chain did not echo the payload");

    echo_task.abort();
}

#[tokio::test]
async fn e2e_socks5_to_vless_to_freedom_transfers_http() {
    let (http_port, http_task) = spawn_http_server().await;
    let (_server, _client, socks_port) = start_client_server_chain().await;

    let mut stream = socks5_connect(socks_port, "127.0.0.1", http_port).await;
    stream
        .write_all(b"GET /demo HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    let response = String::from_utf8(response).expect("HTTP response was not UTF-8");

    assert!(
        response.starts_with("HTTP/1.1 200 OK\r\n"),
        "unexpected HTTP response: {response:?}"
    );
    assert!(
        response.contains("\r\n\r\ndemo http response\n"),
        "HTTP response body was not relayed: {response:?}"
    );

    http_task.abort();
}
