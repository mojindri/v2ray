//! End-to-end tests for HTTP CONNECT inbound + Freedom outbound.
//!
//! These tests verify that the HTTP CONNECT inbound correctly:
//! - Parses CONNECT requests and tunnels traffic to the destination.
//! - Responds with "200 Connection established".
//! - Handles IPv4, domain name, and malformed requests.
//!
//! Test topology:
//!
//!   Test client
//!       → HTTP CONNECT inbound on proxy
//!       → Freedom outbound (direct TCP)
//!       → TCP echo server / HTTP server

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

// ── Helpers ───────────────────────────────────────────────────────────────────

fn unused_local_port() -> u16 {
    let l = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    l.local_addr().unwrap().port()
}

fn parse_config(json: String) -> Arc<blackwire_config::schema::Config> {
    Arc::new(serde_json::from_str(&json).expect("config parse failed"))
}

async fn spawn_echo_server() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    spawn_echo_task(listener)
}

async fn spawn_localhost_echo_server() -> (u16, tokio::task::JoinHandle<()>) {
    // Bind through the same resolver path used by the domain test. On some
    // systems `localhost` resolves to IPv6 before IPv4.
    let listener = TcpListener::bind(("localhost", 0)).await.unwrap();
    spawn_echo_task(listener)
}

fn spawn_echo_task(listener: TcpListener) -> (u16, tokio::task::JoinHandle<()>) {
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 4096];
        loop {
            let n = stream.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            stream.write_all(&buf[..n]).await.unwrap();
        }
    });
    (port, task)
}

fn http_connect_config(proxy_port: u16) -> Arc<blackwire_config::schema::Config> {
    parse_config(format!(
        r#"{{
            "inbounds": [{{
                "tag": "http-in",
                "protocol": "http",
                "listen": "127.0.0.1",
                "port": {proxy_port}
            }}],
            "outbounds": [{{
                "tag": "freedom",
                "protocol": "freedom"
            }}]
        }}"#
    ))
}

/// Send an HTTP CONNECT request and read the 200 response.
async fn http_connect(
    proxy_port: u16,
    target_host: &str,
    target_port: u16,
) -> tokio::net::TcpStream {
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", proxy_port))
        .await
        .unwrap();

    let req = format!(
        "CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}:{target_port}\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).await.unwrap();

    // Read until the blank line after headers.
    let mut response = Vec::new();
    let mut buf = [0u8; 1];
    loop {
        stream.read_exact(&mut buf).await.unwrap();
        response.push(buf[0]);
        if response.ends_with(b"\r\n\r\n") {
            break;
        }
        if response.len() > 512 {
            panic!(
                "response too long: {:?}",
                String::from_utf8_lossy(&response)
            );
        }
    }

    let resp_str = String::from_utf8_lossy(&response);
    assert!(
        resp_str.starts_with("HTTP/1.1 200"),
        "unexpected CONNECT response: {resp_str:?}"
    );

    stream
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// CONNECT to an IPv4 echo server, verify data flows through.
#[tokio::test]
async fn http_connect_ipv4_echo_roundtrip() {
    let (echo_port, echo_task) = spawn_echo_server().await;
    let proxy_port = unused_local_port();

    let _proxy = blackwire_core::Instance::from_config(http_connect_config(proxy_port))
        .await
        .unwrap();
    tokio::time::sleep(tokio::time::Duration::from_millis(30)).await;

    let mut stream = http_connect(proxy_port, "127.0.0.1", echo_port).await;

    let payload = b"hello http connect";
    stream.write_all(payload).await.unwrap();

    let mut got = vec![0u8; payload.len()];
    stream.read_exact(&mut got).await.unwrap();
    assert_eq!(got, payload);

    echo_task.abort();
}

/// CONNECT with a domain name resolves and forwards correctly.
#[tokio::test]
async fn http_connect_domain_echo_roundtrip() {
    let (echo_port, echo_task) = spawn_localhost_echo_server().await;
    let proxy_port = unused_local_port();

    let _proxy = blackwire_core::Instance::from_config(http_connect_config(proxy_port))
        .await
        .unwrap();
    tokio::time::sleep(tokio::time::Duration::from_millis(30)).await;

    let mut stream = http_connect(proxy_port, "localhost", echo_port).await;

    let payload = b"domain connect test";
    stream.write_all(payload).await.unwrap();

    let mut got = vec![0u8; payload.len()];
    stream.read_exact(&mut got).await.unwrap();
    assert_eq!(got, payload);

    echo_task.abort();
}

/// Multiple sequential requests over the same proxy instance.
#[tokio::test]
async fn http_connect_sequential_requests() {
    let proxy_port = unused_local_port();

    let _proxy = blackwire_core::Instance::from_config(http_connect_config(proxy_port))
        .await
        .unwrap();
    tokio::time::sleep(tokio::time::Duration::from_millis(30)).await;

    for i in 0u8..3 {
        let (echo_port, echo_task) = spawn_echo_server().await;
        let mut stream = http_connect(proxy_port, "127.0.0.1", echo_port).await;

        let payload = vec![i; 16];
        stream.write_all(&payload).await.unwrap();
        let mut got = vec![0u8; 16];
        stream.read_exact(&mut got).await.unwrap();
        assert_eq!(got, payload);
        echo_task.abort();
    }
}

/// Large payload flows through the CONNECT tunnel without corruption.
#[tokio::test]
async fn http_connect_large_payload() {
    let (echo_port, echo_task) = spawn_echo_server().await;
    let proxy_port = unused_local_port();

    let _proxy = blackwire_core::Instance::from_config(http_connect_config(proxy_port))
        .await
        .unwrap();
    tokio::time::sleep(tokio::time::Duration::from_millis(30)).await;

    let mut stream = http_connect(proxy_port, "127.0.0.1", echo_port).await;

    let payload = vec![0x42u8; 8192];
    stream.write_all(&payload).await.unwrap();

    let mut got = vec![0u8; payload.len()];
    stream.read_exact(&mut got).await.unwrap();
    assert_eq!(got, payload);

    echo_task.abort();
}

/// A GET method should be rejected by the HTTP CONNECT parser.
#[tokio::test]
async fn http_connect_wrong_method_rejected() {
    let proxy_port = unused_local_port();

    let _proxy = blackwire_core::Instance::from_config(http_connect_config(proxy_port))
        .await
        .unwrap();
    tokio::time::sleep(tokio::time::Duration::from_millis(30)).await;

    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", proxy_port))
        .await
        .unwrap();

    // Send a GET request instead of CONNECT.
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await
        .unwrap();

    // The proxy should close the connection (no 200 response).
    let mut buf = [0u8; 64];
    // Either we read nothing (connection closed) or an error response.
    let result = stream.read(&mut buf).await;
    // Connection should either close or return an error-like response (not 200).
    match result {
        Ok(0) => {} // connection closed — expected
        Ok(n) => {
            let resp = String::from_utf8_lossy(&buf[..n]);
            assert!(
                !resp.starts_with("HTTP/1.1 200"),
                "should not get 200 for GET: {resp}"
            );
        }
        Err(_) => {} // connection error — also acceptable
    }
}

// ── Unit-level tests for the HTTP CONNECT parser ──────────────────────────────

#[test]
fn parse_connect_ipv4_direct() {
    let result = blackwire_protocol::http_connect::parse_connect_request_sync(
        "CONNECT 1.2.3.4:443 HTTP/1.1",
    );
    assert!(result.is_ok());
    assert_eq!(
        result.unwrap(),
        blackwire_common::Address::Ipv4("1.2.3.4".parse().unwrap(), 443)
    );
}

#[test]
fn parse_connect_domain_direct() {
    let result = blackwire_protocol::http_connect::parse_connect_request_sync(
        "CONNECT example.com:8080 HTTP/1.1",
    );
    assert!(result.is_ok());
    assert_eq!(
        result.unwrap(),
        blackwire_common::Address::Domain("example.com".to_string(), 8080)
    );
}

#[test]
fn parse_connect_port_overflow_rejected() {
    let result = blackwire_protocol::http_connect::parse_connect_request_sync(
        "CONNECT example.com:99999 HTTP/1.1",
    );
    assert!(result.is_err());
}
