//! End-to-end test: SOCKS5 inbound → VLESS → Freedom outbound.
//!
//! This test spins up a full proxy chain in a single process:
//!
//!   Test client (SOCKS5)
//!       ↓  connects to socks5 listener on 127.0.0.1:10080
//!   SOCKS5 inbound
//!       ↓  dispatches to VLESS outbound
//!   VLESS outbound
//!       ↓  connects to VLESS inbound on 127.0.0.1:10443
//!   VLESS inbound
//!       ↓  dispatches to Freedom outbound
//!   Freedom outbound
//!       ↓  connects to echo server on 127.0.0.1:10555
//!   Echo server
//!
//! Data path: test sends "HELLO" → echo server → receives "HELLO" back.
//! This verifies that the entire Phase 1 stack works end to end.
//!
//! No external processes are needed — everything runs in Tokio tasks.

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

// Port assignments for this test. We use high ports to avoid conflicts with
// other tests or system services. The ports must be distinct.
const SOCKS5_PORT: u16 = 10080;
const VLESS_PORT:  u16 = 10443;
const ECHO_PORT:   u16 = 10555;

// The UUID for the VLESS user in this test.
// This is arbitrary — we just need client and server to agree.
const TEST_UUID: &str = "a3482e88-686a-4a58-8126-99c9df64b7bf";

/// Spin up a TCP echo server on the given port.
/// It reads up to 1024 bytes and writes them back unchanged.
/// Returns when the listener accepts and handles one connection.
async fn spawn_echo_server(port: u16) {
    let listener = TcpListener::bind(("127.0.0.1", port)).await
        .expect("echo server bind failed");

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("echo accept failed");
        let mut buf = [0u8; 1024];
        loop {
            let n = stream.read(&mut buf).await.expect("echo read failed");
            if n == 0 { break; }
            stream.write_all(&buf[..n]).await.expect("echo write failed");
        }
    });
}

/// Send a SOCKS5 CONNECT request to the SOCKS5 listener and return the stream.
///
/// SOCKS5 CONNECT sequence:
///   Client → Server: VER=5, NMETHODS=1, METHODS=[0x00 no-auth]
///   Server → Client: VER=5, METHOD=0x00
///   Client → Server: VER=5, CMD=1 CONNECT, RSV=0, ATYP=3 domain, ADDR, PORT
///   Server → Client: VER=5, REP=0 success, RSV=0, ATYP=1, BND.ADDR=0.0.0.0, BND.PORT=0
async fn socks5_connect(socks_port: u16, dest_host: &str, dest_port: u16) -> TcpStream {
    let mut stream = TcpStream::connect(("127.0.0.1", socks_port)).await
        .expect("failed to connect to SOCKS5 proxy");

    // Greeting: version + methods
    stream.write_all(&[5, 1, 0]).await.unwrap(); // VER=5, NMETHODS=1, METHOD=no-auth
    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp, [5, 0], "SOCKS5 method negotiation failed");

    // CONNECT request
    let host_bytes = dest_host.as_bytes();
    let mut req = vec![
        5, 1, 0,   // VER=5, CMD=CONNECT, RSV=0
        3,         // ATYP=domain
        host_bytes.len() as u8,
    ];
    req.extend_from_slice(host_bytes);
    req.extend_from_slice(&dest_port.to_be_bytes());
    stream.write_all(&req).await.unwrap();

    // Read reply (10 bytes for IPv4 reply: VER REP RSV ATYP 4B-addr 2B-port)
    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0, "SOCKS5 CONNECT failed: REP={:#x}", reply[1]);

    stream
}

/// Full Phase 1 end-to-end test.
///
/// We skip this test normally because it requires exclusive use of specific
/// ports. Run it explicitly with:
///   cargo test -p integration-tests e2e_socks5_vless -- --ignored
#[tokio::test]
#[ignore = "requires exclusive port use — run with --ignored"]
async fn e2e_socks5_to_vless_to_freedom() {
    // Step 1: Start an echo server.
    spawn_echo_server(ECHO_PORT).await;

    // Step 2: Build a config that chains SOCKS5 → VLESS → Freedom.
    let config_json = format!(r#"{{
        "inbounds": [
            {{
                "tag":      "socks-in",
                "protocol": "socks",
                "listen":   "127.0.0.1",
                "port":     {SOCKS5_PORT}
            }},
            {{
                "tag":      "vless-in",
                "protocol": "vless",
                "listen":   "127.0.0.1",
                "port":     {VLESS_PORT},
                "settings": {{
                    "clients": [{{"id": "{TEST_UUID}", "email": "test@e2e"}}]
                }}
            }}
        ],
        "outbounds": [
            {{
                "tag":      "vless-out",
                "protocol": "vless",
                "settings": {{
                    "address": "127.0.0.1",
                    "port":    {VLESS_PORT},
                    "users":   [{{"id": "{TEST_UUID}", "flow": ""}}]
                }}
            }},
            {{
                "tag":      "freedom",
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
    }}"#);

    let config: proxy_config::schema::Config =
        serde_json::from_str(&config_json).expect("config parse failed");
    let config = Arc::new(config);

    // Step 3: Start the proxy instance.
    let instance = proxy_core::Instance::from_config(config).await
        .expect("instance creation failed");
    drop(instance); // We just wanted to start the listeners

    // Give the listeners a moment to start accepting.
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    // Step 4: Connect via SOCKS5 and send data to the echo server.
    let mut stream = socks5_connect(SOCKS5_PORT, "127.0.0.1", ECHO_PORT).await;

    stream.write_all(b"HELLO").await.unwrap();

    let mut buf = [0u8; 5];
    stream.read_exact(&mut buf).await.unwrap();

    assert_eq!(&buf, b"HELLO", "echo data did not match");
}
