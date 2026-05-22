//! End-to-end test: SOCKS5 client → VLESS client proxy → VLESS server proxy → echo server.
//!
//! This test spins up the full Phase 1 proxy chain inside a single Tokio runtime:
//!
//!   Test TCP client
//!       │  (SOCKS5 CONNECT to 127.0.0.1:<echo_port>)
//!       ▼
//!   CLIENT instance (SOCKS5 inbound + VLESS outbound)
//!       │  (VLESS over TCP)
//!       ▼
//!   SERVER instance (VLESS inbound + Freedom outbound)
//!       │  (plain TCP)
//!       ▼
//!   Echo server (reads N bytes, writes them back)
//!
//! Why two Instance objects?
//!
//! A real deployment has two separate proxy-rs processes: one on the server
//! (VLESS inbound) and one on the client machine (SOCKS5 inbound, VLESS outbound).
//! Using two `Instance` objects in the same test runtime faithfully replicates
//! that topology.
//!
//! Why #[ignore]?
//!
//! The test binds to specific ports. To run it manually:
//!   cargo test -p integration-tests e2e -- --ignored --nocapture

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use proxy_config::schema::Config;
use proxy_core::Instance;

// ── Port selection ────────────────────────────────────────────────────────────

/// Ask the OS for a free TCP port by binding to port 0, then close the socket.
///
/// There is a small TOCTOU race between releasing the port and binding it again
/// in the proxy. For a local test this is negligible — the port stays available
/// for the next few milliseconds.
fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

// ── Echo server ───────────────────────────────────────────────────────────────

/// Start a TCP echo server that reads bytes and writes them back.
///
/// The server loops on one connection — it reads until EOF and echos everything.
/// Spawned as a background task; returns when the first connection closes.
async fn start_echo_server(port: u16) {
    let listener = TcpListener::bind(("127.0.0.1", port)).await
        .expect("echo server bind failed");

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else { break };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    let n = stream.read(&mut buf).await.unwrap_or(0);
                    if n == 0 { break; }
                    if stream.write_all(&buf[..n]).await.is_err() { break; }
                }
            });
        }
    });
}

// ── SOCKS5 client helper ──────────────────────────────────────────────────────

/// Connect to the SOCKS5 proxy and request a CONNECT to `dest_ip:dest_port`.
///
/// SOCKS5 wire format used here:
///   Greeting:  05 01 00                           (VER=5, NMETHODS=1, METHOD=NoAuth)
///   Reply:     05 00                              (VER=5, METHOD=NoAuth accepted)
///   Request:   05 01 00 01 <4-byte IPv4> <2-byte port>  (VER CMD RSV ATYP ADDR PORT)
///   Reply:     05 00 00 01 00 00 00 00 00 00       (success)
async fn socks5_connect_ipv4(proxy_port: u16, dest_ip: [u8; 4], dest_port: u16) -> TcpStream {
    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).await
        .expect("connect to socks5 proxy failed");

    // Greeting
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp, [5, 0], "SOCKS5 method negotiation failed: {resp:?}");

    // CONNECT request — IPv4 (ATYP=0x01)
    let mut req = vec![5u8, 1, 0, 1];   // VER CMD RSV ATYP
    req.extend_from_slice(&dest_ip);    // 4-byte IPv4
    req.extend_from_slice(&dest_port.to_be_bytes()); // PORT big-endian
    stream.write_all(&req).await.unwrap();

    // Reply — 10 bytes for IPv4 reply
    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0, "SOCKS5 CONNECT failed: REP={:#04x}", reply[1]);

    stream
}

// ── Config builders ───────────────────────────────────────────────────────────

/// Build the server-side config: VLESS inbound + Freedom outbound.
///
/// The server accepts VLESS connections from our client proxy and forwards
/// them to real destinations (in this test, to the local echo server).
fn server_config(vless_port: u16, uuid: &str) -> Arc<Config> {
    let json = format!(r#"{{
        "inbounds": [{{
            "tag":      "vless-in",
            "protocol": "vless",
            "listen":   "127.0.0.1",
            "port":     {vless_port},
            "settings": {{
                "clients": [{{"id": "{uuid}", "email": "test@e2e", "flow": ""}}]
            }}
        }}],
        "outbounds": [{{
            "tag":      "freedom",
            "protocol": "freedom"
        }}]
    }}"#);
    let cfg: Config = serde_json::from_str(&json).expect("server config parse failed");
    Arc::new(cfg)
}

/// Build the client-side config: SOCKS5 inbound + VLESS outbound.
///
/// The client accepts SOCKS5 from local apps and tunnels them via VLESS to
/// the server instance running on `vless_port`.
fn client_config(socks_port: u16, vless_port: u16, uuid: &str) -> Arc<Config> {
    let json = format!(r#"{{
        "inbounds": [{{
            "tag":      "socks-in",
            "protocol": "socks",
            "listen":   "127.0.0.1",
            "port":     {socks_port}
        }}],
        "outbounds": [{{
            "tag":      "vless-out",
            "protocol": "vless",
            "settings": {{
                "address": "127.0.0.1",
                "port":    {vless_port},
                "users":   [{{"id": "{uuid}", "flow": ""}}]
            }}
        }}]
    }}"#);
    let cfg: Config = serde_json::from_str(&json).expect("client config parse failed");
    Arc::new(cfg)
}

// ── The actual end-to-end test ────────────────────────────────────────────────

/// Full Phase 1 end-to-end test.
///
/// Data path:
///   test TCP client
///     → SOCKS5 on socks_port
///     → VLESS outbound to vless_port
///     → VLESS inbound
///     → Freedom outbound to echo_port
///     → echo server
///     → back the same way
///
/// Run manually with:
///   cargo test -p integration-tests e2e_socks5_to_vless_to_freedom -- --ignored --nocapture
#[tokio::test]
#[ignore = "binds to OS-allocated ports — run explicitly with --ignored"]
async fn e2e_socks5_to_vless_to_freedom() {
    // Choose free ports — the OS guarantees these are unused right now.
    let echo_port  = free_port();
    let vless_port = free_port();
    let socks_port = free_port();

    // The UUID that both server and client must agree on.
    const UUID: &str = "a3482e88-686a-4a58-8126-99c9df64b7bf";

    // 1. Start the echo server.
    start_echo_server(echo_port).await;

    // 2. Start the VLESS server instance.
    //    Holds the JoinHandle tasks alive until it is dropped.
    let _server = Instance::from_config(server_config(vless_port, UUID))
        .await
        .expect("server instance failed to start");

    // 3. Start the SOCKS5/VLESS client instance.
    let _client = Instance::from_config(client_config(socks_port, vless_port, UUID))
        .await
        .expect("client instance failed to start");

    // 4. Give listeners a moment to start accepting (they spawn immediately,
    //    but the OS accept loop needs one scheduler tick to become ready).
    tokio::time::sleep(Duration::from_millis(100)).await;

    // 5. Connect through the proxy chain to the echo server.
    let mut conn = socks5_connect_ipv4(socks_port, [127, 0, 0, 1], echo_port).await;

    // 6. Send a payload through the entire chain.
    let payload = b"Hello, VLESS proxy chain!";
    conn.write_all(payload).await.expect("write failed");

    // Shut down the write side so the echo server knows we are done sending.
    // Without this, `read_exact` on the reply would block forever because the
    // server is waiting for more data before echoing.
    conn.shutdown().await.expect("shutdown failed");

    // 7. Read the echoed reply — must match exactly what we sent.
    let mut reply = vec![0u8; payload.len()];
    conn.read_exact(&mut reply).await.expect("read failed");

    assert_eq!(reply, payload, "echo data mismatch — proxy chain corrupted the payload");

    println!(
        "✓ E2E test passed: {} bytes relayed through SOCKS5 → VLESS → Freedom",
        payload.len()
    );

    // _server and _client are dropped here — their JoinHandles are aborted,
    // which stops the listener tasks cleanly.
}

// ── Shorter smoke test (no #[ignore]) ─────────────────────────────────────────

/// Verify that two Instance objects can be built and started without panicking.
///
/// This does NOT send any traffic — it just checks that the config parsing and
/// listener startup succeed. It is fast enough to run in CI without the port
/// conflict risk of the full e2e test.
#[tokio::test]
async fn server_and_client_instances_start_successfully() {
    let vless_port = free_port();
    let socks_port = free_port();
    const UUID: &str = "b4593f99-797b-5b69-9237-aada10753cc0";

    let server = Instance::from_config(server_config(vless_port, UUID)).await;
    assert!(server.is_ok(), "server instance failed: {:?}", server.err());

    let client = Instance::from_config(client_config(socks_port, vless_port, UUID)).await;
    assert!(client.is_ok(), "client instance failed: {:?}", client.err());

    // Instances are dropped here — tasks are aborted.
}
