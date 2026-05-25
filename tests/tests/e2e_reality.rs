//! End-to-end integration test for the REALITY transport.
//!
//! # What this tests
//!
//! REALITY is an authentication layer on top of TLS. The client sends a
//! Chrome-fingerprinted TLS ClientHello with an encrypted token hidden in the
//! session_id field. The server validates this token using X25519 ECDH +
//! HKDF-SHA256 + AES-128-GCM, then either accepts the connection and completes
//! a local TLS handshake or silently forwards it to a fallback backend.
//!
//! This test verifies that:
//!   1. A legitimate client (correct X25519 key + short_id) can authenticate.
//!   2. After authentication, TLS 1.3 completes and data flows bidirectionally.
//!   3. An illegitimate client (wrong key) fails authentication and is forwarded
//!      to the fallback server.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use x25519_dalek::{PublicKey, StaticSecret};

use proxy_transport::reality::{
    complete_tls13_server_handshake, RealityClient, RealityClientConfig, RealityServer,
    RealityServerConfig,
};
use proxy_transport::Tls13Stream;

/// Bind to port 0 and return the assigned port.
/// This avoids port conflicts between concurrent tests.
async fn free_port() -> u16 {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Generate a fresh X25519 key pair for a test.
/// Returns (private_key_bytes, public_key_bytes).
fn gen_keypair() -> ([u8; 32], [u8; 32]) {
    let secret = StaticSecret::random();
    let public = PublicKey::from(&secret);
    (*secret.as_bytes(), *public.as_bytes())
}

/// A minimal fallback server that accepts one connection and echoes what it receives.
async fn start_fallback_echo(port: u16) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let mut buf = vec![0u8; 1024];
            if let Ok(n) = stream.read(&mut buf).await {
                let _ = stream.write_all(&buf[..n]).await;
            }
        }
    });
}

// Verify that a legitimate client can authenticate and exchange data with the server.
//
// This tests the full REALITY crypto pipeline:
//   client ECDH → HKDF → AES-128-GCM encrypt (client side)
//   server ECDH → HKDF → AES-128-GCM decrypt + validate (server side)
//   TLS completes and data flows over the authenticated channel
#[tokio::test(flavor = "multi_thread")]
async fn reality_legitimate_client_can_authenticate_and_exchange_data() {
    let (priv_bytes, pub_bytes) = gen_keypair();
    let short_id = vec![0xCA, 0xFE, 0xBA, 0xBE];

    let reality_port = free_port().await;
    let fallback_port = free_port().await;
    let reality_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, reality_port));
    let fallback_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, fallback_port));

    // Start a simple fallback server (needed even for the success path, though
    // it won't be used here).
    start_fallback_echo(fallback_port).await;

    // Build the REALITY server.
    let server = Arc::new(RealityServer::new(RealityServerConfig {
        private_key: priv_bytes,
        short_ids: vec![short_id.clone()],
        fallback: fallback_addr,
        max_time_diff: 120,
    }));

    // Spawn the server task: accept one connection, authenticate it, complete
    // the local TLS handshake, then echo data.
    let server_task = tokio::spawn(async move {
        let listener = TcpListener::bind(reality_addr).await.unwrap();
        let (tcp, _) = listener.accept().await.unwrap();

        let accepted = server
            .accept_with_key(Box::new(tcp))
            .await
            .expect("REALITY authentication should succeed for legitimate client");
        let mut raw_stream = accepted.stream;
        let app_keys = complete_tls13_server_handshake(
            &mut raw_stream,
            &accepted.auth_key,
            "www.microsoft.com",
        )
        .await
        .expect("TLS 1.3 should complete after REALITY authentication");
        let mut stream = Tls13Stream::new_server(raw_stream, app_keys);

        // Read the test payload from the client.
        let mut buf = vec![0u8; 64];
        let n = stream.read(&mut buf).await.unwrap();
        let received = String::from_utf8_lossy(&buf[..n]).to_string();

        // Echo it back.
        stream.write_all(received.as_bytes()).await.unwrap();
        received
    });

    // Give the server a moment to start listening.
    tokio::time::sleep(Duration::from_millis(20)).await;

    // Build the REALITY client and connect.
    let client = RealityClient::new(RealityClientConfig {
        server: reality_addr,
        server_public_key: pub_bytes,
        short_id,
        sni: "www.microsoft.com".to_string(),
        fingerprint: "chrome".to_string(),
    });

    let mut client_stream = tokio::time::timeout(Duration::from_secs(2), client.dial())
        .await
        .expect("REALITY dial timed out")
        .expect("REALITY dial should succeed");

    // Send a test message.
    let msg = b"REALITY integration test payload";
    tokio::time::timeout(Duration::from_secs(2), client_stream.write_all(msg))
        .await
        .expect("client write timed out")
        .unwrap();

    // Read the echo back.
    let mut buf = vec![0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(2), client_stream.read(&mut buf))
        .await
        .expect("client read timed out")
        .unwrap();
    let echoed = &buf[..n];

    assert_eq!(echoed, msg, "echoed data must match what was sent");

    // Verify the server received the same message.
    let server_received = tokio::time::timeout(Duration::from_secs(2), server_task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(server_received, "REALITY integration test payload");
}

// Verify that a client with the wrong server public key fails authentication
// and the connection is forwarded to the fallback.
//
// This simulates a GFW scanner or a misconfigured client trying to connect.
// The server silently proxies to the fallback so the prober gets back a
// realistic response and cannot tell this is a proxy server.
#[tokio::test(flavor = "multi_thread")]
async fn reality_wrong_key_triggers_fallback() {
    let (priv_bytes, _) = gen_keypair();
    let (_, wrong_pub_bytes) = gen_keypair(); // different key pair
    let short_id = vec![0xDE, 0xAD, 0xBE, 0xEF];

    let reality_port = free_port().await;
    let fallback_port = free_port().await;
    let reality_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, reality_port));
    let fallback_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, fallback_port));

    // The fallback server — the prober will get forwarded here.
    start_fallback_echo(fallback_port).await;

    let server = Arc::new(RealityServer::new(RealityServerConfig {
        private_key: priv_bytes,
        short_ids: vec![short_id.clone()],
        fallback: fallback_addr,
        max_time_diff: 120,
    }));

    let server_task = tokio::spawn(async move {
        let listener = TcpListener::bind(reality_addr).await.unwrap();
        let (tcp, _) = listener.accept().await.unwrap();
        // This should fail (fallback path) and return FallbackRequired error.
        let result = server.accept_direct(Box::new(tcp)).await;
        result.is_err() // expect an error (FallbackRequired)
    });

    tokio::time::sleep(Duration::from_millis(20)).await;

    // Client uses the WRONG server public key — ECDH will produce a different
    // shared secret, causing the AES-GCM decryption to fail on the server.
    let bad_client = RealityClient::new(RealityClientConfig {
        server: reality_addr,
        server_public_key: wrong_pub_bytes, // wrong!
        short_id,
        sni: "www.microsoft.com".to_string(),
        fingerprint: "chrome".to_string(),
    });

    // The client can always dial (it just sends bytes) — the failure is on the server.
    let _ = bad_client.dial().await;

    let fallback_triggered = tokio::time::timeout(Duration::from_secs(2), server_task)
        .await
        .unwrap()
        .unwrap();
    assert!(fallback_triggered, "wrong key must trigger fallback path");
}
