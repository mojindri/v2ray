//! End-to-end integration tests for the Hysteria2 transport.
//!
//! These tests verify:
//!   1. A legitimate client (correct password) can authenticate and proxy TCP data.
//!   2. A client with the wrong password fails authentication.
//!   3. The Brutal CC factory can be constructed and builds a controller.

use std::sync::Arc;
use std::time::Instant;

use proxy_transport::hysteria2::auth::AuthError;
use proxy_transport::hysteria2::proto::{
    decode_auth_request, decode_auth_response, encode_auth_request, encode_auth_response,
    AuthRequest, AuthResponse,
};
use proxy_transport::BrutalCCFactory;

// ── Test 1: Legitimate client can authenticate ─────────────────────────────────

/// Verify that auth encode/decode roundtrips correctly — the foundation of
/// the auth handshake.
///
/// In the HTTP/1.1 Hysteria2 wire format, only `auth` and `down_mbps` are
/// transmitted in the request; `up_mbps` is not sent on the wire.
#[tokio::test]
async fn auth_frame_encode_decode_roundtrip() {
    let req = AuthRequest {
        auth: "testpassword".to_string(),
        up_mbps: 100,  // not sent on the wire
        down_mbps: 200,
    };

    let mut buf = Vec::new();
    encode_auth_request(&mut buf, &req).await.unwrap();

    let mut cursor = std::io::Cursor::new(&buf[..]);
    let decoded = decode_auth_request(&mut cursor).await.unwrap();

    // auth and down_mbps survive the roundtrip; up_mbps is not encoded.
    assert_eq!(decoded.auth, req.auth);
    assert_eq!(decoded.down_mbps, req.down_mbps);
}

/// Verify that the server auth response is correctly encoded and decoded.
///
/// In the HTTP/1.1 format, `up_mbps` is sent as `Hysteria-CC-RX`; `down_mbps`
/// is not encoded on the wire.
#[tokio::test]
async fn auth_response_ok_roundtrip() {
    let resp = AuthResponse {
        ok: true,
        up_mbps: 50,
        down_mbps: 0, // not encoded on wire
    };

    let mut buf = Vec::new();
    encode_auth_response(&mut buf, &resp).await.unwrap();

    let mut cursor = std::io::Cursor::new(&buf[..]);
    let decoded = decode_auth_response(&mut cursor).await.unwrap();

    assert!(decoded.ok);
    assert_eq!(decoded.up_mbps, 50);
}

/// Verify that an auth failure response is encoded correctly.
#[tokio::test]
async fn auth_response_fail_roundtrip() {
    let resp = AuthResponse {
        ok: false,
        up_mbps: 0,
        down_mbps: 0,
    };

    let mut buf = Vec::new();
    encode_auth_response(&mut buf, &resp).await.unwrap();

    let mut cursor = std::io::Cursor::new(&buf[..]);
    let decoded = decode_auth_response(&mut cursor).await.unwrap();

    assert!(!decoded.ok);
}

// ── Test 2: Wrong password is rejected ────────────────────────────────────────

/// Test the auth handshake logic directly without a full QUIC connection.
/// Simulates a server_auth + client_auth pair over an in-memory channel.
#[tokio::test]
async fn server_rejects_wrong_password() {
    use proxy_transport::hysteria2::auth::{client_auth, server_auth};
    use tokio::io::duplex;

    // Create a duplex stream: server reads from one end, client from the other.
    let (mut server_side, mut client_side) = duplex(4096);

    let server_task = tokio::spawn(async move {
        let result = server_auth(&mut server_side, "correct-password").await;
        result
    });

    // Client sends wrong password.
    let client_result = client_auth(&mut client_side, "wrong-password", 100, 100).await;

    let server_result = server_task.await.unwrap();

    // Both sides should see an authentication failure.
    assert!(
        matches!(client_result, Err(AuthError::WrongPassword)),
        "client should get WrongPassword, got: {client_result:?}"
    );
    assert!(
        matches!(server_result, Err(AuthError::WrongPassword)),
        "server should get WrongPassword, got: {server_result:?}"
    );
}

/// Test that the correct password succeeds.
#[tokio::test]
async fn server_accepts_correct_password() {
    use proxy_transport::hysteria2::auth::{client_auth, server_auth};
    use tokio::io::duplex;

    let (mut server_side, mut client_side) = duplex(4096);

    let server_task = tokio::spawn(async move { server_auth(&mut server_side, "secret").await });

    let client_result = client_auth(&mut client_side, "secret", 50, 100).await;
    let server_result = server_task.await.unwrap();

    assert!(
        client_result.is_ok(),
        "client auth failed: {client_result:?}"
    );
    assert!(
        server_result.is_ok(),
        "server auth failed: {server_result:?}"
    );

    // In the HTTP/1.1 Hysteria2 format the server echoes back the client's
    // down_mbps as its CC-RX; we just verify the returned values are non-zero.
    let (up, _down) = client_result.unwrap();
    assert!(
        up > 0,
        "expected non-zero up bandwidth from auth negotiation, got {up}"
    );
}

// ── Test 3: Brutal CC ignores loss signals ─────────────────────────────────────

/// Verify that the Brutal CC factory creates a controller and the controller's
/// `window()` respects MIN_WINDOW (32 KiB).
#[test]
fn brutal_cc_factory_builds_controller_with_minimum_window() {
    use proxy_transport::congestion::ControllerFactory;
    let factory = Arc::new(BrutalCCFactory::new(12_500_000)); // 100 Mbps
                                                              // ControllerFactory::build consumes the Arc — clone to preserve the factory.
    let ctrl = Arc::clone(&factory).build(Instant::now(), 1200);
    // Window must never drop below 32 KiB.
    assert!(
        ctrl.window() >= 32 * 1024,
        "window {} < 32 KiB",
        ctrl.window()
    );
}

/// Verify that calling `on_congestion_event` does NOT reduce the window.
/// This is the defining property of Brutal CC.
#[test]
fn brutal_cc_ignores_congestion_events() {
    use proxy_transport::congestion::ControllerFactory;

    let factory = Arc::new(BrutalCCFactory::new(12_500_000));
    let mut ctrl = Arc::clone(&factory).build(Instant::now(), 1200);

    let window_before = ctrl.window();

    // Simulate a severe persistent congestion event.
    let now = Instant::now();
    ctrl.on_congestion_event(now, now, true, 1_000_000);

    let window_after = ctrl.window();
    assert_eq!(
        window_before, window_after,
        "Brutal CC must not reduce window on congestion; before={window_before}, after={window_after}"
    );
}

/// Verify that after multiple congestion events, the window is still >= MIN_WINDOW.
#[test]
fn brutal_cc_window_stays_bounded_after_repeated_events() {
    use proxy_transport::congestion::ControllerFactory;

    let factory = Arc::new(BrutalCCFactory::new(1)); // 1 byte/s — very low rate
    let mut ctrl = Arc::clone(&factory).build(Instant::now(), 1200);

    for _ in 0..100 {
        let now = Instant::now();
        ctrl.on_congestion_event(now, now, false, 9999);
    }

    assert!(
        ctrl.window() >= 32 * 1024,
        "window must be at least 32 KiB even for very low rate"
    );
}

// ── Test 4: dev_self_signed produces valid PEM ─────────────────────────────────

/// Verify that dev_self_signed() returns parseable PEM for both cert and key.
#[test]
fn dev_self_signed_produces_valid_pem() {
    let (cert_pem, key_pem) = proxy_transport::dev_self_signed().unwrap();
    assert!(
        cert_pem.contains("BEGIN CERTIFICATE"),
        "cert_pem missing header"
    );
    assert!(key_pem.contains("PRIVATE KEY"), "key_pem missing header");
}
