//! Integration tests for the Hysteria2 transport (protocol framing and Brutal CC).

use std::sync::Arc;
use std::time::Instant;

use blackwire_common::Address;
use blackwire_transport::hysteria2::auth::{verify_auth_request, AuthError};
use blackwire_transport::hysteria2::proto::{
    auth_response_from_headers, auth_response_to_headers, decode_tcp_request, decode_tcp_response,
    encode_tcp_request, encode_tcp_response, AuthResponse, TcpResponse, STATUS_AUTH_OK,
};
use blackwire_transport::hysteria2::tcp::{address_to_hysteria, hysteria_to_address};
use blackwire_transport::BrutalCCFactory;
use http::header::{HeaderName, HeaderValue};
use http::HeaderMap;

#[test]
fn auth_headers_accept_valid_password() {
    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static("hysteria-auth"),
        HeaderValue::from_static("testpassword"),
    );
    headers.insert(
        HeaderName::from_static("hysteria-cc-rx"),
        HeaderValue::from_static("6250000"),
    );
    let req = verify_auth_request(&headers, "testpassword").unwrap();
    assert_eq!(req.auth, "testpassword");
    assert_eq!(req.rx_bps, 6_250_000);
}

#[test]
fn auth_headers_reject_wrong_password() {
    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static("hysteria-auth"),
        HeaderValue::from_static("wrong"),
    );
    assert!(matches!(
        verify_auth_request(&headers, "expected"),
        Err(AuthError::WrongPassword)
    ));
}

#[test]
fn auth_response_headers_roundtrip() {
    let mut headers = HeaderMap::new();
    auth_response_to_headers(
        &mut headers,
        &AuthResponse {
            ok: true,
            udp_enabled: true,
            rx_bps: 12_500_000,
            rx_auto: false,
        },
    );
    let resp = auth_response_from_headers(&headers, STATUS_AUTH_OK);
    assert!(resp.ok);
    assert!(resp.udp_enabled);
    assert_eq!(resp.rx_bps, 12_500_000);
}

#[tokio::test]
async fn tcp_request_roundtrip_with_frame_type() {
    let addr = "example.com:443";
    let mut buf = Vec::new();
    encode_tcp_request(&mut buf, addr).await.unwrap();
    let mut cursor = std::io::Cursor::new(buf);
    let decoded = decode_tcp_request(&mut cursor).await.unwrap();
    assert_eq!(decoded.addr, addr);
}

#[tokio::test]
async fn tcp_response_roundtrip() {
    let resp = TcpResponse {
        ok: true,
        message: String::new(),
    };
    let mut buf = Vec::new();
    encode_tcp_response(&mut buf, &resp).await.unwrap();
    let mut cursor = std::io::Cursor::new(buf);
    let decoded = decode_tcp_response(&mut cursor).await.unwrap();
    assert_eq!(decoded, resp);
}

#[test]
fn hysteria_address_format_roundtrip() {
    let cases = [
        Address::Ipv4("1.2.3.4".parse().unwrap(), 443),
        Address::Ipv6("2001:db8::1".parse().unwrap(), 8080),
        Address::Domain("example.com".to_string(), 53),
    ];
    for addr in cases {
        let s = address_to_hysteria(&addr);
        let back = hysteria_to_address(&s).unwrap();
        assert_eq!(addr, back);
    }
}

#[test]
fn brutal_cc_factory_builds_controller_with_minimum_window() {
    use blackwire_transport::congestion::ControllerFactory;
    let factory = Arc::new(BrutalCCFactory::new(12_500_000));
    let ctrl = Arc::clone(&factory).build(Instant::now(), 1200);
    assert!(ctrl.window() >= 32 * 1024);
}

#[test]
fn brutal_cc_ignores_congestion_events() {
    use blackwire_transport::congestion::ControllerFactory;

    let factory = Arc::new(BrutalCCFactory::new(12_500_000));
    let mut ctrl = Arc::clone(&factory).build(Instant::now(), 1200);
    let window_before = ctrl.window();
    let now = Instant::now();
    ctrl.on_congestion_event(now, now, true, 1_000_000);
    assert_eq!(window_before, ctrl.window());
}

#[test]
fn dev_self_signed_produces_valid_pem() {
    let (cert_pem, key_pem) = blackwire_transport::dev_self_signed().unwrap();
    assert!(cert_pem.contains("BEGIN CERTIFICATE"));
    assert!(key_pem.contains("PRIVATE KEY"));
}
