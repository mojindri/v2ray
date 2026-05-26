//! Sniffing parity tests (Xray destOverride semantics).

use blackwire_app::sniff::{analyze_peek, apply_dest_override, SniffResult};
use blackwire_common::Address;
use blackwire_config::schema::SniffingConfig;

#[test]
fn http_host_sniff_populates_domain() {
    let peek = b"GET / HTTP/1.1\r\nHost: sniffed.example\r\n\r\n";
    let cfg = SniffingConfig {
        enabled: true,
        dest_override: vec!["http".into()],
        ..Default::default()
    };
    let sniff = analyze_peek(peek, &cfg);
    assert_eq!(sniff.domain.as_deref(), Some("sniffed.example"));
    assert_eq!(sniff.protocol.as_deref(), Some("http"));
}

#[test]
fn dest_override_rewrites_ip_destination() {
    let cfg = SniffingConfig {
        enabled: true,
        dest_override: vec!["http".into(), "tls".into()],
        ..Default::default()
    };
    let sniff = SniffResult {
        protocol: Some("http".into()),
        domain: Some("sniffed.example".into()),
    };
    let ip = "198.18.0.10".parse().unwrap();
    let dest = apply_dest_override(Address::Ipv4(ip, 443), &sniff, &cfg);
    assert_eq!(dest, Address::Domain("sniffed.example".into(), 443));
}

#[test]
fn route_only_leaves_ip_destination_for_dial() {
    let cfg = SniffingConfig {
        enabled: true,
        route_only: true,
        dest_override: vec!["http".into()],
        ..Default::default()
    };
    let sniff = SniffResult {
        protocol: Some("http".into()),
        domain: Some("sniffed.example".into()),
    };
    let ip = "198.18.0.10".parse().unwrap();
    let dest = apply_dest_override(Address::Ipv4(ip, 443), &sniff, &cfg);
    assert_eq!(dest, Address::Ipv4(ip, 443));
}
