use std::net::IpAddr;

use blackwire_config::schema::{Config, InboundConfig, LimitsConfig, LogConfig, OutboundConfig, Protocol};
use blackwire_core::{inbound_listener_changes, requires_instance_restart};

fn minimal_config(port: u16) -> Config {
    Config {
        log: LogConfig::default(),
        dns: None,
        routing: None,
        tun: None,
        limits: LimitsConfig::default(),
        inbounds: vec![InboundConfig {
            tag: "in".into(),
            listen: "127.0.0.1".parse::<IpAddr>().unwrap(),
            port,
            protocol: Protocol::Socks,
            settings: serde_json::json!({}),
            stream_settings: None,
            limits: None,
            sniffing: None,
        }],
        outbounds: vec![OutboundConfig {
            tag: "direct".into(),
            protocol: Protocol::Freedom,
            settings: serde_json::json!({}),
            stream_settings: None,
        }],
        stats: None,
        api: None,
        metrics_addr: None,
    }
}

#[test]
fn inbound_listener_changes_detects_port_change() {
    let old = minimal_config(1080);
    let new = minimal_config(1081);
    let changes = inbound_listener_changes(&old, &new);
    assert_eq!(changes, vec!["in".to_string()]);
}

#[test]
fn requires_instance_restart_ignores_vless_client_list_changes() {
    let mut old = minimal_config(1080);
    old.inbounds[0].protocol = Protocol::Vless;
    old.inbounds[0].settings = serde_json::json!({
        "clients": [{"id":"00000000-0000-4000-8000-000000000001"}]
    });

    let mut new = old.clone();
    new.inbounds[0].settings = serde_json::json!({
        "clients": [
            {"id":"00000000-0000-4000-8000-000000000001"},
            {"id":"00000000-0000-4000-8000-000000000002"}
        ]
    });

    assert!(!requires_instance_restart(&old, &new));
}

#[test]
fn requires_instance_restart_for_outbound_changes() {
    let old = minimal_config(1080);
    let mut new = minimal_config(1080);
    new.outbounds.push(OutboundConfig {
        tag: "backup".into(),
        protocol: Protocol::Freedom,
        settings: serde_json::json!({}),
        stream_settings: None,
    });

    assert!(requires_instance_restart(&old, &new));
}
