//! Production-readiness tests for proxy-core.
//!
//! Scope: instance lifecycle, config-to-handler wiring, routing validation,
//! task cancellation, and failure behavior. This deliberately avoids testing
//! protocol wire formats or transport adapters; those belong in proxy-protocol
//! and proxy-transport.
//!
//! These are deterministic non-fuzz tests. Some are intentionally strict and
//! may fail if proxy-core currently accepts ambiguous or unsafe config.

use std::sync::Arc;
use std::time::Duration;

use proxy_config::schema::Config;
use proxy_core::Instance;
use serde_json::{json, Value};
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout};

const SHORT: Duration = Duration::from_millis(400);

fn parse_config(value: Value) -> Config {
    serde_json::from_value(value).expect("test JSON must match proxy-config schema")
}

fn base_config(inbounds: Value, outbounds: Value) -> Config {
    parse_config(json!({
        "log": { "level": "warning" },
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": { "rules": [] }
    }))
}

fn freedom_outbound(tag: &str) -> Value {
    json!({
        "tag": tag,
        "protocol": "freedom",
        "settings": {}
    })
}

fn socks_inbound(tag: &str, listen: &str, port: u16) -> Value {
    json!({
        "tag": tag,
        "listen": listen,
        "port": port,
        "protocol": "socks",
        "settings": {}
    })
}

fn http_inbound(tag: &str, listen: &str, port: u16) -> Value {
    json!({
        "tag": tag,
        "listen": listen,
        "port": port,
        "protocol": "http",
        "settings": {}
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Lifecycle / task ownership
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn instance_starts_plain_socks_on_ephemeral_port_and_drop_aborts_tasks() {
    let cfg = base_config(
        json!([socks_inbound("socks-in", "127.0.0.1", 0)]),
        json!([freedom_outbound("direct")]),
    );

    let instance = timeout(SHORT, Instance::from_config(Arc::new(cfg)))
        .await
        .expect("from_config timed out")
        .expect("plain SOCKS instance should start");

    drop(instance);

    // Give Tokio a tick to run abort cleanup. This test mainly catches panics
    // in Drop and listener task ownership mistakes.
    sleep(Duration::from_millis(25)).await;
}

#[tokio::test]
async fn instance_wait_returns_after_drop_is_not_required_for_cleanup() {
    let cfg = base_config(
        json!([http_inbound("http-in", "127.0.0.1", 0)]),
        json!([freedom_outbound("direct")]),
    );

    let instance = Instance::from_config(Arc::new(cfg)).await.unwrap();
    drop(instance);
    sleep(Duration::from_millis(25)).await;
}

#[tokio::test]
async fn instance_rejects_invalid_listen_address_before_spawning_listener() {
    let bad = serde_json::from_value::<Config>(json!({
        "log": { "level": "warning" },
        "inbounds": [socks_inbound("bad-listen", "not an ip", 1080)],
        "outbounds": [freedom_outbound("direct")],
        "routing": { "rules": [] }
    }));

    assert!(
        bad.is_err(),
        "config schema should reject invalid listen addresses before startup"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Outbound builder validation
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn vless_outbound_requires_address_port_and_user_id() {
    let cases = [
        json!({ "tag": "vless", "protocol": "vless", "settings": { "port": 443, "users": [{"id":"00000000-0000-4000-8000-000000000001"}] } }),
        json!({ "tag": "vless", "protocol": "vless", "settings": { "address": "127.0.0.1", "users": [{"id":"00000000-0000-4000-8000-000000000001"}] } }),
        json!({ "tag": "vless", "protocol": "vless", "settings": { "address": "127.0.0.1", "port": 443, "users": [{}] } }),
    ];

    for outbound in cases {
        let cfg = base_config(json!([]), json!([outbound]));
        assert!(
            Instance::from_config(Arc::new(cfg)).await.is_err(),
            "malformed VLESS outbound was accepted"
        );
    }
}

#[tokio::test]
async fn vmess_outbound_requires_address_port_and_user_id() {
    let cases = [
        json!({ "tag": "vmess", "protocol": "vmess", "settings": { "port": 443, "users": [{"id":"00000000-0000-4000-8000-000000000001"}] } }),
        json!({ "tag": "vmess", "protocol": "vmess", "settings": { "address": "127.0.0.1", "users": [{"id":"00000000-0000-4000-8000-000000000001"}] } }),
        json!({ "tag": "vmess", "protocol": "vmess", "settings": { "address": "127.0.0.1", "port": 443, "users": [{}] } }),
    ];

    for outbound in cases {
        let cfg = base_config(json!([]), json!([outbound]));
        assert!(
            Instance::from_config(Arc::new(cfg)).await.is_err(),
            "malformed VMess outbound was accepted"
        );
    }
}

#[tokio::test]
async fn trojan_outbound_requires_address_port_and_password() {
    let cases = [
        json!({ "tag": "trojan", "protocol": "trojan", "settings": { "port": 443, "password": "pw" } }),
        json!({ "tag": "trojan", "protocol": "trojan", "settings": { "address": "127.0.0.1", "password": "pw" } }),
        json!({ "tag": "trojan", "protocol": "trojan", "settings": { "address": "127.0.0.1", "port": 443 } }),
    ];

    for outbound in cases {
        let cfg = base_config(json!([]), json!([outbound]));
        assert!(
            Instance::from_config(Arc::new(cfg)).await.is_err(),
            "malformed Trojan outbound was accepted"
        );
    }
}

#[tokio::test]
async fn ss2022_outbound_requires_address_port_and_password() {
    let cases = [
        json!({ "tag": "ss", "protocol": "shadowsocks", "settings": { "port": 8388, "password": "pw" } }),
        json!({ "tag": "ss", "protocol": "shadowsocks", "settings": { "address": "127.0.0.1", "password": "pw" } }),
        json!({ "tag": "ss", "protocol": "shadowsocks", "settings": { "address": "127.0.0.1", "port": 8388 } }),
    ];

    for outbound in cases {
        let cfg = base_config(json!([]), json!([outbound]));
        assert!(
            Instance::from_config(Arc::new(cfg)).await.is_err(),
            "malformed SS-2022 outbound was accepted"
        );
    }
}

#[tokio::test]
async fn outbounds_reject_invalid_uuid_strings() {
    for protocol in ["vless", "vmess"] {
        let cfg = base_config(
            json!([]),
            json!([{
                "tag": protocol,
                "protocol": protocol,
                "settings": {
                    "address": "127.0.0.1",
                    "port": 443,
                    "users": [{ "id": "not-a-uuid" }]
                }
            }]),
        );

        assert!(
            Instance::from_config(Arc::new(cfg)).await.is_err(),
            "{protocol} outbound accepted invalid UUID"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Inbound builder validation
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn vless_inbound_rejects_client_missing_id() {
    let cfg = base_config(
        json!([{
            "tag": "vless-in",
            "listen": "127.0.0.1",
            "port": 0,
            "protocol": "vless",
            "settings": { "clients": [{ "email": "a@example.com" }] }
        }]),
        json!([freedom_outbound("direct")]),
    );

    assert!(Instance::from_config(Arc::new(cfg)).await.is_err());
}

#[tokio::test]
async fn vmess_inbound_rejects_client_missing_id() {
    let cfg = base_config(
        json!([{
            "tag": "vmess-in",
            "listen": "127.0.0.1",
            "port": 0,
            "protocol": "vmess",
            "settings": { "clients": [{ "email": "a@example.com" }] }
        }]),
        json!([freedom_outbound("direct")]),
    );

    assert!(Instance::from_config(Arc::new(cfg)).await.is_err());
}

#[tokio::test]
async fn trojan_inbound_requires_non_empty_clients_with_passwords() {
    let cases = [
        json!({ "clients": [] }),
        json!({ "clients": [{}] }),
        json!({}),
    ];

    for settings in cases {
        let cfg = base_config(
            json!([{
                "tag": "trojan-in",
                "listen": "127.0.0.1",
                "port": 0,
                "protocol": "trojan",
                "settings": settings
            }]),
            json!([freedom_outbound("direct")]),
        );

        assert!(
            Instance::from_config(Arc::new(cfg)).await.is_err(),
            "malformed Trojan inbound was accepted"
        );
    }
}

#[tokio::test]
async fn ss2022_inbound_requires_password() {
    let cfg = base_config(
        json!([{
            "tag": "ss-in",
            "listen": "127.0.0.1",
            "port": 0,
            "protocol": "shadowsocks",
            "settings": {}
        }]),
        json!([freedom_outbound("direct")]),
    );

    assert!(Instance::from_config(Arc::new(cfg)).await.is_err());
}

// ─────────────────────────────────────────────────────────────────────────────
// Transport wrapper config validation owned by core glue
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn tls_inbound_requires_tls_settings_with_non_empty_cert_and_key_paths() {
    let cases = [
        json!({ "security": "tls", "network": "tcp" }),
        json!({ "security": "tls", "network": "tcp", "tlsSettings": { "certificateFile": "", "keyFile": "" } }),
    ];

    for stream_settings in cases {
        let cfg = base_config(
            json!([{
                "tag": "socks-tls",
                "listen": "127.0.0.1",
                "port": 0,
                "protocol": "socks",
                "settings": {},
                "streamSettings": stream_settings
            }]),
            json!([freedom_outbound("direct")]),
        );

        assert!(
            Instance::from_config(Arc::new(cfg)).await.is_err(),
            "TLS inbound with missing cert/key was accepted"
        );
    }
}

#[tokio::test]
async fn tls_inbound_rejects_nonexistent_cert_or_key_path() {
    let cfg = base_config(
        json!([{
            "tag": "socks-tls",
            "listen": "127.0.0.1",
            "port": 0,
            "protocol": "socks",
            "settings": {},
            "streamSettings": {
                "security": "tls",
                "network": "tcp",
                "tlsSettings": {
                    "certificateFile": "/definitely/not/here/cert.pem",
                    "keyFile": "/definitely/not/here/key.pem"
                }
            }
        }]),
        json!([freedom_outbound("direct")]),
    );

    let err = Instance::from_config(Arc::new(cfg)).await.unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("cannot read cert file") || msg.contains("cannot read key file"),
        "unexpected error: {msg}"
    );
}

#[tokio::test]
async fn reality_inbound_requires_complete_reality_settings() {
    let cfg = base_config(
        json!([{
            "tag": "vless-reality",
            "listen": "127.0.0.1",
            "port": 0,
            "protocol": "vless",
            "settings": {
                "clients": [{ "id": "00000000-0000-4000-8000-000000000001" }]
            },
            "streamSettings": {
                "security": "reality",
                "network": "tcp"
            }
        }]),
        json!([freedom_outbound("direct")]),
    );

    assert!(Instance::from_config(Arc::new(cfg)).await.is_err());
}

#[tokio::test]
async fn reality_inbound_rejects_invalid_private_key_and_empty_short_ids() {
    let cases = [
        json!({
            "dest": "127.0.0.1:443",
            "privateKey": "not-hex",
            "shortIds": ["00"],
            "maxTimeDiff": 30
        }),
        json!({
            "dest": "127.0.0.1:443",
            "privateKey": "1111111111111111111111111111111111111111111111111111111111111111",
            "shortIds": [],
            "maxTimeDiff": 30
        }),
    ];

    for reality_settings in cases {
        let cfg = base_config(
            json!([{
                "tag": "vless-reality",
                "listen": "127.0.0.1",
                "port": 0,
                "protocol": "vless",
                "settings": {
                    "clients": [{ "id": "00000000-0000-4000-8000-000000000001" }]
                },
                "streamSettings": {
                    "security": "reality",
                    "network": "tcp",
                    "realitySettings": reality_settings
                }
            }]),
            json!([freedom_outbound("direct")]),
        );

        assert!(
            Instance::from_config(Arc::new(cfg)).await.is_err(),
            "invalid REALITY inbound settings were accepted"
        );
    }
}

#[tokio::test]
async fn shadowtls_requires_complete_settings() {
    let cfg = base_config(
        json!([]),
        json!([{
            "tag": "vless-shadowtls",
            "protocol": "vless",
            "settings": {
                "address": "127.0.0.1",
                "port": 443,
                "users": [{ "id": "00000000-0000-4000-8000-000000000001" }]
            },
            "streamSettings": {
                "security": "shadowtls"
            }
        }]),
    );

    assert!(Instance::from_config(Arc::new(cfg)).await.is_err());
}

#[tokio::test]
async fn mkcp_rejects_invalid_header_instead_of_plain_tcp_fallback() {
    let cfg = base_config(
        json!([]),
        json!([{
            "tag": "vless-kcp",
            "protocol": "vless",
            "settings": {
                "address": "127.0.0.1",
                "port": 443,
                "users": [{ "id": "00000000-0000-4000-8000-000000000001" }]
            },
            "streamSettings": {
                "network": "kcp",
                "kcpSettings": {
                    "header": "bogus"
                }
            }
        }]),
    );

    assert!(Instance::from_config(Arc::new(cfg)).await.is_err());
}

/// Regression guard: the TUN runtime is now implemented. `from_config` must
/// no longer return the old "not production-ready" bail message.
///
/// On a non-root host the call will fail at OS-level device creation; on
/// a privileged Linux host it may succeed and start the runtime. Either
/// outcome is acceptable — what's NOT acceptable is the old placeholder error.
#[tokio::test]
async fn tun_config_is_no_longer_blocked_by_placeholder_guard() {
    let cfg = parse_config(json!({
        "log": { "level": "warning" },
        "tun": {
            "name": "proxy-tun",
            "address": "198.18.0.1",
            "netmask": "255.255.0.0",
            "mtu": 1500
        },
        "inbounds": [],
        "outbounds": [freedom_outbound("direct")],
        "routing": { "rules": [] }
    }));

    match Instance::from_config(Arc::new(cfg)).await {
        Ok(_instance) => {
            // root on Linux — runtime actually started, that's fine
        }
        Err(e) => {
            let msg = e.to_string();
            assert!(
                !msg.contains("privileged device loop and TCP stream reassembly"),
                "TUN placeholder guard is still active; the runtime should now be \
                 implemented. Got: {msg}"
            );
            // Expected: a real OS-level error (device creation, permissions, …)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Routing validation production gates
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn routing_rule_referencing_missing_outbound_tag_must_be_rejected() {
    let mut cfg_json = json!({
        "log": { "level": "warning" },
        "inbounds": [],
        "outbounds": [freedom_outbound("direct")],
        "routing": {
            "rules": [{
                "type": "field",
                "domain": ["domain:example.com"],
                "outboundTag": "missing-outbound"
            }]
        }
    });

    let cfg = parse_config(cfg_json.take());
    let result = Instance::from_config(Arc::new(cfg)).await;

    assert!(
        result.is_err(),
        "routing rule with missing outboundTag was accepted; this is production-dangerous"
    );
}

#[tokio::test]
async fn routing_rule_rejects_reversed_port_range() {
    let cfg = parse_config(json!({
        "log": { "level": "warning" },
        "inbounds": [],
        "outbounds": [freedom_outbound("direct")],
        "routing": {
            "rules": [{
                "type": "field",
                "port": "9000-8000",
                "outboundTag": "direct"
            }]
        }
    }));

    let result = Instance::from_config(Arc::new(cfg)).await;

    assert!(
        result.is_err(),
        "reversed port range 9000-8000 was accepted"
    );
}

#[tokio::test]
async fn routing_rule_rejects_invalid_cidr() {
    let cfg = parse_config(json!({
        "log": { "level": "warning" },
        "inbounds": [],
        "outbounds": [freedom_outbound("direct")],
        "routing": {
            "rules": [{
                "type": "field",
                "ip": ["999.999.999.999/99"],
                "outboundTag": "direct"
            }]
        }
    }));

    assert!(Instance::from_config(Arc::new(cfg)).await.is_err());
}

#[tokio::test]
async fn routing_rule_rejects_invalid_regex() {
    let cfg = parse_config(json!({
        "log": { "level": "warning" },
        "inbounds": [],
        "outbounds": [freedom_outbound("direct")],
        "routing": {
            "rules": [{
                "type": "field",
                "domain": ["regexp:[unclosed"],
                "outboundTag": "direct"
            }]
        }
    }));

    assert!(Instance::from_config(Arc::new(cfg)).await.is_err());
}

#[tokio::test]
async fn routing_rule_can_target_registered_balancer() {
    let cfg = parse_config(json!({
        "log": { "level": "warning" },
        "inbounds": [],
        "outbounds": [
            freedom_outbound("direct-a"),
            freedom_outbound("direct-b")
        ],
        "routing": {
            "balancers": [{
                "tag": "auto",
                "selector": ["direct-a", "direct-b"],
                "strategy": "roundRobin"
            }],
            "rules": [{
                "type": "field",
                "domain": ["domain:example.com"],
                "outboundTag": "auto"
            }]
        }
    }));

    let instance = Instance::from_config(Arc::new(cfg))
        .await
        .expect("balancer should be registered before routing rules are compiled");
    drop(instance);
}

#[tokio::test]
async fn balancer_rejects_missing_selector_outbound() {
    let cfg = parse_config(json!({
        "log": { "level": "warning" },
        "inbounds": [],
        "outbounds": [freedom_outbound("direct")],
        "routing": {
            "balancers": [{
                "tag": "auto",
                "selector": ["missing"]
            }],
            "rules": []
        }
    }));

    assert!(Instance::from_config(Arc::new(cfg)).await.is_err());
}

#[tokio::test]
async fn balancer_rejects_unsupported_health_check_scheme() {
    let cfg = parse_config(json!({
        "log": { "level": "warning" },
        "inbounds": [],
        "outbounds": [freedom_outbound("direct")],
        "routing": {
            "balancers": [{
                "tag": "auto",
                "selector": ["direct"],
                "health_check": {
                    "url": "https://example.com/generate_204"
                }
            }],
            "rules": []
        }
    }));

    assert!(Instance::from_config(Arc::new(cfg)).await.is_err());
}

#[tokio::test]
async fn routing_geo_database_paths_are_loaded_nonfatally_when_missing() {
    let cfg = parse_config(json!({
        "log": { "level": "warning" },
        "inbounds": [],
        "outbounds": [freedom_outbound("direct")],
        "routing": {
            "geoipFile": "/definitely/not/here/geoip.dat",
            "geositeFile": "/definitely/not/here/geosite.dat",
            "rules": [{
                "type": "field",
                "ip": ["geoip:CN"],
                "outboundTag": "direct"
            }, {
                "type": "field",
                "domain": ["geosite:GOOGLE"],
                "outboundTag": "direct"
            }]
        }
    }));

    let instance = Instance::from_config(Arc::new(cfg))
        .await
        .expect("missing geo DB files should warn and degrade, not fail startup");
    drop(instance);
}

#[tokio::test]
async fn dns_fakeip_rejects_invalid_pool_at_startup() {
    let cfg = parse_config(json!({
        "log": { "level": "warning" },
        "dns": {
            "fake_ip": {
                "enabled": true,
                "pool": "not-a-cidr"
            }
        },
        "inbounds": [],
        "outbounds": [freedom_outbound("direct")],
        "routing": { "rules": [] }
    }));

    assert!(Instance::from_config(Arc::new(cfg)).await.is_err());
}

// ─────────────────────────────────────────────────────────────────────────────
// Metrics server failure policy
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn metrics_bind_failure_should_be_visible_not_silent() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let occupied = listener.local_addr().unwrap();

    let cfg = parse_config(json!({
        "log": { "level": "warning" },
        "metricsAddr": occupied.to_string(),
        "inbounds": [],
        "outbounds": [freedom_outbound("direct")],
        "routing": { "rules": [] }
    }));

    let result = Instance::from_config(Arc::new(cfg)).await;

    assert!(
        result.is_err(),
        "metrics server bind failure was silently ignored; production startup should fail or expose degraded state"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Port collision / listener startup behavior
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn listener_bind_failure_should_be_visible_to_startup() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let occupied = listener.local_addr().unwrap();

    let cfg = base_config(
        json!([socks_inbound(
            "socks-in",
            &occupied.ip().to_string(),
            occupied.port()
        )]),
        json!([freedom_outbound("direct")]),
    );

    assert!(
        Instance::from_config(Arc::new(cfg)).await.is_err(),
        "occupied inbound port should fail startup immediately"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Basic smoke: a started listener should at least accept TCP
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn plain_socks_listener_accepts_tcp_before_drop() {
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);

    let cfg = base_config(
        json!([socks_inbound(
            "socks-in",
            &addr.ip().to_string(),
            addr.port()
        )]),
        json!([freedom_outbound("direct")]),
    );

    let instance = Instance::from_config(Arc::new(cfg)).await.unwrap();

    let connect_result = timeout(SHORT, TcpStream::connect(addr)).await;
    drop(instance);

    assert!(
        connect_result.is_ok() && connect_result.unwrap().is_ok(),
        "listener did not accept TCP on configured address"
    );
}
