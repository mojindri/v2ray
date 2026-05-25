use std::sync::Arc;

use blackwire_config::schema::Config;
use blackwire_core::Instance;
use serde_json::{json, Value};

fn cfg(inbounds: Value, outbounds: Value, extra: Option<Value>) -> Config {
    let mut root = json!({
        "log": { "level": "warning" },
        "inbounds": inbounds,
        "outbounds": outbounds
    });
    if let Some(extra) = extra {
        if let Some(obj) = extra.as_object() {
            for (k, v) in obj {
                root[k] = v.clone();
            }
        }
    }
    serde_json::from_value(root).expect("config parse")
}

fn freedom(tag: &str) -> Value {
    json!({ "tag": tag, "protocol": "freedom" })
}

#[tokio::test]
async fn empty_vless_clients_must_fail_startup() {
    let c = cfg(
        json!([{
            "tag":"vless-in","protocol":"vless","listen":"127.0.0.1","port":0,
            "settings":{"clients":[]}
        }]),
        json!([freedom("direct")]),
        None,
    );
    assert!(Instance::from_config(Arc::new(c)).await.is_err());
}

#[tokio::test]
async fn empty_vmess_clients_must_fail_startup() {
    let c = cfg(
        json!([{
            "tag":"vmess-in","protocol":"vmess","listen":"127.0.0.1","port":0,
            "settings":{"clients":[]}
        }]),
        json!([freedom("direct")]),
        None,
    );
    assert!(Instance::from_config(Arc::new(c)).await.is_err());
}

#[tokio::test]
async fn empty_hysteria2_auth_must_fail_startup() {
    let c = cfg(
        json!([{
            "tag":"hy2-in","protocol":"hysteria2","listen":"127.0.0.1","port":0,
            "settings":{"auth":""},
            "streamSettings":{"security":"tls","network":"tcp","tlsSettings":{"certificateFile":"","keyFile":""}}
        }]),
        json!([freedom("direct")]),
        None,
    );
    assert!(Instance::from_config(Arc::new(c)).await.is_err());
}

#[tokio::test]
async fn missing_tls_cert_key_must_fail_startup() {
    let c = cfg(
        json!([{
            "tag":"socks-tls","protocol":"socks","listen":"127.0.0.1","port":0,
            "streamSettings":{"security":"tls","network":"tcp","tlsSettings":{"certificateFile":"","keyFile":""}}
        }]),
        json!([freedom("direct")]),
        None,
    );
    assert!(Instance::from_config(Arc::new(c)).await.is_err());
}

#[tokio::test]
async fn invalid_tls_key_material_must_fail_startup() {
    let cert = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";
    let key = "-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n-----END PRIVATE KEY-----\n";
    let cert_path =
        std::env::temp_dir().join(format!("fail-closed-cert-{}-{}.pem", std::process::id(), 1));
    let key_path =
        std::env::temp_dir().join(format!("fail-closed-key-{}-{}.pem", std::process::id(), 1));
    std::fs::write(&cert_path, cert).expect("write cert");
    std::fs::write(&key_path, key).expect("write key");

    let c = cfg(
        json!([{
            "tag":"socks-tls","protocol":"socks","listen":"127.0.0.1","port":0,
            "streamSettings":{"security":"tls","network":"tcp","tlsSettings":{
                "certificateFile": cert_path.to_string_lossy(),
                "keyFile": key_path.to_string_lossy()
            }}
        }]),
        json!([freedom("direct")]),
        None,
    );
    assert!(Instance::from_config(Arc::new(c)).await.is_err());
}

#[tokio::test]
async fn invalid_dns_config_must_fail_startup() {
    let c = cfg(
        json!([]),
        json!([freedom("direct")]),
        Some(json!({
            "dns": {
                "servers": ["1.1.1.1"],
                "fake_ip": { "enabled": true, "pool": "not-a-cidr" }
            }
        })),
    );
    assert!(Instance::from_config(Arc::new(c)).await.is_err());
}

#[tokio::test]
async fn invalid_outbound_address_must_fail_startup() {
    let c = cfg(
        json!([]),
        json!([{
            "tag":"bad-vless","protocol":"vless",
            "settings":{"address":"bad host with spaces","port":443,"users":[{"id":"00000000-0000-4000-8000-000000000001"}]}
        }]),
        None,
    );
    assert!(Instance::from_config(Arc::new(c)).await.is_err());
}

#[tokio::test]
async fn domain_longer_than_255_bytes_must_fail_startup() {
    let long_domain = "d".repeat(300);
    let c = cfg(
        json!([]),
        json!([{
            "tag":"bad-vless","protocol":"vless",
            "settings":{"address":long_domain,"port":443,"users":[{"id":"00000000-0000-4000-8000-000000000001"}]}
        }]),
        None,
    );
    assert!(Instance::from_config(Arc::new(c)).await.is_err());
}

#[tokio::test]
async fn unsupported_transport_options_must_fail_startup() {
    let c = cfg(
        json!([]),
        json!([{
            "tag":"vless-kcp","protocol":"vless",
            "settings":{"address":"127.0.0.1","port":443,"users":[{"id":"00000000-0000-4000-8000-000000000001"}]},
            "streamSettings":{"network":"kcp","kcpSettings":{"header":"not-supported"}}
        }]),
        None,
    );
    assert!(Instance::from_config(Arc::new(c)).await.is_err());
}
