use std::sync::Arc;
use std::time::Duration;

use blackwire_core::Instance;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[path = "../common/harness.rs"]
mod harness;
#[path = "../common/leak_check.rs"]
mod leak_check;

fn base_cfg(socks_port: u16, vless_port: u16) -> Arc<blackwire_config::schema::Config> {
    harness::parse_config(serde_json::json!({
        "dns": {
            "servers": ["1.1.1.1"]
        },
        "inbounds": [
            {
                "tag": "socks-in",
                "protocol": "socks",
                "listen": "127.0.0.1",
                "port": socks_port
            },
            {
                "tag": "vless-in",
                "protocol": "vless",
                "listen": "127.0.0.1",
                "port": vless_port,
                "settings": {
                    "clients": [{"id": "00000000-0000-4000-8000-000000000001"}]
                }
            }
        ],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}]
    }))
}

async fn one_echo_roundtrip(socks_port: u16, echo_port: u16) {
    let mut s = harness::socks5_connect(socks_port, "127.0.0.1", echo_port).await;
    s.write_all(b"r").await.expect("write");
    let mut out = [0u8; 1];
    s.read_exact(&mut out).await.expect("read");
    assert_eq!(out, [b'r']);
}

#[tokio::test]
async fn reload_same_config_during_traffic_keeps_service_alive() {
    let (echo_port, _echo_task) = harness::spawn_echo_server().await;
    let socks_port = harness::unused_local_port();
    let vless_port = harness::unused_local_port();

    let cfg = base_cfg(socks_port, vless_port);
    let instance = Instance::from_config(cfg.clone()).await.expect("start");
    tokio::time::sleep(Duration::from_millis(80)).await;
    let baseline = leak_check::steady_state_baseline().await;

    let traffic = tokio::spawn(async move {
        for _ in 0..48usize {
            one_echo_roundtrip(socks_port, echo_port).await;
        }
    });

    for _ in 0..8usize {
        instance.reload.apply(&cfg).expect("reload same config");
    }

    traffic.await.expect("traffic join");
    leak_check::settle_for_cleanup().await;
    let after = leak_check::LeakSnapshot::capture();
    leak_check::assert_fd_tasks_close_to_baseline(&baseline, &after, 512, 200);
}

#[tokio::test]
async fn reload_changed_routes_applies_without_disrupting_existing_path() {
    let (echo_port, _echo_task) = harness::spawn_echo_server().await;
    let socks_port = harness::unused_local_port();
    let vless_port = harness::unused_local_port();
    let cfg = base_cfg(socks_port, vless_port);
    let instance = Instance::from_config(cfg.clone()).await.expect("start");
    tokio::time::sleep(Duration::from_millis(80)).await;

    let changed_routes = harness::parse_config(serde_json::json!({
        "inbounds": [
            {"tag":"socks-in","protocol":"socks","listen":"127.0.0.1","port":socks_port},
            {"tag":"vless-in","protocol":"vless","listen":"127.0.0.1","port":vless_port,
             "settings":{"clients":[{"id":"00000000-0000-4000-8000-000000000001"}]}}
        ],
        "outbounds": [{"tag":"direct","protocol":"freedom"}],
        "routing": {
            "rules": [{
                "type": "field",
                "domain": ["suffix:example.com"],
                "outboundTag": "direct"
            }]
        }
    }));
    instance
        .reload
        .apply(&changed_routes)
        .expect("reload changed routes");

    one_echo_roundtrip(socks_port, echo_port).await;
}

#[tokio::test]
async fn reload_changed_dns_and_outbound_does_not_poison_runtime() {
    let (echo_port, _echo_task) = harness::spawn_echo_server().await;
    let socks_port = harness::unused_local_port();
    let vless_port = harness::unused_local_port();
    let cfg = base_cfg(socks_port, vless_port);
    let instance = Instance::from_config(cfg).await.expect("start");
    tokio::time::sleep(Duration::from_millis(80)).await;

    let changed = harness::parse_config(serde_json::json!({
        "dns": { "servers": ["8.8.8.8"] },
        "inbounds": [
            {"tag":"socks-in","protocol":"socks","listen":"127.0.0.1","port":socks_port},
            {"tag":"vless-in","protocol":"vless","listen":"127.0.0.1","port":vless_port,
             "settings":{"clients":[{"id":"00000000-0000-4000-8000-000000000001"}]}}
        ],
        "outbounds": [
            {"tag":"direct","protocol":"freedom"},
            {"tag":"unused-vmess","protocol":"vmess",
             "settings":{"address":"127.0.0.1","port":9,"users":[{"id":"00000000-0000-4000-8000-000000000002"}]}}
        ]
    }));
    instance
        .reload
        .apply(&changed)
        .expect("reload changed dns/outbound");
    one_echo_roundtrip(socks_port, echo_port).await;
}

#[tokio::test]
async fn reload_changed_users_updates_registry() {
    let socks_port = harness::unused_local_port();
    let vless_port = harness::unused_local_port();
    let cfg = base_cfg(socks_port, vless_port);
    let instance = Instance::from_config(cfg).await.expect("start");

    let reg = instance
        .reload
        .vless_registries
        .get("vless-in")
        .expect("vless registry")
        .clone();
    assert_eq!(reg.len(), 1);

    let changed_users = harness::parse_config(serde_json::json!({
        "inbounds": [
            {"tag":"socks-in","protocol":"socks","listen":"127.0.0.1","port":socks_port},
            {"tag":"vless-in","protocol":"vless","listen":"127.0.0.1","port":vless_port,
             "settings":{"clients":[
                {"id":"00000000-0000-4000-8000-000000000001"},
                {"id":"00000000-0000-4000-8000-000000000002"}
             ]}}
        ],
        "outbounds": [{"tag":"direct","protocol":"freedom"}]
    }));

    instance
        .reload
        .apply(&changed_users)
        .expect("reload changed users");
    let reg2 = instance
        .reload
        .vless_registries
        .get("vless-in")
        .expect("vless registry")
        .clone();
    assert_eq!(reg2.len(), 2, "user registry should refresh on reload");
}

#[tokio::test]
async fn invalid_reload_does_not_poison_runtime() {
    let (echo_port, _echo_task) = harness::spawn_echo_server().await;
    let socks_port = harness::unused_local_port();
    let vless_port = harness::unused_local_port();
    let cfg = base_cfg(socks_port, vless_port);
    let instance = Instance::from_config(cfg).await.expect("start");
    tokio::time::sleep(Duration::from_millis(80)).await;

    let invalid = harness::parse_config(serde_json::json!({
        "inbounds": [
            {"tag":"socks-in","protocol":"socks","listen":"127.0.0.1","port":socks_port},
            {"tag":"vless-in","protocol":"vless","listen":"127.0.0.1","port":vless_port,
             "settings":{"clients":[{"id":"00000000-0000-4000-8000-000000000001"}]}}
        ],
        "outbounds": [{"tag":"direct","protocol":"freedom"}],
        "routing": {
            "rules": [{
                "type": "field",
                "domain": ["suffix:test.invalid"],
                "outboundTag": "missing"
            }]
        }
    }));
    assert!(
        instance.reload.apply(&invalid).is_err(),
        "invalid reload must fail"
    );

    one_echo_roundtrip(socks_port, echo_port).await;
}
