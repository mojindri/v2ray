use std::time::Duration;

use proxy_app::metrics::{record_connection_accepted, record_connection_closed, start_metrics_server};

#[path = "../common/harness.rs"]
mod harness;

async fn http_get(addr: &str, path: &str) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut s = tokio::net::TcpStream::connect(addr).await.expect("connect http");
    let req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    s.write_all(req.as_bytes()).await.expect("write req");
    let mut buf = vec![];
    s.read_to_end(&mut buf).await.expect("read resp");
    String::from_utf8_lossy(&buf).into_owned()
}

#[tokio::test]
async fn metrics_endpoint_exposes_proxy_metrics() {
    let addr = format!("127.0.0.1:{}", harness::unused_local_port());
    let _task = start_metrics_server(&addr).expect("start metrics");
    tokio::time::sleep(Duration::from_millis(100)).await;

    record_connection_accepted("socks-in", "socks");
    record_connection_closed("socks-in", 12, 34, Duration::from_millis(50));

    let metrics = http_get(&addr, "/metrics").await;
    assert!(metrics.contains("proxy_connections_total"));
    assert!(metrics.contains("proxy_bytes_total"));
    assert!(metrics.contains("proxy_active_connections"));
    assert!(metrics.contains("proxy_connection_duration_seconds"));
}

#[tokio::test]
async fn dns_failure_returns_actionable_error() {
    let dns = proxy_app::dns::DnsModule::new(proxy_app::dns::DnsModuleConfig {
        servers: vec!["127.0.0.1:1".into()],
        ..Default::default()
    })
    .await
    .expect("dns build");

    let err = dns
        .resolve("this-domain-should-not-exist.invalid")
        .await
        .expect_err("expected dns failure");
    let msg = err.to_string();
    assert!(
        msg.contains("DNS") || msg.contains("dns") || msg.contains("resolve"),
        "dns error should be observable and actionable: {msg}"
    );
}

#[tokio::test]
async fn reload_failure_contains_reason() {
    let socks_port = harness::unused_local_port();
    let cfg = harness::parse_config(serde_json::json!({
        "inbounds": [{
            "tag":"socks-in","protocol":"socks","listen":"127.0.0.1","port":socks_port
        }],
        "outbounds": [{ "tag": "direct", "protocol": "freedom" }]
    }));
    let instance = proxy_core::Instance::from_config(cfg).await.expect("start");

    let invalid = harness::parse_config(serde_json::json!({
        "inbounds": [{
            "tag":"socks-in","protocol":"socks","listen":"127.0.0.1","port":socks_port
        }],
        "outbounds": [{ "tag": "direct", "protocol": "freedom" }],
        "routing": {
            "rules": [{
                "type": "field",
                "domain": ["regexp:[unclosed"],
                "outboundTag": "direct"
            }]
        }
    }));
    let err = instance
        .reload
        .apply(&invalid)
        .expect_err("reload should fail");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("missing")
            || msg.contains("outbound")
            || msg.contains("regex")
            || msg.contains("parse"),
        "reload failure should expose useful cause: {msg}"
    );
}
