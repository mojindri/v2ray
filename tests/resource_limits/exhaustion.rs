#![cfg(feature = "heavy-tests")]

use std::sync::Arc;
use std::time::Duration;

use proxy_core::Instance;
use proxy_protocol::vless::codec as vless_codec;
use proxy_transport::{grpc_accept, grpc_connect, ws_accept, ws_connect, WsConnectConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[path = "../common/harness.rs"]
mod harness;
#[path = "../common/leak_check.rs"]
mod leak_check;

#[tokio::test]
#[ignore = "heavy resource exhaustion scenario"]
async fn ten_k_bad_auth_attempts_do_not_kill_server() {
    let vless_port = harness::unused_local_port();
    let cfg = harness::parse_config(serde_json::json!({
        "inbounds": [{
            "tag":"vless-in",
            "protocol":"vless",
            "listen":"127.0.0.1",
            "port": vless_port,
            "settings":{"clients":[{"id":"00000000-0000-4000-8000-000000000001"}]}
        }],
        "outbounds":[{"tag":"direct","protocol":"freedom"}]
    }));
    let _instance = Instance::from_config(cfg).await.expect("start");
    tokio::time::sleep(Duration::from_millis(80)).await;

    let bad = vless_codec::encode_request(
        &[0x42; 16],
        "",
        vless_codec::Command::Tcp,
        &proxy_common::Address::Domain("example.com".into(), 443),
    )
    .expect("encode");

    for _ in 0..10_000usize {
        if let Ok(mut s) = TcpStream::connect(("127.0.0.1", vless_port)).await {
            let _ = s.write_all(&bad).await;
        }
    }
}

#[test]
#[ignore = "heavy resource exhaustion scenario"]
fn ten_k_fakeip_allocations_remain_bounded() {
    let pool = proxy_app::dns::FakeIpPool::new("198.18.0.0/15").expect("pool");
    for i in 0..10_000usize {
        let d = format!("d{i}.example.test");
        let ip = pool.allocate(&d);
        assert!(pool.is_fake(ip));
    }
}

#[test]
#[ignore = "heavy resource exhaustion scenario"]
fn ten_k_dns_unique_domains_cache_does_not_panic() {
    let cache = proxy_app::dns::DnsCache::new(4096);
    for i in 0..10_000usize {
        let d = format!("u{i}.example.test");
        cache.insert(&d, vec!["1.1.1.1".parse().expect("ip")], 5);
    }
    assert!(cache.len() <= 4096);
}

#[tokio::test]
#[ignore = "heavy resource exhaustion scenario"]
async fn many_websocket_and_grpc_streams_are_handled() {
    let baseline = leak_check::LeakSnapshot::capture();

    for _ in 0..1000usize {
        let (a, b) = tokio::io::duplex(1 << 16);
        let ws_server = tokio::spawn(async move { ws_accept(Box::new(b)).await });
        let mut ws_client = ws_connect(
            Box::new(a),
            WsConnectConfig {
                path: "/".into(),
                host: "localhost".into(),
                headers: vec![],
            },
        )
        .await
        .expect("ws connect");
        let _ = ws_server.await.expect("ws join").expect("ws accept");
        ws_client.write_all(b"x").await.expect("ws write");
    }

    for _ in 0..1000usize {
        let (a, b) = tokio::io::duplex(1 << 16);
        let grpc_server = tokio::spawn(async move { grpc_accept(Box::new(b), "svc.Heavy").await });
        let mut grpc_client = grpc_connect(Box::new(a), "localhost", "svc.Heavy")
            .await
            .expect("grpc connect");
        let _ = grpc_server.await.expect("grpc join").expect("grpc accept");
        grpc_client.write_all(b"x").await.expect("grpc write");
    }

    leak_check::settle_for_cleanup().await;
    let after = leak_check::LeakSnapshot::capture();
    leak_check::assert_close_to_baseline(&baseline, &after, 1024, 400, 200);
}

#[tokio::test]
#[ignore = "heavy resource exhaustion scenario"]
async fn ten_k_mkcp_sessions_smoke() {
    use proxy_transport::{mkcp_accept_sessions, mkcp_connect, MkcpClientConfig, MkcpServerConfig};

    let listen_addr: std::net::SocketAddr = format!("127.0.0.1:{}", harness::unused_local_port())
        .parse()
        .expect("listen");
    let server_cfg = MkcpServerConfig {
        listen: listen_addr,
        header: proxy_transport::mkcp::header::HeaderType::None,
        interval_ms: 10,
        rcv_wnd: 128,
        snd_wnd: 128,
        nodelay: true,
    };
    let mut rx = mkcp_accept_sessions(&server_cfg).await.expect("accept");
    let accept_task = tokio::spawn(async move {
        let mut count = 0usize;
        while count < 10_000 {
            if rx.recv().await.is_some() {
                count += 1;
            }
        }
        count
    });

    for i in 0..10_000u32 {
        let cfg = MkcpClientConfig {
            server: listen_addr,
            conv: i + 1,
            ..Default::default()
        };
        let _ = mkcp_connect(&cfg).await.expect("connect");
    }

    let accepted = accept_task.await.expect("join");
    assert_eq!(accepted, 10_000);
}
