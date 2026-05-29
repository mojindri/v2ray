//! Lightweight CI smoke tests for resource-risk areas.
//!
//! These cover the same scenarios as `resource_limits/exhaustion.rs` at a much
//! smaller scale so they run in normal CI without the `heavy-tests` feature flag.
//!
//! Areas covered:
//! - bad-auth burst (50 wrong-UUID connections; server survives and remains live)
//! - FakeIP allocation pressure (1000 allocs; pool stays bounded, no panic)
//! - DNS cache pressure (1000 unique domains; cache stays bounded, no panic)
//! - WS/gRPC stream churn (20 pairs each; connect/disconnect without panic)
//! - mKCP session churn (50 sessions; all accepted without panic)
//! - connection-limit overflow (maxConnections=5, burst 20; server alive after)

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

fn parse_config(json: serde_json::Value) -> Arc<blackwire_config::schema::Config> {
    Arc::new(serde_json::from_value(json).expect("config parse"))
}

fn unused_local_port() -> u16 {
    std::net::TcpListener::bind(("127.0.0.1", 0))
        .expect("port reserve")
        .local_addr()
        .expect("port addr")
        .port()
}

// ── bad-auth burst ────────────────────────────────────────────────────────────

/// 50 bad-auth (wrong UUID) VLESS connections.
/// Server must reject every one and remain alive for a legitimate round-trip.
#[tokio::test]
async fn bad_auth_burst_server_survives() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("error")
        .try_init();

    const GOOD_UUID: &str = "a0000000-0000-4000-8000-000000000001";

    let vless_port = unused_local_port();
    let socks_port = unused_local_port();
    let echo_port = unused_local_port();

    let _server = blackwire_core::Instance::from_config(parse_config(serde_json::json!({
        "inbounds": [{
            "tag": "vless-in",
            "protocol": "vless",
            "listen": "127.0.0.1",
            "port": vless_port,
            "settings": {"clients": [{"id": GOOD_UUID}]}
        }],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}]
    })))
    .await
    .expect("server start");

    let _client = blackwire_core::Instance::from_config(parse_config(serde_json::json!({
        "inbounds": [{"tag": "socks", "protocol": "socks",
                      "listen": "127.0.0.1", "port": socks_port}],
        "outbounds": [{
            "tag": "out", "protocol": "vless",
            "settings": {"address": "127.0.0.1", "port": vless_port,
                         "users": [{"id": GOOD_UUID, "flow": ""}]}
        }]
    })))
    .await
    .expect("client start");

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Burst: 50 connections carrying a VLESS header with a wrong UUID.
    let bad_uuid = [0xBAu8; 16];
    let bad_req = blackwire_protocol::vless::codec::encode_request(
        &bad_uuid,
        "",
        blackwire_protocol::vless::codec::Command::Tcp,
        &blackwire_common::Address::Domain("example.com".into(), 443),
    )
    .expect("encode bad request");

    for _ in 0..50usize {
        if let Ok(mut s) = TcpStream::connect(("127.0.0.1", vless_port)).await {
            let _ = s.write_all(&bad_req).await;
        }
    }

    // Start a simple echo server for the liveness check.
    let echo_listener = tokio::net::TcpListener::bind(("127.0.0.1", echo_port))
        .await
        .expect("echo bind");
    let _echo = tokio::spawn(async move {
        if let Ok((mut s, _)) = echo_listener.accept().await {
            let mut buf = [0u8; 5];
            if s.read_exact(&mut buf).await.is_ok() {
                let _ = s.write_all(&buf).await;
            }
        }
    });

    tokio::time::sleep(Duration::from_millis(120)).await;

    // Liveness: a legitimate SOCKS5 → VLESS round-trip must succeed after the burst.
    let mut stream = timeout(Duration::from_secs(4), async {
        let mut s = TcpStream::connect(("127.0.0.1", socks_port)).await.unwrap();
        s.write_all(&[5, 1, 0]).await.unwrap();
        let mut r = [0u8; 2];
        s.read_exact(&mut r).await.unwrap();
        assert_eq!(r, [5, 0], "SOCKS5 method negotiation failed");
        let host = b"127.0.0.1";
        let mut req = vec![5, 1, 0, 3, host.len() as u8];
        req.extend_from_slice(host);
        req.extend_from_slice(&echo_port.to_be_bytes());
        s.write_all(&req).await.unwrap();
        let mut reply = [0u8; 10];
        s.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 0, "SOCKS5 CONNECT failed after bad-auth burst");
        s
    })
    .await
    .expect("liveness check timed out after bad-auth burst");

    stream.write_all(b"alive").await.unwrap();
    let mut buf = [0u8; 5];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"alive", "echo mismatch after bad-auth burst");
}

// ── FakeIP allocation pressure ────────────────────────────────────────────────

/// 1000 FakeIP allocations stay bounded and do not panic.
#[test]
fn fakeip_pressure_stays_bounded() {
    let pool = blackwire_app::dns::FakeIpPool::new("198.18.0.0/15").expect("pool");
    for i in 0..1_000usize {
        let domain = format!("smoke{i}.fakeip.test");
        let ip = pool.allocate(&domain);
        assert!(pool.is_fake(ip), "allocated IP must be in the pool range");
    }
}

// ── DNS cache pressure ────────────────────────────────────────────────────────

/// 1000 unique domains inserted into the DNS cache; length stays at or below cap.
#[test]
fn dns_cache_pressure_stays_bounded() {
    const CAP: usize = 512;
    let cache = blackwire_app::dns::DnsCache::new(CAP);
    for i in 0..1_000usize {
        let domain = format!("smoke{i}.dns.test");
        cache.insert(&domain, vec!["1.1.1.1".parse().unwrap()], 30);
    }
    assert!(
        cache.len() <= CAP,
        "cache grew past cap {CAP}: len = {}",
        cache.len()
    );
}

// ── WS / gRPC stream churn ────────────────────────────────────────────────────

/// 20 WebSocket + 20 gRPC connect/disconnect cycles do not panic or deadlock.
#[tokio::test]
async fn ws_and_grpc_stream_churn_no_panic() {
    use blackwire_transport::{grpc_accept, grpc_connect, ws_accept, ws_connect, WsConnectConfig};

    for _ in 0..20usize {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let srv = tokio::spawn(async move { ws_accept(Box::new(b)).await });
        let mut cli = ws_connect(
            Box::new(a),
            WsConnectConfig {
                path: "/smoke".into(),
                host: "localhost".into(),
                headers: vec![],
            },
        )
        .await
        .expect("ws_connect");
        let _ = srv.await.expect("ws_accept join").expect("ws_accept");
        cli.write_all(b"x").await.expect("ws write");
    }

    for _ in 0..20usize {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let srv = tokio::spawn(async move { grpc_accept(Box::new(b), "smoke.Gun").await });
        let mut cli = grpc_connect(Box::new(a), "localhost", "smoke.Gun")
            .await
            .expect("grpc_connect");
        let _ = srv.await.expect("grpc_accept join").expect("grpc_accept");
        cli.write_all(b"x").await.expect("grpc write");
    }
}

// ── mKCP session churn ────────────────────────────────────────────────────────

/// 50 mKCP sessions are established and accepted without panic or resource leak.
///
/// Each client sends one byte so the KCP driver has data to flush on the first
/// tick. Without an actual send the client driver would never transmit a UDP
/// segment and the server would not create a session.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mkcp_session_churn_no_panic() {
    use blackwire_transport::{
        mkcp_accept_sessions, mkcp_connect, MkcpClientConfig, MkcpServerConfig,
    };

    let addr: std::net::SocketAddr = format!("127.0.0.1:{}", unused_local_port())
        .parse()
        .expect("addr parse");

    let server_cfg = MkcpServerConfig {
        listen: addr,
        header: blackwire_transport::mkcp::header::HeaderType::None,
        interval_ms: 10,
        rcv_wnd: 32,
        snd_wnd: 32,
        nodelay: true,
    };

    let mut rx = mkcp_accept_sessions(&server_cfg)
        .await
        .expect("mkcp listen");

    const N: usize = 50;

    // Collect accepted-session count in the background.
    let accept_task = tokio::spawn(async move {
        let mut count = 0usize;
        while count < N {
            if rx.recv().await.is_some() {
                count += 1;
            }
        }
        count
    });

    // Each client writes one byte so the KCP driver has payload to flush on
    // its next tick, triggering the first UDP segment to the server.
    let mut streams = Vec::with_capacity(N);
    for i in 0..N as u32 {
        let cfg = MkcpClientConfig {
            server: addr,
            conv: i + 1,
            interval_ms: 10,
            ..Default::default()
        };
        let mut s = mkcp_connect(&cfg).await.expect("mkcp_connect");
        s.write_all(b"x").await.expect("mkcp write");
        streams.push(s);
    }

    // Wait for all sessions to be accepted (drivers tick at 10 ms).
    let accepted = timeout(Duration::from_secs(10), accept_task)
        .await
        .expect("mkcp session churn timed out")
        .expect("accept task panicked");

    drop(streams);
    assert_eq!(accepted, N, "accepted {accepted} sessions, expected {N}");
}

// ── connection-limit overflow ─────────────────────────────────────────────────

/// Bursting past `maxConnections` on an inbound must not crash the server.
/// After the burst and a drain period the server must still respond.
#[tokio::test]
async fn connection_limit_overflow_server_survives() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("error")
        .try_init();

    let socks_port = unused_local_port();

    let _srv = blackwire_core::Instance::from_config(parse_config(serde_json::json!({
        "inbounds": [{
            "tag": "socks",
            "protocol": "socks",
            "listen": "127.0.0.1",
            "port": socks_port,
            "limits": { "maxConnections": 5 }
        }],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}]
    })))
    .await
    .expect("server start");

    tokio::time::sleep(Duration::from_millis(40)).await;

    // Burst: 20 TCP connections that stall mid-greeting (never complete the
    // SOCKS5 handshake) so they hold slots long enough to exceed the limit.
    let mut stalls: Vec<TcpStream> = Vec::new();
    for _ in 0..20usize {
        if let Ok(mut s) = TcpStream::connect(("127.0.0.1", socks_port)).await {
            let _ = s.write_all(&[0x05]).await; // version byte only — stalls the handshake
            stalls.push(s);
        }
    }

    drop(stalls); // release all stalled connections
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Liveness: the server must still accept and respond to a SOCKS5 greeting.
    let mut s = timeout(
        Duration::from_secs(3),
        TcpStream::connect(("127.0.0.1", socks_port)),
    )
    .await
    .expect("connect timed out after limit-overflow burst")
    .expect("connect failed");

    s.write_all(&[5, 1, 0]).await.expect("write greeting");

    let mut resp = [0u8; 2];
    timeout(Duration::from_secs(2), s.read_exact(&mut resp))
        .await
        .expect("read timed out — server not responding after limit-overflow burst")
        .expect("read failed");

    assert_eq!(resp[0], 5, "expected SOCKS5 version byte in response");
}
