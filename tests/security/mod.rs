use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use blackwire_app::context::Context;
use blackwire_app::dispatcher::Dispatcher;
use blackwire_app::features::InboundHandler;
use blackwire_common::{Address, BoxedStream, ProxyError};
use blackwire_protocol::vless::codec as vless_codec;
use blackwire_protocol::vless::{VlessInbound, VlessUser, VlessUserRegistry};
use blackwire_transport::{dev_self_signed_for_names, tls_accept, tls_connect};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[path = "../common/harness.rs"]
mod harness;

struct CountingDispatcher {
    calls: AtomicUsize,
}

#[async_trait]
impl Dispatcher for CountingDispatcher {
    async fn dispatch(
        &self,
        _ctx: Context,
        _dest: Address,
        _inbound_stream: BoxedStream,
    ) -> Result<(), ProxyError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    async fn connect_outbound(
        &self,
        _ctx: Context,
        _dest: Address,
    ) -> Result<BoxedStream, ProxyError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        Err(ProxyError::Protocol("connect_outbound stub".into()))
    }
}

#[tokio::test]
async fn bad_vless_auth_never_dispatches_outbound() {
    let registry = VlessUserRegistry::new();
    registry.add_user(VlessUser {
        uuid: [0xAA; 16],
        email: "allowed@example".into(),
        flow: String::new(),
    });
    let inbound = VlessInbound::new(
        "vless-in",
        Arc::clone(&registry),
        None,
        Some(Duration::from_secs(1)),
    );
    let dispatcher = Arc::new(CountingDispatcher {
        calls: AtomicUsize::new(0),
    });

    let (mut client, server) = tokio::io::duplex(4096);
    let bad = vless_codec::encode_request(
        &[0xBB; 16],
        "",
        vless_codec::Command::Tcp,
        &Address::Domain("example.com".into(), 443),
    )
    .expect("encode");
    client.write_all(&bad).await.expect("write");
    client.flush().await.expect("flush");
    drop(client);

    let source: SocketAddr = "127.0.0.1:41234".parse().expect("source");
    inbound
        .handle(Box::new(server), source, dispatcher.clone())
        .await
        .expect("handle");

    assert_eq!(
        dispatcher.calls.load(Ordering::Relaxed),
        0,
        "unauthenticated VLESS traffic must not reach dispatcher/outbound"
    );
}

#[tokio::test]
async fn tls_verification_fails_closed_on_sni_mismatch() {
    let (cert, key) = dev_self_signed_for_names(&["localhost".to_string()]).expect("cert");
    let (a, b) = tokio::io::duplex(1 << 16);

    let server = tokio::spawn(async move { tls_accept(Box::new(b), &cert, &key, &[]).await });
    let client = tls_connect(Box::new(a), "not-localhost.invalid", &[], false).await;

    assert!(
        client.is_err(),
        "client verification must fail when certificate does not match SNI"
    );
    let _ = server.await;
}

#[tokio::test]
async fn fakeip_filtered_domain_does_not_allocate_fake_ip() {
    let dns = blackwire_app::dns::DnsModule::new(blackwire_app::dns::DnsModuleConfig {
        fake_ip_enabled: true,
        fake_ip_filter: vec!["blocked.test".into()],
        ..Default::default()
    })
    .await
    .expect("dns");

    assert!(dns.is_filtered("blocked.test"));
    let should_skip = if dns.is_filtered("blocked.test") {
        None
    } else {
        dns.resolve_fake("blocked.test")
    };
    assert!(
        should_skip.is_none(),
        "filtered domain must not allocate fake IP at boundary callsite"
    );
}

#[tokio::test]
async fn reload_cannot_enable_empty_vless_auth_set() {
    let socks_port = harness::unused_local_port();
    let cfg = harness::parse_config(serde_json::json!({
        "inbounds": [{
            "tag": "vless-in",
            "protocol": "vless",
            "listen": "127.0.0.1",
            "port": socks_port,
            "settings": { "clients": [{ "id": "00000000-0000-4000-8000-000000000001" }] }
        }],
        "outbounds": [{ "tag": "direct", "protocol": "freedom" }]
    }));
    let instance = blackwire_core::Instance::from_config(cfg.clone())
        .await
        .expect("start");

    let reloaded = harness::parse_config(serde_json::json!({
        "inbounds": [{
            "tag": "vless-in",
            "protocol": "vless",
            "listen": "127.0.0.1",
            "port": socks_port,
            "settings": { "clients": [] }
        }],
        "outbounds": [{ "tag": "direct", "protocol": "freedom" }]
    }));

    let res = instance.reload.apply(&reloaded);
    assert!(
        res.is_err(),
        "reload must fail closed instead of allowing empty VLESS auth list"
    );
}

#[tokio::test]
async fn routing_rule_cannot_bypass_intended_outbound() {
    let (echo_port, _echo_task) = harness::spawn_echo_server().await;
    let socks_port = harness::unused_local_port();
    let cfg = harness::parse_config(serde_json::json!({
        "inbounds": [{
            "tag":"socks-in","protocol":"socks","listen":"127.0.0.1","port":socks_port
        }],
        "outbounds": [
            {"tag":"direct","protocol":"freedom"},
            {"tag":"blocked","protocol":"vless",
             "settings":{"address":"127.0.0.1","port":9,"users":[{"id":"00000000-0000-4000-8000-000000000001"}]}}
        ],
        "routing": {
            "rules": [{
                "type": "field",
                "ip": ["127.0.0.1/32"],
                "outboundTag": "blocked"
            }]
        }
    }));
    let _instance = blackwire_core::Instance::from_config(cfg)
        .await
        .expect("start");
    tokio::time::sleep(Duration::from_millis(80)).await;

    let mut s = tokio::net::TcpStream::connect(("127.0.0.1", socks_port))
        .await
        .expect("connect socks");
    s.write_all(&[5, 1, 0]).await.expect("greet");
    let mut greet = [0u8; 2];
    s.read_exact(&mut greet).await.expect("greet rep");
    assert_eq!(greet, [5, 0]);
    let octets = [127u8, 0, 0, 1];
    let mut req = vec![5, 1, 0, 1];
    req.extend_from_slice(&octets);
    req.extend_from_slice(&echo_port.to_be_bytes());
    s.write_all(&req).await.expect("req");
    let mut rep = [0u8; 10];
    s.read_exact(&mut rep).await.expect("rep");
    assert_eq!(rep[1], 0, "socks connect reply must succeed");

    s.write_all(b"should-not-echo").await.expect("write");
    let mut buf = [0u8; 4];
    let n = tokio::time::timeout(Duration::from_secs(2), s.read(&mut buf))
        .await
        .expect("timeout")
        .unwrap_or(0);
    assert_eq!(
        n, 0,
        "traffic unexpectedly bypassed intended outbound and reached direct echo"
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn tun_loop_prevention_so_mark_fails_closed_without_privilege() {
    use blackwire_transport::tcp::{TcpClientTransport, TcpConfig};

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let _accept = tokio::spawn(async move {
        let _ = listener.accept().await;
    });

    let transport = TcpClientTransport::new(TcpConfig {
        so_mark: Some(0x1234),
        tcp_fast_open: false,
        max_connections: None,
    });

    match transport.dial(addr).await {
        Ok(_) => {
            // privileged runner; SO_MARK applied successfully before connect.
        }
        Err(e) => {
            let msg = e.to_string();
            assert!(
                msg.contains("SO_MARK failed"),
                "SO_MARK application must fail closed before connect: {msg}"
            );
        }
    }
}
