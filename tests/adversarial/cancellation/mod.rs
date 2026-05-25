use std::time::Duration;

use blackwire_core::Instance;
use blackwire_transport::{dev_self_signed_for_names, grpc_accept, tls_accept, ws_accept};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[path = "../../common/harness.rs"]
mod harness;
#[path = "../../common/leak_check.rs"]
mod leak_check;

fn socks_to_freedom_cfg(socks_port: u16) -> std::sync::Arc<blackwire_config::schema::Config> {
    harness::parse_config(serde_json::json!({
        "inbounds": [{
            "tag": "socks-in",
            "protocol": "socks",
            "listen": "127.0.0.1",
            "port": socks_port
        }],
        "outbounds": [{
            "tag": "direct",
            "protocol": "freedom"
        }]
    }))
}

#[tokio::test]
async fn drop_during_handshake_read_does_not_poison_listener() {
    let socks_port = harness::unused_local_port();
    let _instance = Instance::from_config(socks_to_freedom_cfg(socks_port))
        .await
        .expect("start instance");
    tokio::time::sleep(Duration::from_millis(80)).await;
    let baseline = leak_check::steady_state_baseline().await;

    let mut half = TcpStream::connect(("127.0.0.1", socks_port))
        .await
        .expect("connect socks");
    half.write_all(&[5]).await.expect("partial greeting");
    drop(half);

    let (echo_port, _echo_task) = harness::spawn_echo_server().await;
    let mut s = harness::socks5_connect(socks_port, "127.0.0.1", echo_port).await;
    s.write_all(b"ok").await.expect("write");
    let mut out = [0u8; 2];
    s.read_exact(&mut out).await.expect("read");
    assert_eq!(&out, b"ok");
    drop(s);

    leak_check::settle_for_cleanup().await;
    let after = leak_check::LeakSnapshot::capture();
    leak_check::assert_fd_tasks_close_to_baseline(&baseline, &after, 256, 128);
}

#[tokio::test]
async fn drop_during_relay_copy_and_pending_flush_cleans_up() {
    let (stall_port, _stall_task) = harness::spawn_stalled_reader_server().await;
    let socks_port = harness::unused_local_port();
    let _instance = Instance::from_config(socks_to_freedom_cfg(socks_port))
        .await
        .expect("start instance");
    tokio::time::sleep(Duration::from_millis(80)).await;
    let baseline = leak_check::steady_state_baseline().await;

    let mut s = harness::socks5_connect(socks_port, "127.0.0.1", stall_port).await;
    let payload = vec![0xCDu8; 512 * 1024];
    let _ = tokio::time::timeout(Duration::from_secs(2), s.write_all(&payload)).await;
    drop(s);
    drop(payload);

    leak_check::settle_for_cleanup().await;
    let after = leak_check::LeakSnapshot::capture();
    leak_check::assert_fd_tasks_close_to_baseline(&baseline, &after, 512, 200);
}

#[tokio::test]
async fn drop_during_outbound_connect_keeps_runtime_live() {
    let (drop_port, _drop_task) = harness::spawn_drop_on_connect_server().await;
    let socks_port = harness::unused_local_port();
    let _instance = Instance::from_config(socks_to_freedom_cfg(socks_port))
        .await
        .expect("start instance");
    tokio::time::sleep(Duration::from_millis(80)).await;
    let baseline = leak_check::steady_state_baseline().await;

    for _ in 0..128usize {
        let mut s = harness::socks5_connect(socks_port, "127.0.0.1", drop_port).await;
        let _ = s.write_all(b"hello").await;
        drop(s);
    }

    let (echo_port, _echo_task) = harness::spawn_echo_server().await;
    let mut good = harness::socks5_connect(socks_port, "127.0.0.1", echo_port).await;
    good.write_all(b"live").await.expect("write");
    let mut out = [0u8; 4];
    good.read_exact(&mut out).await.expect("read");
    assert_eq!(&out, b"live");
    drop(good);

    leak_check::settle_for_cleanup().await;
    let after = leak_check::LeakSnapshot::capture();
    leak_check::assert_fd_tasks_close_to_baseline(&baseline, &after, 512, 200);
}

#[tokio::test]
async fn websocket_handshake_drop_returns_error_without_stuck_task() {
    let baseline = leak_check::steady_state_baseline().await;

    let (_a, b) = tokio::io::duplex(4096);
    let server = tokio::spawn(async move { ws_accept(Box::new(b)).await });
    tokio::time::sleep(Duration::from_millis(50)).await;
    server.abort();
    let _ = server.await;

    leak_check::settle_for_cleanup().await;
    let after = leak_check::LeakSnapshot::capture();
    leak_check::assert_fd_tasks_close_to_baseline(&baseline, &after, 128, 64);
}

#[tokio::test]
async fn grpc_setup_drop_returns_error_without_stuck_task() {
    let baseline = leak_check::steady_state_baseline().await;

    let (_a, b) = tokio::io::duplex(4096);
    let server = tokio::spawn(async move { grpc_accept(Box::new(b), "svc.Cancel").await });
    tokio::time::sleep(Duration::from_millis(50)).await;
    server.abort();
    let _ = server.await;

    leak_check::settle_for_cleanup().await;
    let after = leak_check::LeakSnapshot::capture();
    leak_check::assert_fd_tasks_close_to_baseline(&baseline, &after, 128, 64);
}

#[tokio::test]
async fn tls_handshake_drop_returns_clean_error_without_stuck_task() {
    let baseline = leak_check::steady_state_baseline().await;
    let (cert, key) =
        dev_self_signed_for_names(&["localhost".to_string()]).expect("self-signed cert");

    let (_a, b) = tokio::io::duplex(1 << 16);
    let server = tokio::spawn(async move { tls_accept(Box::new(b), &cert, &key, &[]).await });
    tokio::time::sleep(Duration::from_millis(50)).await;
    server.abort();
    let _ = server.await;

    leak_check::settle_for_cleanup().await;
    let after = leak_check::LeakSnapshot::capture();
    leak_check::assert_fd_tasks_close_to_baseline(&baseline, &after, 128, 64);
}

#[tokio::test]
async fn dns_resolve_cancellation_does_not_leak_tasks() {
    let baseline = leak_check::steady_state_baseline().await;
    let dns = blackwire_app::dns::DnsModule::new(blackwire_app::dns::DnsModuleConfig {
        servers: vec!["127.0.0.1:1".into()],
        ..Default::default()
    })
    .await
    .expect("dns");

    let handle = tokio::spawn(async move {
        let _ = dns.resolve("cancel-me.invalid").await;
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    handle.abort();
    let _ = handle.await;

    leak_check::settle_for_cleanup().await;
    let after = leak_check::LeakSnapshot::capture();
    leak_check::assert_fd_tasks_close_to_baseline(&baseline, &after, 128, 64);
}
