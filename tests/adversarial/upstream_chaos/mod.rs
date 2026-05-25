use std::time::Duration;

use proxy_core::Instance;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[path = "../../common/harness.rs"]
mod harness;
#[path = "../../common/leak_check.rs"]
mod leak_check;

fn socks_to_freedom_cfg(socks_port: u16) -> std::sync::Arc<proxy_config::schema::Config> {
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

async fn spawn_partial_then_drop_server() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind partial");
    let port = listener.local_addr().expect("addr").port();
    let task = tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            tokio::spawn(async move {
                let _ = s.write_all(b"PARTIAL").await;
                tokio::time::sleep(Duration::from_millis(10)).await;
            });
        }
    });
    (port, task)
}

async fn spawn_huge_response_server(bytes: usize) -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind huge");
    let port = listener.local_addr().expect("addr").port();
    let task = tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            tokio::spawn(async move {
                let chunk = vec![0x66u8; 8192];
                let mut left = bytes;
                while left > 0 {
                    let n = left.min(chunk.len());
                    if s.write_all(&chunk[..n]).await.is_err() {
                        break;
                    }
                    left -= n;
                }
            });
        }
    });
    (port, task)
}

async fn spawn_malformed_dns_udp_server() -> (u16, tokio::task::JoinHandle<()>) {
    let sock = tokio::net::UdpSocket::bind(("127.0.0.1", 0))
        .await
        .expect("bind dns");
    let port = sock.local_addr().expect("dns addr").port();
    let task = tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        while let Ok((_, peer)) = sock.recv_from(&mut buf).await {
            let _ = sock.send_to(b"\x00\xff\xaa", peer).await;
        }
    });
    (port, task)
}

#[tokio::test]
async fn upstream_close_immediately_is_handled_and_runtime_survives() {
    let (drop_port, _drop_task) = harness::spawn_drop_on_connect_server().await;
    let socks_port = harness::unused_local_port();
    let _instance = Instance::from_config(socks_to_freedom_cfg(socks_port))
        .await
        .expect("start");
    tokio::time::sleep(Duration::from_millis(80)).await;
    let baseline = leak_check::steady_state_baseline().await;

    let mut s = harness::socks5_connect(socks_port, "127.0.0.1", drop_port).await;
    s.write_all(b"x").await.expect("write");
    let n = tokio::time::timeout(Duration::from_secs(2), s.read(&mut [0u8; 1]))
        .await
        .expect("timeout")
        .expect("read");
    assert_eq!(n, 0);
    drop(s);

    let (echo_port, _echo_task) = harness::spawn_echo_server().await;
    let mut good = harness::socks5_connect(socks_port, "127.0.0.1", echo_port).await;
    good.write_all(b"ok").await.expect("write");
    let mut out = [0u8; 2];
    good.read_exact(&mut out).await.expect("read");
    assert_eq!(&out, b"ok");
    drop(good);

    leak_check::settle_for_cleanup().await;
    let after = leak_check::LeakSnapshot::capture();
    leak_check::assert_fd_tasks_close_to_baseline(&baseline, &after, 256, 128);
}

#[tokio::test]
async fn upstream_closes_mid_response_without_proxy_hang() {
    let (srv_port, _task) = spawn_partial_then_drop_server().await;
    let socks_port = harness::unused_local_port();
    let _instance = Instance::from_config(socks_to_freedom_cfg(socks_port))
        .await
        .expect("start");
    tokio::time::sleep(Duration::from_millis(80)).await;
    let baseline = leak_check::steady_state_baseline().await;

    let mut s = harness::socks5_connect(socks_port, "127.0.0.1", srv_port).await;
    let mut got = vec![0u8; "PARTIAL".len()];
    tokio::time::timeout(Duration::from_secs(2), s.read_exact(&mut got))
        .await
        .expect("timeout")
        .expect("read");
    assert_eq!(&got, b"PARTIAL");

    let n = tokio::time::timeout(Duration::from_secs(2), s.read(&mut [0u8; 1]))
        .await
        .expect("timeout")
        .expect("read");
    assert_eq!(n, 0);
    drop(s);

    leak_check::settle_for_cleanup().await;
    let after = leak_check::LeakSnapshot::capture();
    leak_check::assert_fd_tasks_close_to_baseline(&baseline, &after, 256, 128);
}

#[tokio::test]
async fn upstream_stall_triggers_timeout_at_test_layer_and_cleans_up() {
    let (stall_port, _stall_task) = harness::spawn_stalled_reader_server().await;
    let socks_port = harness::unused_local_port();
    let _instance = Instance::from_config(socks_to_freedom_cfg(socks_port))
        .await
        .expect("start");
    tokio::time::sleep(Duration::from_millis(80)).await;
    let baseline = leak_check::steady_state_baseline().await;

    let mut s = harness::socks5_connect(socks_port, "127.0.0.1", stall_port).await;
    s.write_all(b"request").await.expect("write");
    let read = tokio::time::timeout(Duration::from_millis(300), s.read(&mut [0u8; 1])).await;
    assert!(
        read.is_err() || read.expect("read timeout wrapper").unwrap_or(0) == 0,
        "expected timeout or clean close while upstream stalls"
    );
    drop(s);

    leak_check::settle_for_cleanup().await;
    let after = leak_check::LeakSnapshot::capture();
    leak_check::assert_fd_tasks_close_to_baseline(&baseline, &after, 512, 200);
}

#[tokio::test]
async fn upstream_huge_response_is_relayed_without_parser_breakage() {
    let (srv_port, _task) = spawn_huge_response_server(2 << 20).await;
    let socks_port = harness::unused_local_port();
    let _instance = Instance::from_config(socks_to_freedom_cfg(socks_port))
        .await
        .expect("start");
    tokio::time::sleep(Duration::from_millis(80)).await;
    let baseline = leak_check::steady_state_baseline().await;

    let mut s = harness::socks5_connect(socks_port, "127.0.0.1", srv_port).await;
    let mut total = 0usize;
    let mut buf = [0u8; 4096];
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            let n = s.read(&mut buf).await.expect("read");
            if n == 0 {
                break;
            }
            total += n;
            if total >= (2 << 20) {
                break;
            }
        }
    })
    .await
    .expect("timeout");

    assert!(total >= (2 << 20) / 2, "unexpectedly low transferred bytes");
    drop(s);

    leak_check::settle_for_cleanup().await;
    let after = leak_check::LeakSnapshot::capture();
    leak_check::assert_fd_tasks_close_to_baseline(&baseline, &after, 512, 200);
}

#[tokio::test]
async fn malformed_dns_upstream_response_is_handled() {
    let (dns_port, _task) = spawn_malformed_dns_udp_server().await;
    let dns = proxy_app::dns::DnsModule::new(proxy_app::dns::DnsModuleConfig {
        servers: vec![format!("127.0.0.1:{dns_port}")],
        ..Default::default()
    })
    .await
    .expect("dns module");

    let res = tokio::time::timeout(Duration::from_secs(2), dns.resolve("chaos.invalid")).await;
    assert!(res.is_ok(), "dns query path hung");
    assert!(
        res.expect("timeout").is_err(),
        "malformed DNS response should not be accepted"
    );
}
