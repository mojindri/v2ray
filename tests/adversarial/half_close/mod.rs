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

async fn spawn_upstream_shutdown_write_first() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind shutdown-first");
    let port = listener.local_addr().expect("addr").port();
    let task = tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            tokio::spawn(async move {
                let _ = s.write_all(b"server-preface").await;
                let _ = s.shutdown().await;
                let mut sink = [0u8; 512];
                let _ = s.read(&mut sink).await;
            });
        }
    });
    (port, task)
}

async fn spawn_delayed_tail_server() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind delayed tail");
    let port = listener.local_addr().expect("addr").port();
    let task = tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut first = [0u8; 4];
                let _ = s.read_exact(&mut first).await;
                let _ = s.write_all(b"HEAD").await;
                tokio::time::sleep(Duration::from_millis(40)).await;
                let _ = s.write_all(b"TAIL").await;
                let _ = s.shutdown().await;
            });
        }
    });
    (port, task)
}

#[tokio::test]
async fn client_shutdown_write_side_can_still_read_without_deadlock() {
    let baseline = leak_check::LeakSnapshot::capture();

    let (echo_port, _echo_task) = harness::spawn_echo_server().await;
    let socks_port = harness::unused_local_port();
    let _instance = Instance::from_config(socks_to_freedom_cfg(socks_port))
        .await
        .expect("start instance");
    tokio::time::sleep(Duration::from_millis(80)).await;

    let mut s = harness::socks5_connect(socks_port, "127.0.0.1", echo_port).await;
    s.write_all(b"half-close").await.expect("write");
    s.shutdown().await.expect("shutdown write");
    let mut out = vec![0u8; 10];
    tokio::time::timeout(Duration::from_secs(2), s.read_exact(&mut out))
        .await
        .expect("read timed out")
        .expect("read");
    assert_eq!(&out, b"half-close");

    leak_check::settle_for_cleanup().await;
    let after = leak_check::LeakSnapshot::capture();
    leak_check::assert_close_to_baseline(&baseline, &after, 256, 128, 80);
}

#[tokio::test]
async fn upstream_shutdown_write_side_first_does_not_hang_relay() {
    let baseline = leak_check::LeakSnapshot::capture();

    let (srv_port, _srv_task) = spawn_upstream_shutdown_write_first().await;
    let socks_port = harness::unused_local_port();
    let _instance = Instance::from_config(socks_to_freedom_cfg(socks_port))
        .await
        .expect("start instance");
    tokio::time::sleep(Duration::from_millis(80)).await;

    let mut s = harness::socks5_connect(socks_port, "127.0.0.1", srv_port).await;
    let mut preface = vec![0u8; "server-preface".len()];
    tokio::time::timeout(Duration::from_secs(2), s.read_exact(&mut preface))
        .await
        .expect("read timed out")
        .expect("read");
    assert_eq!(&preface, b"server-preface");

    let n = tokio::time::timeout(Duration::from_secs(2), s.read(&mut [0u8; 1]))
        .await
        .expect("eof timed out")
        .expect("read");
    assert_eq!(n, 0, "expected EOF after upstream shutdown");

    leak_check::settle_for_cleanup().await;
    let after = leak_check::LeakSnapshot::capture();
    leak_check::assert_close_to_baseline(&baseline, &after, 256, 128, 80);
}

#[tokio::test]
async fn eof_on_one_side_with_pending_bytes_drains_then_closes() {
    let baseline = leak_check::LeakSnapshot::capture();

    let (srv_port, _srv_task) = spawn_delayed_tail_server().await;
    let socks_port = harness::unused_local_port();
    let _instance = Instance::from_config(socks_to_freedom_cfg(socks_port))
        .await
        .expect("start instance");
    tokio::time::sleep(Duration::from_millis(80)).await;

    let mut s = harness::socks5_connect(socks_port, "127.0.0.1", srv_port).await;
    s.write_all(b"PING").await.expect("write");

    let mut out = [0u8; 8];
    tokio::time::timeout(Duration::from_secs(3), s.read_exact(&mut out))
        .await
        .expect("read timed out")
        .expect("read");
    assert_eq!(&out, b"HEADTAIL");

    let n = tokio::time::timeout(Duration::from_secs(2), s.read(&mut [0u8; 1]))
        .await
        .expect("eof timeout")
        .expect("read");
    assert_eq!(n, 0);

    leak_check::settle_for_cleanup().await;
    let after = leak_check::LeakSnapshot::capture();
    leak_check::assert_close_to_baseline(&baseline, &after, 256, 128, 80);
}
