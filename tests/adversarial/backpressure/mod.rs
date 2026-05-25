use std::time::Duration;

use proxy_core::Instance;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[path = "../../common/harness.rs"]
mod harness;
#[path = "../../common/leak_check.rs"]
mod leak_check;

async fn spawn_push_server(total_bytes: usize) -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind push");
    let port = listener.local_addr().expect("push addr").port();
    let task = tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            tokio::spawn(async move {
                let chunk = vec![0x5Au8; 4096];
                let mut left = total_bytes;
                while left > 0 {
                    let n = left.min(chunk.len());
                    if s.write_all(&chunk[..n]).await.is_err() {
                        break;
                    }
                    left -= n;
                }
                let _ = s.shutdown().await;
            });
        }
    });
    (port, task)
}

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

#[tokio::test]
async fn slow_client_reader_does_not_deadlock_or_leak() {
    let baseline = leak_check::LeakSnapshot::capture();

    let pushed = 128 * 1024usize;
    let (upstream_port, _upstream_task) = spawn_push_server(pushed).await;
    let socks_port = harness::unused_local_port();
    let _instance = Instance::from_config(socks_to_freedom_cfg(socks_port))
        .await
        .expect("start instance");

    tokio::time::sleep(Duration::from_millis(80)).await;

    let mut s = harness::socks5_connect(socks_port, "127.0.0.1", upstream_port).await;
    let mut total = 0usize;
    let mut buf = [0u8; 37];

    let read = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let n = s.read(&mut buf).await.expect("read");
            if n == 0 {
                break;
            }
            total += n;
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await;

    assert!(read.is_ok(), "slow reader path timed out");
    assert!(total >= pushed / 2, "expected substantial data flow");

    leak_check::settle_for_cleanup().await;
    let after = leak_check::LeakSnapshot::capture();
    leak_check::assert_close_to_baseline(&baseline, &after, 256, 128, 80);
}

#[tokio::test]
async fn stalled_upstream_reader_large_write_fails_or_times_out_safely() {
    let baseline = leak_check::LeakSnapshot::capture();

    let (upstream_port, _stall_task) = harness::spawn_stalled_reader_server().await;
    let socks_port = harness::unused_local_port();
    let _instance = Instance::from_config(socks_to_freedom_cfg(socks_port))
        .await
        .expect("start instance");
    tokio::time::sleep(Duration::from_millis(80)).await;

    let mut s = harness::socks5_connect(socks_port, "127.0.0.1", upstream_port).await;
    let payload = vec![0xABu8; 2 << 20];

    let res = tokio::time::timeout(Duration::from_secs(3), async {
        let _ = s.write_all(&payload).await;
        let _ = s.flush().await;
    })
    .await;

    assert!(
        res.is_ok(),
        "write path hung under completely stalled peer instead of backpressuring"
    );

    drop(s);
    leak_check::settle_for_cleanup().await;
    let after = leak_check::LeakSnapshot::capture();
    leak_check::assert_close_to_baseline(&baseline, &after, 512, 200, 100);
}

#[tokio::test]
async fn slow_upstream_reader_applies_backpressure_without_unbounded_growth() {
    let baseline = leak_check::LeakSnapshot::capture();

    let (upstream_port, _slow_task) =
        harness::spawn_slow_echo_server(Duration::from_millis(30)).await;
    let socks_port = harness::unused_local_port();
    let _instance = Instance::from_config(socks_to_freedom_cfg(socks_port))
        .await
        .expect("start instance");
    tokio::time::sleep(Duration::from_millis(80)).await;

    let mut s = harness::socks5_connect(socks_port, "127.0.0.1", upstream_port).await;
    let payload = vec![0x11u8; 96 * 1024];
    s.write_all(&payload).await.expect("write payload");
    s.flush().await.expect("flush");

    let mut got = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(8), s.read_exact(&mut got))
        .await
        .expect("slow echo timed out")
        .expect("read_exact");
    assert_eq!(got, payload);

    leak_check::settle_for_cleanup().await;
    let after = leak_check::LeakSnapshot::capture();
    leak_check::assert_close_to_baseline(&baseline, &after, 256, 128, 80);
}
