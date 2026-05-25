use std::time::Duration;

use proxy_core::Instance;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[path = "../../common/harness.rs"]
mod harness;
#[path = "../../common/leak_check.rs"]
mod leak_check;

fn socks_cfg(port: u16) -> std::sync::Arc<proxy_config::schema::Config> {
    harness::parse_config(serde_json::json!({
        "inbounds": [{
            "tag": "socks-in",
            "protocol": "socks",
            "listen": "127.0.0.1",
            "port": port
        }],
        "outbounds": [{
            "tag": "direct",
            "protocol": "freedom"
        }]
    }))
}

#[tokio::test]
async fn spawned_tasks_per_connection_stays_bounded() {
    let baseline = leak_check::LeakSnapshot::capture();
    let (echo_port, _echo) = harness::spawn_echo_server().await;
    let socks_port = harness::unused_local_port();
    let _instance = Instance::from_config(socks_cfg(socks_port))
        .await
        .expect("start");
    tokio::time::sleep(Duration::from_millis(80)).await;

    let mut joins = Vec::new();
    for _ in 0..300usize {
        joins.push(tokio::spawn(async move {
            let mut s = harness::socks5_connect(socks_port, "127.0.0.1", echo_port).await;
            s.write_all(b"p").await.expect("write");
            let mut out = [0u8; 1];
            s.read_exact(&mut out).await.expect("read");
        }));
    }
    for j in joins {
        j.await.expect("join");
    }

    let peak = leak_check::LeakSnapshot::capture();
    assert!(
        peak.task_count <= baseline.task_count + 2500,
        "unexpected task explosion: baseline={}, peak={}",
        baseline.task_count,
        peak.task_count
    );

    leak_check::settle_for_cleanup().await;
    let after = leak_check::LeakSnapshot::capture();
    leak_check::assert_close_to_baseline(&baseline, &after, 512, 300, 120);
}

#[tokio::test]
async fn cancellation_storm_cleans_up_tasks() {
    let baseline = leak_check::LeakSnapshot::capture();
    let (stall_port, _stall) = harness::spawn_stalled_reader_server().await;
    let socks_port = harness::unused_local_port();
    let _instance = Instance::from_config(socks_cfg(socks_port))
        .await
        .expect("start");
    tokio::time::sleep(Duration::from_millis(80)).await;

    let mut conns = Vec::new();
    for _ in 0..200usize {
        let s = harness::socks5_connect(socks_port, "127.0.0.1", stall_port).await;
        conns.push(s);
    }
    for s in conns {
        drop(s);
    }

    leak_check::settle_for_cleanup().await;
    let after = leak_check::LeakSnapshot::capture();
    leak_check::assert_close_to_baseline(&baseline, &after, 768, 320, 140);
}
