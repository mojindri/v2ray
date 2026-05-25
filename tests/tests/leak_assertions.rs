use std::time::Duration;

use proxy_core::Instance;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[path = "../common/harness.rs"]
mod harness;
#[path = "../common/leak_check.rs"]
mod leak_check;

#[tokio::test]
async fn e2e_connections_return_to_resource_baseline() {
    let baseline = leak_check::LeakSnapshot::capture();

    let (echo_port, _echo_task) = harness::spawn_echo_server().await;
    let socks_port = harness::unused_local_port();
    let cfg = harness::parse_config(serde_json::json!({
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
    }));

    let _instance = Instance::from_config(cfg).await.expect("start");
    tokio::time::sleep(Duration::from_millis(80)).await;

    for _ in 0..128usize {
        let mut s = harness::socks5_connect(socks_port, "127.0.0.1", echo_port).await;
        s.write_all(b"ping").await.expect("write");
        let mut out = [0u8; 4];
        s.read_exact(&mut out).await.expect("read");
        assert_eq!(&out, b"ping");
    }

    leak_check::settle_for_cleanup().await;
    let after = leak_check::LeakSnapshot::capture();
    leak_check::assert_close_to_baseline(&baseline, &after, 512, 200, 100);
}
