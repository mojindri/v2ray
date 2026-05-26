//! Health-check balancer failover under realistic Instance wiring.
//!
//! Topology:
//!
//!   SOCKS client
//!     -> routing selects `auto-proxy` balancer
//!     -> `primary-vless` (broken upstream) marked dead by HTTP probes
//!     -> `backup-freedom` (healthy) carries user traffic to echo target
//!
//! Health probes dial the configured `http://…` URL **through each member
//! outbound**. A broken VLESS upstream fails probes; freedom reaches the local
//! health HTTP server and stays alive.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const TEST_UUID: &str = "a3482e88-686a-4a58-8126-99c9df64b7bf";

fn unused_local_port() -> u16 {
    std::net::TcpListener::bind(("127.0.0.1", 0))
        .expect("failed to reserve local port")
        .local_addr()
        .unwrap()
        .port()
}

fn parse_config(json: String) -> Arc<blackwire_config::schema::Config> {
    Arc::new(serde_json::from_str(&json).expect("config parse failed"))
}

async fn spawn_http_204_server() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("health server bind failed");
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 512];
                let _ = stream.read(&mut buf).await;
                let _ = stream
                    .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                    .await;
            });
        }
    });
    (port, task)
}

async fn spawn_echo_server() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("echo server bind failed");
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    let Ok(n) = stream.read(&mut buf).await else {
                        break;
                    };
                    if n == 0 {
                        break;
                    }
                    if stream.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    (port, task)
}

async fn socks5_connect(socks_port: u16, dest_host: &str, dest_port: u16) -> TcpStream {
    let mut stream = TcpStream::connect(("127.0.0.1", socks_port))
        .await
        .expect("failed to connect to SOCKS5 proxy");

    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp, [5, 0]);

    let host_bytes = dest_host.as_bytes();
    let mut req = vec![5, 1, 0, 3, host_bytes.len() as u8];
    req.extend_from_slice(host_bytes);
    req.extend_from_slice(&dest_port.to_be_bytes());
    stream.write_all(&req).await.unwrap();

    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0, "SOCKS5 CONNECT failed: REP={:#x}", reply[1]);

    stream
}

fn failover_config(
    socks_port: u16,
    health_port: u16,
    bad_vless_port: u16,
) -> Arc<blackwire_config::schema::Config> {
    parse_config(format!(
        r#"{{
            "inbounds": [{{
                "tag": "socks-in",
                "protocol": "socks",
                "listen": "127.0.0.1",
                "port": {socks_port}
            }}],
            "outbounds": [
                {{
                    "tag": "primary-vless",
                    "protocol": "vless",
                    "settings": {{
                        "address": "127.0.0.1",
                        "port": {bad_vless_port},
                        "users": [{{ "id": "{TEST_UUID}", "flow": "" }}]
                    }}
                }},
                {{
                    "tag": "backup-freedom",
                    "protocol": "freedom"
                }}
            ],
            "routing": {{
                "balancers": [{{
                    "tag": "auto-proxy",
                    "selector": ["primary-vless", "backup-freedom"],
                    "strategy": "latency",
                    "health_check": {{
                        "url": "http://127.0.0.1:{health_port}/generate_204",
                        "interval_secs": 1,
                        "timeout_secs": 1,
                        "max_failures": 2
                    }}
                }}],
                "rules": [{{
                    "type": "field",
                    "outboundTag": "auto-proxy"
                }}]
            }}
        }}"#
    ))
}

async fn echo_once(socks_port: u16, echo_port: u16, payload: &[u8]) {
    let mut stream = socks5_connect(socks_port, "127.0.0.1", echo_port).await;
    stream.write_all(payload).await.unwrap();
    let mut echoed = vec![0u8; payload.len()];
    stream.read_exact(&mut echoed).await.unwrap();
    assert_eq!(echoed, payload);
}

async fn run_failover_scenario(
    use_external_health_port: Option<u16>,
    use_external_echo_port: Option<u16>,
) {
    let (health_port, health_task) = match use_external_health_port {
        Some(port) => (port, tokio::spawn(async {})),
        None => spawn_http_204_server().await,
    };
    let (echo_port, echo_task) = match use_external_echo_port {
        Some(port) => (port, tokio::spawn(async {})),
        None => spawn_echo_server().await,
    };

    let socks_port = unused_local_port();
    let bad_vless_port = unused_local_port();

    let config = failover_config(socks_port, health_port, bad_vless_port);
    let _instance = blackwire_core::Instance::from_config(config)
        .await
        .expect("instance start failed");

    // Allow two probe rounds so primary-vless is marked dead (interval=1, max_failures=2).
    tokio::time::sleep(Duration::from_secs(3)).await;

    echo_once(socks_port, echo_port, b"failover-path-ok").await;

    for i in 0..5 {
        let msg = format!("failover-{i}");
        echo_once(socks_port, echo_port, msg.as_bytes()).await;
    }

    health_task.abort();
    echo_task.abort();
}

#[tokio::test]
async fn health_failover_routes_to_backup_when_primary_unhealthy() {
    run_failover_scenario(None, None).await;
}

#[tokio::test]
#[ignore = "requires Docker lab services; run via make -C labs/realistic health-failover"]
async fn health_failover_docker_lab_services() {
    let health_port = std::env::var("HEALTH_PROBE_PORT")
        .expect("HEALTH_PROBE_PORT must be set for docker lab test");
    let echo_port = std::env::var("ECHO_PORT").expect("ECHO_PORT must be set for docker lab test");
    run_failover_scenario(
        Some(health_port.parse().expect("HEALTH_PROBE_PORT")),
        Some(echo_port.parse().expect("ECHO_PORT")),
    )
    .await;
}
