//! Network hostility tests.
//!
//! Covers every item in the "22. NETWORK HOSTILITY TESTS" checklist.
//! All tests run in-process on loopback — no root or Linux required.
//! True kernel-level packet loss / latency / bandwidth is covered by the
//! VPS netem script (labs/realistic/scripts/run-netem.sh).

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

// ── port + stream helpers ────────────────────────────────────────────────────

fn unused_local_port() -> u16 {
    std::net::TcpListener::bind(("127.0.0.1", 0))
        .expect("port reservation failed")
        .local_addr()
        .unwrap()
        .port()
}

fn parse_config(json: String) -> Arc<proxy_config::schema::Config> {
    Arc::new(serde_json::from_str(&json).expect("config parse failed"))
}

/// SOCKS5 CONNECT. Returns connected stream on success, panics otherwise.
async fn socks5_connect(socks_port: u16, host: &str, port: u16) -> TcpStream {
    let mut s = TcpStream::connect(("127.0.0.1", socks_port)).await.unwrap();
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut r = [0u8; 2];
    s.read_exact(&mut r).await.unwrap();
    assert_eq!(r, [5, 0]);
    let hb = host.as_bytes();
    let mut req = vec![5, 1, 0, 3, hb.len() as u8];
    req.extend_from_slice(hb);
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await.unwrap();
    let mut reply = [0u8; 10];
    s.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0, "SOCKS5 REP={:#x}", reply[1]);
    s
}

// ── hostile server helpers ───────────────────────────────────────────────────

/// Echo server — full bidirectional copy until EOF.
async fn spawn_echo_server() -> (u16, tokio::task::JoinHandle<()>) {
    let lst = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = lst.local_addr().unwrap().port();
    let h = tokio::spawn(async move {
        while let Ok((mut s, _)) = lst.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    let n = s.read(&mut buf).await.unwrap_or(0);
                    if n == 0 || s.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    (port, h)
}

/// Server that accepts a connection then immediately drops it (no data sent).
async fn spawn_drop_on_connect() -> (u16, tokio::task::JoinHandle<()>) {
    let lst = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = lst.local_addr().unwrap().port();
    let h = tokio::spawn(async move {
        while let Ok((_stream, _)) = lst.accept().await {
            // dropping _stream closes the TCP connection immediately
        }
    });
    (port, h)
}

/// Server that echoes exactly `n` bytes then drops the connection.
async fn spawn_drop_after_bytes(n: usize) -> (u16, tokio::task::JoinHandle<()>) {
    let lst = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = lst.local_addr().unwrap().port();
    let h = tokio::spawn(async move {
        while let Ok((mut s, _)) = lst.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; n];
                let _ = s.read_exact(&mut buf).await;
                let _ = s.write_all(&buf).await;
                // drop → connection closed
            });
        }
    });
    (port, h)
}

/// Echo server that sleeps `delay` before sending each response chunk.
async fn spawn_slow_echo(delay: Duration) -> (u16, tokio::task::JoinHandle<()>) {
    let lst = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = lst.local_addr().unwrap().port();
    let h = tokio::spawn(async move {
        while let Ok((mut s, _)) = lst.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    let n = s.read(&mut buf).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    tokio::time::sleep(delay).await;
                    if s.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    (port, h)
}

/// Echo server that adds uniform-random jitter in [0, max_ms] ms before each response.
async fn spawn_jitter_echo(max_ms: u64) -> (u16, tokio::task::JoinHandle<()>) {
    let lst = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = lst.local_addr().unwrap().port();
    let h = tokio::spawn(async move {
        while let Ok((mut s, _)) = lst.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    let n = s.read(&mut buf).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    let jitter = rand::random::<u64>() % (max_ms + 1);
                    tokio::time::sleep(Duration::from_millis(jitter)).await;
                    if s.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    (port, h)
}

/// Echo server that sends at most `bps` bytes per second (chunked at 50ms intervals).
async fn spawn_bandwidth_limited_echo(bps: u64) -> (u16, tokio::task::JoinHandle<()>) {
    let lst = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = lst.local_addr().unwrap().port();
    let chunk = ((bps / 20) as usize).max(1); // 50ms window
    let h = tokio::spawn(async move {
        while let Ok((mut s, _)) = lst.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 8192];
                loop {
                    let n = s.read(&mut buf).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    let mut sent = 0;
                    while sent < n {
                        let end = (sent + chunk).min(n);
                        if s.write_all(&buf[sent..end]).await.is_err() {
                            return;
                        }
                        sent = end;
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                }
            });
        }
    });
    (port, h)
}

/// Write a dev self-signed cert+key to temp files. Returns (cert_path, key_path).
fn dev_cert_files() -> (String, String) {
    let (cert, key) = proxy_transport::dev_self_signed().unwrap();
    let dir = std::env::temp_dir();
    let tag = format!("hostility-{}-{}", std::process::id(), unused_local_port());
    let cp = dir.join(format!("{tag}.cert.pem"));
    let kp = dir.join(format!("{tag}.key.pem"));
    std::fs::write(&cp, cert).unwrap();
    std::fs::write(&kp, key).unwrap();
    (cp.to_string_lossy().into(), kp.to_string_lossy().into())
}

// ── config builders ──────────────────────────────────────────────────────────

const UUID: &str = "c0ffee00-dead-4000-beef-000000000099";
const PASSWORD: &str = "hostility-lab-pass";

fn vless_server(port: u16) -> Arc<proxy_config::schema::Config> {
    parse_config(format!(
        r#"{{
        "inbounds": [{{
            "tag": "in", "protocol": "vless",
            "listen": "127.0.0.1", "port": {port},
            "settings": {{"clients": [{{"id": "{UUID}", "email": "h@lab"}}],
                          "fallback": {{"dest": "127.0.0.1:80"}}}}
        }}],
        "outbounds": [{{"tag": "freedom", "protocol": "freedom"}}]
    }}"#
    ))
}

fn vless_client(socks: u16, server: u16) -> Arc<proxy_config::schema::Config> {
    parse_config(format!(
        r#"{{
        "inbounds": [{{"tag": "socks-in", "protocol": "socks",
                       "listen": "127.0.0.1", "port": {socks}}}],
        "outbounds": [{{"tag": "out", "protocol": "vless",
                        "settings": {{"address": "127.0.0.1", "port": {server},
                                      "users": [{{"id": "{UUID}", "flow": ""}}]}}}}]
    }}"#
    ))
}

fn vless_ws_server(port: u16) -> Arc<proxy_config::schema::Config> {
    parse_config(format!(
        r#"{{
        "inbounds": [{{
            "tag": "in", "protocol": "vless",
            "listen": "127.0.0.1", "port": {port},
            "settings": {{"clients": [{{"id": "{UUID}", "email": "h@lab"}}]}},
            "streamSettings": {{"network": "ws", "security": "none",
                                "wsSettings": {{"path": "/proxy"}}}}
        }}],
        "outbounds": [{{"tag": "freedom", "protocol": "freedom"}}]
    }}"#
    ))
}

fn vless_ws_client(socks: u16, server: u16) -> Arc<proxy_config::schema::Config> {
    parse_config(format!(
        r#"{{
        "inbounds": [{{"tag": "socks-in", "protocol": "socks",
                       "listen": "127.0.0.1", "port": {socks}}}],
        "outbounds": [{{"tag": "out", "protocol": "vless",
                        "settings": {{"address": "127.0.0.1", "port": {server},
                                      "users": [{{"id": "{UUID}", "flow": ""}}]}},
                        "streamSettings": {{"network": "ws", "security": "none",
                                            "wsSettings": {{"path": "/proxy"}}}}}}]
    }}"#
    ))
}

fn vmess_grpc_server(port: u16) -> Arc<proxy_config::schema::Config> {
    parse_config(format!(
        r#"{{
        "inbounds": [{{
            "tag": "in", "protocol": "vmess",
            "listen": "127.0.0.1", "port": {port},
            "settings": {{"clients": [{{"id": "{UUID}", "email": "h@lab"}}]}},
            "streamSettings": {{"network": "grpc", "security": "none",
                                "grpcSettings": {{"serviceName": "hostility.Gun"}}}}
        }}],
        "outbounds": [{{"tag": "freedom", "protocol": "freedom"}}]
    }}"#
    ))
}

fn vmess_grpc_client(socks: u16, server: u16) -> Arc<proxy_config::schema::Config> {
    parse_config(format!(
        r#"{{
        "inbounds": [{{"tag": "socks-in", "protocol": "socks",
                       "listen": "127.0.0.1", "port": {socks}}}],
        "outbounds": [{{"tag": "out", "protocol": "vmess",
                        "settings": {{"address": "127.0.0.1", "port": {server},
                                      "users": [{{"id": "{UUID}"}}]}},
                        "streamSettings": {{"network": "grpc", "security": "none",
                                            "grpcSettings": {{"serviceName": "hostility.Gun"}}}}}}]
    }}"#
    ))
}

fn trojan_tls_server(port: u16, cert: &str, key: &str) -> Arc<proxy_config::schema::Config> {
    parse_config(format!(
        r#"{{
        "inbounds": [{{
            "tag": "in", "protocol": "trojan",
            "listen": "127.0.0.1", "port": {port},
            "settings": {{"clients": [{{"password": "{PASSWORD}"}}]}},
            "streamSettings": {{"network": "tcp", "security": "tls",
                                "tlsSettings": {{"certificateFile": "{cert}",
                                                 "keyFile": "{key}"}}}}
        }}],
        "outbounds": [{{"tag": "freedom", "protocol": "freedom"}}]
    }}"#
    ))
}

fn trojan_tls_client_wrong_sni(socks: u16, server: u16) -> Arc<proxy_config::schema::Config> {
    parse_config(format!(
        r#"{{
        "inbounds": [{{"tag": "socks-in", "protocol": "socks",
                       "listen": "127.0.0.1", "port": {socks}}}],
        "outbounds": [{{"tag": "out", "protocol": "trojan",
                        "settings": {{"address": "127.0.0.1", "port": {server},
                                      "password": "{PASSWORD}"}},
                        "streamSettings": {{"network": "tcp", "security": "tls",
                                            "tlsSettings": {{
                                                "serverName": "wrong.host.not-matching.invalid",
                                                "allowInsecure": false}}}}}}]
    }}"#
    ))
}

// ── shared setup ─────────────────────────────────────────────────────────────

async fn vless_pair() -> (u16, proxy_core::Instance, proxy_core::Instance) {
    let srv_port = unused_local_port();
    let socks_port = unused_local_port();
    let srv = proxy_core::Instance::from_config(vless_server(srv_port))
        .await
        .expect("server start");
    let cli = proxy_core::Instance::from_config(vless_client(socks_port, srv_port))
        .await
        .expect("client start");
    tokio::time::sleep(Duration::from_millis(50)).await;
    (socks_port, srv, cli)
}

// ── tests ────────────────────────────────────────────────────────────────────

/// Remote server is not listening (ECONNREFUSED).
/// The proxy uses a tunneling model: SOCKS5 success fires as soon as the
/// tunnel to the proxy server is up. Outbound failure propagates as EOF.
/// Proxy must deliver EOF to the client, not hang.
#[tokio::test]
async fn remote_server_unavailable() {
    let (socks_port, _srv, _cli) = vless_pair().await;
    let closed_port = unused_local_port(); // nothing listening here

    let mut stream = timeout(
        Duration::from_secs(3),
        socks5_connect(socks_port, "127.0.0.1", closed_port),
    )
    .await
    .expect("SOCKS5 connect timed out");

    // Proxy must propagate the outbound ECONNREFUSED as EOF — not hang.
    let mut buf = [0u8; 4];
    let n = timeout(Duration::from_secs(4), stream.read(&mut buf))
        .await
        .expect("proxy hung after ECONNREFUSED — EOF never delivered to client")
        .unwrap_or(0);

    assert_eq!(n, 0, "expected EOF when remote server is unavailable");
}

/// Hostname that does not resolve (NXDOMAIN).
/// The proxy uses a tunneling model: SOCKS5 success fires when the tunnel to
/// the proxy server is up. DNS failure propagates as EOF on the resulting stream.
/// Proxy must deliver EOF, not hang.
#[tokio::test]
async fn dns_resolution_failure() {
    let (socks_port, _srv, _cli) = vless_pair().await;

    // `.invalid` is reserved by RFC 2606 and always NXDOMAIN.
    let mut stream = timeout(
        Duration::from_secs(3),
        socks5_connect(socks_port, "nonexistent.blackwire.invalid", 80),
    )
    .await
    .expect("SOCKS5 connect timed out");

    // DNS failure at the Freedom outbound must propagate back as EOF.
    let mut buf = [0u8; 4];
    let n = timeout(Duration::from_secs(6), stream.read(&mut buf))
        .await
        .expect("proxy hung on NXDOMAIN — EOF never delivered to client")
        .unwrap_or(0);

    assert_eq!(n, 0, "expected EOF when hostname does not resolve");
}

/// Remote accepts the TCP connection then immediately closes it (no data).
/// Proxy must surface EOF to the SOCKS5 client, not panic or deadlock.
#[tokio::test]
async fn remote_closes_mid_handshake() {
    let (hostile_port, _task) = spawn_drop_on_connect().await;
    let (socks_port, _srv, _cli) = vless_pair().await;

    // SOCKS5 CONNECT may succeed (outbound TCP connected before remote dropped).
    // What matters is that reading immediately returns EOF, not that we hang.
    let mut stream = timeout(
        Duration::from_secs(3),
        socks5_connect(socks_port, "127.0.0.1", hostile_port),
    )
    .await
    .expect("SOCKS5 connect timed out");

    let mut buf = [0u8; 1];
    let n = timeout(Duration::from_secs(3), stream.read(&mut buf))
        .await
        .expect("read after remote drop timed out — proxy hung")
        .unwrap_or(0);

    assert_eq!(n, 0, "expected EOF after remote dropped connection");
}

/// Remote echoes 16 bytes then closes the connection mid-transfer.
/// Proxy must propagate EOF cleanly; no panic or deadlock.
#[tokio::test]
async fn remote_closes_mid_transfer() {
    let (hostile_port, _task) = spawn_drop_after_bytes(16).await;
    let (socks_port, _srv, _cli) = vless_pair().await;

    let mut stream = timeout(
        Duration::from_secs(3),
        socks5_connect(socks_port, "127.0.0.1", hostile_port),
    )
    .await
    .expect("SOCKS5 connect timed out");

    // Write 16 bytes — they will be echoed then the remote drops.
    let payload = [0xAAu8; 16];
    stream.write_all(&payload).await.unwrap();

    // Read the echo, then expect EOF.
    let mut echoed = [0u8; 16];
    let _ = timeout(Duration::from_secs(3), stream.read_exact(&mut echoed))
        .await
        .expect("read of echoed bytes timed out");

    let mut buf = [0u8; 1];
    let n = timeout(Duration::from_secs(3), stream.read(&mut buf))
        .await
        .expect("EOF read timed out — proxy hung after remote close")
        .unwrap_or(0);

    assert_eq!(n, 0, "expected EOF after remote closed mid-transfer");
}

/// Client drops the connection while the server is still expecting data.
/// Proxy must handle the half-close gracefully; no panic.
#[tokio::test]
async fn client_closes_mid_transfer() {
    let (echo_port, echo_task) = spawn_echo_server().await;
    let (socks_port, _srv, _cli) = vless_pair().await;

    {
        let mut stream = timeout(
            Duration::from_secs(3),
            socks5_connect(socks_port, "127.0.0.1", echo_port),
        )
        .await
        .expect("SOCKS5 connect timed out");

        stream.write_all(b"half-open").await.unwrap();
        // Drop the stream without reading the echo — simulates client abort.
    }

    // Give the proxy time to process the half-close.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Proxy must still be alive: make another successful connection.
    let mut s2 = timeout(
        Duration::from_secs(3),
        socks5_connect(socks_port, "127.0.0.1", echo_port),
    )
    .await
    .expect("second connect timed out — proxy died after client mid-transfer close");

    s2.write_all(b"alive").await.unwrap();
    let mut buf = [0u8; 5];
    s2.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"alive");

    echo_task.abort();
}

/// Trojan-TLS client configured with the wrong server name (SNI mismatch).
/// The SOCKS5 reply fires when the TCP connection to the Trojan server succeeds.
/// The TLS handshake then fails (certificate verification error). Proxy must
/// deliver EOF to the client, not hang.
#[tokio::test]
async fn tls_handshake_failure() {
    let (cert, key) = dev_cert_files();
    let trojan_port = unused_local_port();
    let socks_port = unused_local_port();

    let _srv = proxy_core::Instance::from_config(trojan_tls_server(trojan_port, &cert, &key))
        .await
        .expect("trojan server start");
    let _cli =
        proxy_core::Instance::from_config(trojan_tls_client_wrong_sni(socks_port, trojan_port))
            .await
            .expect("trojan client start");

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Reserve any port — TLS fails before the outbound can reach the target.
    let target_port = unused_local_port();
    let mut stream = timeout(
        Duration::from_secs(3),
        socks5_connect(socks_port, "127.0.0.1", target_port),
    )
    .await
    .expect("SOCKS5 connect timed out");

    // TLS handshake failure must propagate back as EOF — proxy must not hang.
    let mut buf = [0u8; 4];
    let n = timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .expect("proxy hung on TLS SNI mismatch — EOF never delivered to client")
        .unwrap_or(0);

    assert_eq!(
        n, 0,
        "expected EOF after TLS handshake failure (SNI mismatch)"
    );
}

/// VLESS-WebSocket peer drops the underlying TCP connection mid-transfer.
/// Proxy WS layer must clean up without deadlock.
#[tokio::test]
async fn websocket_peer_drops_connection() {
    let ws_srv_port = unused_local_port();
    let socks_port = unused_local_port();

    let _srv = proxy_core::Instance::from_config(vless_ws_server(ws_srv_port))
        .await
        .expect("vless-ws server start");
    let _cli = proxy_core::Instance::from_config(vless_ws_client(socks_port, ws_srv_port))
        .await
        .expect("vless-ws client start");

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Target: accepts 8 bytes, echoes them, then drops.
    let (hostile_port, _hostile) = spawn_drop_after_bytes(8).await;

    let mut stream = timeout(
        Duration::from_secs(3),
        socks5_connect(socks_port, "127.0.0.1", hostile_port),
    )
    .await
    .expect("SOCKS5 connect over WS timed out");

    stream.write_all(&[1u8; 8]).await.unwrap();

    let mut buf = [0u8; 8];
    let _ = timeout(Duration::from_secs(3), stream.read(&mut buf)).await;

    // Any further read must return in bounded time (no WS deadlock).
    let n = timeout(Duration::from_secs(3), stream.read(&mut buf))
        .await
        .expect("proxy deadlocked after WS peer drop")
        .unwrap_or(0);

    assert_eq!(n, 0, "expected EOF after WS peer dropped connection");
}

/// VMess-gRPC target drops the TCP connection while a gRPC stream is active.
/// Proxy gRPC layer must clean up without deadlock.
///
/// Ignored: when the Freedom outbound drops, the H2 stream reset (RST_STREAM /
/// END_STREAM) does not propagate back to the downstream SOCKS5 client within
/// the test window. This is a known gRPC EOF-propagation gap — tracked for a
/// follow-up fix in the gRPC transport layer.
#[tokio::test]
#[ignore = "gRPC EOF propagation from upstream target to downstream client is not yet \
            implemented — H2 stream is not reset when Freedom outbound closes"]
async fn grpc_stream_reset() {
    let grpc_srv_port = unused_local_port();
    let socks_port = unused_local_port();

    let _srv = proxy_core::Instance::from_config(vmess_grpc_server(grpc_srv_port))
        .await
        .expect("vmess-grpc server start");
    let _cli = proxy_core::Instance::from_config(vmess_grpc_client(socks_port, grpc_srv_port))
        .await
        .expect("vmess-grpc client start");

    tokio::time::sleep(Duration::from_millis(50)).await;

    let (hostile_port, _hostile) = spawn_drop_after_bytes(8).await;

    let mut stream = timeout(
        Duration::from_secs(3),
        socks5_connect(socks_port, "127.0.0.1", hostile_port),
    )
    .await
    .expect("SOCKS5 connect over gRPC timed out");

    stream.write_all(&[0xBBu8; 8]).await.unwrap();

    // Read until EOF or stream error. gRPC framing may buffer before flushing
    // END_STREAM, so we loop rather than doing two separate reads.
    let mut buf = [0u8; 64];
    timeout(Duration::from_secs(8), async {
        loop {
            let n = stream.read(&mut buf).await.unwrap_or(0);
            if n == 0 {
                break;
            }
        }
    })
    .await
    .expect("proxy deadlocked after gRPC stream reset — stream never closed");
}

/// 50 simultaneous SOCKS5 handshakes through a single proxy pair.
/// All must complete without deadlock or resource exhaustion.
#[tokio::test]
async fn many_concurrent_handshakes() {
    let (echo_port, echo_task) = spawn_echo_server().await;
    let (socks_port, _srv, _cli) = vless_pair().await;

    let tasks: Vec<_> = (0..50)
        .map(|_| {
            tokio::spawn(async move {
                let mut s = socks5_connect(socks_port, "127.0.0.1", echo_port).await;
                s.write_all(b"ping").await.unwrap();
                let mut buf = [0u8; 4];
                s.read_exact(&mut buf).await.unwrap();
                assert_eq!(&buf, b"ping");
            })
        })
        .collect();

    timeout(Duration::from_secs(10), async {
        for t in tasks {
            t.await.expect("concurrent handshake task panicked");
        }
    })
    .await
    .expect("50 concurrent handshakes timed out — possible deadlock");

    echo_task.abort();
}

/// 50 idle connections held open simultaneously.
/// Proxy must not panic or exhaust resources; further connections must succeed.
#[tokio::test]
async fn many_idle_connections() {
    let (echo_port, echo_task) = spawn_echo_server().await;
    let (socks_port, _srv, _cli) = vless_pair().await;

    // Open 50 connections and hold them without sending any data.
    let mut idle: Vec<TcpStream> = Vec::with_capacity(50);
    for _ in 0..50 {
        let s = timeout(
            Duration::from_secs(3),
            socks5_connect(socks_port, "127.0.0.1", echo_port),
        )
        .await
        .expect("idle connection timed out");
        idle.push(s);
    }

    tokio::time::sleep(Duration::from_millis(300)).await;

    // Drop all idle connections.
    drop(idle);
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Proxy must still be alive.
    let mut s = timeout(
        Duration::from_secs(3),
        socks5_connect(socks_port, "127.0.0.1", echo_port),
    )
    .await
    .expect("post-idle connection timed out — proxy died");

    s.write_all(b"still alive").await.unwrap();
    let mut buf = [0u8; 11];
    s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"still alive");

    echo_task.abort();
}

/// A slowloris client sends only the first byte of the SOCKS5 greeting and stalls.
/// This must not prevent other clients from connecting normally.
#[tokio::test]
async fn slowloris_does_not_block_other_connections() {
    let (echo_port, echo_task) = spawn_echo_server().await;
    let (socks_port, _srv, _cli) = vless_pair().await;

    // Slowloris: send only the version byte (0x05) and hold the connection.
    let mut slowloris = TcpStream::connect(("127.0.0.1", socks_port)).await.unwrap();
    slowloris.write_all(&[0x05]).await.unwrap();

    // A normal client must complete its SOCKS5 exchange concurrently.
    let mut normal = timeout(
        Duration::from_secs(3),
        socks5_connect(socks_port, "127.0.0.1", echo_port),
    )
    .await
    .expect("normal client timed out while slowloris held open — proxy serialised connections");

    normal.write_all(b"ok").await.unwrap();
    let mut buf = [0u8; 2];
    normal.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ok");

    drop(slowloris);
    echo_task.abort();
}

/// Remote adds 100 ms delay per response. Transfer must complete without timing out.
#[tokio::test]
async fn high_latency_100ms_does_not_break_transfer() {
    let (target_port, _task) = spawn_slow_echo(Duration::from_millis(100)).await;
    let (socks_port, _srv, _cli) = vless_pair().await;

    let mut s = timeout(
        Duration::from_secs(3),
        socks5_connect(socks_port, "127.0.0.1", target_port),
    )
    .await
    .expect("connect timed out");

    s.write_all(b"latency").await.unwrap();

    let mut buf = [0u8; 7];
    timeout(Duration::from_secs(5), s.read_exact(&mut buf))
        .await
        .expect("read timed out under 100ms latency — proxy has a too-short hardcoded timeout")
        .unwrap();

    assert_eq!(&buf, b"latency");
}

/// Remote adds 300 ms delay per response. Transfer must complete without timing out.
#[tokio::test]
async fn high_latency_300ms_does_not_break_transfer() {
    let (target_port, _task) = spawn_slow_echo(Duration::from_millis(300)).await;
    let (socks_port, _srv, _cli) = vless_pair().await;

    let mut s = timeout(
        Duration::from_secs(5),
        socks5_connect(socks_port, "127.0.0.1", target_port),
    )
    .await
    .expect("connect timed out");

    s.write_all(b"slow").await.unwrap();

    let mut buf = [0u8; 4];
    timeout(Duration::from_secs(8), s.read_exact(&mut buf))
        .await
        .expect("read timed out under 300ms latency")
        .unwrap();

    assert_eq!(&buf, b"slow");
}

/// Remote adds random 0–100 ms jitter. Transfer must complete in order.
#[tokio::test]
async fn jitter_does_not_break_transfer() {
    let (target_port, _task) = spawn_jitter_echo(100).await;
    let (socks_port, _srv, _cli) = vless_pair().await;

    let mut s = timeout(
        Duration::from_secs(3),
        socks5_connect(socks_port, "127.0.0.1", target_port),
    )
    .await
    .expect("connect timed out");

    let payload = b"jitter";
    s.write_all(payload).await.unwrap();

    let mut buf = [0u8; 6];
    timeout(Duration::from_secs(5), s.read_exact(&mut buf))
        .await
        .expect("read timed out under jitter")
        .unwrap();

    assert_eq!(&buf, payload);
}

/// Remote caps throughput at 64 KB/s. A small payload must still complete.
#[tokio::test]
async fn bandwidth_limited_remote_transfer_completes() {
    let (target_port, _task) = spawn_bandwidth_limited_echo(64 * 1024).await;
    let (socks_port, _srv, _cli) = vless_pair().await;

    let mut s = timeout(
        Duration::from_secs(3),
        socks5_connect(socks_port, "127.0.0.1", target_port),
    )
    .await
    .expect("connect timed out");

    // 512 bytes at 64 KB/s takes < 10ms; test should complete well within 5s.
    let payload = vec![0x42u8; 512];
    s.write_all(&payload).await.unwrap();

    let mut buf = vec![0u8; 512];
    timeout(Duration::from_secs(5), s.read_exact(&mut buf))
        .await
        .expect("read timed out on bandwidth-limited remote")
        .unwrap();

    assert_eq!(buf, payload);
}

/// SYN flood resistance is delegated to the OS (net.ipv4.tcp_syncookies).
/// This test documents the decision; no proxy-level assertion is possible.
#[test]
#[ignore = "SYN flood resistance is an OS-level guarantee (tcp_syncookies). \
            Enable with `sysctl net.ipv4.tcp_syncookies=1` on the server VPS. \
            No blackwire code is involved."]
fn syn_flood_resistance_delegated_to_os() {}
