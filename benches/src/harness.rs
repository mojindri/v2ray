//! Shared perf-bench harness.
//!
//! Each bench binary creates a `ProxyPair` once (outside the measured loop),
//! then drives traffic through it inside `iter_custom`. The instances keep
//! running for the whole bench run so TCP listener startup cost is excluded
//! from measurements.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Runtime;

// ── UUIDs / passwords ─────────────────────────────────────────────────────────

pub const VLESS_UUID: &str = "a3482e88-686a-4a58-8126-99c9df64b7bf";
pub const VMESS_UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
pub const TROJAN_PASS: &str = "bench-trojan-password";
pub const SS_PASSWORD: &str = "bench-ss2022-password";
pub const GRPC_SERVICE: &str = "bench.Gun";

fn io_timeout() -> Duration {
    std::env::var("BENCH_IO_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|ms| *ms > 0)
        .map(Duration::from_millis)
        .unwrap_or_else(|| Duration::from_secs(5))
}

// ── Port helpers ───────────────────────────────────────────────────────────────

pub fn unused_port() -> u16 {
    std::net::TcpListener::bind(("127.0.0.1", 0))
        .expect("port reserve")
        .local_addr()
        .expect("port addr")
        .port()
}

// ── Echo server ────────────────────────────────────────────────────────────────

pub async fn spawn_echo_server() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("echo bind");
    let port = listener.local_addr().expect("echo addr").port();
    let task = tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 65536];
                loop {
                    let n = s.read(&mut buf).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    if s.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    (port, task)
}

// ── SOCKS5 client helper ───────────────────────────────────────────────────────

pub async fn socks5_connect(socks_port: u16, host: &str, port: u16) -> TcpStream {
    let mut s = TcpStream::connect(("127.0.0.1", socks_port))
        .await
        .expect("socks connect");
    s.write_all(&[5, 1, 0]).await.expect("socks greet");
    let mut g = [0u8; 2];
    s.read_exact(&mut g).await.expect("socks greet reply");
    assert_eq!(g, [5, 0]);
    let hb = host.as_bytes();
    let mut req = vec![5, 1, 0, 3, hb.len() as u8];
    req.extend_from_slice(hb);
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await.expect("socks req");
    let mut rep = [0u8; 10];
    s.read_exact(&mut rep).await.expect("socks rep");
    assert_eq!(rep[1], 0, "SOCKS5 REP={:#x}", rep[1]);
    s
}

// ── Transfer helpers ───────────────────────────────────────────────────────────

/// Send `payload` through `stream` and read back the exact echo. Measures one
/// round-trip (write + full read-back). Returns elapsed wall time.
pub async fn echo_transfer(stream: &mut TcpStream, payload: &[u8]) {
    tokio::time::timeout(io_timeout(), stream.write_all(payload))
        .await
        .unwrap_or_else(|_| {
            panic!(
                "bench stage timeout: echo_transfer/write len={}",
                payload.len()
            )
        })
        .expect("write");
    let mut buf = vec![0u8; payload.len()];
    tokio::time::timeout(io_timeout(), stream.read_exact(&mut buf))
        .await
        .unwrap_or_else(|_| {
            panic!(
                "bench stage timeout: echo_transfer/read len={}",
                payload.len()
            )
        })
        .expect("read");
}

/// Open a new SOCKS5-proxied connection, transfer `payload`, close.
/// Used for short-lived-connection benchmarks (one connection per iteration).
pub async fn one_shot(socks_port: u16, echo_port: u16, payload: &[u8]) {
    let mut s = socks5_connect(socks_port, "127.0.0.1", echo_port).await;
    echo_transfer(&mut s, payload).await;
}

// ── ProxyPair ──────────────────────────────────────────────────────────────────

/// A running server + client proxy pair and a background echo server.
///
/// Create once per bench group. The proxy instances stay alive for the full
/// group run, so listener-bind cost is not included in measurements.
pub struct ProxyPair {
    pub proxy_port: u16,
    pub echo_port: u16,
    pub uses_http_connect: bool,
    // Keep instances alive for the duration of the bench.
    _server: blackwire_core::Instance,
    _client: blackwire_core::Instance,
    _echo_task: tokio::task::JoinHandle<()>,
}

impl ProxyPair {
    pub async fn new(
        server_cfg: Arc<blackwire_config::schema::Config>,
        client_cfg: Arc<blackwire_config::schema::Config>,
    ) -> Self {
        let (echo_port, echo_task) = spawn_echo_server().await;

        let server = blackwire_core::Instance::from_config(server_cfg)
            .await
            .expect("server start");
        let client = blackwire_core::Instance::from_config(client_cfg)
            .await
            .expect("client start");

        // Give listeners a moment to accept before the bench loop starts.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Read socks_port from the client config after startup via the known
        // field; we pass it in directly through the config builders below.
        // This field is populated by the caller.
        Self {
            proxy_port: 0, // set by `with_proxy_port`
            echo_port,
            uses_http_connect: false,
            _server: server,
            _client: client,
            _echo_task: echo_task,
        }
    }

    pub fn with_proxy_port(mut self, port: u16, http_connect: bool) -> Self {
        self.proxy_port = port;
        self.uses_http_connect = http_connect;
        self
    }

    /// Open a proxied connection to the echo server (SOCKS5 or HTTP CONNECT).
    pub async fn connect(&self) -> TcpStream {
        if self.uses_http_connect {
            http_connect(self.proxy_port, "127.0.0.1", self.echo_port).await
        } else {
            socks5_connect(self.proxy_port, "127.0.0.1", self.echo_port).await
        }
    }
}

// ── Config builders ────────────────────────────────────────────────────────────

fn cfg(json: String) -> Arc<blackwire_config::schema::Config> {
    Arc::new(serde_json::from_str(&json).expect("config parse"))
}

fn sniff_block(sniffing: bool) -> &'static str {
    if sniffing {
        r#",
                "sniffing": {
                    "enabled": true,
                    "destOverride": ["http", "tls"]
                }"#
    } else {
        ""
    }
}

// VLESS over plain TCP

pub fn vless_tcp_server(port: u16) -> Arc<blackwire_config::schema::Config> {
    cfg(format!(
        r#"{{
            "inbounds": [{{
                "tag": "vless-in",
                "protocol": "vless",
                "listen": "127.0.0.1",
                "port": {port},
                "settings": {{
                    "clients": [{{"id": "{VLESS_UUID}", "email": "bench@bench"}}]
                }}
            }}],
            "outbounds": [{{"tag": "freedom", "protocol": "freedom"}}],
            "routing": {{"rules": [{{"outboundTag": "freedom"}}]}}
        }}"#
    ))
}

pub fn vless_tcp_client(
    socks_port: u16,
    server_port: u16,
    sniffing: bool,
) -> Arc<blackwire_config::schema::Config> {
    let sniff = sniff_block(sniffing);
    cfg(format!(
        r#"{{
            "inbounds": [{{
                "tag": "socks-in",
                "protocol": "socks",
                "listen": "127.0.0.1",
                "port": {socks_port}
                {sniff}
            }}],
            "outbounds": [{{
                "tag": "vless-out",
                "protocol": "vless",
                "settings": {{
                    "address": "127.0.0.1",
                    "port": {server_port},
                    "users": [{{"id": "{VLESS_UUID}", "flow": ""}}]
                }}
            }}],
            "routing": {{"rules": [{{"outboundTag": "vless-out"}}]}}
        }}"#
    ))
}

// VLESS over WebSocket

pub fn vless_ws_server(port: u16) -> Arc<blackwire_config::schema::Config> {
    cfg(format!(
        r#"{{
            "inbounds": [{{
                "tag": "vless-ws-in",
                "protocol": "vless",
                "listen": "127.0.0.1",
                "port": {port},
                "settings": {{
                    "clients": [{{"id": "{VLESS_UUID}", "email": "bench@bench"}}]
                }},
                "streamSettings": {{
                    "network": "ws",
                    "security": "none",
                    "wsSettings": {{"path": "/bench"}}
                }}
            }}],
            "outbounds": [{{"tag": "freedom", "protocol": "freedom"}}],
            "routing": {{"rules": [{{"outboundTag": "freedom"}}]}}
        }}"#
    ))
}

pub fn vless_ws_client(
    socks_port: u16,
    server_port: u16,
    sniffing: bool,
) -> Arc<blackwire_config::schema::Config> {
    let sniff = sniff_block(sniffing);
    cfg(format!(
        r#"{{
            "inbounds": [{{
                "tag": "socks-in",
                "protocol": "socks",
                "listen": "127.0.0.1",
                "port": {socks_port}
                {sniff}
            }}],
            "outbounds": [{{
                "tag": "vless-ws-out",
                "protocol": "vless",
                "settings": {{
                    "address": "127.0.0.1",
                    "port": {server_port},
                    "users": [{{"id": "{VLESS_UUID}", "flow": ""}}]
                }},
                "streamSettings": {{
                    "network": "ws",
                    "security": "none",
                    "wsSettings": {{"path": "/bench", "host": "127.0.0.1"}}
                }}
            }}],
            "routing": {{"rules": [{{"outboundTag": "vless-ws-out"}}]}}
        }}"#
    ))
}

// VMess over gRPC

pub fn vmess_grpc_server(port: u16) -> Arc<blackwire_config::schema::Config> {
    cfg(format!(
        r#"{{
            "inbounds": [{{
                "tag": "vmess-grpc-in",
                "protocol": "vmess",
                "listen": "127.0.0.1",
                "port": {port},
                "settings": {{
                    "clients": [{{"id": "{VMESS_UUID}", "email": "bench@bench"}}]
                }},
                "streamSettings": {{
                    "network": "grpc",
                    "security": "none",
                    "grpcSettings": {{"serviceName": "{GRPC_SERVICE}"}}
                }}
            }}],
            "outbounds": [{{"tag": "freedom", "protocol": "freedom"}}],
            "routing": {{"rules": [{{"outboundTag": "freedom"}}]}}
        }}"#
    ))
}

/// Client uses HTTP CONNECT ingress (matches `e2e_http_vmess_grpc`).
pub fn vmess_grpc_client(
    http_port: u16,
    server_port: u16,
    sniffing: bool,
) -> Arc<blackwire_config::schema::Config> {
    let sniff = if sniffing {
        r#",
                "sniffing": {
                    "enabled": true,
                    "destOverride": ["http", "tls"]
                }"#
    } else {
        ""
    };
    cfg(format!(
        r#"{{
            "inbounds": [{{
                "tag": "http-in",
                "protocol": "http",
                "listen": "127.0.0.1",
                "port": {http_port}
                {sniff}
            }}],
            "outbounds": [{{
                "tag": "vmess-grpc-out",
                "protocol": "vmess",
                "settings": {{
                    "address": "127.0.0.1",
                    "port": {server_port},
                    "users": [{{"id": "{VMESS_UUID}"}}]
                }},
                "streamSettings": {{
                    "network": "grpc",
                    "security": "none",
                    "grpcSettings": {{"serviceName": "{GRPC_SERVICE}"}}
                }}
            }}],
            "routing": {{"rules": [{{"outboundTag": "vmess-grpc-out"}}]}}
        }}"#
    ))
}

// SS2022

pub fn ss2022_server(port: u16) -> Arc<blackwire_config::schema::Config> {
    cfg(format!(
        r#"{{
            "inbounds": [{{
                "tag": "ss2022-in",
                "protocol": "shadowsocks",
                "listen": "127.0.0.1",
                "port": {port},
                "settings": {{
                    "method": "2022-blake3-aes-256-gcm",
                    "password": "{SS_PASSWORD}"
                }}
            }}],
            "outbounds": [{{"tag": "freedom", "protocol": "freedom"}}],
            "routing": {{"rules": [{{"outboundTag": "freedom"}}]}}
        }}"#
    ))
}

pub fn ss2022_client(
    socks_port: u16,
    server_port: u16,
    sniffing: bool,
) -> Arc<blackwire_config::schema::Config> {
    let sniff = sniff_block(sniffing);
    cfg(format!(
        r#"{{
            "inbounds": [{{
                "tag": "socks-in",
                "protocol": "socks",
                "listen": "127.0.0.1",
                "port": {socks_port}
                {sniff}
            }}],
            "outbounds": [{{
                "tag": "ss2022-out",
                "protocol": "shadowsocks",
                "settings": {{
                    "address": "127.0.0.1",
                    "port": {server_port},
                    "method": "2022-blake3-aes-256-gcm",
                    "password": "{SS_PASSWORD}"
                }}
            }}],
            "routing": {{"rules": [{{"outboundTag": "ss2022-out"}}]}}
        }}"#
    ))
}

// Trojan plain TCP

pub fn trojan_tcp_server(port: u16) -> Arc<blackwire_config::schema::Config> {
    cfg(format!(
        r#"{{
            "inbounds": [{{
                "tag": "trojan-in",
                "protocol": "trojan",
                "listen": "127.0.0.1",
                "port": {port},
                "settings": {{
                    "clients": [{{"password": "{TROJAN_PASS}"}}]
                }}
            }}],
            "outbounds": [{{"tag": "freedom", "protocol": "freedom"}}],
            "routing": {{"rules": [{{"outboundTag": "freedom"}}]}}
        }}"#
    ))
}

pub fn trojan_tcp_client(
    socks_port: u16,
    server_port: u16,
    sniffing: bool,
) -> Arc<blackwire_config::schema::Config> {
    let sniff = sniff_block(sniffing);
    cfg(format!(
        r#"{{
            "inbounds": [{{
                "tag": "socks-in",
                "protocol": "socks",
                "listen": "127.0.0.1",
                "port": {socks_port}
                {sniff}
            }}],
            "outbounds": [{{
                "tag": "trojan-out",
                "protocol": "trojan",
                "settings": {{
                    "address": "127.0.0.1",
                    "port": {server_port},
                    "password": "{TROJAN_PASS}"
                }}
            }}],
            "routing": {{"rules": [{{"outboundTag": "trojan-out"}}]}}
        }}"#
    ))
}

// ── HTTP CONNECT client (VMess gRPC chain) ─────────────────────────────────────

pub async fn http_connect(proxy_port: u16, host: &str, port: u16) -> TcpStream {
    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port))
        .await
        .expect("http proxy connect");

    let req = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n");
    stream
        .write_all(req.as_bytes())
        .await
        .expect("http connect write");

    let mut response = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        stream.read_exact(&mut byte).await.expect("http response");
        response.push(byte[0]);
        if response.ends_with(b"\r\n\r\n") {
            break;
        }
        if response.len() > 512 {
            panic!("HTTP CONNECT response too long");
        }
    }

    let text = String::from_utf8_lossy(&response);
    assert!(
        text.starts_with("HTTP/1.1 200"),
        "unexpected HTTP CONNECT: {text:?}"
    );

    stream
}

// ── Protocol path ─────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ProtocolPath {
    VlessTcp,
    VlessWs,
    VmessGrpc,
    Ss2022,
    TrojanTcp,
}

impl ProtocolPath {
    pub fn bench_name(self) -> &'static str {
        match self {
            Self::VlessTcp => "vless_tcp",
            Self::VlessWs => "vless_ws",
            Self::VmessGrpc => "vmess_grpc",
            Self::Ss2022 => "ss2022",
            Self::TrojanTcp => "trojan_tcp",
        }
    }

    pub fn uses_http_connect(self) -> bool {
        matches!(self, Self::VmessGrpc)
    }

    pub async fn setup(self, sniffing: bool) -> ProxyPair {
        let server_port = unused_port();
        let proxy_port = unused_port();

        let (server_cfg, client_cfg) = match self {
            Self::VlessTcp => (
                vless_tcp_server(server_port),
                vless_tcp_client(proxy_port, server_port, sniffing),
            ),
            Self::VlessWs => (
                vless_ws_server(server_port),
                vless_ws_client(proxy_port, server_port, sniffing),
            ),
            Self::VmessGrpc => (
                vmess_grpc_server(server_port),
                vmess_grpc_client(proxy_port, server_port, sniffing),
            ),
            Self::Ss2022 => (
                ss2022_server(server_port),
                ss2022_client(proxy_port, server_port, sniffing),
            ),
            Self::TrojanTcp => (
                trojan_tcp_server(server_port),
                trojan_tcp_client(proxy_port, server_port, sniffing),
            ),
        };

        ProxyPair::new(server_cfg, client_cfg)
            .await
            .with_proxy_port(proxy_port, self.uses_http_connect())
    }
}

// ── Relay workloads ─────────────────────────────────────────────────────────────

pub async fn relay_bulk(stream: &mut TcpStream, total_bytes: usize, chunk_size: usize) -> usize {
    let chunk_size = chunk_size.max(1).min(total_bytes);
    let chunk = vec![0xCDu8; chunk_size];
    let mut buf = vec![0u8; chunk_size];

    // Interleave write+read in round-trip chunks to avoid H2 flow-control deadlocks
    // that occur when we try to write all bytes before reading any back.
    let mut done = 0usize;
    while done < total_bytes {
        let n = chunk_size.min(total_bytes - done);
        tokio::time::timeout(io_timeout(), stream.write_all(&chunk[..n]))
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "bench stage timeout: relay_bulk/write n={n} done={done} total={total_bytes}"
                )
            })
            .expect("bulk write");
        let mut got = 0usize;
        while got < n {
            let read_fut = stream.read(&mut buf[got..n]);
            let read_n = tokio::time::timeout(io_timeout(), read_fut)
                .await
                .unwrap_or_else(|_| {
                    panic!(
                        "bench stage timeout: relay_bulk/read n={n} got={got} done={done} total={total_bytes}"
                    )
                })
                .expect("bulk read");
            if read_n == 0 {
                panic!(
                    "bench stage eof: relay_bulk/read n={n} got={got} done={done} total={total_bytes}"
                );
            }
            got += read_n;
        }
        done += n;
    }
    done
}

pub async fn short_lived_session(pair: &ProxyPair, payload_len: usize) -> usize {
    let mut stream = pair.connect().await;
    let payload = vec![0xABu8; payload_len];
    echo_transfer(&mut stream, &payload).await;
    payload.len()
}

pub async fn mixed_small_writes(stream: &mut TcpStream, chunk_size: usize, rounds: usize) -> usize {
    let chunk = vec![0x11u8; chunk_size];
    let mut total = 0usize;
    for _ in 0..rounds {
        tokio::time::timeout(io_timeout(), stream.write_all(&chunk))
            .await
            .unwrap_or_else(|_| {
                panic!("bench stage timeout: mixed_small_writes/write chunk={chunk_size}")
            })
            .expect("mixed write");
        let mut echoed = vec![0u8; chunk_size];
        tokio::time::timeout(io_timeout(), stream.read_exact(&mut echoed))
            .await
            .unwrap_or_else(|_| {
                panic!("bench stage timeout: mixed_small_writes/read chunk={chunk_size}")
            })
            .expect("mixed read");
        total += echoed.len();
    }
    total
}

pub async fn concurrent_short_lived(
    pair: &ProxyPair,
    sessions: usize,
    payload_len: usize,
) -> usize {
    let proxy_port = pair.proxy_port;
    let echo_port = pair.echo_port;
    let http = pair.uses_http_connect;

    let mut handles = Vec::with_capacity(sessions);
    for _ in 0..sessions {
        handles.push(tokio::spawn(async move {
            let mut stream = if http {
                http_connect(proxy_port, "127.0.0.1", echo_port).await
            } else {
                socks5_connect(proxy_port, "127.0.0.1", echo_port).await
            };
            let payload = vec![0xFEu8; payload_len];
            echo_transfer(&mut stream, &payload).await;
            payload.len()
        }));
    }

    let mut total = 0usize;
    for handle in handles {
        total += handle.await.expect("conc join");
    }
    total
}

pub fn bulk_transfer_sizes() -> Vec<usize> {
    if std::env::var("BENCH_QUICK").is_ok() {
        return vec![64 * 1024, 256 * 1024];
    }
    vec![64 * 1024, 1024 * 1024, 16 * 1024 * 1024]
}

/// Bulk relay chunk sizes.
///
/// Default keeps historical behavior (`64 KiB`) so existing baselines remain
/// comparable. Set `BENCH_BULK_SWEEP=1` for a quick framing-vs-byte-cost sweep,
/// or set `BENCH_BULK_CHUNKS` to a comma-separated list of bytes.
///
/// Examples:
/// - `BENCH_BULK_SWEEP=1` -> `4 KiB, 16 KiB, 64 KiB`
/// - `BENCH_BULK_CHUNKS=4096,16384,65536,262144`
pub fn bulk_chunk_sizes() -> Vec<usize> {
    if let Ok(raw) = std::env::var("BENCH_BULK_CHUNKS") {
        let parsed: Vec<usize> = raw
            .split(',')
            .filter_map(|s| s.trim().parse::<usize>().ok())
            .filter(|n| *n > 0)
            .collect();
        if !parsed.is_empty() {
            return parsed;
        }
    }
    if std::env::var("BENCH_BULK_SWEEP").is_ok() {
        return vec![4 * 1024, 16 * 1024, 64 * 1024];
    }
    vec![64 * 1024]
}

pub fn short_lived_payload_sizes() -> Vec<usize> {
    vec![64, 256, 1024]
}

pub fn mixed_write_chunk_sizes() -> Vec<usize> {
    vec![64, 128, 512, 1024]
}

pub fn concurrency_levels() -> Vec<usize> {
    vec![1, 8, 32]
}

// ── Optional allocation counters (`bench-alloc` feature) ──────────────────────

#[cfg(feature = "bench-alloc")]
mod alloc_stats {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static ALLOC_COUNT: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_BYTES: AtomicUsize = AtomicUsize::new(0);
    static DEALLOC_COUNT: AtomicUsize = AtomicUsize::new(0);

    struct CountingAlloc;

    unsafe impl GlobalAlloc for CountingAlloc {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
            ALLOC_BYTES.fetch_add(layout.size(), Ordering::Relaxed);
            unsafe { System.alloc(layout) }
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            DEALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
            unsafe { System.dealloc(ptr, layout) }
        }
    }

    #[global_allocator]
    static GLOBAL: CountingAlloc = CountingAlloc;

    #[derive(Clone, Copy, Debug, Default)]
    pub struct AllocSnapshot {
        pub alloc_count: usize,
        pub alloc_bytes: usize,
        pub dealloc_count: usize,
    }

    pub fn reset() {
        ALLOC_COUNT.store(0, Ordering::Relaxed);
        ALLOC_BYTES.store(0, Ordering::Relaxed);
        DEALLOC_COUNT.store(0, Ordering::Relaxed);
    }

    pub fn snapshot() -> AllocSnapshot {
        AllocSnapshot {
            alloc_count: ALLOC_COUNT.load(Ordering::Relaxed),
            alloc_bytes: ALLOC_BYTES.load(Ordering::Relaxed),
            dealloc_count: DEALLOC_COUNT.load(Ordering::Relaxed),
        }
    }
}

#[cfg(feature = "bench-alloc")]
pub use alloc_stats::{reset as alloc_reset, snapshot as alloc_snapshot, AllocSnapshot};

#[cfg(not(feature = "bench-alloc"))]
#[derive(Clone, Copy, Debug, Default)]
pub struct AllocSnapshot {
    pub alloc_count: usize,
    pub alloc_bytes: usize,
    pub dealloc_count: usize,
}

#[cfg(not(feature = "bench-alloc"))]
pub fn alloc_reset() {}

#[cfg(not(feature = "bench-alloc"))]
pub fn alloc_snapshot() -> AllocSnapshot {
    AllocSnapshot::default()
}

pub fn log_alloc(protocol: &str, scenario: &str, snap: AllocSnapshot, bytes_moved: usize) {
    if !cfg!(feature = "bench-alloc") {
        return;
    }
    let per_mib = if bytes_moved > 0 {
        snap.alloc_count as f64 / (bytes_moved as f64 / (1024.0 * 1024.0))
    } else {
        snap.alloc_count as f64
    };
    eprintln!(
        "[bench-alloc] {protocol}/{scenario}: allocs={} bytes={} deallocs={} per_mib_allocs={:.1}",
        snap.alloc_count, snap.alloc_bytes, snap.dealloc_count, per_mib
    );
}

// ── Tokio runtime ──────────────────────────────────────────────────────────────

/// Build the shared tokio runtime for benchmarks.
pub fn bench_runtime() -> Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
}
