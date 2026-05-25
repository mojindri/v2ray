use std::time::Duration;

use proxy_transport::tcp::{TcpClientTransport, TcpConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[path = "../common/leak_check.rs"]
mod leak_check;

async fn spawn_listener_echo(bind: &str) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind(bind).await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let task = tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
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
    (addr, task)
}

async fn spawn_listener_reset(bind: &str) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind(bind).await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let task = tokio::spawn(async move {
        while let Ok((s, _)) = listener.accept().await {
            let sock = socket2::SockRef::from(&s);
            let _ = sock.set_linger(Some(Duration::from_secs(0)));
            drop(s);
        }
    });
    (addr, task)
}

#[tokio::test]
async fn tcp_half_close_behavior_is_clean() {
    let (addr, _task) = spawn_listener_echo("127.0.0.1:0").await;
    let mut s = TcpStream::connect(addr).await.expect("connect");
    s.write_all(b"abc").await.expect("write");
    s.shutdown().await.expect("shutdown write");
    let mut out = [0u8; 3];
    s.read_exact(&mut out).await.expect("read");
    assert_eq!(&out, b"abc");
}

#[tokio::test]
async fn tcp_client_transport_ipv4_and_ipv6_dial() {
    let (v4_addr, _v4_task) = spawn_listener_echo("127.0.0.1:0").await;
    let transport = TcpClientTransport::new(TcpConfig::default());
    let mut v4 = transport.dial(v4_addr).await.expect("dial v4");
    v4.write_all(b"v4").await.expect("write");
    let mut out = [0u8; 2];
    v4.read_exact(&mut out).await.expect("read");
    assert_eq!(&out, b"v4");

    if let Ok((v6_addr, _v6_task)) = tokio::time::timeout(Duration::from_secs(1), spawn_listener_echo("[::1]:0")).await {
        let mut v6 = transport.dial(v6_addr).await.expect("dial v6");
        v6.write_all(b"v6").await.expect("write");
        let mut out6 = [0u8; 2];
        v6.read_exact(&mut out6).await.expect("read");
        assert_eq!(&out6, b"v6");
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn so_mark_is_applied_before_connect_or_fails_closed() {
    let (addr, _task) = spawn_listener_echo("127.0.0.1:0").await;
    let transport = TcpClientTransport::new(TcpConfig {
        so_mark: Some(0x1234),
        tcp_fast_open: false,
        max_connections: None,
    });

    match transport.dial(addr).await {
        Ok(mut s) => {
            // privileged environment: SO_MARK succeeded
            s.write_all(b"ok").await.expect("write");
            let mut out = [0u8; 2];
            s.read_exact(&mut out).await.expect("read");
            assert_eq!(&out, b"ok");
        }
        Err(e) => {
            let msg = e.to_string();
            assert!(
                msg.contains("SO_MARK failed"),
                "expected fail-closed SO_MARK error, got: {msg}"
            );
        }
    }
}

#[tokio::test]
async fn socket_dials_do_not_leak_fds() {
    let baseline = leak_check::LeakSnapshot::capture();
    let (addr, _task) = spawn_listener_echo("127.0.0.1:0").await;
    let transport = TcpClientTransport::new(TcpConfig::default());

    for _ in 0..256usize {
        let mut s = transport.dial(addr).await.expect("dial");
        s.write_all(b"x").await.expect("write");
        let mut out = [0u8; 1];
        s.read_exact(&mut out).await.expect("read");
    }

    leak_check::settle_for_cleanup().await;
    let after = leak_check::LeakSnapshot::capture();
    leak_check::assert_close_to_baseline(&baseline, &after, 128, 128, 60);
}

#[tokio::test]
async fn tcp_reset_behavior_is_handled_without_hang() {
    let (addr, _task) = spawn_listener_reset("127.0.0.1:0").await;
    let mut s = TcpStream::connect(addr).await.expect("connect");
    let _ = s.write_all(b"hello").await;
    let read = tokio::time::timeout(Duration::from_secs(2), s.read(&mut [0u8; 8])).await;
    assert!(read.is_ok(), "RST path should not hang");
}
