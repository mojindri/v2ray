use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub fn parse_config(json: serde_json::Value) -> Arc<proxy_config::schema::Config> {
    Arc::new(serde_json::from_value(json).expect("config parse"))
}

pub fn unused_local_port() -> u16 {
    std::net::TcpListener::bind(("127.0.0.1", 0))
        .expect("port reserve")
        .local_addr()
        .expect("port addr")
        .port()
}

pub async fn spawn_echo_server() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind echo");
    let port = listener.local_addr().expect("echo addr").port();
    let task = tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 8192];
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

pub async fn spawn_slow_echo_server(delay: Duration) -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind slow echo");
    let port = listener.local_addr().expect("slow echo addr").port();
    let task = tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
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
    (port, task)
}

pub async fn spawn_stalled_reader_server() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind stalled reader");
    let port = listener.local_addr().expect("stalled addr").port();
    let task = tokio::spawn(async move {
        while let Ok((_s, _)) = listener.accept().await {
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(30)).await;
            });
        }
    });
    (port, task)
}

pub async fn spawn_drop_on_connect_server() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind drop server");
    let port = listener.local_addr().expect("drop addr").port();
    let task = tokio::spawn(async move { while let Ok((_s, _)) = listener.accept().await {} });
    (port, task)
}

pub async fn socks5_connect(socks_port: u16, host: &str, port: u16) -> TcpStream {
    let mut s = TcpStream::connect(("127.0.0.1", socks_port))
        .await
        .expect("connect socks");
    s.write_all(&[5, 1, 0]).await.expect("socks greet");
    let mut g = [0u8; 2];
    s.read_exact(&mut g).await.expect("socks greet reply");
    assert_eq!(g, [5, 0]);

    let hb = host.as_bytes();
    let mut req = vec![5, 1, 0, 3, hb.len() as u8];
    req.extend_from_slice(hb);
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await.expect("socks connect req");
    let mut rep = [0u8; 10];
    s.read_exact(&mut rep).await.expect("socks connect rep");
    assert_eq!(rep[1], 0, "SOCKS5 REP={:#x}", rep[1]);
    s
}
