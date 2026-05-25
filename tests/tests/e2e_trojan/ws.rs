use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[tokio::test]
async fn ws_transport_echo() {
    use blackwire_transport::{ws_accept, ws_connect, WsConnectConfig};

    let _ = tracing_subscriber::fmt().with_env_filter("warn").try_init();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut ws = ws_accept(Box::new(tcp)).await.unwrap();
        let mut buf = [0u8; 1024];
        let n = ws.read(&mut buf).await.unwrap();
        ws.write_all(&buf[..n]).await.unwrap();
        ws.flush().await.unwrap();
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

    let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let cfg = WsConnectConfig {
        path: "/echo".to_string(),
        host: "localhost".to_string(),
        headers: vec![],
    };
    let mut ws = ws_connect(Box::new(tcp), cfg).await.unwrap();

    let msg = b"ws transport echo test";
    ws.write_all(msg).await.unwrap();
    ws.flush().await.unwrap();

    let mut recv = vec![0u8; msg.len()];
    ws.read_exact(&mut recv).await.unwrap();
    assert_eq!(&recv, msg);
}

#[tokio::test]
async fn ws_transport_large_payload() {
    use blackwire_transport::{ws_accept, ws_connect, WsConnectConfig};

    let _ = tracing_subscriber::fmt().with_env_filter("warn").try_init();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut ws = ws_accept(Box::new(tcp)).await.unwrap();
        let mut buf = vec![0u8; 16 * 1024];
        let mut received = Vec::with_capacity(64 * 1024);
        while received.len() < 64 * 1024 {
            let n = ws.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            received.extend_from_slice(&buf[..n]);
        }
        ws.write_all(&received).await.unwrap();
        ws.flush().await.unwrap();
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

    let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let mut ws = ws_connect(
        Box::new(tcp),
        WsConnectConfig {
            path: "/large".to_string(),
            host: "localhost".to_string(),
            headers: vec![],
        },
    )
    .await
    .unwrap();

    let payload = vec![0xEFu8; 64 * 1024];
    ws.write_all(&payload).await.unwrap();
    ws.flush().await.unwrap();

    let mut recv = vec![0u8; payload.len()];
    ws.read_exact(&mut recv).await.unwrap();
    assert_eq!(recv, payload);
}

#[tokio::test]
async fn ws_transport_custom_path() {
    use blackwire_transport::{ws_accept, ws_connect, WsConnectConfig};

    let _ = tracing_subscriber::fmt().with_env_filter("warn").try_init();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut ws = ws_accept(Box::new(tcp)).await.unwrap();
        let mut buf = [0u8; 32];
        let n = ws.read(&mut buf).await.unwrap();
        ws.write_all(&buf[..n]).await.unwrap();
        ws.flush().await.unwrap();
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

    let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let mut ws = ws_connect(
        Box::new(tcp),
        WsConnectConfig {
            path: "/custom/path/here".to_string(),
            host: "example.com".to_string(),
            headers: vec![("X-Test".to_string(), "value".to_string())],
        },
    )
    .await
    .unwrap();

    ws.write_all(b"custom path").await.unwrap();
    ws.flush().await.unwrap();
    let mut recv = [0u8; 11];
    ws.read_exact(&mut recv).await.unwrap();
    assert_eq!(&recv, b"custom path");
}
