use blackwire_common::Address;
use blackwire_protocol::vless::connect_vless_on_stream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::common::{
    spawn_echo_server, unused_local_port, vless_ws_server, vless_ws_tls_server,
    write_dev_cert_files, TEST_UUID,
};

#[tokio::test]
async fn vless_over_ws_plain() {
    use blackwire_transport::{ws_connect, WsConnectConfig};

    let _ = tracing_subscriber::fmt().with_env_filter("warn").try_init();

    let (echo_port, echo_task) = spawn_echo_server().await;
    let vless_port = unused_local_port();

    let _server = blackwire_core::Instance::from_config(vless_ws_server(vless_port))
        .await
        .expect("server start failed");

    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    let uuid: [u8; 16] = uuid::Uuid::parse_str(TEST_UUID).unwrap().into_bytes();
    let tcp = TcpStream::connect(("127.0.0.1", vless_port)).await.unwrap();
    let ws = ws_connect(
        Box::new(tcp),
        WsConnectConfig {
            path: "/proxy".to_string(),
            host: "localhost".to_string(),
            headers: vec![],
        },
    )
    .await
    .unwrap();

    let dest = Address::Ipv4("127.0.0.1".parse().unwrap(), echo_port);
    let mut stream = connect_vless_on_stream(ws, &uuid, "", &dest).await.unwrap();

    let payload = b"VLESS OVER WS PLAIN";
    stream.write_all(payload).await.unwrap();
    stream.flush().await.unwrap();

    let mut recv = vec![0u8; payload.len()];
    stream.read_exact(&mut recv).await.unwrap();
    assert_eq!(&recv, payload);

    echo_task.abort();
}

#[tokio::test]
async fn vless_over_ws_tls() {
    use blackwire_transport::{tls_connect, ws_connect, WsConnectConfig};

    let _ = tracing_subscriber::fmt().with_env_filter("warn").try_init();

    let (echo_port, echo_task) = spawn_echo_server().await;
    let (cert_path, key_path) = write_dev_cert_files();
    let vless_port = unused_local_port();

    let _server = blackwire_core::Instance::from_config(vless_ws_tls_server(
        vless_port, &cert_path, &key_path,
    ))
    .await
    .expect("server start failed");

    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    let uuid: [u8; 16] = uuid::Uuid::parse_str(TEST_UUID).unwrap().into_bytes();
    let tcp = TcpStream::connect(("127.0.0.1", vless_port)).await.unwrap();
    let tls = tls_connect(Box::new(tcp), "localhost", &[], true)
        .await
        .unwrap();
    let ws = ws_connect(
        tls,
        WsConnectConfig {
            path: "/proxy".to_string(),
            host: "localhost".to_string(),
            headers: vec![],
        },
    )
    .await
    .unwrap();

    let dest = Address::Ipv4("127.0.0.1".parse().unwrap(), echo_port);
    let mut stream = connect_vless_on_stream(ws, &uuid, "", &dest).await.unwrap();

    let payload = b"VLESS OVER WSS";
    stream.write_all(payload).await.unwrap();
    stream.flush().await.unwrap();

    let mut recv = vec![0u8; payload.len()];
    stream.read_exact(&mut recv).await.unwrap();
    assert_eq!(&recv, payload);

    echo_task.abort();
    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);
}

#[tokio::test]
async fn vless_over_ws_large_payload() {
    use blackwire_transport::{ws_connect, WsConnectConfig};

    let _ = tracing_subscriber::fmt().with_env_filter("warn").try_init();

    let (echo_port, echo_task) = spawn_echo_server().await;
    let vless_port = unused_local_port();

    let _server = blackwire_core::Instance::from_config(vless_ws_server(vless_port))
        .await
        .expect("server start failed");

    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    let uuid: [u8; 16] = uuid::Uuid::parse_str(TEST_UUID).unwrap().into_bytes();
    let tcp = TcpStream::connect(("127.0.0.1", vless_port)).await.unwrap();
    let ws = ws_connect(
        Box::new(tcp),
        WsConnectConfig {
            path: "/proxy".to_string(),
            host: "localhost".to_string(),
            headers: vec![],
        },
    )
    .await
    .unwrap();

    let dest = Address::Ipv4("127.0.0.1".parse().unwrap(), echo_port);
    let mut stream = connect_vless_on_stream(ws, &uuid, "", &dest).await.unwrap();

    let payload = vec![0xAAu8; 48 * 1024];
    stream.write_all(&payload).await.unwrap();
    stream.flush().await.unwrap();

    let mut recv = vec![0u8; payload.len()];
    stream.read_exact(&mut recv).await.unwrap();
    assert_eq!(recv, payload);

    echo_task.abort();
}

#[tokio::test]
async fn vless_over_ws_tls_multi_conn() {
    use blackwire_transport::{tls_connect, ws_connect, WsConnectConfig};

    let _ = tracing_subscriber::fmt().with_env_filter("warn").try_init();

    let (echo_port, echo_task) = spawn_echo_server().await;
    let (cert_path, key_path) = write_dev_cert_files();
    let vless_port = unused_local_port();

    let _server = blackwire_core::Instance::from_config(vless_ws_tls_server(
        vless_port, &cert_path, &key_path,
    ))
    .await
    .expect("server start failed");

    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    let uuid: [u8; 16] = uuid::Uuid::parse_str(TEST_UUID).unwrap().into_bytes();

    for i in 0u8..3 {
        let tcp = TcpStream::connect(("127.0.0.1", vless_port)).await.unwrap();
        let tls = tls_connect(Box::new(tcp), "localhost", &[], true)
            .await
            .unwrap();
        let ws = ws_connect(
            tls,
            WsConnectConfig {
                path: "/proxy".to_string(),
                host: "localhost".to_string(),
                headers: vec![],
            },
        )
        .await
        .unwrap();

        let dest = Address::Ipv4("127.0.0.1".parse().unwrap(), echo_port);
        let mut stream = connect_vless_on_stream(ws, &uuid, "", &dest).await.unwrap();

        let msg = format!("connection {i}").into_bytes();
        stream.write_all(&msg).await.unwrap();
        stream.flush().await.unwrap();

        let mut recv = vec![0u8; msg.len()];
        stream.read_exact(&mut recv).await.unwrap();
        assert_eq!(recv, msg, "connection {i} failed");
    }

    echo_task.abort();
    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);
}
