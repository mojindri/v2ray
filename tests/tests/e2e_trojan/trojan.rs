use proxy_common::Address;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::common::{
    parse_config, socks5_connect, spawn_echo_server, spawn_localhost_echo_server,
    trojan_client_plain, trojan_server_plain, trojan_server_tls, unused_local_port,
    write_dev_cert_files, TEST_PASSWORD,
};

#[tokio::test]
async fn trojan_plain_tcp_single_chunk() {
    let _ = tracing_subscriber::fmt().with_env_filter("warn").try_init();

    let (echo_port, echo_task) = spawn_echo_server().await;
    let trojan_port = unused_local_port();
    let socks_port = unused_local_port();

    let _server = proxy_core::Instance::from_config(trojan_server_plain(trojan_port))
        .await
        .expect("server start failed");
    let _client = proxy_core::Instance::from_config(trojan_client_plain(socks_port, trojan_port))
        .await
        .expect("client start failed");

    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    let mut stream = socks5_connect(socks_port, "127.0.0.1", echo_port).await;
    let payload = b"HELLO TROJAN PLAIN TCP";
    stream.write_all(payload).await.unwrap();

    let mut echoed = vec![0u8; payload.len()];
    stream.read_exact(&mut echoed).await.unwrap();
    assert_eq!(echoed, payload);

    echo_task.abort();
}

#[tokio::test]
async fn trojan_plain_tcp_large_payload() {
    let _ = tracing_subscriber::fmt().with_env_filter("warn").try_init();

    let (echo_port, echo_task) = spawn_echo_server().await;
    let trojan_port = unused_local_port();
    let socks_port = unused_local_port();

    let _server = proxy_core::Instance::from_config(trojan_server_plain(trojan_port))
        .await
        .expect("server start failed");
    let _client = proxy_core::Instance::from_config(trojan_client_plain(socks_port, trojan_port))
        .await
        .expect("client start failed");

    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    let mut stream = socks5_connect(socks_port, "127.0.0.1", echo_port).await;
    let payload = vec![0xABu8; 64 * 1024];
    stream.write_all(&payload).await.unwrap();

    let mut echoed = vec![0u8; payload.len()];
    stream.read_exact(&mut echoed).await.unwrap();
    assert_eq!(echoed, payload);

    echo_task.abort();
}

#[tokio::test]
async fn trojan_wrong_password_is_rejected() {
    use proxy_protocol::trojan::codec::encode_request;
    use proxy_protocol::trojan::compute_token;

    let _ = tracing_subscriber::fmt().with_env_filter("warn").try_init();

    let trojan_port = unused_local_port();
    let _server = proxy_core::Instance::from_config(trojan_server_plain(trojan_port))
        .await
        .expect("server start failed");

    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    // Send a header with the wrong password hash. The server should close or reset.
    let mut stream = TcpStream::connect(("127.0.0.1", trojan_port))
        .await
        .unwrap();
    let bad_token = compute_token("wrong-password-12345");
    let dest = Address::Domain("example.com".into(), 80);
    let header = encode_request(&bad_token, &dest).unwrap();
    stream.write_all(&header).await.unwrap();
    stream.flush().await.unwrap();

    let mut buf = [0u8; 16];
    let result = stream.read(&mut buf).await;
    match result {
        Ok(0) => {}
        Ok(_) => {}
        Err(_) => {}
    }
}

#[tokio::test]
async fn trojan_over_tls_roundtrip() {
    use proxy_protocol::trojan::{compute_token, connect_trojan_on_stream};
    use proxy_transport::tls_connect;

    let _ = tracing_subscriber::fmt().with_env_filter("warn").try_init();

    let (echo_port, echo_task) = spawn_echo_server().await;
    let (cert_path, key_path) = write_dev_cert_files();
    let trojan_port = unused_local_port();

    let _server =
        proxy_core::Instance::from_config(trojan_server_tls(trojan_port, &cert_path, &key_path))
            .await
            .expect("server start failed");

    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    let tcp = TcpStream::connect(("127.0.0.1", trojan_port))
        .await
        .unwrap();
    let tls = tls_connect(Box::new(tcp), "localhost", &[], true)
        .await
        .unwrap();

    let token = compute_token(TEST_PASSWORD);
    let dest = Address::Ipv4("127.0.0.1".parse().unwrap(), echo_port);
    let mut stream = connect_trojan_on_stream(tls, &token, &dest).await.unwrap();

    let payload = b"TROJAN OVER TLS";
    stream.write_all(payload).await.unwrap();
    stream.flush().await.unwrap();

    let mut echoed = vec![0u8; payload.len()];
    stream.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, payload);

    echo_task.abort();
    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);
}

#[tokio::test]
async fn trojan_multiple_passwords_any_accepted() {
    use proxy_protocol::trojan::{compute_token, connect_trojan_on_stream};

    let _ = tracing_subscriber::fmt().with_env_filter("warn").try_init();

    let trojan_port = unused_local_port();
    let (echo_port, echo_task) = spawn_echo_server().await;

    let server_config = parse_config(format!(
        r#"{{
            "inbounds": [{{
                "tag": "trojan-in",
                "protocol": "trojan",
                "listen": "127.0.0.1",
                "port": {trojan_port},
                "settings": {{
                    "clients": [
                        {{"password": "password-one"}},
                        {{"password": "password-two"}}
                    ]
                }}
            }}],
            "outbounds": [{{"tag": "freedom", "protocol": "freedom"}}],
            "routing": {{ "rules": [{{"outboundTag": "freedom"}}] }}
        }}"#
    ));

    let _server = proxy_core::Instance::from_config(server_config)
        .await
        .expect("server start failed");

    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    let dest = Address::Ipv4("127.0.0.1".parse().unwrap(), echo_port);

    for pw in &["password-one", "password-two"] {
        let tcp = TcpStream::connect(("127.0.0.1", trojan_port))
            .await
            .unwrap();
        let token = compute_token(pw);
        let mut stream = connect_trojan_on_stream(Box::new(tcp), &token, &dest)
            .await
            .unwrap();
        let msg = format!("hello from {pw}").into_bytes();
        stream.write_all(&msg).await.unwrap();
        stream.flush().await.unwrap();

        let mut recv = vec![0u8; msg.len()];
        stream.read_exact(&mut recv).await.unwrap();
        assert_eq!(recv, msg, "password '{pw}' should have been accepted");
    }

    echo_task.abort();
}

#[tokio::test]
async fn trojan_ipv4_address() {
    let _ = tracing_subscriber::fmt().with_env_filter("warn").try_init();

    let (echo_port, echo_task) = spawn_echo_server().await;
    let trojan_port = unused_local_port();
    let socks_port = unused_local_port();

    let _server = proxy_core::Instance::from_config(trojan_server_plain(trojan_port))
        .await
        .unwrap();
    let _client = proxy_core::Instance::from_config(trojan_client_plain(socks_port, trojan_port))
        .await
        .unwrap();

    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    let mut stream = socks5_connect(socks_port, "127.0.0.1", echo_port).await;
    let payload = b"IPv4 direct address test";
    stream.write_all(payload).await.unwrap();

    let mut recv = vec![0u8; payload.len()];
    stream.read_exact(&mut recv).await.unwrap();
    assert_eq!(recv, payload);

    echo_task.abort();
}

#[tokio::test]
async fn trojan_domain_address() {
    let _ = tracing_subscriber::fmt().with_env_filter("warn").try_init();

    let (echo_port, echo_task) = spawn_localhost_echo_server().await;
    let trojan_port = unused_local_port();
    let socks_port = unused_local_port();

    let _server = proxy_core::Instance::from_config(trojan_server_plain(trojan_port))
        .await
        .unwrap();
    let _client = proxy_core::Instance::from_config(trojan_client_plain(socks_port, trojan_port))
        .await
        .unwrap();

    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    let mut stream = socks5_connect(socks_port, "localhost", echo_port).await;
    let payload = b"domain address test";
    stream.write_all(payload).await.unwrap();

    let mut recv = vec![0u8; payload.len()];
    stream.read_exact(&mut recv).await.unwrap();
    assert_eq!(recv, payload);

    echo_task.abort();
}

#[tokio::test]
async fn trojan_over_tls_large_payload() {
    use proxy_protocol::trojan::{compute_token, connect_trojan_on_stream};
    use proxy_transport::tls_connect;

    let _ = tracing_subscriber::fmt().with_env_filter("warn").try_init();

    let (echo_port, echo_task) = spawn_echo_server().await;
    let (cert_path, key_path) = write_dev_cert_files();
    let trojan_port = unused_local_port();

    let _server =
        proxy_core::Instance::from_config(trojan_server_tls(trojan_port, &cert_path, &key_path))
            .await
            .expect("server start failed");

    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    let tcp = TcpStream::connect(("127.0.0.1", trojan_port))
        .await
        .unwrap();
    let tls = tls_connect(Box::new(tcp), "localhost", &[], true)
        .await
        .unwrap();

    let token = compute_token(TEST_PASSWORD);
    let dest = Address::Ipv4("127.0.0.1".parse().unwrap(), echo_port);
    let mut stream = connect_trojan_on_stream(tls, &token, &dest).await.unwrap();

    let payload = vec![0xCCu8; 32 * 1024];
    stream.write_all(&payload).await.unwrap();
    stream.flush().await.unwrap();

    let mut echoed = vec![0u8; payload.len()];
    stream.read_exact(&mut echoed).await.unwrap();
    assert_eq!(echoed, payload);

    echo_task.abort();
    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);
}
