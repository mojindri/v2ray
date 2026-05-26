use std::sync::Arc;

use blackwire_common::Address;
use blackwire_protocol::vless::codec::{encode_request, Command};
use bytes::Bytes;
use h2::client;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;

const TEST_UUID: &str = "a3482e88-686a-4a58-8126-99c9df64b7bf";

fn parse_uuid(s: &str) -> [u8; 16] {
    *Uuid::parse_str(s).expect("invalid test uuid").as_bytes()
}

fn unused_local_port() -> u16 {
    let listener =
        std::net::TcpListener::bind(("127.0.0.1", 0)).expect("failed to reserve local port");
    listener.local_addr().unwrap().port()
}

async fn spawn_echo_server() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("echo server bind failed");
    let port = listener.local_addr().unwrap().port();

    let task = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    let n = stream.read(&mut buf).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    let _ = stream.write_all(&buf[..n]).await;
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
    assert_eq!(reply[1], 0);

    stream
}

fn parse_config(json: String) -> Arc<blackwire_config::schema::Config> {
    Arc::new(serde_json::from_str(&json).expect("config parse failed"))
}

fn server_config(vless_port: u16) -> Arc<blackwire_config::schema::Config> {
    parse_config(format!(
        r#"{{
            "inbounds": [{{
                "tag": "vless-http-in",
                "protocol": "vless",
                "listen": "127.0.0.1",
                "port": {vless_port},
                "settings": {{
                    "clients": [{{ "id": "{TEST_UUID}", "email": "http@example.test" }}]
                }},
                "streamSettings": {{
                    "network": "splithttp",
                    "splithttpSettings": {{
                        "path": "/split",
                        "method": "PUT"
                    }}
                }}
            }}],
            "outbounds": [{{ "tag": "freedom", "protocol": "freedom" }}],
            "routing": {{ "rules": [{{ "outboundTag": "freedom" }}] }}
        }}"#
    ))
}

fn client_config(socks_port: u16, vless_port: u16) -> Arc<blackwire_config::schema::Config> {
    parse_config(format!(
        r#"{{
            "inbounds": [{{
                "tag": "socks-in",
                "protocol": "socks",
                "listen": "127.0.0.1",
                "port": {socks_port}
            }}],
            "outbounds": [{{
                "tag": "vless-http-out",
                "protocol": "vless",
                "settings": {{
                    "address": "127.0.0.1",
                    "port": {vless_port},
                    "users": [{{ "id": "{TEST_UUID}" }}]
                }},
                "streamSettings": {{
                    "network": "splithttp",
                    "splithttpSettings": {{
                        "path": "/split",
                        "method": "PUT"
                    }}
                }}
            }}],
            "routing": {{ "rules": [{{ "outboundTag": "vless-http-out" }}] }}
        }}"#
    ))
}

fn packet_up_server_config(vless_port: u16) -> Arc<blackwire_config::schema::Config> {
    let (cert, key) = write_temp_tls_files();
    parse_config(format!(
        r#"{{
            "inbounds": [{{
                "tag": "vless-http-in",
                "protocol": "vless",
                "listen": "127.0.0.1",
                "port": {vless_port},
                "settings": {{
                    "clients": [{{ "id": "{TEST_UUID}", "email": "packet-up@example.test" }}]
                }},
                "streamSettings": {{
                    "network": "splithttp",
                    "security": "tls",
                    "tlsSettings": {{
                        "certificateFile": "{}",
                        "keyFile": "{}",
                        "alpn": ["h2"]
                    }},
                    "splithttpSettings": {{
                        "path": "/split",
                        "mode": "packet-up"
                    }}
                }}
            }}],
            "outbounds": [{{ "tag": "freedom", "protocol": "freedom" }}],
            "routing": {{ "rules": [{{ "outboundTag": "freedom" }}] }}
        }}"#,
        cert, key
    ))
}

fn write_temp_tls_files() -> (String, String) {
    let (cert_pem, key_pem) = blackwire_transport::dev_self_signed().expect("self-signed cert");
    let suffix = format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    );
    let cert_path = std::env::temp_dir().join(format!("blackwire-splithttp-{suffix}.crt"));
    let key_path = std::env::temp_dir().join(format!("blackwire-splithttp-{suffix}.key"));
    std::fs::write(&cert_path, cert_pem).expect("write cert");
    std::fs::write(&key_path, key_pem).expect("write key");
    (
        cert_path.to_string_lossy().into_owned(),
        key_path.to_string_lossy().into_owned(),
    )
}

#[tokio::test]
async fn phase6_vless_splithttp_echo() {
    let (echo_port, echo_task) = spawn_echo_server().await;
    let vless_port = unused_local_port();
    let socks_port = unused_local_port();

    let _server = blackwire_core::Instance::from_config(server_config(vless_port))
        .await
        .expect("server start failed");
    let _client = blackwire_core::Instance::from_config(client_config(socks_port, vless_port))
        .await
        .expect("client start failed");

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let mut stream = socks5_connect(socks_port, "127.0.0.1", echo_port).await;
    let payload = b"HELLO SPLITHTTP";
    stream.write_all(payload).await.unwrap();

    let mut echoed = vec![0u8; payload.len()];
    stream.read_exact(&mut echoed).await.unwrap();
    assert_eq!(echoed, payload);

    echo_task.abort();
}

#[tokio::test]
async fn phase6_vless_splithttp_packet_up_h2_echo() {
    let (echo_port, echo_task) = spawn_echo_server().await;
    let vless_port = unused_local_port();

    let _server = blackwire_core::Instance::from_config(packet_up_server_config(vless_port))
        .await
        .expect("packet-up server start failed");

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let tcp = TcpStream::connect(("127.0.0.1", vless_port))
        .await
        .expect("connect packet-up server");
    let tls = blackwire_transport::tls_connect(Box::new(tcp), "localhost", &["h2"], true)
        .await
        .expect("tls connect");
    let (mut h2, conn) = client::Builder::new()
        .handshake(tls)
        .await
        .expect("h2 handshake");
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let get_req = http::Request::builder()
        .method(http::Method::GET)
        .uri("https://localhost/split/session-1")
        .body(())
        .unwrap();
    let (get_resp_fut, mut get_send) = h2.send_request(get_req, false).unwrap();
    get_send.send_data(Bytes::new(), true).unwrap();

    let payload = b"HELLO SPLITHTTP PACKET-UP";
    let dest = Address::Ipv4("127.0.0.1".parse().unwrap(), echo_port);
    let uuid = parse_uuid(TEST_UUID);
    let mut upload = encode_request(&uuid, "", Command::Tcp, &dest)
        .expect("encode vless request")
        .to_vec();
    upload.extend_from_slice(payload);

    let post_req = http::Request::builder()
        .method(http::Method::POST)
        .uri("https://localhost/split/session-1/0")
        .body(())
        .unwrap();
    let (post_resp_fut, mut post_send) = h2.send_request(post_req, false).unwrap();
    post_send.send_data(Bytes::from(upload), true).unwrap();

    let post_resp = post_resp_fut.await.expect("post response");
    assert_eq!(post_resp.status(), http::StatusCode::OK);

    let mut get_resp = get_resp_fut.await.expect("get response");
    assert_eq!(get_resp.status(), http::StatusCode::OK);

    let mut received = Vec::new();
    while received.len() < 2 + payload.len() {
        let chunk = get_resp
            .body_mut()
            .data()
            .await
            .expect("response chunk missing")
            .expect("response chunk error");
        get_resp
            .body_mut()
            .flow_control()
            .release_capacity(chunk.len())
            .expect("release capacity");
        received.extend_from_slice(&chunk);
    }

    assert_eq!(&received[..2], &[0x00, 0x00]);
    assert_eq!(&received[2..2 + payload.len()], payload);

    echo_task.abort();
}
