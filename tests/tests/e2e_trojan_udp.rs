//! Trojan UDP ASSOCIATE over plain TCP (in-process).

use std::sync::Arc;

use blackwire_common::Address;
use blackwire_protocol::trojan::codec::{
    encode_request, encode_udp_datagram, CMD_UDP_ASSOCIATE,
};
use blackwire_protocol::trojan::compute_token;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;

const TEST_PASSWORD: &str = "trojan-udp-lab-pass";

fn parse_config(json: String) -> Arc<blackwire_config::schema::Config> {
    Arc::new(serde_json::from_str(&json).expect("config parse failed"))
}

async fn spawn_udp_echo() -> (u16, tokio::task::JoinHandle<()>) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = sock.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let mut buf = [0u8; 512];
        loop {
            let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
                break;
            };
            let _ = sock.send_to(&buf[..n], peer).await;
        }
    });
    (port, task)
}

#[tokio::test]
async fn trojan_udp_associate_echoes_datagram() {
    let (echo_port, echo_task) = spawn_udp_echo().await;
    let trojan_port = {
        let l = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        l.local_addr().unwrap().port()
    };

    let server = blackwire_core::Instance::from_config(parse_config(format!(
        r#"{{
            "inbounds": [{{
                "tag": "trojan-in",
                "protocol": "trojan",
                "listen": "127.0.0.1",
                "port": {trojan_port},
                "settings": {{ "clients": [{{ "password": "{TEST_PASSWORD}" }}] }}
            }}],
            "outbounds": [{{ "tag": "freedom", "protocol": "freedom" }}],
            "routing": {{ "rules": [{{ "outboundTag": "freedom" }}] }}
        }}"#
    )))
    .await
    .expect("server start");

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let token = compute_token(TEST_PASSWORD);
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", trojan_port))
        .await
        .unwrap();
    let header = encode_request(
        &token,
        CMD_UDP_ASSOCIATE,
        &Address::Ipv4(std::net::Ipv4Addr::LOCALHOST, 0),
    )
    .unwrap();
    stream.write_all(&header).await.unwrap();
    stream.flush().await.unwrap();

    let dest = Address::Ipv4(std::net::Ipv4Addr::LOCALHOST, echo_port);
    let payload = b"trojan-udp-ping";
    let dg = encode_udp_datagram(&dest, payload).unwrap();
    stream.write_all(&dg).await.unwrap();
    stream.flush().await.unwrap();

    let mut acc = Vec::new();
    let mut buf = [0u8; 1024];
    for _ in 0..20 {
        let n = tokio::time::timeout(std::time::Duration::from_secs(2), stream.read(&mut buf))
            .await
            .expect("timed out waiting for UDP reply frame")
            .expect("read failed");
        if n == 0 {
            break;
        }
        acc.extend_from_slice(&buf[..n]);
        if acc.windows(payload.len()).any(|w| w == payload) {
            break;
        }
    }
    assert!(
        acc.windows(payload.len()).any(|w| w == payload),
        "missing echo in reply: {acc:?}"
    );

    drop(server);
    echo_task.abort();
}
