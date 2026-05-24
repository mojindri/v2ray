use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub(crate) const TEST_PASSWORD: &str = "phase4-test-password";
pub(crate) const TEST_UUID: &str = "b45c5b86-1234-4321-abcd-0123456789ab";

pub(crate) fn unused_local_port() -> u16 {
    let listener =
        std::net::TcpListener::bind(("127.0.0.1", 0)).expect("failed to reserve local port");
    listener.local_addr().unwrap().port()
}

pub(crate) async fn spawn_echo_server() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("echo server bind failed");
    spawn_echo_task(listener)
}

pub(crate) async fn spawn_localhost_echo_server() -> (u16, tokio::task::JoinHandle<()>) {
    // Bind through the same OS resolver path used by Freedom for `localhost`.
    // On some systems that is IPv6 first, on others IPv4 first.
    let listener = TcpListener::bind(("localhost", 0))
        .await
        .expect("localhost echo server bind failed");
    spawn_echo_task(listener)
}

fn spawn_echo_task(listener: TcpListener) -> (u16, tokio::task::JoinHandle<()>) {
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

pub(crate) async fn socks5_connect(socks_port: u16, dest_host: &str, dest_port: u16) -> TcpStream {
    let mut stream = TcpStream::connect(("127.0.0.1", socks_port))
        .await
        .expect("failed to connect to SOCKS5 proxy");

    // Method negotiation: version 5, one supported method, no authentication.
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp, [5, 0]);

    // CONNECT request: version, command, reserved byte, domain address, port.
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

pub(crate) fn parse_config(json: String) -> Arc<proxy_config::schema::Config> {
    Arc::new(serde_json::from_str(&json).expect("config parse failed"))
}

pub(crate) fn write_dev_cert_files() -> (String, String) {
    let (cert_pem, key_pem) = proxy_transport::dev_self_signed().unwrap();
    let dir = std::env::temp_dir();
    let unique = format!(
        "blackwire-phase4-{}-{}",
        std::process::id(),
        unused_local_port()
    );
    let cert_path = dir.join(format!("{unique}.cert.pem"));
    let key_path = dir.join(format!("{unique}.key.pem"));

    std::fs::write(&cert_path, cert_pem).expect("write cert failed");
    std::fs::write(&key_path, key_pem).expect("write key failed");

    (
        cert_path.to_string_lossy().into_owned(),
        key_path.to_string_lossy().into_owned(),
    )
}

pub(crate) fn trojan_server_plain(trojan_port: u16) -> Arc<proxy_config::schema::Config> {
    parse_config(format!(
        r#"{{
            "inbounds": [{{
                "tag": "trojan-in",
                "protocol": "trojan",
                "listen": "127.0.0.1",
                "port": {trojan_port},
                "settings": {{
                    "clients": [{{"password": "{TEST_PASSWORD}"}}]
                }}
            }}],
            "outbounds": [{{
                "tag": "freedom",
                "protocol": "freedom"
            }}],
            "routing": {{ "rules": [{{ "outboundTag": "freedom" }}] }}
        }}"#
    ))
}

pub(crate) fn trojan_client_plain(
    socks_port: u16,
    trojan_port: u16,
) -> Arc<proxy_config::schema::Config> {
    parse_config(format!(
        r#"{{
            "inbounds": [{{
                "tag": "socks-in",
                "protocol": "socks",
                "listen": "127.0.0.1",
                "port": {socks_port}
            }}],
            "outbounds": [{{
                "tag": "trojan-out",
                "protocol": "trojan",
                "settings": {{
                    "address": "127.0.0.1",
                    "port": {trojan_port},
                    "password": "{TEST_PASSWORD}"
                }}
            }}],
            "routing": {{ "rules": [{{ "outboundTag": "trojan-out" }}] }}
        }}"#
    ))
}

pub(crate) fn trojan_server_tls(
    trojan_port: u16,
    cert_path: &str,
    key_path: &str,
) -> Arc<proxy_config::schema::Config> {
    parse_config(format!(
        r#"{{
            "inbounds": [{{
                "tag": "trojan-in",
                "protocol": "trojan",
                "listen": "127.0.0.1",
                "port": {trojan_port},
                "settings": {{
                    "clients": [{{"password": "{TEST_PASSWORD}"}}]
                }},
                "streamSettings": {{
                    "network": "tcp",
                    "security": "tls",
                    "tlsSettings": {{
                        "certificateFile": "{cert_path}",
                        "keyFile": "{key_path}"
                    }}
                }}
            }}],
            "outbounds": [{{
                "tag": "freedom",
                "protocol": "freedom"
            }}],
            "routing": {{ "rules": [{{ "outboundTag": "freedom" }}] }}
        }}"#
    ))
}

pub(crate) fn vless_ws_server(vless_port: u16) -> Arc<proxy_config::schema::Config> {
    parse_config(format!(
        r#"{{
            "inbounds": [{{
                "tag": "vless-in",
                "protocol": "vless",
                "listen": "127.0.0.1",
                "port": {vless_port},
                "settings": {{
                    "clients": [{{"id": "{TEST_UUID}", "email": "test@test.com"}}]
                }},
                "streamSettings": {{
                    "network": "ws",
                    "security": "none",
                    "wsSettings": {{
                        "path": "/proxy"
                    }}
                }}
            }}],
            "outbounds": [{{
                "tag": "freedom",
                "protocol": "freedom"
            }}],
            "routing": {{ "rules": [{{ "outboundTag": "freedom" }}] }}
        }}"#
    ))
}

pub(crate) fn vless_ws_tls_server(
    vless_port: u16,
    cert_path: &str,
    key_path: &str,
) -> Arc<proxy_config::schema::Config> {
    parse_config(format!(
        r#"{{
            "inbounds": [{{
                "tag": "vless-in",
                "protocol": "vless",
                "listen": "127.0.0.1",
                "port": {vless_port},
                "settings": {{
                    "clients": [{{"id": "{TEST_UUID}", "email": "test@test.com"}}]
                }},
                "streamSettings": {{
                    "network": "ws",
                    "security": "tls",
                    "tlsSettings": {{
                        "certificateFile": "{cert_path}",
                        "keyFile": "{key_path}"
                    }},
                    "wsSettings": {{
                        "path": "/proxy"
                    }}
                }}
            }}],
            "outbounds": [{{
                "tag": "freedom",
                "protocol": "freedom"
            }}],
            "routing": {{ "rules": [{{ "outboundTag": "freedom" }}] }}
        }}"#
    ))
}
