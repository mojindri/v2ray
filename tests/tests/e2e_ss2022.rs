//! End-to-end tests for Shadowsocks-2022 (SIP022) protocol.
//!
//! Tests the full SS-2022 inbound + outbound chain.
//!
//! Test topology:
//!
//!   Test client (SOCKS5)
//!       → SOCKS5 inbound → SS-2022 outbound → SS-2022 inbound → Freedom outbound
//!       → TCP echo server
//!
//! Or for unit-level crypto tests:
//!   SS-2022 stream encrypt → SS-2022 stream decrypt

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const SS_PASSWORD: &str = "test-shadowsocks-2022-password";

// ── Helpers ───────────────────────────────────────────────────────────────────

fn unused_local_port() -> u16 {
    let l = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    l.local_addr().unwrap().port()
}

fn parse_config(json: String) -> Arc<blackwire_config::schema::Config> {
    Arc::new(serde_json::from_str(&json).expect("config parse failed"))
}

async fn spawn_echo_server() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 8192];
        loop {
            let n = stream.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            stream.write_all(&buf[..n]).await.unwrap();
        }
    });
    (port, task)
}

/// Build a server config: SS-2022 inbound + Freedom outbound.
fn ss2022_server_config(ss_port: u16) -> Arc<blackwire_config::schema::Config> {
    parse_config(format!(
        r#"{{
            "inbounds": [{{
                "tag": "ss-in",
                "protocol": "shadowsocks",
                "listen": "127.0.0.1",
                "port": {ss_port},
                "settings": {{
                    "method": "2022-blake3-aes-256-gcm",
                    "password": "{SS_PASSWORD}"
                }}
            }}],
            "outbounds": [{{
                "tag": "freedom",
                "protocol": "freedom"
            }}]
        }}"#
    ))
}

/// Build a client config: SOCKS5 inbound + SS-2022 outbound.
fn ss2022_client_config(
    socks_port: u16,
    ss_server_port: u16,
) -> Arc<blackwire_config::schema::Config> {
    parse_config(format!(
        r#"{{
            "inbounds": [{{
                "tag": "socks-in",
                "protocol": "socks",
                "listen": "127.0.0.1",
                "port": {socks_port}
            }}],
            "outbounds": [{{
                "tag": "ss-out",
                "protocol": "shadowsocks",
                "settings": {{
                    "address": "127.0.0.1",
                    "port": {ss_server_port},
                    "method": "2022-blake3-aes-256-gcm",
                    "password": "{SS_PASSWORD}"
                }}
            }}]
        }}"#
    ))
}

/// Perform a SOCKS5 CONNECT handshake and return the ready stream.
async fn socks5_connect(socks_port: u16, dest: &str, dest_port: u16) -> tokio::net::TcpStream {
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", socks_port))
        .await
        .unwrap();

    // SOCKS5 greeting: version=5, nmethods=1, method=0 (no auth).
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp[0], 5, "SOCKS5 version mismatch");

    // SOCKS5 CONNECT request.
    let host = dest.as_bytes();
    let mut req = vec![5, 1, 0, 3, host.len() as u8];
    req.extend_from_slice(host);
    req.extend_from_slice(&dest_port.to_be_bytes());
    stream.write_all(&req).await.unwrap();

    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0, "SOCKS5 CONNECT failed");

    stream
}

// ── Integration tests ─────────────────────────────────────────────────────────

/// Full chain: SOCKS5 → SS-2022 outbound → SS-2022 inbound → Freedom → echo server.
#[tokio::test]
async fn ss2022_full_chain_echo() {
    let ss_port = unused_local_port();
    let socks_port = unused_local_port();
    let (echo_port, echo_task) = spawn_echo_server().await;

    let _server = blackwire_core::Instance::from_config(ss2022_server_config(ss_port))
        .await
        .unwrap();
    let _client = blackwire_core::Instance::from_config(ss2022_client_config(socks_port, ss_port))
        .await
        .unwrap();
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    let mut stream = socks5_connect(socks_port, "127.0.0.1", echo_port).await;

    let payload = b"Hello, SS-2022!";
    stream.write_all(payload).await.unwrap();

    let mut got = vec![0u8; payload.len()];
    stream.read_exact(&mut got).await.unwrap();
    assert_eq!(got, payload, "echo mismatch");

    echo_task.abort();
}

/// Large payload (> 16 KiB) to verify chunked framing.
#[tokio::test]
async fn ss2022_large_payload_echo() {
    let ss_port = unused_local_port();
    let socks_port = unused_local_port();
    let (echo_port, echo_task) = spawn_echo_server().await;

    let _server = blackwire_core::Instance::from_config(ss2022_server_config(ss_port))
        .await
        .unwrap();
    let _client = blackwire_core::Instance::from_config(ss2022_client_config(socks_port, ss_port))
        .await
        .unwrap();
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    let mut stream = socks5_connect(socks_port, "127.0.0.1", echo_port).await;
    let payload = vec![0xCDu8; 64 * 1024]; // 64 KiB

    stream.write_all(&payload).await.unwrap();
    let mut got = vec![0u8; payload.len()];
    stream.read_exact(&mut got).await.unwrap();
    assert_eq!(got, payload);

    echo_task.abort();
}

/// Subkey derivation is deterministic and produces 32-byte keys.
#[test]
fn subkey_derivation_deterministic() {
    use blackwire_protocol::ss2022::subkey::derive_subkey;

    let psk = blackwire_protocol::ss2022::password_to_psk(SS_PASSWORD);
    let salt = [0x42u8; 32];

    let k1 = derive_subkey(&psk, &salt);
    let k2 = derive_subkey(&psk, &salt);
    assert_eq!(k1, k2, "subkey must be deterministic");
    assert_eq!(k1.len(), 32, "subkey must be 32 bytes");
}

/// Different salts produce different subkeys.
#[test]
fn subkey_salt_uniqueness() {
    use blackwire_protocol::ss2022::subkey::derive_subkey;

    let psk = blackwire_protocol::ss2022::password_to_psk(SS_PASSWORD);
    let salt1 = [0x01u8; 32];
    let salt2 = [0x02u8; 32];

    let k1 = derive_subkey(&psk, &salt1);
    let k2 = derive_subkey(&psk, &salt2);
    assert_ne!(k1, k2, "different salts must produce different subkeys");
}

/// Anti-replay filter accepts first use and rejects duplicate.
#[tokio::test]
async fn anti_replay_filter() {
    use blackwire_protocol::ss2022::SaltReplay;

    let replay = SaltReplay::new();
    let salt = [0xABu8; 32];

    assert!(
        replay.check_and_insert(&salt),
        "first use should be accepted"
    );
    assert!(
        !replay.check_and_insert(&salt),
        "duplicate use should be rejected"
    );
}

/// SS-2022 stream encrypt/decrypt roundtrip (unit level, no TCP).
#[tokio::test]
async fn stream_encrypt_decrypt_roundtrip() {
    use blackwire_protocol::ss2022::{
        password_to_psk, stream::Ss2022Stream, subkey::derive_subkey,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let psk = password_to_psk(SS_PASSWORD);
    let salt = [0x55u8; 32];
    let subkey = derive_subkey(&psk, &salt);

    let payload = b"SS-2022 stream roundtrip test";
    let (client_half, server_half) = tokio::io::duplex(65536);

    let subkey_c = subkey;
    let handle = tokio::spawn(async move {
        let mut writer = Ss2022Stream::new(Box::new(client_half), &subkey_c);
        writer.write_all(payload).await.unwrap();
        writer.flush().await.unwrap();
    });

    let mut reader = Ss2022Stream::new(Box::new(server_half), &subkey);
    let mut out = vec![0u8; payload.len()];
    reader.read_exact(&mut out).await.unwrap();
    handle.await.unwrap();

    assert_eq!(out, payload);
}

/// Server config with wrong password should be built (it only fails at connection time).
#[test]
fn ss2022_config_parses() {
    let port = unused_local_port();
    let config = ss2022_server_config(port);
    assert_eq!(config.inbounds.len(), 1);
    assert_eq!(config.outbounds.len(), 1);
}
