//! End-to-end tests for VMess protocol.
//!
//! Tests the full VMess inbound + outbound chain with Freedom outbound.
//!
//! Test topology:
//!
//!   Test client (VMess outbound)
//!       → VMess inbound on server proxy
//!       → Freedom outbound (direct TCP)
//!       → TCP echo server

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const TEST_UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

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
        let mut buf = [0u8; 4096];
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

fn vmess_server_config(vmess_port: u16) -> Arc<blackwire_config::schema::Config> {
    parse_config(format!(
        r#"{{
            "inbounds": [{{
                "tag": "vmess-in",
                "protocol": "vmess",
                "listen": "127.0.0.1",
                "port": {vmess_port},
                "settings": {{
                    "clients": [{{
                        "id": "{TEST_UUID}",
                        "email": "test@example.com"
                    }}]
                }}
            }}],
            "outbounds": [{{
                "tag": "freedom",
                "protocol": "freedom"
            }}]
        }}"#
    ))
}

fn vmess_client_config(
    socks_port: u16,
    vmess_server_port: u16,
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
                "tag": "vmess-out",
                "protocol": "vmess",
                "settings": {{
                    "address": "127.0.0.1",
                    "port": {vmess_server_port},
                    "users": [{{
                        "id": "{TEST_UUID}"
                    }}]
                }}
            }}]
        }}"#
    ))
}

async fn socks5_connect(socks_port: u16, dest: &str, dest_port: u16) -> tokio::net::TcpStream {
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", socks_port))
        .await
        .unwrap();

    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await.unwrap();

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

// ── End-to-end tests ──────────────────────────────────────────────────────────

/// VMess outbound connects to VMess inbound and data echoes.
#[tokio::test]
async fn vmess_direct_echo() {
    let vmess_port = unused_local_port();
    let _server = blackwire_core::Instance::from_config(vmess_server_config(vmess_port))
        .await
        .unwrap();
    tokio::time::sleep(tokio::time::Duration::from_millis(30)).await;

    // Create a VMess outbound and connect directly (no SOCKS).
    let uuid = *uuid::Uuid::parse_str(TEST_UUID).unwrap().as_bytes();
    let cmd_key = blackwire_protocol::vmess::auth::cmd_key(&uuid);
    let dest = blackwire_common::Address::Domain("127.0.0.1".to_string(), 0);
    let _ = (uuid, cmd_key, dest); // just verify they compile

    // Use SOCKS+VMess chain for actual data test.
    let socks_port = unused_local_port();
    let (echo_port, echo_task) = spawn_echo_server().await;

    let _client =
        blackwire_core::Instance::from_config(vmess_client_config(socks_port, vmess_port))
            .await
            .unwrap();
    tokio::time::sleep(tokio::time::Duration::from_millis(30)).await;

    let mut stream = socks5_connect(socks_port, "127.0.0.1", echo_port).await;

    let payload = b"vmess echo test";
    stream.write_all(payload).await.unwrap();

    let mut got = vec![0u8; payload.len()];
    stream.read_exact(&mut got).await.unwrap();
    assert_eq!(got, payload);

    echo_task.abort();
}

/// VMess with a larger payload (verifies chunked framing).
#[tokio::test]
async fn vmess_large_payload_echo() {
    let vmess_port = unused_local_port();
    let socks_port = unused_local_port();
    let (echo_port, echo_task) = spawn_echo_server().await;

    let _server = blackwire_core::Instance::from_config(vmess_server_config(vmess_port))
        .await
        .unwrap();
    let _client =
        blackwire_core::Instance::from_config(vmess_client_config(socks_port, vmess_port))
            .await
            .unwrap();
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    let mut stream = socks5_connect(socks_port, "127.0.0.1", echo_port).await;
    let payload = vec![0xABu8; 4096];
    stream.write_all(&payload).await.unwrap();

    let mut got = vec![0u8; payload.len()];
    stream.read_exact(&mut got).await.unwrap();
    assert_eq!(got, payload);

    echo_task.abort();
}

/// Auth with an unrecognized UUID is rejected.
#[tokio::test]
async fn vmess_unknown_uuid_rejected() {
    let vmess_port = unused_local_port();
    let _server = blackwire_core::Instance::from_config(vmess_server_config(vmess_port))
        .await
        .unwrap();
    tokio::time::sleep(tokio::time::Duration::from_millis(30)).await;

    // Try to connect with a random UUID (wrong user).
    let wrong_uuid = [0u8; 16];
    let wrong_cmd_key = blackwire_protocol::vmess::auth::cmd_key(&wrong_uuid);
    let fake_auth = blackwire_protocol::vmess::auth::generate_auth_id(&wrong_cmd_key);

    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", vmess_port))
        .await
        .unwrap();

    // Send the fake auth ID — server should reject.
    stream.write_all(&fake_auth).await.unwrap();

    // Server should close the connection.
    let mut buf = [0u8; 16];
    let result = stream.read(&mut buf).await;
    match result {
        Ok(0) => {}  // EOF — expected
        Err(_) => {} // error — also OK
        Ok(n) => panic!("server sent unexpected bytes: {:?}", &buf[..n]),
    }
}

// ── KDF unit tests ────────────────────────────────────────────────────────────

#[test]
fn kdf_deterministic() {
    use blackwire_protocol::vmess::kdf::kdf;
    let a: [u8; 16] = kdf(b"key", &[b"path"]);
    let b: [u8; 16] = kdf(b"key", &[b"path"]);
    assert_eq!(a, b);
}

#[test]
fn kdf_different_paths_differ() {
    use blackwire_protocol::vmess::kdf::kdf;
    let a: [u8; 16] = kdf(b"key", &[b"a"]);
    let b: [u8; 16] = kdf(b"key", &[b"b"]);
    assert_ne!(a, b);
}

// ── Auth ID unit tests ────────────────────────────────────────────────────────

#[test]
fn auth_id_roundtrip() {
    use blackwire_protocol::vmess::auth::{
        cmd_key, generate_auth_id_at, validate_auth_id, MAX_TIME_DIFF_SECS,
    };
    let uuid = *uuid::Uuid::parse_str(TEST_UUID).unwrap().as_bytes();
    let key = cmd_key(&uuid);
    let now = blackwire_protocol::vmess::auth::current_timestamp();
    let auth = generate_auth_id_at(&key, now);
    assert!(validate_auth_id(&key, &auth, MAX_TIME_DIFF_SECS));
}

#[test]
fn auth_id_wrong_key_rejected() {
    use blackwire_protocol::vmess::auth::{
        cmd_key, generate_auth_id, validate_auth_id, MAX_TIME_DIFF_SECS,
    };
    let uuid = *uuid::Uuid::parse_str(TEST_UUID).unwrap().as_bytes();
    let key = cmd_key(&uuid);
    let auth = generate_auth_id(&key);

    let wrong_key = [0u8; 16];
    assert!(!validate_auth_id(&wrong_key, &auth, MAX_TIME_DIFF_SECS));
}

// ── Codec unit tests ──────────────────────────────────────────────────────────

#[test]
fn vmess_header_encode_decode_domain() {
    use blackwire_protocol::vmess::{
        auth::{cmd_key, generate_auth_id},
        codec::{decode_header, encode_header, Security},
    };

    let uuid = *uuid::Uuid::parse_str(TEST_UUID).unwrap().as_bytes();
    let key = cmd_key(&uuid);
    let auth = generate_auth_id(&key);
    let dest = blackwire_common::Address::Domain("test.example.com".to_string(), 443);

    let (iv, kk, v, connection_nonce, _enc_len, enc_header) =
        encode_header(&key, &auth, &dest, Security::Aes128Gcm).unwrap();

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let mut cursor = std::io::Cursor::new(enc_header.to_vec());
        let req = decode_header(
            &mut cursor,
            &key,
            &auth,
            &connection_nonce,
            enc_header.len() - 16,
        )
        .await
        .unwrap();
        assert_eq!(req.iv, iv);
        assert_eq!(req.key, kk);
        assert_eq!(req.v, v);
        assert_eq!(req.dest, dest);
    });
}

#[test]
fn vmess_header_encode_decode_ipv4() {
    use blackwire_protocol::vmess::{
        auth::{cmd_key, generate_auth_id},
        codec::{decode_header, encode_header, Security},
    };

    let uuid = *uuid::Uuid::parse_str(TEST_UUID).unwrap().as_bytes();
    let key = cmd_key(&uuid);
    let auth = generate_auth_id(&key);
    let dest = blackwire_common::Address::Ipv4("192.168.1.1".parse().unwrap(), 80);

    let (iv, kk, v, connection_nonce, _enc_len, enc_header) =
        encode_header(&key, &auth, &dest, Security::Aes128Gcm).unwrap();

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let mut cursor = std::io::Cursor::new(enc_header.to_vec());
        let req = decode_header(
            &mut cursor,
            &key,
            &auth,
            &connection_nonce,
            enc_header.len() - 16,
        )
        .await
        .unwrap();
        assert_eq!(req.dest, dest);
        let _ = (iv, kk, v);
    });
}
