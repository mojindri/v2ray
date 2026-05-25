//! Production-readiness tests for proxy-protocol.
//!
//! Deterministic, non-fuzz tests covering:
//! - spec-level crypto constants
//! - wire-format compatibility
//! - malformed fixed fixtures
//! - encrypted stream partial writes
//! - replay/auth safety properties
//!
//! Some tests are intentionally strict and may fail if the implementation is
//! simplified or not wire-compatible with Xray/v2ray/sing-box behavior.

use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
    time::{SystemTime, UNIX_EPOCH},
};

use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio::time::{timeout, Duration};

use proxy_common::{Address, BoxedStream};

use proxy_protocol::http_connect::parse_connect_request_sync;
use proxy_protocol::ss2022::subkey::derive_subkey;
use proxy_protocol::ss2022::{password_to_psk, SaltReplay, Ss2022Stream};
use proxy_protocol::trojan::codec as trojan_codec;
use proxy_protocol::vless::codec as vless_codec;
use proxy_protocol::vmess::{auth as vmess_auth, stream::VmessStream};

const SHORT_TIMEOUT: Duration = Duration::from_millis(500);

struct LimitedWriteIo {
    inner: DuplexStream,
    max_write: usize,
}

impl LimitedWriteIo {
    fn new(inner: DuplexStream, max_write: usize) -> Self {
        assert!(max_write > 0);
        Self { inner, max_write }
    }
}

impl AsyncRead for LimitedWriteIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for LimitedWriteIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let n = self.max_write.min(buf.len());
        Pin::new(&mut self.inner).poll_write(cx, &buf[..n])
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

struct PendingOnceWriteIo {
    inner: DuplexStream,
    returned_pending: bool,
}

impl PendingOnceWriteIo {
    fn new(inner: DuplexStream) -> Self {
        Self {
            inner,
            returned_pending: false,
        }
    }
}

impl AsyncRead for PendingOnceWriteIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for PendingOnceWriteIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if !self.returned_pending {
            self.returned_pending = true;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

async fn vless_decode(data: &[u8]) -> Result<vless_codec::VlessRequest, proxy_common::ProxyError> {
    let mut c = std::io::Cursor::new(data.to_vec());
    vless_codec::decode_request(&mut c).await
}

async fn trojan_decode(
    data: &[u8],
) -> Result<trojan_codec::TrojanRequest, proxy_common::ProxyError> {
    let mut c = std::io::Cursor::new(data.to_vec());
    trojan_codec::decode_request(&mut c).await
}

// ─────────────────────────────────────────────────────────────────────────────
// Spec-constant tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn vmess_cmd_key_uses_full_vmess_magic_uuid_string() {
    use md5::{Digest, Md5};

    let uuid = [
        0x10, 0x8b, 0x3c, 0x8f, 0x99, 0xe8, 0x45, 0x88, 0x92, 0xfe, 0xa2, 0x7f, 0x1f, 0x64, 0xe3,
        0x6a,
    ];

    let mut h = Md5::new();
    h.update(uuid);
    h.update(b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
    let expected: [u8; 16] = h.finalize().into();

    assert_eq!(
        vmess_auth::cmd_key(&uuid),
        expected,
        "VMess cmd_key must use the full v2ray magic UUID string"
    );
}

#[test]
fn ss2022_subkey_uses_sip022_context_string() {
    let psk = [0x11u8; 32];
    let salt = [0x22u8; 32];

    let mut material = [0u8; 64];
    material[..32].copy_from_slice(&psk);
    material[32..].copy_from_slice(&salt);

    let expected = blake3::derive_key("shadowsocks 2022 session subkey", &material);

    assert_eq!(
        derive_subkey(&psk, &salt),
        expected,
        "SS-2022 subkey KDF context must match SIP022 exactly"
    );
}

#[test]
fn trojan_encoder_includes_command_byte_after_token_crlf() {
    let token = trojan_codec::compute_token("correct horse battery staple");
    let dest = Address::Domain("example.com".to_string(), 443);
    let encoded = trojan_codec::encode_request(&token, &dest).unwrap();

    let pos = trojan_codec::TOKEN_LEN + 2;
    assert_eq!(
        &encoded[trojan_codec::TOKEN_LEN..trojan_codec::TOKEN_LEN + 2],
        b"\r\n"
    );
    assert_eq!(
        encoded[pos], 0x01,
        "Trojan CONNECT command byte 0x01 must appear before ATYP"
    );
    assert_eq!(
        encoded[pos + 1],
        trojan_codec::ATYP_DOMAIN,
        "ATYP must follow the Trojan command byte"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// VLESS parser / encoder hardening
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn vless_roundtrips_ipv4_ipv6_domain_and_flow() {
    let uuid = [0xabu8; 16];
    let cases = [
        Address::Ipv4("1.2.3.4".parse().unwrap(), 8080),
        Address::Ipv6("2001:db8::1".parse().unwrap(), 8443),
        Address::Domain("proxy.example.com".to_string(), 443),
    ];

    for dest in cases {
        let encoded = vless_codec::encode_request(
            &uuid,
            "xtls-rprx-vision",
            vless_codec::Command::Tcp,
            &dest,
        )
        .unwrap();
        let decoded = vless_decode(&encoded).await.unwrap();
        assert_eq!(decoded.uuid, uuid);
        assert_eq!(decoded.command, vless_codec::Command::Tcp);
        assert_eq!(decoded.dest, dest);
        assert_eq!(decoded.flow, "xtls-rprx-vision");
    }
}

#[tokio::test]
async fn vless_rejects_malformed_fixed_fixtures_without_panic() {
    let uuid = [0x11u8; 16];
    let good = vless_codec::encode_request(
        &uuid,
        "",
        vless_codec::Command::Tcp,
        &Address::Domain("example.com".to_string(), 443),
    )
    .unwrap();

    for cut in 0..good.len() {
        let _ = vless_decode(&good[..cut]).await;
    }

    let mut bad_version = good.to_vec();
    bad_version[0] = 0x7f;
    assert!(vless_decode(&bad_version).await.is_err());

    let mut bad_cmd = good.to_vec();
    bad_cmd[18] = 0xff;
    assert!(vless_decode(&bad_cmd).await.is_err());

    let mut bad_atyp = good.to_vec();
    bad_atyp[21] = 0xff;
    assert!(vless_decode(&bad_atyp).await.is_err());
}

#[tokio::test]
async fn vless_rejects_invalid_utf8_domain() {
    let uuid = [0x22u8; 16];
    let mut data = BytesMut::new();
    data.put_u8(0x00);
    data.extend_from_slice(&uuid);
    data.put_u8(0x00);
    data.put_u8(vless_codec::CMD_TCP);
    data.put_u16(443);
    data.put_u8(0x02);
    data.put_u8(2);
    data.extend_from_slice(&[0xff, 0xfe]);

    assert!(vless_decode(&data).await.is_err());
}

#[test]
fn vless_encoder_must_not_silently_truncate_long_domain_or_flow() {
    let uuid = [0x33u8; 16];
    let long_domain = "a".repeat(300);
    let dest = Address::Domain(long_domain.clone(), 443);
    let encoded = vless_codec::encode_request(&uuid, "", vless_codec::Command::Tcp, &dest);
    assert!(
        encoded.is_err(),
        "domains longer than 256 bytes must be rejected"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Trojan codec hardening
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn trojan_token_is_lowercase_hex_only() {
    let token = trojan_codec::compute_token("password");
    assert_eq!(token.len(), trojan_codec::TOKEN_LEN);
    assert!(token
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
}

#[tokio::test]
async fn trojan_rejects_bad_crlf_and_truncations_without_panic() {
    let token = trojan_codec::compute_token("pw");
    let good =
        trojan_codec::encode_request(&token, &Address::Ipv4("1.2.3.4".parse().unwrap(), 443))
            .unwrap();

    for cut in 0..good.len() {
        let _ = trojan_decode(&good[..cut]).await;
    }

    let mut bad_crlf = good.to_vec();
    bad_crlf[trojan_codec::TOKEN_LEN] = b'X';
    assert!(trojan_decode(&bad_crlf).await.is_err());
}

#[test]
fn trojan_encoder_must_reject_invalid_token_length_in_production_api() {
    let bad = "short";
    let encoded =
        trojan_codec::encode_request(bad, &Address::Domain("example.com".to_string(), 443))
            .unwrap();

    assert_ne!(
        encoded.len(),
        trojan_codec::TOKEN_LEN + 2 + 1 + 1 + "example.com".len() + 2 + 2,
        "Production API should return Result and reject a short Trojan token"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// HTTP CONNECT parser hardening
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn http_connect_parses_valid_targets_and_rejects_bad_ports() {
    assert_eq!(
        parse_connect_request_sync("CONNECT example.com:443 HTTP/1.1").unwrap(),
        Address::Domain("example.com".to_string(), 443)
    );
    assert_eq!(
        parse_connect_request_sync("connect [::1]:8443 HTTP/1.1").unwrap(),
        Address::Ipv6("::1".parse().unwrap(), 8443)
    );

    assert!(parse_connect_request_sync("GET example.com:443 HTTP/1.1").is_err());
    assert!(parse_connect_request_sync("CONNECT example.com HTTP/1.1").is_err());
    assert!(parse_connect_request_sync("CONNECT example.com:99999 HTTP/1.1").is_err());
    assert!(parse_connect_request_sync("CONNECT example.com:notaport HTTP/1.1").is_err());
}

#[test]
fn http_connect_rejects_empty_host_target() {
    assert!(
        parse_connect_request_sync("CONNECT :443 HTTP/1.1").is_err(),
        "empty hosts should be rejected"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// VMess auth / replay properties
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn vmess_auth_accepts_current_rejects_stale_and_wrong_key() {
    let uuid = [0x44u8; 16];
    let key = vmess_auth::cmd_key(&uuid);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let current = vmess_auth::generate_auth_id_at(&key, now);
    assert!(vmess_auth::validate_auth_id(
        &key,
        &current,
        vmess_auth::MAX_TIME_DIFF_SECS
    ));

    let stale = vmess_auth::generate_auth_id_at(&key, now - vmess_auth::MAX_TIME_DIFF_SECS - 10);
    assert!(!vmess_auth::validate_auth_id(
        &key,
        &stale,
        vmess_auth::MAX_TIME_DIFF_SECS
    ));

    let wrong_key = vmess_auth::cmd_key(&[0x45u8; 16]);
    assert!(!vmess_auth::validate_auth_id(
        &wrong_key,
        &current,
        vmess_auth::MAX_TIME_DIFF_SECS
    ));
}

// ─────────────────────────────────────────────────────────────────────────────
// Encrypted stream partial-write / Pending tests
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn vmess_stream_survives_one_byte_inner_writes() {
    let key = [0x55u8; 16];
    let iv = [0x66u8; 16];
    let payload: Vec<u8> = (0..128 * 1024).map(|i| (i % 251) as u8).collect();

    let (client_raw, server_raw) = tokio::io::duplex(512 * 1024);
    let limited_client: BoxedStream = Box::new(LimitedWriteIo::new(client_raw, 1));

    let mut writer = VmessStream::new(limited_client, &key, &iv);
    let mut reader = VmessStream::new(Box::new(server_raw), &key, &iv);

    writer.write_all(&payload).await.unwrap();
    timeout(SHORT_TIMEOUT, writer.flush())
        .await
        .expect("VMess flush timed out")
        .expect("VMess flush failed");

    let mut out = vec![0u8; payload.len()];
    timeout(SHORT_TIMEOUT, reader.read_exact(&mut out))
        .await
        .expect("VMess read timed out")
        .expect("VMess read failed");

    assert_eq!(out, payload);
}

#[tokio::test]
async fn vmess_stream_survives_pending_inner_write() {
    let key = [0x77u8; 16];
    let iv = [0x88u8; 16];
    let payload = b"vmess pending write must not lose encrypted bytes";

    let (client_raw, server_raw) = tokio::io::duplex(64 * 1024);
    let pending_client: BoxedStream = Box::new(PendingOnceWriteIo::new(client_raw));

    let mut writer = VmessStream::new(pending_client, &key, &iv);
    let mut reader = VmessStream::new(Box::new(server_raw), &key, &iv);

    writer.write_all(payload).await.unwrap();
    timeout(SHORT_TIMEOUT, writer.flush())
        .await
        .expect("VMess flush timed out")
        .expect("VMess flush failed");

    let mut out = vec![0u8; payload.len()];
    timeout(SHORT_TIMEOUT, reader.read_exact(&mut out))
        .await
        .expect("VMess read timed out")
        .expect("VMess read failed");

    assert_eq!(&out, payload);
}

#[tokio::test]
async fn ss2022_stream_survives_one_byte_inner_writes() {
    let psk = password_to_psk("test-password");
    let salt = [0x99u8; 32];
    let subkey = derive_subkey(&psk, &salt);
    let payload: Vec<u8> = (0..128 * 1024).map(|i| (i % 253) as u8).collect();

    let (client_raw, server_raw) = tokio::io::duplex(512 * 1024);
    let limited_client: BoxedStream = Box::new(LimitedWriteIo::new(client_raw, 1));

    let mut writer = Ss2022Stream::new(limited_client, &subkey);
    let mut reader = Ss2022Stream::new(Box::new(server_raw), &subkey);

    writer.write_all(&payload).await.unwrap();
    timeout(SHORT_TIMEOUT, writer.flush())
        .await
        .expect("SS-2022 flush timed out")
        .expect("SS-2022 flush failed");

    let mut out = vec![0u8; payload.len()];
    timeout(SHORT_TIMEOUT, reader.read_exact(&mut out))
        .await
        .expect("SS-2022 read timed out")
        .expect("SS-2022 read failed");

    assert_eq!(out, payload);
}

#[tokio::test]
async fn ss2022_stream_survives_pending_inner_write() {
    let psk = password_to_psk("test-password");
    let salt = [0xaau8; 32];
    let subkey = derive_subkey(&psk, &salt);
    let payload = b"ss2022 pending write must not lose encrypted bytes";

    let (client_raw, server_raw) = tokio::io::duplex(64 * 1024);
    let pending_client: BoxedStream = Box::new(PendingOnceWriteIo::new(client_raw));

    let mut writer = Ss2022Stream::new(pending_client, &subkey);
    let mut reader = Ss2022Stream::new(Box::new(server_raw), &subkey);

    writer.write_all(payload).await.unwrap();
    timeout(SHORT_TIMEOUT, writer.flush())
        .await
        .expect("SS-2022 flush timed out")
        .expect("SS-2022 flush failed");

    let mut out = vec![0u8; payload.len()];
    timeout(SHORT_TIMEOUT, reader.read_exact(&mut out))
        .await
        .expect("SS-2022 read timed out")
        .expect("SS-2022 read failed");

    assert_eq!(&out, payload);
}

// ─────────────────────────────────────────────────────────────────────────────
// Replay filter behavior
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn ss2022_replay_rejects_duplicate_salts_and_accepts_distinct_salts() {
    let replay = SaltReplay::new();
    let a = [0x01u8; 32];
    let b = [0x02u8; 32];

    assert!(replay.check_and_insert(&a));
    assert!(!replay.check_and_insert(&a));
    assert!(replay.check_and_insert(&b));
}

// ─────────────────────────────────────────────────────────────────────────────
// Idle / incomplete stream behavior
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn vmess_stream_idle_read_does_not_complete() {
    let key = [0xbbu8; 16];
    let iv = [0xccu8; 16];
    let (_writer, reader) = tokio::io::duplex(1024);
    let mut stream = VmessStream::new(Box::new(reader), &key, &iv);

    let mut out = [0u8; 1];
    let res = timeout(Duration::from_millis(100), stream.read_exact(&mut out)).await;
    assert!(res.is_err(), "idle VMess read completed unexpectedly");
}

#[tokio::test]
async fn ss2022_stream_idle_read_does_not_complete() {
    let psk = password_to_psk("test-password");
    let subkey = derive_subkey(&psk, &[0xddu8; 32]);
    let (_writer, reader) = tokio::io::duplex(1024);
    let mut stream = Ss2022Stream::new(Box::new(reader), &subkey);

    let mut out = [0u8; 1];
    let res = timeout(Duration::from_millis(100), stream.read_exact(&mut out)).await;
    assert!(res.is_err(), "idle SS-2022 read completed unexpectedly");
}
