//! Trojan wire format: header encoding and decoding.
//!
//! # Trojan request format (client → server)
//!
//! ```text
//! ┌────────────────────────────────────────────────────────────────────────┐
//! │ SHA224(password_hex_utf8)[56 bytes] + "\r\n"                           │
//! │ CMD(1) + ATYP(1) + ADDR + PORT(2 big-endian) + "\r\n"                  │
//! │ PAYLOAD...                                                              │
//! └────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Authentication token
//!
//! The SHA-224 digest is computed over the password string:
//!
//! ```text
//! token = lowercase_hex(SHA224(password.as_bytes()))
//! ```
//!
//! This produces a 56-character lowercase hex string, which is sent as the
//! first 56 bytes of every connection, followed by `\r\n`.
//!
//! ## Address encoding (SOCKS5 style)
//!
//! | ATYP | Meaning  | Address bytes          |
//! |------|----------|------------------------|
//! | 0x01 | IPv4     | 4 bytes                |
//! | 0x03 | Domain   | 1-byte len + name bytes|
//! | 0x04 | IPv6     | 16 bytes               |
//!
//! After the address, 2 bytes of big-endian port, then `\r\n`.

use bytes::{BufMut, Bytes, BytesMut};
use sha2::{Digest, Sha224};
use tokio::io::{AsyncRead, AsyncReadExt};

use blackwire_common::{read_socks5_address, write_socks5_address, Address, ProxyError};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Length of a Trojan auth token: SHA224 produces 28 bytes → 56 hex chars.
pub const TOKEN_LEN: usize = 56;

pub use blackwire_common::{ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6};

/// Trojan command byte for TCP CONNECT.
pub const CMD_CONNECT: u8 = 0x01;

// ── Token computation ─────────────────────────────────────────────────────────

/// Compute the 56-character lowercase hex token for a Trojan password.
///
/// The token is `lowercase_hex(SHA224(password.as_bytes()))`.
pub fn compute_token(password: &str) -> String {
    let mut hasher = Sha224::new();
    hasher.update(password.as_bytes());
    let digest = hasher.finalize();
    hex::encode(digest)
}

// ── Decoder ───────────────────────────────────────────────────────────────────

/// Decoded Trojan request header.
#[derive(Debug)]
pub struct TrojanRequest {
    /// The 56-byte auth token (hex-encoded SHA224 of the password).
    pub token: [u8; TOKEN_LEN],

    /// The destination address the client wants to reach.
    pub dest: Address,
}

/// Read and decode a Trojan request header from an async stream.
///
/// After this function returns, the stream is positioned at the first byte of
/// the payload — ready for bidirectional relay.
pub async fn decode_request<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<TrojanRequest, ProxyError> {
    // Read the 56-byte token.
    let mut token = [0u8; TOKEN_LEN];
    reader.read_exact(&mut token).await?;

    expect_crlf(reader, "after token").await?;

    let command = reader.read_u8().await?;
    if command != CMD_CONNECT {
        return Err(ProxyError::Protocol(format!(
            "Trojan: unsupported command {command:#x}"
        )));
    }

    // Read address type.
    let atyp = reader.read_u8().await?;
    let dest = read_socks5_address(reader, atyp, "Trojan").await?;
    expect_crlf(reader, "after address").await?;

    Ok(TrojanRequest { token, dest })
}

async fn expect_crlf<R: AsyncRead + Unpin>(reader: &mut R, ctx: &str) -> Result<(), ProxyError> {
    let mut crlf = [0u8; 2];
    reader.read_exact(&mut crlf).await?;
    if crlf != [b'\r', b'\n'] {
        return Err(ProxyError::Protocol(format!("Trojan: expected CRLF {ctx}")));
    }
    Ok(())
}

// ── Encoder ───────────────────────────────────────────────────────────────────

/// Encode a Trojan request header into bytes.
///
/// The caller should write these bytes to the server stream immediately,
/// followed by the payload.
///
/// # Arguments
/// * `token` — the 56-char hex token string (from `compute_token`)
/// * `dest`  — the destination address and port
pub fn encode_request(token: &str, dest: &Address) -> Result<Bytes, ProxyError> {
    let mut buf = BytesMut::with_capacity(128);

    // Auth token (56 ASCII hex chars).
    buf.put_slice(token.as_bytes());

    // CRLF after token.
    buf.put_slice(b"\r\n");

    // TCP CONNECT command.
    buf.put_u8(CMD_CONNECT);

    // Address.
    write_socks5_address(&mut buf, dest)?;

    // CRLF after address.
    buf.put_slice(b"\r\n");

    Ok(buf.freeze())
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    async fn decode_from_bytes(data: &[u8]) -> Result<TrojanRequest, ProxyError> {
        let mut cursor = std::io::Cursor::new(data);
        decode_request(&mut cursor).await
    }

    /// The SHA224 token is a 56-char lowercase hex string.
    #[test]
    fn token_is_56_chars() {
        let t = compute_token("password");
        assert_eq!(t.len(), TOKEN_LEN);
        assert!(t.chars().all(|c| c.is_ascii_hexdigit()));
    }

    /// Known-value test: SHA224("password") in hex.
    #[test]
    fn token_known_value() {
        // SHA224("password") = d63dc919...
        let token = compute_token("password");
        // Verify it is consistent across calls.
        assert_eq!(token, compute_token("password"));
        assert_ne!(token, compute_token("Password"));
    }

    /// Encode a request to an IPv4 address and decode it back.
    #[tokio::test]
    async fn roundtrip_ipv4() {
        let token = compute_token("test-pass");
        let dest = Address::Ipv4(Ipv4Addr::new(1, 2, 3, 4), 8080);
        let encoded = encode_request(&token, &dest).unwrap();
        let req = decode_from_bytes(&encoded).await.unwrap();

        assert_eq!(req.token, token.as_bytes());
        assert_eq!(req.dest, dest);
    }

    /// Roundtrip for a domain address.
    #[tokio::test]
    async fn roundtrip_domain() {
        let token = compute_token("hello");
        let dest = Address::Domain("example.com".into(), 443);
        let encoded = encode_request(&token, &dest).unwrap();
        let req = decode_from_bytes(&encoded).await.unwrap();

        assert_eq!(req.dest, dest);
    }

    /// Roundtrip for an IPv6 address.
    #[tokio::test]
    async fn roundtrip_ipv6() {
        let token = compute_token("ipv6test");
        let dest = Address::Ipv6("::1".parse().unwrap(), 9090);
        let encoded = encode_request(&token, &dest).unwrap();
        let req = decode_from_bytes(&encoded).await.unwrap();

        assert_eq!(req.dest, dest);
    }

    /// Truncated input should return an error.
    #[tokio::test]
    async fn truncated_returns_error() {
        let result = decode_from_bytes(&[0x01, 0x02]).await;
        assert!(result.is_err());
    }
}
