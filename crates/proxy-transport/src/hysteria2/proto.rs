//! Hysteria2 wire format — binary encoding of auth and proxy frames.
//!
//! All multi-byte integers are big-endian.
//! This module handles encoding (Rust structs → bytes) and
//! decoding (bytes → Rust structs) for each frame type.
//!
//! # Frame types
//!
//! - `AuthRequest` / `AuthResponse` — sent on the first QUIC stream to
//!   authenticate the client and negotiate bandwidth.
//! - `TcpRequest` / `TcpResponse` — sent at the start of each proxy stream
//!   to identify the destination and confirm connectivity.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::{Context as _, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Magic bytes at the start of every auth request: ASCII "HYST".
///
/// This ensures we can detect Hysteria2 auth frames and reject non-Hysteria2
/// connections early.
const MAGIC: u32 = 0x4859_5354; // "HYST"

/// Hysteria2 protocol version byte used in auth frames.
const PROTO_VERSION: u8 = 0x02;

/// Auth request frame — sent by the client on the first QUIC stream.
///
/// Wire layout:
/// ```text
/// [magic: 4 bytes = 0x48595354 "HYST"]
/// [version: 1 byte = 0x02]
/// [auth_len: 2 bytes BE]
/// [auth: auth_len bytes — the password UTF-8]
/// [up_mbps: 4 bytes BE]
/// [down_mbps: 4 bytes BE]
/// [padding_len: 2 bytes BE]
/// [padding: padding_len random bytes]
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct AuthRequest {
    /// Client authentication password.
    pub auth: String,
    /// Client's desired upstream bandwidth in Mbps.
    pub up_mbps: u32,
    /// Client's desired downstream bandwidth in Mbps.
    pub down_mbps: u32,
}

/// Auth response frame — sent by the server after receiving an AuthRequest.
///
/// Wire layout:
/// ```text
/// [status: 1 byte — 0x00=OK, 0x01=auth_failed]
/// [up_mbps: 4 bytes BE — server-allowed upstream]
/// [down_mbps: 4 bytes BE — server-allowed downstream]
/// [padding_len: 2 bytes BE]
/// [padding: padding_len bytes]
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct AuthResponse {
    /// Whether authentication succeeded.
    pub ok: bool,
    /// Server-allowed upstream bandwidth in Mbps.
    pub up_mbps: u32,
    /// Server-allowed downstream bandwidth in Mbps.
    pub down_mbps: u32,
}

/// TCP proxy request — sent by the client at the start of each proxy stream.
///
/// Wire layout:
/// ```text
/// [addr_type: 1 byte — 0x01=IPv4, 0x02=IPv6, 0x03=domain]
///   IPv4: [4 bytes]
///   IPv6: [16 bytes]
///   domain: [name_len: 1 byte][name: name_len bytes UTF-8]
/// [port: 2 bytes BE]
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct TcpRequest {
    /// Destination address (host + port).
    pub dest: Destination,
}

/// TCP proxy response — sent by the server to confirm it can reach the destination.
///
/// Wire layout:
/// ```text
/// [status: 1 byte — 0x00=OK, 0x01=error]
/// [msg_len: 2 bytes BE]
/// [msg: msg_len bytes UTF-8]
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct TcpResponse {
    /// Whether the server can reach the destination.
    pub ok: bool,
    /// Human-readable message (empty on success, error details on failure).
    pub message: String,
}

/// A destination address and port.
#[derive(Debug, Clone, PartialEq)]
pub enum Destination {
    /// IPv4 address and port.
    V4(Ipv4Addr, u16),
    /// IPv6 address and port.
    V6(Ipv6Addr, u16),
    /// Domain name and port.
    Domain(String, u16),
}

/// Encode and write an `AuthRequest` to `w`.
pub async fn encode_auth_request<W: AsyncWrite + Unpin>(
    w: &mut W,
    req: &AuthRequest,
) -> io::Result<()> {
    let auth_bytes = req.auth.as_bytes();
    let padding: Vec<u8> = vec![0u8; 0]; // no padding for simplicity

    w.write_u32(MAGIC).await?;
    w.write_u8(PROTO_VERSION).await?;
    w.write_u16(auth_bytes.len() as u16).await?;
    w.write_all(auth_bytes).await?;
    w.write_u32(req.up_mbps).await?;
    w.write_u32(req.down_mbps).await?;
    w.write_u16(padding.len() as u16).await?;
    w.write_all(&padding).await?;
    Ok(())
}

/// Read and decode an `AuthRequest` from `r`.
pub async fn decode_auth_request<R: AsyncRead + Unpin>(r: &mut R) -> Result<AuthRequest> {
    let magic = r.read_u32().await.context("reading magic")?;
    anyhow::ensure!(
        magic == MAGIC,
        "bad magic: expected 0x{MAGIC:08X}, got 0x{magic:08X}"
    );

    let version = r.read_u8().await.context("reading version")?;
    anyhow::ensure!(
        version == PROTO_VERSION,
        "unsupported Hysteria2 version: {version}"
    );

    let auth_len = r.read_u16().await.context("reading auth_len")? as usize;
    let mut auth_bytes = vec![0u8; auth_len];
    r.read_exact(&mut auth_bytes)
        .await
        .context("reading auth password")?;
    let auth = String::from_utf8(auth_bytes).context("auth password is not valid UTF-8")?;

    let up_mbps = r.read_u32().await.context("reading up_mbps")?;
    let down_mbps = r.read_u32().await.context("reading down_mbps")?;

    // Read and discard padding.
    let padding_len = r.read_u16().await.context("reading padding_len")? as usize;
    let mut padding = vec![0u8; padding_len];
    r.read_exact(&mut padding)
        .await
        .context("reading padding")?;

    Ok(AuthRequest {
        auth,
        up_mbps,
        down_mbps,
    })
}

/// Encode and write an `AuthResponse` to `w`.
pub async fn encode_auth_response<W: AsyncWrite + Unpin>(
    w: &mut W,
    resp: &AuthResponse,
) -> io::Result<()> {
    let status: u8 = if resp.ok { 0x00 } else { 0x01 };
    let padding: Vec<u8> = vec![0u8; 0];

    w.write_u8(status).await?;
    w.write_u32(resp.up_mbps).await?;
    w.write_u32(resp.down_mbps).await?;
    w.write_u16(padding.len() as u16).await?;
    w.write_all(&padding).await?;
    Ok(())
}

/// Read and decode an `AuthResponse` from `r`.
pub async fn decode_auth_response<R: AsyncRead + Unpin>(r: &mut R) -> Result<AuthResponse> {
    let status = r.read_u8().await.context("reading status")?;
    let ok = status == 0x00;

    let up_mbps = r.read_u32().await.context("reading up_mbps")?;
    let down_mbps = r.read_u32().await.context("reading down_mbps")?;

    // Read and discard padding.
    let padding_len = r.read_u16().await.context("reading padding_len")? as usize;
    let mut padding = vec![0u8; padding_len];
    r.read_exact(&mut padding)
        .await
        .context("reading padding")?;

    Ok(AuthResponse { ok, up_mbps, down_mbps })
}

/// Encode and write a `TcpRequest` to `w`.
pub async fn encode_tcp_request<W: AsyncWrite + Unpin>(
    w: &mut W,
    req: &TcpRequest,
) -> io::Result<()> {
    match &req.dest {
        Destination::V4(ip, port) => {
            w.write_u8(0x01).await?;
            w.write_all(&ip.octets()).await?;
            w.write_u16(*port).await?;
        }
        Destination::V6(ip, port) => {
            w.write_u8(0x02).await?;
            w.write_all(&ip.octets()).await?;
            w.write_u16(*port).await?;
        }
        Destination::Domain(name, port) => {
            let name_bytes = name.as_bytes();
            w.write_u8(0x03).await?;
            w.write_u8(name_bytes.len() as u8).await?;
            w.write_all(name_bytes).await?;
            w.write_u16(*port).await?;
        }
    }
    Ok(())
}

/// Read and decode a `TcpRequest` from `r`.
pub async fn decode_tcp_request<R: AsyncRead + Unpin>(r: &mut R) -> Result<TcpRequest> {
    let addr_type = r.read_u8().await.context("reading addr_type")?;
    let dest = match addr_type {
        0x01 => {
            // IPv4
            let mut octets = [0u8; 4];
            r.read_exact(&mut octets).await.context("reading IPv4")?;
            let port = r.read_u16().await.context("reading port")?;
            Destination::V4(Ipv4Addr::from(octets), port)
        }
        0x02 => {
            // IPv6
            let mut octets = [0u8; 16];
            r.read_exact(&mut octets).await.context("reading IPv6")?;
            let port = r.read_u16().await.context("reading port")?;
            Destination::V6(Ipv6Addr::from(octets), port)
        }
        0x03 => {
            // Domain
            let name_len = r.read_u8().await.context("reading name_len")? as usize;
            let mut name_bytes = vec![0u8; name_len];
            r.read_exact(&mut name_bytes)
                .await
                .context("reading domain name")?;
            let name =
                String::from_utf8(name_bytes).context("domain name is not valid UTF-8")?;
            let port = r.read_u16().await.context("reading port")?;
            Destination::Domain(name, port)
        }
        t => anyhow::bail!("unknown address type: 0x{t:02X}"),
    };
    Ok(TcpRequest { dest })
}

/// Encode and write a `TcpResponse` to `w`.
pub async fn encode_tcp_response<W: AsyncWrite + Unpin>(
    w: &mut W,
    resp: &TcpResponse,
) -> io::Result<()> {
    let status: u8 = if resp.ok { 0x00 } else { 0x01 };
    let msg_bytes = resp.message.as_bytes();

    w.write_u8(status).await?;
    w.write_u16(msg_bytes.len() as u16).await?;
    w.write_all(msg_bytes).await?;
    Ok(())
}

/// Read and decode a `TcpResponse` from `r`.
pub async fn decode_tcp_response<R: AsyncRead + Unpin>(r: &mut R) -> Result<TcpResponse> {
    let status = r.read_u8().await.context("reading status")?;
    let ok = status == 0x00;

    let msg_len = r.read_u16().await.context("reading msg_len")? as usize;
    let mut msg_bytes = vec![0u8; msg_len];
    r.read_exact(&mut msg_bytes)
        .await
        .context("reading message")?;
    let message = String::from_utf8(msg_bytes).context("response message is not valid UTF-8")?;

    Ok(TcpResponse { ok, message })
}

/// Convert a `Destination` to a string for display.
impl Destination {
    /// Format the destination as `host:port`.
    pub fn to_host_port(&self) -> (String, u16) {
        match self {
            Destination::V4(ip, port) => (ip.to_string(), *port),
            Destination::V6(ip, port) => (format!("[{ip}]"), *port),
            Destination::Domain(name, port) => (name.clone(), *port),
        }
    }
}

impl From<SocketAddr> for Destination {
    fn from(addr: SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(a) => Destination::V4(*a.ip(), a.port()),
            SocketAddr::V6(a) => Destination::V6(*a.ip(), a.port()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::BufReader;

    macro_rules! roundtrip_test {
        ($name:ident, $encode:ident, $decode:ident, $val:expr) => {
            #[tokio::test]
            async fn $name() {
                let mut buf = Vec::new();
                $encode(&mut buf, &$val).await.unwrap();
                let mut reader = BufReader::new(buf.as_slice());
                let decoded = $decode(&mut reader).await.unwrap();
                assert_eq!($val, decoded);
            }
        };
    }

    roundtrip_test!(
        auth_request_roundtrip,
        encode_auth_request,
        decode_auth_request,
        AuthRequest {
            auth: "secret-password".to_string(),
            up_mbps: 100,
            down_mbps: 200,
        }
    );

    roundtrip_test!(
        auth_response_ok_roundtrip,
        encode_auth_response,
        decode_auth_response,
        AuthResponse {
            ok: true,
            up_mbps: 100,
            down_mbps: 200,
        }
    );

    roundtrip_test!(
        auth_response_fail_roundtrip,
        encode_auth_response,
        decode_auth_response,
        AuthResponse {
            ok: false,
            up_mbps: 0,
            down_mbps: 0,
        }
    );

    roundtrip_test!(
        tcp_request_ipv4_roundtrip,
        encode_tcp_request,
        decode_tcp_request,
        TcpRequest {
            dest: Destination::V4("1.2.3.4".parse().unwrap(), 443),
        }
    );

    roundtrip_test!(
        tcp_request_ipv6_roundtrip,
        encode_tcp_request,
        decode_tcp_request,
        TcpRequest {
            dest: Destination::V6("2001:db8::1".parse().unwrap(), 8080),
        }
    );

    roundtrip_test!(
        tcp_request_domain_roundtrip,
        encode_tcp_request,
        decode_tcp_request,
        TcpRequest {
            dest: Destination::Domain("example.com".to_string(), 443),
        }
    );

    roundtrip_test!(
        tcp_response_ok_roundtrip,
        encode_tcp_response,
        decode_tcp_response,
        TcpResponse {
            ok: true,
            message: String::new(),
        }
    );

    roundtrip_test!(
        tcp_response_error_roundtrip,
        encode_tcp_response,
        decode_tcp_response,
        TcpResponse {
            ok: false,
            message: "connection refused".to_string(),
        }
    );
}
