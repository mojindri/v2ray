//! Hysteria2 wire format — HTTP/1.1 auth over QUIC stream 0, then SOCKS5-style
//! TCP proxy frames on subsequent streams.
//!
//! All multi-byte integers are big-endian.
//!
//! # Auth handshake (stream 0)
//!
//! Client → Server (HTTP/1.1 request):
//! ```text
//! POST / HTTP/1.1\r\n
//! Host: <server_name>\r\n
//! Content-Length: 0\r\n
//! Authorization: Basic <base64(:password)>\r\n
//! Hysteria-CC-RX: <receive_bps>\r\n
//! \r\n
//! ```
//!
//! Server → Client (HTTP/1.1 response):
//! - Success:  `HTTP/1.1 233 HY\r\nHysteria-CC-RX: <bps>\r\nContent-Length: 0\r\n\r\n`
//! - Failure:  `HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n`
//!
//! # TCP proxy frames (each subsequent stream)
//!
//! Client → Server:
//! ```text
//! [uint16 BE: padding_len][padding bytes][uint8 atyp][addr][uint16 BE: port]
//! ```
//!
//! Server → Client:
//! ```text
//! [uint8: status (0=ok)][uint16 BE: msg_len][msg bytes UTF-8]
//! ```

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::{Context as _, Result};
use base64::Engine as _;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Auth request frame — sent by the client on the first QUIC stream.
#[derive(Debug, Clone, PartialEq)]
pub struct AuthRequest {
    /// Client authentication password.
    pub auth: String,
    /// Client's desired upstream bandwidth in Mbps (informational; not sent on wire).
    pub up_mbps: u32,
    /// Client's desired downstream bandwidth in Mbps (sent as `Hysteria-CC-RX`).
    pub down_mbps: u32,
}

/// Auth response frame — sent by the server after receiving an AuthRequest.
#[derive(Debug, Clone, PartialEq)]
pub struct AuthResponse {
    /// Whether authentication succeeded.
    pub ok: bool,
    /// Server-allowed upstream bandwidth in Mbps (from `Hysteria-CC-RX`).
    pub up_mbps: u32,
    /// Server-allowed downstream bandwidth in Mbps (informational; not on wire).
    pub down_mbps: u32,
}

/// TCP proxy request — sent by the client at the start of each proxy stream.
#[derive(Debug, Clone, PartialEq)]
pub struct TcpRequest {
    /// Destination address (host + port).
    pub dest: Destination,
}

/// TCP proxy response — sent by the server to confirm it can reach the destination.
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

// ── Auth encode/decode ─────────────────────────────────────────────────────────

/// Encode and write an `AuthRequest` as an HTTP/1.1 POST to `w`.
///
/// Uses `Authorization: Basic base64(:password)` and
/// `Hysteria-CC-RX: <down_mbps_in_bps>`.
pub async fn encode_auth_request<W: AsyncWrite + Unpin>(
    w: &mut W,
    req: &AuthRequest,
) -> io::Result<()> {
    let cred = format!(":{}", req.auth);
    let b64 = base64::engine::general_purpose::STANDARD.encode(cred.as_bytes());
    let down_bps = req.down_mbps as u64 * 1_000_000 / 8;

    let request = format!(
        "POST / HTTP/1.1\r\nHost: proxy\r\nContent-Length: 0\r\nAuthorization: Basic {b64}\r\nHysteria-CC-RX: {down_bps}\r\n\r\n"
    );
    w.write_all(request.as_bytes()).await
}

/// Read and decode an HTTP/1.1 `AuthRequest` from `r`.
///
/// Parses `Authorization: Basic` for the password and
/// `Hysteria-CC-RX` for the downstream bandwidth.
pub async fn decode_auth_request<R: AsyncRead + Unpin>(r: &mut R) -> Result<AuthRequest> {
    // Read and validate the request line.
    let request_line = read_http_line(r).await.context("reading request line")?;
    anyhow::ensure!(
        request_line.starts_with("POST ") || request_line.starts_with("GET "),
        "expected HTTP request line, got: {request_line:?}"
    );

    let mut auth: Option<String> = None;
    let mut down_bps: u64 = 0;

    // Read headers until the blank separator line.
    loop {
        let line = read_http_line(r).await.context("reading header line")?;
        if line.is_empty() {
            break;
        }
        if let Some(value) = line.strip_prefix("Authorization: Basic ") {
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(value.trim())
                .context("decode Authorization base64")?;
            let cred = String::from_utf8(decoded).context("auth credential is not valid UTF-8")?;
            // Hysteria2 uses empty username: the value is ":password".
            auth = Some(cred.trim_start_matches(':').to_string());
        } else if let Some(value) = line.strip_prefix("Hysteria-CC-RX: ") {
            down_bps = value.trim().parse().unwrap_or(0);
        }
    }

    let auth = auth.ok_or_else(|| anyhow::anyhow!("missing Authorization header in request"))?;
    let down_mbps = (down_bps * 8 / 1_000_000) as u32;

    Ok(AuthRequest {
        auth,
        up_mbps: 0, // not encoded in HTTP/1.1 auth request
        down_mbps,
    })
}

/// Encode and write an `AuthResponse` as an HTTP/1.1 response to `w`.
///
/// Success:  `HTTP/1.1 233 HY` with `Hysteria-CC-RX`.
/// Failure:  `HTTP/1.1 403 Forbidden`.
pub async fn encode_auth_response<W: AsyncWrite + Unpin>(
    w: &mut W,
    resp: &AuthResponse,
) -> io::Result<()> {
    if resp.ok {
        // Prefer up_mbps; fall back to down_mbps so callers can use either field.
        let cc_rx_mbps = if resp.up_mbps > 0 {
            resp.up_mbps
        } else {
            resp.down_mbps
        };
        let cc_rx_bps = cc_rx_mbps as u64 * 1_000_000 / 8;
        let response = format!(
            "HTTP/1.1 233 HY\r\nHysteria-CC-RX: {cc_rx_bps}\r\nContent-Length: 0\r\n\r\n"
        );
        w.write_all(response.as_bytes()).await
    } else {
        w.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            .await
    }
}

/// Read and decode an HTTP/1.1 `AuthResponse` from `r`.
///
/// Status `233` → ok. `Hysteria-CC-RX` is stored in `up_mbps`.
pub async fn decode_auth_response<R: AsyncRead + Unpin>(r: &mut R) -> Result<AuthResponse> {
    let status_line = read_http_line(r).await.context("reading status line")?;
    // "HTTP/1.1 233 HY" → ok; anything else → rejected.
    let ok = status_line.contains(" 233 ");

    let mut up_bps: u64 = 0;

    loop {
        let line = read_http_line(r).await.context("reading response header")?;
        if line.is_empty() {
            break;
        }
        if let Some(value) = line.strip_prefix("Hysteria-CC-RX: ") {
            up_bps = value.trim().parse().unwrap_or(0);
        }
    }

    let up_mbps = (up_bps * 8 / 1_000_000) as u32;

    Ok(AuthResponse {
        ok,
        up_mbps,
        down_mbps: 0, // not encoded in HTTP/1.1 auth response
    })
}

// ── TCP request/response encode/decode ────────────────────────────────────────

/// Encode and write a `TcpRequest` to `w`.
///
/// Wire format: `[uint16 BE padding_len=0][uint8 atyp][addr][uint16 BE port]`
pub async fn encode_tcp_request<W: AsyncWrite + Unpin>(
    w: &mut W,
    req: &TcpRequest,
) -> io::Result<()> {
    // Padding length = 0 (no padding).
    w.write_u16(0).await?;

    match &req.dest {
        Destination::V4(ip, port) => {
            w.write_u8(0x01).await?;
            w.write_all(&ip.octets()).await?;
            w.write_u16(*port).await?;
        }
        Destination::V6(ip, port) => {
            w.write_u8(0x04).await?;
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
///
/// Wire format: `[uint16 BE padding_len][padding][uint8 atyp][addr][uint16 BE port]`
pub async fn decode_tcp_request<R: AsyncRead + Unpin>(r: &mut R) -> Result<TcpRequest> {
    // Read and discard padding.
    let padding_len = r.read_u16().await.context("reading padding_len")? as usize;
    if padding_len > 0 {
        let mut padding = vec![0u8; padding_len];
        r.read_exact(&mut padding).await.context("reading padding")?;
    }

    let addr_type = r.read_u8().await.context("reading addr_type")?;
    let dest = match addr_type {
        0x01 => {
            let mut octets = [0u8; 4];
            r.read_exact(&mut octets).await.context("reading IPv4")?;
            let port = r.read_u16().await.context("reading port")?;
            Destination::V4(Ipv4Addr::from(octets), port)
        }
        0x04 => {
            let mut octets = [0u8; 16];
            r.read_exact(&mut octets).await.context("reading IPv6")?;
            let port = r.read_u16().await.context("reading port")?;
            Destination::V6(Ipv6Addr::from(octets), port)
        }
        0x03 => {
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

// ── Conversion helpers ─────────────────────────────────────────────────────────

/// Convert a `Destination` to a string for display.
impl Destination {
    /// Format the destination as `(host, port)`.
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

// ── Internal helpers ───────────────────────────────────────────────────────────

/// Read one HTTP/1.1 header line (up to `\n`), stripping `\r`.
///
/// Returns an empty string for the blank separator line `\r\n`.
async fn read_http_line<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<String> {
    let mut bytes = Vec::with_capacity(128);
    loop {
        let b = r.read_u8().await?;
        if b == b'\n' {
            break;
        }
        if b != b'\r' {
            bytes.push(b);
        }
    }
    String::from_utf8(bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::BufReader;

    // Auth request roundtrip: only `auth` and `down_mbps` survive the wire
    // (up_mbps is not sent in the HTTP/1.1 Hysteria2 auth request).
    #[tokio::test]
    async fn auth_request_roundtrip() {
        let req = AuthRequest {
            auth: "secret-password".to_string(),
            up_mbps: 0,   // not encoded on wire
            down_mbps: 200,
        };
        let mut buf = Vec::new();
        encode_auth_request(&mut buf, &req).await.unwrap();
        let mut reader = BufReader::new(buf.as_slice());
        let decoded = decode_auth_request(&mut reader).await.unwrap();
        assert_eq!(decoded.auth, req.auth);
        assert_eq!(decoded.down_mbps, req.down_mbps);
        assert_eq!(decoded.up_mbps, 0);
    }

    // Auth response success roundtrip: `ok` and `up_mbps` survive.
    #[tokio::test]
    async fn auth_response_ok_roundtrip() {
        let resp = AuthResponse {
            ok: true,
            up_mbps: 100,
            down_mbps: 0, // not encoded on wire
        };
        let mut buf = Vec::new();
        encode_auth_response(&mut buf, &resp).await.unwrap();
        let mut reader = BufReader::new(buf.as_slice());
        let decoded = decode_auth_response(&mut reader).await.unwrap();
        assert!(decoded.ok);
        assert_eq!(decoded.up_mbps, 100);
    }

    // Auth response failure roundtrip.
    #[tokio::test]
    async fn auth_response_fail_roundtrip() {
        let resp = AuthResponse {
            ok: false,
            up_mbps: 0,
            down_mbps: 0,
        };
        let mut buf = Vec::new();
        encode_auth_response(&mut buf, &resp).await.unwrap();
        let mut reader = BufReader::new(buf.as_slice());
        let decoded = decode_auth_response(&mut reader).await.unwrap();
        assert!(!decoded.ok);
    }

    macro_rules! tcp_roundtrip {
        ($name:ident, $val:expr) => {
            #[tokio::test]
            async fn $name() {
                let mut buf = Vec::new();
                encode_tcp_request(&mut buf, &$val).await.unwrap();
                let mut reader = BufReader::new(buf.as_slice());
                let decoded = decode_tcp_request(&mut reader).await.unwrap();
                assert_eq!($val, decoded);
            }
        };
    }

    tcp_roundtrip!(
        tcp_request_ipv4_roundtrip,
        TcpRequest {
            dest: Destination::V4("1.2.3.4".parse().unwrap(), 443),
        }
    );

    tcp_roundtrip!(
        tcp_request_ipv6_roundtrip,
        TcpRequest {
            dest: Destination::V6("2001:db8::1".parse().unwrap(), 8080),
        }
    );

    tcp_roundtrip!(
        tcp_request_domain_roundtrip,
        TcpRequest {
            dest: Destination::Domain("example.com".to_string(), 443),
        }
    );

    #[tokio::test]
    async fn tcp_response_ok_roundtrip() {
        let resp = TcpResponse {
            ok: true,
            message: String::new(),
        };
        let mut buf = Vec::new();
        encode_tcp_response(&mut buf, &resp).await.unwrap();
        let mut reader = BufReader::new(buf.as_slice());
        let decoded = decode_tcp_response(&mut reader).await.unwrap();
        assert_eq!(resp, decoded);
    }

    #[tokio::test]
    async fn tcp_response_error_roundtrip() {
        let resp = TcpResponse {
            ok: false,
            message: "connection refused".to_string(),
        };
        let mut buf = Vec::new();
        encode_tcp_response(&mut buf, &resp).await.unwrap();
        let mut reader = BufReader::new(buf.as_slice());
        let decoded = decode_tcp_response(&mut reader).await.unwrap();
        assert_eq!(resp, decoded);
    }

    // Verify that padding in the TCP request is skipped correctly.
    #[tokio::test]
    async fn tcp_request_with_padding_is_skipped() {
        let dest = Destination::V4("10.0.0.1".parse().unwrap(), 80);
        // Build a frame with 8 bytes of padding manually.
        let mut buf = Vec::new();
        buf.extend_from_slice(&8u16.to_be_bytes()); // padding_len
        buf.extend_from_slice(&[0xAB; 8]); // padding bytes
        buf.push(0x01); // atyp = IPv4
        buf.extend_from_slice(&[10, 0, 0, 1]); // 10.0.0.1
        buf.extend_from_slice(&80u16.to_be_bytes()); // port 80

        let mut reader = BufReader::new(buf.as_slice());
        let decoded = decode_tcp_request(&mut reader).await.unwrap();
        assert_eq!(decoded.dest, dest);
    }

    // Verify that sing-box-style auth (Authorization: Basic with colon prefix)
    // is decoded correctly.
    #[tokio::test]
    async fn decode_auth_request_strips_colon_prefix() {
        use base64::Engine as _;
        let cred = ":my-secret-password";
        let b64 = base64::engine::general_purpose::STANDARD.encode(cred.as_bytes());
        let raw = format!(
            "POST / HTTP/1.1\r\nHost: proxy.example.com\r\nContent-Length: 0\r\nAuthorization: Basic {b64}\r\nHysteria-CC-RX: 6250000\r\n\r\n"
        );
        let mut reader = BufReader::new(raw.as_bytes());
        let req = decode_auth_request(&mut reader).await.unwrap();
        assert_eq!(req.auth, "my-secret-password");
        assert_eq!(req.down_mbps, 50); // 6250000 bytes/sec * 8 / 1_000_000 = 50 Mbps
    }
}
