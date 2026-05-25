//! Hysteria2 wire format — HTTP/3 auth and QUIC-varint TCP/UDP framing.
//!
//! Auth uses HTTP/3 request/response headers per the Hysteria2 specification.
//! TCP proxy streams use QUIC variable-length integers and `host:port` address strings.

use std::io;

use anyhow::{Context as _, Result};
use http::header::{HeaderName, HeaderValue};
use http::HeaderMap;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::varint::{read_varint, write_varint};

/// HTTP/3 auth path and authority (sing-quic / official spec).
pub const AUTH_HOST: &str = "hysteria";
/// HTTP path used for authentication requests.
pub const AUTH_PATH: &str = "/auth";

/// Header that carries the shared password.
pub const HEADER_AUTH: &str = "hysteria-auth";
/// Header that tells the client whether UDP is enabled.
pub const HEADER_UDP: &str = "hysteria-udp";
/// Header that carries receive-rate hints (`bytes/sec` or `auto`).
pub const HEADER_CC_RX: &str = "hysteria-cc-rx";
/// Header used as random padding noise in auth traffic.
pub const HEADER_PADDING: &str = "hysteria-padding";

/// HTTP status code returned on successful authentication.
pub const STATUS_AUTH_OK: u16 = 233;

/// TCP request frame type on each proxy stream.
pub const FRAME_TYPE_TCP_REQUEST: u64 = 0x401;

/// Maximum accepted `host:port` length in TCP requests.
pub const MAX_ADDRESS_LENGTH: u64 = 2048;
/// Maximum accepted message length in TCP responses.
pub const MAX_MESSAGE_LENGTH: u64 = 2048;
/// Maximum accepted padding length on frames.
pub const MAX_PADDING_LENGTH: u64 = 4096;

/// Auth request — parsed from HTTP/3 headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthRequest {
    /// Shared password sent by the client.
    pub auth: String,
    /// Client receive rate in bytes per second (`Hysteria-CC-RX`). Zero means unknown.
    pub rx_bps: u64,
}

/// Auth response — encoded into HTTP/3 response headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthResponse {
    /// Whether authentication succeeded.
    pub ok: bool,
    /// Whether server supports UDP relay for this session.
    pub udp_enabled: bool,
    /// Server receive rate in bytes per second for the client to respect when uploading.
    pub rx_bps: u64,
    /// Server asks the client to pick its own rate via congestion control.
    pub rx_auto: bool,
}

/// TCP proxy request — destination as `host:port` string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpRequest {
    /// Destination in `host:port` format.
    pub addr: String,
}

/// TCP proxy response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpResponse {
    /// Whether server accepted the connect request.
    pub ok: bool,
    /// Human-readable error text when `ok` is `false`.
    pub message: String,
}

// ── Auth (HTTP/3 headers) ─────────────────────────────────────────────────────

/// Parse an auth request from HTTP/3 request headers.
pub fn auth_request_from_headers(headers: &HeaderMap) -> Result<AuthRequest> {
    let auth = header_string(headers, HEADER_AUTH)
        .ok_or_else(|| anyhow::anyhow!("missing {HEADER_AUTH} header"))?;
    let rx_bps = header_string(headers, HEADER_CC_RX)
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);
    Ok(AuthRequest { auth, rx_bps })
}

/// Write auth response headers into `headers`.
pub fn auth_response_to_headers(headers: &mut HeaderMap, resp: &AuthResponse) {
    headers.insert(
        header_name(HEADER_UDP),
        HeaderValue::from_str(&resp.udp_enabled.to_string()).expect("bool header"),
    );
    let cc = if resp.rx_auto {
        "auto".to_string()
    } else {
        resp.rx_bps.to_string()
    };
    headers.insert(
        header_name(HEADER_CC_RX),
        HeaderValue::from_str(&cc).expect("cc-rx header"),
    );
    headers.insert(header_name(HEADER_PADDING), HeaderValue::from_static(""));
}

/// Parse auth response headers from an HTTP/3 response.
pub fn auth_response_from_headers(headers: &HeaderMap, status: u16) -> AuthResponse {
    let ok = status == STATUS_AUTH_OK;
    let udp_enabled = header_string(headers, HEADER_UDP)
        .and_then(|v| v.parse().ok())
        .unwrap_or(false);
    let cc_rx = header_string(headers, HEADER_CC_RX);
    let rx_auto = cc_rx.as_deref() == Some("auto");
    let rx_bps = if rx_auto {
        0
    } else {
        cc_rx.and_then(|v| v.parse::<u64>().ok()).unwrap_or(0)
    };
    AuthResponse {
        ok,
        udp_enabled,
        rx_bps,
        rx_auto,
    }
}

/// Returns true if this HTTP request looks like a Hysteria2 auth request.
///
/// Official clients use `:authority: hysteria`; sing-box uses the TLS SNI / server
/// hostname (e.g. `blackwire.local`). Path `POST /auth` is the reliable signal.
pub fn is_auth_request(method: &str, path: &str, _authority: Option<&str>) -> bool {
    method.eq_ignore_ascii_case("POST") && path == AUTH_PATH
}

// ── TCP proxy (QUIC streams) ──────────────────────────────────────────────────

/// Encode a TCP proxy request (includes `0x401` frame type).
pub async fn encode_tcp_request<W: AsyncWrite + Unpin>(w: &mut W, addr: &str) -> io::Result<()> {
    let mut buf = Vec::new();
    write_varint(&mut buf, FRAME_TYPE_TCP_REQUEST)?;
    write_varint(&mut buf, addr.len() as u64)?;
    buf.extend_from_slice(addr.as_bytes());
    write_varint(&mut buf, 0)?;
    w.write_all(&buf).await
}

/// Decode a TCP proxy request. Consumes leading `0x401` when present.
pub async fn decode_tcp_request<R: AsyncRead + Unpin>(r: &mut R) -> Result<TcpRequest> {
    let first = read_varint(r).await.context("reading tcp frame")?;
    let addr_len = if first == FRAME_TYPE_TCP_REQUEST {
        read_varint(r).await.context("reading address length")?
    } else {
        first
    };
    anyhow::ensure!(
        addr_len > 0 && addr_len <= MAX_ADDRESS_LENGTH,
        "invalid address length: {addr_len}"
    );
    let mut addr_bytes = vec![0u8; addr_len as usize];
    r.read_exact(&mut addr_bytes)
        .await
        .context("reading address")?;
    let addr = String::from_utf8(addr_bytes).context("address is not valid UTF-8")?;
    skip_padding(r).await?;
    Ok(TcpRequest { addr })
}

/// Encode a TCP proxy response.
pub async fn encode_tcp_response<W: AsyncWrite + Unpin>(
    w: &mut W,
    resp: &TcpResponse,
) -> io::Result<()> {
    let status: u8 = if resp.ok { 0x00 } else { 0x01 };
    let msg_bytes = resp.message.as_bytes();
    let mut buf = Vec::with_capacity(16 + msg_bytes.len());
    buf.push(status);
    write_varint(&mut buf, msg_bytes.len() as u64)?;
    buf.extend_from_slice(msg_bytes);
    write_varint(&mut buf, 0)?;
    w.write_all(&buf).await
}

/// Decode a TCP proxy response.
pub async fn decode_tcp_response<R: AsyncRead + Unpin>(r: &mut R) -> Result<TcpResponse> {
    let status = r.read_u8().await.context("reading tcp status")?;
    let ok = status == 0x00;
    let msg_len = read_varint(r).await.context("reading message length")?;
    anyhow::ensure!(
        msg_len <= MAX_MESSAGE_LENGTH,
        "invalid message length: {msg_len}"
    );
    let mut msg_bytes = vec![0u8; msg_len as usize];
    if msg_len > 0 {
        r.read_exact(&mut msg_bytes)
            .await
            .context("reading message")?;
    }
    let message = String::from_utf8(msg_bytes).context("message is not valid UTF-8")?;
    skip_padding(r).await?;
    Ok(TcpResponse { ok, message })
}

async fn skip_padding<R: AsyncRead + Unpin>(r: &mut R) -> Result<()> {
    let padding_len = read_varint(r).await.context("reading padding length")?;
    anyhow::ensure!(
        padding_len <= MAX_PADDING_LENGTH,
        "invalid padding length: {padding_len}"
    );
    if padding_len > 0 {
        let mut padding = vec![0u8; padding_len as usize];
        r.read_exact(&mut padding)
            .await
            .context("reading padding")?;
    }
    Ok(())
}

fn header_name(name: &str) -> HeaderName {
    HeaderName::from_bytes(name.as_bytes()).expect("valid header name")
}

fn header_string(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::BufReader;

    #[test]
    fn auth_headers_roundtrip() {
        let mut req_headers = HeaderMap::new();
        req_headers.insert(header_name(HEADER_AUTH), HeaderValue::from_static("secret"));
        req_headers.insert(
            header_name(HEADER_CC_RX),
            HeaderValue::from_static("6250000"),
        );
        let req = auth_request_from_headers(&req_headers).unwrap();
        assert_eq!(req.auth, "secret");
        assert_eq!(req.rx_bps, 6_250_000);

        let mut resp_headers = HeaderMap::new();
        auth_response_to_headers(
            &mut resp_headers,
            &AuthResponse {
                ok: true,
                udp_enabled: true,
                rx_bps: 12_500_000,
                rx_auto: false,
            },
        );
        let resp = auth_response_from_headers(&resp_headers, STATUS_AUTH_OK);
        assert!(resp.ok);
        assert!(resp.udp_enabled);
        assert_eq!(resp.rx_bps, 12_500_000);
    }

    #[tokio::test]
    async fn tcp_request_roundtrip() {
        let addr = "example.com:443";
        let mut buf = Vec::new();
        encode_tcp_request(&mut buf, addr).await.unwrap();
        let mut reader = BufReader::new(buf.as_slice());
        let decoded = decode_tcp_request(&mut reader).await.unwrap();
        assert_eq!(decoded.addr, addr);
    }

    #[tokio::test]
    async fn tcp_response_roundtrip() {
        let resp = TcpResponse {
            ok: true,
            message: String::new(),
        };
        let mut buf = Vec::new();
        encode_tcp_response(&mut buf, &resp).await.unwrap();
        let mut reader = BufReader::new(buf.as_slice());
        let decoded = decode_tcp_response(&mut reader).await.unwrap();
        assert_eq!(decoded, resp);
    }
}
