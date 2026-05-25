//! HTTP CONNECT inbound handler.
//!
//! HTTP CONNECT is used by browsers and many tools to tunnel HTTPS through a
//! proxy. The client sends a CONNECT request, and after the proxy responds
//! with "200 Connection established", both sides treat the connection as a
//! raw TCP tunnel.
//!
//! # Wire format (client → server)
//!
//! ```text
//! CONNECT host:port HTTP/1.1\r\n
//! Host: host:port\r\n
//! Proxy-Authorization: ...\r\n    (optional)
//! \r\n
//! ```
//!
//! # Wire format (server → client)
//!
//! ```text
//! HTTP/1.1 200 Connection established\r\n
//! \r\n
//! ```
//!
//! After the 200 response, raw bytes follow in both directions.
//!
//! # References
//!
//! RFC 7231 §4.3.6 — Tunnel

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::debug;

use blackwire_app::context::Context;
use blackwire_app::dispatcher::Dispatcher;
use blackwire_app::features::InboundHandler;
use blackwire_common::{
    with_handshake_timeout, Address, BoxedStream, Network, PrependedStream, ProxyError,
};

// ── Constants ──────────────────────────────────────────────────────────────────

/// Maximum bytes to read for the HTTP CONNECT request line + headers.
const MAX_HEADER_BYTES: usize = 8192;

// ── Inbound handler ────────────────────────────────────────────────────────────

/// HTTP CONNECT inbound handler.
///
/// Accepts HTTP CONNECT requests, responds with 200, then relays bytes
/// transparently to the destination.
pub struct HttpConnectInbound {
    /// Unique tag from config.
    tag: String,
    /// Optional limit for reading the HTTP request headers (Xray `Handshake`).
    handshake_timeout: Option<Duration>,
}

impl HttpConnectInbound {
    /// Create a new HTTP CONNECT inbound handler.
    pub fn new(tag: impl Into<String>, handshake_timeout: Option<Duration>) -> Arc<Self> {
        Arc::new(Self {
            tag: tag.into(),
            handshake_timeout,
        })
    }
}

#[async_trait]
impl InboundHandler for HttpConnectInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn networks(&self) -> &[Network] {
        &[Network::Tcp]
    }

    async fn handle(
        &self,
        stream: BoxedStream,
        source: SocketAddr,
        dispatcher: Arc<dyn Dispatcher>,
    ) -> Result<(), ProxyError> {
        let (dest, mut stream) =
            with_handshake_timeout(self.handshake_timeout, parse_connect_request(stream))
                .await
                .map_err(|e| {
                    debug!(source = %source, error = %e, "HTTP CONNECT parse failed");
                    e
                })?;

        debug!(source = %source, dest = %dest, "HTTP CONNECT tunnel established");

        // Send 200 Connection established.
        stream
            .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
            .await?;
        stream.flush().await?;

        let ctx = Context::new(&self.tag, source);
        dispatcher.dispatch(ctx, dest, stream).await
    }
}

// ── Request parsing ────────────────────────────────────────────────────────────

/// Parse an HTTP CONNECT request from the stream.
///
/// Reads the request line and all headers, validates that the method is
/// CONNECT, extracts the target host:port, and returns the parsed `Address`
/// plus a stream positioned at the first byte after the header block. Any bytes
/// already buffered by the reader (e.g. coalesced TLS ClientHello) are
/// preserved via [`PrependedStream`], matching Xray's `BufferedReader` behavior.
pub async fn parse_connect_request(
    stream: BoxedStream,
) -> Result<(Address, BoxedStream), ProxyError> {
    let mut reader = BufReader::new(stream);
    let mut total_bytes = 0usize;
    let mut first_line = String::new();

    // Read the request line.
    let n = reader.read_line(&mut first_line).await?;
    if n == 0 {
        return Err(ProxyError::Protocol("HTTP CONNECT: unexpected EOF".into()));
    }
    total_bytes += n;

    // Drain the remaining headers until the blank line.
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            return Err(ProxyError::Protocol(
                "HTTP CONNECT: unexpected EOF in headers".into(),
            ));
        }
        total_bytes += n;

        if total_bytes > MAX_HEADER_BYTES {
            return Err(ProxyError::Protocol(
                "HTTP CONNECT: headers too large".into(),
            ));
        }

        // A blank line (\r\n or \n alone) terminates the headers.
        if line == "\r\n" || line == "\n" {
            break;
        }
    }

    let dest = parse_request_line(first_line.trim())?;

    // Preserve any bytes already read past the header block (Xray BufferedReader).
    let remainder = reader.buffer().to_vec();
    let inner = reader.into_inner();
    let stream = if remainder.is_empty() {
        inner
    } else {
        Box::new(PrependedStream::new(inner, remainder)) as BoxedStream
    };

    Ok((dest, stream))
}

/// Parse the request line `CONNECT host:port HTTP/1.1` into an `Address`.
fn parse_request_line(line: &str) -> Result<Address, ProxyError> {
    let mut parts = line.splitn(3, ' ');

    let method = parts.next().unwrap_or("");
    if !method.eq_ignore_ascii_case("CONNECT") {
        return Err(ProxyError::Protocol(format!(
            "HTTP CONNECT: expected CONNECT method, got '{method}'"
        )));
    }

    let target = parts
        .next()
        .ok_or_else(|| ProxyError::Protocol("HTTP CONNECT: missing target".into()))?;

    // target is "host:port"
    let (host, port_str) = target
        .rsplit_once(':')
        .ok_or_else(|| ProxyError::Protocol("HTTP CONNECT: malformed target (no port)".into()))?;

    let port: u16 = port_str
        .parse()
        .map_err(|_| ProxyError::Protocol(format!("HTTP CONNECT: invalid port '{port_str}'")))?;

    let host = host.trim_matches(|c| c == '[' || c == ']'); // strip IPv6 brackets
    if host.is_empty() {
        return Err(ProxyError::Protocol(
            "HTTP CONNECT: empty host in target".into(),
        ));
    }

    // Try to parse as an IP address first.
    if let Ok(ip4) = host.parse::<std::net::Ipv4Addr>() {
        return Ok(Address::Ipv4(ip4, port));
    }
    if let Ok(ip6) = host.parse::<std::net::Ipv6Addr>() {
        return Ok(Address::Ipv6(ip6, port));
    }

    Ok(Address::Domain(host.to_string(), port))
}

/// Parse only the request-line portion of an HTTP CONNECT request.
///
/// This is a convenience function for use in unit tests. The normal entry
/// point is `parse_connect_request`, which reads a full request from a stream.
pub fn parse_connect_request_sync(request_line: &str) -> Result<Address, ProxyError> {
    parse_request_line(request_line)
}

// ── Unit tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    fn addr(host: &str, port: u16) -> Address {
        Address::Domain(host.to_string(), port)
    }

    // ── parse_request_line tests ──────────────────────────────────────────────

    #[test]
    fn parse_domain_target() {
        let a = parse_request_line("CONNECT example.com:443 HTTP/1.1").unwrap();
        assert_eq!(a, addr("example.com", 443));
    }

    #[test]
    fn parse_ipv4_target() {
        let a = parse_request_line("CONNECT 1.2.3.4:8080 HTTP/1.1").unwrap();
        assert_eq!(a, Address::Ipv4("1.2.3.4".parse().unwrap(), 8080));
    }

    #[test]
    fn parse_ipv6_target() {
        let a = parse_request_line("CONNECT [::1]:443 HTTP/1.1").unwrap();
        assert_eq!(a, Address::Ipv6("::1".parse().unwrap(), 443));
    }

    #[test]
    fn wrong_method_rejected() {
        let result = parse_request_line("GET / HTTP/1.1");
        assert!(result.is_err());
    }

    #[test]
    fn missing_port_rejected() {
        let result = parse_request_line("CONNECT example.com HTTP/1.1");
        assert!(result.is_err());
    }

    #[test]
    fn invalid_port_rejected() {
        let result = parse_request_line("CONNECT example.com:notaport HTTP/1.1");
        assert!(result.is_err());
    }

    // ── parse_connect_request integration tests ───────────────────────────────

    async fn parse_from_bytes(data: &[u8]) -> Result<(Address, BoxedStream), ProxyError> {
        let cursor = std::io::Cursor::new(data.to_vec());
        let stream: BoxedStream = Box::new(cursor);
        parse_connect_request(stream).await
    }

    #[tokio::test]
    async fn full_request_domain() {
        let req = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
        let (a, _) = parse_from_bytes(req).await.unwrap();
        assert_eq!(a, addr("example.com", 443));
    }

    #[tokio::test]
    async fn full_request_ipv4() {
        let req = b"CONNECT 93.184.216.34:443 HTTP/1.1\r\nHost: 93.184.216.34\r\n\r\n";
        let (a, _) = parse_from_bytes(req).await.unwrap();
        assert_eq!(a, Address::Ipv4("93.184.216.34".parse().unwrap(), 443));
    }

    #[tokio::test]
    async fn full_request_multiple_headers() {
        let req = b"CONNECT proxy.example.com:8443 HTTP/1.1\r\nHost: proxy.example.com:8443\r\nProxy-Connection: keep-alive\r\nUser-Agent: curl/7.79\r\n\r\n";
        let (a, _) = parse_from_bytes(req).await.unwrap();
        assert_eq!(a, addr("proxy.example.com", 8443));
    }

    #[tokio::test]
    async fn missing_blank_line_returns_error() {
        let req = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n";
        // No trailing \r\n\r\n — should error with unexpected EOF.
        let result = parse_from_bytes(req).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn get_method_rejected() {
        let req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let result = parse_from_bytes(req).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn preserves_post_header_bytes() {
        let req = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\nCLIENT_HELLO";
        let (_, mut stream) = parse_from_bytes(req).await.unwrap();
        let mut tail = vec![0u8; 12];
        stream.read_exact(&mut tail).await.unwrap();
        assert_eq!(&tail, b"CLIENT_HELLO");
    }
}
