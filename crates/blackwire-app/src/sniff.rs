//! Traffic sniffing aligned with Xray `app/dispatcher` sniffing behavior.
//!
//! When inbound sniffing is enabled, peeks the first bytes of the TCP stream to detect
//! HTTP Host or TLS SNI (unless `metadataOnly`). `destOverride` rewrites an IP
//! destination to the sniffed domain; `routeOnly` keeps the dial target as-is and
//! exposes the sniffed domain for routing only.
//!
//! FakeDNS sniffing (`"fakedns"` in `destOverride`) is metadata-only: it checks
//! whether the destination is a fake IP and reverse-looks up the domain without
//! peeking at any stream bytes.

use blackwire_common::{Address, BoxedStream, PrependedStream, ProxyError};
use blackwire_config::schema::SniffingConfig;
use tokio::io::AsyncReadExt;
use tokio::time::{timeout, Duration};

use crate::dns::DnsModule;

const MAX_SNIFF: usize = 8192;
/// Xray waits briefly for client payload before routing; do not block the dispatcher forever.
const SNIFF_PEEK_TIMEOUT: Duration = Duration::from_millis(300);

/// Result of sniffing the start of a connection.
#[derive(Debug, Clone, Default)]
pub struct SniffResult {
    /// Sniffed protocol label (`http`, `tls`, …).
    pub protocol: Option<String>,
    /// Sniffed host / SNI when detected.
    pub domain: Option<String>,
}

/// Peek up to `MAX_SNIFF` bytes, detect protocol/domain, return a prepended stream.
pub async fn sniff_stream(
    mut stream: BoxedStream,
    config: &SniffingConfig,
) -> Result<(BoxedStream, SniffResult), ProxyError> {
    if !config.enabled || config.metadata_only {
        return Ok((stream, SniffResult::default()));
    }

    let mut peek = vec![0u8; MAX_SNIFF];
    let n = match timeout(SNIFF_PEEK_TIMEOUT, stream.read(&mut peek)).await {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => 0,
    };
    peek.truncate(n);
    if peek.is_empty() {
        return Ok((stream, SniffResult::default()));
    }

    let result = analyze_peek(&peek, config);
    let stream: BoxedStream = Box::new(PrependedStream::new(stream, peek));
    Ok((stream, result))
}

/// Analyze buffered bytes without consuming the stream.
pub fn analyze_peek(peek: &[u8], config: &SniffingConfig) -> SniffResult {
    let want_http = config.dest_override.iter().any(|p| p == "http");
    let want_tls = config.dest_override.iter().any(|p| p == "tls");

    if want_tls {
        if let Some(domain) = tls_sni(peek) {
            return SniffResult {
                protocol: Some("tls".into()),
                domain: Some(domain),
            };
        }
    }

    if want_http {
        if let Some(host) = http_host(peek) {
            return SniffResult {
                protocol: Some("http".into()),
                domain: Some(host),
            };
        }
    }

    SniffResult::default()
}

/// Apply destOverride: replace IP destination with sniffed domain when configured.
pub fn apply_dest_override(dest: Address, sniff: &SniffResult, config: &SniffingConfig) -> Address {
    if !config.enabled || config.route_only {
        return dest;
    }
    let Some(domain) = sniff.domain.as_ref() else {
        return dest;
    };
    match dest {
        Address::Ipv4(_, port) | Address::Ipv6(_, port) => {
            if config
                .dest_override
                .iter()
                .any(|p| p == "http" || p == "tls" || p == "fakedns")
            {
                Address::Domain(domain.clone(), port)
            } else {
                dest
            }
        }
        other => other,
    }
}

/// FakeDNS sniffing: reverse-lookup a fake IP to its domain name.
///
/// Unlike HTTP/TLS sniffing, this is metadata-only — no stream bytes are consumed.
/// Returns a `SniffResult` with `protocol = "fakedns"` when `dest` is a recognised
/// fake IP, or a default (empty) result otherwise.
pub fn sniff_fakedns(dest: &Address, dns: &DnsModule) -> SniffResult {
    let Address::Ipv4(ip, _) = dest else {
        return SniffResult::default();
    };
    let Some(domain) = dns.reverse_fake(*ip) else {
        return SniffResult::default();
    };
    SniffResult {
        protocol: Some("fakedns".into()),
        domain: Some(domain),
    }
}

/// Parse a TLS ClientHello to extract the SNI (Server Name Indication) extension.
///
/// # What is SNI?
/// When a browser connects to `https://example.com`, it sends a TLS ClientHello
/// that includes the domain name in clear text (before encryption starts).
/// This "server name" field is the SNI. We use it to route HTTPS connections by
/// domain even though the payload is encrypted.
///
/// # TLS ClientHello wire structure (simplified)
/// ```text
/// TLS Record Header (5 bytes):
///   [0]    content type = 0x16 (Handshake)
///   [1-2]  record version (e.g., 0x03 0x01)
///   [3-4]  record length
///
/// Handshake Message (starts at byte 5):
///   [5]    message type = 0x01 (ClientHello)
///   [6-8]  message length (3 bytes, big-endian)
///   [9-10] legacy TLS version (2 bytes)
///   [11-42] Random (32 random bytes used in key derivation)
///   [43]   legacy session ID length (1 byte, 0 or 32)
///   [44..] legacy session ID data (0-32 bytes)
///   ...    cipher suites (2-byte length + list)
///   ...    compression methods (1-byte length + list)
///   ...    extensions (2-byte length + list of extensions)
/// ```
///
/// Each extension has: type (2 bytes) + length (2 bytes) + data.
/// The SNI extension (type 0x0000) contains: list_length(2) + entry_type(1) + name_len(2) + name.
fn tls_sni(data: &[u8]) -> Option<String> {
    // First byte must be 0x16 = TLS Handshake record type.
    // The record header is 5 bytes long; we need at least that many bytes.
    if data.len() < 5 || data[0] != 0x16 {
        return None;
    }

    // Jump past the 5-byte TLS record header into the Handshake message body.
    let mut pos = 5usize;
    if pos >= data.len() {
        return None;
    }

    // The first byte of the Handshake message must be 0x01 = ClientHello.
    // Other handshake message types (ServerHello = 0x02, etc.) are not ClientHellos.
    if data[pos] != 0x01 {
        return None;
    }

    // Skip: HandshakeType (1 byte) + MessageLength (3 bytes) = 4 bytes.
    // After this we're at the start of the ClientHello fields.
    pos += 4;

    // Skip: legacy_version (2 bytes) + Random (32 bytes) + session_id_length_byte (1 byte).
    // The "Random" is 32 truly random bytes used for key derivation — not human-readable.
    // The session_id_length tells us how many bytes follow for the session ID, but we
    // skip the length byte here and handle the actual session ID bytes just below.
    pos += 2 + 32 + 1;

    if pos + 2 > data.len() {
        return None;
    }

    // Read the session ID field (2-byte length prefix + data).
    // The session ID is an opaque blob used for TLS session resumption.
    // We skip it entirely — it contains no routing-relevant information.
    let sess_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2 + sess_len;

    if pos + 2 > data.len() {
        return None;
    }

    // Read the cipher suites field (2-byte length prefix + list of 2-byte suite IDs).
    // Cipher suites are negotiated algorithms like AES-256-GCM or ChaCha20-Poly1305.
    // We skip the whole list — we only care about extensions, which come later.
    let suites_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2 + suites_len;

    if pos >= data.len() {
        return None;
    }

    // Read the compression methods field (1-byte length + list).
    // Compression is effectively never used in modern TLS; we skip it.
    let comp_len = data[pos] as usize;
    pos += 1 + comp_len;

    if pos + 2 > data.len() {
        return None;
    }

    // Read the extensions section (2-byte total length + list of extensions).
    // Extensions are where SNI, ALPN, key_share, and other TLS 1.3 features live.
    let ext_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2; // move past the 2-byte extensions-length field
    let end = pos.saturating_add(ext_len);

    // Walk each extension. Each entry is: type(2) + length(2) + data.
    while pos + 4 <= end.min(data.len()) {
        let etype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let elen = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        pos += 4; // move past extension type and length fields
        if pos + elen > data.len() {
            break;
        }

        // Extension type 0x0000 is the "server_name" (SNI) extension.
        // Its data layout: list_length(2) + name_type(1) + name_length(2) + name_bytes.
        // name_type == 0 means "host_name" (the only defined type).
        if etype == 0 && elen > 5 && data[pos + 2] == 0 {
            let name_len = u16::from_be_bytes([data[pos + 3], data[pos + 4]]) as usize;
            if pos + 5 + name_len <= data.len() {
                // The SNI hostname is plain ASCII bytes (no null terminator).
                // Convert to a Rust String — if it is not valid UTF-8, return None.
                return std::str::from_utf8(&data[pos + 5..pos + 5 + name_len])
                    .ok()
                    .map(str::to_string);
            }
        }
        pos += elen; // advance to the next extension
    }
    None
}

/// Parse a plain-text HTTP/1.1 request to extract the `Host` header value.
///
/// # How HTTP/1.1 requests look on the wire
/// ```text
/// GET /path HTTP/1.1\r\n
/// Host: example.com\r\n
/// User-Agent: ...\r\n
/// \r\n
/// ```
/// The first line is the "request line" (method + path + version).
/// The following lines are headers, each "Name: value". An empty line ends the headers.
///
/// We only look at the `Host:` header because that tells us the domain name the
/// client wants to reach — this is the same information we'd get from DNS, but
/// extracted from the raw bytes before they're forwarded.
fn http_host(data: &[u8]) -> Option<String> {
    // The first few bytes of an HTTP request are ASCII text. If they're not valid
    // UTF-8, this is not a plain HTTP request we can parse.
    let text = std::str::from_utf8(data).ok()?;
    let first = text.lines().next()?;

    // The first line must start with a known HTTP method.
    // If it doesn't, these bytes are probably not an HTTP request at all.
    if !first.starts_with("GET ")
        && !first.starts_with("POST ")
        && !first.starts_with("PUT ")
        && !first.starts_with("HEAD ")
        && !first.starts_with("CONNECT ")
    {
        return None;
    }

    // Scan header lines (skip the first "request line").
    // Stop at the blank line that separates headers from the request body.
    for line in text.lines().skip(1) {
        if line.is_empty() {
            break; // blank line = end of headers
        }
        let lower = line.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("host:") {
            // Strip any surrounding whitespace from the header value.
            let host = rest.trim();
            // Drop the port if present (e.g., "example.com:8080" → "example.com").
            let host = host.split(':').next().unwrap_or(host);
            if !host.is_empty() {
                return Some(host.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::{DnsModule, DnsModuleConfig};
    use blackwire_config::schema::SniffingConfig;

    #[tokio::test]
    async fn sniff_fakedns_returns_domain_for_fake_ip() {
        let dns = DnsModule::new(DnsModuleConfig {
            fake_ip_enabled: true,
            ..Default::default()
        })
        .await
        .unwrap();

        let fake_ip = dns.resolve_fake("example.com").unwrap();
        let dest = Address::Ipv4(fake_ip, 80);
        let result = sniff_fakedns(&dest, &dns);

        assert_eq!(result.protocol.as_deref(), Some("fakedns"));
        assert_eq!(result.domain.as_deref(), Some("example.com"));
    }

    #[tokio::test]
    async fn sniff_fakedns_returns_default_for_real_ip() {
        let dns = DnsModule::new(DnsModuleConfig {
            fake_ip_enabled: true,
            ..Default::default()
        })
        .await
        .unwrap();

        let dest = Address::Ipv4("1.2.3.4".parse().unwrap(), 80);
        let result = sniff_fakedns(&dest, &dns);

        assert!(result.protocol.is_none());
        assert!(result.domain.is_none());
    }

    #[test]
    fn apply_dest_override_fakedns_replaces_ip_with_domain() {
        let config = SniffingConfig {
            enabled: true,
            dest_override: vec!["fakedns".into()],
            ..Default::default()
        };
        let sniff = SniffResult {
            protocol: Some("fakedns".into()),
            domain: Some("example.com".into()),
        };
        let dest = Address::Ipv4("198.18.0.1".parse().unwrap(), 443);
        let result = apply_dest_override(dest, &sniff, &config);
        assert_eq!(result, Address::Domain("example.com".into(), 443));
    }

    #[test]
    fn apply_dest_override_fakedns_route_only_keeps_ip() {
        let config = SniffingConfig {
            enabled: true,
            route_only: true,
            dest_override: vec!["fakedns".into()],
            ..Default::default()
        };
        let sniff = SniffResult {
            protocol: Some("fakedns".into()),
            domain: Some("example.com".into()),
        };
        let dest = Address::Ipv4("198.18.0.1".parse().unwrap(), 443);
        let result = apply_dest_override(dest, &sniff, &config);
        assert_eq!(result, Address::Ipv4("198.18.0.1".parse().unwrap(), 443));
    }
}
