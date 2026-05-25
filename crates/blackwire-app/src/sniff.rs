//! Traffic sniffing aligned with Xray `app/dispatcher` sniffing behavior.
//!
//! Peeks the first bytes of a TCP stream to detect HTTP Host or TLS SNI when the
//! destination is an IP (common for transparent proxy / tun paths).

use blackwire_common::{Address, BoxedStream, PrependedStream, ProxyError};
use blackwire_config::schema::SniffingConfig;
use tokio::io::AsyncReadExt;

const MAX_SNIFF: usize = 8192;

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
    if !config.enabled {
        return Ok((stream, SniffResult::default()));
    }

    let mut peek = vec![0u8; MAX_SNIFF];
    let n = stream.read(&mut peek).await?;
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
    if !config.enabled {
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
                .any(|p| p == "http" || p == "tls")
            {
                Address::Domain(domain.clone(), port)
            } else {
                dest
            }
        }
        other => other,
    }
}

fn tls_sni(data: &[u8]) -> Option<String> {
    if data.len() < 5 || data[0] != 0x16 {
        return None;
    }
    let mut pos = 5usize;
    if pos >= data.len() {
        return None;
    }
    if data[pos] != 0x01 {
        return None;
    }
    pos += 4;
    pos += 2 + 32 + 1;
    if pos + 2 > data.len() {
        return None;
    }
    let sess_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2 + sess_len;
    if pos + 2 > data.len() {
        return None;
    }
    let suites_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2 + suites_len;
    if pos >= data.len() {
        return None;
    }
    let comp_len = data[pos] as usize;
    pos += 1 + comp_len;
    if pos + 2 > data.len() {
        return None;
    }
    let ext_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;
    let end = pos.saturating_add(ext_len);
    while pos + 4 <= end.min(data.len()) {
        let etype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let elen = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;
        if pos + elen > data.len() {
            break;
        }
        if etype == 0 && elen > 5 && data[pos + 2] == 0 {
            let name_len = u16::from_be_bytes([data[pos + 3], data[pos + 4]]) as usize;
            if pos + 5 + name_len <= data.len() {
                return std::str::from_utf8(&data[pos + 5..pos + 5 + name_len])
                    .ok()
                    .map(str::to_string);
            }
        }
        pos += elen;
    }
    None
}

fn http_host(data: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(data).ok()?;
    let first = text.lines().next()?;
    if !first.starts_with("GET ")
        && !first.starts_with("POST ")
        && !first.starts_with("PUT ")
        && !first.starts_with("HEAD ")
        && !first.starts_with("CONNECT ")
    {
        return None;
    }
    for line in text.lines().skip(1) {
        if line.is_empty() {
            break;
        }
        let lower = line.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("host:") {
            let host = rest.trim();
            let host = host.split(':').next().unwrap_or(host);
            if !host.is_empty() {
                return Some(host.to_string());
            }
        }
    }
    None
}
