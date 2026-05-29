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
