//! Real DNS resolver backed by `hickory-resolver`.
//!
//! Supports:
//! - System default resolver (when no servers are configured)
//! - Custom upstream servers (plain UDP, IP addresses)
//!
//! The resolver is async and integrates cleanly with the Tokio runtime.

use std::net::IpAddr;

use std::sync::Arc;

use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::TokioResolver;
use tracing::debug;

use blackwire_common::ProxyError;

/// A DNS resolver that can perform real name lookups.
pub struct DnsResolver {
    inner: TokioResolver,
}

impl DnsResolver {
    /// Create a new resolver.
    ///
    /// If `servers` is empty, the OS system resolver is used.
    /// If servers are provided, they are used as upstreams.
    /// If all provided servers fail to parse, we fall back to the system
    /// resolver with a warning — matching xray's `NewLocalDNSClient()` fallback.
    ///
    /// Plain IP addresses (e.g. `"8.8.8.8"`) are supported.
    /// DoT/DoH URLs are skipped with a warning.
    pub async fn new(servers: &[String]) -> Result<Self, ProxyError> {
        let resolver = if servers.is_empty() {
            build_system_resolver()?
        } else {
            match build_custom_config(servers).await {
                Some(config) => {
                    TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
                        .build()
                        .map_err(|e| {
                            ProxyError::Protocol(format!("DNS custom resolver build: {e}"))
                        })?
                }
                None => {
                    // All operator-configured servers were unparseable.
                    // Fall back to the system resolver (xray uses NewLocalDNSClient()).
                    tracing::warn!(
                        "all configured DNS servers are invalid; \
                         falling back to system resolver — check your config"
                    );
                    build_system_resolver()?
                }
            }
        };

        Ok(Self { inner: resolver })
    }

    /// Resolve a domain name to a list of IP addresses.
    ///
    /// Returns all A and AAAA records from the first successful lookup.
    pub async fn resolve(&self, domain: &str) -> Result<Vec<IpAddr>, ProxyError> {
        debug!(domain = %domain, "DNS resolve");
        let lookup = self
            .inner
            .lookup_ip(domain)
            .await
            .map_err(|e| ProxyError::DnsResolutionFailed(format!("{domain}: {e}")))?;

        let ips: Vec<IpAddr> = lookup.iter().collect();
        if ips.is_empty() {
            return Err(ProxyError::DnsResolutionFailed(format!(
                "{domain}: no records returned"
            )));
        }
        Ok(ips)
    }
}

/// Build a system resolver using `/etc/resolv.conf` (or OS equivalent).
///
/// This matches xray's `NewLocalDNSClient()` fallback path.
fn build_system_resolver() -> Result<TokioResolver, ProxyError> {
    TokioResolver::builder(TokioRuntimeProvider::default())
        .unwrap_or_else(|_| {
            TokioResolver::builder_with_config(
                ResolverConfig::default(),
                TokioRuntimeProvider::default(),
            )
        })
        .build()
        .map_err(|e| ProxyError::Protocol(format!("DNS system resolver build: {e}")))
}

/// Build a custom resolver config from server address strings.
///
/// Returns `None` if all servers fail to parse (caller falls back to system
/// resolver with a warning).
///
/// Build resolver config from Xray/sing-box style server URLs (`udp://`, `tcp://`,
/// `tls://`, `https://`).
async fn build_custom_config(servers: &[String]) -> Option<ResolverConfig> {
    let mut name_servers: Vec<NameServerConfig> = Vec::new();

    for server in servers {
        if let Some(ns) = parse_dns_upstream(server).await {
            name_servers.push(ns);
        } else {
            tracing::warn!(server = %server, "cannot parse DNS server address; skipping");
        }
    }

    if name_servers.is_empty() {
        return None;
    }

    Some(ResolverConfig::from_parts(None, vec![], name_servers))
}

async fn parse_dns_upstream(server: &str) -> Option<NameServerConfig> {
    if let Some(rest) = server.strip_prefix("https://") {
        let (host, path) = split_host_path(rest);
        let ip = resolve_host_ip(&host, 443).await?;
        return Some(NameServerConfig::https(
            ip,
            Arc::from(host.as_str()),
            Some(Arc::from(path.as_str())),
        ));
    }
    if let Some(rest) = server.strip_prefix("tls://") {
        let (host, _) = split_host_path(rest);
        let ip = resolve_host_ip(&host, 853).await?;
        return Some(NameServerConfig::tls(ip, Arc::from(host.as_str())));
    }
    if let Some(rest) = server.strip_prefix("udp://") {
        return parse_ip_upstream(rest, true).await;
    }
    if let Some(rest) = server.strip_prefix("tcp://") {
        return parse_ip_upstream(rest, false).await;
    }
    if let Ok(ip) = server.parse::<IpAddr>() {
        return Some(NameServerConfig::new(
            ip,
            true,
            vec![ConnectionConfig::udp(), ConnectionConfig::tcp()],
        ));
    }
    if let Ok(sa) = server.parse::<std::net::SocketAddr>() {
        return Some(NameServerConfig::new(
            sa.ip(),
            true,
            vec![ConnectionConfig::udp(), ConnectionConfig::tcp()],
        ));
    }
    None
}

fn split_host_path(url: &str) -> (String, String) {
    let (host, path) = url.split_once('/').unwrap_or((url, ""));
    if path.is_empty() {
        (host.to_string(), "/".to_string())
    } else {
        let mut normalized = String::with_capacity(path.len() + 1);
        normalized.push('/');
        normalized.push_str(path);
        (host.to_string(), normalized)
    }
}

async fn resolve_host_ip(host: &str, default_port: u16) -> Option<IpAddr> {
    let (name, port) = if let Some((h, p)) = host.rsplit_once(':') {
        (h, p.parse().unwrap_or(default_port))
    } else {
        (host, default_port)
    };
    let mut addrs = tokio::net::lookup_host((name, port)).await.ok()?;
    addrs.next().map(|a| a.ip())
}

async fn parse_ip_upstream(host_port: &str, prefer_udp: bool) -> Option<NameServerConfig> {
    let ip = if let Ok(sa) = host_port.parse::<std::net::SocketAddr>() {
        sa.ip()
    } else if let Ok(ip) = host_port.parse::<IpAddr>() {
        ip
    } else {
        resolve_host_ip(host_port, 53).await?
    };
    let conns = if prefer_udp {
        vec![ConnectionConfig::udp(), ConnectionConfig::tcp()]
    } else {
        vec![ConnectionConfig::tcp()]
    };
    Some(NameServerConfig::new(ip, true, conns))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Resolver builds without panicking when given empty server list.
    #[tokio::test]
    async fn resolver_builds_system() {
        let r = DnsResolver::new(&[]).await;
        assert!(r.is_ok());
    }

    /// Resolver builds without panicking with a valid upstream IP.
    #[tokio::test]
    async fn resolver_builds_custom_ip() {
        let r = DnsResolver::new(&["8.8.8.8".to_string()]).await;
        assert!(r.is_ok());
    }

    /// Resolver builds with a DoH URL (Xray/sing-box style).
    #[tokio::test]
    async fn resolver_builds_with_doh() {
        let r = DnsResolver::new(&["https://dns.google/dns-query".to_string()]).await;
        assert!(r.is_ok());
    }
}
