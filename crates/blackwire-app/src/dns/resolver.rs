//! Real DNS resolver backed by `hickory-resolver`.
//!
//! Supports:
//! - System default resolver (when no servers are configured)
//! - Custom upstream servers (plain UDP, IP addresses)
//!
//! The resolver is async and integrates cleanly with the Tokio runtime.

use std::net::IpAddr;

use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::TokioResolver;
use tracing::debug;

use proxy_common::ProxyError;

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
            match build_custom_config(servers) {
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
/// Only plain IP addresses (UDP port 53) are supported. DoT/DoH URLs
/// are skipped with a warning.
fn build_custom_config(servers: &[String]) -> Option<ResolverConfig> {
    let mut name_servers: Vec<NameServerConfig> = Vec::new();

    for server in servers {
        if server.starts_with("https://") || server.starts_with("tls://") {
            tracing::warn!(server = %server, "DoH/DoT upstream not yet supported; skipping");
            continue;
        }
        // Try parsing as IP:port or just IP (default port 53).
        let ip: Option<IpAddr> = if let Ok(sa) = server.parse::<std::net::SocketAddr>() {
            Some(sa.ip())
        } else if let Ok(ip) = server.parse::<IpAddr>() {
            Some(ip)
        } else {
            tracing::warn!(server = %server, "cannot parse DNS server address; skipping");
            None
        };

        if let Some(ip) = ip {
            name_servers.push(NameServerConfig::new(
                ip,
                true,
                vec![ConnectionConfig::udp(), ConnectionConfig::tcp()],
            ));
        }
    }

    if name_servers.is_empty() {
        return None;
    }

    Some(ResolverConfig::from_parts(None, vec![], name_servers))
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

    /// Resolver builds without panicking with a DoH URL (which we skip).
    #[tokio::test]
    async fn resolver_builds_skips_doh() {
        let r = DnsResolver::new(&["https://dns.google/dns-query".to_string()]).await;
        assert!(r.is_ok());
    }
}
