//! DNS resolver with FakeIP support.
//!
//! `DnsModule` provides two resolution modes:
//!
//! 1. **Real resolution**: uses `hickory-resolver` to resolve domain names to
//!    actual IP addresses, with a TTL-based cache.
//!
//! 2. **FakeIP**: assigns stable fake IP addresses from a reserved pool
//!    (`198.18.0.0/15`) to domain names. The same domain always gets the same
//!    IP. Reverse lookup (fake IP → domain) is also supported. This is used
//!    in TUN/transparent proxy mode so the routing layer can identify the
//!    original domain from the connection's destination IP.
//!
//! # Usage
//!
//! ```no_run
//! use std::net::IpAddr;
//!
//! use proxy_app::dns::{DnsModule, DnsModuleConfig};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let module = DnsModule::new(DnsModuleConfig {
//!         fake_ip_enabled: true,
//!         ..Default::default()
//!     })
//!     .await?;
//!
//!     // Real resolution:
//!     let ips = module.resolve("example.com").await?;
//!     assert!(!ips.is_empty());
//!
//!     // FakeIP:
//!     let fake = module.resolve_fake("example.com");
//!     let domain = module.reverse_fake(fake);
//!     assert_eq!(domain.as_deref(), Some("example.com"));
//!     assert!(module.is_fake_ip(IpAddr::V4(fake)));
//!     Ok(())
//! }
//! ```

pub mod cache;
pub mod fakeip;
pub mod resolver;

use std::net::{IpAddr, Ipv4Addr};

use proxy_common::ProxyError;

pub use cache::DnsCache;
pub use fakeip::FakeIpPool;
pub use resolver::DnsResolver;

/// Configuration for the `DnsModule`.
#[derive(Debug, Clone)]
pub struct DnsModuleConfig {
    /// Upstream DNS server addresses (e.g. `"8.8.8.8"`, `"https://dns.google/dns-query"`).
    pub servers: Vec<String>,

    /// Whether FakeIP mode is enabled.
    pub fake_ip_enabled: bool,

    /// CIDR range to allocate fake IPs from. Default: `"198.18.0.0/15"`.
    pub fake_ip_range: String,

    /// Domain names that bypass FakeIP (always resolved normally).
    pub fake_ip_filter: Vec<String>,
}

impl Default for DnsModuleConfig {
    fn default() -> Self {
        Self {
            servers: vec!["8.8.8.8".into(), "1.1.1.1".into()],
            fake_ip_enabled: false,
            fake_ip_range: "198.18.0.0/15".into(),
            fake_ip_filter: vec!["localhost".into()],
        }
    }
}

/// The DNS module: real resolver + FakeIP pool + TTL cache.
pub struct DnsModule {
    resolver: DnsResolver,
    cache: DnsCache,
    fakeip: Option<FakeIpPool>,
    filter: Vec<String>,
}

impl DnsModule {
    /// Create a new `DnsModule` from the given config.
    ///
    /// `servers` is used to configure the upstream resolver. If empty, the
    /// system resolver is used.
    pub async fn new(config: DnsModuleConfig) -> Result<Self, ProxyError> {
        let resolver = DnsResolver::new(&config.servers).await?;
        let cache = DnsCache::new(512);
        let fakeip = if config.fake_ip_enabled {
            Some(
                FakeIpPool::new(&config.fake_ip_range)
                    .map_err(|e| ProxyError::Protocol(format!("FakeIP pool init failed: {e}")))?,
            )
        } else {
            None
        };
        Ok(Self {
            resolver,
            cache,
            fakeip,
            filter: config.fake_ip_filter,
        })
    }

    /// Resolve a domain name to a list of real IP addresses.
    ///
    /// Results are cached with TTL. Returns an error if resolution fails.
    pub async fn resolve(&self, domain: &str) -> Result<Vec<IpAddr>, ProxyError> {
        // Check cache first.
        if let Some(cached) = self.cache.get(domain) {
            return Ok(cached);
        }

        let ips = self.resolver.resolve(domain).await?;
        self.cache.insert(domain, ips.clone(), 300); // 5-minute TTL
        Ok(ips)
    }

    /// Assign or retrieve the FakeIP for a domain.
    ///
    /// Returns `Some(ip)` when FakeIP is enabled, or `None` when FakeIP is
    /// disabled. Callers must check `is_filtered` before calling this; the
    /// filter is not enforced internally (same architecture as xray).
    pub fn resolve_fake(&self, domain: &str) -> Option<Ipv4Addr> {
        self.fakeip.as_ref().map(|pool| pool.allocate(domain))
    }

    /// Look up the domain name that was assigned a given fake IP.
    ///
    /// Returns `None` if the IP is not a known fake IP or FakeIP is disabled.
    pub fn reverse_fake(&self, ip: Ipv4Addr) -> Option<String> {
        self.fakeip.as_ref()?.reverse(ip)
    }

    /// Returns `true` if the IP falls within the configured FakeIP pool range.
    pub fn is_fake_ip(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => self.fakeip.as_ref().is_some_and(|pool| pool.is_fake(v4)),
            IpAddr::V6(_) => false,
        }
    }

    /// Returns `true` if the domain is in the FakeIP bypass filter.
    ///
    /// Filtered domains should be resolved normally rather than with FakeIP.
    pub fn is_filtered(&self, domain: &str) -> bool {
        self.filter
            .iter()
            .any(|f| domain == f || domain.ends_with(&format!(".{f}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FakeIP is allocated and the same domain always gets the same IP.
    #[tokio::test]
    async fn fakeip_stable_allocation() {
        let cfg = DnsModuleConfig {
            fake_ip_enabled: true,
            ..Default::default()
        };
        let module = DnsModule::new(cfg).await.unwrap();

        let ip1 = module.resolve_fake("example.com").unwrap();
        let ip2 = module.resolve_fake("example.com").unwrap();
        assert_eq!(ip1, ip2);

        let ip3 = module.resolve_fake("other.com").unwrap();
        assert_ne!(ip1, ip3);
    }

    /// Reverse lookup returns the correct domain.
    #[tokio::test]
    async fn fakeip_reverse_lookup() {
        let cfg = DnsModuleConfig {
            fake_ip_enabled: true,
            ..Default::default()
        };
        let module = DnsModule::new(cfg).await.unwrap();

        let ip = module.resolve_fake("mysite.net").unwrap();
        let domain = module.reverse_fake(ip).unwrap();
        assert_eq!(domain, "mysite.net");
    }

    /// `is_fake_ip` correctly identifies IPs in the pool range.
    #[tokio::test]
    async fn fakeip_is_fake_ip() {
        let cfg = DnsModuleConfig {
            fake_ip_enabled: true,
            ..Default::default()
        };
        let module = DnsModule::new(cfg).await.unwrap();

        let ip = module.resolve_fake("test.example.com").unwrap();
        assert!(module.is_fake_ip(IpAddr::V4(ip)));

        // 1.1.1.1 is outside the 198.18.0.0/15 range
        assert!(!module.is_fake_ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
    }

    /// Filtered domains are identified correctly.
    #[tokio::test]
    async fn fakeip_filter() {
        let cfg = DnsModuleConfig {
            fake_ip_enabled: true,
            fake_ip_filter: vec!["localhost".into(), "local".into()],
            ..Default::default()
        };
        let module = DnsModule::new(cfg).await.unwrap();

        assert!(module.is_filtered("localhost"));
        assert!(module.is_filtered("myhost.local"));
        assert!(!module.is_filtered("example.com"));
    }

    /// DnsModule builds without panicking even with empty server list (uses system).
    #[tokio::test]
    async fn dns_module_builds_with_empty_servers() {
        let cfg = DnsModuleConfig {
            servers: vec![],
            ..Default::default()
        };
        let result = DnsModule::new(cfg).await;
        assert!(result.is_ok());
    }
}
