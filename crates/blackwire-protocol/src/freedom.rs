//! Freedom outbound — direct TCP connection to the destination.
//!
//! "Freedom" means no proxy protocol: the proxy connects directly to the
//! destination server without wrapping the traffic in any additional protocol.
//!
//! This is the simplest possible outbound and is typically used for:
//!   - Traffic that should not be proxied (local IPs, LAN traffic)
//!   - The "direct" outbound in a configuration where only some traffic is proxied
//!   - Testing — to verify the proxy pipeline works without protocol complexity
//!
//! Freedom does DNS resolution itself: if the destination is a domain name,
//! it resolves it to an IP using the OS resolver before connecting.

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use tracing::debug;

use proxy_app::context::Context;
use proxy_app::features::OutboundHandler;
use proxy_common::{tcp_connect, Address, BoxedStream, ProxyError};

/// The freedom outbound: connects directly to the destination.
pub struct FreedomOutbound {
    /// The unique tag for this outbound (from config.json).
    tag: String,
}

impl FreedomOutbound {
    /// Create a new freedom outbound with the given tag.
    pub fn new(tag: impl Into<String>) -> Arc<Self> {
        Arc::new(Self { tag: tag.into() })
    }
}

#[async_trait]
impl OutboundHandler for FreedomOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn connect(&self, _ctx: &Context, dest: &Address) -> Result<BoxedStream, ProxyError> {
        // Resolve the destination to a socket address.
        let socket_addr = resolve(dest).await?;

        debug!(dest = %dest, resolved = %socket_addr, "freedom: connecting");

        let stream = tcp_connect(socket_addr).await?;

        // Disable Nagle's algorithm for lower latency.
        stream.set_nodelay(true)?;

        Ok(Box::new(stream))
    }
}

/// Resolve an `Address` to a `SocketAddr` for TCP connect.
///
/// - IPv4/IPv6 addresses are returned as-is.
/// - Domain names are resolved using the OS default DNS resolver
///   (the same one used by `getaddrinfo`). In Phase 4, this will be
///   replaced by the `DnsModule` which supports DoT/DoH and FakeIP.
async fn resolve(dest: &Address) -> Result<SocketAddr, ProxyError> {
    match dest {
        Address::Ipv4(ip, port) => Ok(SocketAddr::new(std::net::IpAddr::V4(*ip), *port)),
        Address::Ipv6(ip, port) => Ok(SocketAddr::new(std::net::IpAddr::V6(*ip), *port)),
        Address::Domain(name, port) => {
            // `tokio::net::lookup_host` does async DNS resolution using the OS resolver.
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host((name.as_str(), *port))
                .await
                .map_err(|e| ProxyError::DnsResolutionFailed(format!("{name}: {e}")))?
                .collect();

            // Use the first resolved address.
            addrs
                .into_iter()
                .next()
                .ok_or_else(|| ProxyError::DnsResolutionFailed(name.clone()))
        }
    }
}
