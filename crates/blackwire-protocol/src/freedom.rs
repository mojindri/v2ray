//! Freedom outbound — direct TCP connection to the destination.
//!
//! "Freedom" means no proxy protocol: the proxy connects directly to the
//! destination server without wrapping the traffic in any additional protocol.
//!
//! When the top-level `dns` block is configured (Xray/sing-box style), domain
//! lookups use that module (e.g. Docker embedded DNS). Otherwise freedom falls
//! back to `tokio::net::lookup_host` (OS resolver).

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use async_trait::async_trait;
use tracing::debug;

use blackwire_app::context::Context;
use blackwire_app::dns::DnsModule;
use blackwire_app::features::OutboundHandler;
use blackwire_common::{tcp_connect, Address, BoxedStream, ProxyError};

/// The freedom outbound: connects directly to the destination.
pub struct FreedomOutbound {
    tag: String,
    dns: Option<Arc<DnsModule>>,
}

impl FreedomOutbound {
    /// Create a freedom outbound using the OS resolver for domains.
    pub fn new(tag: impl Into<String>) -> Arc<Self> {
        Arc::new(Self {
            tag: tag.into(),
            dns: None,
        })
    }

    /// Create a freedom outbound that resolves domains via the configured DNS module.
    pub fn new_with_dns(tag: impl Into<String>, dns: Arc<DnsModule>) -> Arc<Self> {
        Arc::new(Self {
            tag: tag.into(),
            dns: Some(dns),
        })
    }

    async fn resolve(&self, dest: &Address) -> Result<SocketAddr, ProxyError> {
        match dest {
            Address::Ipv4(ip, port) => Ok(SocketAddr::new(IpAddr::V4(*ip), *port)),
            Address::Ipv6(ip, port) => Ok(SocketAddr::new(IpAddr::V6(*ip), *port)),
            Address::Domain(name, port) => {
                if let Some(dns) = &self.dns {
                    let ips = dns.resolve(name).await?;
                    let ip = ips.into_iter().next().ok_or_else(|| {
                        ProxyError::DnsResolutionFailed(format!("{name}: no records returned"))
                    })?;
                    return Ok(SocketAddr::new(ip, *port));
                }

                let addrs: Vec<SocketAddr> = tokio::net::lookup_host((name.as_str(), *port))
                    .await
                    .map_err(|e| ProxyError::DnsResolutionFailed(format!("{name}: {e}")))?
                    .collect();

                addrs
                    .into_iter()
                    .next()
                    .ok_or_else(|| ProxyError::DnsResolutionFailed(name.clone()))
            }
        }
    }
}

#[async_trait]
impl OutboundHandler for FreedomOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn connect(&self, _ctx: &Context, dest: &Address) -> Result<BoxedStream, ProxyError> {
        let socket_addr = self.resolve(dest).await?;

        debug!(dest = %dest, resolved = %socket_addr, "freedom: connecting");

        let stream = tcp_connect(socket_addr).await?;
        stream.set_nodelay(true)?;
        Ok(Box::new(stream))
    }
}
