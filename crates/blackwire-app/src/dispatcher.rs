//! Dispatcher: the connection between inbounds and outbounds.
//!
//! After an inbound handler decodes a connection's destination address, it
//! hands the connection to the dispatcher. The dispatcher:
//!
//!   1. Asks the router which outbound to use.
//!   2. Calls `OutboundHandler::connect()` to open a connection to the destination.
//!   3. Relays bytes bidirectionally between the inbound and outbound connections.
//!   4. Records statistics (bytes transferred, connection duration).
//!
//! # The relay loop
//!
//! The default relay is implemented using `tokio::io::copy_bidirectional`. This
//! runs two concurrent copy loops:
//!   - Inbound → Outbound: read from the client, write to the server
//!   - Outbound → Inbound: read from the server, write to the client
//!
//! Both loops run until either side closes the connection or an error occurs.
//!
//! # Linux splice(2)
//!
//! On Linux, raw TCP-to-TCP relays use `splice(2)`, which moves bytes through
//! kernel pipes without copying them into userspace. Non-Linux builds and
//! non-raw streams keep using `copy_bidirectional`.

use std::sync::Arc;
use std::time::Instant;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use tracing::{debug, info, warn};

use std::collections::HashMap;

use blackwire_common::{Address, BoxedStream, ProxyError};
use blackwire_config::schema::SniffingConfig;

use crate::context::Context;
use crate::dns::DnsModule;
use crate::features::OutboundHandler;
use crate::metrics::{record_connection_accepted, record_connection_closed};
use crate::router::{normalize_routing_domain_strategy, Router, RoutingDomainStrategy};
use crate::runtime_stats;

/// The dispatcher connects inbounds to outbounds by consulting the router
/// and relaying bytes.
#[async_trait]
pub trait Dispatcher: Send + Sync + 'static {
    /// Dispatch a connection to the appropriate outbound.
    ///
    /// # Arguments
    /// * `ctx` — connection context (inbound tag, user, source address)
    /// * `dest` — the destination the client wants to reach
    /// * `inbound_stream` — the byte stream from the inbound side
    async fn dispatch(
        &self,
        ctx: Context,
        dest: Address,
        inbound_stream: BoxedStream,
    ) -> Result<(), ProxyError>;

    /// Route and open an outbound stream without relaying (Mux.Cool sub-connections).
    async fn connect_outbound(
        &self,
        ctx: Context,
        dest: Address,
    ) -> Result<BoxedStream, ProxyError>;
}

/// The standard dispatcher implementation.
///
/// Uses the router to pick an outbound, then relays bytes between
/// the inbound and outbound connections.
pub struct DefaultDispatcher {
    router: Arc<dyn Router>,
    outbounds: std::collections::HashMap<String, Arc<dyn OutboundHandler>>,
    dns: Option<Arc<DnsModule>>,
    sniffing: Arc<ArcSwap<HashMap<String, SniffingConfig>>>,
}

impl DefaultDispatcher {
    /// Create a new dispatcher with the given router and outbounds map.
    ///
    /// # Arguments
    /// * `router` — the routing engine
    /// * `outbounds` — map from outbound tag to outbound handler
    pub fn new(
        router: Arc<dyn Router>,
        outbounds: std::collections::HashMap<String, Arc<dyn OutboundHandler>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            router,
            outbounds,
            dns: None,
            sniffing: Arc::new(ArcSwap::from_pointee(HashMap::new())),
        })
    }

    /// Create a dispatcher with per-inbound sniffing settings (Xray `sniffing`).
    pub fn new_with_sniffing(
        router: Arc<dyn Router>,
        outbounds: std::collections::HashMap<String, Arc<dyn OutboundHandler>>,
        sniffing: Arc<ArcSwap<HashMap<String, SniffingConfig>>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            router,
            outbounds,
            dns: None,
            sniffing,
        })
    }

    /// Create a dispatcher with DNS/FakeIP support.
    ///
    /// If a destination IP is in the configured FakeIP pool, the dispatcher
    /// restores the original domain before routing and outbound connection.
    pub fn new_with_dns(
        router: Arc<dyn Router>,
        outbounds: std::collections::HashMap<String, Arc<dyn OutboundHandler>>,
        dns: Arc<DnsModule>,
    ) -> Arc<Self> {
        Arc::new(Self {
            router,
            outbounds,
            dns: Some(dns),
            sniffing: Arc::new(ArcSwap::from_pointee(HashMap::new())),
        })
    }

    /// Dispatcher with DNS and sniffing.
    pub fn new_with_dns_and_sniffing(
        router: Arc<dyn Router>,
        outbounds: std::collections::HashMap<String, Arc<dyn OutboundHandler>>,
        dns: Arc<DnsModule>,
        sniffing: Arc<ArcSwap<HashMap<String, SniffingConfig>>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            router,
            outbounds,
            dns: Some(dns),
            sniffing,
        })
    }
}

#[async_trait]
impl Dispatcher for DefaultDispatcher {
    async fn dispatch(
        &self,
        mut ctx: Context,
        mut dest: Address,
        mut inbound_stream: BoxedStream,
    ) -> Result<(), ProxyError> {
        let sniff_cfg = self.sniffing.load().get(&ctx.inbound_tag).cloned();
        if let Some(cfg) = sniff_cfg {
            if cfg.enabled {
                let (stream, sniff) = crate::sniff::sniff_stream(inbound_stream, &cfg).await?;
                inbound_stream = stream;
                dest = crate::sniff::apply_dest_override(dest, &sniff, &cfg);
                ctx = ctx.with_sniff(sniff.protocol, sniff.domain);
            }
        }

        let inbound_tag = ctx.inbound_tag.clone();
        let user_email = ctx.user.clone();
        let dest_label = dest.to_string();

        let start = Instant::now();
        let outbound_stream = self.connect_outbound(ctx, dest).await?;

        info!(dest = %dest_label, inbound = %inbound_tag, "relay started");

        // Relay bytes bidirectionally until either side closes.
        //
        // The relay helper uses Linux splice(2) for raw TCP-to-TCP streams and
        // falls back to copy_bidirectional for every other stream type.
        //
        // Both paths run two concurrent copy loops:
        //   inbound → outbound (client sending data to the server)
        //   outbound → inbound (server sending data back to the client)
        //
        // It returns the total bytes sent in each direction when finished.
        let result = crate::relay::relay_bidirectional(inbound_stream, outbound_stream).await;

        let elapsed = start.elapsed();

        match &result {
            Ok((up, down)) => {
                info!(
                    dest = %dest_label,
                    inbound = %inbound_tag,
                    uplink_bytes = up,
                    downlink_bytes = down,
                    duration_ms = elapsed.as_millis(),
                    "relay finished"
                );
            }
            Err(e) => {
                debug!(
                    dest = %dest_label,
                    inbound = %inbound_tag,
                    error = %e,
                    "relay error"
                );
            }
        }

        let (rx_bytes, tx_bytes) = result.unwrap_or((0, 0));
        record_connection_closed(&inbound_tag, rx_bytes, tx_bytes, elapsed);
        if let Some(user) = user_email.as_deref() {
            runtime_stats::record_user_traffic(user, rx_bytes, tx_bytes);
        }

        Ok(())
    }

    async fn connect_outbound(
        &self,
        ctx: Context,
        dest: Address,
    ) -> Result<BoxedStream, ProxyError> {
        DefaultDispatcher::connect_outbound(self, ctx, dest).await
    }
}

impl DefaultDispatcher {
    /// Route and dial the destination without starting a relay loop.
    pub async fn connect_outbound(
        &self,
        ctx: Context,
        dest: Address,
    ) -> Result<BoxedStream, ProxyError> {
        let dest = self.restore_fakeip_destination(dest);

        let protocol_label = ctx.sniffed_protocol.as_deref().unwrap_or("tcp");
        record_connection_accepted(&ctx.inbound_tag, protocol_label);

        let route = self
            .pick_route_xray(
                &ctx.inbound_tag,
                &dest,
                ctx.user.as_deref(),
                ctx.sniffed_protocol.as_deref(),
                ctx.sniffed_domain.as_deref(),
            )
            .await?;

        debug!(outbound = %route.outbound_tag, "route selected");

        let outbound = self
            .outbounds
            .get(route.outbound_tag.as_ref())
            .ok_or_else(|| {
                ProxyError::Protocol(format!("outbound '{}' not found", route.outbound_tag))
            })?;

        outbound.connect(&ctx, &dest).await.map_err(|e| {
            warn!(
                outbound = %route.outbound_tag,
                dest = %dest,
                error = %e,
                "outbound connect failed"
            );
            e
        })
    }

    /// Xray routing: https://xtls.github.io/en/config/routing.html#domainstrategy
    async fn pick_route_xray(
        &self,
        inbound_tag: &str,
        dest: &Address,
        user: Option<&str>,
        sniffed_protocol: Option<&str>,
        sniffed_domain: Option<&str>,
    ) -> Result<crate::router::Route, ProxyError> {
        let strategy = normalize_routing_domain_strategy(self.router.domain_strategy().as_deref());

        if strategy == RoutingDomainStrategy::IpOnDemand
            && matches!(dest, Address::Domain(..))
            && self.router.has_ip_rules()
        {
            if let Some(ips) = self.resolve_domain_ips(dest).await {
                for ip_dest in &ips {
                    let ctx = Self::routing_ctx(
                        ip_dest,
                        inbound_tag,
                        user,
                        sniffed_protocol,
                        sniffed_domain,
                    );
                    let (route, matched) = self.router.pick_route_match(&ctx);
                    if matched {
                        return Ok(route);
                    }
                }
            }
        }

        let ctx = Self::routing_ctx(dest, inbound_tag, user, sniffed_protocol, sniffed_domain);
        let (route, matched) = self.router.pick_route_match(&ctx);
        if matched || strategy == RoutingDomainStrategy::AsIs {
            return Ok(route);
        }

        if strategy == RoutingDomainStrategy::IpIfNonMatch {
            if let Address::Domain(_, _) = dest {
                if let Some(ips) = self.resolve_domain_ips(dest).await {
                    for ip_dest in &ips {
                        let ctx = Self::routing_ctx(
                            ip_dest,
                            inbound_tag,
                            user,
                            sniffed_protocol,
                            sniffed_domain,
                        );
                        let (route, matched) = self.router.pick_route_match(&ctx);
                        if matched {
                            return Ok(route);
                        }
                    }
                }
            }
        }

        Ok(route)
    }

    fn routing_ctx<'a>(
        dest: &'a Address,
        inbound_tag: &'a str,
        user: Option<&'a str>,
        sniffed_protocol: Option<&'a str>,
        sniffed_domain: Option<&'a str>,
    ) -> crate::router::RoutingContext<'a> {
        crate::router::RoutingContext {
            dest,
            network: blackwire_common::Network::Tcp,
            inbound_tag,
            user,
            sniffed_protocol,
            sniffed_domain,
        }
    }

    async fn resolve_domain_ips(&self, dest: &Address) -> Option<Vec<Address>> {
        let Address::Domain(name, port) = dest else {
            return None;
        };
        let mut ips = Vec::new();
        if let Some(dns) = &self.dns {
            if let Ok(resolved) = dns.resolve(name).await {
                for ip in resolved {
                    ips.push(match ip {
                        std::net::IpAddr::V4(v4) => Address::Ipv4(v4, *port),
                        std::net::IpAddr::V6(v6) => Address::Ipv6(v6, *port),
                    });
                }
            }
        }
        if ips.is_empty() {
            if let Ok(addrs) = tokio::net::lookup_host((name.as_str(), *port)).await {
                for addr in addrs {
                    ips.push(match addr {
                        std::net::SocketAddr::V4(v4) => Address::Ipv4(*v4.ip(), *port),
                        std::net::SocketAddr::V6(v6) => Address::Ipv6(*v6.ip(), *port),
                    });
                }
            }
        }
        if ips.is_empty() {
            None
        } else {
            Some(ips)
        }
    }

    fn restore_fakeip_destination(&self, dest: Address) -> Address {
        let Some(dns) = &self.dns else {
            return dest;
        };

        match dest {
            Address::Ipv4(ip, port) if dns.is_fake_ip(std::net::IpAddr::V4(ip)) => dns
                .reverse_fake(ip)
                .map(|domain| Address::Domain(domain, port))
                .unwrap_or(Address::Ipv4(ip, port)),
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::DnsModuleConfig;
    use crate::router::{Route, RoutingContext};

    struct StaticRouter;

    impl Router for StaticRouter {
        fn pick_route_match(&self, _ctx: &RoutingContext<'_>) -> (Route, bool) {
            (
                Route {
                    outbound_tag: Arc::from("unused"),
                },
                false,
            )
        }
    }

    #[tokio::test]
    async fn dispatcher_restores_fakeip_destination_before_routing() {
        let dns = Arc::new(
            DnsModule::new(DnsModuleConfig {
                fake_ip_enabled: true,
                ..Default::default()
            })
            .await
            .unwrap(),
        );
        let fake = dns.resolve_fake("example.com").unwrap();
        let dispatcher = DefaultDispatcher::new_with_dns(
            Arc::new(StaticRouter),
            std::collections::HashMap::new(),
            dns,
        );

        let restored = dispatcher.restore_fakeip_destination(Address::Ipv4(fake, 443));
        assert_eq!(restored, Address::Domain("example.com".into(), 443));
    }

    #[tokio::test]
    async fn dispatcher_keeps_unknown_fakeip_as_ip_destination() {
        let dns = Arc::new(
            DnsModule::new(DnsModuleConfig {
                fake_ip_enabled: true,
                ..Default::default()
            })
            .await
            .unwrap(),
        );
        let dispatcher = DefaultDispatcher::new_with_dns(
            Arc::new(StaticRouter),
            std::collections::HashMap::new(),
            dns,
        );

        let ip = "198.18.0.100".parse().unwrap();
        let restored = dispatcher.restore_fakeip_destination(Address::Ipv4(ip, 443));
        assert_eq!(restored, Address::Ipv4(ip, 443));
    }
}
