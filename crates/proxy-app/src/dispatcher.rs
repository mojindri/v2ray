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
//! The relay is implemented using `tokio::io::copy_bidirectional`. This runs
//! two concurrent copy loops:
//!   - Inbound → Outbound: read from the client, write to the server
//!   - Outbound → Inbound: read from the server, write to the client
//!
//! Both loops run until either side closes the connection or an error occurs.
//!
//! # Future enhancement: splice(2)
//!
//! On Linux, `tokio::io::copy_bidirectional` goes through userspace (kernel →
//! userspace → kernel). For XTLS Vision, we will replace this with the Linux
//! `splice(2)` syscall, which copies directly between file descriptors in the
//! kernel, bypassing userspace entirely. This is implemented in Phase 2.

use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use tracing::{debug, info, instrument, warn};

use proxy_common::{Address, BoxedStream, ProxyError};

use crate::context::Context;
use crate::features::OutboundHandler;
use crate::router::Router;

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
}

/// The standard dispatcher implementation.
///
/// Uses the router to pick an outbound, then relays bytes between
/// the inbound and outbound connections.
pub struct DefaultDispatcher {
    router: Arc<dyn Router>,
    outbounds: std::collections::HashMap<String, Arc<dyn OutboundHandler>>,
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
        Arc::new(Self { router, outbounds })
    }
}

#[async_trait]
impl Dispatcher for DefaultDispatcher {
    #[instrument(skip(self, inbound_stream), fields(dest = %dest, inbound = %ctx.inbound_tag))]
    async fn dispatch(
        &self,
        ctx: Context,
        dest: Address,
        inbound_stream: BoxedStream,
    ) -> Result<(), ProxyError> {
        // Step 1: Ask the router which outbound to use.
        let routing_ctx = crate::router::RoutingContext {
            dest: &dest,
            network: proxy_common::Network::Tcp,
            inbound_tag: &ctx.inbound_tag,
            user: ctx.user.as_deref(),
        };
        let route = self.router.pick_route(&routing_ctx)?;

        debug!(outbound = %route.outbound_tag, "route selected");

        // Step 2: Find the outbound handler.
        let outbound = self.outbounds.get(&route.outbound_tag)
            .ok_or_else(|| ProxyError::Protocol(
                format!("outbound '{}' not found", route.outbound_tag)
            ))?;

        // Step 3: Open a connection to the destination via the outbound.
        let start = Instant::now();
        let outbound_stream = outbound.connect(&ctx, &dest).await.map_err(|e| {
            warn!(
                outbound = %route.outbound_tag,
                dest = %dest,
                error = %e,
                "outbound connect failed"
            );
            e
        })?;

        info!(
            outbound = %route.outbound_tag,
            dest = %dest,
            "relay started"
        );

        // Step 4: Relay bytes bidirectionally until either side closes.
        //
        // copy_bidirectional runs two concurrent copy loops:
        //   inbound → outbound (client sending data to the server)
        //   outbound → inbound (server sending data back to the client)
        //
        // It returns the total bytes sent in each direction when finished.
        let result = tokio::io::copy_bidirectional(
            &mut { inbound_stream },
            &mut { outbound_stream },
        ).await;

        let elapsed = start.elapsed();

        match result {
            Ok((up, down)) => {
                info!(
                    outbound = %route.outbound_tag,
                    dest = %dest,
                    uplink_bytes = up,
                    downlink_bytes = down,
                    duration_ms = elapsed.as_millis(),
                    "relay finished"
                );
            }
            Err(e) => {
                // Connection errors during relay are normal (client disconnected,
                // server reset, etc.) — log at debug level, not warn.
                debug!(
                    outbound = %route.outbound_tag,
                    dest = %dest,
                    error = %e,
                    "relay error"
                );
            }
        }

        Ok(())
    }
}
