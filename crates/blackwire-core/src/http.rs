//! HTTP CONNECT protocol wiring for `instance.rs`.
//!
//! Builds the `HttpConnectInbound` handler from config.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;

use blackwire_app::features::InboundHandler;
use blackwire_protocol::http_connect::HttpConnectInbound;

/// Build an HTTP CONNECT inbound handler from config.
pub(crate) fn build_http_inbound(
    cfg: &blackwire_config::schema::InboundConfig,
    handshake_timeout: Option<Duration>,
) -> Result<Arc<dyn InboundHandler>> {
    Ok(HttpConnectInbound::new(&cfg.tag, handshake_timeout))
}
