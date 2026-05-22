//! HTTP CONNECT protocol wiring for `instance.rs`.
//!
//! Builds the `HttpConnectInbound` handler from config.

use std::sync::Arc;

use anyhow::Result;

use proxy_app::features::InboundHandler;
use proxy_protocol::http_connect::HttpConnectInbound;

/// Build an HTTP CONNECT inbound handler from config.
pub(crate) fn build_http_inbound(
    cfg: &proxy_config::schema::InboundConfig,
) -> Result<Arc<dyn InboundHandler>> {
    Ok(HttpConnectInbound::new(&cfg.tag))
}
