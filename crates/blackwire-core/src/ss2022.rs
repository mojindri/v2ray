//! Shadowsocks-2022 protocol wiring for `instance.rs`.
//!
//! Reads SS-2022-specific settings from config JSON and builds the
//! `Ss2022Inbound` / `Ss2022Outbound` handlers.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context as _, Result};

use proxy_app::features::{InboundHandler, OutboundHandler};
use proxy_protocol::ss2022::{inbound::Ss2022Inbound, outbound::Ss2022Outbound};

/// Build an SS-2022 inbound handler from config.
///
/// Expected config shape:
/// ```json
/// {
///   "settings": {
///     "method": "2022-blake3-aes-256-gcm",
///     "password": "your-password"
///   }
/// }
/// ```
pub(crate) fn build_ss2022_inbound(
    cfg: &proxy_config::schema::InboundConfig,
) -> Result<Arc<dyn InboundHandler>> {
    let password = cfg.settings["password"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("SS-2022 inbound '{}' missing 'password'", cfg.tag))?
        .to_string();

    Ok(Ss2022Inbound::new(&cfg.tag, &password))
}

/// Build an SS-2022 outbound handler from config.
///
/// Expected config shape:
/// ```json
/// {
///   "settings": {
///     "address": "1.2.3.4",
///     "port": 8388,
///     "method": "2022-blake3-aes-256-gcm",
///     "password": "your-password"
///   }
/// }
/// ```
pub(crate) fn build_ss2022_outbound(
    cfg: &proxy_config::schema::OutboundConfig,
) -> Result<Arc<dyn OutboundHandler>> {
    let settings = &cfg.settings;

    let server_str = settings["address"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("SS-2022 outbound '{}' missing 'address'", cfg.tag))?;
    let port = settings["port"]
        .as_u64()
        .ok_or_else(|| anyhow::anyhow!("SS-2022 outbound '{}' missing 'port'", cfg.tag))?;
    let server: SocketAddr = format!("{server_str}:{port}")
        .parse()
        .with_context(|| format!("invalid SS-2022 server address '{server_str}:{port}'"))?;

    let password = settings["password"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("SS-2022 outbound '{}' missing 'password'", cfg.tag))?
        .to_string();

    Ok(Ss2022Outbound::new(&cfg.tag, server, &password))
}
