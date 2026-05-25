//! Trojan protocol wiring for `instance.rs`.
//!
//! Reads Trojan-specific settings from config JSON and builds the
//! `TrojanInbound` / `TrojanOutbound` handlers.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context as _, Result};

use blackwire_app::features::{InboundHandler, OutboundHandler};
use blackwire_protocol::trojan::{TrojanInbound, TrojanOutbound, TrojanOutboundConfig};

use crate::outbound_transport::{uses_outbound_transport, TransportTrojanOutbound};

/// Build a Trojan inbound handler from config.
pub(crate) fn build_trojan_inbound(
    cfg: &blackwire_config::schema::InboundConfig,
) -> Result<Arc<dyn InboundHandler>> {
    // Collect passwords from config JSON.
    // Expected shape: { "clients": [{ "password": "..." }, ...] }
    let clients = cfg.settings["clients"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("Trojan inbound '{}' missing 'clients' array", cfg.tag))?;

    let passwords: Vec<String> = clients
        .iter()
        .enumerate()
        .map(|(i, c)| {
            c["password"]
                .as_str()
                .ok_or_else(|| {
                    anyhow::anyhow!("Trojan client #{} in '{}' missing 'password'", i, cfg.tag)
                })
                .map(|s| s.to_string())
        })
        .collect::<Result<_>>()?;

    if passwords.is_empty() {
        anyhow::bail!("Trojan inbound '{}' has no configured clients", cfg.tag);
    }

    Ok(TrojanInbound::new(&cfg.tag, &passwords))
}

/// Build a Trojan outbound handler from config.
pub(crate) fn build_trojan_outbound(
    cfg: &blackwire_config::schema::OutboundConfig,
) -> Result<Arc<dyn OutboundHandler>> {
    let settings = &cfg.settings;

    let server_str = settings["address"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Trojan outbound '{}' missing 'address'", cfg.tag))?;
    let port = settings["port"]
        .as_u64()
        .ok_or_else(|| anyhow::anyhow!("Trojan outbound '{}' missing 'port'", cfg.tag))?;
    let server: SocketAddr = format!("{server_str}:{port}")
        .parse()
        .with_context(|| format!("invalid Trojan server address '{server_str}:{port}'"))?;

    let password = settings["password"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Trojan outbound '{}' missing 'password'", cfg.tag))?
        .to_string();

    if uses_outbound_transport(&cfg.stream_settings) {
        Ok(TransportTrojanOutbound::new(
            &cfg.tag,
            server,
            password,
            cfg.stream_settings.clone(),
        ))
    } else {
        Ok(TrojanOutbound::new(
            &cfg.tag,
            TrojanOutboundConfig { server, password },
        ))
    }
}
