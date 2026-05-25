//! VMess protocol wiring for `instance.rs`.
//!
//! Reads VMess-specific settings from config JSON and builds the
//! `VmessInbound` / `VmessOutbound` handlers.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context as _, Result};

use proxy_app::features::{InboundHandler, OutboundHandler};
use proxy_protocol::vmess::{VmessInbound, VmessOutbound, VmessOutboundConfig, VmessUserRegistry};

use crate::outbound_transport::{uses_outbound_transport, TransportVmessOutbound};

/// Build a VMess inbound handler from config.
pub(crate) fn build_vmess_inbound(
    cfg: &proxy_config::schema::InboundConfig,
) -> Result<Arc<dyn InboundHandler>> {
    let registry = VmessUserRegistry::new();

    let clients = cfg.settings["clients"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("VMess inbound '{}' missing 'clients' array", cfg.tag))?;

    if clients.is_empty() {
        anyhow::bail!("VMess inbound '{}' has no configured clients", cfg.tag);
    }

    for (i, client) in clients.iter().enumerate() {
        let id_str = client["id"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("VMess client #{i} missing 'id'"))?;
        let uuid =
            parse_uuid(id_str).with_context(|| format!("invalid UUID in VMess client #{i}"))?;
        let email = client["email"].as_str().unwrap_or("").to_string();
        registry.add_user(uuid, email);
    }

    Ok(VmessInbound::new(&cfg.tag, registry))
}

/// Build a VMess outbound handler from config.
pub(crate) fn build_vmess_outbound(
    cfg: &proxy_config::schema::OutboundConfig,
) -> Result<Arc<dyn OutboundHandler>> {
    let settings = &cfg.settings;

    let server_str = settings["address"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("VMess outbound '{}' missing 'address'", cfg.tag))?;
    let port = settings["port"]
        .as_u64()
        .ok_or_else(|| anyhow::anyhow!("VMess outbound '{}' missing 'port'", cfg.tag))?;
    let server: SocketAddr = format!("{server_str}:{port}")
        .parse()
        .with_context(|| format!("invalid VMess server address '{server_str}:{port}'"))?;

    let uuid_str = settings["users"][0]["id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("VMess outbound '{}' missing users[0].id", cfg.tag))?;
    let uuid = parse_uuid(uuid_str)?;

    if uses_outbound_transport(&cfg.stream_settings) {
        Ok(TransportVmessOutbound::new(
            &cfg.tag,
            server,
            uuid,
            cfg.stream_settings.clone(),
        ))
    } else {
        Ok(VmessOutbound::new(
            &cfg.tag,
            VmessOutboundConfig { server, uuid },
        ))
    }
}

/// Parse a UUID string into 16 bytes.
fn parse_uuid(s: &str) -> Result<[u8; 16]> {
    let uuid = uuid::Uuid::parse_str(s).with_context(|| format!("invalid UUID '{s}'"))?;
    Ok(*uuid.as_bytes())
}
