//! Hysteria2 glue used by the instance builder.
//!
//! This module wires together the Hysteria2 transport (from blackwire-transport)
//! with the instance lifecycle. It reads the config settings JSON and
//! constructs `Hysteria2ServerConfig` / `Hysteria2ClientConfig`.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context as _, Result};

use blackwire_app::dispatcher::Dispatcher;
use blackwire_config::schema::{InboundConfig, OutboundConfig};
use blackwire_transport::{
    Hysteria2ClientConfig, Hysteria2OutboundHandler, Hysteria2Server, Hysteria2ServerConfig,
};

/// Build and launch a Hysteria2 server inbound, returning a join handle for
/// the server task.
///
/// The server runs on a QUIC UDP socket (not TCP), so it does not go through
/// the normal `TcpServerTransport` path. Instead, it spawns its own task here.
pub(crate) fn start_hysteria2_inbound(
    cfg: &InboundConfig,
    dispatcher: Arc<dyn Dispatcher>,
) -> Result<tokio::task::JoinHandle<()>> {
    let server_config = parse_server_config(cfg)?;
    let tag = cfg.tag.clone();

    let handle = tokio::spawn(async move {
        let server = Hysteria2Server::new(server_config);
        if let Err(e) = server.serve(dispatcher).await {
            tracing::error!(tag = %tag, error = %e, "Hysteria2 server failed");
        }
    });

    Ok(handle)
}

/// Build a `Hysteria2OutboundHandler` from the outbound config.
pub(crate) fn build_hysteria2_outbound(
    cfg: &OutboundConfig,
) -> Result<Arc<dyn blackwire_app::features::OutboundHandler>> {
    let client_config = parse_client_config(cfg)?;
    Ok(Hysteria2OutboundHandler::new(
        client_config,
        cfg.tag.clone(),
    ))
}

// ── Config parsing ────────────────────────────────────────────────────────────

/// Parse Hysteria2 server settings from inbound config.
fn parse_server_config(cfg: &InboundConfig) -> Result<Hysteria2ServerConfig> {
    let s = &cfg.settings;

    let password = s["auth"].as_str().unwrap_or_default().to_string();

    let up_mbps = s["upMbps"].as_u64().unwrap_or(100);
    let down_mbps = s["downMbps"].as_u64().unwrap_or(100);

    // Read TLS cert+key from stream_settings.tlsSettings.
    let stream = cfg.stream_settings.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "Hysteria2 inbound '{tag}' missing streamSettings",
            tag = cfg.tag
        )
    })?;

    let tls = stream.tls_settings.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "Hysteria2 inbound '{tag}' missing tlsSettings",
            tag = cfg.tag
        )
    })?;

    let cert_path = require_field(&tls.certificate_file, "tlsSettings.certificateFile")?;
    let key_path = require_field(&tls.key_file, "tlsSettings.keyFile")?;

    let cert_pem = std::fs::read_to_string(cert_path)
        .with_context(|| format!("reading Hysteria2 cert '{cert_path}'"))?;
    let key_pem = std::fs::read_to_string(key_path)
        .with_context(|| format!("reading Hysteria2 key '{key_path}'"))?;

    let addr: SocketAddr = format!("{}:{}", cfg.listen, cfg.port)
        .parse()
        .with_context(|| {
            format!(
                "invalid Hysteria2 listen address '{}:{}'",
                cfg.listen, cfg.port
            )
        })?;

    Ok(Hysteria2ServerConfig {
        tag: cfg.tag.clone(),
        addr,
        password,
        up_mbps,
        down_mbps,
        cert_pem,
        key_pem,
    })
}

/// Parse Hysteria2 client settings from outbound config.
fn parse_client_config(cfg: &OutboundConfig) -> Result<Hysteria2ClientConfig> {
    let s = &cfg.settings;

    let server_str = s["server"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Hysteria2 outbound '{}' missing 'server'", cfg.tag))?;
    let server: SocketAddr = server_str
        .parse()
        .with_context(|| format!("invalid Hysteria2 server address '{server_str}'"))?;

    let password = s["auth"].as_str().unwrap_or_default().to_string();

    let up_mbps = s["upMbps"].as_u64().unwrap_or(100);
    let down_mbps = s["downMbps"].as_u64().unwrap_or(100);
    let skip_cert_verify = s["skipCertVerify"].as_bool().unwrap_or(false);

    // Use the server address host as SNI if not explicitly configured.
    let server_name = s["serverName"]
        .as_str()
        .map(|s| s.to_string())
        .unwrap_or_else(|| server.ip().to_string());

    Ok(Hysteria2ClientConfig {
        server,
        server_name,
        password,
        up_mbps,
        down_mbps,
        skip_cert_verify,
    })
}

fn require_field<'a>(value: &'a str, field: &str) -> Result<&'a str> {
    if value.is_empty() {
        anyhow::bail!("{field} must not be empty");
    }
    Ok(value)
}
