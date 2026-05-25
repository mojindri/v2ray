use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use validator::{Validate, ValidationError, ValidationErrors};

use super::{Protocol, SniffingConfig, StreamSettingsConfig};

/// An inbound handler: a port and protocol the proxy listens on.
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct InboundConfig {
    /// Unique name used in routing rules and logs.
    pub tag: String,

    /// Proxy protocol: "socks", "http", "vless", and so on.
    pub protocol: Protocol,

    /// IP address to listen on.
    pub listen: IpAddr,

    /// Port to listen on. Must be between 1 and 65535.
    #[validate(range(min = 1, max = 65535))]
    pub port: u16,

    /// Protocol-specific settings. Shape depends on `protocol`.
    #[serde(default)]
    pub settings: serde_json::Value,

    /// Transport settings: TLS, WebSocket, REALITY, etc.
    #[serde(
        default,
        rename = "streamSettings",
        alias = "stream_settings",
        skip_serializing_if = "Option::is_none"
    )]
    pub stream_settings: Option<StreamSettingsConfig>,

    /// Per-inbound runtime safety limits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<InboundLimitsConfig>,

    /// Sniffing settings for detecting inner protocol.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sniffing: Option<SniffingConfig>,
}

/// An outbound handler: a protocol used to forward traffic to the destination.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundConfig {
    /// Unique name referenced by routing rules.
    pub tag: String,

    /// Proxy protocol: "freedom", "vless", "vmess", and so on.
    pub protocol: Protocol,

    /// Protocol-specific settings.
    #[serde(default)]
    pub settings: serde_json::Value,

    /// Transport settings: TLS, WebSocket, REALITY, etc.
    #[serde(
        default,
        rename = "streamSettings",
        alias = "stream_settings",
        skip_serializing_if = "Option::is_none"
    )]
    pub stream_settings: Option<StreamSettingsConfig>,
}

impl Validate for OutboundConfig {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = ValidationErrors::new();

        if let Some(port) = self.settings.get("port") {
            let invalid = port
                .as_u64()
                .map(|p| p == 0 || p > u16::MAX as u64)
                .or_else(|| port.as_i64().map(|p| p <= 0 || p > u16::MAX as i64))
                .unwrap_or(false);

            if invalid {
                let mut error = ValidationError::new("range");
                error.message = Some("outbound settings.port must be between 1 and 65535".into());
                errors.add("settings.port", error);
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

/// Per-inbound runtime safety limits.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct InboundLimitsConfig {
    /// Max concurrent connections on this inbound only (overrides global default).
    #[serde(
        default,
        rename = "maxConnections",
        alias = "max_connections",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_connections: Option<usize>,

    /// Handshake timeout for this inbound (seconds). Overrides global `limits.maxHandshakeSeconds`.
    /// Applies to REALITY/TLS/VLESS header phases only — not the relay body.
    #[serde(
        default,
        rename = "maxHandshakeSeconds",
        alias = "max_handshake_seconds",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_handshake_seconds: Option<u64>,

    /// Idle timeout for this inbound (reserved; not wired yet).
    #[serde(
        default,
        rename = "maxIdleSeconds",
        alias = "max_idle_seconds",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_idle_seconds: Option<u64>,
}
