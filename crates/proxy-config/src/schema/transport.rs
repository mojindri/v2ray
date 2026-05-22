use serde::{Deserialize, Serialize};

use super::{NetworkType, SecurityType};

/// Transport layer settings: how to wrap or protect the connection.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StreamSettingsConfig {
    /// Transport to use: "tcp", "ws", "grpc", "quic", "kcp", or "splithttp".
    #[serde(default)]
    pub network: NetworkType,

    /// Whether to use TLS, REALITY, or no security wrapper.
    #[serde(default)]
    pub security: SecurityType,

    /// TLS-specific settings.
    #[serde(
        default,
        rename = "tlsSettings",
        skip_serializing_if = "Option::is_none"
    )]
    pub tls_settings: Option<TlsConfig>,

    /// REALITY-specific settings.
    #[serde(
        default,
        rename = "realitySettings",
        skip_serializing_if = "Option::is_none"
    )]
    pub reality_settings: Option<RealityConfig>,

    /// WebSocket-specific settings.
    #[serde(
        default,
        rename = "wsSettings",
        skip_serializing_if = "Option::is_none"
    )]
    pub ws_settings: Option<WsConfig>,

    /// gRPC-specific settings.
    #[serde(
        default,
        rename = "grpcSettings",
        skip_serializing_if = "Option::is_none"
    )]
    pub grpc_settings: Option<GrpcConfig>,
}

/// TLS configuration used when `security = "tls"`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TlsConfig {
    /// Server name (SNI) to present during the TLS handshake.
    #[serde(
        default,
        rename = "serverName",
        skip_serializing_if = "String::is_empty"
    )]
    pub server_name: String,

    /// Skip certificate verification. Use only for development.
    #[serde(default, rename = "allowInsecure")]
    pub allow_insecure: bool,

    /// ALPN protocols to offer.
    #[serde(default)]
    pub alpn: Vec<String>,

    /// Path to the TLS certificate file. Server-side only.
    #[serde(
        default,
        rename = "certificateFile",
        skip_serializing_if = "String::is_empty"
    )]
    pub certificate_file: String,

    /// Path to the TLS private key file. Server-side only.
    #[serde(default, rename = "keyFile", skip_serializing_if = "String::is_empty")]
    pub key_file: String,
}

/// REALITY configuration for TLS camouflage.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RealityConfig {
    /// Whether this is a server config.
    #[serde(default)]
    pub show: bool,

    /// Real destination used when authentication fails.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub dest: String,

    /// Server's X25519 private key. Server-side only.
    #[serde(
        default,
        rename = "privateKey",
        skip_serializing_if = "String::is_empty"
    )]
    pub private_key: String,

    /// Short IDs clients may use to authenticate.
    #[serde(default, rename = "shortIds")]
    pub short_ids: Vec<String>,

    /// Server's X25519 public key. Client-side only.
    #[serde(
        default,
        rename = "publicKey",
        skip_serializing_if = "String::is_empty"
    )]
    pub public_key: String,

    /// Client short ID. Must match one of the server short IDs.
    #[serde(default, rename = "shortId", skip_serializing_if = "String::is_empty")]
    pub short_id: String,

    /// TLS fingerprint to mimic.
    #[serde(default = "default_fingerprint")]
    pub fingerprint: String,

    /// Server name (SNI) to use in the ClientHello.
    #[serde(
        default,
        rename = "serverName",
        skip_serializing_if = "String::is_empty"
    )]
    pub server_name: String,

    /// Maximum allowed time difference in seconds.
    #[serde(default = "default_max_time_diff", rename = "maxTimeDiff")]
    pub max_time_diff: u64,
}

fn default_fingerprint() -> String {
    "chrome".to_string()
}
fn default_max_time_diff() -> u64 {
    60
}

/// WebSocket transport settings.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WsConfig {
    /// HTTP path for the WebSocket upgrade request.
    #[serde(default = "default_ws_path")]
    pub path: String,

    /// Additional HTTP headers for the upgrade request.
    #[serde(default)]
    pub headers: std::collections::HashMap<String, String>,
}

fn default_ws_path() -> String {
    "/".to_string()
}

/// gRPC transport settings.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GrpcConfig {
    /// gRPC service name.
    #[serde(default = "default_grpc_service", rename = "serviceName")]
    pub service_name: String,

    /// Whether to open multiple parallel gRPC streams over one HTTP/2 connection.
    #[serde(default, rename = "multiMode")]
    pub multi_mode: bool,
}

fn default_grpc_service() -> String {
    "GunService".to_string()
}

/// Sniffing settings — detect the inner protocol of a connection.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SniffingConfig {
    /// Whether sniffing is enabled.
    pub enabled: bool,

    /// Protocols to sniff for: "http", "tls", or "fakedns".
    #[serde(default, rename = "destOverride")]
    pub dest_override: Vec<String>,
}
