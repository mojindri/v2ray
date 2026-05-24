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

    /// ShadowTLS-specific settings.
    #[serde(
        default,
        rename = "shadowTlsSettings",
        skip_serializing_if = "Option::is_none"
    )]
    pub shadow_tls_settings: Option<ShadowTlsConfig>,

    /// mKCP-specific settings.
    #[serde(
        default,
        rename = "kcpSettings",
        skip_serializing_if = "Option::is_none"
    )]
    pub kcp_settings: Option<KcpConfig>,
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

/// Hysteria2 protocol configuration.
///
/// Hysteria2 uses QUIC with the Brutal congestion controller to achieve high
/// throughput on high-latency, lossy links. This struct is used both for
/// server inbound and client outbound configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Hysteria2Config {
    /// Authentication password (both client and server must use the same value).
    #[serde(default)]
    pub auth: String,

    /// Target upstream bandwidth in Mbps (client → server direction).
    ///
    /// Used to tune the Brutal CC window size. Higher values allow more in-flight
    /// bytes on high-bandwidth links.
    #[serde(default = "default_mbps", rename = "upMbps")]
    pub up_mbps: u64,

    /// Target downstream bandwidth in Mbps (server → client direction).
    #[serde(default = "default_mbps", rename = "downMbps")]
    pub down_mbps: u64,

    /// Server address for client config (e.g. "example.com:443" or "1.2.3.4:443").
    ///
    /// Not required for server-side config.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub server: String,

    /// Skip TLS certificate verification.
    ///
    /// WARNING: Only use this for development and testing. In production, always
    /// verify the server certificate to prevent man-in-the-middle attacks.
    #[serde(default, rename = "skipCertVerify")]
    pub skip_cert_verify: bool,
}

/// Default bandwidth in Mbps when none is specified.
///
/// 100 Mbps is a reasonable default for most modern connections.
fn default_mbps() -> u64 {
    100
}

/// ShadowTLS v3 configuration.
///
/// ShadowTLS wraps a real TLS handshake in front of another proxy protocol so
/// that it looks like a legitimate HTTPS connection to an external observer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowTlsConfig {
    /// Pre-shared key (password) used to derive the HMAC marker.
    pub password: String,

    /// Real TLS backend the server relays the handshake to, e.g. `"www.apple.com:443"`.
    pub dest: String,

    /// Protocol version. This implementation only supports version 3.
    #[serde(default = "default_shadowtls_version")]
    pub version: u8,
}

fn default_shadowtls_version() -> u8 {
    3
}

/// mKCP transport settings (UDP-based reliable stream).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KcpConfig {
    /// Packet obfuscation header type (`"none"`, `"srtp"`, `"wechat-video"`, etc.).
    #[serde(default = "default_kcp_header")]
    pub header: String,
    /// Maximum transmission unit for KCP segments.
    #[serde(default = "default_kcp_mtu")]
    pub mtu: u16,
    /// Transmission time interval in milliseconds (how often KCP flushes).
    #[serde(default = "default_kcp_tti")]
    pub tti: u64,
    /// Declared uplink capacity in MB/s (used for window sizing).
    #[serde(default = "default_kcp_capacity")]
    pub uplink_capacity: u32,
    /// Declared downlink capacity in MB/s (used for window sizing).
    #[serde(default = "default_kcp_capacity")]
    pub downlink_capacity: u32,
    /// Enable KCP congestion control (usually `false` for proxy workloads).
    #[serde(default)]
    pub congestion: bool,
    /// KCP receive window size in packets.
    #[serde(default = "default_kcp_buf")]
    pub read_buffer_size: u32,
    /// KCP send window size in packets.
    #[serde(default = "default_kcp_buf")]
    pub write_buffer_size: u32,
}
fn default_kcp_header() -> String {
    "none".into()
}
fn default_kcp_mtu() -> u16 {
    1350
}
fn default_kcp_tti() -> u64 {
    50
}
fn default_kcp_capacity() -> u32 {
    5
}
fn default_kcp_buf() -> u32 {
    2
}
