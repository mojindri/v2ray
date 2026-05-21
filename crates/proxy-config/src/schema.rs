//! Configuration schema — the Rust structs that map to the JSON config file.
//!
//! Every field in the config file corresponds to a field in one of these
//! structs. `serde` handles deserialisation (JSON → Rust structs) and
//! `validator` handles validation (checking that values are in range, required
//! fields are present, etc.).
//!
//! # Adding a new config field
//!
//! 1. Add the field to the appropriate struct below.
//! 2. If the field is required, do not make it `Option<T>`.
//! 3. If the field has constraints (e.g. port must be 1–65535), add a
//!    `#[validate(...)]` attribute.
//! 4. Add a test in the `tests` module at the bottom.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use validator::Validate;

/// The top-level configuration object.
///
/// This is what gets deserialised from the JSON config file.
/// Every field is optional except `inbounds` and `outbounds` — you always
/// need at least one of each to have a working proxy.
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct Config {
    /// Logging settings (log level, output format, file path).
    #[serde(default)]
    pub log: LogConfig,

    /// DNS resolver settings (upstream servers, FakeIP range, etc.).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<DnsConfig>,

    /// Routing rules: which connections go through which outbound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub routing: Option<RoutingConfig>,

    /// List of inbound handlers — the ports and protocols the proxy listens on.
    /// At least one inbound is required.
    #[validate(length(min = 1, message = "at least one inbound is required"), nested)]
    pub inbounds: Vec<InboundConfig>,

    /// List of outbound handlers — the protocols used to forward traffic.
    /// At least one outbound is required.
    #[validate(length(min = 1, message = "at least one outbound is required"), nested)]
    pub outbounds: Vec<OutboundConfig>,

    /// Statistics collection settings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stats: Option<serde_json::Value>,

    /// Management API settings (the gRPC stats API).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api: Option<serde_json::Value>,
}

/// Log level and output settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LogConfig {
    /// How verbose the logs should be.
    /// Options: "debug", "info", "warn", "error". Default: "info".
    pub level: String,

    /// Whether to output logs as JSON (true) or human-readable text (false).
    /// JSON is better for log aggregation (e.g. sending to Elasticsearch).
    /// Human-readable is better for reading in a terminal.
    pub json: bool,

    /// Optional file path to write logs to. If empty, logs go to stderr.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub file: String,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            json: false,
            file: String::new(),
        }
    }
}

/// DNS resolver configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DnsConfig {
    /// Upstream DNS servers. Each entry is a URL like:
    ///   - "udp://8.8.8.8:53"  — plain DNS over UDP
    ///   - "tls://1.1.1.1:853" — DNS over TLS
    ///   - "https://1.1.1.1/dns-query" — DNS over HTTPS
    #[serde(default)]
    pub servers: Vec<String>,

    /// FakeIP settings. When enabled, domain names get assigned fake IP
    /// addresses from a private range so the proxy can intercept them
    /// before they reach the OS resolver.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fake_ip: Option<FakeIpConfig>,
}

/// FakeIP settings: assign fake IPs to domain names for TUN mode interception.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FakeIpConfig {
    /// Whether FakeIP mode is enabled.
    pub enabled: bool,

    /// The IP range to allocate fake IPs from.
    /// Default: "198.18.0.0/15" (RFC 2544 benchmarking range — safe to use).
    #[serde(default = "default_fake_ip_range")]
    pub pool: String,
}

fn default_fake_ip_range() -> String {
    "198.18.0.0/15".to_string()
}

/// Routing configuration: rules for deciding which outbound to use.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RoutingConfig {
    /// The outbound tag to use when no rule matches.
    /// If not set, the first outbound in the list is used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain_strategy: Option<String>,

    /// The routing rules, evaluated in order. First match wins.
    #[serde(default)]
    pub rules: Vec<RoutingRule>,

    /// Load-balancer configurations.
    #[serde(default)]
    pub balancers: Vec<BalancerConfig>,
}

/// A single routing rule.
///
/// A rule matches a connection if ALL specified conditions are true:
///   - `domain` matches (if present)
///   - `ip` matches (if present)
///   - `port` matches (if present)
///   - `inbound_tag` matches (if present)
///
/// When a rule matches, the connection is forwarded to `outbound_tag`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RoutingRule {
    /// The rule type. Always "field" in the current implementation.
    #[serde(rename = "type", default = "default_rule_type")]
    pub rule_type: String,

    /// Domain matching patterns. Each entry can be:
    ///   - "domain:example.com" — exact match
    ///   - "suffix:example.com" — matches example.com and any subdomain
    ///   - "keyword:vpn"        — matches any domain containing "vpn"
    ///   - "regexp:.*\\.google\\..*" — regular expression
    ///   - "geosite:CN"         — all domains in the China GeoSite list
    #[serde(default)]
    pub domain: Vec<String>,

    /// IP matching patterns. Each entry can be:
    ///   - "1.2.3.4/24"     — CIDR range
    ///   - "geoip:CN"       — all IPs in the China GeoIP list
    #[serde(default)]
    pub ip: Vec<String>,

    /// Port matching. Examples: "443", "80,443", "8000-9000".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<String>,

    /// Only apply this rule to connections arriving on this inbound tag.
    #[serde(default, rename = "inboundTag", skip_serializing_if = "Vec::is_empty")]
    pub inbound_tag: Vec<String>,

    /// The outbound tag to use when this rule matches.
    #[serde(rename = "outboundTag")]
    pub outbound_tag: String,
}

fn default_rule_type() -> String {
    "field".to_string()
}

/// Load balancer configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalancerConfig {
    /// Unique name for this balancer. Referenced by routing rules.
    pub tag: String,

    /// The outbound tags this balancer distributes traffic across.
    pub selector: Vec<String>,

    /// How to choose between outbounds: "random", "roundRobin", or "latency".
    #[serde(default = "default_balancer_strategy")]
    pub strategy: String,

    /// Health check settings for this balancer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health_check: Option<HealthCheckConfig>,
}

fn default_balancer_strategy() -> String {
    "latency".to_string()
}

/// Health check configuration for a load balancer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckConfig {
    /// URL to check — the proxy connects through the outbound and fetches this URL.
    /// A 204 response means the outbound is healthy.
    #[serde(default = "default_health_check_url")]
    pub url: String,

    /// How often to run health checks, in seconds.
    #[serde(default = "default_health_check_interval")]
    pub interval_secs: u64,

    /// How long to wait for a response before considering the check failed, in seconds.
    #[serde(default = "default_health_check_timeout")]
    pub timeout_secs: u64,

    /// How many consecutive failures before marking the outbound as dead.
    #[serde(default = "default_max_failures")]
    pub max_failures: u32,
}

fn default_health_check_url() -> String {
    "http://www.gstatic.com/generate_204".to_string()
}
fn default_health_check_interval() -> u64 { 30 }
fn default_health_check_timeout() -> u64 { 5 }
fn default_max_failures() -> u32 { 3 }

/// An inbound handler: a port and protocol the proxy listens on.
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct InboundConfig {
    /// A unique name for this inbound, used in routing rules and logs.
    pub tag: String,

    /// The proxy protocol: "socks", "http", "vless", "vmess", "trojan", etc.
    pub protocol: Protocol,

    /// The IP address to listen on.
    /// "0.0.0.0" means listen on all interfaces (accessible from the network).
    /// "127.0.0.1" means listen only on localhost (not accessible from outside).
    pub listen: IpAddr,

    /// The port to listen on. Must be between 1 and 65535.
    #[validate(range(min = 1, max = 65535))]
    pub port: u16,

    /// Protocol-specific settings. The shape depends on `protocol`.
    /// For example, for "vless" this holds the user list.
    #[serde(default)]
    pub settings: serde_json::Value,

    /// Transport settings: whether to wrap the connection in TLS, WebSocket, etc.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_settings: Option<StreamSettingsConfig>,

    /// Sniffing settings: detect the inner protocol of a connection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sniffing: Option<SniffingConfig>,
}

/// An outbound handler: a protocol used to forward traffic to the destination.
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct OutboundConfig {
    /// A unique name for this outbound, referenced by routing rules.
    pub tag: String,

    /// The proxy protocol: "freedom", "vless", "vmess", "trojan", "shadowsocks", etc.
    pub protocol: Protocol,

    /// Protocol-specific settings (server address, user credentials, etc.).
    #[serde(default)]
    pub settings: serde_json::Value,

    /// Transport settings: TLS, WebSocket, REALITY, etc.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_settings: Option<StreamSettingsConfig>,
}

/// Transport layer settings: how to wrap or protect the connection.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StreamSettingsConfig {
    /// Which transport to use: "tcp", "ws", "grpc", "quic", "kcp", "splithttp".
    #[serde(default)]
    pub network: NetworkType,

    /// Whether to use TLS, REALITY, or no encryption.
    #[serde(default)]
    pub security: SecurityType,

    /// TLS-specific settings (certificate, SNI, ALPN, etc.).
    #[serde(default, rename = "tlsSettings", skip_serializing_if = "Option::is_none")]
    pub tls_settings: Option<TlsConfig>,

    /// REALITY-specific settings (server public key, short ID, fingerprint, etc.).
    #[serde(default, rename = "realitySettings", skip_serializing_if = "Option::is_none")]
    pub reality_settings: Option<RealityConfig>,

    /// WebSocket-specific settings (path, headers).
    #[serde(default, rename = "wsSettings", skip_serializing_if = "Option::is_none")]
    pub ws_settings: Option<WsConfig>,

    /// gRPC-specific settings (service name, multiMode).
    #[serde(default, rename = "grpcSettings", skip_serializing_if = "Option::is_none")]
    pub grpc_settings: Option<GrpcConfig>,
}

/// TLS configuration (used when security = "tls").
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TlsConfig {
    /// The server name (SNI) to present during the TLS handshake.
    #[serde(default, rename = "serverName", skip_serializing_if = "String::is_empty")]
    pub server_name: String,

    /// Whether to skip certificate verification.
    /// ONLY set to true in development — never in production.
    #[serde(default, rename = "allowInsecure")]
    pub allow_insecure: bool,

    /// ALPN protocols to offer during the TLS handshake.
    /// Typical values: ["h2", "http/1.1"].
    #[serde(default)]
    pub alpn: Vec<String>,

    /// Path to the TLS certificate file (PEM format). Server-side only.
    #[serde(default, rename = "certificateFile", skip_serializing_if = "String::is_empty")]
    pub certificate_file: String,

    /// Path to the TLS private key file (PEM format). Server-side only.
    #[serde(default, rename = "keyFile", skip_serializing_if = "String::is_empty")]
    pub key_file: String,
}

/// REALITY configuration — the advanced TLS-camouflage protocol.
///
/// REALITY makes the server look like a legitimate TLS site to censors,
/// while still allowing authenticated clients to use it as a proxy.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RealityConfig {
    // ── Server-side settings ────────────────────────────────────────────────
    /// Whether this is a server config (true) or client config (false).
    #[serde(default)]
    pub show: bool,

    /// The real destination to proxy to when a client fails authentication.
    /// Should be a well-known HTTPS site with TLS 1.3 and X25519 key exchange,
    /// e.g. "www.microsoft.com:443". Connections from probers will be forwarded
    /// to this site, making the server look like a real HTTPS server.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub dest: String,

    /// The server's X25519 private key (base64 encoded). Server-side only.
    /// Generate with: proxy-rs x25519
    #[serde(default, rename = "privateKey", skip_serializing_if = "String::is_empty")]
    pub private_key: String,

    /// Short IDs that clients must use to authenticate.
    /// Each is an 8-byte hex string (16 hex characters).
    /// Multiple clients can share the same server but use different short IDs.
    #[serde(default, rename = "shortIds")]
    pub short_ids: Vec<String>,

    // ── Client-side settings ────────────────────────────────────────────────
    /// The server's X25519 public key (base64 encoded). Client-side only.
    /// Provided by the server operator.
    #[serde(default, rename = "publicKey", skip_serializing_if = "String::is_empty")]
    pub public_key: String,

    /// The short ID this client will use. Must match one of the server's shortIds.
    #[serde(default, rename = "shortId", skip_serializing_if = "String::is_empty")]
    pub short_id: String,

    /// The TLS fingerprint to mimic. "chrome" means Chrome 131.
    /// This makes the connection look like a real Chrome browser to DPI systems.
    #[serde(default = "default_fingerprint")]
    pub fingerprint: String,

    /// The server name (SNI) to use in the ClientHello.
    /// Must match the dest server's certificate.
    #[serde(default, rename = "serverName", skip_serializing_if = "String::is_empty")]
    pub server_name: String,

    /// Maximum allowed time difference (in seconds) between client and server clocks.
    /// If clocks differ by more than this, authentication fails.
    #[serde(default = "default_max_time_diff", rename = "maxTimeDiff")]
    pub max_time_diff: u64,
}

fn default_fingerprint() -> String { "chrome".to_string() }
fn default_max_time_diff() -> u64 { 60 }

/// WebSocket transport settings.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WsConfig {
    /// The HTTP path for the WebSocket upgrade request. Default: "/".
    #[serde(default = "default_ws_path")]
    pub path: String,

    /// Additional HTTP headers to include in the upgrade request.
    /// Common use: set "Host" to a CDN domain for domain fronting.
    #[serde(default)]
    pub headers: std::collections::HashMap<String, String>,
}

fn default_ws_path() -> String { "/".to_string() }

/// gRPC transport settings.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GrpcConfig {
    /// The gRPC service name. Default: "GunService".
    #[serde(default = "default_grpc_service", rename = "serviceName")]
    pub service_name: String,

    /// Whether to open multiple parallel gRPC streams over one HTTP/2 connection.
    /// Helps avoid per-stream flow-control bottlenecks on high-latency links.
    #[serde(default, rename = "multiMode")]
    pub multi_mode: bool,
}

fn default_grpc_service() -> String { "GunService".to_string() }

/// Sniffing settings — detect the inner protocol of a connection.
///
/// When enabled, the proxy inspects the first bytes of each connection to
/// determine whether it is HTTP, TLS (HTTPS), or BitTorrent. This allows
/// routing rules to use the detected protocol as a condition.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SniffingConfig {
    /// Whether sniffing is enabled.
    pub enabled: bool,

    /// Which protocols to sniff for.
    /// Options: "http", "tls", "fakedns".
    #[serde(default, rename = "destOverride")]
    pub dest_override: Vec<String>,
}

/// Proxy protocol identifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    /// VLESS — lightweight, authentication via UUID. Priority 0.
    Vless,
    /// VMess — older protocol with AEAD encryption. Legacy compatibility.
    Vmess,
    /// Trojan — disguises traffic as HTTPS. Legacy compatibility.
    Trojan,
    /// Shadowsocks-2022 — Iran mobile fallback.
    #[serde(rename = "shadowsocks")]
    Shadowsocks,
    /// Hysteria2 — QUIC-based, for high-latency/lossy links (China).
    Hysteria2,
    /// ShadowTLS — wraps another protocol inside a real TLS handshake (Iran).
    ShadowTls,
    /// SOCKS5 — standard local proxy protocol. Used as the inbound for clients.
    Socks,
    /// HTTP CONNECT proxy. Used as the inbound for HTTP clients.
    Http,
    /// Freedom — direct connection to the destination, no proxy protocol.
    Freedom,
}

/// Which transport wrapping to use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum NetworkType {
    /// Raw TCP — no framing, bytes sent as-is.
    #[default]
    Tcp,
    /// WebSocket — TCP connection upgraded to WebSocket protocol.
    Ws,
    /// gRPC — HTTP/2-based remote procedure call framing.
    Grpc,
    /// QUIC — UDP-based transport with built-in encryption and reliability.
    Quic,
    /// mKCP — KCP ARQ protocol over UDP for lossy links.
    Kcp,
    /// SplitHTTP (XHTTP) — uses HTTP GET for download and POST for upload.
    #[serde(rename = "splithttp")]
    SplitHttp,
}

/// Which security layer to apply on top of the transport.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SecurityType {
    /// No encryption — bytes sent in plaintext. Only safe for localhost.
    #[default]
    None,
    /// Standard TLS using a real certificate.
    Tls,
    /// REALITY — TLS camouflage against a real destination site.
    Reality,
}

#[cfg(test)]
mod tests {
    use super::*;

    // Checks that a minimal valid config deserialises without errors.
    #[test]
    fn minimal_config_deserialises() {
        let json = r#"{
            "inbounds": [{
                "tag": "socks",
                "protocol": "socks",
                "listen": "127.0.0.1",
                "port": 1080
            }],
            "outbounds": [{
                "tag": "direct",
                "protocol": "freedom"
            }]
        }"#;

        let cfg: Config = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.inbounds.len(), 1);
        assert_eq!(cfg.outbounds.len(), 1);
        assert_eq!(cfg.inbounds[0].tag, "socks");
        assert_eq!(cfg.outbounds[0].tag, "direct");
    }

    // Checks that a config with an invalid port number fails validation.
    #[test]
    fn invalid_port_fails_validation() {
        let json = r#"{
            "inbounds": [{
                "tag": "bad",
                "protocol": "socks",
                "listen": "127.0.0.1",
                "port": 0
            }],
            "outbounds": [{"tag": "d", "protocol": "freedom"}]
        }"#;

        let cfg: Config = serde_json::from_str(json).unwrap();
        // Port 0 should fail the range validator.
        assert!(cfg.validate().is_err());
    }

    // Checks that a config with no inbounds fails validation.
    #[test]
    fn empty_inbounds_fails_validation() {
        let json = r#"{
            "inbounds": [],
            "outbounds": [{"tag": "d", "protocol": "freedom"}]
        }"#;

        let cfg: Config = serde_json::from_str(json).unwrap();
        assert!(cfg.validate().is_err());
    }

    // Checks that log defaults are applied when the log section is absent.
    #[test]
    fn log_defaults_applied() {
        let json = r#"{
            "inbounds": [{"tag":"i","protocol":"socks","listen":"127.0.0.1","port":1080}],
            "outbounds": [{"tag":"o","protocol":"freedom"}]
        }"#;
        let cfg: Config = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.log.level, "info");
        assert!(!cfg.log.json);
    }

    // Checks that network and security type deserialise from lowercase strings.
    #[test]
    fn network_and_security_type_deserialise() {
        let json = r#"{"network": "ws", "security": "reality"}"#;
        let s: StreamSettingsConfig = serde_json::from_str(json).unwrap();
        assert_eq!(s.network, NetworkType::Ws);
        assert_eq!(s.security, SecurityType::Reality);
    }
}
