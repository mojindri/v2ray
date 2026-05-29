//! Configuration schema — Rust structs that map to the JSON config file.
//!
//! The schema is split by responsibility so each file stays small:
//! - `logging_dns` handles logging and DNS/FakeIP settings.
//! - `routing` handles route rules and load balancers.
//! - `endpoint` handles inbound and outbound entries.
//! - `transport` handles TCP/TLS/REALITY/WebSocket/gRPC wrappers.
//! - `protocol` holds shared protocol enums.

mod endpoint;
mod logging_dns;
mod profile;
mod protocol;
mod routing;
mod transport;

pub use endpoint::{InboundConfig, InboundLimitsConfig, OutboundConfig};
pub use logging_dns::{DnsConfig, FakeIpConfig, LogConfig};
pub use profile::{
    validate_fast_profile, FastConfig, FastPoolPolicy, FastSplicePolicy, ProfileMode,
    ProfileViolation,
};
pub use protocol::{NetworkType, Protocol, SecurityType};
pub use routing::{BalancerConfig, HealthCheckConfig, RoutingConfig, RoutingRule};
pub use transport::{
    GrpcConfig, Hysteria2Config, KcpConfig, RealityConfig, ShadowTlsConfig, SniffingConfig,
    SplitHttpConfig, StreamSettingsConfig, TlsConfig, WsConfig,
};

use serde::{Deserialize, Serialize};
use validator::Validate;

/// The top-level configuration object.
///
/// This is what gets deserialised from the JSON config file. Every field is
/// optional except `inbounds` and `outbounds`.
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct Config {
    /// Operating profile. `"compat"` (default) enables all features.
    /// `"fast"` enforces a strict latency-first subset.
    #[serde(default)]
    pub profile: ProfileMode,

    /// Extra settings that apply only when `profile = "fast"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fast: Option<FastConfig>,

    /// Logging settings.
    #[serde(default)]
    pub log: LogConfig,

    /// DNS resolver settings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<DnsConfig>,

    /// Routing rules for outbound selection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub routing: Option<RoutingConfig>,

    /// TUN interception settings.
    ///
    /// Linux and macOS have active full-device runtimes today. Windows Wintun
    /// device creation and split-route setup are wired, and Windows can point
    /// at an explicit `wintun.dll`, but full runtime startup fails early until
    /// a native TCP redirection backend is implemented.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tun: Option<TunConfig>,

    /// Runtime safety limits.
    #[serde(default)]
    pub limits: LimitsConfig,

    /// Ports and protocols the proxy listens on.
    #[validate(length(min = 1, message = "at least one inbound is required"), nested)]
    pub inbounds: Vec<InboundConfig>,

    /// Protocols used to forward traffic.
    #[validate(length(min = 1, message = "at least one outbound is required"), nested)]
    pub outbounds: Vec<OutboundConfig>,

    /// Statistics collection settings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stats: Option<serde_json::Value>,

    /// Management API settings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api: Option<serde_json::Value>,

    /// Metrics/health HTTP server listen address, e.g. `"127.0.0.1:8080"`.
    ///
    /// When set, the proxy starts a Prometheus metrics endpoint at this address.
    #[serde(
        default,
        rename = "metricsAddr",
        alias = "metrics_addr",
        skip_serializing_if = "Option::is_none"
    )]
    pub metrics_addr: Option<String>,
}

/// Runtime safety limits.
///
/// These are intentionally conservative knobs for production hardening.
/// `max_connections` is currently applied per TCP listener unless a more
/// specific inbound limit is set. Global cross-listener accounting can be
/// added later without changing the config shape.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LimitsConfig {
    /// Maximum concurrent connections for the whole process (optional).
    /// Applied per TCP listener unless overridden by per-inbound limits.
    #[serde(
        default,
        rename = "maxConnections",
        alias = "max_connections",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_connections: Option<usize>,

    /// Default per-inbound connection cap when an inbound has no own `limits` block.
    #[serde(
        default,
        rename = "maxConnectionsPerInbound",
        alias = "max_connections_per_inbound",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_connections_per_inbound: Option<usize>,

    /// Wall-clock limit for inbound **handshake only** (REALITY/TLS/VLESS header).
    /// Does not cut off an established relay. Omitted = no limit.
    #[serde(
        default,
        rename = "maxHandshakeSeconds",
        alias = "max_handshake_seconds",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_handshake_seconds: Option<u64>,

    /// Close idle connections after this many seconds (reserved; not wired yet).
    #[serde(
        default,
        rename = "maxIdleSeconds",
        alias = "max_idle_seconds",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_idle_seconds: Option<u64>,
}

/// Top-level TUN interception settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunConfig {
    /// TUN interface name (e.g. `"tun0"`).
    #[serde(default = "default_tun_name")]
    pub name: String,
    /// IPv4 address assigned to the TUN device.
    #[serde(default = "default_tun_address")]
    pub address: String,
    /// Netmask for the TUN IPv4 network.
    #[serde(default = "default_tun_netmask")]
    pub netmask: String,
    /// MTU for the TUN interface.
    #[serde(default = "default_tun_mtu")]
    pub mtu: u16,
    /// iptables/nftables mark for packets that should bypass the TUN path.
    #[serde(default = "default_tun_bypass_mark")]
    pub bypass_mark: u32,
    /// macOS-only physical interface used by protected outbound sockets.
    ///
    /// Example: `"en0"`. When unset, macOS full-device TUN remains gated to
    /// avoid routing Blackwire's own outbound sockets back into utun.
    #[serde(
        default,
        rename = "outboundInterface",
        alias = "outbound_interface",
        skip_serializing_if = "Option::is_none"
    )]
    pub outbound_interface: Option<String>,
    /// Local port where redirected TCP connections are accepted.
    #[serde(default = "default_tun_redirect_port")]
    pub redirect_port: u16,
    /// Local DNS port used by the transparent-proxy DNS path.
    #[serde(default = "default_tun_dns_port")]
    pub dns_port: u16,
    /// Windows-only path to `wintun.dll`.
    ///
    /// When unset, the Windows backend uses the `tun` crate default
    /// (`wintun.dll` in the process DLL search path).
    #[serde(
        default,
        rename = "wintunFile",
        alias = "wintun_file",
        skip_serializing_if = "Option::is_none"
    )]
    pub wintun_file: Option<String>,
}

fn default_tun_name() -> String {
    "blackwire-tun".to_string()
}

fn default_tun_address() -> String {
    "198.18.0.1".to_string()
}

fn default_tun_netmask() -> String {
    "255.255.0.0".to_string()
}

fn default_tun_mtu() -> u16 {
    1500
}

fn default_tun_bypass_mark() -> u32 {
    0x1234
}

fn default_tun_redirect_port() -> u16 {
    7890
}

fn default_tun_dns_port() -> u16 {
    5300
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mkcp_header_accepts_xray_object_form() {
        let json = r#"{
            "header": { "type": "none" },
            "tti": 10
        }"#;
        let kcp: super::transport::KcpConfig = serde_json::from_str(json).unwrap();
        assert_eq!(kcp.header, "none");
    }

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

    #[test]
    fn tun_platform_fields_accept_camel_and_snake_case() {
        let camel: TunConfig = serde_json::from_str(
            r#"{
                "outboundInterface": "en0",
                "wintunFile": "C:\\Program Files\\Blackwire\\wintun.dll"
            }"#,
        )
        .unwrap();
        assert_eq!(camel.outbound_interface.as_deref(), Some("en0"));
        assert_eq!(
            camel.wintun_file.as_deref(),
            Some(r#"C:\Program Files\Blackwire\wintun.dll"#)
        );

        let snake: TunConfig = serde_json::from_str(
            r#"{
                "outbound_interface": "Ethernet",
                "wintun_file": ".\\wintun.dll"
            }"#,
        )
        .unwrap();
        assert_eq!(snake.outbound_interface.as_deref(), Some("Ethernet"));
        assert_eq!(snake.wintun_file.as_deref(), Some(r#".\wintun.dll"#));
    }

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
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn empty_inbounds_fails_validation() {
        let json = r#"{
            "inbounds": [],
            "outbounds": [{"tag": "d", "protocol": "freedom"}]
        }"#;

        let cfg: Config = serde_json::from_str(json).unwrap();
        assert!(cfg.validate().is_err());
    }

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

    #[test]
    fn network_and_security_type_deserialise() {
        let json = r#"{"network": "ws", "security": "reality"}"#;
        let s: StreamSettingsConfig = serde_json::from_str(json).unwrap();
        assert_eq!(s.network, NetworkType::Ws);
        assert_eq!(s.security, SecurityType::Reality);
    }

    #[test]
    fn splithttp_xhttp_extras_deserialise() {
        let json = r#"{
            "network": "splithttp",
            "splithttpSettings": {
                "path": "/split",
                "mode": "packet-up",
                "xPaddingBytes": "16-32",
                "xPaddingMethod": "repeat-x",
                "xPaddingHeader": "X-Test-Padding",
                "scMaxBufferedPosts": 12,
                "xmux": { "maxConcurrency": 4 },
                "downloadSettings": { "network": "tcp" }
            }
        }"#;
        let s: StreamSettingsConfig = serde_json::from_str(json).unwrap();
        let cfg = s.splithttp_settings.expect("splithttp settings");
        assert_eq!(cfg.mode, "packet-up");
        assert_eq!(cfg.x_padding_method, "repeat-x");
        assert_eq!(cfg.x_padding_header, "X-Test-Padding");
        assert_eq!(cfg.sc_max_buffered_posts, 12);
        assert!(cfg.xmux.is_some());
        assert!(cfg.download_settings.is_some());
    }

    /// `protocol: shadowtls` on an inbound must be rejected with a clear error
    /// pointing users to `security: shadowtls` instead.
    #[test]
    fn shadowtls_as_inbound_protocol_is_rejected() {
        let json = r#"{
            "inbounds": [{
                "tag": "bad",
                "protocol": "shadowtls",
                "listen": "127.0.0.1",
                "port": 8443
            }],
            "outbounds": [{"tag": "d", "protocol": "freedom"}]
        }"#;
        let cfg: Config = serde_json::from_str(json).unwrap();
        let err = cfg
            .validate()
            .expect_err("shadowtls inbound should fail validation");
        let msg = err.to_string();
        assert!(
            msg.contains("shadowtls") || msg.contains("streamSettings"),
            "expected a message referencing shadowtls or streamSettings, got: {msg}"
        );
    }

    /// `protocol: shadowtls` on an outbound must be rejected with a clear error.
    #[test]
    fn shadowtls_as_outbound_protocol_is_rejected() {
        let json = r#"{
            "inbounds": [{
                "tag": "socks",
                "protocol": "socks",
                "listen": "127.0.0.1",
                "port": 1080
            }],
            "outbounds": [{"tag": "bad", "protocol": "shadowtls"}]
        }"#;
        let cfg: Config = serde_json::from_str(json).unwrap();
        let err = cfg
            .validate()
            .expect_err("shadowtls outbound should fail validation");
        let msg = err.to_string();
        assert!(
            msg.contains("shadowtls") || msg.contains("streamSettings"),
            "expected a message referencing shadowtls or streamSettings, got: {msg}"
        );
    }
}
