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
mod protocol;
mod routing;
mod transport;

pub use endpoint::{InboundConfig, OutboundConfig};
pub use logging_dns::{DnsConfig, FakeIpConfig, LogConfig};
pub use protocol::{NetworkType, Protocol, SecurityType};
pub use routing::{BalancerConfig, HealthCheckConfig, RoutingConfig, RoutingRule};
pub use transport::{
    GrpcConfig, Hysteria2Config, KcpConfig, RealityConfig, ShadowTlsConfig, SniffingConfig,
    StreamSettingsConfig, TlsConfig, WsConfig,
};

use serde::{Deserialize, Serialize};
use validator::Validate;

/// The top-level configuration object.
///
/// This is what gets deserialised from the JSON config file. Every field is
/// optional except `inbounds` and `outbounds`.
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct Config {
    /// Logging settings.
    #[serde(default)]
    pub log: LogConfig,

    /// DNS resolver settings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<DnsConfig>,

    /// Routing rules for outbound selection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub routing: Option<RoutingConfig>,

    /// Linux TUN interception settings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tun: Option<TunConfig>,

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

/// Top-level Linux TUN interception settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunConfig {
    #[serde(default = "default_tun_name")]
    pub name: String,
    #[serde(default = "default_tun_address")]
    pub address: String,
    #[serde(default = "default_tun_netmask")]
    pub netmask: String,
    #[serde(default = "default_tun_mtu")]
    pub mtu: u16,
    #[serde(default = "default_tun_bypass_mark")]
    pub bypass_mark: u32,
    #[serde(default = "default_tun_redirect_port")]
    pub redirect_port: u16,
    #[serde(default = "default_tun_dns_port")]
    pub dns_port: u16,
}

fn default_tun_name() -> String {
    "proxy-tun".to_string()
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
}
