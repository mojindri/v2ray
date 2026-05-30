use serde::{Deserialize, Serialize};

use super::{Config, NetworkType, Protocol, SecurityType};

/// Operating profile for the proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProfileMode {
    /// Broad compatibility mode: all protocols, transports, and features enabled.
    /// The default — prioritises interoperability with Xray / sing-box configs.
    #[default]
    Compat,
    /// Latency-first production path: narrow protocol/transport matrix, strict
    /// defaults, and active rejection of features that add per-connection overhead.
    Fast,
}

impl std::fmt::Display for ProfileMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProfileMode::Compat => f.write_str("compat"),
            ProfileMode::Fast => f.write_str("fast"),
        }
    }
}

impl std::str::FromStr for ProfileMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "compat" => Ok(ProfileMode::Compat),
            "fast" => Ok(ProfileMode::Fast),
            other => Err(format!(
                "unknown profile '{other}'; expected 'compat' or 'fast'"
            )),
        }
    }
}

/// Extra settings that only apply when `profile = "fast"`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FastConfig {
    /// Reject `security = none` when `true` (default). Set `false` only in lab /
    /// benchmark environments where unencrypted VLESS TCP is acceptable.
    #[serde(default = "FastConfig::default_strict_production")]
    pub strict_production: bool,

    /// TCP preconnect pooling policy for Freedom outbounds.
    ///
    /// `disabled` avoids preconnect pooling entirely. `adaptive` starts
    /// conservative and enables pooling only for hot destinations. `fixed`
    /// keeps legacy numeric `poolSize` behavior for lab/debug configs.
    #[serde(default)]
    pub pool: FastPoolPolicy,

    /// Raw TCP relay policy. `adaptive` currently means "use splice when both
    /// streams are raw TCP and record the decision"; policy hooks are kept here
    /// so future payload-aware thresholds do not change config shape.
    #[serde(default)]
    pub splice: FastSplicePolicy,
}

impl FastConfig {
    fn default_strict_production() -> bool {
        true
    }
}

impl Default for FastConfig {
    fn default() -> Self {
        Self {
            strict_production: true,
            pool: FastPoolPolicy::default(),
            splice: FastSplicePolicy::default(),
        }
    }
}

/// TCP connection pool strategy for the Fast Profile outbound.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FastPoolPolicy {
    /// Ramp pool size based on destination hotness.
    Adaptive,
    /// Disable pooling entirely (default).
    #[default]
    Disabled,
    /// Use a fixed pool size set by `poolSize`.
    Fixed,
}

/// Splice relay strategy for the Fast Profile dispatcher.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FastSplicePolicy {
    /// Use splice only after `ADAPTIVE_SPLICE_MIN_BYTES` have been relayed (default).
    #[default]
    Adaptive,
    /// Never use splice; always use `copy_bidirectional`.
    Disabled,
    /// Always use splice for eligible (raw TCP) streams.
    Always,
}

/// A validation finding returned by [`validate_fast_profile`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileViolation {
    /// Hard error — this configuration cannot run under Fast Profile.
    Error(String),
    /// Warning — configuration will work but may hurt the latency story.
    Warning(String),
}

impl ProfileViolation {
    /// Returns `true` if this is a hard error that should abort startup.
    pub fn is_error(&self) -> bool {
        matches!(self, ProfileViolation::Error(_))
    }

    /// The human-readable violation message, without the severity prefix.
    pub fn message(&self) -> &str {
        match self {
            ProfileViolation::Error(m) | ProfileViolation::Warning(m) => m,
        }
    }
}

impl std::fmt::Display for ProfileViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProfileViolation::Error(m) => write!(f, "error: {m}"),
            ProfileViolation::Warning(m) => write!(f, "warning: {m}"),
        }
    }
}

fn protocol_name(p: &Protocol) -> &'static str {
    match p {
        Protocol::Vless => "vless",
        Protocol::Vmess => "vmess",
        Protocol::Trojan => "trojan",
        Protocol::Shadowsocks => "shadowsocks",
        Protocol::Hysteria2 => "hysteria2",
        Protocol::ShadowTls => "shadowtls",
        Protocol::Socks => "socks",
        Protocol::Http => "http",
        Protocol::Freedom => "freedom",
    }
}

fn network_name(n: &NetworkType) -> &'static str {
    match n {
        NetworkType::Tcp => "tcp",
        NetworkType::Ws => "ws",
        NetworkType::HttpUpgrade => "httpupgrade",
        NetworkType::Grpc => "grpc",
        NetworkType::Quic => "quic",
        NetworkType::Kcp => "kcp",
        NetworkType::SplitHttp => "splithttp",
    }
}

/// Validate `config` against Fast Profile constraints.
///
/// Returns an empty `Vec` when `config.profile` is `Compat` — no restrictions
/// apply. When `Fast`, returns a list of findings:
/// - [`ProfileViolation::Error`] — the config must not start; caller should abort.
/// - [`ProfileViolation::Warning`] — caller should print and continue.
pub fn validate_fast_profile(config: &Config) -> Vec<ProfileViolation> {
    if config.profile != ProfileMode::Fast {
        return vec![];
    }

    let strict = config
        .fast
        .as_ref()
        .map(|f| f.strict_production)
        .unwrap_or(true);

    let mut v: Vec<ProfileViolation> = Vec::new();

    // ── Inbounds ──────────────────────────────────────────────────────────────
    for ib in &config.inbounds {
        if ib.protocol != Protocol::Vless {
            v.push(ProfileViolation::Error(format!(
                "inbound '{}': protocol '{}' is not allowed in Fast Profile (only vless)",
                ib.tag,
                protocol_name(&ib.protocol)
            )));
        }

        match &ib.stream_settings {
            Some(ss) => {
                if ss.network != NetworkType::Tcp {
                    v.push(ProfileViolation::Error(format!(
                        "inbound '{}': network='{}' is not allowed in Fast Profile (only tcp)",
                        ib.tag,
                        network_name(&ss.network)
                    )));
                }

                if ss.security == SecurityType::None {
                    let msg = format!(
                        "inbound '{}': security=none; use reality or tls in Fast Profile",
                        ib.tag
                    );
                    if strict {
                        v.push(ProfileViolation::Error(msg));
                    } else {
                        v.push(ProfileViolation::Warning(msg));
                    }
                }
            }
            None => {
                // Absent streamSettings implies no TLS/REALITY (security=none).
                let msg = format!(
                    "inbound '{}': no streamSettings (security=none); use reality or tls in Fast Profile",
                    ib.tag
                );
                if strict {
                    v.push(ProfileViolation::Error(msg));
                } else {
                    v.push(ProfileViolation::Warning(msg));
                }
            }
        }

        if ib.sniffing.as_ref().is_some_and(|s| s.enabled) {
            v.push(ProfileViolation::Error(format!(
                "inbound '{}': sniffing=true is not allowed in Fast Profile (adds per-connection overhead)",
                ib.tag
            )));
        }
    }

    // ── Outbounds ─────────────────────────────────────────────────────────────
    for ob in &config.outbounds {
        if ob.protocol != Protocol::Vless && ob.protocol != Protocol::Freedom {
            v.push(ProfileViolation::Error(format!(
                "outbound '{}': protocol '{}' is not allowed in Fast Profile (only vless, freedom)",
                ob.tag,
                protocol_name(&ob.protocol)
            )));
        }
    }

    // ── DNS ───────────────────────────────────────────────────────────────────
    if config
        .dns
        .as_ref()
        .and_then(|d| d.fake_ip.as_ref())
        .is_some_and(|f| f.enabled)
    {
        v.push(ProfileViolation::Error(
            "dns.fakeIp=true is not allowed in Fast Profile (adds per-query overhead)".into(),
        ));
    }

    // ── Routing ───────────────────────────────────────────────────────────────
    if let Some(routing) = &config.routing {
        if routing
            .domain_strategy
            .as_deref()
            .is_some_and(|s| s.eq_ignore_ascii_case("IpOnDemand"))
        {
            v.push(ProfileViolation::Error(
                "routing.domainStrategy=IpOnDemand is not allowed in Fast Profile \
                 (forces a DNS lookup on every connection)"
                    .into(),
            ));
        }

        if routing.rules.len() > 50 {
            v.push(ProfileViolation::Warning(format!(
                "routing has {} rules; large rule sets add routing latency (consider pruning to ≤ 50)",
                routing.rules.len()
            )));
        }

        let geo_count: usize = routing
            .rules
            .iter()
            .flat_map(|r| r.domain.iter().chain(r.ip.iter()))
            .filter(|p| p.starts_with("geosite:") || p.starts_with("geoip:"))
            .count();

        if geo_count > 20 {
            v.push(ProfileViolation::Warning(format!(
                "{geo_count} GeoSite/GeoIP patterns across routing rules; \
                 large geo sets increase per-connection routing time"
            )));
        }
    }

    v
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::*;
    use crate::schema::{
        Config, InboundConfig, LimitsConfig, LogConfig, OutboundConfig, RoutingConfig, RoutingRule,
        SniffingConfig, StreamSettingsConfig,
    };

    fn fast_vless_config() -> Config {
        Config {
            profile: ProfileMode::Fast,
            fast: None,
            log: LogConfig::default(),
            dns: None,
            routing: None,
            tun: None,
            limits: LimitsConfig::default(),
            inbounds: vec![InboundConfig {
                tag: "in-vless".into(),
                listen: "127.0.0.1".parse::<IpAddr>().unwrap(),
                port: 443,
                protocol: Protocol::Vless,
                settings: serde_json::json!({}),
                stream_settings: Some(StreamSettingsConfig {
                    security: SecurityType::Reality,
                    ..Default::default()
                }),
                limits: None,
                sniffing: None,
            }],
            outbounds: vec![OutboundConfig {
                tag: "direct".into(),
                protocol: Protocol::Freedom,
                settings: serde_json::json!({}),
                stream_settings: None,
            }],
            stats: None,
            api: None,
            metrics_addr: None,
        }
    }

    #[test]
    fn compat_profile_skips_all_checks() {
        let mut cfg = fast_vless_config();
        cfg.profile = ProfileMode::Compat;
        // Even a vmess inbound should not trigger any violations in Compat mode.
        cfg.inbounds[0].protocol = Protocol::Vmess;
        assert!(validate_fast_profile(&cfg).is_empty());
    }

    #[test]
    fn valid_fast_profile_has_no_violations() {
        let cfg = fast_vless_config();
        assert!(validate_fast_profile(&cfg).is_empty());
    }

    #[test]
    fn vmess_inbound_is_rejected() {
        let mut cfg = fast_vless_config();
        cfg.inbounds[0].protocol = Protocol::Vmess;
        let violations = validate_fast_profile(&cfg);
        assert!(violations.iter().any(|v| v.is_error()));
        assert!(violations
            .iter()
            .any(|v| v.message().contains("vmess") && v.message().contains("inbound")));
    }

    #[test]
    fn ws_transport_is_rejected() {
        let mut cfg = fast_vless_config();
        cfg.inbounds[0].stream_settings = Some(StreamSettingsConfig {
            network: NetworkType::Ws,
            security: SecurityType::Tls,
            ..Default::default()
        });
        let violations = validate_fast_profile(&cfg);
        assert!(violations
            .iter()
            .any(|v| v.is_error() && v.message().contains("ws")));
    }

    #[test]
    fn security_none_strict_production_is_error() {
        let mut cfg = fast_vless_config();
        cfg.fast = Some(FastConfig {
            strict_production: true,
            ..Default::default()
        });
        cfg.inbounds[0].stream_settings = Some(StreamSettingsConfig {
            security: SecurityType::None,
            ..Default::default()
        });
        let violations = validate_fast_profile(&cfg);
        assert!(violations
            .iter()
            .any(|v| v.is_error() && v.message().contains("security=none")));
    }

    #[test]
    fn security_none_lab_mode_is_warning() {
        let mut cfg = fast_vless_config();
        cfg.fast = Some(FastConfig {
            strict_production: false,
            ..Default::default()
        });
        cfg.inbounds[0].stream_settings = Some(StreamSettingsConfig {
            security: SecurityType::None,
            ..Default::default()
        });
        let violations = validate_fast_profile(&cfg);
        assert!(!violations.iter().any(|v| v.is_error()));
        assert!(violations
            .iter()
            .any(|v| matches!(v, ProfileViolation::Warning(_))
                && v.message().contains("security=none")));
    }

    #[test]
    fn sniffing_enabled_is_rejected() {
        let mut cfg = fast_vless_config();
        cfg.inbounds[0].sniffing = Some(SniffingConfig {
            enabled: true,
            dest_override: vec![],
            metadata_only: false,
            route_only: false,
        });
        let violations = validate_fast_profile(&cfg);
        assert!(violations
            .iter()
            .any(|v| v.is_error() && v.message().contains("sniffing")));
    }

    #[test]
    fn vmess_outbound_is_rejected() {
        let mut cfg = fast_vless_config();
        cfg.outbounds[0].protocol = Protocol::Vmess;
        let violations = validate_fast_profile(&cfg);
        assert!(violations
            .iter()
            .any(|v| v.is_error() && v.message().contains("outbound")));
    }

    #[test]
    fn fake_ip_is_rejected() {
        use crate::schema::{DnsConfig, FakeIpConfig};
        let mut cfg = fast_vless_config();
        cfg.dns = Some(DnsConfig {
            servers: vec![],
            fake_ip: Some(FakeIpConfig {
                enabled: true,
                pool: "198.18.0.0/15".into(),
            }),
        });
        let violations = validate_fast_profile(&cfg);
        assert!(violations
            .iter()
            .any(|v| v.is_error() && v.message().contains("fakeIp")));
    }

    #[test]
    fn ip_on_demand_is_rejected() {
        let mut cfg = fast_vless_config();
        cfg.routing = Some(RoutingConfig {
            domain_strategy: Some("IpOnDemand".into()),
            ..Default::default()
        });
        let violations = validate_fast_profile(&cfg);
        assert!(violations
            .iter()
            .any(|v| v.is_error() && v.message().contains("IpOnDemand")));
    }

    #[test]
    fn large_rule_set_warns() {
        let mut cfg = fast_vless_config();
        let rules: Vec<RoutingRule> = (0..=50)
            .map(|i| RoutingRule {
                outbound_tag: "direct".into(),
                domain: vec![format!("domain:example{i}.com")],
                ..Default::default()
            })
            .collect();
        cfg.routing = Some(RoutingConfig {
            rules,
            ..Default::default()
        });
        let violations = validate_fast_profile(&cfg);
        assert!(violations
            .iter()
            .any(|v| matches!(v, ProfileViolation::Warning(_)) && v.message().contains("rules")));
    }

    #[test]
    fn large_geo_set_warns() {
        let mut cfg = fast_vless_config();
        let rules: Vec<RoutingRule> = (0..=20)
            .map(|i| RoutingRule {
                outbound_tag: "direct".into(),
                ip: vec![format!("geoip:CN{i}")],
                ..Default::default()
            })
            .collect();
        cfg.routing = Some(RoutingConfig {
            rules,
            ..Default::default()
        });
        let violations = validate_fast_profile(&cfg);
        assert!(violations
            .iter()
            .any(|v| matches!(v, ProfileViolation::Warning(_))
                && v.message().contains("GeoSite/GeoIP")));
    }

    #[test]
    fn profile_deserialises_from_json() {
        let json = r#"{"profile": "fast"}"#;
        let m: serde_json::Value = serde_json::from_str(json).unwrap();
        let mode: ProfileMode = serde_json::from_value(m["profile"].clone()).unwrap();
        assert_eq!(mode, ProfileMode::Fast);
    }

    #[test]
    fn profile_defaults_to_compat() {
        let mode = ProfileMode::default();
        assert_eq!(mode, ProfileMode::Compat);
    }
}
