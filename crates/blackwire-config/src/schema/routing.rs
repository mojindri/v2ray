use serde::{Deserialize, Serialize};

/// Routing configuration: rules for deciding which outbound to use.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RoutingConfig {
    /// Outbound tag to use when no rule matches.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain_strategy: Option<String>,

    /// Optional path to v2ray-compatible `geoip.dat`.
    #[serde(
        default,
        rename = "geoipFile",
        alias = "geoip_file",
        skip_serializing_if = "Option::is_none"
    )]
    pub geoip_file: Option<String>,

    /// Optional path to v2ray-compatible `geosite.dat`.
    #[serde(
        default,
        rename = "geositeFile",
        alias = "geosite_file",
        skip_serializing_if = "Option::is_none"
    )]
    pub geosite_file: Option<String>,

    /// Routing rules, evaluated in order. First match wins.
    #[serde(default)]
    pub rules: Vec<RoutingRule>,

    /// Load-balancer configurations.
    #[serde(default)]
    pub balancers: Vec<BalancerConfig>,
}

/// A single routing rule.
///
/// The rule matches only when every populated condition matches.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RoutingRule {
    /// Rule type. Current implementation uses "field".
    #[serde(rename = "type", default = "default_rule_type")]
    pub rule_type: String,

    /// Domain matching patterns like `domain:example.com` or `suffix:example.com`.
    #[serde(default)]
    pub domain: Vec<String>,

    /// IP matching patterns like CIDR ranges or `geoip:CN`.
    #[serde(default)]
    pub ip: Vec<String>,

    /// Port matching examples: "443", "80,443", or "8000-9000".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<String>,

    /// Only apply this rule to connections arriving on these inbound tags.
    #[serde(default, rename = "inboundTag", skip_serializing_if = "Vec::is_empty")]
    pub inbound_tag: Vec<String>,

    /// Sniffed protocol match (`http`, `tls`, …) — Xray `protocol` field.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub protocol: Vec<String>,

    /// Outbound tag to use when this rule matches.
    #[serde(rename = "outboundTag")]
    pub outbound_tag: String,
}

fn default_rule_type() -> String {
    "field".to_string()
}

/// Load balancer configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalancerConfig {
    /// Unique name for this balancer.
    pub tag: String,

    /// Outbound tags this balancer distributes traffic across.
    pub selector: Vec<String>,

    /// Selection strategy: "random", "roundRobin", or "latency".
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
    /// URL to check. A 204 response means the outbound is healthy.
    #[serde(default = "default_health_check_url")]
    pub url: String,

    /// How often to run health checks, in seconds.
    #[serde(default = "default_health_check_interval")]
    pub interval_secs: u64,

    /// Timeout before considering a health check failed, in seconds.
    #[serde(default = "default_health_check_timeout")]
    pub timeout_secs: u64,

    /// Consecutive failures before marking the outbound dead.
    #[serde(default = "default_max_failures")]
    pub max_failures: u32,
}

fn default_health_check_url() -> String {
    "http://www.gstatic.com/generate_204".to_string()
}
fn default_health_check_interval() -> u64 {
    30
}
fn default_health_check_timeout() -> u64 {
    5
}
fn default_max_failures() -> u32 {
    3
}
