use serde::{Deserialize, Serialize};

/// Log level and output settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LogConfig {
    /// How verbose logs should be: "debug", "info", "warn", or "error".
    pub level: String,

    /// Whether to output logs as JSON.
    pub json: bool,

    /// Optional file path to write logs to. Empty means stderr.
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
    /// Upstream DNS servers, such as `udp://8.8.8.8:53` or DoH URLs.
    #[serde(default)]
    pub servers: Vec<String>,

    /// FakeIP settings for TUN mode interception.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fake_ip: Option<FakeIpConfig>,
}

/// FakeIP settings: assign fake IPs to domain names for TUN mode interception.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FakeIpConfig {
    /// Whether FakeIP mode is enabled.
    pub enabled: bool,

    /// IP range to allocate fake IPs from.
    #[serde(default = "default_fake_ip_range")]
    pub pool: String,
}

fn default_fake_ip_range() -> String {
    "198.18.0.0/15".to_string()
}
