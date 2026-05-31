use crate::models::{CapabilityItem, CapabilityMap};

pub fn blackwire_capabilities() -> CapabilityMap {
    CapabilityMap {
        protocols: vec![
            item(
                "socks",
                "SOCKS5 inbound",
                "supported",
                "TCP CONNECT and UDP ASSOCIATE inbound",
            ),
            item(
                "http",
                "HTTP CONNECT inbound",
                "supported",
                "Local HTTP CONNECT inbound",
            ),
            item(
                "freedom",
                "Freedom outbound",
                "supported",
                "Direct outbound",
            ),
            item(
                "vless",
                "VLESS",
                "supported",
                "Inbound and outbound, UDP, MUX, Vision",
            ),
            item(
                "vmess",
                "VMess AEAD",
                "supported",
                "Legacy alterId is hidden",
            ),
            item(
                "trojan",
                "Trojan",
                "supported",
                "Inbound and outbound, TCP and UDP",
            ),
            item(
                "shadowsocks",
                "Shadowsocks / SS2022",
                "supported",
                "Inbound and outbound, TCP and UDP",
            ),
            item(
                "hysteria2",
                "Hysteria2",
                "supported",
                "QUIC/HTTP3 TCP stream proxy and UDP",
            ),
        ],
        transports: vec![
            item("tcp", "TCP", "supported", "Raw TCP transport"),
            item(
                "ws",
                "WebSocket",
                "supported",
                "Path and headers through wsSettings",
            ),
            item("grpc", "gRPC", "supported", "Gun-style gRPC transport"),
            item(
                "reality",
                "REALITY",
                "supported",
                "Security layer for TCP-compatible endpoints",
            ),
            item("tls", "TLS", "supported", "rustls TLS security layer"),
            item(
                "shadowtls",
                "ShadowTLS v3",
                "supported",
                "security=shadowtls, not a protocol",
            ),
            item("kcp", "mKCP", "supported", "UDP KCP transport"),
            item("quic", "QUIC", "supported", "Legacy V2Ray QUIC transport"),
            item(
                "httpupgrade",
                "HTTPUpgrade",
                "supported",
                "HTTP upgrade path/header transport",
            ),
            item(
                "splithttp",
                "SplitHTTP / xHTTP",
                "supported",
                "stream-one and packet-up paths",
            ),
        ],
        security: vec![
            item(
                "none",
                "No security",
                "supported",
                "Use only on trusted links",
            ),
            item(
                "tls",
                "TLS",
                "supported",
                "Certificate/key fields validated by Blackwire",
            ),
            item(
                "reality",
                "REALITY",
                "supported",
                "X25519/shortId based camouflage",
            ),
            item("shadowtls", "ShadowTLS", "supported", "v3 security wrapper"),
        ],
        config: vec![
            item(
                "routing",
                "Routing rules",
                "supported",
                "Rules, geoip/geosite, balancers, health checks",
            ),
            item(
                "dns",
                "DNS",
                "supported",
                "System/custom upstreams, DoH/DoT, FakeIP",
            ),
            item(
                "tun",
                "TUN",
                "supported",
                "Linux/macOS/Windows runtime fields with platform caveats",
            ),
            item(
                "metricsAddr",
                "Prometheus metrics",
                "supported",
                "metrics/health HTTP listener",
            ),
            item(
                "api",
                "gRPC API",
                "supported",
                "Handler and Stats service listener",
            ),
            item(
                "profile",
                "Runtime profile",
                "supported",
                "compat and fast profiles",
            ),
            item(
                "fast",
                "Fast profile tuning",
                "supported",
                "pool/splice strict production knobs",
            ),
        ],
        runtime: vec![
            item(
                "grpc-live-apply",
                "gRPC live apply",
                "supported",
                "Native endpoint JSON through proxy_settings",
            ),
            item(
                "stats",
                "Traffic stats",
                "experimental",
                "Depends on Blackwire StatsService runtime",
            ),
            item(
                "systemd",
                "Linux service control",
                "supported",
                "Local systemctl/journalctl helpers",
            ),
        ],
    }
}

fn item(
    key: &'static str,
    label: &'static str,
    status: &'static str,
    notes: &'static str,
) -> CapabilityItem {
    CapabilityItem {
        key,
        label,
        status,
        notes,
    }
}
