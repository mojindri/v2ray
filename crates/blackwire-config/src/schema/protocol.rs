use serde::{Deserialize, Serialize};

/// Proxy protocol identifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    /// VLESS — lightweight, authentication via UUID.
    Vless,
    /// VMess — older protocol with AEAD encryption.
    Vmess,
    /// Trojan — disguises traffic as HTTPS.
    Trojan,
    /// Shadowsocks-2022.
    #[serde(rename = "shadowsocks")]
    Shadowsocks,
    /// Hysteria2 — QUIC-based.
    Hysteria2,
    /// ShadowTLS — wraps another protocol inside a real TLS handshake.
    ShadowTls,
    /// SOCKS5 local proxy protocol.
    Socks,
    /// HTTP CONNECT proxy.
    Http,
    /// Freedom — direct connection to the destination.
    Freedom,
}

/// Which transport wrapping to use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum NetworkType {
    /// Raw TCP.
    #[default]
    Tcp,
    /// WebSocket.
    Ws,
    /// gRPC over HTTP/2.
    Grpc,
    /// QUIC-based transport.
    Quic,
    /// KCP ARQ over UDP.
    Kcp,
    /// SplitHTTP (XHTTP).
    #[serde(rename = "splithttp")]
    SplitHttp,
}

/// Which security layer to apply on top of the transport.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SecurityType {
    /// No encryption. Only safe for local trusted links.
    #[default]
    None,
    /// Standard TLS.
    Tls,
    /// REALITY TLS camouflage.
    Reality,
    /// ShadowTLS v3 — wraps another protocol inside a real TLS handshake.
    #[serde(rename = "shadowtls")]
    ShadowTls,
}
