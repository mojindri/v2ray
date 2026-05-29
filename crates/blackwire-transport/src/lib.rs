//! blackwire-transport — transport layer implementations.
//!
//! A "transport" is the underlying mechanism used to move bytes between two
//! endpoints. This crate contains implementations for:
//!
//!   - **TCP** — raw TCP sockets, the most common transport
//!   - **TLS** — TLS encryption on top of TCP
//!   - **WebSocket** — HTTP upgrade to WebSocket protocol
//!   - **REALITY** — TLS camouflage using a real destination site
//!   - **gRPC** — HTTP/2 framing via tonic
//!   - **QUIC** — UDP-based transport for VLESS/VMess and Hysteria2
//!   - **mKCP** — KCP ARQ over UDP for lossy links
//!   - **TUN** — OS network interface for full-device routing
//!
//! Each transport converts its connection type into a `BoxedStream`, which
//! is what the protocol layer receives. The protocol layer never knows which
//! transport is underneath.

#[cfg(target_os = "linux")]
mod ktls;
mod pem;
pub mod reality;
pub mod tcp;

// QUIC and Hysteria2
pub mod hysteria2;
pub mod quic;

// TLS and WebSocket transports
pub mod tls;
pub mod ws;

/// HTTPUpgrade transport (Xray `httpupgrade` network).
pub mod httpupgrade;

mod splithttp_packet_up;

/// SplitHTTP / xHTTP transport.
pub mod splithttp;

/// TUN transport runtime and packet helpers for full-device proxying.
#[cfg(target_os = "linux")]
pub mod tun;

// gRPC transport
pub mod grpc;

// mKCP transport
/// mKCP transport implementation (KCP over UDP).
pub mod mkcp;

/// Generic QUIC transport for VLESS / VMess stream protocols.
pub mod v2rayquic;

// ShadowTLS v3 transport
pub mod shadowtls;

pub use grpc::{decode_grpc_frame, encode_grpc_frame, grpc_accept, grpc_connect, GrpcStream};
pub use httpupgrade::{accept_httpupgrade, dial_httpupgrade, httpupgrade_listen_path};
pub use hysteria2::{
    Hysteria2Client, Hysteria2ClientConfig, Hysteria2OutboundHandler, Hysteria2Server,
    Hysteria2ServerConfig, Hysteria2UdpSession, UdpDestination,
};
pub use mkcp::{
    mkcp_accept_once, mkcp_accept_sessions, mkcp_connect, MkcpClientConfig, MkcpServerConfig,
};
pub use quic::{
    build_client_endpoint, build_client_endpoint_with_alpn, build_server_endpoint,
    build_server_endpoint_with_alpn, dev_self_signed, dev_self_signed_for_names,
    ensure_crypto_provider,
};
pub use quic::{BrutalCC, BrutalCCFactory};
pub use reality::{
    complete_tls13_server_handshake, reality_server_tls_stream, tls_cert_for_auth_key,
    tls_pem_for_auth_key, RealityAccepted, RealityClient, RealityClientConfig, RealityServer,
    RealityServerConfig, Tls13Stream,
};
pub use shadowtls::{
    compute_marker, shadowtls_accept, shadowtls_connect, shadowtls_marker_accept,
    shadowtls_marker_connect, shadowtls_v3_connect, write_marker_record,
};
pub use splithttp::{
    normalize_splithttp_mode, splithttp_accept, splithttp_accept_h2, splithttp_connect,
    splithttp_listen_params, PacketUpH2TunnelFn, SplitHttpAcceptResult, SplitHttpMode,
};
pub use tcp::{TcpClientTransport, TcpServerTransport};
pub use tls::{
    build_server_config as tls_build_server_config, build_tls_acceptor,
    cached_client_config as tls_cached_client_config, tls_accept, tls_accept_tls13,
    tls_accept_with_acceptor, tls_connect, tls_connect_with_config,
};
#[cfg(target_os = "linux")]
pub use tun::{
    build_tcp_rst, create_tun, IpPacket, TransportProtocol, TunConfig, TunRuntime, UdpNatTable,
};
pub use v2rayquic::{accepted_quic_stream, quic_connect, quic_server_endpoint, QuicStream};
pub use ws::{ws_accept, ws_connect, WsConnectConfig};

// Re-export quinn's congestion module so downstream crates can implement
// or use congestion controllers without depending on quinn directly.
pub use quinn::congestion;
