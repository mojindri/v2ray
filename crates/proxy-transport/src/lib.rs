//! proxy-transport — transport layer implementations.
//!
//! A "transport" is the underlying mechanism used to move bytes between two
//! endpoints. This crate contains implementations for:
//!
//!   - **TCP** (Phase 1) — raw TCP sockets, the most common transport
//!   - **TLS** (Phase 2) — TLS encryption on top of TCP
//!   - **WebSocket** (Phase 2) — HTTP upgrade to WebSocket protocol
//!   - **REALITY** (Phase 2) — TLS camouflage using a real destination site
//!   - **gRPC** (Phase 5) — HTTP/2 framing via tonic
//!   - **QUIC** (Phase 3) — UDP-based transport for Hysteria2
//!   - **mKCP** (Phase 5) — KCP ARQ over UDP for lossy links
//!   - **TUN** (Phase 4) — OS network interface for full-device routing
//!
//! Each transport converts its connection type into a `BoxedStream`, which
//! is what the protocol layer receives. The protocol layer never knows which
//! transport is underneath.

pub mod reality;
pub mod tcp;

// Phase 3: QUIC and Hysteria2
pub mod hysteria2;
pub mod quic;

// Phase 4: TLS and WebSocket transports
pub mod tls;
pub mod ws;

// Phase 4+
/// TUN transport runtime and packet helpers for full-device proxying.
pub mod tun;

// Phase 5: gRPC transport
pub mod grpc;

// mKCP transport
/// mKCP transport implementation (KCP over UDP).
pub mod mkcp;

// Phase 7: ShadowTLS v3 transport
pub mod shadowtls;

pub use grpc::{decode_grpc_frame, encode_grpc_frame, grpc_accept, grpc_connect, GrpcStream};
pub use hysteria2::{
    Hysteria2Client, Hysteria2ClientConfig, Hysteria2OutboundHandler, Hysteria2Server,
    Hysteria2ServerConfig,
};
pub use mkcp::{
    mkcp_accept_once, mkcp_accept_sessions, mkcp_connect, MkcpClientConfig, MkcpServerConfig,
};
pub use quic::{
    build_client_endpoint, build_server_endpoint, dev_self_signed, dev_self_signed_for_names,
};
pub use quic::{BrutalCC, BrutalCCFactory};
pub use reality::{
    complete_tls13_server_handshake, tls_cert_for_auth_key, tls_pem_for_auth_key, RealityAccepted,
    RealityClient, RealityClientConfig, RealityServer, RealityServerConfig, Tls13Stream,
};
pub use shadowtls::{
    compute_marker, shadowtls_accept, shadowtls_connect, shadowtls_marker_accept,
    shadowtls_marker_connect, shadowtls_v3_connect, write_marker_record,
};
pub use tcp::{TcpClientTransport, TcpServerTransport};
pub use tls::{
    build_server_config as tls_build_server_config, tls_accept, tls_accept_tls13, tls_connect,
};
pub use tun::{
    build_tcp_rst, create_tun, IpPacket, TransportProtocol, TunConfig, TunRuntime, UdpNatTable,
};
pub use ws::{ws_accept, ws_connect, WsConnectConfig};

// Re-export quinn's congestion module so downstream crates can implement
// or use congestion controllers without depending on quinn directly.
pub use quinn::congestion;
