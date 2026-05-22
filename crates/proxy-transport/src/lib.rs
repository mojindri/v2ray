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
pub mod quic;
pub mod hysteria2;

// Phase 2+ (remaining)
// pub mod tls;
// pub mod websocket;

// Phase 4+
// pub mod tun;

// Phase 5+
// pub mod grpc;
// pub mod mkcp;

pub use reality::{RealityClient, RealityClientConfig, RealityServer, RealityServerConfig};
pub use tcp::{TcpClientTransport, TcpServerTransport};
pub use quic::{build_client_endpoint, build_server_endpoint, dev_self_signed};
pub use quic::{BrutalCC, BrutalCCFactory};
pub use hysteria2::{
    Hysteria2Client, Hysteria2ClientConfig, Hysteria2OutboundHandler, Hysteria2Server,
    Hysteria2ServerConfig,
};

// Re-export quinn's congestion module so downstream crates can implement
// or use congestion controllers without depending on quinn directly.
pub use quinn::congestion as congestion;
