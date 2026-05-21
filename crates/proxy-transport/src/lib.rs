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

pub mod tcp;

// Phase 2+
// pub mod tls;
// pub mod websocket;
// pub mod reality;

// Phase 3+
// pub mod quic;

// Phase 4+
// pub mod tun;

// Phase 5+
// pub mod grpc;
// pub mod mkcp;

pub use tcp::{TcpClientTransport, TcpServerTransport};
