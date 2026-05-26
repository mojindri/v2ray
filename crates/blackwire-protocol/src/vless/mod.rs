//! VLESS protocol — inbound and outbound handlers.
//!
//! VLESS is a lightweight proxy protocol designed to disguise traffic as HTTPS.
//! It was created by the v2ray/Xray project and is the recommended protocol
//! for bypassing censorship in China and Russia (especially when combined with
//! the REALITY transport in Phase 2).
//!
//! # How VLESS works
//!
//! The client sends a small header at the start of each connection containing:
//!   - A version byte (always 0)
//!   - A 16-byte UUID identifying the user
//!   - Optional "addons" (protobuf-encoded, used for the `xtls-rprx-vision` flow)
//!   - A command byte (TCP connect or UDP associate)
//!   - The destination address and port
//!
//! After this header, raw payload bytes follow — there is no per-chunk framing.
//! This is what makes VLESS "lightweight": it adds minimal overhead compared
//! to protocols like VMess which encrypt and re-frame every chunk.
//!
//! # Active-probe resistance
//!
//! VLESS servers are a target for active probing by censorship systems. A prober
//! connects to the port and sends unexpected data, then observes the server's
//! response. If the server immediately closes the connection or returns an error,
//! the censor knows it is a proxy.
//!
//! The defence: when authentication fails, we do NOT close the connection.
//! Instead we forward everything (including the already-read header bytes) to
//! a fallback backend (usually Nginx on localhost:80 serving a real website).
//! The prober gets back a real web page and cannot tell the difference.
//!
//! # Modules
//!   - `codec`    — wire format encoding and decoding
//!   - `inbound`  — server-side handler (accepts VLESS connections)
//!   - `outbound` — client-side handler (sends VLESS connections)
//!   - `registry` — user UUID registry with fast O(1) lookup

pub mod codec;
pub mod inbound;
pub mod mux;
pub mod outbound;
pub mod registry;
pub mod udp;
pub mod vision;

pub use inbound::VlessInbound;
pub use outbound::{connect_vless_on_stream, VlessOutbound, VlessOutboundConfig};
pub use registry::{VlessUser, VlessUserRegistry};
