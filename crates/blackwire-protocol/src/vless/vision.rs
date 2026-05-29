//! XTLS Vision stream adapter.
//!
//! The implementation lives in `blackwire-common` so the Linux relay can
//! recognize Vision-over-TCP streams and hand them into splice after Vision
//! direct-copy negotiation, without making `blackwire-app` depend on this crate.

pub use blackwire_common::{wrap_vision_stream, VisionStream};
