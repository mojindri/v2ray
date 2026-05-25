//! proxy-tls — raw TLS ClientHello builder and browser fingerprint profiles.
//!
//! # What this crate does
//!
//! When connecting to a REALITY server, we need to send a TLS ClientHello
//! that looks exactly like a real Chrome 131 browser. If the ClientHello
//! looks like Rust's `rustls` library instead of Chrome, a censor can tell
//! immediately that the client is a proxy tool, not a browser.
//!
//! This crate provides three things:
//!
//! ## 1. `FingerprintProfile` (`profile` module)
//!
//! Describes what a Chrome 131 ClientHello looks like: which cipher suites,
//! which extensions, which elliptic curves, in what order. Loadable from a
//! JSON file so operators can update fingerprints without recompiling.
//!
//! ## 2. `grease_u16` / `grease_u8` (`grease` module)
//!
//! Generates random GREASE placeholder values (RFC 8701). Chrome inserts these
//! in cipher suite lists, extension lists, and named group lists to keep TLS
//! servers from depending on knowing all valid values.
//!
//! ## 3. `ClientHelloBuilder` (`client_hello` module)
//!
//! Constructs the actual ClientHello bytes, field by field, to match Chrome 131
//! exactly. Used by the REALITY transport client to disguise itself as Chrome.
//!
//! # Relationship to REALITY
//!
//! The REALITY transport (`proxy-transport/src/reality.rs`) uses this crate to:
//!   1. Build a Chrome-identical ClientHello.
//!   2. Override the `random` field with ECDH+HKDF-derived bytes.
//!   3. Override the `session_id` field with the AES-128-GCM encrypted token.
//!   4. Send the raw bytes over TCP (before rustls takes over after ServerHello).

pub mod client_hello;
pub mod grease;
pub mod profile;

pub use client_hello::ClientHelloBuilder;
pub use grease::{grease_u16, grease_u8, is_grease_u16};
pub use profile::FingerprintProfile;
