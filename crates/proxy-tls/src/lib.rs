//! proxy-tls — raw TLS ClientHello builder and browser fingerprint profiles.
//!
//! # What this crate does
//!
//! When connecting to a REALITY server (Phase 2), we need to send a TLS
//! ClientHello that looks exactly like a real Chrome 131 browser. If the
//! ClientHello looks like Rust's `rustls` library instead of Chrome, a
//! censor can tell immediately that the client is a proxy tool, not a browser.
//!
//! This crate provides:
//!   - A `ClientHelloBuilder` that constructs a Chrome-131-identical
//!     ClientHello message byte-by-byte.
//!   - `FingerprintProfile` — a set of extension IDs, cipher suites, and
//!     GREASE values loaded from a JSON file at startup.
//!   - `grease_value()` — a function that picks a GREASE value per RFC 8701.
//!
//! # GREASE (RFC 8701)
//!
//! Chrome randomly inserts "GREASE" placeholder values into extension lists,
//! cipher suite lists, and key share groups. This forces TLS server
//! implementors to handle unknown values gracefully. Because Chrome always
//! does this, a ClientHello without GREASE looks different from Chrome.
//! Our builder includes GREASE in all the same places Chrome does.
//!
//! # Phase 1 status
//!
//! In Phase 1, this crate is a stub. The builder is not yet implemented.
//! REALITY transport ships in Phase 2. This crate exists now so that
//! `proxy-transport` can depend on it without requiring code changes later.

// Phase 2 will add:
//   pub mod client_hello;
//   pub mod grease;
//   pub mod profile;
//   pub use client_hello::ClientHelloBuilder;
//   pub use profile::FingerprintProfile;
//   pub use grease::grease_value;
