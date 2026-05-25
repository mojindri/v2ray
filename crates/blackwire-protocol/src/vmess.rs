//! VMess protocol — AEAD-encrypted proxy with UUID authentication.
//!
//! VMess is the original V2Ray protocol. Since 2022 it uses AEAD encryption
//! exclusively (the old MD5-based header format is deprecated).
//!
//! # How VMess AEAD works
//!
//! 1. Client generates an auth ID: AES-128-ECB encrypted timestamp + CRC.
//! 2. Client encrypts the request header (IV, Key, destination) with AES-128-GCM,
//!    using keys derived via HMAC-SHA256 KDF from the cmd_key.
//! 3. Data flows as AEAD-encrypted chunks (AES-128-GCM or ChaCha20-Poly1305).
//!
//! # Modules
//!
//! - `kdf`      — HMAC-SHA256-based key derivation function
//! - `auth`     — auth ID generation and validation
//! - `codec`    — request header encode/decode (AEAD encrypted)
//! - `stream`   — AEAD chunk-framed `BoxedStream` wrapper
//! - `inbound`  — server-side handler
//! - `outbound` — client-side handler

pub mod auth;
pub mod codec;
pub mod inbound;
pub mod kdf;
pub mod outbound;
pub mod stream;

pub use inbound::{VmessInbound, VmessUser, VmessUserRegistry};
pub use outbound::{connect_vmess_on_stream, VmessOutbound, VmessOutboundConfig};
