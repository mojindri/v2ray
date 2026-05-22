//! Shadowsocks-2022 (SIP022 / AEAD-2022) proxy protocol.
//!
//! SS-2022 uses blake3-derived session subkeys and AES-256-GCM AEAD encryption.
//! It has a salt-based anti-replay system to prevent replay attacks.
//!
//! # Wire format (TCP)
//!
//! Client → Server:
//!
//! ```text
//! ┌───────────────────────────────────────────────────────────────┐
//! │ 32-byte random salt                                            │
//! │ AEAD-encrypted header (see below)                             │
//! │ AEAD-encrypted data chunks (2-byte length, each separately)   │
//! └───────────────────────────────────────────────────────────────┘
//! ```
//!
//! Header plaintext:
//! ```text
//!   type(1)=0x00 | timestamp(8 BE) | atyp(1) | addr | port(2 BE) | padding_len(2 BE) | padding(N)
//! ```
//!
//! Server → Client: same format (separate salt for each direction).
//!
//! # Key derivation
//!
//! Password → PSK via blake3 hash:
//!   `psk = blake3::hash(password.as_bytes())`
//!
//! Per-session subkey:
//!   `subkey = blake3::derive_key("ss-subkey", psk || salt)`
//!
//! # Modules
//!
//! - `subkey`  — session subkey derivation
//! - `replay`  — salt-based anti-replay filter
//! - `stream`  — AEAD-encrypted chunked stream
//! - `inbound` — server-side handler (read salt, check replay, decrypt header)
//! - `outbound`— client-side handler (generate salt, encrypt header)

pub mod inbound;
pub mod outbound;
pub mod replay;
pub mod stream;
pub mod subkey;

pub use inbound::Ss2022Inbound;
pub use outbound::Ss2022Outbound;
pub use replay::SaltReplay;
pub use stream::Ss2022Stream;
pub use subkey::derive_subkey;

/// SS-2022 configuration (shared by inbound and outbound builders).
#[derive(Debug, Clone)]
pub struct Ss2022Config {
    /// Cipher method — only "2022-blake3-aes-256-gcm" is currently supported.
    pub method: String,
    /// Server password (raw UTF-8). PSK = blake3::hash(password).
    pub password: String,
}

/// Derive the 32-byte PSK from a raw password string.
///
/// PSK = blake3::hash(password.as_bytes())
pub fn password_to_psk(password: &str) -> [u8; 32] {
    blake3::hash(password.as_bytes()).into()
}
