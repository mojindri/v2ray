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

#[cfg(feature = "fuzzing")]
pub mod fuzzing;
pub mod inbound;
pub mod outbound;
pub mod replay;
pub mod stream;
pub mod subkey;
mod variable_header;

#[cfg(feature = "fuzzing")]
pub use fuzzing::try_decrypt_chunk_for_fuzz;
pub use inbound::Ss2022Inbound;
pub use outbound::{Ss2022ChunkedOutbound, Ss2022Outbound};
pub use replay::SaltReplay;
pub use stream::Ss2022Stream;
pub use subkey::derive_subkey;

/// Parse an 8-byte big-endian timestamp from a fixed-width slice.
pub(crate) fn u64_from_be8(bytes: &[u8]) -> Result<u64, blackwire_common::ProxyError> {
    let arr: [u8; 8] = bytes.try_into().map_err(|_| {
        blackwire_common::ProxyError::Protocol("SS-2022: timestamp field must be 8 bytes".into())
    })?;
    Ok(u64::from_be_bytes(arr))
}

/// SS-2022 configuration (shared by inbound and outbound builders).
#[derive(Debug, Clone)]
pub struct Ss2022Config {
    /// Cipher method — only "2022-blake3-aes-256-gcm" is currently supported.
    pub method: String,
    /// Server password: either a base64-encoded 32-byte key (xray/sing-box compatible)
    /// or an arbitrary UTF-8 string (PSK derived via blake3 hash for internal use).
    pub password: String,
}

/// Derive the 32-byte PSK from a password string.
///
/// If `password` is a valid standard or URL-safe base64 string that decodes to
/// exactly 32 bytes, those bytes are used directly as the PSK — this matches the
/// behavior of xray-core and sing-box for `2022-blake3-aes-256-gcm`.
///
/// Otherwise the PSK falls back to `blake3::hash(password.as_bytes())`, which
/// allows arbitrary UTF-8 strings to work for purely internal use cases.
pub fn password_to_psk(password: &str) -> [u8; 32] {
    use base64::Engine as _;
    let engines = [
        base64::engine::general_purpose::STANDARD,
        base64::engine::general_purpose::URL_SAFE,
        base64::engine::general_purpose::URL_SAFE_NO_PAD,
    ];
    for engine in &engines {
        if let Ok(bytes) = engine.decode(password) {
            if bytes.len() == 32 {
                let mut key = [0u8; 32];
                key.copy_from_slice(&bytes);
                return key;
            }
        }
    }
    blake3::hash(password.as_bytes()).into()
}
