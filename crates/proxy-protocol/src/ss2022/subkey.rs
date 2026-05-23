//! SS-2022 session subkey derivation.
//!
//! Each session uses a unique 32-byte random salt. The per-session subkey is
//! derived using blake3's key derivation function:
//!
//! ```text
//! subkey = blake3::derive_key("shadowsocks 2022 session subkey", psk || salt)
//! ```
//!
//! The `psk` (pre-shared key) is itself derived from the password:
//! ```text
//! psk = blake3::hash(password.as_bytes())
//! ```
//!
//! Each direction (client→server and server→client) uses its own salt and
//! therefore its own independent subkey.

/// The blake3 KDF context string for SS-2022 subkey derivation.
const SUBKEY_CONTEXT: &str = "shadowsocks 2022 session subkey";

/// Derive a 32-byte session subkey from the PSK and a random per-session salt.
///
/// # Arguments
/// * `psk`  — 32-byte pre-shared key (`blake3::hash(password)`)
/// * `salt` — 32-byte random salt generated at the start of each session
///
/// # Returns
/// 32-byte session subkey for use with AES-256-GCM.
pub fn derive_subkey(psk: &[u8; 32], salt: &[u8; 32]) -> [u8; 32] {
    // Build the key material: psk || salt (64 bytes total).
    let mut material = [0u8; 64];
    material[..32].copy_from_slice(psk);
    material[32..].copy_from_slice(salt);

    // Use blake3's domain-separated key derivation.
    blake3::derive_key(SUBKEY_CONTEXT, &material)
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_psk() -> [u8; 32] {
        *blake3::hash(b"test-password").as_bytes()
    }

    fn test_salt() -> [u8; 32] {
        [0x42u8; 32]
    }

    /// Subkey derivation is deterministic for the same inputs.
    #[test]
    fn subkey_is_deterministic() {
        let psk = test_psk();
        let salt = test_salt();
        let k1 = derive_subkey(&psk, &salt);
        let k2 = derive_subkey(&psk, &salt);
        assert_eq!(k1, k2);
    }

    /// Different salts produce different subkeys.
    #[test]
    fn different_salt_different_subkey() {
        let psk = test_psk();
        let salt1 = [0x01u8; 32];
        let salt2 = [0x02u8; 32];
        let k1 = derive_subkey(&psk, &salt1);
        let k2 = derive_subkey(&psk, &salt2);
        assert_ne!(k1, k2);
    }

    /// Different PSKs (passwords) produce different subkeys.
    #[test]
    fn different_psk_different_subkey() {
        let psk1 = *blake3::hash(b"password1").as_bytes();
        let psk2 = *blake3::hash(b"password2").as_bytes();
        let salt = test_salt();
        let k1 = derive_subkey(&psk1, &salt);
        let k2 = derive_subkey(&psk2, &salt);
        assert_ne!(k1, k2);
    }

    /// The subkey is 32 bytes long (suitable for AES-256-GCM).
    #[test]
    fn subkey_is_32_bytes() {
        let psk = test_psk();
        let salt = test_salt();
        let k = derive_subkey(&psk, &salt);
        assert_eq!(k.len(), 32);
    }
}
