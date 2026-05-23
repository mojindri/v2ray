//! VMess Key Derivation Function (KDF).
//!
//! VMess AEAD uses HMAC-SHA256 as its KDF primitive. Multiple paths are
//! chained together to derive independent keys for each use:
//!
//! ```text
//! kdf(key, [path1, path2, ...]) =
//!     HMAC-SHA256(HMAC-SHA256(...HMAC-SHA256(key, path1)..., path2), pathN)
//! ```
//!
//! The outer HMAC result is truncated to the requested length (N bytes).
//!
//! # References
//!
//! v2fly/v2ray-core: `common/crypto/kdf.go`

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Derive `N` bytes from `key` by chaining HMAC-SHA256 over each path segment.
///
/// # Arguments
/// * `key`   — the base key material (typically the VMess `cmd_key`)
/// * `paths` — an ordered slice of path labels to chain into the derivation
///
/// # Panics
///
/// Panics if `N > 32` (the HMAC-SHA256 output is 32 bytes).
pub fn kdf<const N: usize>(key: &[u8], paths: &[&[u8]]) -> [u8; N] {
    assert!(
        N <= 32,
        "KDF output cannot exceed 32 bytes (HMAC-SHA256 size)"
    );

    // The derivation starts with the base key. Each path segment is added by
    // using the current output as the new key and the path as the message.
    let mut current_key = key.to_vec();

    for &path in paths {
        let mut mac = match HmacSha256::new_from_slice(&current_key) {
            Ok(v) => v,
            Err(_) => panic!("HMAC accepts any key length"),
        };
        mac.update(path);
        current_key = mac.finalize().into_bytes().to_vec();
    }

    let mut out = [0u8; N];
    out.copy_from_slice(&current_key[..N]);
    out
}

// ── Unit tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Same inputs produce the same outputs (deterministic).
    #[test]
    fn deterministic() {
        let key = b"test-key-material";
        let paths: &[&[u8]] = &[b"path-a", b"path-b"];
        let a: [u8; 16] = kdf(key, paths);
        let b: [u8; 16] = kdf(key, paths);
        assert_eq!(a, b);
    }

    /// Different paths produce different outputs.
    #[test]
    fn different_paths_differ() {
        let key = b"same-key";
        let a: [u8; 16] = kdf(key, &[b"path-a"]);
        let b: [u8; 16] = kdf(key, &[b"path-b"]);
        assert_ne!(a, b);
    }

    /// Different keys produce different outputs.
    #[test]
    fn different_keys_differ() {
        let paths: &[&[u8]] = &[b"shared-path"];
        let a: [u8; 16] = kdf(b"key-1", paths);
        let b: [u8; 16] = kdf(b"key-2", paths);
        assert_ne!(a, b);
    }

    /// Can derive 32 bytes (full HMAC-SHA256 output).
    #[test]
    fn derive_32_bytes() {
        let out: [u8; 32] = kdf(b"key", &[b"path"]);
        // Just verify it is non-zero.
        assert!(out.iter().any(|&b| b != 0));
    }

    /// Chaining multiple paths is order-sensitive.
    #[test]
    fn path_order_matters() {
        let key = b"key";
        let a: [u8; 16] = kdf(key, &[b"p1", b"p2"]);
        let b: [u8; 16] = kdf(key, &[b"p2", b"p1"]);
        assert_ne!(a, b);
    }

    /// Zero paths: one HMAC round with an empty message acts as identity.
    #[test]
    fn zero_paths_uses_key_directly() {
        let key = b"my-key";
        // With no paths, `current_key` stays as `key` and we just copy the first N bytes.
        // But we do NOT apply any HMAC in that case — so the result is the key itself.
        let out: [u8; 6] = kdf(key, &[]);
        assert_eq!(&out, b"my-key");
    }
}
