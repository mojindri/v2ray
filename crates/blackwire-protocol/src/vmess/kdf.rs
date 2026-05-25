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

    let digest = kdf_hash(paths, key);
    let mut out = [0u8; N];
    out.copy_from_slice(&digest[..N]);
    out
}

const VMESS_AEAD_KDF_SALT: &[u8] = b"VMess AEAD KDF";
const HMAC_BLOCK_SIZE: usize = 64;

fn kdf_hash(paths: &[&[u8]], msg: &[u8]) -> [u8; 32] {
    if paths.is_empty() {
        let mut mac =
            HmacSha256::new_from_slice(VMESS_AEAD_KDF_SALT).expect("HMAC accepts any key length");
        mac.update(msg);
        let digest = mac.finalize().into_bytes();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        return out;
    }

    hmac_with_kdf_hash(&paths[..paths.len() - 1], paths[paths.len() - 1], msg)
}

fn hmac_with_kdf_hash(hash_paths: &[&[u8]], key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut block_key = [0u8; HMAC_BLOCK_SIZE];

    if key.len() > HMAC_BLOCK_SIZE {
        let hashed_key = kdf_hash(hash_paths, key);
        block_key[..hashed_key.len()].copy_from_slice(&hashed_key);
    } else {
        block_key[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; HMAC_BLOCK_SIZE];
    let mut opad = [0x5cu8; HMAC_BLOCK_SIZE];

    for i in 0..HMAC_BLOCK_SIZE {
        ipad[i] ^= block_key[i];
        opad[i] ^= block_key[i];
    }

    let mut inner_input = Vec::with_capacity(HMAC_BLOCK_SIZE + msg.len());
    inner_input.extend_from_slice(&ipad);
    inner_input.extend_from_slice(msg);
    let inner = kdf_hash(hash_paths, &inner_input);

    let mut outer_input = Vec::with_capacity(HMAC_BLOCK_SIZE + inner.len());
    outer_input.extend_from_slice(&opad);
    outer_input.extend_from_slice(&inner);

    kdf_hash(hash_paths, &outer_input)
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

    #[test]
    fn zero_paths_uses_salted_hmac() {
        let key = b"my-key";
        let out: [u8; 6] = kdf(key, &[]);
        assert_ne!(&out, b"my-key");
    }
}
