//! VMess AEAD authentication ID generation and validation.
//!
//! # Auth ID construction (client)
//!
//! 1. Build a 16-byte plaintext:
//!    - bytes 0–7:  current Unix timestamp (big-endian)
//!    - bytes 8–11: 4 random bytes
//!    - bytes 12–15: `crc32(bytes 0..12)` (big-endian)
//! 2. Encrypt with `AES-128` ECB using `KDF16(cmd_key, "AES Auth ID Encryption")`.
//!
//! # cmd_key
//!
//! `cmd_key = MD5(uuid_bytes || "c48619fe-8f02-49e0-b9e9-edf763e17e21")`
//!
//! # How it works
//!
//! The client builds a short auth block from time, randomness, and CRC32, then
//! encrypts it with a key derived from the user's UUID. The server reverses that
//! process and checks time and checksum.
//!
//! # Why
//!
//! This lets the server quickly identify valid users and reject malformed or old
//! auth IDs before doing expensive header processing.

use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes_gcm::aes::Aes128;
use crc32fast::Hasher as Crc32Hasher;
use md5::{Digest as Md5Digest, Md5};
use rand::RngExt;

use super::kdf::kdf;

/// Maximum allowed clock difference in seconds for replay protection.
pub const MAX_TIME_DIFF_SECS: u64 = 120;

/// Salt appended to UUID bytes when deriving `cmd_key`.
const CMD_KEY_SALT: &[u8] = b"c48619fe-8f02-49e0-b9e9-edf763e17e21";

/// KDF label for the AES auth ID encryption key.
const KDF_AUTH_ID: &[u8] = b"AES Auth ID Encryption";

// ── cmd_key derivation ─────────────────────────────────────────────────────────

/// Derive the 16-byte `cmd_key` from a 16-byte UUID.
pub fn cmd_key(uuid: &[u8; 16]) -> [u8; 16] {
    let mut hasher = Md5::new();
    hasher.update(uuid);
    hasher.update(CMD_KEY_SALT);
    hasher.finalize().into()
}

// ── Auth ID generation ─────────────────────────────────────────────────────────

/// Generate a 16-byte auth ID for the current time.
pub fn generate_auth_id(cmd_key: &[u8; 16]) -> [u8; 16] {
    let now = current_timestamp();
    generate_auth_id_at(cmd_key, now)
}

/// Generate a 16-byte auth ID for a specific timestamp (useful for testing).
///
/// Plaintext layout: `timestamp_be(8) | random(4) | crc32(first_12)(4)`
/// AES key: `KDF16(cmd_key, "AES Auth ID Encryption")`
pub fn generate_auth_id_at(cmd_key: &[u8; 16], timestamp: u64) -> [u8; 16] {
    let mut plaintext = [0u8; 16];

    // bytes 0–7: timestamp
    plaintext[0..8].copy_from_slice(&timestamp.to_be_bytes());

    // bytes 8–11: 4 random bytes
    rand::rng().fill(&mut plaintext[8..12]);

    // bytes 12–15: CRC32 of first 12 bytes
    let checksum = crc32_bytes(&plaintext[0..12]);
    plaintext[12..16].copy_from_slice(&checksum.to_be_bytes());

    // Encrypt with AES-128 ECB, key = KDF16(cmd_key, "AES Auth ID Encryption")
    let aes_key: [u8; 16] = kdf(cmd_key, &[KDF_AUTH_ID]);
    aes128_ecb_encrypt(&aes_key, &mut plaintext);

    plaintext
}

// ── Auth ID validation ─────────────────────────────────────────────────────────

/// Validate a received auth ID against a `cmd_key`.
pub fn validate_auth_id(cmd_key: &[u8; 16], auth_id: &[u8; 16], max_diff_secs: u64) -> bool {
    let aes_key: [u8; 16] = kdf(cmd_key, &[KDF_AUTH_ID]);
    let mut block = *auth_id;
    aes128_ecb_decrypt(&aes_key, &mut block);

    // bytes 12–15 = CRC32(bytes 0..12)
    let expected_crc = crc32_bytes(&block[0..12]);
    let received_crc = u32::from_be_bytes([block[12], block[13], block[14], block[15]]);
    if expected_crc != received_crc {
        return false;
    }

    // bytes 0–7 = timestamp
    let ts_bytes: [u8; 8] = match block[0..8].try_into() {
        Ok(v) => v,
        Err(_) => return false,
    };
    let timestamp = u64::from_be_bytes(ts_bytes);
    let now = current_timestamp();
    now.abs_diff(timestamp) <= max_diff_secs
}

// ── AES-128 ECB helpers ────────────────────────────────────────────────────────

fn aes128_ecb_encrypt(key: &[u8; 16], block: &mut [u8; 16]) {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let block_ga = GenericArray::from_mut_slice(block);
    cipher.encrypt_block(block_ga);
}

fn aes128_ecb_decrypt(key: &[u8; 16], block: &mut [u8; 16]) {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let block_ga = GenericArray::from_mut_slice(block);
    cipher.decrypt_block(block_ga);
}

// ── CRC32 helper ──────────────────────────────────────────────────────────────

fn crc32_bytes(data: &[u8]) -> u32 {
    let mut h = Crc32Hasher::new();
    h.update(data);
    h.finalize()
}

// ── Timestamp helper ──────────────────────────────────────────────────────────

/// Return the current Unix timestamp in seconds.
pub fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ── Unit tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_uuid() -> [u8; 16] {
        *uuid::Uuid::parse_str("a3482e88-686a-4a58-8126-99c9df64b7bf")
            .unwrap()
            .as_bytes()
    }

    #[test]
    fn cmd_key_is_deterministic() {
        let uuid = test_uuid();
        assert_eq!(cmd_key(&uuid), cmd_key(&uuid));
    }

    #[test]
    fn generate_and_validate_roundtrip() {
        let uuid = test_uuid();
        let key = cmd_key(&uuid);
        let now = current_timestamp();
        let auth = generate_auth_id_at(&key, now);
        assert!(validate_auth_id(&key, &auth, MAX_TIME_DIFF_SECS));
    }

    #[test]
    fn old_timestamp_rejected() {
        let uuid = test_uuid();
        let key = cmd_key(&uuid);
        let old = current_timestamp() - MAX_TIME_DIFF_SECS - 10;
        let auth = generate_auth_id_at(&key, old);
        assert!(!validate_auth_id(&key, &auth, MAX_TIME_DIFF_SECS));
    }

    #[test]
    fn wrong_key_rejected() {
        let uuid = test_uuid();
        let key = cmd_key(&uuid);
        let now = current_timestamp();
        let auth = generate_auth_id_at(&key, now);
        let other_key = cmd_key(&[0u8; 16]);
        assert!(!validate_auth_id(&other_key, &auth, MAX_TIME_DIFF_SECS));
    }

    #[test]
    fn tampered_auth_id_rejected() {
        let uuid = test_uuid();
        let key = cmd_key(&uuid);
        let now = current_timestamp();
        let mut auth = generate_auth_id_at(&key, now);
        auth[0] ^= 0xFF;
        assert!(!validate_auth_id(&key, &auth, MAX_TIME_DIFF_SECS));
    }
}
