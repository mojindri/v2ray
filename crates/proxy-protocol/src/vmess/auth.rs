//! VMess AEAD authentication ID generation and validation.
//!
//! The auth ID is a 16-byte value sent at the start of every VMess connection.
//! It lets the server identify the user without a plaintext UUID, and includes
//! a timestamp to prevent replay attacks.
//!
//! # Auth ID construction (client)
//!
//! 1. Compute `cmd_key = MD5(uuid_bytes || [0x63, 0x61, 0x36, 0x66])`.
//! 2. Build a 16-byte plaintext:
//!    - bytes 0–7: current Unix timestamp (seconds, big-endian)
//!    - bytes 8–11: `crc32(bytes 0..7)` (big-endian)
//!    - bytes 12–15: 4 random bytes
//! 3. Encrypt the plaintext with `AES-128` in ECB mode (single block, no IV)
//!    using `cmd_key` as the key → produces the 16-byte auth ID.
//!
//! # Validation (server)
//!
//! For each registered UUID:
//! 1. Compute `cmd_key`.
//! 2. Decrypt the received auth ID with AES-128 ECB.
//! 3. Verify `crc32(bytes 0..7) == bytes 8..11`.
//! 4. Check `|now − timestamp| ≤ max_diff_secs` (replay protection).
//!
//! # References
//!
//! v2fly/v2ray-core: `proxy/vmess/inbound/inbound.go`, `common/protocol/headers.go`

use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes_gcm::aes::Aes128;
use aes_gcm::aead::generic_array::GenericArray;
use crc32fast::Hasher as Crc32Hasher;
use md5::{Digest as Md5Digest, Md5};
use rand::RngCore;

/// Maximum allowed clock difference in seconds for replay protection.
pub const MAX_TIME_DIFF_SECS: u64 = 120;

/// Salt appended to UUID bytes when deriving `cmd_key`.
const CMD_KEY_SALT: &[u8] = &[0x63, 0x61, 0x36, 0x66];

// ── cmd_key derivation ─────────────────────────────────────────────────────────

/// Derive the 16-byte `cmd_key` from a 16-byte UUID.
///
/// `cmd_key = MD5(uuid_bytes || [0x63, 0x61, 0x36, 0x66])`
pub fn cmd_key(uuid: &[u8; 16]) -> [u8; 16] {
    let mut hasher = Md5::new();
    hasher.update(uuid);
    hasher.update(CMD_KEY_SALT);
    hasher.finalize().into()
}

// ── Auth ID generation ─────────────────────────────────────────────────────────

/// Generate a 16-byte auth ID for the current time.
///
/// # Arguments
/// * `cmd_key` — 16-byte key derived from the user's UUID
pub fn generate_auth_id(cmd_key: &[u8; 16]) -> [u8; 16] {
    let now = current_timestamp();
    generate_auth_id_at(cmd_key, now)
}

/// Generate a 16-byte auth ID for a specific timestamp (useful for testing).
pub fn generate_auth_id_at(cmd_key: &[u8; 16], timestamp: u64) -> [u8; 16] {
    let mut plaintext = [0u8; 16];

    // bytes 0–7: timestamp
    plaintext[0..8].copy_from_slice(&timestamp.to_be_bytes());

    // bytes 8–11: CRC32 of the timestamp bytes
    let checksum = crc32_bytes(&plaintext[0..8]);
    plaintext[8..12].copy_from_slice(&checksum.to_be_bytes());

    // bytes 12–15: random
    rand::thread_rng().fill_bytes(&mut plaintext[12..16]);

    // Encrypt with AES-128 ECB (single block, no IV)
    aes128_ecb_encrypt(cmd_key, &mut plaintext);

    plaintext
}

// ── Auth ID validation ─────────────────────────────────────────────────────────

/// Validate a received auth ID against a `cmd_key`.
///
/// Returns `true` if the auth ID was produced by this `cmd_key` within the
/// allowed time window.
///
/// # Arguments
/// * `cmd_key`       — key derived from the user's UUID
/// * `auth_id`       — the 16-byte auth ID received from the client
/// * `max_diff_secs` — maximum allowed clock skew
pub fn validate_auth_id(cmd_key: &[u8; 16], auth_id: &[u8; 16], max_diff_secs: u64) -> bool {
    let mut block = *auth_id;
    aes128_ecb_decrypt(cmd_key, &mut block);

    // Extract and verify checksum.
    let expected_crc = crc32_bytes(&block[0..8]);
    let received_crc = u32::from_be_bytes([block[8], block[9], block[10], block[11]]);
    if expected_crc != received_crc {
        return false;
    }

    // Extract and verify timestamp.
    let timestamp = u64::from_be_bytes(block[0..8].try_into().unwrap());
    let now = current_timestamp();
    let diff = now.abs_diff(timestamp);

    diff <= max_diff_secs
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
        let k1 = cmd_key(&uuid);
        let k2 = cmd_key(&uuid);
        assert_eq!(k1, k2);
    }

    #[test]
    fn cmd_key_length_is_16() {
        let uuid = test_uuid();
        let k = cmd_key(&uuid);
        assert_eq!(k.len(), 16);
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

        let other_uuid = [0u8; 16];
        let other_key = cmd_key(&other_uuid);
        assert!(!validate_auth_id(&other_key, &auth, MAX_TIME_DIFF_SECS));
    }

    #[test]
    fn tampered_auth_id_rejected() {
        let uuid = test_uuid();
        let key = cmd_key(&uuid);
        let now = current_timestamp();
        let mut auth = generate_auth_id_at(&key, now);
        auth[0] ^= 0xFF; // flip bits
        assert!(!validate_auth_id(&key, &auth, MAX_TIME_DIFF_SECS));
    }
}
