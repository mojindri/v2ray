//! ShadowTLS v3 marker — HMAC-SHA256 tag that signals the data channel start.
//!
//! After the TLS handshake, the client injects an 8-byte HMAC-SHA256 tag at the
//! beginning of the first Application Data record it sends. The server watches
//! the server→client data stream for this tag to know when to switch from
//! transparent relay mode to proxy mode.
//!
//! # Tag derivation
//!
//! ```text
//! marker = HMAC-SHA256(key = psk, data = server_random)[0..8]
//! ```
//!
//! Both sides derive the same 8-byte value from the pre-shared key and the
//! `server_random` field extracted from the ServerHello message.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// Compute the 8-byte HMAC-SHA256 marker.
///
/// # Arguments
/// * `psk`           — the pre-shared key (password bytes)
/// * `server_random` — the 32-byte `server_random` field from ServerHello
///
/// Returns the first 8 bytes of HMAC-SHA256(key=psk, data=server_random).
pub fn compute_marker(psk: &[u8], server_random: &[u8; 32]) -> [u8; 8] {
    let mut mac = match HmacSha256::new_from_slice(psk) {
        Ok(v) => v,
        Err(_) => panic!("HMAC accepts any key length"),
    };
    mac.update(server_random);
    let result = mac.finalize().into_bytes();

    let mut out = [0u8; 8];
    out.copy_from_slice(&result[..8]);
    out
}

/// Compare two markers without leaking which byte mismatched.
///
/// This keeps authentication behavior stable even when the peer sends junk.
pub(crate) fn markers_equal(expected: &[u8; 8], candidate: &[u8; 8]) -> bool {
    expected.ct_eq(candidate).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Marker computation is deterministic: same inputs always produce the same output.
    #[test]
    fn deterministic_marker() {
        let psk = b"test-password";
        let server_random = [0x42u8; 32];
        let m1 = compute_marker(psk, &server_random);
        let m2 = compute_marker(psk, &server_random);
        assert_eq!(m1, m2);
    }

    /// Different PSKs produce different markers.
    #[test]
    fn different_psk_different_marker() {
        let sr = [0x01u8; 32];
        let m1 = compute_marker(b"key1", &sr);
        let m2 = compute_marker(b"key2", &sr);
        assert_ne!(m1, m2);
    }

    /// Different server_random values produce different markers.
    #[test]
    fn different_server_random_different_marker() {
        let psk = b"shared-key";
        let m1 = compute_marker(psk, &[0xABu8; 32]);
        let m2 = compute_marker(psk, &[0xCDu8; 32]);
        assert_ne!(m1, m2);
    }

    /// Marker is exactly 8 bytes.
    #[test]
    fn marker_length() {
        let marker = compute_marker(b"pass", &[0u8; 32]);
        assert_eq!(marker.len(), 8);
    }
}
