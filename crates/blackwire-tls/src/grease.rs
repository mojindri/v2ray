//! GREASE value generation (RFC 8701).
//!
//! # What is GREASE?
//!
//! "Generate Random Extensions And Sustain Extensibility" (GREASE) is a
//! technique Chrome uses to keep TLS implementations honest. It works by
//! inserting deliberately unknown values into TLS fields:
//!
//!   - Cipher suite list: insert one unknown cipher suite
//!   - Extension list: insert one unknown extension
//!   - Named group list (for key share): insert one unknown group
//!   - ALPN: insert one unknown ALPN string
//!
//! A correct TLS server must silently ignore unknown values and not crash.
//! This "greases" the protocol — like WD-40 — keeping servers from becoming
//! rigid by depending on exact known values.
//!
//! # Why does this matter for our proxy?
//!
//! When we build a ClientHello to mimic Chrome, we must include GREASE values
//! in the same positions Chrome uses them. Without GREASE, our ClientHello looks
//! different from a real Chrome ClientHello, making it easier for DPI systems to
//! fingerprint us.
//!
//! # The 16 GREASE values
//!
//! RFC 8701 defines exactly 16 GREASE values for 16-bit fields:
//!   0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
//!   0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA
//!
//! Pattern: the two bytes are always equal, and the low nibble is always 0x0A.
//! Chrome picks one of these 16 values randomly for each connection.

use rand::{Rng, RngExt};

/// The 16 GREASE values defined by RFC 8701 for 16-bit TLS fields.
///
/// These are the only valid GREASE values. Any other value is not GREASE —
/// it is just an unknown value, which may confuse TLS servers that do not
/// implement RFC 8701 (though they should silently ignore it regardless).
const GREASE_VALUES_U16: [u16; 16] = [
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
    0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
];

/// The 16 GREASE values for 8-bit TLS fields (compression method, etc.).
///
/// Same pattern, just the low byte: 0x0A, 0x1A, 0x2A, …, 0xFA.
const GREASE_VALUES_U8: [u8; 16] = [
    0x0A, 0x1A, 0x2A, 0x3A, 0x4A, 0x5A, 0x6A, 0x7A, 0x8A, 0x9A, 0xAA, 0xBA, 0xCA, 0xDA, 0xEA, 0xFA,
];

/// Pick a random GREASE value for a 16-bit TLS field.
///
/// Call this once per connection to get the GREASE cipher suite value,
/// and again (independently) to get the GREASE extension/group value.
/// Chrome uses the same GREASE value across all lists in a single ClientHello,
/// but uses different values for the cipher suite vs. the extension.
///
/// # Example
/// ```rust
/// use blackwire_tls::grease::grease_u16;
/// let mut rng = rand::rng();
/// let grease = grease_u16(&mut rng);
/// assert!(grease & 0x0F0F == 0x0A0A, "must be a GREASE value");
/// ```
pub fn grease_u16(rng: &mut impl Rng) -> u16 {
    let idx = rng.random_range(0..16usize);
    GREASE_VALUES_U16[idx]
}

/// Pick a random GREASE value for an 8-bit TLS field.
pub fn grease_u8(rng: &mut impl Rng) -> u8 {
    let idx = rng.random_range(0..16usize);
    GREASE_VALUES_U8[idx]
}

/// Check whether a given u16 is a valid GREASE value.
///
/// Useful for test assertions.
pub fn is_grease_u16(v: u16) -> bool {
    GREASE_VALUES_U16.contains(&v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    // Checks that every output of grease_u16 is one of the 16 valid GREASE values.
    #[test]
    fn grease_u16_always_valid() {
        let mut rng = rand::rngs::SmallRng::seed_from_u64(42);
        for _ in 0..1000 {
            let v = grease_u16(&mut rng);
            assert!(is_grease_u16(v), "got non-GREASE value {v:#06x}");
        }
    }

    // Checks that all 16 GREASE values are reachable over many calls.
    // (Statistical test — fails with probability 16^(-1000) which is negligible.)
    #[test]
    fn grease_u16_covers_all_values() {
        let mut rng = rand::rngs::SmallRng::seed_from_u64(0);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..10_000 {
            seen.insert(grease_u16(&mut rng));
        }
        assert_eq!(seen.len(), 16, "not all 16 GREASE values were generated");
    }

    // Checks that grease_u8 produces values with the correct pattern (low nibble = 0x0A).
    #[test]
    fn grease_u8_low_nibble() {
        let mut rng = rand::rngs::SmallRng::seed_from_u64(7);
        for _ in 0..1000 {
            let v = grease_u8(&mut rng);
            assert_eq!(v & 0x0F, 0x0A, "low nibble of {v:#04x} should be 0x0A");
        }
    }
}
