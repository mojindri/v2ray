//! TLS fingerprint profiles — the blueprint for a Chrome-identical ClientHello.
//!
//! # What is a fingerprint profile?
//!
//! A TLS fingerprint is a set of characteristics that identify a TLS client:
//!   - Which cipher suites it supports (and in what order)
//!   - Which TLS extensions it includes (and in what order)
//!   - Which elliptic curves (named groups) it supports
//!   - Which signature algorithms it accepts
//!   - What ALPN protocols it advertises
//!
//! JA3 and JA4 are fingerprinting algorithms that hash these fields into a
//! short string. Censorship systems (GFW, DPI boxes) use JA3 to detect proxy
//! tools by their unusual fingerprints.
//!
//! Chrome 131 has a well-known JA3 hash:
//!   771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,\
//!   0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0
//!
//! # How do we use this?
//!
//! `FingerprintProfile::chrome_131()` returns the hardcoded Chrome 131 profile.
//! The `ClientHelloBuilder` reads this profile and constructs a ClientHello byte
//! buffer that matches Chrome's JA3/JA4 fingerprint exactly.
//!
//! In Phase 2, we load the profile from `fingerprints/chrome-131.json` at
//! startup so operators can update the fingerprint without recompiling.

use serde::{Deserialize, Serialize};

/// A complete TLS fingerprint profile describing what a ClientHello looks like.
///
/// Every field here corresponds to a section of the TLS ClientHello message.
/// The order of items within each list matters — it affects the fingerprint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintProfile {
    /// TLS cipher suites, in the exact order they appear in the ClientHello.
    ///
    /// These are 16-bit values defined in the TLS IANA registry.
    /// Example: 0x1301 = TLS_AES_128_GCM_SHA256 (TLS 1.3)
    ///          0xC02B = TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (TLS 1.2)
    ///
    /// One GREASE cipher suite is inserted at position 0 before the real list.
    pub cipher_suites: Vec<u16>,

    /// TLS extension IDs, in the exact order they appear in the ClientHello.
    ///
    /// The order matters for JA3 fingerprinting. Chrome always uses the same
    /// extension order. A GREASE extension is inserted at a specific position.
    pub extensions: Vec<u16>,

    /// Elliptic curve "named groups" supported by the client.
    ///
    /// Appears in the `supported_groups` extension (extension 10).
    /// A GREASE group value is inserted at position 0.
    pub supported_groups: Vec<u16>,

    /// Application-Layer Protocol Negotiation (ALPN) protocols.
    ///
    /// Tells the server which HTTP versions the client supports.
    /// Chrome sends ["h2", "http/1.1"] in that order.
    pub alpn: Vec<String>,

    /// Signature algorithms supported by the client.
    ///
    /// Appears in the `signature_algorithms` extension (extension 13).
    /// These are 16-bit scheme IDs from the TLS registry.
    pub signature_algorithms: Vec<u16>,
}

impl FingerprintProfile {
    /// Return the hardcoded Chrome 131 fingerprint profile.
    ///
    /// This was extracted from a real Chrome 131.0.6778.108 ClientHello captured
    /// with Wireshark. It matches the JA3 hash:
    ///   `771,4865-4866-...,0-23-65281-...,29-23-24,0`
    ///
    /// Note: GREASE values are NOT included here. The `ClientHelloBuilder` adds
    /// them dynamically per-connection, which is what Chrome does.
    pub fn chrome_131() -> Self {
        Self {
            // Cipher suites — Chrome 131 order.
            // TLS 1.3 suites first (4865..4867), then TLS 1.2 (the rest).
            cipher_suites: vec![
                0x1301, // TLS_AES_128_GCM_SHA256
                0x1302, // TLS_AES_256_GCM_SHA384
                0x1303, // TLS_CHACHA20_POLY1305_SHA256
                0xC02B, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
                0xC02F, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                0xC02C, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
                0xC030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
                0xCCA9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
                0xCCA8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
                0xC013, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
                0xC014, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
                0x009C, // TLS_RSA_WITH_AES_128_GCM_SHA256
                0x009D, // TLS_RSA_WITH_AES_256_GCM_SHA384
                0x002F, // TLS_RSA_WITH_AES_128_CBC_SHA
                0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
            ],

            // Extensions — the exact list and order Chrome 131 uses.
            // Each number is the extension type code from the IANA registry.
            extensions: vec![
                0x0000, // server_name (SNI)
                0x0017, // extended_master_secret
                0xFF01, // renegotiation_info
                0x000A, // supported_groups (elliptic curves)
                0x000B, // ec_point_formats
                0x0023, // session_ticket
                0x0010, // application_layer_protocol_negotiation
                0x0005, // status_request (OCSP stapling)
                0x000D, // signature_algorithms
                0x0012, // signed_certificate_timestamp
                0x0033, // key_share
                0x002D, // psk_key_exchange_modes
                0x002B, // supported_versions
                0x001B, // compress_certificate
                0x0015, // padding
            ],

            // Supported elliptic curve groups — x25519 first (Chrome's preference).
            supported_groups: vec![
                29, // x25519
                23, // secp256r1
                24, // secp384r1
            ],

            // ALPN — Chrome prefers HTTP/2 but falls back to HTTP/1.1.
            alpn: vec!["h2".to_string(), "http/1.1".to_string()],

            // Signature algorithms — Chrome 131's supported list.
            // These are "SignatureScheme" values from RFC 8446.
            signature_algorithms: vec![
                0x0403, // ecdsa_secp256r1_sha256
                0x0804, // rsa_pss_rsae_sha256
                0x0401, // rsa_pkcs1_sha256
                0x0503, // ecdsa_secp384r1_sha384
                0x0805, // rsa_pss_rsae_sha384
                0x0501, // rsa_pkcs1_sha384
                0x0806, // rsa_pss_rsae_sha512
                0x0601, // rsa_pkcs1_sha512
            ],
        }
    }

    /// Load a fingerprint profile from a JSON file.
    ///
    /// The JSON format matches `fingerprints/chrome-131.json`.
    pub fn from_json_file(path: &std::path::Path) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(path).map_err(|e| {
            anyhow::anyhow!("failed to read fingerprint file {}: {}", path.display(), e)
        })?;
        // Strip JSON comments (lines starting with "_comment") by pre-processing.
        // A proper JSON parser would reject these — we remove them first.
        let cleaned: String = raw
            .lines()
            .filter(|l| !l.trim_start().starts_with("\"_comment"))
            .collect::<Vec<_>>()
            .join("\n");
        serde_json::from_str(&cleaned)
            .map_err(|e| anyhow::anyhow!("failed to parse fingerprint JSON: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Checks that the Chrome 131 profile has the correct number of cipher suites.
    // Chrome 131 has 15 cipher suites (plus one GREASE added dynamically = 16 total).
    #[test]
    fn chrome_131_cipher_suite_count() {
        let p = FingerprintProfile::chrome_131();
        assert_eq!(
            p.cipher_suites.len(),
            15,
            "Chrome 131 should have 15 static cipher suites (GREASE added dynamically)"
        );
    }

    // Checks that the Chrome 131 profile has the correct number of extensions.
    // Chrome 131 has 15 extensions (plus one GREASE added dynamically).
    #[test]
    fn chrome_131_extension_count() {
        let p = FingerprintProfile::chrome_131();
        assert_eq!(
            p.extensions.len(),
            15,
            "Chrome 131 should have 15 static extensions"
        );
    }

    // Checks that x25519 (group 29) is the first supported group, which is what
    // Chrome uses and what gives best performance.
    #[test]
    fn chrome_131_x25519_first_group() {
        let p = FingerprintProfile::chrome_131();
        assert_eq!(p.supported_groups[0], 29, "x25519 (29) should be first");
    }

    // Checks that ALPN includes h2 before http/1.1 — Chrome prefers HTTP/2.
    #[test]
    fn chrome_131_alpn_h2_first() {
        let p = FingerprintProfile::chrome_131();
        assert_eq!(p.alpn[0], "h2");
        assert_eq!(p.alpn[1], "http/1.1");
    }
}
