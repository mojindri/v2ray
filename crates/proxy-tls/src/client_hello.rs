//! Raw TLS ClientHello builder — constructs Chrome-like bytes.
//!
//! REALITY needs a ClientHello that looks like Chrome instead of rustls. This
//! module builds the TLS record manually, while child modules keep extension
//! encoding and wire helpers out of this top-level builder file.

mod extensions;
mod wire;

use bytes::{BufMut, BytesMut};
use rand::{Rng, RngExt};
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::grease::grease_u16;
use crate::profile::FingerprintProfile;
use wire::put_u24;

/// Builds a complete TLS ClientHello that matches the selected fingerprint.
pub struct ClientHelloBuilder {
    pub(super) profile: FingerprintProfile,
}

impl ClientHelloBuilder {
    /// Create a builder using the given fingerprint profile.
    pub fn new(profile: FingerprintProfile) -> Self {
        Self { profile }
    }

    /// Create a builder using the hardcoded Chrome 131 profile.
    pub fn chrome_131() -> Self {
        Self::new(FingerprintProfile::chrome_131())
    }

    /// Build a complete TLS ClientHello record.
    ///
    /// `random` and `session_id` are supplied by REALITY so it can place its
    /// ECDH/HKDF and encrypted-token material into normal TLS fields.
    pub fn build(
        &self,
        sni: &str,
        random: &[u8; 32],
        session_id: &[u8; 32],
        x25519_pub: Option<&[u8; 32]>,
        rng: &mut impl Rng,
    ) -> BytesMut {
        self.build_with_additional_key_share(sni, random, session_id, x25519_pub, None, rng)
    }

    /// Build a ClientHello with an optional additional secp256r1 key share.
    ///
    /// REALITY uses this to offer both x25519 and P-256 on the first flight so
    /// origins that prefer `secp256r1` do not force a HelloRetryRequest.
    pub fn build_with_additional_key_share(
        &self,
        sni: &str,
        random: &[u8; 32],
        session_id: &[u8; 32],
        x25519_pub: Option<&[u8; 32]>,
        secp256r1_pub: Option<&[u8]>,
        rng: &mut impl Rng,
    ) -> BytesMut {
        let grease_cipher = grease_u16(rng);
        let grease_ext = grease_u16(rng);

        // If no x25519 key was supplied, generate one just for key_share.
        let generated;
        let key_bytes: &[u8; 32] = match x25519_pub {
            Some(k) => k,
            None => {
                let secret = EphemeralSecret::random();
                generated = *PublicKey::from(&secret).as_bytes();
                &generated
            }
        };

        let body = self.build_client_hello_body(
            sni,
            random,
            session_id,
            grease_cipher,
            grease_ext,
            key_bytes,
            secp256r1_pub,
        );

        let mut handshake = BytesMut::with_capacity(4 + body.len());
        handshake.put_u8(0x01); // handshake_type = ClientHello
        put_u24(&mut handshake, body.len() as u32);
        handshake.extend_from_slice(&body);

        let mut record = BytesMut::with_capacity(5 + handshake.len());
        record.put_u8(0x16); // content_type = handshake
        record.put_u8(0x03);
        record.put_u8(0x01); // legacy record version = TLS 1.0
        record.put_u16(handshake.len() as u16);
        record.extend_from_slice(&handshake);

        record
    }

    /// Build the ClientHello body, meaning everything after the handshake header.
    #[allow(clippy::too_many_arguments)]
    fn build_client_hello_body(
        &self,
        sni: &str,
        random: &[u8; 32],
        session_id: &[u8; 32],
        grease_cipher: u16,
        grease_ext: u16,
        x25519_pub: &[u8; 32],
        secp256r1_pub: Option<&[u8]>,
    ) -> BytesMut {
        let mut buf = BytesMut::with_capacity(512);

        buf.put_u16(0x0303); // legacy_version = TLS 1.2
        buf.put_slice(random);
        buf.put_u8(0x20); // session_id_len = 32
        buf.put_slice(session_id);

        let cipher_count = 1 + self.profile.cipher_suites.len();
        buf.put_u16((cipher_count * 2) as u16);
        buf.put_u16(grease_cipher);
        for &cs in &self.profile.cipher_suites {
            buf.put_u16(cs);
        }

        buf.put_u8(0x01); // compression_methods length
        buf.put_u8(0x00); // null compression

        let extensions =
            self.build_extensions(sni, grease_cipher, grease_ext, x25519_pub, secp256r1_pub);
        buf.put_u16(extensions.len() as u16);
        buf.extend_from_slice(&extensions);

        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    fn make_rng() -> impl Rng {
        rand::rngs::SmallRng::seed_from_u64(42)
    }
    fn random32() -> [u8; 32] {
        [0xABu8; 32]
    }
    fn session32() -> [u8; 32] {
        [0xCDu8; 32]
    }

    #[test]
    fn client_hello_starts_with_record_header() {
        let mut rng = make_rng();
        let hello = ClientHelloBuilder::chrome_131().build(
            "example.com",
            &random32(),
            &session32(),
            None,
            &mut rng,
        );

        assert_eq!(hello[0], 0x16);
        assert_eq!(hello[1], 0x03);
        assert_eq!(hello[2], 0x01);
    }

    #[test]
    fn handshake_type_is_client_hello() {
        let mut rng = make_rng();
        let hello = ClientHelloBuilder::chrome_131().build(
            "example.com",
            &random32(),
            &session32(),
            None,
            &mut rng,
        );

        assert_eq!(hello[5], 0x01);
    }

    #[test]
    fn random_field_at_correct_offset() {
        let mut rng = make_rng();
        let our_random = [0x42u8; 32];
        let hello = ClientHelloBuilder::chrome_131().build(
            "example.com",
            &our_random,
            &session32(),
            None,
            &mut rng,
        );

        let random_start = 5 + 4 + 2;
        assert_eq!(&hello[random_start..random_start + 32], &our_random);
    }

    #[test]
    fn session_id_at_correct_offset() {
        let mut rng = make_rng();
        let our_session_id = [0x55u8; 32];
        let hello = ClientHelloBuilder::chrome_131().build(
            "example.com",
            &random32(),
            &our_session_id,
            None,
            &mut rng,
        );

        let sid_start = 5 + 4 + 2 + 32 + 1;
        assert_eq!(&hello[sid_start..sid_start + 32], &our_session_id);
    }

    #[test]
    fn sni_hostname_present_in_output() {
        let mut rng = make_rng();
        let hello = ClientHelloBuilder::chrome_131().build(
            "proxy.example.org",
            &random32(),
            &session32(),
            None,
            &mut rng,
        );

        let needle = b"proxy.example.org";
        assert!(hello.windows(needle.len()).any(|w| w == needle));
    }
}

#[cfg(test)]
#[path = "client_hello/hard_tests.rs"]
mod hard_clienthello_tests;
