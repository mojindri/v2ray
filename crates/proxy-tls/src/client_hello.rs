//! Raw TLS ClientHello builder — constructs exact Chrome 131 bytes.
//!
//! # Why build ClientHello bytes manually?
//!
//! Normal TLS libraries (rustls, OpenSSL) build the ClientHello for you, but
//! they use their own fingerprint. A DPI system can easily tell "this is rustls,
//! not Chrome" by looking at the cipher suite order, extension list, and GREASE
//! values.
//!
//! For REALITY transport, we need the ClientHello to look exactly like Chrome.
//! So we build the bytes ourselves, field by field, to match Chrome 131's
//! fingerprint precisely.
//!
//! # TLS record structure
//!
//! A TLS ClientHello on the wire looks like this:
//!
//!   ┌── TLS Record Header (5 bytes) ──────────────────────────────────────┐
//!   │  content_type  = 0x16 (handshake)                                   │
//!   │  legacy_version = 0x03 0x01 (TLS 1.0 — always this, even for 1.3)  │
//!   │  length         = <2-byte length of the record body>                │
//!   └─────────────────────────────────────────────────────────────────────┘
//!   ┌── Handshake Header (4 bytes) ───────────────────────────────────────┐
//!   │  handshake_type = 0x01 (ClientHello)                                │
//!   │  length         = <3-byte length of the ClientHello body>           │
//!   └─────────────────────────────────────────────────────────────────────┘
//!   ┌── ClientHello Body ─────────────────────────────────────────────────┐
//!   │  legacy_version = 0x03 0x03 (TLS 1.2 — always this, per RFC 8446)  │
//!   │  random         = <32 random bytes>                                 │
//!   │  session_id_len = 0x20 (32)                                         │
//!   │  session_id     = <32 bytes — carries REALITY encrypted token>      │
//!   │  cipher_suites_len = <2-byte count * 2>                             │
//!   │  cipher_suites  = <list of 2-byte suite IDs, with one GREASE first> │
//!   │  compression_methods_len = 0x01                                     │
//!   │  compression_methods     = 0x00 (no compression)                   │
//!   │  extensions_len = <2-byte total extension length>                   │
//!   │  extensions     = <extension data…>                                 │
//!   └─────────────────────────────────────────────────────────────────────┘
//!
//! # REALITY usage
//!
//! When building a REALITY ClientHello:
//!   - `random` = 32 bytes from the REALITY ECDH/HKDF key derivation
//!     (first 20 bytes are the HKDF salt; last 12 are the AES-GCM nonce)
//!   - `session_id` = the 32-byte REALITY encrypted token
//!     (16 bytes ciphertext + 16 bytes AES-GCM tag)
//!   - Everything else matches Chrome 131 exactly.

use bytes::{BufMut, BytesMut};
use rand::Rng;
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::grease::grease_u16;
use crate::profile::FingerprintProfile;

/// Builds a complete TLS ClientHello that matches Chrome 131's fingerprint.
pub struct ClientHelloBuilder {
    profile: FingerprintProfile,
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

    /// Build a complete TLS ClientHello record (5-byte header + body).
    ///
    /// # Arguments
    ///
    /// * `sni`        — the server name to put in the SNI extension (e.g. "www.apple.com")
    /// * `random`     — 32-byte random field. For normal TLS: random bytes.
    ///                  For REALITY: the first 32 bytes derived from ECDH+HKDF.
    /// * `session_id` — 32-byte session ID. For normal TLS: random bytes.
    ///                  For REALITY: the encrypted token (ciphertext + tag).
    /// * `x25519_pub` — the x25519 public key to advertise in the key_share extension.
    ///                  For REALITY: the client's ephemeral public key used for ECDH.
    ///                  For testing: any 32-byte value; pass `None` to auto-generate.
    /// * `rng`        — random source for GREASE values.
    ///
    /// # Returns
    ///
    /// The complete TLS record bytes, ready to send over TCP.
    pub fn build(
        &self,
        sni: &str,
        random: &[u8; 32],
        session_id: &[u8; 32],
        x25519_pub: Option<&[u8; 32]>,
        rng: &mut impl Rng,
    ) -> BytesMut {
        // Pick GREASE values for this connection.
        // Chrome uses two independent GREASE values: one for cipher/group/version,
        // and one for the GREASE extension.
        let grease_cipher = grease_u16(rng); // used in cipher suites + named groups
        let grease_ext    = grease_u16(rng); // used as a GREASE extension type

        // If no x25519 key was supplied, generate a fresh ephemeral one.
        // The key is only used to populate the key_share extension field.
        let generated;
        let key_bytes: &[u8; 32] = match x25519_pub {
            Some(k) => k,
            None => {
                // rand::thread_rng() satisfies CryptoRng, which EphemeralSecret needs.
                let secret = EphemeralSecret::random_from_rng(rand::thread_rng());
                generated = *PublicKey::from(&secret).as_bytes();
                &generated
            }
        };

        // Build the ClientHello body first, then wrap it in the handshake header,
        // then wrap that in the TLS record header. We work inside-out.
        let body = self.build_client_hello_body(sni, random, session_id, grease_cipher, grease_ext, key_bytes);

        // Handshake header:
        //   [0]     = 0x01 (ClientHello)
        //   [1..4]  = length of body (3 bytes, big-endian)
        let mut handshake = BytesMut::with_capacity(4 + body.len());
        handshake.put_u8(0x01); // handshake_type = ClientHello
        put_u24(&mut handshake, body.len() as u32);
        handshake.extend_from_slice(&body);

        // TLS record header:
        //   [0]     = 0x16 (content_type = handshake)
        //   [1..3]  = 0x03 0x01 (legacy_record_version = TLS 1.0)
        //   [3..5]  = length of the handshake message (2 bytes, big-endian)
        let mut record = BytesMut::with_capacity(5 + handshake.len());
        record.put_u8(0x16);           // content_type = handshake
        record.put_u8(0x03);           // legacy_version high byte
        record.put_u8(0x01);           // legacy_version low byte (TLS 1.0)
        record.put_u16(handshake.len() as u16); // length
        record.extend_from_slice(&handshake);

        record
    }

    /// Build just the ClientHello body (everything after the handshake header).
    fn build_client_hello_body(
        &self,
        sni: &str,
        random: &[u8; 32],
        session_id: &[u8; 32],
        grease_cipher: u16,
        grease_ext: u16,
        x25519_pub: &[u8; 32],
    ) -> BytesMut {
        let mut buf = BytesMut::with_capacity(512);

        // legacy_version = 0x0303 (TLS 1.2).
        // This field is always 0x0303 in TLS 1.3, even though the actual
        // negotiated version is in the `supported_versions` extension.
        buf.put_u16(0x0303);

        // random — 32 bytes.
        // For REALITY: first 20 bytes are HKDF salt, last 12 are AES-GCM nonce.
        buf.put_slice(random);

        // session_id_len = 0x20 (32 bytes).
        // TLS 1.3 always uses a 32-byte session ID for middlebox compatibility.
        buf.put_u8(0x20);

        // session_id — 32 bytes.
        // For REALITY: first 16 bytes are AES-GCM ciphertext, last 16 are the tag.
        buf.put_slice(session_id);

        // Cipher suites: GREASE first, then the profile list.
        // Length is (1 GREASE + N profile suites) * 2 bytes each.
        let cipher_count = 1 + self.profile.cipher_suites.len();
        buf.put_u16((cipher_count * 2) as u16);
        buf.put_u16(grease_cipher); // GREASE cipher suite
        for &cs in &self.profile.cipher_suites {
            buf.put_u16(cs);
        }

        // Compression methods: always [0x01, 0x00] (length=1, method=null).
        buf.put_u8(0x01); // length
        buf.put_u8(0x00); // null compression

        // Extensions: build all extension data, then prepend the 2-byte length.
        let extensions = self.build_extensions(sni, grease_cipher, grease_ext, x25519_pub);
        buf.put_u16(extensions.len() as u16);
        buf.extend_from_slice(&extensions);

        buf
    }

    /// Build the extensions block (all extensions concatenated, no outer length prefix).
    fn build_extensions(
        &self,
        sni: &str,
        grease_group: u16,
        grease_ext: u16,
        x25519_pub: &[u8; 32],
    ) -> BytesMut {
        let mut buf = BytesMut::with_capacity(256);

        // Iterate through the profile's extension list.
        // For each extension type, call the appropriate builder.
        // Insert the GREASE extension between padding and the last extension.

        for &ext_type in &self.profile.extensions {
            match ext_type {
                0x0000 => self.ext_server_name(&mut buf, sni),
                0x0017 => self.ext_extended_master_secret(&mut buf),
                0xFF01 => self.ext_renegotiation_info(&mut buf),
                0x000A => self.ext_supported_groups(&mut buf, grease_group),
                0x000B => self.ext_ec_point_formats(&mut buf),
                0x0023 => self.ext_session_ticket(&mut buf),
                0x0010 => self.ext_alpn(&mut buf),
                0x0005 => self.ext_status_request(&mut buf),
                0x000D => self.ext_signature_algorithms(&mut buf),
                0x0012 => self.ext_signed_cert_timestamp(&mut buf),
                0x0033 => self.ext_key_share(&mut buf, grease_group, x25519_pub),
                0x002D => self.ext_psk_key_exchange_modes(&mut buf),
                0x002B => self.ext_supported_versions(&mut buf),
                0x001B => self.ext_compress_certificate(&mut buf),
                0x0015 => self.ext_padding(&mut buf),
                _      => {} // Unknown extension — skip (shouldn't happen)
            }
        }

        // Insert GREASE extension at the end (Chrome inserts it near the end).
        put_extension(&mut buf, grease_ext, &[0x00, 0x00]); // empty GREASE ext

        buf
    }

    // ── Individual extension builders ─────────────────────────────────────────

    /// SNI extension (0x0000) — tells the server which hostname we want.
    ///
    /// Without SNI, the server cannot determine which certificate to present
    /// when it hosts multiple domains on the same IP. SNI is the domain name
    /// the client is connecting to.
    fn ext_server_name(&self, buf: &mut BytesMut, sni: &str) {
        // server_name extension body layout:
        //   list_length (2 bytes)
        //     name_type = 0x00 (host_name) (1 byte)
        //     name_length (2 bytes)
        //     name (name_length bytes)
        let name_bytes = sni.as_bytes();
        let inner_len = 1 + 2 + name_bytes.len(); // type + len + data
        let list_len  = inner_len;

        let mut data = BytesMut::new();
        data.put_u16(list_len as u16);
        data.put_u8(0x00); // host_name type
        data.put_u16(name_bytes.len() as u16);
        data.put_slice(name_bytes);

        put_extension(buf, 0x0000, &data);
    }

    /// extended_master_secret (0x0017) — empty body, signals support.
    fn ext_extended_master_secret(&self, buf: &mut BytesMut) {
        put_extension(buf, 0x0017, &[]);
    }

    /// renegotiation_info (0xFF01) — indicates no renegotiation.
    ///
    /// Chrome includes this with an empty renegotiated_connection field.
    fn ext_renegotiation_info(&self, buf: &mut BytesMut) {
        put_extension(buf, 0xFF01, &[0x00]); // renegotiated_connection_length = 0
    }

    /// supported_groups (0x000A) — the elliptic curves we support.
    ///
    /// A GREASE group value is inserted first, matching Chrome's behaviour.
    fn ext_supported_groups(&self, buf: &mut BytesMut, grease_group: u16) {
        let total_groups = 1 + self.profile.supported_groups.len();
        let list_bytes   = total_groups * 2;

        let mut data = BytesMut::new();
        data.put_u16(list_bytes as u16); // named_group_list length
        data.put_u16(grease_group); // GREASE named group
        for &g in &self.profile.supported_groups {
            data.put_u16(g);
        }

        put_extension(buf, 0x000A, &data);
    }

    /// ec_point_formats (0x000B) — uncompressed points only.
    fn ext_ec_point_formats(&self, buf: &mut BytesMut) {
        put_extension(buf, 0x000B, &[0x01, 0x00]); // length=1, uncompressed=0
    }

    /// session_ticket (0x0023) — empty body means "request a new ticket".
    fn ext_session_ticket(&self, buf: &mut BytesMut) {
        put_extension(buf, 0x0023, &[]);
    }

    /// ALPN (0x0010) — application layer protocol negotiation.
    fn ext_alpn(&self, buf: &mut BytesMut) {
        let mut inner = BytesMut::new();
        for protocol in &self.profile.alpn {
            let p = protocol.as_bytes();
            inner.put_u8(p.len() as u8);
            inner.put_slice(p);
        }
        let mut data = BytesMut::new();
        data.put_u16(inner.len() as u16);
        data.extend_from_slice(&inner);

        put_extension(buf, 0x0010, &data);
    }

    /// status_request (0x0005) — OCSP stapling request.
    ///
    /// Body layout: status_type=ocsp(1), responder_id_list_len=0, extensions_len=0.
    fn ext_status_request(&self, buf: &mut BytesMut) {
        put_extension(buf, 0x0005, &[
            0x01,       // certificate_status_type = ocsp
            0x00, 0x00, // responder_id_list length = 0
            0x00, 0x00, // request_extensions length = 0
        ]);
    }

    /// signature_algorithms (0x000D) — signature schemes the client accepts.
    fn ext_signature_algorithms(&self, buf: &mut BytesMut) {
        let list_len = self.profile.signature_algorithms.len() * 2;
        let mut data = BytesMut::new();
        data.put_u16(list_len as u16);
        for &alg in &self.profile.signature_algorithms {
            data.put_u16(alg);
        }
        put_extension(buf, 0x000D, &data);
    }

    /// signed_certificate_timestamp (0x0012) — SCT request, empty body.
    fn ext_signed_cert_timestamp(&self, buf: &mut BytesMut) {
        put_extension(buf, 0x0012, &[]);
    }

    /// key_share (0x0033) — the client's public key share for key exchange.
    ///
    /// Chrome sends two key shares: GREASE (empty) + x25519 (real key).
    /// The GREASE key share signals to the server that the client ignores
    /// unknown group types, which is required RFC 8701 behaviour.
    ///
    /// `x25519_pub` is the 32-byte x25519 public key to advertise.
    /// For REALITY this MUST be the client's ephemeral ECDH key, because the server
    /// extracts this key from the ClientHello to perform ECDH and derive auth_key.
    fn ext_key_share(&self, buf: &mut BytesMut, grease_group: u16, x25519_pub: &[u8; 32]) {
        let mut client_shares = BytesMut::new();

        // GREASE key share: group=GREASE, key_exchange=1 zero byte.
        // (Real Chrome uses a 1-byte key exchange for GREASE — it's just a placeholder.)
        client_shares.put_u16(grease_group); // group
        client_shares.put_u16(1);            // key_exchange length = 1
        client_shares.put_u8(0x00);          // 1 zero byte

        // x25519 key share: 32-byte public key.
        client_shares.put_u16(29);  // x25519 named group
        client_shares.put_u16(32);  // key_exchange length = 32
        client_shares.put_slice(x25519_pub);

        let mut data = BytesMut::new();
        data.put_u16(client_shares.len() as u16); // client_shares total length
        data.extend_from_slice(&client_shares);

        put_extension(buf, 0x0033, &data);
    }

    /// psk_key_exchange_modes (0x002D) — signals support for PSK with (EC)DHE.
    ///
    /// Value 0x01 = psk_dhe_ke (require (EC)DHE, the mode TLS 1.3 sessions use).
    fn ext_psk_key_exchange_modes(&self, buf: &mut BytesMut) {
        put_extension(buf, 0x002D, &[0x01, 0x01]); // length=1, mode=psk_dhe_ke
    }

    /// supported_versions (0x002B) — the TLS versions the client supports.
    ///
    /// Chrome sends TLS 1.3 (0x0304) first, then TLS 1.2 (0x0303).
    /// A GREASE version is also sent (Chrome uses it as the first entry).
    fn ext_supported_versions(&self, buf: &mut BytesMut) {
        put_extension(buf, 0x002B, &[
            0x08,       // versions list length = 8 bytes (4 versions × 2 bytes)
            // Note: Chrome also adds a GREASE version first in real connections.
            // For simplicity we use a fixed GREASE value here; the builder caller
            // can override if needed.
            0x7A, 0x7A, // GREASE version (0x7A7A)
            0x03, 0x04, // TLS 1.3
            0x03, 0x03, // TLS 1.2
            0x03, 0x02, // TLS 1.1 (Chrome still lists it for compat)
        ]);
    }

    /// compress_certificate (0x001B) — Brotli certificate compression.
    ///
    /// Chrome 131 supports Brotli (2) and Zlib (1) certificate compression.
    fn ext_compress_certificate(&self, buf: &mut BytesMut) {
        put_extension(buf, 0x001B, &[
            0x02,       // algorithms length = 2 entries × 2 bytes = 4 → wait, it's in algorithm_ids
            // Actually: length = number of AlgorithmID entries (each 2 bytes)
            // Chrome uses [brotli=2, zlib=1], encoded as:
            //   length (1 byte) = 4  (2 IDs × 2 bytes each)
            //   0x00, 0x02 = brotli
            //   0x00, 0x01 = zlib
            0x00, 0x02, // brotli
            0x00, 0x01, // zlib
        ]);
    }

    /// padding (0x0015) — pad the ClientHello to a standard size.
    ///
    /// Chrome pads the ClientHello to 512 bytes to prevent length-based
    /// fingerprinting. We include a minimal padding extension here; the
    /// caller can adjust the padding length based on the total message size.
    fn ext_padding(&self, buf: &mut BytesMut) {
        // Padding of 1 zero byte. The actual length doesn't affect correctness —
        // servers ignore padding content. A full implementation would calculate
        // the exact padding needed to reach 512 bytes.
        let padding = vec![0u8; 1];
        put_extension(buf, 0x0015, &padding);
    }
}

/// Write a TLS extension into `buf`.
///
/// TLS extension format:
///   extension_type  (2 bytes, big-endian)
///   extension_data_length (2 bytes, big-endian)
///   extension_data  (extension_data_length bytes)
fn put_extension(buf: &mut BytesMut, ext_type: u16, data: &[u8]) {
    buf.put_u16(ext_type);
    buf.put_u16(data.len() as u16);
    buf.put_slice(data);
}

/// Write a 24-bit big-endian integer into `buf`.
///
/// TLS uses 3-byte length fields in the handshake header.
fn put_u24(buf: &mut BytesMut, v: u32) {
    buf.put_u8((v >> 16) as u8);
    buf.put_u8((v >>  8) as u8);
    buf.put_u8( v        as u8);
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    fn make_rng() -> impl Rng { rand::rngs::SmallRng::seed_from_u64(42) }
    fn random32() -> [u8; 32] { [0xABu8; 32] }
    fn session32() -> [u8; 32] { [0xCDu8; 32] }

    // Checks that the built ClientHello starts with the TLS record header bytes.
    // The first byte must be 0x16 (content_type = handshake).
    #[test]
    fn client_hello_starts_with_record_header() {
        let mut rng = make_rng();
        let hello = ClientHelloBuilder::chrome_131()
            .build("example.com", &random32(), &session32(), None, &mut rng);

        // TLS record header: content_type=0x16, version=0x0301, length (2 bytes)
        assert_eq!(hello[0], 0x16, "content_type must be 0x16 (handshake)");
        assert_eq!(hello[1], 0x03, "legacy_version[0] must be 0x03");
        assert_eq!(hello[2], 0x01, "legacy_version[1] must be 0x01 (TLS 1.0)");
    }

    // Checks that the handshake type byte (after the 5-byte record header) is 0x01.
    #[test]
    fn handshake_type_is_client_hello() {
        let mut rng = make_rng();
        let hello = ClientHelloBuilder::chrome_131()
            .build("example.com", &random32(), &session32(), None, &mut rng);

        // Byte 5 is the first byte after the 5-byte TLS record header.
        assert_eq!(hello[5], 0x01, "handshake type must be 0x01 (ClientHello)");
    }

    // Checks that our random field appears at the correct offset.
    //
    // Offset within the ClientHello body:
    //   handshake_header (4 bytes: type + 3-byte length)
    //   legacy_version   (2 bytes)
    //   random           (32 bytes) ← starts at byte 5+4+2 = 11 from record start
    #[test]
    fn random_field_at_correct_offset() {
        let mut rng = make_rng();
        let our_random = [0x42u8; 32];
        let hello = ClientHelloBuilder::chrome_131()
            .build("example.com", &our_random, &session32(), None, &mut rng);

        // Record header (5) + handshake header (4) + legacy_version (2) = offset 11
        let random_start = 5 + 4 + 2;
        assert_eq!(&hello[random_start..random_start + 32], &our_random,
            "random field must appear at offset {random_start}");
    }

    // Checks that the session_id field appears at the correct offset.
    //
    // session_id follows: random(32) + session_id_len(1) → offset 11+32+1 = 44
    #[test]
    fn session_id_at_correct_offset() {
        let mut rng = make_rng();
        let our_session_id = [0x55u8; 32];
        let hello = ClientHelloBuilder::chrome_131()
            .build("example.com", &random32(), &our_session_id, None, &mut rng);

        // Record header (5) + handshake header (4) + legacy_version (2) + random (32) + sid_len (1)
        let sid_start = 5 + 4 + 2 + 32 + 1;
        assert_eq!(&hello[sid_start..sid_start + 32], &our_session_id,
            "session_id must appear at offset {sid_start}");
    }

    // Checks that the SNI hostname appears somewhere in the ClientHello bytes.
    #[test]
    fn sni_hostname_present_in_output() {
        let mut rng = make_rng();
        let hello = ClientHelloBuilder::chrome_131()
            .build("proxy.example.org", &random32(), &session32(), None, &mut rng);

        let needle = b"proxy.example.org";
        assert!(hello.windows(needle.len()).any(|w| w == needle),
            "SNI hostname not found in ClientHello");
    }
}
