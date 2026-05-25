use bytes::{BufMut, BytesMut};

use super::wire::put_extension;
use super::ClientHelloBuilder;

impl ClientHelloBuilder {
    /// Build the extensions block without the outer extensions length prefix.
    pub(super) fn build_extensions(
        &self,
        sni: &str,
        grease_group: u16,
        grease_ext: u16,
        x25519_pub: &[u8; 32],
        secp256r1_pub: Option<&[u8]>,
    ) -> BytesMut {
        let mut buf = BytesMut::with_capacity(256);

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
                0x0033 => self.ext_key_share(&mut buf, grease_group, x25519_pub, secp256r1_pub),
                0x002D => self.ext_psk_key_exchange_modes(&mut buf),
                0x002B => self.ext_supported_versions(&mut buf),
                0x001B => self.ext_compress_certificate(&mut buf),
                0x0015 => self.ext_padding(&mut buf),
                // Pass unknown extensions through as empty bodies so the profile
                // list is never silently truncated.  An operator who adds a new
                // extension type to a profile gets a well-formed (zero-length)
                // placeholder rather than a silent omission.
                _ => put_extension(&mut buf, ext_type, &[]),
            }
        }

        // Chrome sends GREASE extensions so servers learn to ignore unknown IDs.
        put_extension(&mut buf, grease_ext, &[0x00, 0x00]);
        buf
    }

    fn ext_server_name(&self, buf: &mut BytesMut, sni: &str) {
        let name_bytes = sni.as_bytes();
        let inner_len = 1 + 2 + name_bytes.len();

        let mut data = BytesMut::new();
        data.put_u16(inner_len as u16);
        data.put_u8(0x00); // host_name
        data.put_u16(name_bytes.len() as u16);
        data.put_slice(name_bytes);

        put_extension(buf, 0x0000, &data);
    }

    fn ext_extended_master_secret(&self, buf: &mut BytesMut) {
        put_extension(buf, 0x0017, &[]);
    }

    fn ext_renegotiation_info(&self, buf: &mut BytesMut) {
        put_extension(buf, 0xFF01, &[0x00]);
    }

    fn ext_supported_groups(&self, buf: &mut BytesMut, grease_group: u16) {
        let total_groups = 1 + self.profile.supported_groups.len();
        let mut data = BytesMut::new();
        data.put_u16((total_groups * 2) as u16);
        data.put_u16(grease_group);
        for &g in &self.profile.supported_groups {
            data.put_u16(g);
        }

        put_extension(buf, 0x000A, &data);
    }

    fn ext_ec_point_formats(&self, buf: &mut BytesMut) {
        put_extension(buf, 0x000B, &[0x01, 0x00]);
    }

    fn ext_session_ticket(&self, buf: &mut BytesMut) {
        put_extension(buf, 0x0023, &[]);
    }

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

    fn ext_status_request(&self, buf: &mut BytesMut) {
        put_extension(buf, 0x0005, &[0x01, 0x00, 0x00, 0x00, 0x00]);
    }

    fn ext_signature_algorithms(&self, buf: &mut BytesMut) {
        let mut data = BytesMut::new();
        data.put_u16((self.profile.signature_algorithms.len() * 2) as u16);
        for &alg in &self.profile.signature_algorithms {
            data.put_u16(alg);
        }
        put_extension(buf, 0x000D, &data);
    }

    fn ext_signed_cert_timestamp(&self, buf: &mut BytesMut) {
        put_extension(buf, 0x0012, &[]);
    }

    fn ext_key_share(
        &self,
        buf: &mut BytesMut,
        grease_group: u16,
        x25519_pub: &[u8; 32],
        secp256r1_pub: Option<&[u8]>,
    ) {
        let mut client_shares = BytesMut::new();

        // GREASE key share, then the real x25519 share used by REALITY ECDH.
        client_shares.put_u16(grease_group);
        client_shares.put_u16(1);
        client_shares.put_u8(0x00);
        client_shares.put_u16(29); // x25519 named group
        client_shares.put_u16(32);
        client_shares.put_slice(x25519_pub);
        if let Some(pubkey) = secp256r1_pub {
            client_shares.put_u16(23); // secp256r1 named group
            client_shares.put_u16(pubkey.len() as u16);
            client_shares.put_slice(pubkey);
        }

        let mut data = BytesMut::new();
        data.put_u16(client_shares.len() as u16);
        data.extend_from_slice(&client_shares);
        put_extension(buf, 0x0033, &data);
    }

    fn ext_psk_key_exchange_modes(&self, buf: &mut BytesMut) {
        put_extension(buf, 0x002D, &[0x01, 0x01]);
    }

    fn ext_supported_versions(&self, buf: &mut BytesMut) {
        put_extension(
            buf,
            0x002B,
            &[
                0x08, 0x7A, 0x7A, // GREASE
                0x03, 0x04, // TLS 1.3
                0x03, 0x03, // TLS 1.2
                0x03, 0x02, // TLS 1.1 compatibility
            ],
        );
    }

    fn ext_compress_certificate(&self, buf: &mut BytesMut) {
        // RFC 8879: a u8 length prefix followed by 2-byte algorithm IDs.
        // Chrome advertises Brotli (0x0002) here.
        put_extension(buf, 0x001B, &[0x02, 0x00, 0x02]);
    }

    fn ext_padding(&self, buf: &mut BytesMut) {
        put_extension(buf, 0x0015, &[0x00]);
    }
}
