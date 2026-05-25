use bytes::{BufMut, BytesMut};

/// Write a TLS extension into `buf`.
pub(super) fn put_extension(buf: &mut BytesMut, ext_type: u16, data: &[u8]) {
    buf.put_u16(ext_type);
    buf.put_u16(data.len() as u16);
    buf.put_slice(data);
}

/// Write a 24-bit big-endian integer into `buf`.
///
/// TLS handshake lengths are 3 bytes, not the usual 2 or 4.
pub(super) fn put_u24(buf: &mut BytesMut, v: u32) {
    buf.put_u8((v >> 16) as u8);
    buf.put_u8((v >> 8) as u8);
    buf.put_u8(v as u8);
}
