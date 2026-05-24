//! QUIC variable-length integer encoding (RFC 9000).

use std::io;
use tokio::io::{AsyncRead, AsyncReadExt};

pub(crate) const MAX_VARINT: u64 = 4_611_686_018_427_387_903;

/// Encode `value` as a QUIC varint into `buf`.
pub(crate) fn write_varint(buf: &mut Vec<u8>, mut value: u64) -> io::Result<()> {
    if value > MAX_VARINT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("varint value out of range: {value}"),
        ));
    }
    if value <= 63 {
        buf.push(value as u8);
        return Ok(());
    }
    if value <= 16_383 {
        value |= 0x4000;
        buf.push((value >> 8) as u8);
        buf.push(value as u8);
        return Ok(());
    }
    if value <= 1_073_741_823 {
        value |= 0x8000_0000;
        buf.push((value >> 24) as u8);
        buf.push((value >> 16) as u8);
        buf.push((value >> 8) as u8);
        buf.push(value as u8);
        return Ok(());
    }
    if value <= MAX_VARINT {
        value |= 0xC000_0000_0000_0000;
        buf.push((value >> 56) as u8);
        buf.push((value >> 48) as u8);
        buf.push((value >> 40) as u8);
        buf.push((value >> 32) as u8);
        buf.push((value >> 24) as u8);
        buf.push((value >> 16) as u8);
        buf.push((value >> 8) as u8);
        buf.push(value as u8);
    }
    Ok(())
}

/// Read one QUIC varint from `r`.
pub(crate) async fn read_varint<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<u64> {
    let first = r.read_u8().await?;
    let len = 1 << (first >> 6);
    if len == 1 {
        return Ok(u64::from(first & 0x3f));
    }
    let mut buf = [0u8; 8];
    r.read_exact(&mut buf[..len - 1]).await?;
    let mut value = u64::from(first & 0x3f);
    for b in &buf[..len - 1] {
        value = (value << 8) | u64::from(*b);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn varint_roundtrip() {
        for value in [0u64, 1, 63, 64, 16_383, 16_384, 0x401] {
            let mut buf = Vec::new();
            write_varint(&mut buf, value).unwrap();
            let mut cursor = std::io::Cursor::new(buf);
            let decoded = read_varint(&mut cursor).await.unwrap();
            assert_eq!(decoded, value);
        }
    }
}
