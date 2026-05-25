use std::io;

use aes_gcm::{
    aead::{generic_array::GenericArray, Aead, Payload},
    Aes256Gcm, KeyInit,
};
use bytes::{Bytes, BytesMut};

fn make_nonce(counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&counter.to_be_bytes());
    nonce
}

/// Try to decrypt one SS-2022 chunk from raw bytes using a fixed subkey.
///
/// This mirrors the stream decoder logic without needing an async transport.
pub fn try_decrypt_chunk_for_fuzz(
    subkey: &[u8; 32],
    raw: &[u8],
) -> Result<Option<Bytes>, io::Error> {
    let cipher = Aes256Gcm::new(GenericArray::from_slice(subkey));
    let src = BytesMut::from(raw);

    if src.len() < 18 {
        return Ok(None);
    }

    let len_ct = &src[..18];
    let len_pt = cipher
        .decrypt(GenericArray::from_slice(&make_nonce(0)), len_ct)
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "SS-2022: length field decryption failed",
            )
        })?;

    if len_pt.len() < 2 {
        return Ok(None);
    }

    let data_len = u16::from_be_bytes([len_pt[0], len_pt[1]]) as usize;
    if data_len == 0 {
        return Ok(Some(Bytes::new()));
    }

    let total_len = 18 + data_len + 16;
    if src.len() < total_len {
        return Ok(None);
    }

    let data_ct = &src[18..total_len];
    let plaintext = cipher
        .decrypt(
            GenericArray::from_slice(&make_nonce(1)),
            Payload {
                msg: data_ct,
                aad: &[],
            },
        )
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "SS-2022: data chunk decryption failed",
            )
        })?;

    Ok(Some(Bytes::from(plaintext)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_input_reports_incomplete() {
        let subkey = [0x11u8; 32];
        assert!(try_decrypt_chunk_for_fuzz(&subkey, &[1, 2, 3])
            .unwrap()
            .is_none());
    }
}
