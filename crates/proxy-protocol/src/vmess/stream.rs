//! VMess data channel stream — VMess chunked body framing.
//!
//! Chunk wire format (each direction independently):
//! ```text
//! size(2) | encrypted_or_plain_payload(size)
//! ```
//! Size is either plain big-endian or SHAKE-masked when ChunkMasking is set.
//! AEAD payload nonces use `counter_be_u16 || iv[2..12]` and increment once
//! per payload, matching Xray's VMess body reader/writer.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use aes_gcm::{
    aead::{generic_array::GenericArray, Aead, Payload},
    Aes128Gcm, KeyInit,
};
use bytes::{Bytes, BytesMut};
use chacha20poly1305::ChaCha20Poly1305;
use md5::{Digest as Md5Digest, Md5};
use rand::RngCore;
use sha3_010::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake128,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use proxy_common::BoxedStream;

use super::codec::Security;

const MAX_CHUNK_SIZE: usize = 16 * 1024;
pub const REQUEST_OPTION_CHUNK_MASKING: u8 = 0x04;
pub const REQUEST_OPTION_GLOBAL_PADDING: u8 = 0x08;

fn chunk_nonce(counter: u16, iv: &[u8; 16]) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[0..2].copy_from_slice(&counter.to_be_bytes());
    nonce[2..12].copy_from_slice(&iv[2..12]);
    nonce
}

enum BodyCipher {
    Aes128Gcm(Box<Aes128Gcm>),
    ChaCha20Poly1305(Box<ChaCha20Poly1305>),
    None,
}

impl BodyCipher {
    fn new(security: Security, key: &[u8; 16]) -> Self {
        match security {
            Security::Aes128Gcm => {
                Self::Aes128Gcm(Box::new(Aes128Gcm::new(GenericArray::from_slice(key))))
            }
            Security::ChaCha20Poly1305 => Self::ChaCha20Poly1305(Box::new(ChaCha20Poly1305::new(
                GenericArray::from_slice(&chacha_key(key)),
            ))),
            Security::None => Self::None,
        }
    }

    fn overhead(&self) -> usize {
        match self {
            Self::Aes128Gcm(_) | Self::ChaCha20Poly1305(_) => 16,
            Self::None => 0,
        }
    }

    fn encrypt(&self, nonce: &[u8; 12], data: &[u8]) -> Result<Vec<u8>, ()> {
        match self {
            Self::Aes128Gcm(cipher) => cipher
                .encrypt(
                    GenericArray::from_slice(nonce),
                    Payload {
                        msg: data,
                        aad: &[],
                    },
                )
                .map_err(|_| ()),
            Self::ChaCha20Poly1305(cipher) => cipher
                .encrypt(
                    GenericArray::from_slice(nonce),
                    Payload {
                        msg: data,
                        aad: &[],
                    },
                )
                .map_err(|_| ()),
            Self::None => Ok(data.to_vec()),
        }
    }

    fn decrypt(&self, nonce: &[u8; 12], data: &[u8]) -> Result<Vec<u8>, ()> {
        match self {
            Self::Aes128Gcm(cipher) => cipher
                .decrypt(
                    GenericArray::from_slice(nonce),
                    Payload {
                        msg: data,
                        aad: &[],
                    },
                )
                .map_err(|_| ()),
            Self::ChaCha20Poly1305(cipher) => cipher
                .decrypt(
                    GenericArray::from_slice(nonce),
                    Payload {
                        msg: data,
                        aad: &[],
                    },
                )
                .map_err(|_| ()),
            Self::None => Ok(data.to_vec()),
        }
    }
}

fn chacha_key(key: &[u8; 16]) -> [u8; 32] {
    let first = Md5::digest(key);
    let second = Md5::digest(first);
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&first);
    out[16..].copy_from_slice(&second);
    out
}

struct SizeMask {
    reader: Box<dyn XofReader + Send + Sync>,
}

impl SizeMask {
    fn new(iv: &[u8; 16]) -> Self {
        let mut shake = Shake128::default();
        shake.update(iv);
        Self {
            reader: Box::new(shake.finalize_xof()),
        }
    }

    fn next(&mut self) -> u16 {
        let mut buf = [0u8; 2];
        self.reader.read(&mut buf);
        u16::from_be_bytes(buf)
    }
}

/// VMess AEAD chunk stream with independent read and write ciphers.
///
/// - `new()`: same key/iv both directions (blackwire ↔ blackwire)
/// - `new_bidir()`: separate keys — use this when one peer is xray/sing-box
pub struct VmessStream {
    inner: BoxedStream,

    read_cipher: BodyCipher,
    read_iv: [u8; 16],
    read_counter: u16,
    read_size_mask: Option<SizeMask>,
    read_global_padding: bool,
    read_buf: BytesMut,
    read_raw_buf: BytesMut,

    write_cipher: BodyCipher,
    write_iv: [u8; 16],
    write_counter: u16,
    write_size_mask: Option<SizeMask>,
    write_global_padding: bool,
    write_buf: BytesMut,
}

impl VmessStream {
    /// Same key/iv for both directions (internal blackwire use).
    pub fn new(inner: BoxedStream, key: &[u8; 16], iv: &[u8; 16]) -> Self {
        Self::new_bidir(inner, key, iv, key, iv, Security::Aes128Gcm, 0)
    }

    /// Separate keys for each direction.
    ///
    /// - Server inbound: `read_key = request_key`, `write_key = response_key`
    /// - Client outbound: `read_key = response_key`, `write_key = request_key`
    pub fn new_bidir(
        inner: BoxedStream,
        read_key: &[u8; 16],
        read_iv: &[u8; 16],
        write_key: &[u8; 16],
        write_iv: &[u8; 16],
        security: Security,
        options: u8,
    ) -> Self {
        let chunk_masking = options & REQUEST_OPTION_CHUNK_MASKING != 0;
        Self {
            inner,
            read_cipher: BodyCipher::new(security, read_key),
            read_iv: *read_iv,
            read_counter: 0,
            read_size_mask: chunk_masking.then(|| SizeMask::new(read_iv)),
            read_global_padding: options & REQUEST_OPTION_GLOBAL_PADDING != 0,
            read_buf: BytesMut::new(),
            read_raw_buf: BytesMut::new(),
            write_cipher: BodyCipher::new(security, write_key),
            write_iv: *write_iv,
            write_counter: 0,
            write_size_mask: chunk_masking.then(|| SizeMask::new(write_iv)),
            write_global_padding: options & REQUEST_OPTION_GLOBAL_PADDING != 0,
            write_buf: BytesMut::new(),
        }
    }

    fn next_read_padding_len(&mut self) -> usize {
        if !self.read_global_padding {
            return 0;
        }
        self.read_size_mask
            .as_mut()
            .map(|mask| (mask.next() % 64) as usize)
            .unwrap_or(0)
    }

    fn next_write_padding_len(&mut self) -> usize {
        if !self.write_global_padding {
            return 0;
        }
        self.write_size_mask
            .as_mut()
            .map(|mask| (mask.next() % 64) as usize)
            .unwrap_or(0)
    }

    fn decode_size(&mut self, bytes: [u8; 2]) -> usize {
        let encoded = u16::from_be_bytes(bytes);
        let decoded = match &mut self.read_size_mask {
            Some(mask) => encoded ^ mask.next(),
            None => encoded,
        };
        decoded as usize
    }

    fn encode_size(&mut self, size: usize) -> [u8; 2] {
        let mut encoded = size as u16;
        if let Some(mask) = &mut self.write_size_mask {
            encoded ^= mask.next();
        }
        encoded.to_be_bytes()
    }

    fn try_decrypt_chunk(&mut self, src: &mut BytesMut) -> Option<Result<Bytes, io::Error>> {
        if src.len() < 2 {
            return None;
        }

        let encoded_size = [src[0], src[1]];
        let padding_len = self.next_read_padding_len();
        let size = self.decode_size(encoded_size);
        let overhead = self.read_cipher.overhead();

        if size == overhead + padding_len {
            let _ = src.split_to(2);
            if padding_len > 0 && src.len() >= padding_len {
                let _ = src.split_to(padding_len);
            }
            return Some(Ok(Bytes::new()));
        }

        if size < overhead + padding_len {
            return Some(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "VMess: body chunk size smaller than authentication tag",
            )));
        }

        let total = 2 + size;
        if src.len() < total {
            return None;
        }

        let _ = src.split_to(2);
        let data_ct = src.split_to(size - padding_len);
        if padding_len > 0 {
            let _ = src.split_to(padding_len);
        }
        let data_nonce = chunk_nonce(self.read_counter, &self.read_iv);

        let plaintext = match self.read_cipher.decrypt(&data_nonce, &data_ct) {
            Ok(pt) => pt,
            Err(_) => {
                return Some(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "VMess: data chunk decryption failed",
                )));
            }
        };
        self.read_counter = self.read_counter.wrapping_add(1);

        Some(Ok(Bytes::from(plaintext)))
    }

    fn encrypt_chunk(&mut self, data: &[u8]) -> io::Result<Vec<u8>> {
        let nonce_arr = chunk_nonce(self.write_counter, &self.write_iv);
        let data_ct = self.write_cipher.encrypt(&nonce_arr, data).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "VMess: body chunk encrypt failed",
            )
        })?;
        self.write_counter = self.write_counter.wrapping_add(1);

        let padding_len = self.next_write_padding_len();
        let size = self.encode_size(data_ct.len() + padding_len);
        let mut out = Vec::with_capacity(size.len() + data_ct.len() + padding_len);
        out.extend_from_slice(&size);
        out.extend_from_slice(&data_ct);
        if padding_len > 0 {
            let start = out.len();
            out.resize(start + padding_len, 0);
            rand::thread_rng().fill_bytes(&mut out[start..]);
        }
        Ok(out)
    }
}

impl AsyncRead for VmessStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if !self.read_buf.is_empty() {
                let n = self.read_buf.len().min(buf.remaining());
                buf.put_slice(&self.read_buf[..n]);
                let _ = self.read_buf.split_to(n);
                return Poll::Ready(Ok(()));
            }

            let mut tmp = [0u8; 4096];
            let mut tmp_buf = ReadBuf::new(&mut tmp);
            match Pin::new(self.inner.as_mut()).poll_read(cx, &mut tmp_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {
                    let filled = tmp_buf.filled().len();
                    if filled == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    self.read_raw_buf.extend_from_slice(&tmp[..filled]);

                    let mut raw = std::mem::take(&mut self.read_raw_buf);
                    loop {
                        match self.try_decrypt_chunk(&mut raw) {
                            Some(Ok(pt)) => {
                                if pt.is_empty() {
                                    self.read_raw_buf = raw;
                                    return Poll::Ready(Ok(()));
                                }
                                self.read_buf.extend_from_slice(&pt);
                            }
                            Some(Err(e)) => {
                                self.read_raw_buf = raw;
                                return Poll::Ready(Err(e));
                            }
                            None => break,
                        }
                    }
                    self.read_raw_buf = raw;
                }
            }
        }
    }
}

impl AsyncWrite for VmessStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let chunk = &buf[..buf.len().min(MAX_CHUNK_SIZE)];
        let encrypted = match self.encrypt_chunk(chunk) {
            Ok(v) => v,
            Err(e) => return Poll::Ready(Err(e)),
        };
        self.write_buf.extend_from_slice(&encrypted);
        Poll::Ready(Ok(chunk.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.write_buf.is_empty() {
            let data = self.write_buf.clone().freeze();
            match Pin::new(self.inner.as_mut()).poll_write(cx, &data) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(n)) => {
                    let _ = self.write_buf.split_to(n);
                }
            }
        }
        Pin::new(self.inner.as_mut()).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(self.inner.as_mut()).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn test_key_iv() -> ([u8; 16], [u8; 16]) {
        ([0x42u8; 16], [0x24u8; 16])
    }

    #[tokio::test]
    async fn encrypt_decrypt_roundtrip() {
        let (key, iv) = test_key_iv();
        let payload = b"hello vmess stream";
        let (client_half, server_half) = tokio::io::duplex(65536);
        let handle = tokio::spawn(async move {
            let mut writer = VmessStream::new(Box::new(client_half), &key, &iv);
            writer.write_all(payload).await.unwrap();
            writer.flush().await.unwrap();
        });
        let mut reader = VmessStream::new(Box::new(server_half), &key, &iv);
        let mut out = vec![0u8; payload.len()];
        reader.read_exact(&mut out).await.unwrap();
        handle.await.unwrap();
        assert_eq!(out, payload);
    }

    #[tokio::test]
    async fn bidir_roundtrip() {
        let req_key = [0x11u8; 16];
        let req_iv = [0x22u8; 16];
        let resp_key = super::super::codec::response_body_key(&req_key);
        let resp_iv = super::super::codec::response_body_iv(&req_iv);
        let payload = b"bidir test payload";

        let (client_half, server_half) = tokio::io::duplex(65536);

        // Client writes with req_key, reads with resp_key
        let handle = tokio::spawn(async move {
            let mut client = VmessStream::new_bidir(
                Box::new(client_half),
                &resp_key,
                &resp_iv,
                &req_key,
                &req_iv,
                Security::Aes128Gcm,
                0,
            );
            client.write_all(payload).await.unwrap();
            client.flush().await.unwrap();
        });

        // Server reads with req_key
        let mut server = VmessStream::new_bidir(
            Box::new(server_half),
            &req_key,
            &req_iv,
            &resp_key,
            &resp_iv,
            Security::Aes128Gcm,
            0,
        );
        let mut out = vec![0u8; payload.len()];
        server.read_exact(&mut out).await.unwrap();
        handle.await.unwrap();
        assert_eq!(out, payload);
    }

    #[test]
    fn chunk_nonce_uniqueness() {
        let iv = [0x55u8; 16];
        assert_ne!(chunk_nonce(0, &iv), chunk_nonce(1, &iv));
        assert_eq!(chunk_nonce(42, &iv).len(), 12);
    }
}
