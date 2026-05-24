//! VMess data channel stream — AEAD-encrypted chunked framing.
//!
//! Chunk wire format (each direction independently):
//! ```text
//! enc_length(18) | enc_data(data_len + 16)
//! ```
//! Per-chunk nonce: `counter_be_u16(2) || iv[2..12](10)` — 12 bytes total.
//! Counter increments once per field (length uses N, data uses N+1).

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use aes_gcm::{
    aead::{generic_array::GenericArray, Aead, Payload},
    Aes128Gcm, KeyInit,
};
use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use proxy_common::BoxedStream;

const MAX_CHUNK_SIZE: usize = 16 * 1024;

fn chunk_nonce(counter: u16, iv: &[u8; 16]) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[0..2].copy_from_slice(&counter.to_be_bytes());
    nonce[2..12].copy_from_slice(&iv[2..12]);
    nonce
}

/// VMess AEAD chunk stream with independent read and write ciphers.
///
/// - `new()`: same key/iv both directions (proxy-rs ↔ proxy-rs)
/// - `new_bidir()`: separate keys — use this when one peer is xray/sing-box
pub struct VmessStream {
    inner: BoxedStream,

    read_cipher: Aes128Gcm,
    read_iv: [u8; 16],
    read_counter: u16,
    read_buf: BytesMut,
    read_raw_buf: BytesMut,

    write_cipher: Aes128Gcm,
    write_iv: [u8; 16],
    write_counter: u16,
    write_buf: BytesMut,
}

impl VmessStream {
    /// Same key/iv for both directions (internal proxy-rs use).
    pub fn new(inner: BoxedStream, key: &[u8; 16], iv: &[u8; 16]) -> Self {
        Self::new_bidir(inner, key, iv, key, iv)
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
    ) -> Self {
        Self {
            inner,
            read_cipher: Aes128Gcm::new(GenericArray::from_slice(read_key)),
            read_iv: *read_iv,
            read_counter: 0,
            read_buf: BytesMut::new(),
            read_raw_buf: BytesMut::new(),
            write_cipher: Aes128Gcm::new(GenericArray::from_slice(write_key)),
            write_iv: *write_iv,
            write_counter: 0,
            write_buf: BytesMut::new(),
        }
    }

    fn try_decrypt_chunk(&mut self, src: &mut BytesMut) -> Option<Result<Bytes, io::Error>> {
        if src.len() < 18 {
            return None;
        }

        let nonce_arr = chunk_nonce(self.read_counter, &self.read_iv);
        let nonce = GenericArray::from_slice(&nonce_arr);

        let len_pt = self.read_cipher.decrypt(nonce, src[..18].as_ref()).ok()?;
        if len_pt.len() < 2 {
            return None;
        }
        let data_len = u16::from_be_bytes([len_pt[0], len_pt[1]]) as usize;

        if data_len == 0 {
            let _ = src.split_to(18);
            self.read_counter = self.read_counter.wrapping_add(1);
            return Some(Ok(Bytes::new()));
        }

        let total = 18 + data_len + 16;
        if src.len() < total {
            return None;
        }

        let _ = src.split_to(18);
        self.read_counter = self.read_counter.wrapping_add(1);

        let data_ct = src.split_to(data_len + 16);
        let data_nonce_arr = chunk_nonce(self.read_counter, &self.read_iv);
        let data_nonce = GenericArray::from_slice(&data_nonce_arr);

        let plaintext = match self.read_cipher.decrypt(
            data_nonce,
            Payload {
                msg: &data_ct,
                aad: &[],
            },
        ) {
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

    fn encrypt_chunk(&mut self, data: &[u8]) -> Vec<u8> {
        let nonce_arr = chunk_nonce(self.write_counter, &self.write_iv);
        let nonce = GenericArray::from_slice(&nonce_arr);

        let data_len = data.len() as u16;
        let len_ct = self
            .write_cipher
            .encrypt(nonce, data_len.to_be_bytes().as_slice())
            .expect("AES-128-GCM encrypt must not fail");
        self.write_counter = self.write_counter.wrapping_add(1);

        let data_nonce_arr = chunk_nonce(self.write_counter, &self.write_iv);
        let data_nonce = GenericArray::from_slice(&data_nonce_arr);
        let data_ct = self
            .write_cipher
            .encrypt(data_nonce, data)
            .expect("AES-128-GCM encrypt must not fail");
        self.write_counter = self.write_counter.wrapping_add(1);

        let mut out = Vec::with_capacity(len_ct.len() + data_ct.len());
        out.extend_from_slice(&len_ct);
        out.extend_from_slice(&data_ct);
        out
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
        let encrypted = self.encrypt_chunk(chunk);
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
            let mut client =
                VmessStream::new_bidir(Box::new(client_half), &resp_key, &resp_iv, &req_key, &req_iv);
            client.write_all(payload).await.unwrap();
            client.flush().await.unwrap();
        });

        // Server reads with req_key
        let mut server =
            VmessStream::new_bidir(Box::new(server_half), &req_key, &req_iv, &resp_key, &resp_iv);
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
