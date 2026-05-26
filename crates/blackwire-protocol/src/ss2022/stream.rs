//! SS-2022 AEAD-encrypted chunked stream.
//!
//! After the header exchange, both sides exchange data as a sequence of
//! AEAD-encrypted chunks. Each chunk has the form:
//!
//! ```text
//! ┌──────────────────────────────────────────────────┐
//! │ 2-byte plaintext length (big-endian)              │  — AES-256-GCM encrypted → 18 bytes
//! │ Data ciphertext (length bytes + 16-byte AEAD tag) │
//! └──────────────────────────────────────────────────┘
//! ```
//!
//! The nonce for each chunk is a 12-byte big-endian counter. The same subkey
//! is used for both the length field and the data field, but with separate
//! nonce values (counter increments once per field).
//!
//! # Key
//!
//! The 32-byte session subkey derived from `derive_subkey(psk, salt)` is used
//! as the AES-256-GCM key.

use std::io;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};

use aes_gcm::{
    aead::{consts::U16, generic_array::GenericArray, AeadInPlace},
    Aes256Gcm, KeyInit,
};
use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use blackwire_common::{BoxedStream, BufferPool};

/// Maximum plaintext chunk payload size (16 KiB).
const MAX_CHUNK_SIZE: usize = 16 * 1024;
const READ_CHUNK_SIZE: usize = 64 * 1024;

fn ss2022_buffer_pool() -> &'static Arc<BufferPool> {
    static POOL: OnceLock<Arc<BufferPool>> = OnceLock::new();
    POOL.get_or_init(BufferPool::new)
}

// ── Nonce helper ──────────────────────────────────────────────────────────────

/// Build a 12-byte nonce from a 64-bit counter (little-endian, SIP022 spec).
fn make_nonce(counter: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..8].copy_from_slice(&counter.to_le_bytes());
    n
}

// ── Ss2022Stream ─────────────────────────────────────────────────────────────

/// Wraps a `BoxedStream` in SS-2022 AEAD chunk framing (AES-256-GCM).
///
/// Each read/write is transparently encrypted/decrypted. The stream is
/// stateful: the nonce counter increments with every encrypted field.
pub struct Ss2022Stream {
    inner: BoxedStream,
    read_cipher: Aes256Gcm,
    write_cipher: Aes256Gcm,

    // Read state
    read_counter: u64,
    read_buf: Bytes,    // decrypted plaintext waiting to be consumed
    read_raw: BytesMut, // raw ciphertext accumulated from inner
    // Reused scratch buffers for decrypt paths to avoid per-chunk allocations.
    read_len_scratch: [u8; 2],

    // Write state
    write_counter: u64,
    write_buf: BytesMut, // encrypted bytes waiting to be flushed
    response_header: Option<[u8; 43]>,
}

impl Ss2022Stream {
    /// Create a new `Ss2022Stream` wrapping `inner`, with nonce counters starting at `start_nonce`.
    ///
    /// For SIP022 compatibility, pass `start_nonce = 2` (handshake consumes nonces 0 and 1).
    pub fn new_with_nonce(inner: BoxedStream, subkey: &[u8; 32], start_nonce: u64) -> Self {
        Self::new_bidir(
            inner,
            subkey,
            start_nonce,
            subkey,
            start_nonce,
            BytesMut::new(),
            None,
        )
    }

    /// Create a new `Ss2022Stream` wrapping `inner`, nonces starting at 0.
    pub fn new(inner: BoxedStream, subkey: &[u8; 32]) -> Self {
        Self::new_with_nonce(inner, subkey, 0)
    }

    /// Create a stream with independent read/write keys and counters.
    pub fn new_bidir(
        inner: BoxedStream,
        read_subkey: &[u8; 32],
        read_start_nonce: u64,
        write_subkey: &[u8; 32],
        write_start_nonce: u64,
        initial_read: BytesMut,
        response_header: Option<[u8; 43]>,
    ) -> Self {
        Self {
            inner,
            read_cipher: Aes256Gcm::new(GenericArray::from_slice(read_subkey)),
            write_cipher: Aes256Gcm::new(GenericArray::from_slice(write_subkey)),
            read_counter: read_start_nonce,
            read_buf: initial_read.freeze(),
            read_raw: ss2022_buffer_pool().acquire(MAX_CHUNK_SIZE + 256),
            read_len_scratch: [0u8; 2],
            write_counter: write_start_nonce,
            write_buf: ss2022_buffer_pool().acquire(MAX_CHUNK_SIZE + 256),
            response_header,
        }
    }

    /// Try to decrypt the next chunk from `src`.
    ///
    /// Returns `None` if there is not enough data yet.
    /// Returns `Some(Ok(bytes))` on success or `Some(Err(...))` on AEAD failure.
    fn try_decrypt_chunk(&mut self, src: &mut BytesMut) -> Option<Result<Bytes, io::Error>> {
        // Length field: 2-byte plaintext → 18 bytes on wire (2 + 16 tag).
        if src.len() < 18 {
            return None;
        }

        let len_nonce = make_nonce(self.read_counter);
        self.read_len_scratch.copy_from_slice(&src[..2]);
        let len_tag = GenericArray::<u8, U16>::clone_from_slice(&src[2..18]);
        if self
            .read_cipher
            .decrypt_in_place_detached(
                GenericArray::from_slice(&len_nonce),
                &[],
                &mut self.read_len_scratch,
                &len_tag,
            )
            .is_err()
        {
            return Some(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "SS-2022: length field decryption failed",
            )));
        }
        let data_len = u16::from_be_bytes(self.read_len_scratch) as usize;

        // A zero-length chunk signals end of stream.
        if data_len == 0 {
            let _ = src.split_to(18);
            self.read_counter += 1;
            return Some(Ok(Bytes::new()));
        }

        let total = 18 + data_len + 16;
        if src.len() < total {
            return None;
        }

        let _ = src.split_to(18);
        self.read_counter += 1;

        let mut data_ct = src.split_to(data_len + 16);
        let data_nonce = make_nonce(self.read_counter);
        let data_tag = GenericArray::<u8, U16>::clone_from_slice(&data_ct[data_len..]);
        data_ct.truncate(data_len);
        if self
            .read_cipher
            .decrypt_in_place_detached(
                GenericArray::from_slice(&data_nonce),
                &[],
                &mut data_ct,
                &data_tag,
            )
            .is_err()
        {
            return Some(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "SS-2022: data chunk decryption failed",
            )));
        }
        self.read_counter += 1;

        let plain = data_ct.freeze();
        Some(Ok(plain))
    }

    fn encrypt_append(
        cipher: &Aes256Gcm,
        nonce: &[u8; 12],
        dst: &mut BytesMut,
        data: &[u8],
        error: &'static str,
    ) -> io::Result<()> {
        let start = dst.len();
        dst.extend_from_slice(data);
        let tag = cipher
            .encrypt_in_place_detached(GenericArray::from_slice(nonce), &[], &mut dst[start..])
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, error))?;
        dst.extend_from_slice(tag.as_slice());
        Ok(())
    }

    /// Encrypt `data` directly into the write buffer (length ciphertext + data ciphertext).
    fn append_encrypted_chunk(&mut self, dst: &mut BytesMut, data: &[u8]) -> io::Result<()> {
        if let Some(mut fixed_header) = self.response_header.take() {
            fixed_header[41..43].copy_from_slice(&(data.len() as u16).to_be_bytes());

            let header_nonce = make_nonce(self.write_counter);
            dst.reserve(fixed_header.len() + 16 + data.len() + 16);
            Self::encrypt_append(
                &self.write_cipher,
                &header_nonce,
                dst,
                fixed_header.as_slice(),
                "SS-2022: response header encrypt failed",
            )?;
            self.write_counter += 1;

            let data_nonce = make_nonce(self.write_counter);
            Self::encrypt_append(
                &self.write_cipher,
                &data_nonce,
                dst,
                data,
                "SS-2022: response payload encrypt failed",
            )?;
            self.write_counter += 1;
            return Ok(());
        }

        let len_nonce = make_nonce(self.write_counter);
        let data_len = data.len() as u16;
        dst.reserve(18 + data.len() + 16);
        Self::encrypt_append(
            &self.write_cipher,
            &len_nonce,
            dst,
            data_len.to_be_bytes().as_slice(),
            "SS-2022: chunk length encrypt failed",
        )?;
        self.write_counter += 1;

        let data_nonce = make_nonce(self.write_counter);
        Self::encrypt_append(
            &self.write_cipher,
            &data_nonce,
            dst,
            data,
            "SS-2022: chunk payload encrypt failed",
        )?;
        self.write_counter += 1;
        Ok(())
    }
}

impl Drop for Ss2022Stream {
    fn drop(&mut self) {
        ss2022_buffer_pool().release(std::mem::take(&mut self.read_raw));
        ss2022_buffer_pool().release(std::mem::take(&mut self.write_buf));
    }
}

impl AsyncRead for Ss2022Stream {
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

            // Consume any fully-buffered ciphertext before polling the socket.
            let mut raw = std::mem::take(&mut self.read_raw);
            match self.try_decrypt_chunk(&mut raw) {
                Some(Ok(plaintext)) => {
                    self.read_raw = raw;
                    if plaintext.is_empty() {
                        return Poll::Ready(Ok(())); // stream end
                    }
                    self.read_buf = plaintext;
                    continue;
                }
                Some(Err(e)) => {
                    self.read_raw = raw;
                    return Poll::Ready(Err(e));
                }
                None => {
                    self.read_raw = raw;
                }
            }

            let mut tmp = [0u8; READ_CHUNK_SIZE];
            let mut tmp_buf = ReadBuf::new(&mut tmp);
            match Pin::new(self.inner.as_mut()).poll_read(cx, &mut tmp_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {
                    let filled = tmp_buf.filled().len();
                    if filled == 0 {
                        return Poll::Ready(Ok(())); // EOF
                    }
                    self.read_raw.extend_from_slice(&tmp[..filled]);

                    let mut raw = std::mem::take(&mut self.read_raw);
                    loop {
                        match self.try_decrypt_chunk(&mut raw) {
                            Some(Ok(plaintext)) => {
                                if plaintext.is_empty() {
                                    self.read_raw = raw;
                                    return Poll::Ready(Ok(())); // stream end
                                }
                                self.read_buf = plaintext;
                                // Emit one decrypted chunk per poll_read. Keep any
                                // remaining ciphertext in read_raw for subsequent polls.
                                break;
                            }
                            Some(Err(e)) => {
                                self.read_raw = raw;
                                return Poll::Ready(Err(e));
                            }
                            None => break,
                        }
                    }
                    self.read_raw = raw;
                }
            }
        }
    }
}

impl AsyncWrite for Ss2022Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // If previous ciphertext is still queued, drain it before accepting more
        // plaintext so we propagate backpressure to callers.
        while !self.write_buf.is_empty() {
            let this = self.as_mut().get_mut();
            match Pin::new(this.inner.as_mut()).poll_write(cx, &this.write_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "SS-2022: inner write returned 0",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    let _ = this.write_buf.split_to(n);
                }
            }
        }

        let chunk = &buf[..buf.len().min(MAX_CHUNK_SIZE)];
        let mut staged = std::mem::take(&mut self.write_buf);
        let result = self.append_encrypted_chunk(&mut staged, chunk);
        self.write_buf = staged;
        if let Err(e) = result {
            return Poll::Ready(Err(e));
        }

        // Opportunistically drain newly-buffered ciphertext too.
        while !self.write_buf.is_empty() {
            let this = self.as_mut().get_mut();
            match Pin::new(this.inner.as_mut()).poll_write(cx, &this.write_buf) {
                Poll::Pending => break,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "SS-2022: inner write returned 0",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    let _ = this.write_buf.split_to(n);
                }
            }
        }
        Poll::Ready(Ok(chunk.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Split field borrows without cloning the buffer. Ss2022Stream: Unpin.
        while !self.write_buf.is_empty() {
            let this = self.as_mut().get_mut();
            match Pin::new(this.inner.as_mut()).poll_write(cx, &this.write_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "SS-2022: inner write returned 0",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    let _ = this.write_buf.split_to(n);
                }
            }
        }
        Pin::new(self.inner.as_mut()).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(self.inner.as_mut()).poll_shutdown(cx)
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn test_subkey() -> [u8; 32] {
        let psk = *blake3::hash(b"test-password").as_bytes();
        crate::ss2022::subkey::derive_subkey(&psk, &[0x55u8; 32])
    }

    /// Encrypt on one side and decrypt on the other — data must match.
    #[tokio::test]
    async fn encrypt_decrypt_roundtrip() {
        let subkey = test_subkey();
        let payload = b"Hello, Shadowsocks-2022!";

        let (client_half, server_half) = tokio::io::duplex(65536);

        let subkey_c = subkey;
        let handle = tokio::spawn(async move {
            let mut writer = Ss2022Stream::new(Box::new(client_half), &subkey_c);
            writer.write_all(payload).await.unwrap();
            writer.flush().await.unwrap();
        });

        let mut reader = Ss2022Stream::new(Box::new(server_half), &subkey);
        let mut out = vec![0u8; payload.len()];
        reader.read_exact(&mut out).await.unwrap();
        handle.await.unwrap();
        assert_eq!(out, payload);
    }

    /// Large payload spans multiple chunks.
    #[tokio::test]
    async fn large_payload_roundtrip() {
        let subkey = test_subkey();
        let payload = vec![0xABu8; 32 * 1024]; // 32 KiB > MAX_CHUNK_SIZE

        let (client_half, server_half) = tokio::io::duplex(128 * 1024);

        let payload_c = payload.clone();
        let subkey_c = subkey;
        let handle = tokio::spawn(async move {
            let mut writer = Ss2022Stream::new(Box::new(client_half), &subkey_c);
            writer.write_all(&payload_c).await.unwrap();
            writer.flush().await.unwrap();
        });

        let mut reader = Ss2022Stream::new(Box::new(server_half), &subkey);
        let mut out = vec![0u8; payload.len()];
        reader.read_exact(&mut out).await.unwrap();
        handle.await.unwrap();
        assert_eq!(out, payload);
    }

    /// Nonce counter produces different values.
    #[test]
    fn nonce_uniqueness() {
        let n0 = make_nonce(0);
        let n1 = make_nonce(1);
        assert_ne!(n0, n1);
    }

    /// Nonce is always 12 bytes.
    #[test]
    fn nonce_length() {
        assert_eq!(make_nonce(42).len(), 12);
    }
}
