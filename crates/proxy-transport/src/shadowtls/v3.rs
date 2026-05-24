//! ShadowTLS v3 protocol primitives.
//!
//! These helpers implement the parts that make v3 materially different from
//! the repo's local marker mode:
//!
//! - ClientHello authentication through the 32-byte SessionID field.
//! - Stateful ApplicationData framing with a 4-byte rolling HMAC prefix.
//! - Backend handshake-frame tainting used by the client to authenticate the
//!   ShadowTLS server before switching to the data stream.

use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use hmac::{Hmac, KeyInit, Mac};
use rand::RngCore;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use proxy_common::{BoxedStream, PrependedStream, ProxyError};

type ShadowHmac = Hmac<Sha1>;

const TLS_HEADER_LEN: usize = 5;
const TLS_APPLICATION_DATA: u8 = 0x17;
const TLS_HANDSHAKE: u8 = 0x16;
const CLIENT_HELLO: u8 = 0x01;
const SESSION_ID_LEN: usize = 32;
const SESSION_ID_RANDOM_LEN: usize = 28;
const TAG_LEN: usize = 4;
const MAX_TLS_PLAINTEXT: usize = 16_384;

const READ_PHASE_PLAINTEXT: u8 = 0;
const READ_PHASE_HEADER: u8 = 1;
const READ_PHASE_BODY: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Decoded meaning of a ShadowTLS v3 ApplicationData frame.
pub enum V3FrameKind {
    /// Authenticated backend-handshake residue. Caller should ignore payload.
    ResidualHandshake,
    /// Normal post-handshake application data.
    Data,
}

#[derive(Debug, Clone)]
/// Parsed SessionID location and bytes from a TLS ClientHello.
pub struct ClientHelloSession {
    /// Full 32-byte SessionID as it appears on the wire.
    pub session_id: [u8; SESSION_ID_LEN],
    /// Byte offset of SessionID start inside the TLS record.
    pub session_id_offset: usize,
}

/// Fill the ClientHello SessionID with 28 random bytes and a 4-byte HMAC tag.
///
/// The HMAC is computed over the TLS handshake bytes without the 5-byte record
/// header, with the last 4 bytes of SessionID set to zero as the upstream v3
/// design specifies.
pub fn sign_client_hello_session_id<R: RngCore + ?Sized>(
    client_hello_record: &mut [u8],
    psk: &[u8],
    rng: &mut R,
) -> Result<ClientHelloSession, ProxyError> {
    let offset = session_id_offset(client_hello_record)?;
    rng.fill_bytes(&mut client_hello_record[offset..offset + SESSION_ID_RANDOM_LEN]);
    client_hello_record[offset + SESSION_ID_RANDOM_LEN..offset + SESSION_ID_LEN].fill(0);

    let tag = client_hello_hmac(client_hello_record, psk)?;
    client_hello_record[offset + SESSION_ID_RANDOM_LEN..offset + SESSION_ID_LEN]
        .copy_from_slice(&tag);

    let mut session_id = [0u8; SESSION_ID_LEN];
    session_id.copy_from_slice(&client_hello_record[offset..offset + SESSION_ID_LEN]);

    Ok(ClientHelloSession {
        session_id,
        session_id_offset: offset,
    })
}

/// Verify the 4-byte HMAC tag inside a signed ClientHello SessionID.
pub fn verify_client_hello_session_id(
    client_hello_record: &[u8],
    psk: &[u8],
) -> Result<ClientHelloSession, ProxyError> {
    let offset = session_id_offset(client_hello_record)?;
    let tag = client_hello_hmac(client_hello_record, psk)?;
    let candidate = &client_hello_record[offset + SESSION_ID_RANDOM_LEN..offset + SESSION_ID_LEN];

    if tag.as_slice().ct_eq(candidate).unwrap_u8() != 1 {
        return Err(ProxyError::AuthFailed);
    }

    let mut session_id = [0u8; SESSION_ID_LEN];
    session_id.copy_from_slice(&client_hello_record[offset..offset + SESSION_ID_LEN]);

    Ok(ClientHelloSession {
        session_id,
        session_id_offset: offset,
    })
}

#[derive(Clone)]
/// Stateful encoder for ShadowTLS v3 ApplicationData records.
pub struct V3FrameEncoder {
    mac: ShadowHmac,
}

impl V3FrameEncoder {
    /// Build encoder state for client-to-server data direction.
    pub fn client_to_server(psk: &[u8], server_random: &[u8; 32]) -> Self {
        Self::new(psk, server_random, b"C")
    }

    /// Build encoder state for server-to-client data direction.
    pub fn server_to_client(psk: &[u8], server_random: &[u8; 32]) -> Self {
        Self::new(psk, server_random, b"S")
    }

    fn new(psk: &[u8], server_random: &[u8; 32], direction: &[u8]) -> Self {
        let mut mac = match ShadowHmac::new_from_slice(psk) {
            Ok(v) => v,
            Err(_) => panic!("HMAC accepts any key length"),
        };
        mac.update(server_random);
        mac.update(direction);
        Self { mac }
    }

    /// Wrap plaintext into one authenticated TLS ApplicationData record.
    pub fn encode_application_data(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, ProxyError> {
        if plaintext.len() > MAX_TLS_PLAINTEXT {
            return Err(ProxyError::Protocol(format!(
                "ShadowTLS v3 plaintext too large: {}",
                plaintext.len()
            )));
        }

        let tag = next_tag(&self.mac, plaintext);
        self.mac.update(plaintext);
        self.mac.update(&tag);

        let mut payload = Vec::with_capacity(TAG_LEN + plaintext.len());
        payload.extend_from_slice(&tag);
        payload.extend_from_slice(plaintext);
        Ok(encode_tls_record(TLS_APPLICATION_DATA, &payload))
    }
}

#[derive(Clone)]
/// Stateful decoder for ShadowTLS v3 ApplicationData records.
pub struct V3FrameDecoder {
    data_mac: ShadowHmac,
    residual_mac: Option<ShadowHmac>,
}

impl V3FrameDecoder {
    /// Build decoder state for frames sent by the client.
    pub fn client_to_server(psk: &[u8], server_random: &[u8; 32]) -> Self {
        Self {
            data_mac: V3FrameEncoder::client_to_server(psk, server_random).mac,
            residual_mac: None,
        }
    }

    /// Build decoder state for frames sent by the server.
    pub fn server_to_client(psk: &[u8], server_random: &[u8; 32]) -> Self {
        Self {
            data_mac: V3FrameEncoder::server_to_client(psk, server_random).mac,
            residual_mac: Some(residual_handshake_mac(psk, server_random)),
        }
    }

    /// Decode one authenticated ApplicationData record.
    ///
    /// Returns frame kind plus plaintext payload (empty for residual frames).
    pub fn decode_application_data(
        &mut self,
        record: &[u8],
    ) -> Result<(V3FrameKind, Vec<u8>), ProxyError> {
        let payload = application_payload(record)?;
        if payload.len() < TAG_LEN {
            return Err(ProxyError::Protocol(
                "ShadowTLS v3 ApplicationData frame too short".into(),
            ));
        }

        let (candidate, data) = payload.split_at(TAG_LEN);

        if let Some(mac) = &mut self.residual_mac {
            let tag = next_tag(mac, data);
            if tag.as_slice().ct_eq(candidate).unwrap_u8() == 1 {
                mac.update(data);
                return Ok((V3FrameKind::ResidualHandshake, Vec::new()));
            }
        }

        let tag = next_tag(&self.data_mac, data);
        if tag.as_slice().ct_eq(candidate).unwrap_u8() != 1 {
            return Err(ProxyError::AuthFailed);
        }
        self.residual_mac = None;
        self.data_mac.update(data);
        self.data_mac.update(candidate);
        Ok((V3FrameKind::Data, data.to_vec()))
    }
}

/// Taint an ApplicationData record relayed from the handshake backend.
///
/// The upstream v3 server XORs backend ApplicationData with
/// SHA256(psk || server_random) and prefixes a 4-byte HMAC computed with a
/// separate residual-handshake HMAC seeded by `server_random`.
pub fn taint_backend_application_data(
    residual_mac: &mut ShadowHmac,
    psk: &[u8],
    server_random: &[u8; 32],
    record: &[u8],
) -> Result<Vec<u8>, ProxyError> {
    let payload = application_payload(record)?;
    let mut processed = payload.to_vec();
    xor_with_handshake_mask(&mut processed, psk, server_random);

    let tag = next_tag(residual_mac, &processed);
    residual_mac.update(&processed);

    let mut tainted = Vec::with_capacity(TAG_LEN + processed.len());
    tainted.extend_from_slice(&tag);
    tainted.extend_from_slice(&processed);
    Ok(encode_tls_record(TLS_APPLICATION_DATA, &tainted))
}

/// Create residual-handshake HMAC state seeded from `psk` and `server_random`.
pub fn residual_handshake_mac(psk: &[u8], server_random: &[u8; 32]) -> ShadowHmac {
    let mut mac = match ShadowHmac::new_from_slice(psk) {
        Ok(v) => v,
        Err(_) => panic!("HMAC accepts any key length"),
    };
    mac.update(server_random);
    mac
}

/// Extract the 32-byte server random from a TLS ServerHello record.
pub fn server_random_from_server_hello_record(record: &[u8]) -> Option<[u8; 32]> {
    if record.len() < TLS_HEADER_LEN + 38 || record[0] != TLS_HANDSHAKE {
        return None;
    }
    let payload = record_payload(record)?;
    if payload.first() != Some(&0x02) || payload.len() < 38 {
        return None;
    }
    let mut server_random = [0u8; 32];
    server_random.copy_from_slice(&payload[6..38]);
    Some(server_random)
}

/// ShadowTLS v3 ApplicationData stream.
///
/// This stream runs after the relayed TLS handshake has produced a verified
/// `server_random`. It intentionally does not use TLS AEAD keys for proxy data:
/// v3 authenticates every post-handshake frame with rolling HMAC tags derived
/// from `psk` and `server_random`.
pub struct V3Stream {
    inner: BoxedStream,
    encoder: V3FrameEncoder,
    decoder: V3FrameDecoder,
    plain_buf: Vec<u8>,
    plain_pos: usize,
    header_buf: [u8; TLS_HEADER_LEN],
    header_pos: usize,
    body_buf: Vec<u8>,
    body_pos: usize,
    read_phase: u8,
    write_buf: Vec<u8>,
    write_pos: usize,
    write_chunk_len: usize,
}

impl V3Stream {
    /// Build the client-side post-handshake ShadowTLS v3 stream.
    pub fn client(inner: BoxedStream, psk: &[u8], server_random: &[u8; 32]) -> Self {
        Self::new(
            inner,
            V3FrameEncoder::client_to_server(psk, server_random),
            V3FrameDecoder::server_to_client(psk, server_random),
        )
    }

    /// Build a client stream using an already-initialized decoder state.
    ///
    /// Use this when residual-handshake frames were processed earlier.
    pub fn client_after_residual(
        inner: BoxedStream,
        psk: &[u8],
        server_random: &[u8; 32],
        decoder: V3FrameDecoder,
    ) -> Self {
        Self::new(
            inner,
            V3FrameEncoder::client_to_server(psk, server_random),
            decoder,
        )
    }

    /// Build the server-side post-handshake ShadowTLS v3 stream.
    pub fn server(inner: BoxedStream, psk: &[u8], server_random: &[u8; 32]) -> Self {
        Self::new(
            inner,
            V3FrameEncoder::server_to_client(psk, server_random),
            V3FrameDecoder::client_to_server(psk, server_random),
        )
    }

    /// Build a server stream after consuming the first client data record.
    ///
    /// If that first record already contains user bytes, they are replayed by
    /// wrapping the stream in `PrependedStream`.
    pub fn server_after_first_client_record(
        inner: BoxedStream,
        psk: &[u8],
        server_random: &[u8; 32],
        first_client_record: &[u8],
    ) -> Result<BoxedStream, ProxyError> {
        let mut decoder = V3FrameDecoder::client_to_server(psk, server_random);
        let (kind, first_payload) = decoder.decode_application_data(first_client_record)?;
        if kind != V3FrameKind::Data {
            return Err(ProxyError::Protocol(
                "ShadowTLS v3 expected first client data frame".into(),
            ));
        }

        let stream = Self::new(
            inner,
            V3FrameEncoder::server_to_client(psk, server_random),
            decoder,
        );
        if first_payload.is_empty() {
            Ok(Box::new(stream))
        } else {
            Ok(Box::new(PrependedStream::new(stream, first_payload)))
        }
    }

    fn new(inner: BoxedStream, encoder: V3FrameEncoder, decoder: V3FrameDecoder) -> Self {
        Self {
            inner,
            encoder,
            decoder,
            plain_buf: Vec::new(),
            plain_pos: 0,
            header_buf: [0; TLS_HEADER_LEN],
            header_pos: 0,
            body_buf: Vec::new(),
            body_pos: 0,
            read_phase: READ_PHASE_HEADER,
            write_buf: Vec::new(),
            write_pos: 0,
            write_chunk_len: 0,
        }
    }
}

impl AsyncRead for V3Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if self.read_phase == READ_PHASE_PLAINTEXT {
                if self.plain_pos < self.plain_buf.len() {
                    let available = &self.plain_buf[self.plain_pos..];
                    let n = available.len().min(buf.remaining());
                    buf.put_slice(&available[..n]);
                    self.plain_pos += n;
                    if self.plain_pos >= self.plain_buf.len() {
                        self.plain_buf.clear();
                        self.plain_pos = 0;
                    }
                    return Poll::Ready(Ok(()));
                }
                self.read_phase = READ_PHASE_HEADER;
                self.header_pos = 0;
            }

            if self.read_phase == READ_PHASE_HEADER {
                while self.header_pos < TLS_HEADER_LEN {
                    let remaining = TLS_HEADER_LEN - self.header_pos;
                    let mut tmp = [0u8; TLS_HEADER_LEN];
                    let mut read_buf = ReadBuf::new(&mut tmp[..remaining]);
                    ready!(Pin::new(&mut self.inner).poll_read(cx, &mut read_buf))?;
                    let n = read_buf.filled().len();
                    if n == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "ShadowTLS v3 peer closed mid-record-header",
                        )));
                    }
                    let header_pos = self.header_pos;
                    self.header_buf[header_pos..header_pos + n]
                        .copy_from_slice(&read_buf.filled()[..n]);
                    self.header_pos += n;
                }

                if self.header_buf[0] != TLS_APPLICATION_DATA {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "ShadowTLS v3 expected ApplicationData, got 0x{:02x}",
                            self.header_buf[0]
                        ),
                    )));
                }

                let body_len =
                    u16::from_be_bytes([self.header_buf[3], self.header_buf[4]]) as usize;
                if body_len > MAX_TLS_PLAINTEXT + TAG_LEN {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("ShadowTLS v3 record too large: {body_len}"),
                    )));
                }
                self.body_buf.resize(body_len, 0);
                self.body_pos = 0;
                self.read_phase = READ_PHASE_BODY;
            }

            if self.read_phase == READ_PHASE_BODY {
                while self.body_pos < self.body_buf.len() {
                    let remaining = self.body_buf.len() - self.body_pos;
                    let mut tmp = [0u8; 2048];
                    let read_len = remaining.min(tmp.len());
                    let mut read_buf = ReadBuf::new(&mut tmp[..read_len]);
                    ready!(Pin::new(&mut self.inner).poll_read(cx, &mut read_buf))?;
                    let n = read_buf.filled().len();
                    if n == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "ShadowTLS v3 peer closed mid-record-body",
                        )));
                    }
                    let body_pos = self.body_pos;
                    self.body_buf[body_pos..body_pos + n].copy_from_slice(&read_buf.filled()[..n]);
                    self.body_pos += n;
                }

                let mut record = Vec::with_capacity(TLS_HEADER_LEN + self.body_buf.len());
                record.extend_from_slice(&self.header_buf);
                record.extend_from_slice(&self.body_buf);
                self.read_phase = READ_PHASE_HEADER;
                self.header_pos = 0;
                self.body_pos = 0;

                match self.decoder.decode_application_data(&record) {
                    Ok((V3FrameKind::ResidualHandshake, _)) => continue,
                    Ok((V3FrameKind::Data, data)) if data.is_empty() => continue,
                    Ok((V3FrameKind::Data, data)) => {
                        self.plain_buf = data;
                        self.plain_pos = 0;
                        self.read_phase = READ_PHASE_PLAINTEXT;
                    }
                    Err(e) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            e.to_string(),
                        )));
                    }
                }
            }
        }
    }
}

impl AsyncWrite for V3Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if !self.write_buf.is_empty() {
            while self.write_pos < self.write_buf.len() {
                let write_pos = self.write_pos;
                let pending = self.write_buf[write_pos..].to_vec();
                let n = ready!(Pin::new(&mut self.inner).poll_write(cx, &pending))?;
                if n == 0 {
                    return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)));
                }
                self.write_pos += n;
            }
            self.write_buf.clear();
            self.write_pos = 0;
            let consumed = self.write_chunk_len;
            self.write_chunk_len = 0;
            return Poll::Ready(Ok(consumed));
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let chunk_len = buf.len().min(MAX_TLS_PLAINTEXT);
        let record = self
            .encoder
            .encode_application_data(&buf[..chunk_len])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        self.write_buf = record;
        self.write_pos = 0;
        self.write_chunk_len = chunk_len;

        while self.write_pos < self.write_buf.len() {
            let write_pos = self.write_pos;
            let pending = self.write_buf[write_pos..].to_vec();
            match Pin::new(&mut self.inner).poll_write(cx, &pending) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)));
                }
                Poll::Ready(Ok(n)) => self.write_pos += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        self.write_buf.clear();
        self.write_pos = 0;
        self.write_chunk_len = 0;
        Poll::Ready(Ok(chunk_len))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

fn client_hello_hmac(record: &[u8], psk: &[u8]) -> Result<[u8; TAG_LEN], ProxyError> {
    let offset = session_id_offset(record)?;
    let mut signed = record[TLS_HEADER_LEN..].to_vec();
    let sid_offset_in_handshake = offset - TLS_HEADER_LEN;
    signed
        [sid_offset_in_handshake + SESSION_ID_RANDOM_LEN..sid_offset_in_handshake + SESSION_ID_LEN]
        .fill(0);

    let mut mac = match ShadowHmac::new_from_slice(psk) {
        Ok(v) => v,
        Err(_) => panic!("HMAC accepts any key length"),
    };
    mac.update(&signed);
    Ok(first_tag(mac))
}

fn session_id_offset(record: &[u8]) -> Result<usize, ProxyError> {
    if record.len() < TLS_HEADER_LEN + 4 {
        return Err(ProxyError::Protocol(
            "ShadowTLS v3 ClientHello record too short".into(),
        ));
    }
    if record[0] != TLS_HANDSHAKE {
        return Err(ProxyError::Protocol(
            "ShadowTLS v3 expected TLS handshake record".into(),
        ));
    }
    let record_len = u16::from_be_bytes([record[3], record[4]]) as usize;
    if record.len() < TLS_HEADER_LEN + record_len {
        return Err(ProxyError::Protocol(
            "ShadowTLS v3 truncated ClientHello record".into(),
        ));
    }

    let body = &record[TLS_HEADER_LEN..TLS_HEADER_LEN + record_len];
    if body.len() < 43 || body[0] != CLIENT_HELLO {
        return Err(ProxyError::Protocol(
            "ShadowTLS v3 expected ClientHello handshake".into(),
        ));
    }

    let declared = ((body[1] as usize) << 16) | ((body[2] as usize) << 8) | body[3] as usize;
    if declared + 4 != body.len() {
        return Err(ProxyError::Protocol(
            "ShadowTLS v3 ClientHello length mismatch".into(),
        ));
    }

    let mut pos = 4 + 2 + 32;
    if pos >= body.len() {
        return Err(ProxyError::Protocol(
            "ShadowTLS v3 missing SessionID length".into(),
        ));
    }
    let session_id_len = body[pos] as usize;
    pos += 1;
    if session_id_len != SESSION_ID_LEN {
        return Err(ProxyError::Protocol(format!(
            "ShadowTLS v3 SessionID must be 32 bytes, got {session_id_len}"
        )));
    }
    if pos + SESSION_ID_LEN > body.len() {
        return Err(ProxyError::Protocol(
            "ShadowTLS v3 truncated SessionID".into(),
        ));
    }
    Ok(TLS_HEADER_LEN + pos)
}

fn application_payload(record: &[u8]) -> Result<&[u8], ProxyError> {
    if record.len() < TLS_HEADER_LEN {
        return Err(ProxyError::Protocol(
            "ShadowTLS v3 TLS record too short".into(),
        ));
    }
    if record[0] != TLS_APPLICATION_DATA {
        return Err(ProxyError::Protocol(format!(
            "ShadowTLS v3 expected ApplicationData record, got {}",
            record[0]
        )));
    }
    let len = u16::from_be_bytes([record[3], record[4]]) as usize;
    if record.len() < TLS_HEADER_LEN + len {
        return Err(ProxyError::Protocol(
            "ShadowTLS v3 truncated ApplicationData record".into(),
        ));
    }
    Ok(&record[TLS_HEADER_LEN..TLS_HEADER_LEN + len])
}

fn record_payload(record: &[u8]) -> Option<&[u8]> {
    if record.len() < TLS_HEADER_LEN {
        return None;
    }
    let len = u16::from_be_bytes([record[3], record[4]]) as usize;
    if record.len() < TLS_HEADER_LEN + len {
        return None;
    }
    Some(&record[TLS_HEADER_LEN..TLS_HEADER_LEN + len])
}

fn encode_tls_record(record_type: u8, payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u16;
    let mut out = Vec::with_capacity(TLS_HEADER_LEN + payload.len());
    out.extend_from_slice(&[record_type, 0x03, 0x03, (len >> 8) as u8, len as u8]);
    out.extend_from_slice(payload);
    out
}

fn next_tag(mac: &ShadowHmac, data: &[u8]) -> [u8; TAG_LEN] {
    let mut cloned = mac.clone();
    cloned.update(data);
    first_tag(cloned)
}

fn first_tag(mac: ShadowHmac) -> [u8; TAG_LEN] {
    let bytes = mac.finalize().into_bytes();
    match bytes[..TAG_LEN].try_into() {
        Ok(v) => v,
        Err(_) => panic!("slice has tag length"),
    }
}

fn xor_with_handshake_mask(data: &mut [u8], psk: &[u8], server_random: &[u8; 32]) {
    let mut hasher = Sha256::new();
    hasher.update(psk);
    hasher.update(server_random);
    let mask: [u8; 32] = hasher.finalize().into();
    for (idx, byte) in data.iter_mut().enumerate() {
        *byte ^= mask[idx % mask.len()];
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proxy_tls::ClientHelloBuilder;
    use rand::{rngs::StdRng, SeedableRng};
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    fn client_hello() -> Vec<u8> {
        ClientHelloBuilder::chrome_131()
            .build(
                "example.com",
                &[0x11; 32],
                &[0x22; 32],
                None,
                &mut StdRng::seed_from_u64(7),
            )
            .to_vec()
    }

    #[test]
    fn client_hello_session_id_signs_and_verifies() {
        let psk = b"shadowtls-v3-password";
        let mut hello = client_hello();
        let signed =
            sign_client_hello_session_id(&mut hello, psk, &mut StdRng::seed_from_u64(42)).unwrap();

        assert_ne!(
            &signed.session_id[..SESSION_ID_RANDOM_LEN],
            &[0u8; SESSION_ID_RANDOM_LEN]
        );
        verify_client_hello_session_id(&hello, psk).unwrap();
        assert!(verify_client_hello_session_id(&hello, b"wrong-password").is_err());
    }

    #[test]
    fn client_hello_tampering_is_rejected() {
        let psk = b"shadowtls-v3-password";
        let mut hello = client_hello();
        sign_client_hello_session_id(&mut hello, psk, &mut StdRng::seed_from_u64(42)).unwrap();

        let last = hello.len() - 1;
        hello[last] ^= 0x01;
        assert!(verify_client_hello_session_id(&hello, psk).is_err());
    }

    #[test]
    fn data_frames_are_stateful_and_directional() {
        let psk = b"shadowtls-v3-password";
        let server_random = [0x44; 32];
        let mut encoder = V3FrameEncoder::client_to_server(psk, &server_random);
        let mut decoder = V3FrameDecoder::client_to_server(psk, &server_random);

        let first = encoder.encode_application_data(b"hello").unwrap();
        let second = encoder.encode_application_data(b"world").unwrap();

        let (kind, data) = decoder.decode_application_data(&first).unwrap();
        assert_eq!(kind, V3FrameKind::Data);
        assert_eq!(data, b"hello");

        let (kind, data) = decoder.decode_application_data(&second).unwrap();
        assert_eq!(kind, V3FrameKind::Data);
        assert_eq!(data, b"world");

        let mut wrong_direction = V3FrameDecoder::server_to_client(psk, &server_random);
        assert!(wrong_direction.decode_application_data(&first).is_err());
    }

    #[test]
    fn reordered_data_frames_are_rejected() {
        let psk = b"shadowtls-v3-password";
        let server_random = [0x44; 32];
        let mut encoder = V3FrameEncoder::client_to_server(psk, &server_random);
        let mut decoder = V3FrameDecoder::client_to_server(psk, &server_random);

        let first = encoder.encode_application_data(b"first").unwrap();
        let second = encoder.encode_application_data(b"second").unwrap();

        assert!(decoder.decode_application_data(&second).is_err());
        let (kind, data) = decoder.decode_application_data(&first).unwrap();
        assert_eq!(kind, V3FrameKind::Data);
        assert_eq!(data, b"first");
    }

    #[test]
    fn residual_backend_frame_is_authenticated_and_filtered() {
        let psk = b"shadowtls-v3-password";
        let server_random = [0x44; 32];
        let backend_record = encode_tls_record(TLS_APPLICATION_DATA, b"encrypted-finished");

        let mut residual_mac = residual_handshake_mac(psk, &server_random);
        let tainted =
            taint_backend_application_data(&mut residual_mac, psk, &server_random, &backend_record)
                .unwrap();

        let mut decoder = V3FrameDecoder::server_to_client(psk, &server_random);
        let (kind, data) = decoder.decode_application_data(&tainted).unwrap();
        assert_eq!(kind, V3FrameKind::ResidualHandshake);
        assert!(data.is_empty());
    }

    #[tokio::test]
    async fn v3_stream_transfers_bidirectionally() {
        let psk = b"shadowtls-v3-password";
        let server_random = [0x66; 32];
        let (client_raw, server_raw) = duplex(4096);
        let mut client = V3Stream::client(Box::new(client_raw), psk, &server_random);
        let mut server = V3Stream::server(Box::new(server_raw), psk, &server_random);

        let client_task = async {
            client.write_all(b"ping").await?;
            client.flush().await?;
            let mut response = [0u8; 4];
            client.read_exact(&mut response).await?;
            io::Result::Ok(response)
        };

        let server_task = async {
            let mut request = [0u8; 4];
            server.read_exact(&mut request).await?;
            server.write_all(b"pong").await?;
            server.flush().await?;
            io::Result::Ok(request)
        };

        let (client_seen, server_seen) = tokio::try_join!(client_task, server_task).unwrap();
        assert_eq!(&server_seen, b"ping");
        assert_eq!(&client_seen, b"pong");
    }

    #[tokio::test]
    async fn v3_stream_filters_residual_handshake_before_data() {
        let psk = b"shadowtls-v3-password";
        let server_random = [0x67; 32];
        let (client_raw, mut server_raw) = duplex(4096);
        let mut client = V3Stream::client(Box::new(client_raw), psk, &server_random);

        let backend_record = encode_tls_record(TLS_APPLICATION_DATA, b"encrypted-finished");
        let mut residual_mac = residual_handshake_mac(psk, &server_random);
        let residual =
            taint_backend_application_data(&mut residual_mac, psk, &server_random, &backend_record)
                .unwrap();

        let mut encoder = V3FrameEncoder::server_to_client(psk, &server_random);
        let data = encoder.encode_application_data(b"ready").unwrap();

        server_raw.write_all(&residual).await.unwrap();
        server_raw.write_all(&data).await.unwrap();
        server_raw.flush().await.unwrap();

        let mut buf = [0u8; 5];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ready");
    }
}
