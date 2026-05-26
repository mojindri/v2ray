//! gRPC transport (Gun protocol) — HTTP/2 tunnel via length-prefixed framing.
//!
//! This implements the "Gun" gRPC transport used by xray/v2ray for CDN bypass.
//! It tunnels arbitrary byte streams inside a single bidirectional gRPC stream,
//! using HTTP/2 framing with length-prefixed protobuf messages.
//!
//! # Wire format (two layers)
//!
//! ## Layer 1 — gRPC frame (5-byte header)
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │ Compressed flag (1 byte)  — always 0x00 (uncompressed)  │
//! │ Message length (4 bytes, big-endian)                     │
//! │ Message payload (length bytes)  ← layer 2 lives here    │
//! └─────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Layer 2 — protobuf Hunk message
//!
//! The message payload is a serialised `message Hunk { bytes data = 1; }`:
//!
//! ```text
//! ┌────────────────────────────────────────────────────────────┐
//! │ Field tag  (1 byte)  — 0x0A  (field 1, wire type 2)        │
//! │ Data length (varint) — protobuf varint encoding of len(data)│
//! │ Data        (N bytes) — the raw tunnelled bytes             │
//! └────────────────────────────────────────────────────────────┘
//! ```
//!
//! `GrpcStream` handles both layers transparently: reads unwrap Hunk then
//! the gRPC frame, writes add the Hunk wrapper then the gRPC frame.
//!
//! # HTTP/2 endpoint
//!
//! - Method: POST
//! - Path: `/{service_name}/Tun`
//! - Content-Type: `application/grpc`
//!
//! # References
//!
//! - gRPC over HTTP/2: <https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md>
//! - xray-core Gun transport: `transport/internet/grpc/`

use std::io;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use blackwire_common::{BoxedStream, BufferPool, ProxyError};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum message size accepted (16 MiB).
const MAX_MESSAGE_SIZE: u32 = 16 * 1024 * 1024;

/// gRPC frame header length (1 compressed flag + 4 length bytes).
const FRAME_HEADER_LEN: usize = 5;

fn grpc_buffer_pool() -> &'static Arc<BufferPool> {
    static POOL: OnceLock<Arc<BufferPool>> = OnceLock::new();
    POOL.get_or_init(BufferPool::new)
}

// ── gRPC frame encode / decode ────────────────────────────────────────────────

/// Encode `payload` as a gRPC length-prefixed frame.
pub fn encode_grpc_frame(payload: &[u8]) -> Bytes {
    let mut buf = BytesMut::with_capacity(FRAME_HEADER_LEN + payload.len());
    append_grpc_frame(&mut buf, payload);
    buf.freeze()
}

fn append_grpc_frame(buf: &mut BytesMut, payload: &[u8]) {
    buf.put_u8(0x00); // not compressed
    buf.put_u32(payload.len() as u32);
    buf.put_slice(payload);
}

fn append_grpc_frame_prefix(buf: &mut BytesMut, payload_len: usize) {
    buf.put_u8(0x00); // not compressed
    buf.put_u32(payload_len as u32);
}

// ── protobuf Hunk encode / decode ─────────────────────────────────────────────

fn append_hunk(buf: &mut BytesMut, data: &[u8]) {
    buf.put_u8(0x0A); // field 1, wire type 2
    put_varint(data.len() as u64, buf);
    buf.put_slice(data);
}

/// Decode a protobuf `Hunk { bytes data = 1; }` message, returning the inner bytes.
///
/// Returns an error if the tag is missing or wrong, or if the length prefix
/// extends beyond the supplied slice.
fn decode_hunk(payload: Bytes) -> Result<Bytes, ProxyError> {
    if payload.is_empty() {
        return Ok(Bytes::new());
    }
    if payload[0] != 0x0A {
        return Err(ProxyError::Protocol(format!(
            "gRPC Gun: expected Hunk field tag 0x0A, got {:#x}",
            payload[0]
        )));
    }
    let (data_len, varint_len) = get_varint(&payload[1..]).ok_or_else(|| {
        ProxyError::Protocol("gRPC Gun: truncated or oversized Hunk varint".into())
    })?;
    let offset = 1 + varint_len;
    let end = offset + data_len;
    if payload.len() < end {
        return Err(ProxyError::Protocol(
            "gRPC Gun: Hunk data extends past message boundary".into(),
        ));
    }
    Ok(payload.slice(offset..end))
}

/// Append a protobuf varint encoding of `val` to `buf`.
fn put_varint(mut val: u64, buf: &mut BytesMut) {
    loop {
        let byte = (val & 0x7F) as u8;
        val >>= 7;
        if val == 0 {
            buf.put_u8(byte);
            return;
        }
        buf.put_u8(byte | 0x80);
    }
}

/// Decode a protobuf varint from `buf`.
///
/// Returns `Some((value, bytes_consumed))` or `None` if the slice is empty,
/// truncated, or the value overflows 64 bits.
fn get_varint(buf: &[u8]) -> Option<(usize, usize)> {
    let mut val: u64 = 0;
    let mut shift = 0u32;
    for (i, &byte) in buf.iter().enumerate() {
        if shift >= 64 {
            return None; // overflow
        }
        val |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            return Some((val as usize, i + 1));
        }
        shift += 7;
    }
    None // truncated
}

/// Decode the next gRPC frame from a buffer.
///
/// Returns `Some(payload_bytes)` if a complete frame is in `buf`, or `None`
/// if more data is needed. On success the consumed bytes are removed from
/// `buf`.
pub fn decode_grpc_frame(buf: &mut BytesMut) -> Result<Option<Bytes>, ProxyError> {
    if buf.len() < FRAME_HEADER_LEN {
        return Ok(None);
    }

    let compressed = buf[0];
    if compressed != 0x00 {
        return Err(ProxyError::Transport(format!(
            "gRPC: compressed frames not supported (flag={compressed:#x})"
        )));
    }

    let len_bytes: [u8; 4] = buf[1..5]
        .try_into()
        .map_err(|_| ProxyError::Protocol("gRPC: invalid frame header".into()))?;
    let len = u32::from_be_bytes(len_bytes);
    if len > MAX_MESSAGE_SIZE {
        return Err(ProxyError::Transport(format!(
            "gRPC: message too large ({len} bytes)"
        )));
    }

    let total = FRAME_HEADER_LEN + len as usize;
    if buf.len() < total {
        return Ok(None); // need more data
    }

    buf.advance(FRAME_HEADER_LEN); // consume header
    let payload = buf.split_to(len as usize).freeze();
    Ok(Some(payload))
}

// ── GrpcStream: BoxedStream wrapper ──────────────────────────────────────────

/// A `BoxedStream`-compatible stream that wraps another stream in gRPC framing.
///
/// Writes are buffered and flushed as single gRPC frames.
/// Reads decode incoming gRPC frames and serve their payloads transparently.
pub struct GrpcStream {
    /// The underlying HTTP/2 (or TCP for tests) byte stream.
    inner: BoxedStream,

    /// Buffer of raw bytes from the inner stream (undecoded).
    recv_buf: BytesMut,

    /// Decoded payload bytes ready to serve to readers.
    read_buf: Bytes,

    /// Pre-encoded gRPC frames waiting to be flushed to the inner stream.
    write_buf: BytesMut,
}

impl GrpcStream {
    /// Wrap an existing stream in gRPC framing.
    pub fn new(inner: BoxedStream) -> Self {
        Self {
            inner,
            recv_buf: grpc_buffer_pool().acquire(16 * 1024),
            read_buf: Bytes::new(),
            write_buf: grpc_buffer_pool().acquire(16 * 1024),
        }
    }
}

impl Drop for GrpcStream {
    fn drop(&mut self) {
        grpc_buffer_pool().release(std::mem::take(&mut self.recv_buf));
        grpc_buffer_pool().release(std::mem::take(&mut self.write_buf));
    }
}

impl AsyncRead for GrpcStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            // Serve from already-decoded payload.
            if !self.read_buf.is_empty() {
                let n = self.read_buf.len().min(buf.remaining());
                buf.put_slice(&self.read_buf[..n]);
                let _ = self.read_buf.split_to(n);
                return Poll::Ready(Ok(()));
            }

            // Try to decode a frame from recv_buf.
            match decode_grpc_frame(&mut self.recv_buf) {
                Err(e) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        e.to_string(),
                    )));
                }
                Ok(Some(payload)) => {
                    if payload.is_empty() {
                        return Poll::Ready(Ok(())); // end of stream
                    }
                    let payload_len = payload.len();
                    let payload_first_byte = payload.first().copied().unwrap_or(0);
                    // Unwrap the protobuf Hunk message to get the raw tunnelled bytes.
                    match decode_hunk(payload) {
                        Ok(data) => {
                            tracing::trace!(
                                payload_len,
                                data_len = data.len(),
                                first_bytes = %hex::encode(&data[..data.len().min(20)]),
                                "gRPC: decoded Hunk"
                            );
                            self.read_buf = data;
                        }
                        Err(e) => {
                            tracing::warn!(
                                payload_len,
                                first_byte = format!("{:#04x}", payload_first_byte),
                                "gRPC: Hunk decode failed: {e}"
                            );
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                e.to_string(),
                            )));
                        }
                    }
                    continue;
                }
                Ok(None) => {} // need more data
            }

            // Read more data from the inner stream.
            let mut tmp = [0u8; 8192];
            let mut tmp_buf = ReadBuf::new(&mut tmp);
            match Pin::new(self.inner.as_mut()).poll_read(cx, &mut tmp_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {
                    let n = tmp_buf.filled().len();
                    if n == 0 {
                        return Poll::Ready(Ok(())); // EOF
                    }
                    self.recv_buf.extend_from_slice(&tmp[..n]);
                }
            }
        }
    }
}

impl AsyncWrite for GrpcStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Encode each write immediately as a bounded gRPC frame (xray pattern).
        // This prevents unbounded write_buf growth when flush is delayed.
        let n = buf.len().min(MAX_MESSAGE_SIZE as usize);
        let data = &buf[..n];
        let mut varint_len = 1usize;
        let mut remaining = data.len() as u64;
        while remaining >= 0x80 {
            remaining >>= 7;
            varint_len += 1;
        }
        let hunk_len = 1 + varint_len + data.len();
        self.write_buf.reserve(FRAME_HEADER_LEN + hunk_len);
        append_grpc_frame_prefix(&mut self.write_buf, hunk_len);
        append_hunk(&mut self.write_buf, data);
        Poll::Ready(Ok(n))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.write_buf.is_empty() {
            let this = self.as_mut().get_mut();
            match Pin::new(this.inner.as_mut()).poll_write(cx, &this.write_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "gRPC frame write returned zero bytes",
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

// ── HTTP/2 handshake helpers ──────────────────────────────────────────────────

/// Perform a gRPC client handshake and return a `BoxedStream` wrapping the
/// bidirectional gRPC data channel.
///
/// # Arguments
/// * `tcp_stream`   — an already-connected TCP (or TLS) stream
/// * `authority`    — the HTTP/2 `:authority` (Host) pseudo-header value
/// * `service_name` — the gRPC service name (path = `/{service_name}/Tun`)
pub async fn grpc_connect(
    tcp_stream: BoxedStream,
    authority: &str,
    service_name: &str,
) -> Result<BoxedStream, ProxyError> {
    use h2::client;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (h2, conn) = client::Builder::new()
        .handshake(tcp_stream)
        .await
        .map_err(|e| ProxyError::Transport(format!("gRPC h2 handshake failed: {e}")))?;

    // Drive the connection in the background.
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let path = format!("/{service_name}/Tun");

    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri(format!("https://{authority}{path}"))
        .header(http::header::CONTENT_TYPE, "application/grpc")
        .header(http::header::TE, "trailers")
        .header("grpc-encoding", "identity")
        .body(())
        .map_err(|e| ProxyError::Transport(format!("gRPC request build failed: {e}")))?;

    let mut h2_ready = h2
        .ready()
        .await
        .map_err(|e| ProxyError::Transport(format!("gRPC h2 ready failed: {e}")))?;

    let (response_future, send_stream) = h2_ready
        .send_request(request, false)
        .map_err(|e| ProxyError::Transport(format!("gRPC send_request failed: {e}")))?;

    // Use a duplex pipe to bridge the h2 streams.
    let (proxy_end, user_end) = tokio::io::duplex(256 * 1024);
    let (mut proxy_reader, mut proxy_writer) = tokio::io::split(proxy_end);

    let mut send_h2 = send_stream;

    // Task: h2 response → proxy_writer (so user can read from user_end).
    tokio::spawn(async move {
        let response = match response_future.await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = %e, "gRPC upstream response failed");
                return;
            }
        };
        if response.status() != http::StatusCode::OK {
            tracing::warn!(status = %response.status(), "gRPC upstream returned non-200; treating as connection failure");
            return; // proxy_writer EOF signals the failure to the reader
        }
        let mut recv_body = response.into_body();
        loop {
            match recv_body.data().await {
                None => break,
                Some(Err(_)) => break,
                Some(Ok(chunk)) => {
                    let _ = recv_body.flow_control().release_capacity(chunk.len());
                    if proxy_writer.write_all(&chunk).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    // Task: proxy_reader → h2 send (so writes from user_end reach the server).
    tokio::spawn(async move {
        let mut buf = [0u8; 8192];
        loop {
            let n = match proxy_reader.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            let data = Bytes::copy_from_slice(&buf[..n]);
            if let Err(e) = send_h2.send_data(data, false) {
                tracing::warn!(error = %e, "gRPC send_data failed");
                break;
            }
        }
        let _ = send_h2.send_data(Bytes::new(), true);
    });

    Ok(Box::new(GrpcStream::new(Box::new(user_end))))
}

/// Accept a gRPC tunnel connection on an already-established stream.
///
/// Returns a `BoxedStream` wrapping the gRPC data channel.
pub async fn grpc_accept(
    tcp_stream: BoxedStream,
    service_name: &str,
) -> Result<BoxedStream, ProxyError> {
    use h2::server;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut conn = server::Builder::new()
        .handshake(tcp_stream)
        .await
        .map_err(|e| ProxyError::Transport(format!("gRPC h2 server handshake failed: {e}")))?;

    let expected_path = format!("/{service_name}/Tun");

    // Accept the next request.
    let (request, mut respond) = conn
        .accept()
        .await
        .ok_or_else(|| ProxyError::Transport("gRPC: no incoming request".into()))?
        .map_err(|e| ProxyError::Transport(format!("gRPC accept error: {e}")))?;

    let path = request.uri().path().to_string();
    tracing::warn!(path = %path, expected = %expected_path, "gRPC: incoming request");
    if path != expected_path {
        return Err(ProxyError::Protocol(format!(
            "gRPC: unexpected path '{path}' (expected '{expected_path}')"
        )));
    }

    // Send 200 headers back.
    let response = http::Response::builder()
        .status(200)
        .header(http::header::CONTENT_TYPE, "application/grpc")
        .body(())
        .map_err(|e| ProxyError::Protocol(format!("gRPC: invalid static response: {e}")))?;

    let send_stream = respond
        .send_response(response, false)
        .map_err(|e| ProxyError::Transport(format!("gRPC send_response failed: {e}")))?;

    let recv_body = request.into_body();

    // Drive the connection in background so additional streams (none expected) are handled.
    tokio::spawn(async move { while conn.accept().await.is_some() {} });

    // Use a duplex pipe to bridge the h2 streams.
    let (proxy_end, user_end) = tokio::io::duplex(256 * 1024);
    let (mut proxy_reader, mut proxy_writer) = tokio::io::split(proxy_end);

    let mut recv = recv_body;
    let mut send = send_stream;

    // Task: h2 recv → proxy_writer (so user can read from user_end).
    tokio::spawn(async move {
        loop {
            match recv.data().await {
                None => break,
                Some(Err(_)) => break,
                Some(Ok(chunk)) => {
                    let _ = recv.flow_control().release_capacity(chunk.len());
                    if proxy_writer.write_all(&chunk).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    // Task: proxy_reader → h2 send (so writes from user_end reach the client).
    tokio::spawn(async move {
        let mut buf = [0u8; 8192];
        loop {
            let n = match proxy_reader.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            let data = Bytes::copy_from_slice(&buf[..n]);
            if send.send_data(data, false).is_err() {
                break;
            }
        }
        let _ = send.send_data(Bytes::new(), true);
    });

    Ok(Box::new(GrpcStream::new(Box::new(user_end))))
}

#[cfg(test)]
mod tests;
