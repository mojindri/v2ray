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
/// IO bridge read chunk to reduce per-read overhead on bulk relay paths.
const BRIDGE_READ_CHUNK: usize = 64 * 1024;
/// Coalescing target for a single gRPC Hunk payload on bulk paths.
const COALESCE_TARGET_BYTES: usize = 16 * 1024;
/// Larger h2 flow-control windows reduce update churn during bulk relay.
const H2_INITIAL_WINDOW_SIZE: u32 = 2 * 1024 * 1024;

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

// ── GrpcStream: Gun framing over IO or native HTTP/2 ─────────────────────────

enum GrpcInner {
    /// Duplex/TCP used by unit tests.
    Io(BoxedStream),
    /// Live gRPC Gun tunnel (no intermediate duplex bridge tasks).
    H2 {
        send: h2::SendStream<Bytes>,
        recv: h2::RecvStream,
    },
}

/// Gun-framed bidirectional stream (gRPC length prefix + protobuf Hunk).
///
/// Writes are buffered and flushed as gRPC frames. Reads decode incoming frames
/// and expose the inner tunnel bytes to callers.
pub struct GrpcStream {
    inner: GrpcInner,
    recv_buf: BytesMut,
    read_buf: Bytes,
    pending_plain: BytesMut,
    write_buf: BytesMut,
}

impl GrpcStream {
    /// Wrap an existing byte stream (tests, mocks).
    pub fn new(inner: BoxedStream) -> Self {
        Self::with_inner(GrpcInner::Io(inner))
    }

    fn from_h2(send: h2::SendStream<Bytes>, recv: h2::RecvStream) -> Self {
        Self::with_inner(GrpcInner::H2 { send, recv })
    }

    fn with_inner(inner: GrpcInner) -> Self {
        Self {
            inner,
            recv_buf: grpc_buffer_pool().acquire(16 * 1024),
            read_buf: Bytes::new(),
            pending_plain: grpc_buffer_pool().acquire(16 * 1024),
            write_buf: grpc_buffer_pool().acquire(16 * 1024),
        }
    }

    fn ingest_h2_chunk(&mut self, chunk: Bytes) {
        self.recv_buf.extend_from_slice(&chunk);
    }

    /// Returns `Ok(true)` when bytes were copied into `buf`, `Ok(false)` when more
    /// recv data is needed, or `Err` on decode failure.
    fn serve_decoded_frames(&mut self, buf: &mut ReadBuf<'_>) -> io::Result<bool> {
        loop {
            if !self.read_buf.is_empty() {
                let n = self.read_buf.len().min(buf.remaining());
                buf.put_slice(&self.read_buf[..n]);
                let _ = self.read_buf.split_to(n);
                return Ok(true);
            }

            match decode_grpc_frame(&mut self.recv_buf) {
                Err(e) => {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string()));
                }
                Ok(Some(payload)) => {
                    if payload.is_empty() {
                        return Ok(false);
                    }
                    match decode_hunk(payload) {
                        Ok(data) => self.read_buf = data,
                        Err(e) => {
                            return Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string()));
                        }
                    }
                }
                Ok(None) => return Ok(false),
            }
        }
    }

    fn flush_h2_send(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let GrpcInner::H2 { send, .. } = &mut self.inner else {
            return Poll::Ready(Ok(()));
        };

        while !self.write_buf.is_empty() {
            send.reserve_capacity(self.write_buf.len());
            match send.poll_capacity(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "gRPC send stream closed",
                    )));
                }
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(io::Error::other(e)));
                }
                Poll::Ready(Some(Ok(0))) => {
                    return Poll::Pending;
                }
                Poll::Ready(Some(Ok(cap))) => {
                    let n = cap.min(self.write_buf.len());
                    let chunk = self.write_buf.split_to(n).freeze();
                    send.send_data(chunk, false).map_err(io::Error::other)?;
                }
            }
        }
        Poll::Ready(Ok(()))
    }

    fn encode_pending_plain_into_frames(&mut self, force: bool) {
        while !self.pending_plain.is_empty()
            && (force || self.pending_plain.len() >= COALESCE_TARGET_BYTES)
        {
            let payload_len = self.pending_plain.len().min(MAX_MESSAGE_SIZE as usize);
            let payload = self.pending_plain.split_to(payload_len);
            let mut varint_len = 1usize;
            let mut remaining = payload_len as u64;
            while remaining >= 0x80 {
                remaining >>= 7;
                varint_len += 1;
            }
            let hunk_len = 1 + varint_len + payload_len;
            self.write_buf.reserve(FRAME_HEADER_LEN + hunk_len);
            append_grpc_frame_prefix(&mut self.write_buf, hunk_len);
            append_hunk(&mut self.write_buf, &payload);
        }
    }
}

impl Drop for GrpcStream {
    fn drop(&mut self) {
        grpc_buffer_pool().release(std::mem::take(&mut self.recv_buf));
        grpc_buffer_pool().release(std::mem::take(&mut self.pending_plain));
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
            if self.serve_decoded_frames(buf)? {
                return Poll::Ready(Ok(()));
            }

            match &mut self.inner {
                GrpcInner::Io(inner) => {
                    let mut tmp = [0u8; BRIDGE_READ_CHUNK];
                    let mut tmp_buf = ReadBuf::new(&mut tmp);
                    match Pin::new(inner.as_mut()).poll_read(cx, &mut tmp_buf) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(())) => {
                            let n = tmp_buf.filled().len();
                            if n == 0 {
                                return Poll::Ready(Ok(()));
                            }
                            self.recv_buf.extend_from_slice(&tmp[..n]);
                        }
                    }
                }
                GrpcInner::H2 { recv, .. } => match recv.poll_data(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(None) => return Poll::Ready(Ok(())),
                    Poll::Ready(Some(Err(e))) => {
                        return Poll::Ready(Err(io::Error::other(e)));
                    }
                    Poll::Ready(Some(Ok(chunk))) => {
                        let _ = recv.flow_control().release_capacity(chunk.len());
                        self.ingest_h2_chunk(chunk);
                    }
                },
            }
        }
    }
}

impl AsyncWrite for GrpcStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Coalesce small writes into larger Hunks to reduce h2/gRPC framing cost.
        let n = buf.len().min(MAX_MESSAGE_SIZE as usize);
        self.pending_plain.extend_from_slice(&buf[..n]);
        self.encode_pending_plain_into_frames(false);
        // Keep write-side progress without forcing a full flush on every call.
        let this = self.as_mut().get_mut();
        match &mut this.inner {
            GrpcInner::Io(inner) => {
                while !this.write_buf.is_empty() {
                    match Pin::new(inner.as_mut()).poll_write(cx, &this.write_buf) {
                        Poll::Pending => break,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(0)) => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "gRPC frame write returned zero bytes",
                            )));
                        }
                        Poll::Ready(Ok(written)) => {
                            let _ = this.write_buf.split_to(written);
                        }
                    }
                }
            }
            GrpcInner::H2 { .. } => match this.flush_h2_send(cx) {
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) | Poll::Pending => {}
            },
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        this.encode_pending_plain_into_frames(true);
        match &mut this.inner {
            GrpcInner::Io(inner) => {
                while !this.write_buf.is_empty() {
                    match Pin::new(inner.as_mut()).poll_write(cx, &this.write_buf) {
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
                Pin::new(inner.as_mut()).poll_flush(cx)
            }
            GrpcInner::H2 { .. } => this.flush_h2_send(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        this.encode_pending_plain_into_frames(true);
        if let GrpcInner::Io(inner) = &mut this.inner {
            return Pin::new(inner.as_mut()).poll_shutdown(cx);
        }
        match this.flush_h2_send(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {}
        }
        if let GrpcInner::H2 { send, .. } = &mut this.inner {
            send.send_data(Bytes::new(), true)
                .map_err(io::Error::other)?;
        }
        Poll::Ready(Ok(()))
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

    let (h2, conn) = client::Builder::new()
        .initial_window_size(H2_INITIAL_WINDOW_SIZE)
        .initial_connection_window_size(H2_INITIAL_WINDOW_SIZE)
        .handshake(tcp_stream)
        .await
        .map_err(|e| ProxyError::Transport(format!("gRPC h2 handshake failed: {e}")))?;

    // Drive the connection in the background.
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let path = format!("/{service_name}/Tun");
    let uri = format!("https://{authority}{path}");

    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri(uri)
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

    let response = response_future
        .await
        .map_err(|e| ProxyError::Transport(format!("gRPC upstream response failed: {e}")))?;
    if response.status() != http::StatusCode::OK {
        return Err(ProxyError::Transport(format!(
            "gRPC upstream returned {}",
            response.status()
        )));
    }

    let recv_body = response.into_body();
    Ok(Box::new(GrpcStream::from_h2(send_stream, recv_body)))
}

/// Accept a gRPC tunnel connection on an already-established stream.
///
/// Returns a `BoxedStream` wrapping the gRPC data channel.
pub async fn grpc_accept(
    tcp_stream: BoxedStream,
    service_name: &str,
) -> Result<BoxedStream, ProxyError> {
    use h2::server;

    let mut conn = server::Builder::new()
        .initial_window_size(H2_INITIAL_WINDOW_SIZE)
        .initial_connection_window_size(H2_INITIAL_WINDOW_SIZE)
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

    let path = request.uri().path();
    tracing::debug!(path = %path, expected = %expected_path, "gRPC: incoming request");
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

    // Keep driving the HTTP/2 connection until fully closed. After the first `accept()`
    // (handled above), further `accept()` calls return `None`; we must still `poll_closed`.
    tokio::spawn(async move {
        while let Some(Ok(_)) = conn.accept().await {}
        let _ = std::future::poll_fn(|cx| conn.poll_closed(cx)).await;
    });

    Ok(Box::new(GrpcStream::from_h2(send_stream, recv_body)))
}

#[cfg(test)]
mod tests;
