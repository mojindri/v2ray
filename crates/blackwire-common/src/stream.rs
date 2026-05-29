//! The universal byte-stream abstraction used across the whole proxy.
//!
//! # The core idea
//!
//! Every protocol (VLESS, VMess, Trojan, Shadowsocks, SOCKS5…) needs to read
//! and write bytes to a connection. Every transport (TCP, WebSocket, gRPC,
//! QUIC…) provides a connection that can be read from and written to.
//!
//! Rather than having each protocol know about every transport, we define a
//! single trait — `AsyncReadWrite` — that every transport implements. Protocols
//! only ever talk to a `BoxedStream`, which is a heap-allocated trait object.
//! The protocol code cannot tell whether the bytes are coming over a raw TCP
//! socket, a WebSocket frame, or a gRPC stream — and it does not need to.
//!
//! # The orthogonality invariant
//!
//! Protocol code MUST NOT downcast `BoxedStream` to learn the concrete transport
//! type. If you find yourself writing `stream.downcast::<TcpStream>()`, you are
//! breaking the abstraction. The whole point is that protocols are oblivious to
//! transports and vice versa.
//!
//! The only exception is infrastructure code that owns the relay implementation.
//! On Linux, the relay can optimize raw TCP sockets with `splice(2)`, so this
//! module exposes a small Linux-only helper for that specific case. Protocols
//! should still treat `BoxedStream` as completely opaque.
//!
//! # `Link` — splitting a stream into reader + writer
//!
//! Some parts of the dispatcher need separate read and write halves so they can
//! pump bytes in both directions independently (bidirectional relay). `Link`
//! holds those two halves.

use std::any::Any;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
#[cfg(target_os = "linux")]
use tokio::net::TcpStream;

/// A trait that combines both `AsyncRead` and `AsyncWrite`.
///
/// Every transport produces a type that implements this trait.
/// Every protocol consumes a `BoxedStream`, which is a `Box<dyn AsyncReadWrite>`.
///
/// You do not need to implement this yourself — the blanket impl below
/// automatically implements it for anything that is already both `AsyncRead`
/// and `AsyncWrite`.
pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Any {
    /// Return this stream as `Any` for infrastructure-level type recovery.
    ///
    /// `Any` is Rust's safe runtime type check. We use it only to ask a narrow
    /// question in the relay layer: "is this boxed stream still a raw TCP
    /// socket?" If the answer is no, normal async copying is used.
    fn as_any(&self) -> &dyn Any;

    /// Convert this boxed stream into `Any` for infrastructure-level downcast.
    ///
    /// This consumes the box. That matters because recovering a `TcpStream`
    /// means we need ownership of the socket, not just a borrowed reference.
    fn into_any(self: Box<Self>) -> Box<dyn Any + Send>;
}

// Blanket implementation: anything that is already AsyncRead + AsyncWrite
// automatically becomes AsyncReadWrite. This means TlsStream, WebSocketStream,
// TcpStream, and any adapter types all just work without extra boilerplate.
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> AsyncReadWrite for T {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any + Send> {
        self
    }
}

/// A heap-allocated, type-erased byte stream.
///
/// This is what every transport hands to every protocol. The protocol reads
/// and writes bytes through this, without knowing what is underneath.
///
/// The `Box<dyn ...>` means there is one level of heap indirection per
/// connection, but that cost is negligible compared to the cost of actually
/// reading/writing network data.
pub type BoxedStream = Box<dyn AsyncReadWrite + Send + Unpin + 'static>;

const VISION_INITIAL: i32 = -1;
const VISION_COMMAND_PADDING_CONTINUE: i32 = 0;
const VISION_COMMAND_PADDING_END: i32 = 1;
const VISION_COMMAND_PADDING_DIRECT: i32 = 2;
const TLS_APPLICATION_DATA_START: [u8; 3] = [0x17, 0x03, 0x03];

/// Per-direction XTLS Vision unpadding state.
#[derive(Debug, Clone, Default)]
struct VisionUnpaddingState {
    remaining_command: i32,
    remaining_content: i32,
    remaining_padding: i32,
    current_command: i32,
}

impl VisionUnpaddingState {
    fn new() -> Self {
        Self {
            remaining_command: VISION_INITIAL,
            remaining_content: VISION_INITIAL,
            remaining_padding: VISION_INITIAL,
            ..Default::default()
        }
    }

    /// Feed bytes into `out`; returns `true` when the stream should switch to direct copy.
    fn feed(&mut self, uuid: &[u8; 16], input: &[u8], out: &mut Vec<u8>) -> bool {
        let mut switch_to_direct = false;
        let mut pos = 0usize;
        while pos < input.len() {
            if self.remaining_command == VISION_INITIAL
                && self.remaining_content == VISION_INITIAL
                && self.remaining_padding == VISION_INITIAL
            {
                if input.len().saturating_sub(pos) >= 21 && input[pos..pos + 16] == uuid[..] {
                    pos += 16;
                    self.remaining_command = 5;
                } else {
                    out.extend_from_slice(&input[pos..]);
                    return switch_to_direct;
                }
            }

            if self.remaining_command > 0 {
                let byte = input[pos];
                pos += 1;
                match self.remaining_command {
                    5 => self.current_command = i32::from(byte),
                    4 => self.remaining_content = i32::from(byte) << 8,
                    3 => self.remaining_content |= i32::from(byte),
                    2 => self.remaining_padding = i32::from(byte) << 8,
                    1 => self.remaining_padding |= i32::from(byte),
                    _ => {}
                }
                self.remaining_command -= 1;
            } else if self.remaining_content > 0 {
                let take = (self.remaining_content as usize).min(input.len() - pos);
                out.extend_from_slice(&input[pos..pos + take]);
                pos += take;
                self.remaining_content -= take as i32;
            } else if self.remaining_padding > 0 {
                let skip = (self.remaining_padding as usize).min(input.len() - pos);
                pos += skip;
                self.remaining_padding -= skip as i32;
            }

            if self.remaining_command <= 0
                && self.remaining_content <= 0
                && self.remaining_padding <= 0
            {
                if self.current_command == VISION_COMMAND_PADDING_CONTINUE {
                    self.remaining_command = 5;
                } else {
                    switch_to_direct = self.current_command == VISION_COMMAND_PADDING_DIRECT;
                    self.remaining_command = VISION_INITIAL;
                    self.remaining_content = VISION_INITIAL;
                    self.remaining_padding = VISION_INITIAL;
                    if pos < input.len() {
                        out.extend_from_slice(&input[pos..]);
                    }
                    break;
                }
            }
        }
        switch_to_direct
    }
}

/// XTLS Vision stream wrapper.
///
/// Protocol handlers use it as an opaque stream adapter. The Linux relay may
/// recover `VisionStream<BoxedStream>` after both directions have reached
/// Vision direct-copy mode and continue through the raw TCP splice path.
pub struct VisionStream<S> {
    inner: S,
    uuid: [u8; 16],
    read_state: VisionUnpaddingState,
    read_buf: Vec<u8>,
    feed_scratch: Vec<u8>,
    read_direct_copy: bool,
    write_uuid_once: bool,
    write_direct_copy: bool,
    write_buf: Vec<u8>,
    write_pos: usize,
}

impl<S> VisionStream<S> {
    /// Wrap `inner` with XTLS Vision padding/unpadding for the given VLESS UUID.
    pub fn new(inner: S, uuid: [u8; 16]) -> Self {
        Self {
            inner,
            uuid,
            read_state: VisionUnpaddingState::new(),
            read_buf: Vec::new(),
            feed_scratch: Vec::new(),
            read_direct_copy: false,
            write_uuid_once: true,
            write_direct_copy: false,
            write_buf: Vec::new(),
            write_pos: 0,
        }
    }

    /// Unwrap the underlying stream after Vision processing.
    pub fn into_inner(self) -> S {
        self.inner
    }

    /// Whether Vision has switched both directions to direct copy and has no buffered plaintext.
    pub fn is_direct_copy_ready(&self) -> bool {
        self.read_direct_copy
            && self.write_direct_copy
            && self.read_buf.is_empty()
            && self.write_buf.is_empty()
    }
}

impl VisionStream<BoxedStream> {
    /// True when the wrapped erased stream can still be recovered as raw TCP.
    #[cfg(target_os = "linux")]
    pub fn inner_is_tcp_like(&self) -> bool {
        boxed_stream_is_tcp_like(&self.inner)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for VisionStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.read_direct_copy {
            return Pin::new(&mut self.inner).poll_read(cx, buf);
        }

        loop {
            if !self.read_buf.is_empty() {
                let n = buf.remaining().min(self.read_buf.len());
                buf.put_slice(&self.read_buf[..n]);
                self.read_buf.drain(..n);
                return Poll::Ready(Ok(()));
            }

            let mut tmp = [0u8; 8192];
            let mut rb = ReadBuf::new(&mut tmp);
            match Pin::new(&mut self.inner).poll_read(cx, &mut rb) {
                Poll::Ready(Ok(())) => {
                    if rb.filled().is_empty() {
                        return Poll::Ready(Ok(()));
                    }
                    let uuid = self.uuid;
                    let mut scratch = std::mem::take(&mut self.feed_scratch);
                    scratch.clear();
                    let switch_to_direct = self.read_state.feed(&uuid, rb.filled(), &mut scratch);
                    self.feed_scratch = scratch;
                    if switch_to_direct {
                        self.read_direct_copy = true;
                    }
                    if self.feed_scratch.is_empty() {
                        continue;
                    }
                    let n = buf.remaining().min(self.feed_scratch.len());
                    buf.put_slice(&self.feed_scratch[..n]);
                    if n < self.feed_scratch.len() {
                        let extra = self.feed_scratch[n..].to_vec();
                        self.read_buf.extend_from_slice(&extra);
                    }
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> VisionStream<S> {
    fn poll_drain_write_buf(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        while self.write_pos < self.write_buf.len() {
            let chunk = self.write_buf[self.write_pos..].to_vec();
            match Pin::new(&mut self.inner).poll_write(cx, &chunk) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "failed to write Vision frame",
                    )));
                }
                Poll::Ready(Ok(n)) => self.write_pos += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.write_buf.clear();
        self.write_pos = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for VisionStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if !self.write_buf.is_empty() {
            match self.as_mut().poll_drain_write_buf(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        if self.write_direct_copy {
            return Pin::new(&mut self.inner).poll_write(cx, buf);
        }
        if buf.is_empty() {
            return Pin::new(&mut self.inner).poll_write(cx, buf);
        }

        let include_uuid = self.write_uuid_once;
        if include_uuid {
            self.write_uuid_once = false;
        }
        let command = if looks_like_tls_application_data(buf) && is_complete_tls_record(buf) {
            VISION_COMMAND_PADDING_DIRECT as u8
        } else {
            VISION_COMMAND_PADDING_END as u8
        };
        self.write_buf = vision_pad_chunk(&self.uuid, buf, command, include_uuid);
        self.write_pos = 0;

        match self.as_mut().poll_drain_write_buf(cx) {
            Poll::Ready(Ok(())) => {
                if command == VISION_COMMAND_PADDING_DIRECT as u8 {
                    self.write_direct_copy = true;
                }
                Poll::Ready(Ok(buf.len()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().poll_drain_write_buf(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_flush(cx),
            other => other,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().poll_drain_write_buf(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_shutdown(cx),
            other => other,
        }
    }
}

/// Wrap a boxed stream for Vision flow.
pub fn wrap_vision_stream(stream: BoxedStream, uuid: [u8; 16]) -> BoxedStream {
    Box::new(VisionStream::new(stream, uuid))
}

fn vision_pad_chunk(uuid: &[u8; 16], content: &[u8], command: u8, include_uuid: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(21 + content.len());
    if include_uuid {
        out.extend_from_slice(uuid);
    }
    let cl = content.len();
    out.push(command);
    out.push((cl >> 8) as u8);
    out.push((cl & 0xff) as u8);
    out.push(0);
    out.push(0);
    out.extend_from_slice(content);
    out
}

fn looks_like_tls_application_data(buf: &[u8]) -> bool {
    buf.len() >= 6 && buf[..3] == TLS_APPLICATION_DATA_START
}

fn is_complete_tls_record(buf: &[u8]) -> bool {
    let mut pos = 0usize;
    while pos < buf.len() {
        if buf.len() - pos < 5 {
            return false;
        }
        if buf[pos..pos + 3] != TLS_APPLICATION_DATA_START {
            return false;
        }
        let record_len = u16::from_be_bytes([buf[pos + 3], buf[pos + 4]]) as usize;
        pos += 5;
        if buf.len() - pos < record_len {
            return false;
        }
        pos += record_len;
    }
    true
}

/// Marks a stream that came from an optimistic preconnect pool.
///
/// The dispatcher can use this narrow marker to apply a first-use guard
/// without exposing pool internals through the outbound trait.
pub struct PooledStream<S> {
    inner: S,
    pool_tag: Option<String>,
    peer_addr: Option<SocketAddr>,
}

impl<S> PooledStream<S> {
    /// Wrap a stream with no pool metadata.
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            pool_tag: None,
            peer_addr: None,
        }
    }

    /// Wrap a stream with a pool tag for first-use tracking.
    pub fn with_pool_tag(inner: S, pool_tag: impl Into<String>) -> Self {
        Self {
            inner,
            pool_tag: Some(pool_tag.into()),
            peer_addr: None,
        }
    }

    /// Return the pool tag if this stream came from a pool.
    pub fn pool_tag(&self) -> Option<&str> {
        self.pool_tag.as_deref()
    }

    /// Wrap a stream with both a pool tag and the peer address.
    pub fn with_pool_metadata(
        inner: S,
        pool_tag: impl Into<String>,
        peer_addr: SocketAddr,
    ) -> Self {
        Self {
            inner,
            pool_tag: Some(pool_tag.into()),
            peer_addr: Some(peer_addr),
        }
    }

    /// Return the peer address if known.
    pub fn peer_addr(&self) -> Option<SocketAddr> {
        self.peer_addr
    }

    /// Unwrap to the inner stream, discarding metadata.
    pub fn into_inner(self) -> S {
        self.inner
    }

    /// Unwrap to `(inner, pool_tag)`.
    pub fn into_parts(self) -> (S, Option<String>) {
        (self.inner, self.pool_tag)
    }

    /// Unwrap to `(inner, pool_tag, peer_addr)`.
    pub fn into_metadata_parts(self) -> (S, Option<String>, Option<SocketAddr>) {
        (self.inner, self.pool_tag, self.peer_addr)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PooledStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PooledStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Recover a raw TCP stream from a boxed stream when the transport is still TCP.
///
/// This is intentionally Linux-only because the only current caller is the
/// Linux `splice(2)` relay path. Protocol code should continue to treat
/// `BoxedStream` as opaque.
#[cfg(target_os = "linux")]
pub fn try_into_tcp_stream(stream: BoxedStream) -> Result<TcpStream, BoxedStream> {
    match try_into_tcp_stream_with_prefix(stream) {
        Ok((tcp, prefix)) if prefix.is_empty() => Ok(tcp),
        Ok((tcp, prefix)) => Err(Box::new(PrependedStream::new(tcp, prefix))),
        Err(stream) => Err(stream),
    }
}

/// Recover a raw TCP stream plus unread prefix bytes from a boxed stream.
///
/// Some protocol handlers buffer a few bytes past the handshake boundary using
/// `PrependedStream`. The relay can still optimize those connections by
/// draining the unread prefix first, then switching to splice on the recovered
/// raw sockets.
///
/// # Type detection note
///
/// We use `(*stream).as_any()` (deref through the Box) rather than
/// `stream.as_any()` to force vtable dispatch.  The blanket impl that makes
/// `Box<dyn AsyncReadWrite>` itself implement `AsyncReadWrite` would otherwise
/// intercept `as_any()` and return the box type instead of the concrete inner
/// type.  Dereffing ensures the vtable for the concrete type is used.
#[cfg(target_os = "linux")]
pub fn try_into_tcp_stream_with_prefix(
    stream: BoxedStream,
) -> Result<(TcpStream, Vec<u8>), BoxedStream> {
    // Check the concrete type via vtable dispatch (`*stream` not `stream`).
    if (*stream).as_any().is::<TcpStream>() {
        let any = stream.into_any();
        let tcp = any
            .downcast::<TcpStream>()
            .expect("stream type checked as TcpStream before downcast");
        return Ok((*tcp, Vec::new()));
    }

    if (*stream).as_any().is::<PrependedStream<TcpStream>>() {
        let any = stream.into_any();
        let prepended = any
            .downcast::<PrependedStream<TcpStream>>()
            .expect("stream type checked as PrependedStream<TcpStream> before downcast");
        let (tcp, prefix) = prepended.into_parts();
        return Ok((tcp, prefix));
    }

    if (*stream).as_any().is::<PooledStream<TcpStream>>() {
        let any = stream.into_any();
        let pooled = any
            .downcast::<PooledStream<TcpStream>>()
            .expect("stream type checked as PooledStream<TcpStream> before downcast");
        let (tcp, _, _) = pooled.into_metadata_parts();
        return Ok((tcp, Vec::new()));
    }

    if (*stream).as_any().is::<PrependedStream<BoxedStream>>() {
        let any = stream.into_any();
        let prepended = any
            .downcast::<PrependedStream<BoxedStream>>()
            .expect("stream type checked as PrependedStream<BoxedStream> before downcast");
        let (inner, mut prefix) = prepended.into_parts();

        return match try_into_tcp_stream_with_prefix(inner) {
            Ok((tcp, mut inner_prefix)) => {
                if prefix.is_empty() {
                    Ok((tcp, inner_prefix))
                } else if inner_prefix.is_empty() {
                    Ok((tcp, prefix))
                } else {
                    prefix.append(&mut inner_prefix);
                    Ok((tcp, prefix))
                }
            }
            Err(inner) => Err(Box::new(PrependedStream::new(inner, prefix))),
        };
    }

    // Not raw TCP: hand the original stream back to the caller so it can
    // use the portable fallback path without losing any data.
    Err(stream)
}

#[cfg(target_os = "linux")]
fn boxed_stream_is_tcp_like(stream: &BoxedStream) -> bool {
    (*stream).as_any().is::<TcpStream>()
        || (*stream).as_any().is::<PrependedStream<TcpStream>>()
        || (*stream).as_any().is::<PooledStream<TcpStream>>()
        || (*stream).as_any().is::<PrependedStream<BoxedStream>>()
}

/// Recover a Vision wrapper from a boxed stream for Linux relay infrastructure.
#[cfg(target_os = "linux")]
pub fn try_into_vision_stream(
    stream: BoxedStream,
) -> Result<VisionStream<BoxedStream>, BoxedStream> {
    if (*stream).as_any().is::<VisionStream<BoxedStream>>() {
        let any = stream.into_any();
        let vision = any
            .downcast::<VisionStream<BoxedStream>>()
            .expect("stream type checked as VisionStream<BoxedStream> before downcast");
        return Ok(*vision);
    }
    Err(stream)
}

/// A bidirectional link: separate read and write halves of a stream.
///
/// Used by the dispatcher when it needs to relay bytes between two connections
/// simultaneously. For example: read from the inbound connection, write to the
/// outbound connection — and at the same time read from the outbound connection
/// and write to the inbound connection.
///
/// # Why not just use `BoxedStream` directly?
///
/// `tokio::io::copy_bidirectional` requires two separate `AsyncRead +
/// AsyncWrite` references. Creating a `Link` by splitting a stream is the
/// clean way to get those two independent handles.
pub struct Link {
    /// The reading half: bytes coming from the remote end.
    pub reader: Box<dyn AsyncRead + Send + Unpin + 'static>,
    /// The writing half: bytes going to the remote end.
    pub writer: Box<dyn AsyncWrite + Send + Unpin + 'static>,
}

impl Link {
    /// Split a `BoxedStream` into its read and write halves.
    ///
    /// After calling this, you can pass `reader` and `writer` to separate
    /// async tasks. The underlying stream is shared safely via tokio's split
    /// mechanism.
    pub fn from_stream(stream: BoxedStream) -> Self {
        let (r, w) = tokio::io::split(stream);
        Self {
            reader: Box::new(r),
            writer: Box::new(w),
        }
    }
}

/// A stream that prepends a fixed buffer before passing through to the inner stream.
///
/// # Why is this needed?
///
/// REALITY (and similar protocols) need to peek at the first bytes of a
/// connection to decide whether the client is authentic. They read the TLS
/// record header and ClientHello from the TCP socket — but then need to hand
/// the *entire* stream (including those already-read bytes) to rustls or a
/// fallback backend.
///
/// `PrependedStream` solves this by holding the already-read bytes in a buffer.
/// When `AsyncRead` is polled, it returns bytes from the buffer first, then
/// falls through to the underlying stream once the buffer is exhausted.
pub struct PrependedStream<S> {
    /// Bytes that were already read and need to be re-served before the inner stream.
    prefix: Vec<u8>,
    /// How many bytes of the prefix have already been returned to the caller.
    prefix_pos: usize,
    /// The underlying stream. Once `prefix` is exhausted, reads go here.
    inner: S,
}

impl<S> PrependedStream<S> {
    /// Create a new `PrependedStream` that will yield `prefix` bytes first,
    /// followed by everything from `inner`.
    pub fn new(inner: S, prefix: Vec<u8>) -> Self {
        Self {
            prefix,
            prefix_pos: 0,
            inner,
        }
    }

    /// Consume the stream and return the unread prefix bytes plus the inner stream.
    pub fn into_parts(self) -> (S, Vec<u8>) {
        let unread = if self.prefix_pos >= self.prefix.len() {
            Vec::new()
        } else {
            self.prefix[self.prefix_pos..].to_vec()
        };
        (self.inner, unread)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrependedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // If there are still prefix bytes to return, copy them into buf first.
        if self.prefix_pos < self.prefix.len() {
            let remaining = &self.prefix[self.prefix_pos..];
            let n = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..n]);
            self.prefix_pos += n;
            return Poll::Ready(Ok(()));
        }
        // Prefix exhausted — delegate to the inner stream.
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrependedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Writes always go directly to the inner stream — the prefix only
        // affects reading.
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Combines separate read and write halves into a single bidirectional stream.
///
/// QUIC gives separate `RecvStream` and `SendStream` halves. This adapter
/// merges them so they satisfy `AsyncRead + AsyncWrite` together — the
/// interface every protocol and outbound handler expects.
///
/// # Usage
///
/// ```rust
/// use blackwire_common::{BoxedStream, ReunionStream};
/// use tokio::io::{duplex, split};
///
/// let (stream_a, _stream_b) = duplex(1024);
/// let (recv, send) = split(stream_a);
/// let stream: BoxedStream = Box::new(ReunionStream::new(recv, send));
/// drop(stream);
/// ```
pub struct ReunionStream<R, W> {
    /// The reading half of the stream (bytes from the remote end).
    read: R,
    /// The writing half of the stream (bytes going to the remote end).
    write: W,
}

impl<R, W> ReunionStream<R, W> {
    /// Create a new `ReunionStream` from separate read and write halves.
    pub fn new(read: R, write: W) -> Self {
        Self { read, write }
    }
}

impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> AsyncRead for ReunionStream<R, W> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.read).poll_read(cx, buf)
    }
}

impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> AsyncWrite for ReunionStream<R, W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.write).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.write).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.write).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Checks that PrependedStream returns the prefix bytes first, then the
    // bytes from the inner stream.
    #[tokio::test]
    async fn prepended_stream_prefix_then_inner() {
        // We use a cursor as a simple in-memory reader instead:
        let inner = std::io::Cursor::new(b"world".to_vec());
        let mut stream = PrependedStream::new(inner, b"hello ".to_vec());

        let mut out = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut out)
            .await
            .unwrap();

        assert_eq!(out, b"hello world");
    }

    // Checks that PrependedStream with an empty prefix behaves like the
    // inner stream directly.
    #[tokio::test]
    async fn prepended_stream_empty_prefix() {
        let inner = std::io::Cursor::new(b"data".to_vec());
        let mut stream = PrependedStream::new(inner, vec![]);

        let mut out = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut out)
            .await
            .unwrap();

        assert_eq!(out, b"data");
    }

    #[test]
    fn vision_passthrough_without_header() {
        let mut st = VisionUnpaddingState::new();
        let uuid = [0u8; 16];
        let mut out = Vec::new();
        let direct = st.feed(&uuid, b"hello world", &mut out);
        assert_eq!(out, b"hello world");
        assert!(!direct);
    }

    #[test]
    fn vision_switches_to_direct_copy_after_direct_command() {
        let uuid = [7u8; 16];
        let mut frame = uuid.to_vec();
        frame.extend_from_slice(&[
            VISION_COMMAND_PADDING_DIRECT as u8,
            0,
            3,
            0,
            0,
            b'a',
            b'b',
            b'c',
        ]);
        frame.extend_from_slice(b"tail");

        let mut st = VisionUnpaddingState::new();
        let mut out = Vec::new();
        let direct = st.feed(&uuid, &frame, &mut out);
        assert_eq!(out, b"abctail");
        assert!(direct);
    }

    #[test]
    fn vision_detects_complete_tls_records() {
        let tls_record = [
            0x17, 0x03, 0x03, 0x00, 0x03, b'a', b'b', b'c', 0x17, 0x03, 0x03, 0x00, 0x01, b'z',
        ];
        assert!(looks_like_tls_application_data(&tls_record));
        assert!(is_complete_tls_record(&tls_record));
        assert!(!is_complete_tls_record(&tls_record[..tls_record.len() - 1]));
    }
}
