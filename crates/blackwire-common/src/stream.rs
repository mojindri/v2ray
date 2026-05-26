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
#[cfg(target_os = "linux")]
pub fn try_into_tcp_stream_with_prefix(
    stream: BoxedStream,
) -> Result<(TcpStream, Vec<u8>), BoxedStream> {
    // First check the type by reference. This avoids consuming the box unless
    // we already know the downcast should succeed.
    if stream.as_any().is::<TcpStream>() {
        let any = stream.into_any();
        let tcp = any
            .downcast::<TcpStream>()
            .expect("stream type checked as TcpStream before downcast");
        return Ok((*tcp, Vec::new()));
    }

    if stream.as_any().is::<PrependedStream<TcpStream>>() {
        let any = stream.into_any();
        let prepended = any
            .downcast::<PrependedStream<TcpStream>>()
            .expect("stream type checked as PrependedStream<TcpStream> before downcast");
        let (tcp, prefix) = prepended.into_parts();
        return Ok((tcp, prefix));
    }

    if stream.as_any().is::<PrependedStream<BoxedStream>>() {
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
}
