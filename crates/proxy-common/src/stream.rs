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
//! # `Link` — splitting a stream into reader + writer
//!
//! Some parts of the dispatcher need separate read and write halves so they can
//! pump bytes in both directions independently (bidirectional relay). `Link`
//! holds those two halves.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A trait that combines both `AsyncRead` and `AsyncWrite`.
///
/// Every transport produces a type that implements this trait.
/// Every protocol consumes a `BoxedStream`, which is a `Box<dyn AsyncReadWrite>`.
///
/// You do not need to implement this yourself — the blanket impl below
/// automatically implements it for anything that is already both `AsyncRead`
/// and `AsyncWrite`.
pub trait AsyncReadWrite: AsyncRead + AsyncWrite {}

// Blanket implementation: anything that is already AsyncRead + AsyncWrite
// automatically becomes AsyncReadWrite. This means TlsStream, WebSocketStream,
// TcpStream, and any adapter types all just work without extra boilerplate.
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> AsyncReadWrite for T {}

/// A heap-allocated, type-erased byte stream.
///
/// This is what every transport hands to every protocol. The protocol reads
/// and writes bytes through this, without knowing what is underneath.
///
/// The `Box<dyn ...>` means there is one level of heap indirection per
/// connection, but that cost is negligible compared to the cost of actually
/// reading/writing network data.
pub type BoxedStream = Box<dyn AsyncReadWrite + Send + Unpin + 'static>;

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
