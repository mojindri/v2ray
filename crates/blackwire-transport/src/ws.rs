//! WebSocket transport — HTTP/1.1 upgrade to binary WebSocket framing.
//!
//! This module wraps a plain TCP stream in a WebSocket connection using
//! `tokio-tungstenite`. After the upgrade handshake, the caller gets a
//! `BoxedStream` that transparently reads/writes binary WebSocket frames.
//!
//! # Protocol overview
//!
//! The client sends a standard HTTP/1.1 Upgrade request:
//! ```text
//! GET /path HTTP/1.1\r\n
//! Host: ...\r\n
//! Upgrade: websocket\r\n
//! Connection: Upgrade\r\n
//! Sec-WebSocket-Key: <base64>\r\n
//! Sec-WebSocket-Version: 13\r\n
//! \r\n
//! ```
//!
//! The server responds with `101 Switching Protocols`. After that, both sides
//! exchange binary WebSocket frames. This module hides all of that and gives
//! the protocol layer a plain `AsyncRead + AsyncWrite` byte stream.
//!
//! # Binary-only
//!
//! This module only handles `Binary` frames. `Text` frames and control frames
//! (Ping, Pong, Close) are handled internally by tungstenite.

use std::io;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};

use bytes::{Bytes, BytesMut};
use futures::sink::Sink;
use futures::stream::Stream;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::{
    accept_async_with_config, client_async_with_config, tungstenite,
    tungstenite::client::IntoClientRequest, tungstenite::protocol::WebSocketConfig,
};
use tungstenite::Message;

use blackwire_common::{BoxedStream, BufferPool, ProxyError};

/// Configuration for a WebSocket connection.
#[derive(Debug, Clone)]
pub struct WsConnectConfig {
    /// HTTP path for the upgrade request (e.g. "/ws").
    pub path: String,

    /// The `Host` header value sent in the upgrade request.
    pub host: String,

    /// Additional HTTP headers to include in the upgrade request.
    pub headers: Vec<(String, String)>,
}

impl Default for WsConnectConfig {
    fn default() -> Self {
        Self {
            path: "/".to_string(),
            host: String::new(),
            headers: Vec::new(),
        }
    }
}

/// Perform a WebSocket client handshake over an existing TCP stream.
///
/// After this function returns, the caller has a `BoxedStream` that
/// transparently wraps WebSocket binary frames. No HTTP framing is visible.
///
/// # Arguments
/// * `tcp_stream` — the already-connected TCP stream to upgrade
/// * `cfg` — WebSocket connection parameters (path, host, headers)
pub async fn ws_connect(
    tcp_stream: BoxedStream,
    cfg: WsConnectConfig,
) -> Result<BoxedStream, ProxyError> {
    // Build a URL for tungstenite. It needs a URL even for an already-connected
    // stream (the host/path go into the HTTP Upgrade request headers).
    let host = if cfg.host.is_empty() {
        "localhost".to_string()
    } else {
        cfg.host.clone()
    };
    let url_str = format!("ws://{host}{}", cfg.path);

    // Use IntoClientRequest on the URL string so tungstenite automatically
    // generates the Sec-WebSocket-Key and other required headers.
    let mut request = url_str
        .into_client_request()
        .map_err(|e| ProxyError::Transport(format!("invalid WebSocket URL: {e}")))?;

    // Append any custom headers.
    for (k, v) in &cfg.headers {
        let name = tungstenite::http::header::HeaderName::from_bytes(k.as_bytes())
            .map_err(|e| ProxyError::Transport(format!("invalid header name '{k}': {e}")))?;
        let value = tungstenite::http::header::HeaderValue::from_str(v)
            .map_err(|e| ProxyError::Transport(format!("invalid header value '{v}': {e}")))?;
        request.headers_mut().insert(name, value);
    }

    let ws_config = WebSocketConfig::default();
    let (ws_stream, _response) = client_async_with_config(request, tcp_stream, Some(ws_config))
        .await
        .map_err(|e| ProxyError::Transport(format!("WebSocket handshake failed: {e}")))?;

    Ok(Box::new(WsStream::new(ws_stream)))
}

/// Perform a WebSocket server handshake over an existing TCP stream.
///
/// After this function returns, the caller has a `BoxedStream` that
/// transparently wraps WebSocket binary frames.
///
/// # Arguments
/// * `tcp_stream` — the inbound TCP stream to upgrade
pub async fn ws_accept(tcp_stream: BoxedStream) -> Result<BoxedStream, ProxyError> {
    let ws_config = WebSocketConfig::default();
    let ws_stream = accept_async_with_config(tcp_stream, Some(ws_config))
        .await
        .map_err(|e| ProxyError::Transport(format!("WebSocket accept failed: {e}")))?;

    Ok(Box::new(WsStream::new(ws_stream)))
}

/// Gorilla write buffer size used by Xray (`WriteBufferSize: 4 * 1024`).
const WS_WRITE_BUFFER_SIZE: usize = 4 * 1024;

type InnerWsStream<S> = tokio_tungstenite::WebSocketStream<S>;

fn ws_buffer_pool() -> &'static Arc<BufferPool> {
    static POOL: OnceLock<Arc<BufferPool>> = OnceLock::new();
    POOL.get_or_init(BufferPool::new)
}

/// A `BoxedStream`-compatible wrapper around a tungstenite WebSocket stream.
///
/// Reads return the payload bytes from the next binary frame.
/// Writes are buffered until flushed, then sent as a single binary frame.
///
/// Control frames (Ping, Pong, Close) are handled automatically by
/// tungstenite and are not visible to the caller.
pub struct WsStream<S> {
    /// The underlying tungstenite WebSocket stream.
    inner: InnerWsStream<S>,

    /// Buffered bytes from the current incoming frame.
    /// We may receive a large frame but the caller reads it in small chunks.
    read_buf: Bytes,

    /// True if the remote side has sent a Close frame.
    closed: bool,

    /// Buffered outgoing bytes, assembled into a frame on flush.
    write_buf: BytesMut,

    /// Message staged for sink readiness / flush without losing bytes on `Pending`.
    pending_write: Option<Message>,
}

impl<S> WsStream<S> {
    /// Wrap an established WebSocket stream.
    pub fn new(inner: InnerWsStream<S>) -> Self {
        Self {
            inner,
            read_buf: Bytes::new(),
            closed: false,
            write_buf: ws_buffer_pool().acquire(WS_WRITE_BUFFER_SIZE),
            pending_write: None,
        }
    }
}

impl<S> Drop for WsStream<S> {
    fn drop(&mut self) {
        ws_buffer_pool().release(std::mem::take(&mut self.write_buf));
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for WsStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            // If we already have buffered bytes from a previous frame, serve them.
            if !self.read_buf.is_empty() {
                let n = self.read_buf.len().min(buf.remaining());
                buf.put_slice(&self.read_buf[..n]);
                let _ = self.read_buf.split_to(n);
                return Poll::Ready(Ok(()));
            }

            if self.closed {
                return Poll::Ready(Ok(())); // EOF
            }

            // Poll the WebSocket stream for the next message.
            // Use Stream::poll_next via the trait bound.
            match Stream::poll_next(Pin::new(&mut self.inner), cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => {
                    self.closed = true;
                    return Poll::Ready(Ok(())); // EOF
                }
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(ws_err_to_io(e)));
                }
                Poll::Ready(Some(Ok(msg))) => match msg {
                    Message::Binary(data) => {
                        // Buffer the frame bytes and loop to serve them.
                        self.read_buf = data;
                        // Loop: serve from read_buf on the next iteration.
                    }
                    Message::Text(data) => {
                        // Some implementations send text frames; treat as binary.
                        self.read_buf = Bytes::copy_from_slice(data.as_bytes());
                    }
                    Message::Close(_) => {
                        self.closed = true;
                        return Poll::Ready(Ok(()));
                    }
                    // Ping/Pong are handled by tungstenite automatically.
                    Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => {
                        // Ignore; loop to get the next message.
                    }
                },
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for WsStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.write_buf.len() >= WS_WRITE_BUFFER_SIZE {
            match self.as_mut().poll_flush(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        let space = WS_WRITE_BUFFER_SIZE.saturating_sub(self.write_buf.len());
        let n = buf.len().min(space);
        self.write_buf.extend_from_slice(&buf[..n]);
        Poll::Ready(Ok(n))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.pending_write.is_none() && !self.write_buf.is_empty() {
            let data = self.write_buf.split().freeze();
            self.pending_write = Some(Message::Binary(data));
        }

        if let Some(msg) = self.pending_write.take() {
            match Sink::poll_ready(Pin::new(&mut self.inner), cx) {
                Poll::Pending => {
                    self.pending_write = Some(msg);
                    return Poll::Pending;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(ws_err_to_io(e))),
                Poll::Ready(Ok(())) => {}
            }
            if let Err(e) = Sink::start_send(Pin::new(&mut self.inner), msg) {
                return Poll::Ready(Err(ws_err_to_io(e)));
            }
        }

        // Flush the underlying sink.
        Sink::poll_flush(Pin::new(&mut self.inner), cx).map_err(ws_err_to_io)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().poll_flush(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {
                Sink::poll_close(Pin::new(&mut self.inner), cx).map_err(ws_err_to_io)
            }
        }
    }
}

/// Convert a tungstenite error into a standard `io::Error`.
fn ws_err_to_io(e: tungstenite::Error) -> io::Error {
    match e {
        tungstenite::Error::Io(io_err) => io_err,
        tungstenite::Error::ConnectionClosed | tungstenite::Error::AlreadyClosed => {
            io::Error::new(io::ErrorKind::ConnectionAborted, "WebSocket closed")
        }
        other => io::Error::other(other.to_string()),
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    /// Spawn a WebSocket echo server on a random port.
    /// Returns the port number.
    async fn spawn_ws_echo_server() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut ws: BoxedStream = ws_accept(Box::new(tcp)).await.unwrap();
            // Echo: read one chunk, write it back.
            let mut buf = vec![0u8; 4096];
            let n = ws.read(&mut buf).await.unwrap();
            ws.write_all(&buf[..n]).await.unwrap();
            ws.flush().await.unwrap();
        });

        port
    }

    /// Test: client connects, sends binary data, server echoes it back.
    #[tokio::test]
    async fn ws_handshake_and_binary_echo() {
        let port = spawn_ws_echo_server().await;

        let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let cfg = WsConnectConfig {
            path: "/ws".to_string(),
            host: "localhost".to_string(),
            headers: vec![],
        };
        let mut ws: BoxedStream = ws_connect(Box::new(tcp), cfg).await.unwrap();

        let payload = b"hello websocket";
        ws.write_all(payload).await.unwrap();
        ws.flush().await.unwrap();

        let mut recv = vec![0u8; payload.len()];
        ws.read_exact(&mut recv).await.unwrap();
        assert_eq!(&recv, payload);
    }

    /// Test: client connects with custom headers and sends multiple frames.
    #[tokio::test]
    async fn ws_custom_headers_and_multi_write() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut ws: BoxedStream = ws_accept(Box::new(tcp)).await.unwrap();
            // Echo everything until EOF.
            let mut buf = vec![0u8; 4096];
            loop {
                let n = ws.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                ws.write_all(&buf[..n]).await.unwrap();
                ws.flush().await.unwrap();
            }
        });

        let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let cfg = WsConnectConfig {
            path: "/proxy".to_string(),
            host: "example.com".to_string(),
            headers: vec![("X-Custom".to_string(), "test".to_string())],
        };
        let mut ws: BoxedStream = ws_connect(Box::new(tcp), cfg).await.unwrap();

        // Write two chunks separately.
        ws.write_all(b"chunk1").await.unwrap();
        ws.flush().await.unwrap();

        let mut buf = [0u8; 6];
        ws.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"chunk1");

        ws.write_all(b"chunk2").await.unwrap();
        ws.flush().await.unwrap();

        let mut buf2 = [0u8; 6];
        ws.read_exact(&mut buf2).await.unwrap();
        assert_eq!(&buf2, b"chunk2");
    }
}
