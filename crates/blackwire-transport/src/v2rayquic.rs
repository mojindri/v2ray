//! Generic QUIC transport for stream-based protocols such as VLESS and VMess.
//!
//! Upstream Xray and sing-box expose this as the v2ray QUIC transport: a QUIC
//! connection carries one or more bidirectional byte streams, and the proxy
//! protocol runs directly on each QUIC stream.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use quinn::{Connection, Endpoint, RecvStream, SendStream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use blackwire_common::{BoxedStream, ProxyError, ReunionStream};

use crate::quic::{build_client_endpoint_with_alpn, build_server_endpoint_with_alpn};

const V2RAY_QUIC_ALPN: &[u8] = b"h3";

/// Connected QUIC bidirectional stream kept alive by its endpoint/connection.
pub struct QuicStream {
    _endpoint: Option<Endpoint>,
    _connection: Connection,
    inner: ReunionStream<RecvStream, SendStream>,
}

impl QuicStream {
    fn new(
        endpoint: Option<Endpoint>,
        connection: Connection,
        recv: RecvStream,
        send: SendStream,
    ) -> Self {
        Self {
            _endpoint: endpoint,
            _connection: connection,
            inner: ReunionStream::new(recv, send),
        }
    }
}

impl AsyncRead for QuicStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Dial a QUIC server and open one bidirectional stream.
pub async fn quic_connect(
    server: SocketAddr,
    server_name: &str,
    skip_verify: bool,
) -> Result<BoxedStream, ProxyError> {
    let endpoint = build_client_endpoint_with_alpn(skip_verify, &[V2RAY_QUIC_ALPN.to_vec()])
        .map_err(|e| ProxyError::Transport(format!("QUIC client endpoint: {e}")))?;
    let connecting = endpoint
        .connect(server, server_name)
        .map_err(|e| ProxyError::Transport(format!("QUIC connect setup: {e}")))?;
    let connection = connecting
        .await
        .map_err(|e| ProxyError::Transport(format!("QUIC handshake: {e}")))?;
    let (send, recv) = connection
        .open_bi()
        .await
        .map_err(|e| ProxyError::Transport(format!("QUIC open stream: {e}")))?;
    Ok(Box::new(QuicStream::new(
        Some(endpoint),
        connection,
        recv,
        send,
    )))
}

/// Build a server QUIC endpoint for stream-based v2ray protocols.
pub fn quic_server_endpoint(
    addr: SocketAddr,
    cert_pem: &str,
    key_pem: &str,
) -> anyhow::Result<Endpoint> {
    build_server_endpoint_with_alpn(addr, cert_pem, key_pem, &[V2RAY_QUIC_ALPN.to_vec()])
}

/// Wrap an accepted QUIC stream pair for protocol handling.
pub fn accepted_quic_stream(
    connection: Connection,
    recv: RecvStream,
    send: SendStream,
) -> BoxedStream {
    Box::new(QuicStream::new(None, connection, recv, send))
}
