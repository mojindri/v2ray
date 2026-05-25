//! VLESS inbound handler — accepts VLESS connections from clients.
//!
//! This is the server-side half of the VLESS protocol. When a client connects,
//! this handler:
//!
//!   1. Reads and decodes the VLESS request header from the stream.
//!   2. Looks up the UUID in the user registry.
//!   3. If the UUID is valid: sends the VLESS response header, then hands
//!      the stream to the dispatcher to relay to the destination.
//!   4. If the UUID is NOT valid: forwards the entire connection (including
//!      already-read bytes) to the fallback backend WITHOUT closing.
//!
//! # The fallback is critical for security
//!
//! If we closed the connection on auth failure, a censor could run a script
//! that connects to our port and observes: "the server closes the connection
//! immediately for random data — it must be a proxy." By forwarding to a real
//! web server instead, we make the server indistinguishable from a normal
//! HTTPS endpoint.
//!
//! The fallback address is typically "127.0.0.1:80" where Nginx is serving
//! a real website. The censor probes us and gets a real web page back.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::AsyncWriteExt;
use tracing::{debug, warn};

use blackwire_app::context::Context;
use blackwire_app::dispatcher::Dispatcher;
use blackwire_app::features::InboundHandler;
use blackwire_common::{
    copy_bidirectional_with_idle, tcp_connect, with_handshake_timeout, BoxedStream, Network,
    PrependedStream, ProxyError, CONNECTION_IDLE_TIMEOUT,
};

use super::codec::{decode_request, encode_response};
use super::registry::VlessUserRegistry;

/// The VLESS inbound handler.
pub struct VlessInbound {
    /// The unique tag for this inbound (from config.json).
    tag: String,

    /// The user registry: UUID → user info.
    registry: Arc<VlessUserRegistry>,

    /// Where to forward connections when authentication fails.
    /// Typically "127.0.0.1:80" (a local Nginx serving a real website).
    /// If `None`, failed connections are silently dropped (not recommended for production).
    fallback: Option<SocketAddr>,
    /// Optional limit for reading the VLESS request header (Xray `Handshake`).
    handshake_timeout: Option<Duration>,
}

impl VlessInbound {
    /// Create a new VLESS inbound handler.
    ///
    /// # Arguments
    /// * `tag`      — the inbound's unique name from config.json
    /// * `registry` — the user UUID registry
    /// * `fallback` — optional fallback backend address for failed auth
    pub fn new(
        tag: impl Into<String>,
        registry: Arc<VlessUserRegistry>,
        fallback: Option<SocketAddr>,
        handshake_timeout: Option<Duration>,
    ) -> Arc<Self> {
        Arc::new(Self {
            tag: tag.into(),
            registry,
            fallback,
            handshake_timeout,
        })
    }
}

#[async_trait]
impl InboundHandler for VlessInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn networks(&self) -> &[Network] {
        &[Network::Tcp]
    }

    async fn handle(
        &self,
        mut stream: BoxedStream,
        source: SocketAddr,
        dispatcher: Arc<dyn Dispatcher>,
    ) -> Result<(), ProxyError> {
        // We need to capture the header bytes in case auth fails and we
        // need to forward them to the fallback backend. We do this by
        // wrapping the stream in a "tee" first — but the simpler approach
        // is to decode the header, then if auth fails, reconstruct the
        // bytes and prepend them to the stream.

        // Read the raw header bytes into a buffer so we can replay them
        // if authentication fails.
        let mut header_buf = Vec::with_capacity(64);

        // We decode the header using a "recording" reader that saves bytes
        // as they are read.
        let request = {
            let mut recorder = RecordingReader::new(&mut stream, &mut header_buf);
            with_handshake_timeout(self.handshake_timeout, decode_request(&mut recorder)).await
        };

        match request {
            Ok(req) => {
                // Check if the UUID is in the registry.
                match self.registry.validate(&req.uuid) {
                    Some(user) => {
                        debug!(
                            source = %source,
                            dest = %req.dest,
                            user = %user.email,
                            flow = %req.flow,
                            "VLESS authenticated"
                        );

                        // Check if the client requested XTLS Vision flow.
                        // Phase 1: log a warning that it is not yet implemented.
                        // Phase 2: this will enable the splice path.
                        if req.flow == "xtls-rprx-vision" {
                            // TODO Phase 2: enable XTLS Vision splice
                            debug!("XTLS Vision flow requested — splice not yet implemented in Phase 1");
                        }

                        // Send the VLESS response header to the client.
                        // After this, raw bytes follow — no more VLESS framing.
                        // Flush explicitly so buffered transports (WebSocket) send
                        // the response immediately.
                        let resp = encode_response();
                        stream.write_all(&resp).await?;
                        stream.flush().await?;

                        // Hand the stream to the dispatcher to relay to the destination.
                        let ctx = Context::new(&self.tag, source).with_user(user.email.clone());
                        dispatcher.dispatch(ctx, req.dest, stream).await
                    }
                    None => {
                        // UUID not found — forward to fallback.
                        warn!(source = %source, "VLESS auth failed — forwarding to fallback");
                        self.do_fallback(stream, header_buf).await
                    }
                }
            }
            Err(e) => {
                // Could not parse the header — also forward to fallback.
                // This handles the case where a probe sends HTTP or TLS traffic
                // to our VLESS port.
                debug!(source = %source, error = %e, "VLESS header parse failed — forwarding to fallback");
                self.do_fallback(stream, header_buf).await
            }
        }
    }
}

impl VlessInbound {
    /// Forward a connection to the fallback backend.
    ///
    /// We prepend the already-read header bytes to the stream so the fallback
    /// backend sees the full original request (including the bytes we read
    /// during the VLESS header attempt).
    async fn do_fallback(
        &self,
        stream: BoxedStream,
        header_bytes: Vec<u8>,
    ) -> Result<(), ProxyError> {
        let fallback_addr = match self.fallback {
            Some(addr) => addr,
            None => {
                // No fallback configured — silently discard.
                return Ok(());
            }
        };

        // Connect to the fallback backend.
        let mut fallback = tcp_connect(fallback_addr)
            .await
            .map_err(|e| ProxyError::Transport(format!("fallback connect failed: {e}")))?;

        // Prepend the already-read header bytes to the inbound stream.
        // The fallback backend will see the complete original request.
        let prepended: BoxedStream = Box::new(PrependedStream::new(stream, header_bytes));

        // Relay with Xray default connection idle timeout (300s).
        copy_bidirectional_with_idle(&mut { prepended }, &mut fallback, CONNECTION_IDLE_TIMEOUT)
            .await;

        Ok(())
    }
}

// ── Recording reader ──────────────────────────────────────────────────────────

/// A reader that records every byte read from the inner reader into a buffer.
///
/// Used to capture the VLESS header bytes while reading them, so that if
/// authentication fails, we can prepend them back to the stream for the
/// fallback backend.
struct RecordingReader<'a> {
    inner: &'a mut BoxedStream,
    record: &'a mut Vec<u8>,
}

impl<'a> RecordingReader<'a> {
    fn new(inner: &'a mut BoxedStream, record: &'a mut Vec<u8>) -> Self {
        Self { inner, record }
    }
}

impl<'a> tokio::io::AsyncRead for RecordingReader<'a> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let result = std::pin::Pin::new(self.inner.as_mut()).poll_read(cx, buf);
        if let std::task::Poll::Ready(Ok(())) = &result {
            // Record the newly read bytes.
            let after = buf.filled().len();
            self.record.extend_from_slice(&buf.filled()[before..after]);
        }
        result
    }
}

impl<'a> tokio::io::AsyncWrite for RecordingReader<'a> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(self.inner.as_mut()).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(self.inner.as_mut()).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(self.inner.as_mut()).poll_shutdown(cx)
    }
}
