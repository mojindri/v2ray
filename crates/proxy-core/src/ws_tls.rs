//! WebSocket and TLS connection handlers for `instance.rs`.
//!
//! These adapters wrap an inbound `ConnectionHandler` with transport-layer
//! upgrades (TLS, WebSocket) before the protocol layer sees the stream.
//!
//! The layering order is:
//!   TCP → [TLS] → [WebSocket] → Protocol (VLESS, Trojan, …)
//!
//! Both layers are optional and can be combined:
//!   - TCP only (no security, no WS)
//!   - TCP + TLS (security = "tls")
//!   - TCP + WS  (network = "ws", no TLS)
//!   - TCP + TLS + WS (network = "ws", security = "tls")

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;

use proxy_app::dispatcher::Dispatcher;
use proxy_app::features::{ConnectionHandler, InboundHandler};
use proxy_common::{BoxedStream, ProxyError};
use proxy_config::schema::{NetworkType, SecurityType, StreamSettingsConfig};
use proxy_transport::{tls_accept, ws_accept};

// ── Query helpers ─────────────────────────────────────────────────────────────

/// Returns `true` when the config requests standard TLS wrapping.
pub(crate) fn uses_tls(stream_settings: &Option<StreamSettingsConfig>) -> bool {
    stream_settings
        .as_ref()
        .is_some_and(|s| s.security == SecurityType::Tls)
}

/// Returns `true` when the config requests WebSocket framing.
pub(crate) fn uses_ws(stream_settings: &Option<StreamSettingsConfig>) -> bool {
    stream_settings
        .as_ref()
        .is_some_and(|s| s.network == NetworkType::Ws)
}

// ── TLS inbound handler ───────────────────────────────────────────────────────

/// A `ConnectionHandler` that performs a TLS server handshake, then delegates
/// to the wrapped inner handler.
pub(crate) struct TlsConnectionHandler {
    cert_pem: String,
    key_pem: String,
    inner: Arc<dyn ConnectionHandler>,
}

impl TlsConnectionHandler {
    /// Wrap an existing handler with TLS.
    pub(crate) fn new(
        cert_pem: String,
        key_pem: String,
        inner: Arc<dyn ConnectionHandler>,
    ) -> Arc<Self> {
        Arc::new(Self {
            cert_pem,
            key_pem,
            inner,
        })
    }
}

#[async_trait::async_trait]
impl ConnectionHandler for TlsConnectionHandler {
    async fn handle_connection(
        &self,
        stream: BoxedStream,
        source: SocketAddr,
    ) -> Result<(), ProxyError> {
        let tls_stream = tls_accept(stream, &self.cert_pem, &self.key_pem, &[]).await?;
        self.inner.handle_connection(tls_stream, source).await
    }
}

// ── WebSocket inbound handler ─────────────────────────────────────────────────

/// A `ConnectionHandler` that performs a WebSocket server handshake, then
/// delegates to the wrapped inner handler.
pub(crate) struct WsConnectionHandler {
    inner: Arc<dyn ConnectionHandler>,
}

impl WsConnectionHandler {
    pub(crate) fn new(inner: Arc<dyn ConnectionHandler>) -> Arc<Self> {
        Arc::new(Self { inner })
    }
}

#[async_trait::async_trait]
impl ConnectionHandler for WsConnectionHandler {
    async fn handle_connection(
        &self,
        stream: BoxedStream,
        source: SocketAddr,
    ) -> Result<(), ProxyError> {
        let ws_stream = ws_accept(stream).await?;
        self.inner.handle_connection(ws_stream, source).await
    }
}

// ── Plain inbound adapter ─────────────────────────────────────────────────────

/// Adapter that lets the transport layer call an `InboundHandler` through
/// the `ConnectionHandler` trait. Identical to the one in `instance.rs`
/// but defined here so we can reuse it in TLS/WS wrappers.
pub(crate) struct PlainConnectionHandler {
    pub(crate) inbound: Arc<dyn InboundHandler>,
    pub(crate) dispatcher: Arc<dyn Dispatcher>,
}

#[async_trait::async_trait]
impl ConnectionHandler for PlainConnectionHandler {
    async fn handle_connection(
        &self,
        stream: BoxedStream,
        source: SocketAddr,
    ) -> Result<(), ProxyError> {
        self.inbound
            .handle(stream, source, Arc::clone(&self.dispatcher))
            .await
    }
}

/// Build a connection handler with the appropriate transport wrappers.
///
/// This is the single place that applies TLS and WebSocket layers.
/// The layering order (innermost first):
///   PlainConnectionHandler → [WsConnectionHandler] → [TlsConnectionHandler]
///
/// That means:
/// - TLS is peeled off first (outermost).
/// - WebSocket is peeled off next.
/// - The protocol handler sees raw data last.
pub(crate) fn build_conn_handler(
    inbound: Arc<dyn InboundHandler>,
    dispatcher: Arc<dyn Dispatcher>,
    stream_settings: &Option<StreamSettingsConfig>,
) -> Result<Arc<dyn ConnectionHandler>, anyhow::Error> {
    // Innermost: protocol handler.
    let mut handler: Arc<dyn ConnectionHandler> = Arc::new(PlainConnectionHandler {
        inbound,
        dispatcher,
    });

    // Add WebSocket layer if requested.
    if uses_ws(stream_settings) {
        handler = WsConnectionHandler::new(handler);
    }

    // Add TLS layer if requested.
    if uses_tls(stream_settings) {
        let tls_cfg = stream_settings
            .as_ref()
            .and_then(|s| s.tls_settings.as_ref())
            .ok_or_else(|| anyhow::anyhow!("security=tls but no tlsSettings provided"))?;

        let cert_path = &tls_cfg.certificate_file;
        let key_path = &tls_cfg.key_file;

        if cert_path.is_empty() || key_path.is_empty() {
            return Err(anyhow::anyhow!(
                "TLS requires non-empty certificateFile and keyFile"
            ));
        }

        let cert_pem = std::fs::read_to_string(cert_path)
            .map_err(|e| anyhow::anyhow!("cannot read cert file '{cert_path}': {e}"))?;
        let key_pem = std::fs::read_to_string(key_path)
            .map_err(|e| anyhow::anyhow!("cannot read key file '{key_path}': {e}"))?;

        handler = TlsConnectionHandler::new(cert_pem, key_pem, handler);
    }

    Ok(handler)
}
