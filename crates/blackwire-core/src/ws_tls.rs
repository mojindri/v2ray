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
use std::time::Duration;

use anyhow::Result;

use blackwire_app::dispatcher::Dispatcher;
use blackwire_app::features::{ConnectionHandler, InboundHandler};
use blackwire_common::{with_handshake_timeout, BoxedStream, ProxyError};
use blackwire_config::schema::{NetworkType, SecurityType, StreamSettingsConfig};
use blackwire_transport::{
    accept_httpupgrade, grpc_accept, httpupgrade_listen_path, shadowtls_accept, splithttp_accept,
    splithttp_listen_params, normalize_splithttp_mode, SplitHttpAcceptResult, tls_accept, ws_accept,
};

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

/// Returns `true` when the config requests gRPC transport.
pub(crate) fn uses_grpc(stream_settings: &Option<StreamSettingsConfig>) -> bool {
    stream_settings
        .as_ref()
        .is_some_and(|s| s.network == NetworkType::Grpc)
}

/// Returns `true` when the config requests HTTPUpgrade framing.
pub(crate) fn uses_httpupgrade(stream_settings: &Option<StreamSettingsConfig>) -> bool {
    stream_settings
        .as_ref()
        .is_some_and(|s| s.network == NetworkType::HttpUpgrade)
}

pub(crate) fn uses_splithttp(stream_settings: &Option<StreamSettingsConfig>) -> bool {
    stream_settings
        .as_ref()
        .is_some_and(|s| s.network == NetworkType::SplitHttp)
}

/// Returns `true` when the config requests ShadowTLS wrapping.
pub(crate) fn uses_shadowtls(stream_settings: &Option<StreamSettingsConfig>) -> bool {
    stream_settings
        .as_ref()
        .is_some_and(|s| s.security == SecurityType::ShadowTls)
}

// ── TLS inbound handler ───────────────────────────────────────────────────────

/// A `ConnectionHandler` that performs a TLS server handshake, then delegates
/// to the wrapped inner handler.
pub(crate) struct TlsConnectionHandler {
    cert_pem: String,
    key_pem: String,
    /// ALPN protocols to advertise during the TLS handshake (e.g. `["h2"]` for gRPC).
    alpn: Vec<String>,
    handshake_timeout: Option<Duration>,
    inner: Arc<dyn ConnectionHandler>,
}

impl TlsConnectionHandler {
    /// Wrap an existing handler with TLS.
    ///
    /// `alpn` should be `["h2"]` when the inner handler is gRPC, empty otherwise.
    pub(crate) fn new(
        cert_pem: String,
        key_pem: String,
        alpn: Vec<String>,
        handshake_timeout: Option<Duration>,
        inner: Arc<dyn ConnectionHandler>,
    ) -> Arc<Self> {
        Arc::new(Self {
            cert_pem,
            key_pem,
            alpn,
            handshake_timeout,
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
        let alpn: Vec<&str> = self.alpn.iter().map(|s| s.as_str()).collect();
        let tls_stream = with_handshake_timeout(
            self.handshake_timeout,
            tls_accept(stream, &self.cert_pem, &self.key_pem, &alpn),
        )
        .await?;
        self.inner.handle_connection(tls_stream, source).await
    }
}

// ── HTTPUpgrade inbound handler ───────────────────────────────────────────────

/// A `ConnectionHandler` that performs an HTTP/1.1 Upgrade handshake, then
/// delegates to the wrapped inner handler.
pub(crate) struct HttpUpgradeConnectionHandler {
    expected_path: Option<String>,
    handshake_timeout: Option<Duration>,
    inner: Arc<dyn ConnectionHandler>,
}

impl HttpUpgradeConnectionHandler {
    pub(crate) fn new(
        expected_path: Option<String>,
        handshake_timeout: Option<Duration>,
        inner: Arc<dyn ConnectionHandler>,
    ) -> Arc<Self> {
        Arc::new(Self {
            expected_path,
            handshake_timeout,
            inner,
        })
    }
}

#[async_trait::async_trait]
impl ConnectionHandler for HttpUpgradeConnectionHandler {
    async fn handle_connection(
        &self,
        stream: BoxedStream,
        source: SocketAddr,
    ) -> Result<(), ProxyError> {
        let path = self.expected_path.as_deref();
        let upgraded =
            with_handshake_timeout(self.handshake_timeout, accept_httpupgrade(stream, path))
                .await?;
        self.inner.handle_connection(upgraded, source).await
    }
}

// ── WebSocket inbound handler ─────────────────────────────────────────────────

/// A `ConnectionHandler` that performs a WebSocket server handshake, then
/// delegates to the wrapped inner handler.
pub(crate) struct WsConnectionHandler {
    handshake_timeout: Option<Duration>,
    inner: Arc<dyn ConnectionHandler>,
}

impl WsConnectionHandler {
    pub(crate) fn new(
        handshake_timeout: Option<Duration>,
        inner: Arc<dyn ConnectionHandler>,
    ) -> Arc<Self> {
        Arc::new(Self {
            handshake_timeout,
            inner,
        })
    }
}

#[async_trait::async_trait]
impl ConnectionHandler for WsConnectionHandler {
    async fn handle_connection(
        &self,
        stream: BoxedStream,
        source: SocketAddr,
    ) -> Result<(), ProxyError> {
        let ws_stream = with_handshake_timeout(self.handshake_timeout, ws_accept(stream)).await?;
        self.inner.handle_connection(ws_stream, source).await
    }
}

// ── gRPC inbound handler ──────────────────────────────────────────────────────

pub(crate) struct SplitHttpConnectionHandler {
    expected_path: Option<String>,
    expected_method: Option<String>,
    mode: blackwire_transport::SplitHttpMode,
    handshake_timeout: Option<Duration>,
    inner: Arc<dyn ConnectionHandler>,
}

impl SplitHttpConnectionHandler {
    pub(crate) fn new(
        expected_path: Option<String>,
        expected_method: Option<String>,
        mode: blackwire_transport::SplitHttpMode,
        handshake_timeout: Option<Duration>,
        inner: Arc<dyn ConnectionHandler>,
    ) -> Arc<Self> {
        Arc::new(Self {
            expected_path,
            expected_method,
            mode,
            handshake_timeout,
            inner,
        })
    }
}

#[async_trait::async_trait]
impl ConnectionHandler for SplitHttpConnectionHandler {
    async fn handle_connection(
        &self,
        stream: BoxedStream,
        source: SocketAddr,
    ) -> Result<(), ProxyError> {
        let path = self.expected_path.as_deref();
        let method = self.expected_method.as_deref();
        let accepted = with_handshake_timeout(
            self.handshake_timeout,
            splithttp_accept(stream, path, method, self.mode),
        )
        .await?;
        match accepted {
            SplitHttpAcceptResult::Tunnel(stream) => {
                self.inner.handle_connection(stream, source).await
            }
            SplitHttpAcceptResult::UploadOnly | SplitHttpAcceptResult::Preflight => Ok(()),
        }
    }
}

/// A `ConnectionHandler` that performs a gRPC server handshake, then delegates
/// to the wrapped inner handler.
pub(crate) struct GrpcConnectionHandler {
    service_name: String,
    handshake_timeout: Option<Duration>,
    inner: Arc<dyn ConnectionHandler>,
}

// ── ShadowTLS inbound handler ─────────────────────────────────────────────────

pub(crate) struct ShadowTlsConnectionHandler {
    password: String,
    dest: String,
    handshake_timeout: Option<Duration>,
    inner: Arc<dyn ConnectionHandler>,
}

impl ShadowTlsConnectionHandler {
    pub(crate) fn new(
        password: impl Into<String>,
        dest: impl Into<String>,
        handshake_timeout: Option<Duration>,
        inner: Arc<dyn ConnectionHandler>,
    ) -> Arc<Self> {
        Arc::new(Self {
            password: password.into(),
            dest: dest.into(),
            handshake_timeout,
            inner,
        })
    }
}

#[async_trait::async_trait]
impl ConnectionHandler for ShadowTlsConnectionHandler {
    async fn handle_connection(
        &self,
        stream: BoxedStream,
        source: SocketAddr,
    ) -> Result<(), ProxyError> {
        let stream = with_handshake_timeout(
            self.handshake_timeout,
            shadowtls_accept(stream, self.password.as_bytes(), &self.dest),
        )
        .await?;
        self.inner.handle_connection(stream, source).await
    }
}

impl GrpcConnectionHandler {
    pub(crate) fn new(
        service_name: impl Into<String>,
        handshake_timeout: Option<Duration>,
        inner: Arc<dyn ConnectionHandler>,
    ) -> Arc<Self> {
        Arc::new(Self {
            service_name: service_name.into(),
            handshake_timeout,
            inner,
        })
    }
}

#[async_trait::async_trait]
impl ConnectionHandler for GrpcConnectionHandler {
    async fn handle_connection(
        &self,
        stream: BoxedStream,
        source: SocketAddr,
    ) -> Result<(), ProxyError> {
        let grpc_stream = with_handshake_timeout(
            self.handshake_timeout,
            grpc_accept(stream, &self.service_name),
        )
        .await?;
        self.inner.handle_connection(grpc_stream, source).await
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
    handshake_timeout: Option<Duration>,
) -> Result<Arc<dyn ConnectionHandler>, anyhow::Error> {
    // Innermost: protocol handler.
    let mut handler: Arc<dyn ConnectionHandler> = Arc::new(PlainConnectionHandler {
        inbound,
        dispatcher,
    });

    // Add WebSocket layer if requested.
    if uses_ws(stream_settings) {
        handler = WsConnectionHandler::new(handshake_timeout, handler);
    }

    // Add HTTPUpgrade layer if requested (mutually exclusive with WS/gRPC).
    if uses_httpupgrade(stream_settings) {
        let expected_path = stream_settings.as_ref().and_then(httpupgrade_listen_path);
        handler = HttpUpgradeConnectionHandler::new(expected_path, handshake_timeout, handler);
    }

    if uses_splithttp(stream_settings) {
        let (expected_path, expected_method, mode) = stream_settings
            .as_ref()
            .map(splithttp_listen_params)
            .unwrap_or((None, None, normalize_splithttp_mode("")));
        handler = SplitHttpConnectionHandler::new(
            expected_path,
            expected_method,
            mode,
            handshake_timeout,
            handler,
        );
    }

    // Add gRPC layer if requested (mutually exclusive with WS).
    if uses_grpc(stream_settings) {
        let service_name = stream_settings
            .as_ref()
            .and_then(|s| s.grpc_settings.as_ref())
            .map(|g| g.service_name.as_str())
            .unwrap_or("GunService")
            .to_string();
        handler = GrpcConnectionHandler::new(service_name, handshake_timeout, handler);
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

        // gRPC runs over HTTP/2, which requires the "h2" ALPN token during TLS negotiation.
        let alpn = if uses_grpc(stream_settings) {
            vec!["h2".to_string()]
        } else {
            vec![]
        };
        let alpn_refs: Vec<&str> = alpn.iter().map(|s| s.as_str()).collect();
        blackwire_transport::tls_build_server_config(&cert_pem, &key_pem, &alpn_refs)
            .map_err(|e| anyhow::anyhow!("invalid TLS certificate/key material: {e}"))?;
        handler = TlsConnectionHandler::new(cert_pem, key_pem, alpn, handshake_timeout, handler);
    }

    if uses_shadowtls(stream_settings) {
        let shadow_cfg = stream_settings
            .as_ref()
            .and_then(|s| s.shadow_tls_settings.as_ref())
            .ok_or_else(|| {
                anyhow::anyhow!("security=shadowtls but no shadowTlsSettings provided")
            })?;
        if shadow_cfg.version != 3 {
            return Err(anyhow::anyhow!(
                "unsupported ShadowTLS version {}",
                shadow_cfg.version
            ));
        }
        if shadow_cfg.password.is_empty() || shadow_cfg.dest.is_empty() {
            return Err(anyhow::anyhow!(
                "ShadowTLS requires non-empty password and dest"
            ));
        }
        handler = ShadowTlsConnectionHandler::new(
            shadow_cfg.password.clone(),
            shadow_cfg.dest.clone(),
            handshake_timeout,
            handler,
        );
    }

    Ok(handler)
}
