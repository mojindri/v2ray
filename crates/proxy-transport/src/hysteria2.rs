//! Hysteria2 transport — QUIC-based proxy protocol for high-latency links.
//!
//! Hysteria2 is designed for connections with high latency and packet loss,
//! such as cross-border connections into China. It achieves high throughput
//! by using QUIC with a custom "Brutal" congestion controller that ignores
//! loss signals.
//!
//! # How a Hysteria2 connection works
//!
//! 1. Client connects via QUIC (UDP, TLS 1.3).
//! 2. Client opens the first bidirectional QUIC stream and sends an
//!    auth frame (password + requested bandwidth).
//! 3. Server validates the password and responds OK or Unauthorized.
//! 4. After auth, each new QUIC bidirectional stream = one proxied TCP connection.
//! 5. UDP is proxied via QUIC datagrams (see `udp` module).
//!
//! # Module layout
//!
//! - `proto` — wire format encode/decode for all frame types
//! - `auth` — authentication handshake helpers
//! - `tcp` — TCP proxy stream request/response handling
//! - `udp` — UDP proxy datagram encode/decode

pub mod auth;
pub mod proto;
pub mod tcp;
pub mod udp;

pub use auth::AuthError;
pub use proto::{AuthRequest, AuthResponse, TcpRequest, TcpResponse};

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use proxy_app::context::Context;
use proxy_app::dispatcher::Dispatcher;
use proxy_app::features::OutboundHandler;
use proxy_common::{Address, BoxedStream, ProxyError, ReunionStream};
use tracing::{debug, info, warn};

use crate::quic::{BrutalCCFactory, build_server_endpoint};

/// Configuration for a Hysteria2 inbound server.
#[derive(Debug, Clone)]
pub struct Hysteria2ServerConfig {
    /// UDP address to listen on.
    pub addr: SocketAddr,
    /// Authentication password clients must supply.
    pub password: String,
    /// Target upstream bandwidth in Mbps (client → server).
    pub up_mbps: u64,
    /// Target downstream bandwidth in Mbps (server → client).
    pub down_mbps: u64,
    /// PEM-encoded TLS certificate chain.
    pub cert_pem: String,
    /// PEM-encoded TLS private key.
    pub key_pem: String,
}

/// Configuration for a Hysteria2 outbound client.
#[derive(Debug, Clone)]
pub struct Hysteria2ClientConfig {
    /// Remote Hysteria2 server address.
    pub server: SocketAddr,
    /// Server name for TLS SNI (usually the server's hostname).
    pub server_name: String,
    /// Authentication password.
    pub password: String,
    /// Client's target upstream bandwidth in Mbps.
    pub up_mbps: u64,
    /// Client's target downstream bandwidth in Mbps.
    pub down_mbps: u64,
    /// Whether to skip TLS certificate verification (dev/testing only).
    pub skip_cert_verify: bool,
}

/// A Hysteria2 proxy server.
///
/// Listens on a QUIC endpoint, authenticates clients, and dispatches each
/// proxy stream to the configured `Dispatcher`.
pub struct Hysteria2Server {
    config: Hysteria2ServerConfig,
}

impl Hysteria2Server {
    /// Create a new server with the given config.
    pub fn new(config: Hysteria2ServerConfig) -> Self {
        Self { config }
    }

    /// Start serving on the configured address.
    ///
    /// Accepts QUIC connections, authenticates each client, then dispatches
    /// proxy streams to `dispatcher`. Runs until the endpoint is closed or an
    /// unrecoverable error occurs.
    pub async fn serve(&self, dispatcher: Arc<dyn Dispatcher>) -> Result<()> {
        let endpoint = build_server_endpoint(
            self.config.addr,
            &self.config.cert_pem,
            &self.config.key_pem,
        )?;

        info!(addr = %self.config.addr, "Hysteria2 server listening");

        while let Some(incoming) = endpoint.accept().await {
            let conn = match incoming.await {
                Ok(c) => c,
                Err(e) => {
                    warn!("QUIC connection failed during handshake: {e}");
                    continue;
                }
            };

            let password = self.config.password.clone();
            let dispatcher = Arc::clone(&dispatcher);
            tokio::spawn(async move {
                if let Err(e) = handle_connection(conn, password, dispatcher).await {
                    debug!("Hysteria2 connection closed: {e}");
                }
            });
        }

        Ok(())
    }
}

/// Handle a single QUIC connection: auth, then dispatch proxy streams.
async fn handle_connection(
    conn: quinn::Connection,
    password: String,
    dispatcher: Arc<dyn Dispatcher>,
) -> Result<()> {
    // The first stream is the auth stream.
    let (mut auth_send, mut auth_recv) = conn.accept_bi().await?;

    // Run the authentication handshake. Use a block so auth_stream's borrow ends
    // before the accept loop below needs to borrow other variables.
    {
        let mut auth_stream = ReunionStream::new(&mut auth_recv, &mut auth_send);
        auth::server_auth(&mut auth_stream, &password).await?;
    }

    // All subsequent streams are TCP proxy requests.
    loop {
        let (mut send, mut recv) = conn.accept_bi().await?;
        let dispatcher = Arc::clone(&dispatcher);

        tokio::spawn(async move {
            let dest = match tcp::server_read_request(&mut recv).await {
                Ok(d) => d,
                Err(e) => {
                    warn!("Hysteria2 bad TCP request: {e}");
                    return;
                }
            };

            if let Err(e) = tcp::server_write_response(&mut send, true, "").await {
                warn!("Hysteria2 response write failed: {e}");
                return;
            }

            // Combine the QUIC send+recv halves into a single BoxedStream.
            let stream: BoxedStream = Box::new(ReunionStream::new(recv, send));

            let ctx = Context {
                source: None,
                inbound_tag: "hysteria2".to_string(),
                user: None,
                sniffed_protocol: None,
            };

            if let Err(e) = dispatcher.dispatch(ctx, dest, stream).await {
                debug!("Hysteria2 dispatch error: {e}");
            }
        });
    }
}

/// A Hysteria2 proxy client.
///
/// Connects to a remote Hysteria2 server over QUIC and proxies TCP connections
/// through it. Each call to `connect_and_dial()` opens a new QUIC stream on the
/// existing connection.
pub struct Hysteria2Client {
    config: Hysteria2ClientConfig,
}

impl Hysteria2Client {
    /// Create a new client with the given config.
    pub fn new(config: Hysteria2ClientConfig) -> Self {
        Self { config }
    }

    /// Connect to the Hysteria2 server, authenticate, and open a stream for `dest`.
    ///
    /// Returns a `BoxedStream` that can be used for bidirectional data relay.
    ///
    /// Note: Phase 3 creates a new QUIC connection per request. Connection
    /// pooling (reusing the QUIC connection across streams) is a Phase 4
    /// enhancement.
    pub async fn connect_and_dial(&self, dest: &Address) -> Result<BoxedStream, ProxyError> {
        // Build the QUIC client endpoint with Brutal CC applied.
        let target_bps = self.config.up_mbps * 1_000_000 / 8;
        let mut transport_config = quinn::TransportConfig::default();
        transport_config
            .congestion_controller_factory(Arc::new(BrutalCCFactory::new(target_bps)));
        let transport_arc = Arc::new(transport_config);

        // Build a fresh ClientConfig for this connection.
        let client_config = build_hysteria2_client_config(
            self.config.skip_cert_verify,
            transport_arc,
        )
        .map_err(|e| ProxyError::Transport(e.to_string()))?;

        // Bind a client endpoint (any local port).
        let endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())
            .map_err(|e| ProxyError::Transport(format!("client endpoint: {e}")))?;

        let server_name = &self.config.server_name;
        let conn = endpoint
            .connect_with(client_config, self.config.server, server_name)
            .map_err(|e| ProxyError::Transport(format!("QUIC connect: {e}")))?
            .await
            .map_err(|e| ProxyError::Transport(format!("QUIC handshake: {e}")))?;

        // Open the auth stream first.
        let (mut auth_send, mut auth_recv) = conn
            .open_bi()
            .await
            .map_err(|e| ProxyError::Transport(format!("open auth stream: {e}")))?;

        // Use a block so auth_stream's borrow of auth_send/auth_recv ends
        // before we try to open the proxy stream below.
        {
            let mut auth_stream = ReunionStream::new(&mut auth_recv, &mut auth_send);
            auth::client_auth(
                &mut auth_stream,
                &self.config.password,
                self.config.up_mbps,
                self.config.down_mbps,
            )
            .await
            .map_err(|e| match e {
                AuthError::WrongPassword => ProxyError::AuthFailed,
                AuthError::Io(io_e) => ProxyError::Io(io_e),
                AuthError::Protocol(msg) => ProxyError::Protocol(msg),
            })?;
        }

        // Open a proxy stream for this request.
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .map_err(|e| ProxyError::Transport(format!("open proxy stream: {e}")))?;

        tcp::client_write_request(&mut send, dest).await?;
        tcp::client_read_response(&mut recv).await?;

        // Return a combined stream for bidirectional relay.
        Ok(Box::new(ReunionStream::new(recv, send)))
    }
}

/// A Hysteria2 outbound handler for use in `instance.rs`.
pub struct Hysteria2OutboundHandler {
    client: Hysteria2Client,
    tag: String,
}

impl Hysteria2OutboundHandler {
    /// Create a new outbound handler.
    pub fn new(config: Hysteria2ClientConfig, tag: String) -> Arc<Self> {
        Arc::new(Self {
            client: Hysteria2Client::new(config),
            tag,
        })
    }
}

#[async_trait::async_trait]
impl OutboundHandler for Hysteria2OutboundHandler {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn connect(
        &self,
        _ctx: &Context,
        dest: &Address,
    ) -> Result<BoxedStream, ProxyError> {
        self.client.connect_and_dial(dest).await
    }
}

// ── Private helpers ────────────────────────────────────────────────────────────

/// Build a `quinn::ClientConfig` with the given transport config and optional
/// certificate verification skip.
fn build_hysteria2_client_config(
    skip_verify: bool,
    transport: Arc<quinn::TransportConfig>,
) -> anyhow::Result<quinn::ClientConfig> {
    use anyhow::Context as _;
    use quinn::crypto::rustls::QuicClientConfig;

    let tls_config = if skip_verify {
        // Accept any server certificate — for testing only.
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipVerifier))
            .with_no_client_auth()
    } else {
        // Use platform root certificates.
        let mut roots = rustls::RootCertStore::empty();
        let result = rustls_native_certs::load_native_certs();
        for cert in result.certs {
            let _ = roots.add(cert);
        }
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    };

    let quic_config = QuicClientConfig::try_from(tls_config)
        .context("build QuicClientConfig")?;
    let mut config = quinn::ClientConfig::new(Arc::new(quic_config));
    config.transport_config(transport);
    Ok(config)
}

/// TLS verifier that accepts any certificate — for use in tests only.
#[derive(Debug)]
struct SkipVerifier;

impl rustls::client::danger::ServerCertVerifier for SkipVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
        ]
    }
}
