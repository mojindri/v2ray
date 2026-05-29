//! Hysteria2 transport — QUIC-based proxy protocol for high-latency links.
//!
//! External clients (sing-box, Xray, Hiddify) speak HTTP/3 for authentication and
//! QUIC-varint TCP framing on subsequent streams. See the [Hysteria2 protocol spec](https://v2.hysteria.network/docs/developers/Protocol/).

pub mod auth;
pub mod http3;
pub mod proto;
pub mod tcp;
pub mod udp;
mod varint;

pub use auth::AuthError;
pub use proto::{AuthRequest, AuthResponse, TcpRequest, TcpResponse};

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};

use anyhow::Result;
use blackwire_app::context::Context;
use blackwire_app::dispatcher::Dispatcher;
use blackwire_app::features::OutboundHandler;
use blackwire_common::{Address, BoxedStream, ProxyError, ReunionStream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Semaphore;
use tracing::{info, warn};

/// Maximum concurrent QUIC connections on a single Hysteria2 server.
///
/// The official hysteria2 server defaults to `maxIncomingConnections: 1024`.
/// sing-quic has no cap, but we follow the reference implementation.
const MAX_HYSTERIA2_CONNECTIONS: usize = 1024;

use crate::quic::{build_hysteria2_server_endpoint, ensure_crypto_provider, BrutalCCFactory};

/// Configuration for a Hysteria2 inbound server.
#[derive(Debug, Clone)]
pub struct Hysteria2ServerConfig {
    /// Inbound tag used for routing rules.
    pub tag: String,
    /// Socket address to listen on (for example `0.0.0.0:443`).
    pub addr: SocketAddr,
    /// Shared password that clients must send during HTTP/3 auth.
    pub password: String,
    /// Max client → server rate in Mbps (server receive / `Hysteria-CC-RX` in auth response).
    pub up_mbps: u64,
    /// Max server → client rate in Mbps (used for Brutal on server→client path when enabled).
    pub down_mbps: u64,
    /// Server certificate in PEM format.
    pub cert_pem: String,
    /// Private key for `cert_pem`, in PEM format.
    pub key_pem: String,
    /// Maximum concurrent QUIC connections. Falls back to `MAX_HYSTERIA2_CONNECTIONS`.
    pub max_connections: Option<usize>,
}

/// Configuration for a Hysteria2 outbound client.
#[derive(Debug, Clone)]
pub struct Hysteria2ClientConfig {
    /// Remote Hysteria2 server socket address.
    pub server: SocketAddr,
    /// TLS server name (SNI) to present during QUIC handshake.
    pub server_name: String,
    /// Shared password used for HTTP/3 auth.
    pub password: String,
    /// Max client upload rate in Mbps.
    pub up_mbps: u64,
    /// Max client download rate in Mbps.
    pub down_mbps: u64,
    /// If `true`, skip TLS certificate verification (unsafe, for testing only).
    pub skip_cert_verify: bool,
}

/// A Hysteria2 proxy server.
pub struct Hysteria2Server {
    config: Hysteria2ServerConfig,
}

impl Hysteria2Server {
    /// Build a Hysteria2 server from static config.
    pub fn new(config: Hysteria2ServerConfig) -> Self {
        Self { config }
    }

    /// Start accepting QUIC connections and proxying TCP streams.
    ///
    /// This runs until the endpoint is closed or the task is cancelled.
    pub async fn serve(&self, dispatcher: Arc<dyn Dispatcher>) -> Result<()> {
        let endpoint = build_hysteria2_server_endpoint(
            self.config.addr,
            &self.config.cert_pem,
            &self.config.key_pem,
            self.config.up_mbps,
            self.config.down_mbps,
        )?;

        info!(addr = %self.config.addr, "Hysteria2 server listening (HTTP/3)");

        let cap = self
            .config
            .max_connections
            .unwrap_or(MAX_HYSTERIA2_CONNECTIONS);
        let conn_limiter = Arc::new(Semaphore::new(cap));

        while let Some(incoming) = endpoint.accept().await {
            let permit = match Arc::clone(&conn_limiter).try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    warn!(
                        max = MAX_HYSTERIA2_CONNECTIONS,
                        "Hysteria2 connection limit reached; dropping incoming QUIC connection"
                    );
                    // Drop `incoming` without awaiting — rejects the connection.
                    continue;
                }
            };

            let conn = match incoming.await {
                Ok(c) => c,
                Err(e) => {
                    warn!("QUIC connection failed during handshake: {e}");
                    continue;
                }
            };

            let config = self.config.clone();
            let dispatcher = Arc::clone(&dispatcher);
            tokio::spawn(async move {
                let _permit = permit; // hold until connection fully closes
                if let Err(e) = http3::serve_connection(conn, config, dispatcher).await {
                    warn!("Hysteria2 connection closed: {e}");
                }
            });
        }

        Ok(())
    }
}

/// A Hysteria2 proxy client.
pub struct Hysteria2Client {
    config: Hysteria2ClientConfig,
}

impl Hysteria2Client {
    /// Build a Hysteria2 client from static config.
    pub fn new(config: Hysteria2ClientConfig) -> Self {
        Self { config }
    }

    /// Connect to the server, authenticate, and open one proxied TCP stream.
    ///
    /// The returned stream is ready to carry bytes for `dest`.
    pub async fn connect_and_dial(&self, dest: &Address) -> Result<BoxedStream, ProxyError> {
        let rx_bps = self.config.down_mbps.saturating_mul(1_000_000 / 8);
        let target_bps = self.config.up_mbps.saturating_mul(1_000_000 / 8);
        let mut transport_config = quinn::TransportConfig::default();
        transport_config.congestion_controller_factory(Arc::new(BrutalCCFactory::new(target_bps)));

        // Size QUIC flow-control windows to the configured bandwidth × 500 ms RTT.
        // Without this, BrutalCC can be stalled waiting for STREAM_DATA_BLOCKED
        // acknowledgement before the CC window fills on high-bandwidth links.
        let (stream_rx, conn_rx, conn_tx) =
            crate::quic::bdp_windows(self.config.down_mbps, self.config.up_mbps);
        transport_config.stream_receive_window(stream_rx);
        transport_config.receive_window(conn_rx);
        transport_config.send_window(conn_tx);

        let transport_arc = Arc::new(transport_config);

        let client_config =
            build_hysteria2_client_config(self.config.skip_cert_verify, transport_arc)
                .map_err(|e| ProxyError::Transport(e.to_string()))?;

        let bind_addr: SocketAddr = "0.0.0.0:0"
            .parse()
            .map_err(|e| ProxyError::Transport(format!("invalid client bind addr: {e}")))?;
        let endpoint = quinn::Endpoint::client(bind_addr)
            .map_err(|e| ProxyError::Transport(format!("client endpoint: {e}")))?;

        let server_name = &self.config.server_name;
        let conn = endpoint
            .connect_with(client_config, self.config.server, server_name)
            .map_err(|e| ProxyError::Transport(format!("QUIC connect: {e}")))?
            .await
            .map_err(|e| ProxyError::Transport(format!("QUIC handshake: {e}")))?;

        client_h3_auth(&conn, &self.config.password, rx_bps).await?;

        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .map_err(|e| ProxyError::Transport(format!("open proxy stream: {e}")))?;

        tcp::client_write_request(&mut send, dest).await?;
        tcp::client_read_response(&mut recv).await?;

        Ok(Box::new(Hysteria2Stream {
            inner: ReunionStream::new(recv, send),
            _conn: conn,
            _endpoint: endpoint,
        }))
    }
}

/// Perform the HTTP/3 authentication handshake.
async fn client_h3_auth(
    conn: &quinn::Connection,
    password: &str,
    rx_bps: u64,
) -> Result<(), ProxyError> {
    use http::header::{HeaderName, HeaderValue};
    use http::{Method, Request};

    let (driver, mut send_request) = h3::client::new(h3_quinn::Connection::new(conn.clone()))
        .await
        .map_err(|e| ProxyError::Transport(format!("h3 client: {e}")))?;

    // Keep the HTTP/3 connection driver alive for the lifetime of the QUIC session.
    tokio::spawn(async move {
        let _ = driver;
    });

    let mut req_builder = Request::builder().method(Method::POST).uri(format!(
        "https://{}{}",
        proto::AUTH_HOST,
        proto::AUTH_PATH
    ));
    req_builder = req_builder.header(http::header::HOST, proto::AUTH_HOST);
    req_builder = req_builder.header(
        HeaderName::from_static("hysteria-auth"),
        HeaderValue::from_str(password).map_err(|e| ProxyError::Protocol(e.to_string()))?,
    );
    req_builder = req_builder.header(
        HeaderName::from_static("hysteria-cc-rx"),
        HeaderValue::from_str(&rx_bps.to_string())
            .map_err(|e| ProxyError::Protocol(e.to_string()))?,
    );
    req_builder = req_builder.header(
        HeaderName::from_static("hysteria-padding"),
        HeaderValue::from_static(""),
    );
    let req = req_builder
        .body(())
        .map_err(|e| ProxyError::Protocol(e.to_string()))?;

    let mut stream = send_request
        .send_request(req)
        .await
        .map_err(|e| ProxyError::Transport(format!("send auth request: {e}")))?;
    stream
        .finish()
        .await
        .map_err(|e| ProxyError::Transport(format!("finish auth request: {e}")))?;

    let resp = stream
        .recv_response()
        .await
        .map_err(|e| ProxyError::Transport(format!("recv auth response: {e}")))?;

    if resp.status().as_u16() != proto::STATUS_AUTH_OK {
        return Err(ProxyError::AuthFailed);
    }

    let _auth = proto::auth_response_from_headers(resp.headers(), resp.status().as_u16());
    Ok(())
}

struct Hysteria2Stream {
    inner: ReunionStream<quinn::RecvStream, quinn::SendStream>,
    _conn: quinn::Connection,
    _endpoint: quinn::Endpoint,
}

impl AsyncRead for Hysteria2Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for Hysteria2Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Outbound handler that dials destinations through a Hysteria2 client.
pub struct Hysteria2OutboundHandler {
    client: Hysteria2Client,
    tag: String,
}

impl Hysteria2OutboundHandler {
    /// Create a shared outbound handler with a fixed tag.
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

    async fn connect(&self, _ctx: &Context, dest: &Address) -> Result<BoxedStream, ProxyError> {
        self.client.connect_and_dial(dest).await
    }
}

fn build_hysteria2_client_config(
    skip_verify: bool,
    transport: Arc<quinn::TransportConfig>,
) -> anyhow::Result<quinn::ClientConfig> {
    use anyhow::Context as _;
    use quinn::crypto::rustls::QuicClientConfig;

    ensure_crypto_provider();

    let mut tls_config = if skip_verify {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipVerifier))
            .with_no_client_auth()
    } else {
        let mut roots = rustls::RootCertStore::empty();
        let result = rustls_native_certs::load_native_certs();
        for cert in result.certs {
            let _ = roots.add(cert);
        }
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    };
    tls_config.alpn_protocols = vec![b"h3".to_vec()];

    let quic_config = QuicClientConfig::try_from(tls_config).context("build QuicClientConfig")?;
    let mut config = quinn::ClientConfig::new(Arc::new(quic_config));
    config.transport_config(transport);
    Ok(config)
}

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
