//! QUIC endpoint construction helpers.
//!
//! QUIC is a UDP-based transport protocol built on TLS 1.3. It supports
//! multiple simultaneous bidirectional streams over a single connection,
//! built-in loss recovery, and 0-RTT connection establishment.
//!
//! This module provides helpers to build Quinn QUIC server and client endpoints
//! with the TLS configuration required for Hysteria2.

mod brutal_cc;

pub use brutal_cc::{BrutalCC, BrutalCCFactory};

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{ClientConfig, Endpoint, ServerConfig, TransportConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::RootCertStore;

/// Install the rustls crypto provider used by this workspace.
///
/// Several dependencies may enable different rustls provider features. Calling
/// this before building TLS configs makes QUIC startup deterministic.
pub(crate) fn ensure_crypto_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

/// Build a QUIC server endpoint.
///
/// Parses the certificate and private key from PEM strings, sets up TLS with
/// ALPN `["h3"]`, and opens a UDP socket at `addr`.
///
/// # Arguments
/// * `addr`     — UDP socket address to bind
/// * `cert_pem` — PEM-encoded certificate chain
/// * `key_pem`  — PEM-encoded private key (PKCS#8 or PKCS#1)
pub fn build_server_endpoint(addr: SocketAddr, cert_pem: &str, key_pem: &str) -> Result<Endpoint> {
    ensure_crypto_provider();

    let (certs, key) = parse_cert_and_key(cert_pem, key_pem)?;

    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("invalid TLS certificate or key")?;

    // Hysteria2 auth is HTTP/3; sing-box and sing-quic negotiate ALPN "h3".
    tls_config.alpn_protocols = vec![b"h3".to_vec()];

    let quic_server_config = QuicServerConfig::try_from(tls_config)
        .context("failed to build QUIC server config from TLS config")?;

    let mut server_config = ServerConfig::with_crypto(Arc::new(quic_server_config));

    // Set a 30-second idle timeout so stale connections are cleaned up even
    // when the client disappears without sending a proper close.
    let mut transport = TransportConfig::default();
    let idle_timeout = Duration::from_secs(30)
        .try_into()
        .expect("constant 30s idle timeout fits in quinn IdleTimeout");
    transport.max_idle_timeout(Some(idle_timeout));
    server_config.transport_config(Arc::new(transport));

    Endpoint::server(server_config, addr).context("failed to open QUIC server endpoint")
}

/// Build a QUIC server endpoint for Hysteria2 inbounds.
///
/// Same as [`build_server_endpoint`] but enables QUIC datagrams for future UDP relay.
pub fn build_hysteria2_server_endpoint(
    addr: SocketAddr,
    cert_pem: &str,
    key_pem: &str,
) -> Result<Endpoint> {
    ensure_crypto_provider();

    let (certs, key) = parse_cert_and_key(cert_pem, key_pem)?;

    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("invalid TLS certificate or key")?;

    tls_config.alpn_protocols = vec![b"h3".to_vec()];

    let quic_server_config = QuicServerConfig::try_from(tls_config)
        .context("failed to build QUIC server config from TLS config")?;

    let mut server_config = ServerConfig::with_crypto(Arc::new(quic_server_config));

    let mut transport = TransportConfig::default();
    let idle_timeout = Duration::from_secs(30)
        .try_into()
        .expect("constant 30s idle timeout fits in quinn IdleTimeout");
    transport.max_idle_timeout(Some(idle_timeout));
    transport.datagram_receive_buffer_size(Some(2 * 1024 * 1024));
    transport.datagram_send_buffer_size(2 * 1024 * 1024);
    server_config.transport_config(Arc::new(transport));

    Endpoint::server(server_config, addr).context("failed to open Hysteria2 QUIC endpoint")
}

/// Build a QUIC client endpoint.
///
/// When `skip_verify` is `true`, TLS certificate validation is disabled.
/// This is useful for development with self-signed certificates but MUST NOT
/// be used in production.
pub fn build_client_endpoint(skip_verify: bool) -> Result<Endpoint> {
    ensure_crypto_provider();

    let mut tls_config = if skip_verify {
        build_no_verify_client_tls()
    } else {
        build_default_client_tls()?
    };
    tls_config.alpn_protocols = vec![b"h3".to_vec()];

    let quic_client_config = QuicClientConfig::try_from(tls_config)
        .context("failed to build QUIC client config from TLS config")?;

    let client_config = ClientConfig::new(Arc::new(quic_client_config));

    // Bind to any available local port.
    let bind_addr = "0.0.0.0:0"
        .parse()
        .context("invalid client bind address literal")?;
    let mut endpoint = Endpoint::client(bind_addr).context("failed to open client socket")?;
    endpoint.set_default_client_config(client_config);

    Ok(endpoint)
}

/// Generate a throwaway self-signed certificate and key for testing.
///
/// Returns `(cert_pem, key_pem)`. The certificate is valid for `localhost`.
/// Do not use in production — these certs are generated fresh every run
/// and are not persisted anywhere.
pub fn dev_self_signed() -> Result<(String, String)> {
    dev_self_signed_for_names(&["localhost".to_string()])
}

/// Self-signed cert for dev/test with arbitrary DNS SAN entries (e.g. REALITY cover SNI).
pub fn dev_self_signed_for_names(names: &[String]) -> Result<(String, String)> {
    let subjects = if names.is_empty() {
        vec!["localhost".to_string()]
    } else {
        names.to_vec()
    };
    let rcgen::CertifiedKey { cert, signing_key } = rcgen::generate_simple_self_signed(subjects)
        .context("failed to generate self-signed certificate")?;
    Ok((cert.pem(), signing_key.serialize_pem()))
}

// ── Private helpers ────────────────────────────────────────────────────────────

/// Parse PEM cert chain + PEM private key into rustls types.
fn parse_cert_and_key(
    cert_pem: &str,
    key_pem: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    crate::pem::parse_cert_and_key(cert_pem, key_pem).map_err(|e| anyhow::Error::msg(e.to_string()))
}

/// Build a client TLS config that accepts any server certificate.
///
/// For use in tests and development only. Skips all certificate chain and
/// hostname validation.
fn build_no_verify_client_tls() -> rustls::ClientConfig {
    rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth()
}

/// Build a client TLS config that uses the platform's native root certificates.
///
/// Falls back to an empty trust store if native roots fail to load.
fn build_default_client_tls() -> Result<rustls::ClientConfig> {
    let mut roots = RootCertStore::empty();
    // load_native_certs() returns a CertificateResult with .certs and .errors.
    let result = rustls_native_certs::load_native_certs();
    if !result.errors.is_empty() {
        tracing::warn!(
            "some native root certificates failed to load: {} errors",
            result.errors.len()
        );
    }
    for cert in result.certs {
        // Ignore individual parse errors — one bad root cert in the OS
        // store should not prevent the proxy from connecting.
        let _ = roots.add(cert);
    }
    Ok(rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth())
}

/// A TLS certificate verifier that accepts any certificate without validation.
///
/// This is intentionally insecure — only for use in tests and development.
#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        // Accept any signature scheme to not block connections.
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dev_self_signed_returns_valid_pem() {
        let (cert_pem, key_pem) = dev_self_signed().unwrap();
        assert!(cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(key_pem.contains("PRIVATE KEY"));
    }

    #[test]
    fn parse_cert_and_key_roundtrip() {
        let (cert_pem, key_pem) = dev_self_signed().unwrap();
        let (certs, _key) = parse_cert_and_key(&cert_pem, &key_pem).unwrap();
        assert!(!certs.is_empty());
    }

    #[test]
    fn brutal_cc_factory_builds_controller() {
        use quinn::congestion::ControllerFactory;
        use std::sync::Arc;
        let factory = Arc::new(BrutalCCFactory::new(12_500_000));
        // ControllerFactory::build takes self: Arc<Self>, so clone to preserve the factory.
        let ctrl = Arc::clone(&factory).build(std::time::Instant::now(), 1200);
        // Window must be at least MIN_WINDOW (32 KiB).
        assert!(ctrl.window() >= 32 * 1024);
    }
}
