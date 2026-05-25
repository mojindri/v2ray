//! Standard TLS transport — client and server using `tokio-rustls`.
//!
//! This module wraps a `BoxedStream` in a TLS layer. After the handshake,
//! the caller receives a `BoxedStream` that is indistinguishable from any
//! other stream — it just happens to be encrypted.
//!
//! # Client (`tls_connect`)
//!
//! The client performs a TLS handshake as the initiating party. It presents
//! an SNI hostname and optional ALPN protocols. If `skip_verify` is `true`
//! (dev/test only), certificate validation is skipped.
//!
//! # Server (`tls_accept`)
//!
//! The server performs a TLS handshake as the accepting party. It loads its
//! certificate and private key from PEM strings. PEM parsing is done with the
//! same hand-rolled parser used in `quic.rs` — no extra dependencies needed.
//!
//! # Security note
//!
//! `skip_verify = true` disables certificate chain verification. Never use
//! this in production — it allows man-in-the-middle attacks.

use std::sync::Arc;

use rustls::pki_types::{CertificateDer, ServerName};
use rustls::version::TLS13;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use blackwire_common::{BoxedStream, ProxyError};

// ── Client ────────────────────────────────────────────────────────────────────

/// Perform a TLS client handshake over an existing stream.
///
/// # Arguments
/// * `stream`      — the underlying transport stream (usually TCP)
/// * `sni`         — the server name to present in the TLS ClientHello
/// * `alpn`        — ALPN protocols to offer (e.g. `["h2", "http/1.1"]`)
/// * `skip_verify` — if `true`, skip certificate validation (dev only)
pub async fn tls_connect(
    stream: BoxedStream,
    sni: &str,
    alpn: &[&str],
    skip_verify: bool,
) -> Result<BoxedStream, ProxyError> {
    crate::quic::ensure_crypto_provider();
    let config = build_client_config(alpn, skip_verify)?;
    let connector = TlsConnector::from(Arc::new(config));

    let server_name = ServerName::try_from(sni.to_owned())
        .map_err(|e| ProxyError::Tls(format!("invalid SNI '{sni}': {e}")))?;

    let tls_stream = connector
        .connect(server_name, stream)
        .await
        .map_err(|e| ProxyError::Tls(format!("TLS connect failed: {e}")))?;

    Ok(Box::new(tls_stream))
}

/// Build a rustls `ClientConfig` for outbound TLS.
fn build_client_config(alpn: &[&str], skip_verify: bool) -> Result<ClientConfig, ProxyError> {
    crate::quic::ensure_crypto_provider();
    let mut config = if skip_verify {
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth()
    } else {
        let mut root_store = RootCertStore::empty();
        let native_roots = rustls_native_certs::load_native_certs();
        for cert in native_roots.certs {
            let _ = root_store.add(cert);
        }
        ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };

    config.alpn_protocols = alpn.iter().map(|s| s.as_bytes().to_vec()).collect();
    Ok(config)
}

// ── Server ────────────────────────────────────────────────────────────────────

/// Perform a TLS server handshake over an existing stream.
///
/// # Arguments
/// * `stream`   — the inbound transport stream to upgrade
/// * `cert_pem` — PEM-encoded certificate chain
/// * `key_pem`  — PEM-encoded private key
/// * `alpn`     — ALPN protocols to advertise
pub async fn tls_accept(
    stream: BoxedStream,
    cert_pem: &str,
    key_pem: &str,
    alpn: &[&str],
) -> Result<BoxedStream, ProxyError> {
    crate::quic::ensure_crypto_provider();
    let config = build_server_config(cert_pem, key_pem, alpn)?;
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let tls_stream = acceptor
        .accept(stream)
        .await
        .map_err(|e| ProxyError::Tls(format!("TLS accept failed: {e}")))?;

    Ok(Box::new(tls_stream))
}

/// TLS 1.3 server handshake for REALITY (ed25519 temporary certificate).
pub async fn tls_accept_tls13(
    stream: BoxedStream,
    cert_pem: &str,
    key_pem: &str,
    alpn: &[&str],
) -> Result<BoxedStream, ProxyError> {
    crate::quic::ensure_crypto_provider();
    let config = build_tls13_server_config(cert_pem, key_pem, alpn)?;
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let tls_stream = acceptor
        .accept(stream)
        .await
        .map_err(|e| ProxyError::Tls(format!("TLS accept failed: {e}")))?;

    Ok(Box::new(tls_stream))
}

/// Build a rustls `ServerConfig` from PEM strings.
///
/// This is `pub` so that the `instance.rs` wiring can pre-build the config
/// and reuse it across connections without re-parsing PEM every time.
pub fn build_server_config(
    cert_pem: &str,
    key_pem: &str,
    alpn: &[&str],
) -> Result<ServerConfig, ProxyError> {
    crate::quic::ensure_crypto_provider();
    let certs = crate::pem::parse_certs(cert_pem)?;
    let key = crate::pem::parse_private_key(key_pem)?;

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| ProxyError::Tls(format!("TLS server config error: {e}")))?;

    config.alpn_protocols = alpn.iter().map(|s| s.as_bytes().to_vec()).collect();
    Ok(config)
}

fn build_tls13_server_config(
    cert_pem: &str,
    key_pem: &str,
    alpn: &[&str],
) -> Result<ServerConfig, ProxyError> {
    crate::quic::ensure_crypto_provider();
    let certs = crate::pem::parse_certs(cert_pem)?;
    let key = crate::pem::parse_private_key(key_pem)?;

    let mut config = ServerConfig::builder_with_protocol_versions(&[&TLS13])
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| ProxyError::Tls(format!("TLS 1.3 server config error: {e}")))?;

    config.alpn_protocols = alpn.iter().map(|s| s.as_bytes().to_vec()).collect();
    Ok(config)
}

// ── Certificate verification bypass (dev only) ────────────────────────────────

/// A certificate verifier that accepts any certificate without validation.
///
/// WARNING: This completely disables TLS security. Use only for local testing.
#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        // Delegate to the installed provider.
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    fn gen_self_signed() -> (String, String) {
        crate::quic::dev_self_signed().expect("dev_self_signed failed")
    }

    async fn spawn_tls_echo_server(cert_pem: String, key_pem: String) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut tls = tls_accept(Box::new(tcp), &cert_pem, &key_pem, &[])
                .await
                .unwrap();
            let mut buf = vec![0u8; 4096];
            let n = tls.read(&mut buf).await.unwrap();
            tls.write_all(&buf[..n]).await.unwrap();
            tls.flush().await.unwrap();
        });

        port
    }

    /// Test: self-signed cert roundtrip with skip_verify.
    #[tokio::test]
    async fn tls_self_signed_roundtrip() {
        let (cert_pem, key_pem) = gen_self_signed();
        let port = spawn_tls_echo_server(cert_pem, key_pem).await;

        let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let mut tls = tls_connect(Box::new(tcp), "localhost", &[], true)
            .await
            .unwrap();

        let msg = b"hello tls";
        tls.write_all(msg).await.unwrap();
        tls.flush().await.unwrap();

        let mut recv = vec![0u8; msg.len()];
        tls.read_exact(&mut recv).await.unwrap();
        assert_eq!(&recv, msg);
    }

    /// Test: ALPN is accepted without breaking the handshake.
    #[tokio::test]
    async fn tls_alpn_roundtrip() {
        let (cert_pem, key_pem) = gen_self_signed();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let c = cert_pem.clone();
        let k = key_pem.clone();

        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut tls = tls_accept(Box::new(tcp), &c, &k, &["h2"]).await.unwrap();
            let mut buf = [0u8; 4];
            tls.read_exact(&mut buf).await.unwrap();
            tls.write_all(&buf).await.unwrap();
            tls.flush().await.unwrap();
        });

        let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let mut tls = tls_connect(Box::new(tcp), "localhost", &["h2"], true)
            .await
            .unwrap();

        tls.write_all(b"ping").await.unwrap();
        tls.flush().await.unwrap();
        let mut recv = [0u8; 4];
        tls.read_exact(&mut recv).await.unwrap();
        assert_eq!(&recv, b"ping");
    }
}
