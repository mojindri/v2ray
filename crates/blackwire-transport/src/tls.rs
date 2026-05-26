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

// ── Linux kTLS (Kernel TLS) ───────────────────────────────────────────────────
//
// When both conditions hold:
//   1. The underlying transport is a raw TcpStream.
//   2. The kernel supports SO_KTLS (Linux 4.13+ for TLS 1.2,  4.17+ for TLS 1.3).
//
// …we transfer TLS record encryption/decryption into the kernel so that the
// relay layer can use splice(2) on the resulting fd.  From the kernel's point
// of view the fd is a regular TCP socket; reads/writes are automatically
// en/decrypted without touching user-space buffers.
//
// Fallback: if TCP_ULP "tls" is rejected (old kernel, unsupported cipher, or
// non-TCP transport) we silently keep the normal tokio-rustls TlsStream path.

#[cfg(target_os = "linux")]
mod ktls {
    use std::io;

    use rustls::ConnectionTrafficSecrets;

    // ── linux/tls.h constants ─────────────────────────────────────────────────

    // SOL_TLS is not in all libc versions; use the numeric value.
    const SOL_TLS: libc::c_int = 282;
    const TLS_TX: libc::c_int = 1;
    const TLS_RX: libc::c_int = 2;
    // TCP_ULP is not exported by libc; numeric value from <linux/tcp.h>.
    pub(super) const TCP_ULP: libc::c_int = 31;

    const TLS_1_3_VERSION: u16 = 0x0304;
    const TLS_CIPHER_AES_GCM_128: u16 = 51;
    const TLS_CIPHER_AES_GCM_256: u16 = 52;

    // ── Kernel crypto-info structs (must match linux/tls.h exactly) ───────────

    #[repr(C)]
    struct TlsCryptoInfo {
        version: u16,
        cipher_type: u16,
    }

    // tls12_crypto_info_aes_gcm_128
    #[repr(C)]
    struct AesGcm128Info {
        info: TlsCryptoInfo,
        iv: [u8; 8],
        key: [u8; 16],
        salt: [u8; 4],
        rec_seq: [u8; 8],
    }

    // tls12_crypto_info_aes_gcm_256
    #[repr(C)]
    struct AesGcm256Info {
        info: TlsCryptoInfo,
        iv: [u8; 8],
        key: [u8; 32],
        salt: [u8; 4],
        rec_seq: [u8; 8],
    }

    // ── Public entry points ───────────────────────────────────────────────────

    /// Install the TLS TX and RX keys on a socket that already has TCP_ULP set.
    ///
    /// Called after `setsockopt(TCP_ULP, "tls")` has succeeded.  Returns `Err`
    /// if the cipher suite is not supported by the kernel TLS implementation.
    pub(super) fn install_keys(
        fd: libc::c_int,
        seq_tx: u64,
        secrets_tx: &ConnectionTrafficSecrets,
        seq_rx: u64,
        secrets_rx: &ConnectionTrafficSecrets,
    ) -> io::Result<()> {
        set_tls_key(fd, TLS_TX, seq_tx, secrets_tx)?;
        set_tls_key(fd, TLS_RX, seq_rx, secrets_rx)
    }

    fn set_tls_key(
        fd: libc::c_int,
        direction: libc::c_int,
        seq: u64,
        secrets: &ConnectionTrafficSecrets,
    ) -> io::Result<()> {
        match secrets {
            ConnectionTrafficSecrets::Aes128Gcm { key, iv } => {
                let iv_bytes = iv.as_ref(); // 12 bytes
                let key_bytes = key.as_ref(); // AES-128 uses first 16
                if key_bytes.len() < 16 || iv_bytes.len() < 12 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "short AES-128-GCM key/iv",
                    ));
                }
                // Rustls Iv for TLS 1.3: [fixed_iv_prefix(4) || implicit_nonce(8)]
                // Linux kTLS splits as salt[4] || iv[8].
                let info = AesGcm128Info {
                    info: TlsCryptoInfo {
                        version: TLS_1_3_VERSION,
                        cipher_type: TLS_CIPHER_AES_GCM_128,
                    },
                    salt: iv_bytes[..4].try_into().unwrap(),
                    iv: iv_bytes[4..12].try_into().unwrap(),
                    key: key_bytes[..16].try_into().unwrap(),
                    rec_seq: seq.to_be_bytes(),
                };
                setsockopt_tls(fd, direction, &info)
            }
            ConnectionTrafficSecrets::Aes256Gcm { key, iv } => {
                let iv_bytes = iv.as_ref();
                let key_bytes = key.as_ref();
                if key_bytes.len() < 32 || iv_bytes.len() < 12 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "short AES-256-GCM key/iv",
                    ));
                }
                let info = AesGcm256Info {
                    info: TlsCryptoInfo {
                        version: TLS_1_3_VERSION,
                        cipher_type: TLS_CIPHER_AES_GCM_256,
                    },
                    salt: iv_bytes[..4].try_into().unwrap(),
                    iv: iv_bytes[4..12].try_into().unwrap(),
                    key: key_bytes[..32].try_into().unwrap(),
                    rec_seq: seq.to_be_bytes(),
                };
                setsockopt_tls(fd, direction, &info)
            }
            // ChaCha20-Poly1305 kTLS requires kernel 5.11+; defer to the
            // user-space TLS path for now.
            _ => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "cipher not supported by kTLS path",
            )),
        }
    }

    fn setsockopt_tls<T: Sized>(fd: libc::c_int, direction: libc::c_int, info: &T) -> io::Result<()> {
        // SAFETY: `info` is a repr(C) struct whose layout matches the kernel struct.
        let rc = unsafe {
            libc::setsockopt(
                fd,
                SOL_TLS,
                direction,
                info as *const T as *const libc::c_void,
                std::mem::size_of::<T>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

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
/// On Linux, when the underlying transport is a raw `TcpStream`, the handshake
/// result is upgraded to kernel TLS (kTLS) by calling `setsockopt TCP_ULP "tls"`
/// and installing the traffic keys.  The returned `BoxedStream` is then a plain
/// `TcpStream` whose encryption is handled transparently by the kernel, which
/// lets the relay layer use `splice(2)` for zero-copy forwarding.
///
/// If the kernel rejects kTLS (old kernel, non-TCP transport, unsupported
/// cipher) the function falls back to the normal tokio-rustls `TlsStream`.
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

    // ── Linux kTLS upgrade ────────────────────────────────────────────────────
    //
    // Phase 1 (probe): borrow the TlsStream to get the inner TcpStream fd and
    //   try setsockopt(TCP_ULP, "tls").  The borrow ends before we consume the
    //   TlsStream so that Phase 2 can call into_inner() without conflict.
    //
    // Phase 2 (commit): only after the probe succeeds, consume the TlsStream,
    //   extract traffic secrets from the rustls connection, and install keys.
    //
    // Either phase failing falls through to the normal TlsStream path.
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        use blackwire_common::AsyncReadWrite;
        use tokio::net::TcpStream;

        // Phase 1 — probe (scoped so the borrow of tls_stream ends before
        // into_inner() is called below).
        let maybe_fd: Option<libc::c_int> = {
            // Cast to &dyn AsyncReadWrite to force vtable dispatch on as_any();
            // calling stream.as_any() would use the blanket impl on Box<dyn ..>
            // and return the Box type rather than the concrete inner type.
            let inner_dyn: &dyn AsyncReadWrite = tls_stream.get_ref().0.as_ref();
            if inner_dyn.as_any().is::<TcpStream>() {
                let fd = inner_dyn
                    .as_any()
                    .downcast_ref::<TcpStream>()
                    .unwrap()
                    .as_raw_fd();
                let ulp = b"tls\0";
                // SAFETY: setsockopt with a NUL-terminated "tls" string.
                let ok = unsafe {
                    libc::setsockopt(
                        fd,
                        libc::IPPROTO_TCP,
                        ktls::TCP_ULP,
                        ulp.as_ptr() as *const libc::c_void,
                        (ulp.len() - 1) as libc::socklen_t,
                    ) == 0
                };
                if ok { Some(fd) } else { None }
            } else {
                None
            }
            // inner_dyn borrow of tls_stream ends here.
        };

        if let Some(fd) = maybe_fd {
            // Phase 2 — commit: tls_stream borrow has ended; consume it.
            let (inner, server_conn) = tls_stream.into_inner();
            match server_conn.dangerous_extract_secrets() {
                Ok(secrets) => {
                    let seq_tx = secrets.tx.0;
                    let seq_rx = secrets.rx.0;
                    match ktls::install_keys(fd, seq_tx, &secrets.tx.1, seq_rx, &secrets.rx.1) {
                        Ok(()) => {
                            let tcp = *inner
                                .into_any()
                                .downcast::<TcpStream>()
                                .expect("confirmed TcpStream in phase 1");
                            tracing::debug!("kTLS enabled on inbound TLS connection");
                            return Ok(Box::new(tcp));
                        }
                        Err(e) => {
                            tracing::warn!("kTLS key install failed: {e}; dropping connection");
                            return Err(ProxyError::Tls(
                                format!("kTLS key install failed: {e}"),
                            ));
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("kTLS secret extraction failed: {e}; dropping connection");
                    return Err(ProxyError::Tls(
                        format!("kTLS secret extraction failed: {e}"),
                    ));
                }
            }
        }
        // ULP rejected or inner is not TCP: fall through to TlsStream.
    }

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
    // Enable secret extraction so the kTLS path can install kernel keys after
    // the handshake.  On non-Linux this field still exists but is never used.
    config.enable_secret_extraction = true;
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
    config.enable_secret_extraction = true;
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
