//! Complete TLS 1.3 after REALITY auth using rustls (uTLS / sing-box compatible).

use proxy_common::{BoxedStream, ProxyError};

use super::cert::{tls_cert_for_auth_key, tls_pem_for_auth_key, verify_reality_cert_hmac};

/// Run a TLS 1.3 server handshake on `stream` after REALITY authentication.
///
/// The stream must begin with a replay of the client's ClientHello (see
/// [`RealityServer::accept_with_key`](super::RealityServer::accept_with_key)).
pub async fn accept_tls13_after_reality(
    stream: BoxedStream,
    auth_key: &[u8; 32],
    cover_sni: &str,
) -> Result<BoxedStream, ProxyError> {
    let (cert_der, _) = tls_cert_for_auth_key(auth_key, cover_sni, false)?;
    verify_reality_cert_hmac(auth_key, &cert_der)?;
    let (cert_pem, key_pem) = tls_pem_for_auth_key(auth_key, cover_sni)?;

    crate::tls::tls_accept_tls13(stream, &cert_pem, &key_pem, &[]).await
}
