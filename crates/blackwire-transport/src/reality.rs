//! REALITY transport — TLS camouflage using a real server as cover.
//!
//! REALITY hides proxy authentication inside fields that already exist in a
//! TLS ClientHello. A valid client sends a Chrome-like ClientHello containing:
//!
//! - a fresh X25519 public key in the TLS `key_share` extension,
//! - 32 bytes of `random` used as HKDF salt and AES-GCM nonce material,
//! - an encrypted token inside the 32-byte `session_id` field.
//!
//! The server parses that ClientHello, derives the same shared secret, decrypts
//! the token, and checks the short ID plus timestamp. If authentication fails,
//! the connection is forwarded to the configured fallback HTTPS site so probes
//! see ordinary TLS traffic.
//!
//! The implementation is split by role:
//! - `client` builds and sends the authenticated ClientHello.
//! - `server` validates incoming ClientHellos and handles fallback forwarding.
//! - `parser` extracts only the ClientHello fields REALITY needs.

mod cert;
mod client;
mod parser;
mod server;
pub(crate) mod tls13;

pub use cert::{tls_cert_for_auth_key, tls_pem_for_auth_key, verify_reality_cert_hmac};
pub use client::{RealityClient, RealityClientConfig};
pub use parser::{parse_client_hello, ClientHelloFields};
pub use server::{RealityAccepted, RealityServer, RealityServerConfig};
pub use tls13::{complete_tls13_server_handshake, Tls13Stream};

/// Complete TLS 1.3 as server after REALITY auth, wrapping the result in a `BoxedStream`.
///
/// Combines [`complete_tls13_server_handshake`] and [`Tls13Stream::new_server`] so that
/// callers don't need to name the private handshake-key type.
pub async fn reality_server_tls_stream(
    mut stream: blackwire_common::BoxedStream,
    auth_key: &[u8; 32],
    cover_sni: &str,
) -> Result<blackwire_common::BoxedStream, blackwire_common::ProxyError> {
    let keys = complete_tls13_server_handshake(&mut stream, auth_key, cover_sni).await?;
    Ok(Box::new(Tls13Stream::new_server(stream, keys)))
}

/// The HKDF info string used to derive the REALITY auth key.
///
/// This must match exactly between client and server, including casing.
pub(crate) const REALITY_HKDF_INFO: &[u8] = b"REALITY";

/// Byte length of the encrypted REALITY auth plaintext (Xray / sing-box compatible).
pub(crate) const REALITY_TOKEN_PLAINTEXT_LEN: usize = 16;

/// Maximum allowed clock skew between client and server in seconds.
pub(crate) const MAX_TIME_DIFF_SECS: i64 = 120;

/// Byte offset of the `session_id` inside the ClientHello handshake body.
///
/// This offset is counted after the 5-byte TLS record header:
/// handshake_type(1) + handshake_len(3) + legacy_version(2) + random(32)
/// + session_id_len(1) = 39.
pub(crate) const SESSION_ID_OFFSET_IN_HANDSHAKE_BODY: usize = 39;
