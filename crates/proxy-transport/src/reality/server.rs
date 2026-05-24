use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::Result;
use hkdf::Hkdf;
use sha2::Sha256;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, warn};
use x25519_dalek::{PublicKey, StaticSecret};

use proxy_common::{BoxedStream, PrependedStream, ProxyError};

use super::parser::{parse_client_hello, ClientHelloFields};
use super::{MAX_TIME_DIFF_SECS, REALITY_HKDF_INFO, SESSION_ID_OFFSET_IN_HANDSHAKE_BODY};

/// Stream ready for TLS after successful REALITY authentication.
pub struct RealityAccepted {
    pub stream: BoxedStream,
    pub auth_key: [u8; 32],
}

/// REALITY server configuration read from the inbound config.
pub struct RealityServerConfig {
    /// The server's long-term X25519 private key. Keep this secret.
    pub private_key: [u8; 32],

    /// Valid short IDs for this server. Clients must present one of them.
    pub short_ids: Vec<Vec<u8>>,

    /// Real HTTPS destination used when authentication fails.
    pub fallback: SocketAddr,

    /// Maximum allowed clock skew in seconds.
    pub max_time_diff: i64,
}

/// REALITY server: authenticates incoming connections or forwards them away.
pub struct RealityServer {
    config: Arc<RealityServerConfig>,
    private_key: StaticSecret,
}

impl RealityServer {
    pub fn new(mut config: RealityServerConfig) -> Self {
        if config.max_time_diff <= 0 {
            config.max_time_diff = MAX_TIME_DIFF_SECS;
        }
        let private_key = StaticSecret::from(config.private_key);
        Self {
            private_key,
            config: Arc::new(config),
        }
    }

    /// Accept a connection and replay the ClientHello for a later TLS stack.
    ///
    /// This is the production shape: rustls must see the exact bytes we already
    /// parsed, so the returned `PrependedStream` gives those bytes back first.
    pub async fn accept(&self, stream: BoxedStream) -> Result<BoxedStream, ProxyError> {
        Ok(self.accept_with_key(stream).await?.stream)
    }

    /// Like [`accept`](Self::accept) but also returns the per-connection REALITY auth key.
    pub async fn accept_with_key(
        &self,
        stream: BoxedStream,
    ) -> Result<RealityAccepted, ProxyError> {
        let (stream, auth_key) = self
            .accept_inner(stream, ReplayMode::PrependClientHello)
            .await?;
        Ok(RealityAccepted { stream, auth_key })
    }

    /// Accept a connection without replaying the ClientHello.
    ///
    /// Phase 2 uses this direct mode because full TLS completion is not wired
    /// yet. After authentication, the next readable byte is the VLESS header.
    pub async fn accept_direct(&self, stream: BoxedStream) -> Result<BoxedStream, ProxyError> {
        Ok(self
            .accept_inner(stream, ReplayMode::ConsumeClientHello)
            .await?
            .0)
    }

    async fn accept_inner(
        &self,
        mut stream: BoxedStream,
        replay_mode: ReplayMode,
    ) -> Result<(BoxedStream, [u8; 32]), ProxyError> {
        let mut record_header = [0u8; 5];
        stream.read_exact(&mut record_header).await?;

        if record_header[0] != 0x16 {
            debug!(
                "not a TLS record (byte[0]={:#04x}) — forwarding to fallback",
                record_header[0]
            );
            return self.do_fallback(stream, record_header.to_vec()).await;
        }

        let record_len = u16::from_be_bytes([record_header[3], record_header[4]]) as usize;
        if record_len > 16384 {
            debug!("oversized record ({record_len} bytes) — forwarding to fallback");
            return self.do_fallback(stream, record_header.to_vec()).await;
        }

        let mut handshake_body = vec![0u8; record_len];
        stream.read_exact(&mut handshake_body).await?;

        let fields = match parse_client_hello(&handshake_body) {
            Ok(f) => f,
            Err(e) => {
                debug!(error = %e, "ClientHello parse failed — forwarding to fallback");
                let all_bytes = join_record(record_header, &handshake_body);
                return self.do_fallback(stream, all_bytes).await;
            }
        };

        let auth_key = match self.derive_auth_key(&fields, &handshake_body) {
            Ok(key) => key,
            Err(e) => {
                debug!(error = %e, "REALITY authentication failed — forwarding to fallback");
                let all_bytes = join_record(record_header, &handshake_body);
                return self.do_fallback(stream, all_bytes).await;
            }
        };

        debug!("REALITY authentication succeeded");
        let stream = match replay_mode {
            ReplayMode::PrependClientHello => {
                let replay = join_record(record_header, &handshake_body);
                Box::new(PrependedStream::new(stream, replay)) as BoxedStream
            }
            ReplayMode::ConsumeClientHello => stream,
        };
        Ok((stream, auth_key))
    }

    /// Derive the REALITY auth key and validate the encrypted session token.
    fn derive_auth_key(
        &self,
        fields: &ClientHelloFields,
        handshake_body: &[u8],
    ) -> Result<[u8; 32]> {
        let client_pub = PublicKey::from(fields.x25519_key_share);
        let shared_secret = self.private_key.diffie_hellman(&client_pub);

        let hk = Hkdf::<Sha256>::new(Some(&fields.random[..20]), shared_secret.as_bytes());
        let mut auth_key = [0u8; 32];
        hk.expand(REALITY_HKDF_INFO, &mut auth_key)
            .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?;

        let aad = make_reality_aad(handshake_body)?;
        let plaintext = decrypt_session_id(fields, &auth_key, &aad)?;
        validate_token(
            &plaintext,
            &self.config.short_ids,
            self.config.max_time_diff,
        )?;
        Ok(auth_key)
    }

    /// Forward to the real fallback HTTPS site and finish the connection there.
    async fn do_fallback(
        &self,
        mut stream: BoxedStream,
        already_read: Vec<u8>,
    ) -> Result<(BoxedStream, [u8; 32]), ProxyError> {
        warn!(fallback = %self.config.fallback, "forwarding to fallback");

        let mut fallback = TcpStream::connect(self.config.fallback)
            .await
            .map_err(|e| ProxyError::Transport(format!("fallback connect: {e}")))?;

        // Replay the bytes we consumed before proxying both directions.
        fallback.write_all(&already_read).await?;
        tokio::io::copy_bidirectional(&mut stream, &mut fallback)
            .await
            .ok();

        Err(ProxyError::FallbackRequired)
    }
}

#[derive(Clone, Copy)]
enum ReplayMode {
    PrependClientHello,
    ConsumeClientHello,
}

fn join_record(record_header: [u8; 5], handshake_body: &[u8]) -> Vec<u8> {
    let mut all_bytes = record_header.to_vec();
    all_bytes.extend_from_slice(handshake_body);
    all_bytes
}

fn make_reality_aad(handshake_body: &[u8]) -> Result<Vec<u8>> {
    let sid_start = SESSION_ID_OFFSET_IN_HANDSHAKE_BODY;
    let sid_end = sid_start + 32;
    if handshake_body.len() < sid_end {
        anyhow::bail!("handshake body too short to contain session_id");
    }

    // AES-GCM AAD is the ClientHello body with session_id zeroed, because the
    // session_id itself is the ciphertext and cannot authenticate itself.
    let mut aad = handshake_body.to_vec();
    aad[sid_start..sid_end].fill(0);
    Ok(aad)
}

fn decrypt_session_id(
    fields: &ClientHelloFields,
    auth_key: &[u8; 32],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(auth_key));
    let nonce = Nonce::from_slice(&fields.random[20..32]);

    cipher
        .decrypt(
            nonce,
            Payload {
                msg: &fields.session_id,
                aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("AES-128-GCM decryption failed (bad client?)"))
}

fn validate_token(
    plaintext: &[u8],
    allowed_short_ids: &[Vec<u8>],
    max_time_diff: i64,
) -> Result<()> {
    if plaintext.len() < 16 {
        anyhow::bail!("decrypted token too short: {} bytes", plaintext.len());
    }

    let ts = u32::from_be_bytes([plaintext[4], plaintext[5], plaintext[6], plaintext[7]]) as i64;
    let short_id = &plaintext[8..16];
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let diff = (now - ts).abs();
    if diff > max_time_diff {
        anyhow::bail!("timestamp skew too large: {diff}s (max {max_time_diff}s)");
    }

    let effective_short_id = strip_zero_padding(short_id);
    let valid = allowed_short_ids
        .iter()
        .any(|allowed| allowed.as_slice() == effective_short_id);
    if !valid {
        anyhow::bail!("short_id not in allowed list");
    }

    Ok(())
}

fn strip_zero_padding(short_id: &[u8]) -> &[u8] {
    let last_nonzero = short_id
        .iter()
        .rposition(|&b| b != 0)
        .map(|i| i + 1)
        .unwrap_or(0);
    &short_id[..last_nonzero]
}
