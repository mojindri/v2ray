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

use super::parser::{parse_client_hello, reality_auth_peer_public_keys, ClientHelloFields};
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
        if std::env::var_os("REALITY_DEBUG_HELLO").is_some() {
            use base64::Engine;
            let b64 = base64::engine::general_purpose::STANDARD.encode(&handshake_body);
            warn!(hello_b64 = %b64, "REALITY client hello capture");
        }
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
        let mut peer_pubs = reality_auth_peer_public_keys(handshake_body);
        if peer_pubs.is_empty() {
            peer_pubs.push(fields.x25519_key_share);
        }

        let wire_aad = handshake_body.to_vec();
        let zeroed_aad = make_reality_aad_zeroed_session_id(handshake_body)?;

        for peer_pub in peer_pubs {
            let shared_secret = self
                .private_key
                .diffie_hellman(&PublicKey::from(peer_pub));
            let hk = Hkdf::<Sha256>::new(Some(&fields.random[..20]), shared_secret.as_bytes());
            let mut auth_key = [0u8; 32];
            if hk.expand(REALITY_HKDF_INFO, &mut auth_key).is_err() {
                continue;
            }

            // Xray/sing-box seal with hello.Raw where session_id is still zeroed (plaintext
            // lives only in SessionId until after Seal). REALITY Open uses zeroed original.
            for aad in [&zeroed_aad, &wire_aad] {
                if let Ok(plaintext) = decrypt_session_id(fields, &auth_key, aad) {
                    if validate_token(
                        &plaintext,
                        &self.config.short_ids,
                        self.config.max_time_diff,
                    )
                    .is_ok()
                        && auth_roundtrip_matches(fields, &auth_key, aad, &plaintext)
                    {
                        return Ok(auth_key);
                    }
                }
            }

            // Xray/sing-box seal with hello.Raw where session_id[0..16] is plaintext and
            // session_id[16..32] is zero before encryption.
            for plaintext16 in
                candidate_reality_plaintexts(&self.config.short_ids, self.config.max_time_diff)
            {
                let Ok(seal_aad) = make_reality_aad_after_decrypt(handshake_body, &plaintext16)
                else {
                    continue;
                };
                if let Ok(plaintext) = decrypt_session_id(fields, &auth_key, &seal_aad) {
                    if validate_token(
                        &plaintext,
                        &self.config.short_ids,
                        self.config.max_time_diff,
                    )
                    .is_ok()
                        && auth_roundtrip_matches(fields, &auth_key, &seal_aad, &plaintext)
                    {
                        return Ok(auth_key);
                    }
                }
            }
        }

        Err(anyhow::anyhow!("REALITY authentication failed"))
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

/// AAD used by our own REALITY client (session_id built as zeros before encryption).
fn make_reality_aad_zeroed_session_id(handshake_body: &[u8]) -> Result<Vec<u8>> {
    let sid_start = SESSION_ID_OFFSET_IN_HANDSHAKE_BODY;
    let sid_end = sid_start + 32;
    if handshake_body.len() < sid_end {
        anyhow::bail!("handshake body too short to contain session_id");
    }

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
        .map_err(|_| anyhow::anyhow!("AES-256-GCM decryption failed (bad client?)"))
}

fn encrypt_session_id(
    fields: &ClientHelloFields,
    auth_key: &[u8; 32],
    aad: &[u8],
    plaintext16: &[u8],
) -> Result<[u8; 32]> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(auth_key));
    let nonce = Nonce::from_slice(&fields.random[20..32]);
    let output = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext16,
                aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("AES-256-GCM encryption failed"))?;
    output
        .try_into()
        .map_err(|_| anyhow::anyhow!("REALITY token encryption length mismatch"))
}

fn auth_roundtrip_matches(
    fields: &ClientHelloFields,
    auth_key: &[u8; 32],
    aad: &[u8],
    plaintext: &[u8],
) -> bool {
    if plaintext.len() < 16 {
        return false;
    }
    encrypt_session_id(fields, auth_key, aad, &plaintext[..16])
        .map(|enc| enc == fields.session_id)
        .unwrap_or(false)
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

/// After decrypting the session token, rebuild the ClientHello AAD that Xray/sing-box
/// used at `Seal` time: plaintext in the first 16 session_id bytes, zeros in the last 16.
/// Candidate 16-byte session tokens for Xray/sing-box ClientHello sealing.
fn candidate_reality_plaintexts(short_ids: &[Vec<u8>], max_time_diff: i64) -> Vec<[u8; 16]> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let window = max_time_diff.max(1).min(600);
    // sing-box: 1.8.1 (+ byte 3 may be non-zero from PutUint64 before version overwrite).
    // Xray 26.3.x uses core.Version bytes in the first three slots.
    const VERSION_PREFIXES: &[[u8; 4]] = &[
        [1, 8, 1, 0],
        [26, 3, 27, 0],
        [1, 8, 0, 0],
        [0, 0, 0, 0],
    ];

    let mut out = Vec::new();
    for short_id in short_ids {
        let mut sid8 = [0u8; 8];
        let copy_len = short_id.len().min(8);
        sid8[..copy_len].copy_from_slice(&short_id[..copy_len]);

        for prefix in VERSION_PREFIXES {
            // sing-box leaves byte 3 from PutUint64; for current Unix times it is 0.
            let b3_end = if prefix[..3] == [1, 8, 1] { 1u8 } else { prefix[3] };
            for b3 in 0..=b3_end {
                for dt in -window..=window {
                    let ts = (now + dt) as u32;
                    let mut pt = [0u8; 16];
                    pt[..3].copy_from_slice(&prefix[..3]);
                    pt[3] = b3;
                    pt[4..8].copy_from_slice(&ts.to_be_bytes());
                    pt[8..16].copy_from_slice(&sid8);
                    out.push(pt);
                }
            }
        }
    }
    out
}

fn make_reality_aad_after_decrypt(handshake_body: &[u8], plaintext16: &[u8]) -> Result<Vec<u8>> {
    let sid_start = SESSION_ID_OFFSET_IN_HANDSHAKE_BODY;
    let sid_end = sid_start + 32;
    if handshake_body.len() < sid_end {
        anyhow::bail!("handshake body too short to contain session_id");
    }
    if plaintext16.len() != 16 {
        anyhow::bail!("REALITY token plaintext must be 16 bytes");
    }

    let mut aad = handshake_body.to_vec();
    aad[sid_start..sid_start + 16].copy_from_slice(plaintext16);
    aad[sid_start + 16..sid_end].fill(0);
    Ok(aad)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::{Aes256Gcm, Key, Nonce};
    use hkdf::Hkdf;
    use sha2::Sha256;
    use x25519_dalek::{PublicKey, StaticSecret};

    /// Reproduce Xray `Seal` / REALITY `Open` AAD behavior from xtls/reality.
    /// ClientHello captured from sing-box 1.13 + chrome fp against matrix keys (docker).
    #[test]
    fn docker_singbox_chrome_hello_authenticates() {
        let hello = include_bytes!("testdata/singbox-chrome-hello.bin");
        let priv_hex = "6f4850ca51ced64b4acfd90c73fd60392c0c2f92744933b28b1bc0f7b8683d79";
        let priv_bytes: [u8; 32] = hex::decode(priv_hex).unwrap().try_into().unwrap();
        let short_id = hex::decode("aabbccdd00000001").unwrap();

        let server = RealityServer::new(RealityServerConfig {
            private_key: priv_bytes,
            short_ids: vec![short_id],
            fallback: "127.0.0.1:80".parse().unwrap(),
            // This fixture is a static Docker capture. Keep the test focused on
            // Xray/sing-box REALITY decrypt + cert HMAC, not wall-clock freshness.
            max_time_diff: 10 * 365 * 24 * 60 * 60,
        });

        let fields = parse_client_hello(hello).expect("parse captured hello");
        let auth_key = server
            .derive_auth_key(&fields, hello)
            .expect("matrix server must authenticate captured sing-box hello");
        let (cert, _) = crate::reality::cert::tls_cert_for_auth_key(
            &auth_key,
            "www.microsoft.com",
            false,
        )
        .unwrap();
        crate::reality::cert::verify_reality_cert_hmac(&auth_key, &cert)
            .expect("cert HMAC must verify with same auth_key");
    }

    #[test]
    fn matrix_lab_reality_keypair_is_valid() {
        let priv_hex = "6f4850ca51ced64b4acfd90c73fd60392c0c2f92744933b28b1bc0f7b8683d79";
        let pub_hex = "968612b14962343a5327f212761e90dc0ddf31ced39da41fb839694be2b8e96a";
        let priv_bytes: [u8; 32] = hex::decode(priv_hex).unwrap().try_into().unwrap();
        let expected_pub: [u8; 32] = hex::decode(pub_hex).unwrap().try_into().unwrap();
        let secret = StaticSecret::from(priv_bytes);
        let derived = *PublicKey::from(&secret).as_bytes();
        assert_eq!(derived, expected_pub);
    }

    #[test]
    fn xray_reality_gcm_uses_plaintext_session_id_in_aad() {
        let mut random = [0u8; 32];
        random[20..].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
        let mut session_plain = [0u8; 32];
        session_plain[0] = 1;
        session_plain[1] = 8;
        session_plain[2] = 1;
        session_plain[4..8].copy_from_slice(&1_700_000_000u32.to_be_bytes());

        let mut raw = vec![0u8; 100];
        raw[4] = 0x03;
        raw[5] = 0x03;
        raw[6..38].copy_from_slice(&random);
        raw[38] = 32;
        raw[39..71].copy_from_slice(&session_plain);

        let shared = [7u8; 32];
        let mut auth_key = [0u8; 32];
        Hkdf::<Sha256>::new(Some(&random[..20]), &shared)
            .expand(REALITY_HKDF_INFO, &mut auth_key)
            .unwrap();

        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&auth_key));
        let nonce = Nonce::from_slice(&random[20..32]);
        let ct = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: &session_plain[..16],
                    aad: &raw,
                },
            )
            .unwrap();

        let mut session_wire = [0u8; 32];
        session_wire[..ct.len()].copy_from_slice(&ct);
        let mut original = raw.clone();
        original[39..71].copy_from_slice(&session_wire);

        let zeroed = make_reality_aad_zeroed_session_id(&original).unwrap();
        let seal_aad = make_reality_aad_after_decrypt(&original, &session_plain[..16]).unwrap();

        assert!(cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &session_wire,
                    aad: &original,
                },
            )
            .is_err());
        assert!(cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &session_wire,
                    aad: &zeroed,
                },
            )
            .is_err());
        let plain = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &session_wire,
                    aad: &seal_aad,
                },
            )
            .unwrap();
        assert_eq!(&plain[..16], &session_plain[..16]);
    }
}
