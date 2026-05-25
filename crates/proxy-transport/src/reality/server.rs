use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::Result;
use hkdf::Hkdf;
use sha2::Sha256;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, warn};
use x25519_dalek::{PublicKey, StaticSecret};

use proxy_common::{
    copy_bidirectional_with_idle, tcp_connect, BoxedStream, PrependedStream, ProxyError,
    CONNECTION_IDLE_TIMEOUT,
};

use super::parser::{parse_client_hello, reality_auth_peer_public_keys, ClientHelloFields};
use super::{MAX_TIME_DIFF_SECS, REALITY_HKDF_INFO, SESSION_ID_OFFSET_IN_HANDSHAKE_BODY};

/// Stream ready for TLS after successful REALITY authentication.
pub struct RealityAccepted {
    /// Accepted stream positioned for the next protocol stage.
    pub stream: BoxedStream,
    /// Per-connection key used by later REALITY/TLS steps.
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
    /// Create a REALITY server helper from inbound settings.
    ///
    /// If `max_time_diff` is non-positive, the default safety window is used.
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

    /// Accept a connection and replay the ClientHello for post-auth TLS.
    ///
    /// The returned [`PrependedStream`] replays the exact ClientHello bytes for
    /// [`complete_tls13_server_handshake`](crate::reality::complete_tls13_server_handshake).
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
        let peer_keys = reality_auth_peer_public_keys_or_fallback(fields, handshake_body);
        let zeroed_aad = xray_zeroed_session_id_aad(handshake_body)?;
        let wire_aad = handshake_body.to_vec();

        for (peer_idx, peer_pub) in peer_keys.iter().enumerate() {
            let peer_kind = peer_key_kind(peer_idx);
            let auth_key =
                match derive_reality_auth_key(&self.private_key, peer_pub, &fields.random) {
                    Ok(key) => key,
                    Err(_) => continue,
                };

            // Xray/sing-box: Seal(..., hello.SessionId[:16], hello.Raw) with session_id zeroed in Raw.
            // XTLS REALITY server Open(..., hs.clientHello.original) uses zeroed original.
            for (aad_mode, aad) in [
                (RealityAadMode::Zeroed, zeroed_aad.as_slice()),
                (RealityAadMode::Wire, wire_aad.as_slice()),
            ] {
                if let Some(token) = decrypt_and_validate_reality_token(
                    fields,
                    &auth_key,
                    aad,
                    &self.config.short_ids,
                    self.config.max_time_diff,
                ) {
                    log_reality_auth_ok(peer_kind, aad_mode, fields, &token, &auth_key);
                    return Ok(auth_key);
                }
            }

            // Xray/sing-box: Seal with hello.Raw where session_id[0..16] is plaintext, [16..32] zero.
            for plaintext16 in
                candidate_reality_tokens(&self.config.short_ids, self.config.max_time_diff)
            {
                let Ok(seal_aad) = xray_plaintext_session_id_aad(handshake_body, &plaintext16)
                else {
                    continue;
                };
                if let Some(token) = decrypt_and_validate_reality_token(
                    fields,
                    &auth_key,
                    &seal_aad,
                    &self.config.short_ids,
                    self.config.max_time_diff,
                ) {
                    log_reality_auth_ok(
                        peer_kind,
                        RealityAadMode::PlaintextSession,
                        fields,
                        &token,
                        &auth_key,
                    );
                    return Ok(auth_key);
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

        let mut fallback = tcp_connect(self.config.fallback)
            .await
            .map_err(|e| ProxyError::Transport(format!("fallback connect: {e}")))?;

        // Replay the bytes we consumed before proxying both directions.
        fallback.write_all(&already_read).await?;
        copy_bidirectional_with_idle(&mut stream, &mut fallback, CONNECTION_IDLE_TIMEOUT).await;

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

#[derive(Clone, Copy)]
enum RealityAadMode {
    Zeroed,
    Wire,
    PlaintextSession,
}

impl RealityAadMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Zeroed => "zeroed",
            Self::Wire => "wire",
            Self::PlaintextSession => "plaintext_session",
        }
    }
}

#[derive(Clone, Copy)]
enum RealityPeerKeyKind {
    X25519,
    MlkemTail,
}

impl RealityPeerKeyKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::X25519 => "x25519",
            Self::MlkemTail => "mlkem_tail",
        }
    }
}

/// Standalone X25519 first, ML-KEM768 tail second; fallback to parsed key_share.
fn reality_auth_peer_public_keys_or_fallback(
    fields: &ClientHelloFields,
    handshake_body: &[u8],
) -> Vec<[u8; 32]> {
    let mut peer_keys = reality_auth_peer_public_keys(handshake_body);
    if peer_keys.is_empty() {
        peer_keys.push(fields.x25519_key_share);
    }
    peer_keys
}

fn peer_key_kind(peer_idx: usize) -> RealityPeerKeyKind {
    if peer_idx == 0 {
        RealityPeerKeyKind::X25519
    } else {
        RealityPeerKeyKind::MlkemTail
    }
}

fn derive_reality_auth_key(
    private_key: &StaticSecret,
    peer_pub: &[u8; 32],
    client_random: &[u8; 32],
) -> Result<[u8; 32]> {
    let shared_secret = private_key.diffie_hellman(&PublicKey::from(*peer_pub));
    let hk = Hkdf::<Sha256>::new(Some(&client_random[..20]), shared_secret.as_bytes());
    let mut auth_key = [0u8; 32];
    hk.expand(REALITY_HKDF_INFO, &mut auth_key)
        .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?;
    Ok(auth_key)
}

fn decrypt_and_validate_reality_token(
    fields: &ClientHelloFields,
    auth_key: &[u8; 32],
    aad: &[u8],
    short_ids: &[Vec<u8>],
    max_time_diff: i64,
) -> Option<Vec<u8>> {
    let plaintext = decrypt_reality_session_id(fields, auth_key, aad).ok()?;
    validate_reality_token(&plaintext, short_ids, max_time_diff).ok()?;
    if !reality_auth_roundtrip_matches(fields, auth_key, aad, &plaintext) {
        return None;
    }
    Some(plaintext)
}

fn log_reality_auth_ok(
    peer_kind: RealityPeerKeyKind,
    aad_mode: RealityAadMode,
    fields: &ClientHelloFields,
    token: &[u8],
    auth_key: &[u8; 32],
) {
    let version = if token.len() >= 4 {
        format!(
            "{:02x}{:02x}{:02x}{:02x}",
            token[0], token[1], token[2], token[3]
        )
    } else {
        "????".to_string()
    };
    let short_id_hex = hex::encode(token.get(8..16).unwrap_or(&[]));
    debug!(
        peer_key = peer_kind.as_str(),
        aad = aad_mode.as_str(),
        client_version = %version,
        short_id = %short_id_hex,
        auth_key_prefix = %hex::encode(&auth_key[..4]),
        "REALITY auth succeeded"
    );
    if std::env::var_os("REALITY_DEBUG_HELLO").is_some() {
        debug!(
            sni = %fields.sni,
            random_prefix = %hex::encode(&fields.random[..4]),
            "REALITY_DEBUG_HELLO"
        );
    }
}

/// AAD with session_id zeroed — matches Xray/sing-box Seal input and REALITY Open original.
fn xray_zeroed_session_id_aad(handshake_body: &[u8]) -> Result<Vec<u8>> {
    let sid_start = SESSION_ID_OFFSET_IN_HANDSHAKE_BODY;
    let sid_end = sid_start + 32;
    if handshake_body.len() < sid_end {
        anyhow::bail!("handshake body too short to contain session_id");
    }

    let mut aad = handshake_body.to_vec();
    aad[sid_start..sid_end].fill(0);
    Ok(aad)
}

fn decrypt_reality_session_id(
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

fn reality_auth_roundtrip_matches(
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

fn validate_reality_token(
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

/// AAD with plaintext in session_id[0..16] and zeros in [16..32] — Xray/sing-box Seal layout.
fn xray_plaintext_session_id_aad(handshake_body: &[u8], plaintext16: &[u8]) -> Result<Vec<u8>> {
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

/// Candidate 16-byte session tokens for Xray/sing-box ClientHello sealing.
fn candidate_reality_tokens(short_ids: &[Vec<u8>], max_time_diff: i64) -> Vec<[u8; 16]> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let window = max_time_diff.clamp(1, 600);
    // sing-box: 1.8.1 (+ byte 3 may be non-zero from PutUint64 before version overwrite).
    // Xray 26.3.x uses core.Version bytes in the first three slots.
    const VERSION_PREFIXES: &[[u8; 4]] =
        &[[1, 8, 1, 0], [26, 3, 27, 0], [1, 8, 0, 0], [0, 0, 0, 0]];

    let mut out = Vec::new();
    for short_id in short_ids {
        let mut sid8 = [0u8; 8];
        let copy_len = short_id.len().min(8);
        sid8[..copy_len].copy_from_slice(&short_id[..copy_len]);

        for prefix in VERSION_PREFIXES {
            // sing-box leaves byte 3 from PutUint64; for current Unix times it is 0.
            let b3_end = if prefix[..3] == [1, 8, 1] {
                1u8
            } else {
                prefix[3]
            };
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

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::{Aes256Gcm, Key, Nonce};
    use hkdf::Hkdf;
    use sha2::Sha256;
    use x25519_dalek::{PublicKey, StaticSecret};

    /// Static sing-box Chrome ClientHello fixture (see `testdata/README.md`).
    /// Does not enforce wall-clock freshness; verifies decrypt, auth key, and cert HMAC.
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
        let (cert, _) =
            crate::reality::cert::tls_cert_for_auth_key(&auth_key, "www.microsoft.com", false)
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

        let zeroed = xray_zeroed_session_id_aad(&original).unwrap();
        let seal_aad = xray_plaintext_session_id_aad(&original, &session_plain[..16]).unwrap();

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
