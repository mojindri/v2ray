//! REALITY transport — TLS camouflage using a real server as cover.
//!
//! # What is REALITY?
//!
//! REALITY is a transport layer developed by the Xray project that makes a proxy
//! connection look exactly like a real TLS connection to a legitimate website.
//!
//! The problem it solves: even with VLESS over TLS, a censor can look at the
//! TLS certificate chain and see that your server's certificate was not issued
//! by a trusted CA (or was self-signed). REALITY solves this by:
//!
//!   1. Using a real website (e.g. `www.apple.com`) as the "cover identity".
//!   2. When an authorised client connects, the proxy performs its own key
//!      exchange hidden inside the ClientHello, then hands off to rustls which
//!      completes a real TLS handshake.
//!   3. When an unauthorised probe connects (e.g. a GFW scanner), the server
//!      forwards the connection to the real `www.apple.com`. The prober gets
//!      back a genuine Apple TLS certificate — not our server's certificate.
//!
//! From outside, you cannot tell whether you are talking to our proxy or to Apple.
//!
//! # How the REALITY handshake works
//!
//! ```text
//! Client (proxy)                            Server (proxy)
//!   │                                            │
//!   │  1. Generate ephemeral X25519 key pair.    │
//!   │     Compute shared = ECDH(client_priv,     │
//!   │                           server_pub)       │
//!   │                                            │
//!   │  2. Derive auth_key via HKDF-SHA256:       │
//!   │     salt   = random[0..20]                 │
//!   │     secret = shared                        │
//!   │     info   = b"REALITY"                    │
//!   │     → auth_key[32]                         │
//!   │                                            │
//!   │  3. Encrypt the token into session_id:     │
//!   │     key    = auth_key[0..16]               │
//!   │     nonce  = random[20..32]                │
//!   │     aad    = ClientHello body with         │
//!   │              session_id field zeroed        │
//!   │     plaintext = version(3) ‖ ts(4BE) ‖    │
//!   │                 short_id(8) ‖ zeros(5)     │
//!   │     → session_id = ct(16) ‖ tag(16)        │
//!   │                                            │
//!   │  4. Build Chrome-identical ClientHello     │
//!   │     with computed random + session_id.     │
//!   │     Send raw bytes over TCP.               │
//!   │──── ClientHello ──────────────────────────▶│
//!   │                                            │  5. Parse ClientHello.
//!   │                                            │     Extract client X25519
//!   │                                            │     public key from key_share.
//!   │                                            │
//!   │                                            │  6. ECDH(server_priv, client_pub)
//!   │                                            │     → shared secret.
//!   │                                            │
//!   │                                            │  7. HKDF → auth_key
//!   │                                            │     AES-128-GCM decrypt session_id.
//!   │                                            │     Validate short_id and timestamp.
//!   │                                            │
//!   │◀─── ServerHello (from rustls) ────────────│  8a. Auth OK → rustls handshake.
//!   │  (real TLS 1.3 handshake continues)        │
//!   │                                            │  8b. Auth FAIL → forward to real
//!   │                                            │      dest (e.g. www.apple.com).
//!   │◀─── real Apple ServerHello ───────────────│      Prober gets real cert.
//! ```
//!
//! # The AAD detail (critical for correctness)
//!
//! The AAD for AES-128-GCM is the ClientHello body (the full TLS handshake
//! message, NOT including the 5-byte TLS record header), with the session_id
//! bytes zeroed out.
//!
//! Why zeroed? Because the session_id IS the ciphertext — we cannot include
//! the ciphertext in its own authentication data.
//!
//! The session_id sits at bytes 39..71 of the ClientHello body:
//!   handshake_type  (1)
//!   handshake_len   (3)
//!   legacy_version  (2)
//!   random          (32)
//!   session_id_len  (1)    ← byte 39 from here
//!   session_id      (32)   ← bytes 39..71
//!
//! Total offset: 1+3+2+32+1 = 39.
//!
//! # This module implements:
//!   - `RealityClient::dial()` — client side
//!   - `RealityServer::accept()` — server side
//!   - `parse_client_hello()` — extract fields from a raw ClientHello
//!   - `ClientHelloFields` — parsed fields from a ClientHello

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Key, Nonce};
use anyhow::Result;
use hkdf::Hkdf;
use sha2::Sha256;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, warn};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

use proxy_common::{BoxedStream, PrependedStream, ProxyError};
use proxy_tls::ClientHelloBuilder;

// ── Constants ─────────────────────────────────────────────────────────────────

/// The HKDF info string used to derive the REALITY auth key.
/// This must match exactly between client and server — including the capitalisation.
/// Defined by the Xray project; we replicate it for interoperability.
const REALITY_HKDF_INFO: &[u8] = b"REALITY";

/// The REALITY protocol version byte written into the encrypted token.
/// Must be 0x01 (or higher). 0x00 means "no flow control".
const REALITY_TOKEN_VERSION: u8 = 0x01;

/// Maximum allowed clock skew between client and server (in seconds).
/// If the token's timestamp is more than this many seconds off, reject it.
const MAX_TIME_DIFF_SECS: i64 = 120;

/// Byte offset of the session_id within the ClientHello **handshake body**
/// (i.e. after the 5-byte TLS record header, at offset 0 = handshake_type).
///
/// Layout:
///   handshake_type (1) + handshake_len (3) + legacy_version (2) + random (32)
///   + session_id_len (1) = 39.
const SESSION_ID_OFFSET_IN_HANDSHAKE_BODY: usize = 39;

// ── REALITY client ────────────────────────────────────────────────────────────

/// REALITY client configuration (read from the outbound config).
pub struct RealityClientConfig {
    /// The REALITY server's address.
    pub server: SocketAddr,

    /// The server's long-term X25519 public key (from the server operator).
    /// This is the 32-byte key generated by `proxy-rs x25519` on the server.
    pub server_public_key: [u8; 32],

    /// The short ID assigned to this client (1–8 bytes).
    /// The server validates that the token contains a known short_id.
    pub short_id: Vec<u8>,

    /// The SNI to use in the ClientHello (the cover domain).
    /// Must match what the server expects — usually a major website like
    /// "www.apple.com" or "dl.google.com".
    pub sni: String,

    /// Which Chrome fingerprint profile to use.
    /// "chrome" is the only supported value in Phase 2.
    pub fingerprint: String,
}

/// REALITY client: connects to a REALITY server and returns an authenticated stream.
pub struct RealityClient {
    config: RealityClientConfig,
}

impl RealityClient {
    pub fn new(config: RealityClientConfig) -> Self {
        Self { config }
    }

    /// Connect to the REALITY server and perform the REALITY handshake.
    ///
    /// On success, returns a stream that has completed the REALITY + TLS handshake.
    /// The stream is then ready for VLESS (or any other protocol) payload.
    pub async fn dial(&self) -> Result<BoxedStream, ProxyError> {
        // ── All crypto is done synchronously before any .await ───────────────
        //
        // `rand::thread_rng()` is not `Send` (it uses a thread-local `Rc`), so
        // it must not be held across an `.await` point. We do all the random and
        // crypto work here and capture only the final `Vec<u8>` (which IS Send)
        // to send over the network.
        let final_hello = self.build_client_hello()
            .map_err(|e| ProxyError::Protocol(e.to_string()))?;

        debug!(server = %self.config.server, sni = %self.config.sni, "REALITY dial");

        // ── Async TCP work ───────────────────────────────────────────────────
        let mut tcp = TcpStream::connect(self.config.server).await?;
        tcp.set_nodelay(true)?;

        // Send the ClientHello.
        tcp.write_all(&final_hello).await?;

        debug!(server = %self.config.server, "REALITY ClientHello sent");

        // Hand off to rustls for the actual TLS handshake.
        // The server will respond with a real ServerHello because it authenticated
        // our token and knows we are a legitimate client.
        //
        // Note: In a full implementation, we would complete the TLS handshake here
        // using tokio-rustls. For Phase 2 scaffold, we return the raw stream.
        // The REALITY-over-TLS completion is wired in instance.rs.
        Ok(Box::new(tcp))
    }

    /// Build the REALITY ClientHello bytes synchronously (no async).
    ///
    /// Separated from `dial()` so that non-`Send` types (`ThreadRng`) are never
    /// held across an `.await` point.
    fn build_client_hello(&self) -> Result<Vec<u8>> {
        use rand::RngCore as _;

        // Step 1: Generate an ephemeral X25519 key pair for this connection.
        // This key pair has TWO roles:
        //   (a) ECDH with the server's long-term key → derive auth_key for AES-GCM
        //   (b) Advertised in the ClientHello key_share extension so the server knows
        //       which key we used for ECDH
        let mut rng = rand::thread_rng();
        let client_secret = EphemeralSecret::random_from_rng(&mut rng);
        let client_public = PublicKey::from(&client_secret);
        let client_pub_bytes = *client_public.as_bytes();

        // Step 2: ECDH with the server's long-term public key.
        let server_pub_key = PublicKey::from(self.config.server_public_key);
        let shared_secret = client_secret.diffie_hellman(&server_pub_key);

        // Step 3: Generate 32 random bytes for the `random` field.
        // Bytes [0..20] become the HKDF salt; bytes [20..32] become the AES nonce.
        let mut random = [0u8; 32];
        rng.fill_bytes(&mut random);

        // Step 4: HKDF-SHA256 to derive auth_key.
        let salt = &random[..20];
        let hk = Hkdf::<Sha256>::new(Some(salt), shared_secret.as_bytes());
        let mut auth_key = [0u8; 32];
        hk.expand(REALITY_HKDF_INFO, &mut auth_key)
            .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?;

        // Step 5: Build the ClientHello body (without the session_id yet).
        // We need to build it first so we can compute the AAD (which is the
        // ClientHello body with session_id zeroed).
        let builder = ClientHelloBuilder::chrome_131();

        // Placeholder session_id — all zeros — for the initial build.
        // We will replace it after encryption.
        let zero_session_id = [0u8; 32];
        let hello_bytes = builder.build(
            &self.config.sni, &random, &zero_session_id,
            Some(&client_pub_bytes), &mut rng,
        );

        // Step 6: Extract the handshake body (bytes after the 5-byte TLS record header).
        // This is the AAD for AES-128-GCM.
        let handshake_body = &hello_bytes[5..]; // skip the 5-byte record header

        // The session_id sits at offset 39..71 in the handshake body.
        // For the AAD these bytes must be zero — and they already are because
        // we built with zero_session_id. So `handshake_body` IS the AAD.
        let aad = handshake_body;

        // Step 7: Encrypt the REALITY token into the session_id.
        // Xray token plaintext layout (16 bytes):
        //   version(1) | reserved(1) | ts(4 BE) | short_id(8, zero-padded) | zeros(2)
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;

        let mut plaintext = [0u8; 16];
        plaintext[0] = REALITY_TOKEN_VERSION;
        // plaintext[1] = reserved = 0
        plaintext[2..6].copy_from_slice(&ts.to_be_bytes());

        // short_id: copy up to 8 bytes, zero-pad the rest.
        let sid_len = self.config.short_id.len().min(8);
        plaintext[6..6 + sid_len].copy_from_slice(&self.config.short_id[..sid_len]);
        // [14..16] remain zero

        let key = Key::<Aes128Gcm>::from_slice(&auth_key[..16]);
        let cipher = Aes128Gcm::new(key);

        // Nonce = random[20..32] (12 bytes).
        let nonce_bytes = &random[20..32];
        let nonce = Nonce::from_slice(nonce_bytes);

        // Encrypt. AES-128-GCM produces ciphertext of the same length as
        // plaintext (16 bytes) plus a 16-byte authentication tag = 32 bytes total.
        // This fills exactly one session_id field.
        let ciphertext_with_tag = cipher.encrypt(nonce, Payload { msg: &plaintext, aad })
            .map_err(|_| anyhow::anyhow!("REALITY token encryption failed"))?;

        debug_assert_eq!(ciphertext_with_tag.len(), 32,
            "AES-128-GCM output for 16-byte plaintext must be 32 bytes");

        // Step 8: Patch the session_id in the already-built ClientHello bytes.
        //
        // We do NOT rebuild the ClientHello because rebuilding would call grease_u16()
        // again, producing different GREASE values — the server would then compute
        // a different AAD and the decryption would fail.
        //
        // Instead we write the ciphertext directly into the session_id slot.
        // The session_id is at byte offset 44 from the start of the record:
        //   TLS record header (5) + SESSION_ID_OFFSET_IN_HANDSHAKE_BODY (39) = 44.
        // (SESSION_ID_OFFSET_IN_HANDSHAKE_BODY already accounts for the session_id_len byte.)
        let mut final_hello = hello_bytes;
        // SESSION_ID_OFFSET_IN_HANDSHAKE_BODY = 39 already points to the first byte
        // of session_id (past the session_id_len byte at offset 38).
        // In final_hello: 5-byte TLS record header + 39-byte offset = byte 44.
        let sid_start = 5 + SESSION_ID_OFFSET_IN_HANDSHAKE_BODY;
        final_hello[sid_start..sid_start + 32].copy_from_slice(&ciphertext_with_tag);

        Ok(final_hello.to_vec())
    }
}

// ── REALITY server ────────────────────────────────────────────────────────────

/// REALITY server configuration (read from the inbound config).
pub struct RealityServerConfig {
    /// The server's long-term X25519 private key.
    /// Generated with `proxy-rs x25519`. Must be kept secret.
    pub private_key: [u8; 32],

    /// Valid short IDs for this server. A client must present one of these in
    /// its REALITY token. Acts as an extra layer of authentication on top of
    /// the X25519 ECDH.
    pub short_ids: Vec<Vec<u8>>,

    /// Where to forward connections that fail REALITY authentication.
    /// This is the address of a real HTTPS website (e.g. `www.apple.com:443`).
    /// The prober connects and gets back a real TLS handshake + real certificate.
    pub fallback: SocketAddr,

    /// Maximum allowed clock skew in seconds. Default: 120.
    pub max_time_diff: i64,
}

/// REALITY server: authenticates incoming connections and either accepts them
/// as proxy connections or forwards them to the fallback backend.
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

    /// Accept an incoming connection and authenticate it as REALITY.
    ///
    /// Returns:
    ///   - `Ok(stream)` if authentication succeeded. The stream is a `PrependedStream`
    ///     that replays the already-read bytes so rustls sees the complete ClientHello.
    ///   - `Err(ProxyError::FallbackRequired)` after silently forwarding the connection
    ///     to the fallback (the caller should not send any error response to the client).
    pub async fn accept(&self, mut stream: BoxedStream) -> Result<BoxedStream, ProxyError> {
        // Read the 5-byte TLS record header to determine record length.
        let mut record_header = [0u8; 5];
        stream.read_exact(&mut record_header).await?;

        // Validate that this looks like a TLS ClientHello:
        //   record_header[0] = 0x16 (content_type = handshake)
        //   record_header[1..3] = legacy_version (should be 0x03, 0x01)
        if record_header[0] != 0x16 {
            debug!("not a TLS record (byte[0]={:#04x}) — forwarding to fallback", record_header[0]);
            return self.do_fallback(stream, record_header.to_vec()).await;
        }

        let record_len = u16::from_be_bytes([record_header[3], record_header[4]]) as usize;
        if record_len > 16384 {
            // TLS records are limited to 16 KiB by spec. Anything larger is suspect.
            debug!("oversized record ({record_len} bytes) — forwarding to fallback");
            return self.do_fallback(stream, record_header.to_vec()).await;
        }

        // Read the ClientHello body.
        let mut handshake_body = vec![0u8; record_len];
        stream.read_exact(&mut handshake_body).await?;

        // Parse the ClientHello fields.
        let fields = match parse_client_hello(&handshake_body) {
            Ok(f) => f,
            Err(e) => {
                debug!(error = %e, "ClientHello parse failed — forwarding to fallback");
                let mut all_bytes = record_header.to_vec();
                all_bytes.extend_from_slice(&handshake_body);
                return self.do_fallback(stream, all_bytes).await;
            }
        };

        // Attempt REALITY authentication.
        match self.authenticate(&fields, &handshake_body) {
            Ok(()) => {
                debug!("REALITY authentication succeeded");
                // Prepend the already-read bytes so rustls sees the full ClientHello.
                let mut replay = record_header.to_vec();
                replay.extend_from_slice(&handshake_body);
                Ok(Box::new(PrependedStream::new(stream, replay)))
            }
            Err(e) => {
                debug!(error = %e, "REALITY authentication failed — forwarding to fallback");
                let mut all_bytes = record_header.to_vec();
                all_bytes.extend_from_slice(&handshake_body);
                self.do_fallback(stream, all_bytes).await
            }
        }
    }

    /// Accept a connection and perform REALITY authentication.
    ///
    /// Unlike `accept()`, this does NOT prepend the ClientHello bytes to the return stream.
    /// After authentication, returns the raw stream positioned at the byte AFTER the
    /// ClientHello. This is used in Phase 2 (without TLS) so the VLESS layer can
    /// read its header immediately from the stream.
    ///
    /// In a production deployment with TLS, use `accept()` instead — it replays
    /// the ClientHello so rustls can complete a real TLS 1.3 handshake.
    pub async fn accept_direct(&self, mut stream: BoxedStream) -> Result<BoxedStream, ProxyError> {
        // Read the 5-byte TLS record header to determine record length.
        let mut record_header = [0u8; 5];
        stream.read_exact(&mut record_header).await?;

        if record_header[0] != 0x16 {
            debug!("not a TLS record (byte[0]={:#04x}) — forwarding to fallback", record_header[0]);
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
                let mut all_bytes = record_header.to_vec();
                all_bytes.extend_from_slice(&handshake_body);
                return self.do_fallback(stream, all_bytes).await;
            }
        };

        match self.authenticate(&fields, &handshake_body) {
            Ok(()) => {
                debug!("REALITY authentication succeeded (direct mode — no ClientHello replay)");
                // Return the raw stream. The ClientHello bytes have been consumed.
                // The next byte the caller reads will be the first byte AFTER the ClientHello
                // (which in a VLESS-over-REALITY connection is the VLESS header).
                Ok(stream)
            }
            Err(e) => {
                debug!(error = %e, "REALITY authentication failed — forwarding to fallback");
                let mut all_bytes = record_header.to_vec();
                all_bytes.extend_from_slice(&handshake_body);
                self.do_fallback(stream, all_bytes).await
            }
        }
    }

    /// Verify the REALITY token in the ClientHello's session_id.
    fn authenticate(&self, fields: &ClientHelloFields, handshake_body: &[u8]) -> Result<()> {
        // Step 1: ECDH with the client's ephemeral public key.
        let client_pub = PublicKey::from(fields.x25519_key_share);
        let shared_secret = self.private_key.diffie_hellman(&client_pub);

        // Step 2: HKDF-SHA256 to derive auth_key.
        let salt = &fields.random[..20];
        let hk = Hkdf::<Sha256>::new(Some(salt), shared_secret.as_bytes());
        let mut auth_key = [0u8; 32];
        hk.expand(REALITY_HKDF_INFO, &mut auth_key)
            .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?;

        // Step 3: Build the AAD — the handshake body with session_id bytes zeroed.
        // The session_id is at bytes SESSION_ID_OFFSET..SESSION_ID_OFFSET+32.
        let mut aad = handshake_body.to_vec();
        if aad.len() < SESSION_ID_OFFSET_IN_HANDSHAKE_BODY + 32 {
            anyhow::bail!("handshake body too short to contain session_id");
        }
        // Zero out the session_id bytes in the AAD copy.
        for b in &mut aad[SESSION_ID_OFFSET_IN_HANDSHAKE_BODY..SESSION_ID_OFFSET_IN_HANDSHAKE_BODY + 32] {
            *b = 0;
        }

        // Step 4: AES-128-GCM decrypt the session_id.
        let key    = Key::<Aes128Gcm>::from_slice(&auth_key[..16]);
        let cipher = Aes128Gcm::new(key);
        let nonce  = Nonce::from_slice(&fields.random[20..32]);

        // session_id = ciphertext(16) ‖ tag(16).
        let plaintext = cipher
            .decrypt(nonce, Payload { msg: &fields.session_id, aad: &aad })
            .map_err(|_| anyhow::anyhow!("AES-128-GCM decryption failed (bad client?)"))?;

        if plaintext.len() < 16 {
            anyhow::bail!("decrypted token too short: {} bytes", plaintext.len());
        }

        // Step 5: Validate the decrypted token.
        // plaintext layout: version(1) | reserved(1) | ts(4 BE) | short_id(8) | zeros(2)

        let _version = plaintext[0];
        let ts = u32::from_be_bytes([
            plaintext[2], plaintext[3], plaintext[4], plaintext[5],
        ]) as i64;
        let short_id = &plaintext[6..14]; // 8 bytes, may be zero-padded

        // Validate timestamp (clock skew check).
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let diff = (now - ts).abs();
        if diff > self.config.max_time_diff {
            anyhow::bail!("timestamp skew too large: {diff}s (max {}s)", self.config.max_time_diff);
        }

        // Validate short_id: the client's short_id must be in our allowed list.
        // short_id in the token is zero-padded to 8 bytes — strip trailing zeros.
        let effective_short_id = {
            let last_nonzero = short_id.iter().rposition(|&b| b != 0)
                .map(|i| i + 1)
                .unwrap_or(0);
            &short_id[..last_nonzero]
        };

        let valid = self.config.short_ids.iter()
            .any(|allowed| allowed.as_slice() == effective_short_id);
        if !valid {
            anyhow::bail!("short_id not in allowed list");
        }

        Ok(())
    }

    /// Forward the connection to the fallback backend, replaying already-read bytes.
    ///
    /// The prober connects and gets back a genuine TLS handshake from the real
    /// destination. We never close the connection abruptly.
    async fn do_fallback(&self, mut stream: BoxedStream, already_read: Vec<u8>) -> Result<BoxedStream, ProxyError> {
        warn!(fallback = %self.config.fallback, "forwarding to fallback");

        let mut fallback = TcpStream::connect(self.config.fallback).await
            .map_err(|e| ProxyError::Transport(format!("fallback connect: {e}")))?;

        // First replay the bytes we already read.
        fallback.write_all(&already_read).await?;

        // Then relay bidirectionally.
        tokio::io::copy_bidirectional(&mut stream, &mut fallback)
            .await
            .ok();

        // Return an error so the caller knows this connection is done
        // (we handled it ourselves via the fallback path).
        Err(ProxyError::FallbackRequired)
    }
}

// ── ClientHello parser ────────────────────────────────────────────────────────

/// Parsed fields from a TLS ClientHello.
///
/// We only extract the fields we need for REALITY authentication.
/// The full ClientHello is preserved as raw bytes for the AAD computation.
pub struct ClientHelloFields {
    /// The 32-byte `random` field. Used as HKDF salt (bytes 0..20) and
    /// AES nonce (bytes 20..32).
    pub random: [u8; 32],

    /// The 32-byte `session_id` field. In REALITY, this contains the
    /// AES-128-GCM encrypted token: 16 bytes ciphertext + 16 bytes tag.
    pub session_id: [u8; 32],

    /// The client's X25519 public key from the `key_share` extension.
    /// Used for the ECDH computation.
    pub x25519_key_share: [u8; 32],

    /// The SNI hostname from the `server_name` extension.
    pub sni: String,
}

/// Parse a TLS ClientHello from its **handshake body** (after the 5-byte record header).
///
/// Returns an error if the bytes don't look like a valid ClientHello, or if
/// the required fields (random, session_id, x25519 key_share) are missing.
pub fn parse_client_hello(body: &[u8]) -> Result<ClientHelloFields> {
    // Minimum length check.
    // The ClientHello body must have at least:
    //   handshake_type(1) + length(3) + legacy_version(2) + random(32)
    //   + session_id_len(1) + session_id(32) = 71 bytes.
    anyhow::ensure!(body.len() >= 71, "ClientHello body too short: {} bytes", body.len());

    // handshake_type must be 0x01 (ClientHello).
    anyhow::ensure!(body[0] == 0x01,
        "expected ClientHello (0x01), got {:#04x}", body[0]);

    // Skip: handshake_type(1) + length(3) + legacy_version(2) = 6 bytes.
    let mut pos = 6;

    // Extract the 32-byte random field.
    let random: [u8; 32] = body[pos..pos + 32].try_into().unwrap();
    pos += 32;

    // Session ID length (must be 32 for TLS 1.3 / REALITY).
    let sid_len = body[pos] as usize;
    pos += 1;
    anyhow::ensure!(sid_len == 32,
        "session_id_len must be 32, got {sid_len}");

    let session_id: [u8; 32] = body[pos..pos + 32].try_into().unwrap();
    pos += 32;

    // Skip cipher suites.
    anyhow::ensure!(pos + 2 <= body.len(), "truncated at cipher_suites_len");
    let cs_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2 + cs_len;

    // Skip compression methods.
    anyhow::ensure!(pos + 1 <= body.len(), "truncated at compression_methods_len");
    let comp_len = body[pos] as usize;
    pos += 1 + comp_len;

    // Parse extensions.
    anyhow::ensure!(pos + 2 <= body.len(), "truncated at extensions_len");
    let _ext_total_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;

    let mut x25519_key_share: Option<[u8; 32]> = None;
    let mut sni = String::new();

    while pos + 4 <= body.len() {
        let ext_type = u16::from_be_bytes([body[pos], body[pos + 1]]);
        let ext_len  = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
        pos += 4;

        anyhow::ensure!(pos + ext_len <= body.len(), "truncated extension data");
        let ext_data = &body[pos..pos + ext_len];
        pos += ext_len;

        match ext_type {
            0x0000 => {
                // server_name extension.
                // Body: list_len(2) + name_type(1) + name_len(2) + name_bytes
                if ext_data.len() >= 5 {
                    let name_len = u16::from_be_bytes([ext_data[3], ext_data[4]]) as usize;
                    if ext_data.len() >= 5 + name_len {
                        sni = String::from_utf8_lossy(&ext_data[5..5 + name_len]).into_owned();
                    }
                }
            }
            0x0033 => {
                // key_share extension.
                // Body: client_shares_len(2) + [group(2) + key_len(2) + key_bytes]*
                if ext_data.len() < 2 { continue; }
                let shares_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
                let mut sp = 2;
                while sp + 4 <= 2 + shares_len && sp + 4 <= ext_data.len() {
                    let group   = u16::from_be_bytes([ext_data[sp], ext_data[sp + 1]]);
                    let key_len = u16::from_be_bytes([ext_data[sp + 2], ext_data[sp + 3]]) as usize;
                    sp += 4;
                    if sp + key_len > ext_data.len() { break; }

                    // x25519 is group 29, with a 32-byte key.
                    if group == 29 && key_len == 32 {
                        let mut key = [0u8; 32];
                        key.copy_from_slice(&ext_data[sp..sp + 32]);
                        x25519_key_share = Some(key);
                    }
                    sp += key_len;
                }
            }
            _ => {} // Skip unknown extensions.
        }
    }

    let x25519_key_share = x25519_key_share
        .ok_or_else(|| anyhow::anyhow!("no x25519 key share found in ClientHello"))?;

    Ok(ClientHelloFields {
        random,
        session_id,
        x25519_key_share,
        sni,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proxy_tls::ClientHelloBuilder;

    // Build a ClientHello with the builder, then parse it with our parser.
    // This verifies that parse_client_hello correctly extracts the fields
    // we put in.
    #[test]
    fn parse_builder_output() {
        let random     = [0x11u8; 32];
        let session_id = [0x22u8; 32];
        let mut rng    = rand::thread_rng();

        let hello = ClientHelloBuilder::chrome_131()
            .build("www.example.com", &random, &session_id, None, &mut rng);

        // The builder output includes the 5-byte TLS record header.
        // parse_client_hello takes the handshake body (after that header).
        let handshake_body = &hello[5..];
        let fields = parse_client_hello(handshake_body)
            .expect("parse_client_hello failed on builder output");

        assert_eq!(fields.random,     random,     "random field mismatch");
        assert_eq!(fields.session_id, session_id, "session_id field mismatch");
        assert_eq!(fields.sni, "www.example.com",  "SNI field mismatch");
        // x25519 key share will be present (builder always adds one).
        // We can't predict its value since rng is random, but it must be 32 bytes.
    }

    // Checks that a too-short input returns an error rather than panicking.
    #[test]
    fn parse_truncated_input_returns_error() {
        assert!(parse_client_hello(&[]).is_err());
        assert!(parse_client_hello(&[0x01, 0x00, 0x00, 0x10]).is_err());
    }

    // Checks that a non-ClientHello handshake type returns an error.
    #[test]
    fn parse_wrong_handshake_type_returns_error() {
        let mut body = vec![0x02u8]; // 0x02 = ServerHello, not ClientHello
        body.extend(vec![0u8; 80]);  // pad to minimum length
        assert!(parse_client_hello(&body).is_err());
    }
}
