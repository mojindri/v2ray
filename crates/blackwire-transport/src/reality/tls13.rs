//! TLS 1.3 handshake completion for REALITY Phase 3.
//!
//! After sending the REALITY-authenticated ClientHello, this module:
//!   1. Reads ServerHello and extracts the server's x25519 key_share.
//!   2. Derives handshake traffic secrets via the TLS 1.3 HKDF key schedule.
//!   3. Decrypts EncryptedExtensions, Certificate, CertificateVerify, Finished.
//!   4. Verifies the server Finished HMAC.
//!   5. Sends client ChangeCipherSpec (legacy) + client Finished.
//!   6. Derives application traffic secrets.
//!   7. Returns a [`Tls13Stream`] that AEAD-encrypts/decrypts application data.
//!
//! Supported cipher suites:
//!   - `TLS_AES_128_GCM_SHA256`   (0x1301)
//!   - `TLS_AES_256_GCM_SHA384`   (0x1302)
//!
//! Reference: RFC 8446 (TLS 1.3).

use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce};
use hkdf::Hkdf;
use hmac::Mac;
// `hmac::KeyInit as _` brings new_from_slice into scope for Hmac<H>
// without creating a name that would conflict with aes_gcm::aead::KeyInit.
use hmac::{Hmac, KeyInit as _};
use p256::ecdh::EphemeralSecret as P256EphemeralSecret;
use p256::PublicKey as P256PublicKey;
use pin_project_lite::pin_project;
use sha2::{Digest, Sha256, Sha384};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tracing::debug;
use x25519_dalek::{PublicKey, StaticSecret};

use blackwire_common::{BoxedStream, ProxyError};

// ── TLS record types ─────────────────────────────────────────────────────────

const RT_CHANGE_CIPHER_SPEC: u8 = 0x14;
const RT_ALERT: u8 = 0x15;
const RT_HANDSHAKE: u8 = 0x16;
const RT_APPLICATION_DATA: u8 = 0x17;

// ── TLS handshake message types ───────────────────────────────────────────────

const HS_CLIENT_HELLO: u8 = 0x01;
const HS_SERVER_HELLO: u8 = 0x02;
const HS_ENCRYPTED_EXTENSIONS: u8 = 0x08;
const HS_CERTIFICATE: u8 = 0x0b;
const HS_CERTIFICATE_VERIFY: u8 = 0x0f;
const HS_FINISHED: u8 = 0x14;
const HELLO_RETRY_REQUEST_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

// ── Cipher suite ──────────────────────────────────────────────────────────────

/// TLS 1.3 cipher suites that we support.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CipherSuite {
    /// TLS_AES_128_GCM_SHA256 (0x1301)
    Aes128GcmSha256,
    /// TLS_AES_256_GCM_SHA384 (0x1302)
    Aes256GcmSha384,
}

impl CipherSuite {
    pub(crate) fn from_u16(v: u16) -> Result<Self, ProxyError> {
        match v {
            0x1301 => Ok(Self::Aes128GcmSha256),
            0x1302 => Ok(Self::Aes256GcmSha384),
            other => Err(ProxyError::Protocol(format!(
                "unsupported TLS 1.3 cipher suite 0x{other:04x}"
            ))),
        }
    }

    pub(super) fn to_u16(self) -> u16 {
        match self {
            Self::Aes128GcmSha256 => 0x1301,
            Self::Aes256GcmSha384 => 0x1302,
        }
    }

    /// Length of the hash output used by this suite.
    fn hash_len(self) -> usize {
        match self {
            Self::Aes128GcmSha256 => 32,
            Self::Aes256GcmSha384 => 48,
        }
    }

    /// Length of the AEAD key for this suite.
    fn key_len(self) -> usize {
        match self {
            Self::Aes128GcmSha256 => 16,
            Self::Aes256GcmSha384 => 32,
        }
    }

    /// HKDF-Extract: returns raw PRK bytes.
    fn hkdf_extract(self, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
        match self {
            Self::Aes128GcmSha256 => {
                let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), ikm);
                prk.to_vec()
            }
            Self::Aes256GcmSha384 => {
                let (prk, _) = Hkdf::<Sha384>::extract(Some(salt), ikm);
                prk.to_vec()
            }
        }
    }

    /// HKDF-Expand-Label as defined in RFC 8446 §7.1.
    fn expand_label(
        self,
        prk: &[u8],
        label: &str,
        context: &[u8],
        len: usize,
    ) -> Result<Vec<u8>, ProxyError> {
        let full_label = format!("tls13 {label}");
        // HkdfLabel = uint16(len) || uint8(label_len) || label || uint8(ctx_len) || ctx
        let mut info = Vec::with_capacity(2 + 1 + full_label.len() + 1 + context.len());
        info.extend_from_slice(&(len as u16).to_be_bytes());
        info.push(full_label.len() as u8);
        info.extend_from_slice(full_label.as_bytes());
        info.push(context.len() as u8);
        info.extend_from_slice(context);

        let mut okm = vec![0u8; len];
        match self {
            Self::Aes128GcmSha256 => {
                let hkdf = Hkdf::<Sha256>::from_prk(prk).map_err(|_| {
                    ProxyError::Tls("TLS 1.3 HKDF-Expand: invalid SHA-256 PRK".into())
                })?;
                hkdf.expand(&info, &mut okm).map_err(|_| {
                    ProxyError::Tls("TLS 1.3 HKDF-Expand: SHA-256 output length".into())
                })?;
            }
            Self::Aes256GcmSha384 => {
                let hkdf = Hkdf::<Sha384>::from_prk(prk).map_err(|_| {
                    ProxyError::Tls("TLS 1.3 HKDF-Expand: invalid SHA-384 PRK".into())
                })?;
                hkdf.expand(&info, &mut okm).map_err(|_| {
                    ProxyError::Tls("TLS 1.3 HKDF-Expand: SHA-384 output length".into())
                })?;
            }
        }
        Ok(okm)
    }

    /// Derive-Secret(secret, label, messages) = Expand-Label(secret, label, Hash(messages), H)
    fn derive_secret(
        self,
        prk: &[u8],
        label: &str,
        transcript_hash: &[u8],
    ) -> Result<Vec<u8>, ProxyError> {
        self.expand_label(prk, label, transcript_hash, self.hash_len())
    }

    /// Hash(data) with the suite's hash function.
    pub(super) fn hash(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Aes128GcmSha256 => Sha256::digest(data).to_vec(),
            Self::Aes256GcmSha384 => Sha384::digest(data).to_vec(),
        }
    }

    /// HMAC(key, data) with the suite's hash function.
    pub(super) fn hmac(self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, ProxyError> {
        match self {
            Self::Aes128GcmSha256 => {
                let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| {
                    ProxyError::Tls("TLS 1.3 HMAC: invalid SHA-256 key length".into())
                })?;
                mac.update(data);
                Ok(mac.finalize().into_bytes().to_vec())
            }
            Self::Aes256GcmSha384 => {
                let mut mac = Hmac::<Sha384>::new_from_slice(key).map_err(|_| {
                    ProxyError::Tls("TLS 1.3 HMAC: invalid SHA-384 key length".into())
                })?;
                mac.update(data);
                Ok(mac.finalize().into_bytes().to_vec())
            }
        }
    }
}

// ── Key material ─────────────────────────────────────────────────────────────

/// Handshake-phase traffic keys (client and server).
pub(super) struct HsKeys {
    client_key: Vec<u8>,
    client_iv: [u8; 12],
    client_finished_key: Vec<u8>,
    server_key: Vec<u8>,
    server_iv: [u8; 12],
    server_finished_key: Vec<u8>,
    /// Master secret, needed to derive application traffic secrets.
    master_secret: Vec<u8>,
}

/// Application-phase traffic keys.
pub struct AppKeys {
    pub(crate) cs: CipherSuite,
    pub(crate) client_key: Vec<u8>,
    pub(crate) client_iv: [u8; 12],
    pub(crate) server_key: Vec<u8>,
    pub(crate) server_iv: [u8; 12],
}

// ── HKDF key schedule ────────────────────────────────────────────────────────

/// Run the TLS 1.3 handshake key schedule (RFC 8446 §7.1).
///
/// `dhe` is the x25519 shared secret from the TLS key_share exchange.
/// `transcript_hash` is Hash(ClientHello || ServerHello).
pub(super) fn derive_handshake_keys(
    cs: CipherSuite,
    dhe: &[u8; 32],
    transcript_hash: &[u8],
) -> Result<HsKeys, ProxyError> {
    let hash_len = cs.hash_len();
    let zero = vec![0u8; hash_len];

    // early_secret = HKDF-Extract(salt=0, IKM=0)
    let early_secret = cs.hkdf_extract(&zero, &zero);

    // derived = Derive-Secret(early_secret, "derived", "")
    let empty_hash = cs.hash(b"");
    let derived = cs.derive_secret(&early_secret, "derived", &empty_hash)?;

    // handshake_secret = HKDF-Extract(salt=derived, IKM=DHE)
    let hs_secret = cs.hkdf_extract(&derived, dhe);

    // {client,server}_handshake_traffic_secret
    let c_hs_traffic = cs.derive_secret(&hs_secret, "c hs traffic", transcript_hash)?;
    let s_hs_traffic = cs.derive_secret(&hs_secret, "s hs traffic", transcript_hash)?;

    // master_secret = HKDF-Extract(salt=Derive-Secret(hs, "derived", ""), IKM=0)
    let derived2 = cs.derive_secret(&hs_secret, "derived", &empty_hash)?;
    let master_secret = cs.hkdf_extract(&derived2, &zero);

    // Derive write keys + IVs
    let key_len = cs.key_len();
    let c_key = cs.expand_label(&c_hs_traffic, "key", b"", key_len)?;
    let c_iv = iv_from_label(cs, &c_hs_traffic)?;
    let s_key = cs.expand_label(&s_hs_traffic, "key", b"", key_len)?;
    let s_iv = iv_from_label(cs, &s_hs_traffic)?;

    // Finished keys
    let c_fin = cs.expand_label(&c_hs_traffic, "finished", b"", hash_len)?;
    let s_fin = cs.expand_label(&s_hs_traffic, "finished", b"", hash_len)?;

    Ok(HsKeys {
        client_key: c_key,
        client_iv: c_iv,
        client_finished_key: c_fin,
        server_key: s_key,
        server_iv: s_iv,
        server_finished_key: s_fin,
        master_secret,
    })
}

/// Derive application traffic keys from the master secret.
pub(super) fn derive_app_keys(
    cs: CipherSuite,
    master_secret: &[u8],
    transcript_hash: &[u8], // Hash(CH..server Finished)
) -> Result<AppKeys, ProxyError> {
    let key_len = cs.key_len();

    let c_app = cs.derive_secret(master_secret, "c ap traffic", transcript_hash)?;
    let s_app = cs.derive_secret(master_secret, "s ap traffic", transcript_hash)?;

    let c_key = cs.expand_label(&c_app, "key", b"", key_len)?;
    let c_iv = iv_from_label(cs, &c_app)?;
    let s_key = cs.expand_label(&s_app, "key", b"", key_len)?;
    let s_iv = iv_from_label(cs, &s_app)?;

    Ok(AppKeys {
        cs,
        client_key: c_key,
        client_iv: c_iv,
        server_key: s_key,
        server_iv: s_iv,
    })
}

fn iv_from_label(cs: CipherSuite, traffic_secret: &[u8]) -> Result<[u8; 12], ProxyError> {
    let raw = cs.expand_label(traffic_secret, "iv", b"", 12)?;
    raw.try_into()
        .map_err(|_| ProxyError::Tls("TLS 1.3 IV derivation length mismatch".into()))
}

// ── AEAD ──────────────────────────────────────────────────────────────────────

/// Compute the AEAD nonce: IV XOR (seq padded to 12 bytes big-endian, §5.3).
fn compute_nonce(iv: &[u8; 12], seq: u64) -> [u8; 12] {
    let mut nonce = *iv;
    let seq_bytes = seq.to_be_bytes();
    // seq is 8 bytes; XOR into the last 8 bytes of the 12-byte IV.
    for i in 0..8 {
        nonce[4 + i] ^= seq_bytes[i];
    }
    nonce
}

/// Decrypt a TLS 1.3 application-data record body.
///
/// `header` is the 5-byte TLS record header (used as AAD).
/// Returns `(inner_plaintext, inner_content_type)`.
pub(super) fn decrypt_app_record(
    cs: CipherSuite,
    key: &[u8],
    iv: &[u8; 12],
    seq: u64,
    ciphertext: &[u8],
    header: [u8; 5],
) -> Result<(Vec<u8>, u8), ProxyError> {
    let nonce = compute_nonce(iv, seq);
    let nonce_ga = Nonce::from_slice(&nonce);

    let plaintext = match cs {
        CipherSuite::Aes128GcmSha256 => {
            let cipher = Aes128Gcm::new_from_slice(key)
                .map_err(|_| ProxyError::Protocol("bad AES-128-GCM key len".into()))?;
            cipher
                .decrypt(
                    nonce_ga,
                    Payload {
                        msg: ciphertext,
                        aad: &header,
                    },
                )
                .map_err(|_| ProxyError::Protocol("AES-128-GCM decrypt failed".into()))?
        }
        CipherSuite::Aes256GcmSha384 => {
            let cipher = Aes256Gcm::new_from_slice(key)
                .map_err(|_| ProxyError::Protocol("bad AES-256-GCM key len".into()))?;
            cipher
                .decrypt(
                    nonce_ga,
                    Payload {
                        msg: ciphertext,
                        aad: &header,
                    },
                )
                .map_err(|_| ProxyError::Protocol("AES-256-GCM decrypt failed".into()))?
        }
    };

    if plaintext.is_empty() {
        return Err(ProxyError::Protocol(
            "decrypted TLS record is empty (no content-type byte)".into(),
        ));
    }

    let inner_type = plaintext[plaintext.len() - 1];
    let inner = plaintext[..plaintext.len() - 1].to_vec();
    Ok((inner, inner_type))
}

/// Encrypt a TLS 1.3 application-data record.
///
/// `inner_type` is the inner content type (0x16 = handshake, 0x17 = app data).
/// Returns the full 5-byte-header + ciphertext record.
pub(super) fn encrypt_app_record(
    cs: CipherSuite,
    key: &[u8],
    iv: &[u8; 12],
    seq: u64,
    inner_plaintext: &[u8],
    inner_type: u8,
) -> Result<Vec<u8>, ProxyError> {
    let mut msg = inner_plaintext.to_vec();
    msg.push(inner_type); // TLS 1.3 inner content type

    let tag_len = 16; // AES-GCM tag
    let ct_len = msg.len() + tag_len;

    // AAD = 5-byte record header with the ciphertext length
    let header: [u8; 5] = [
        RT_APPLICATION_DATA,
        0x03,
        0x03,
        (ct_len >> 8) as u8,
        ct_len as u8,
    ];

    let nonce = compute_nonce(iv, seq);
    let nonce_ga = Nonce::from_slice(&nonce);

    let ciphertext = match cs {
        CipherSuite::Aes128GcmSha256 => {
            let cipher = Aes128Gcm::new_from_slice(key)
                .map_err(|_| ProxyError::Protocol("bad AES-128-GCM key".into()))?;
            cipher
                .encrypt(
                    nonce_ga,
                    Payload {
                        msg: &msg,
                        aad: &header,
                    },
                )
                .map_err(|_| ProxyError::Protocol("AES-128-GCM encrypt failed".into()))?
        }
        CipherSuite::Aes256GcmSha384 => {
            let cipher = Aes256Gcm::new_from_slice(key)
                .map_err(|_| ProxyError::Protocol("bad AES-256-GCM key".into()))?;
            cipher
                .encrypt(
                    nonce_ga,
                    Payload {
                        msg: &msg,
                        aad: &header,
                    },
                )
                .map_err(|_| ProxyError::Protocol("AES-256-GCM encrypt failed".into()))?
        }
    };

    let mut record = Vec::with_capacity(5 + ciphertext.len());
    record.extend_from_slice(&header);
    record.extend_from_slice(&ciphertext);
    Ok(record)
}

// ── TLS record I/O ────────────────────────────────────────────────────────────

/// Read one complete TLS record from the stream.
/// Returns `(record_type, body)` where `body` does NOT include the 5-byte header.
async fn read_record(tcp: &mut TcpStream) -> Result<([u8; 5], Vec<u8>), ProxyError> {
    let mut header = [0u8; 5];
    tcp.read_exact(&mut header).await?;
    let body_len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let mut body = vec![0u8; body_len];
    tcp.read_exact(&mut body).await?;
    Ok((header, body))
}

pub(super) async fn read_record_stream(
    stream: &mut BoxedStream,
) -> Result<([u8; 5], Vec<u8>), ProxyError> {
    let mut header = [0u8; 5];
    stream.read_exact(&mut header).await?;
    let body_len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let mut body = vec![0u8; body_len];
    stream.read_exact(&mut body).await?;
    Ok((header, body))
}

pub(super) fn write_handshake_record(body: &[u8]) -> Vec<u8> {
    let mut record = Vec::with_capacity(5 + body.len());
    record.push(RT_HANDSHAKE);
    record.extend_from_slice(&[0x03, 0x03]);
    record.extend_from_slice(&(body.len() as u16).to_be_bytes());
    record.extend_from_slice(body);
    record
}

// ── ServerHello parser ────────────────────────────────────────────────────────

/// Parse a ServerHello handshake message body (starting at the `type` byte).
///
/// Returns `(cipher_suite, selected_group, server_key_share_bytes)`.
fn parse_server_hello(hs_body: &[u8]) -> Result<(CipherSuite, u16, Vec<u8>), ProxyError> {
    if hs_body.len() < 4 {
        return Err(ProxyError::Protocol("ServerHello body too short".into()));
    }
    if hs_body[0] != HS_SERVER_HELLO {
        return Err(ProxyError::Protocol(format!(
            "expected ServerHello (0x02), got 0x{:02x}",
            hs_body[0]
        )));
    }

    // Skip: type(1) + length(3) + legacy_version(2) + random(32)
    let random_start = 4 + 2;
    let random_end = random_start + 32;
    let random = &hs_body[random_start..random_end];
    let is_hrr = random == HELLO_RETRY_REQUEST_RANDOM;

    let mut pos = random_end;
    if pos >= hs_body.len() {
        return Err(ProxyError::Protocol(
            "ServerHello: truncated at session_id".into(),
        ));
    }

    let sid_len = hs_body[pos] as usize;
    pos += 1 + sid_len;

    if pos + 3 > hs_body.len() {
        return Err(ProxyError::Protocol(
            "ServerHello: truncated at cipher_suite".into(),
        ));
    }

    let raw_cs = u16::from_be_bytes([hs_body[pos], hs_body[pos + 1]]);
    let cs = CipherSuite::from_u16(raw_cs)?;
    pos += 2; // cipher_suite
    pos += 1; // legacy_compression_method

    // Extensions
    if pos + 2 > hs_body.len() {
        return Err(ProxyError::Protocol(
            "ServerHello: no extensions length".into(),
        ));
    }
    let ext_total = u16::from_be_bytes([hs_body[pos], hs_body[pos + 1]]) as usize;
    pos += 2;
    let ext_end = (pos + ext_total).min(hs_body.len());

    let mut server_share: Option<(u16, Vec<u8>)> = None;
    let mut ext_summaries = Vec::new();

    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([hs_body[pos], hs_body[pos + 1]]);
        let ext_len = u16::from_be_bytes([hs_body[pos + 2], hs_body[pos + 3]]) as usize;
        pos += 4;
        if pos + ext_len > hs_body.len() {
            break;
        }
        let ext_data = &hs_body[pos..pos + ext_len];
        pos += ext_len;
        ext_summaries.push(describe_server_hello_extension(ext_type, ext_data));

        if ext_type == 0x0033 {
            // key_share: ServerKeyShare = group(2) + key_exchange_len(2) + key_bytes
            if ext_data.len() >= 4 {
                let group = u16::from_be_bytes([ext_data[0], ext_data[1]]);
                let key_len = u16::from_be_bytes([ext_data[2], ext_data[3]]) as usize;
                if ext_data.len() >= 4 + key_len {
                    server_share = Some((group, ext_data[4..4 + key_len].to_vec()));
                }
            }
        }
    }

    let server_share = server_share.ok_or_else(|| {
        let kind = if is_hrr {
            "HelloRetryRequest"
        } else {
            "ServerHello"
        };
        ProxyError::Protocol(format!(
            "{kind}: no usable key_share; cipher_suite=0x{raw_cs:04x}; extensions=[{}]",
            ext_summaries.join(", ")
        ))
    })?;

    Ok((cs, server_share.0, server_share.1))
}

fn describe_server_hello_extension(ext_type: u16, ext_data: &[u8]) -> String {
    match ext_type {
        0x002b if ext_data.len() == 2 => {
            let version = u16::from_be_bytes([ext_data[0], ext_data[1]]);
            format!(
                "supported_versions(len={}, selected=0x{version:04x})",
                ext_data.len()
            )
        }
        0x0033 if ext_data.len() >= 2 => {
            let group = u16::from_be_bytes([ext_data[0], ext_data[1]]);
            if ext_data.len() == 2 {
                format!("key_share(len=2, selected_group=0x{group:04x})")
            } else if ext_data.len() >= 4 {
                let key_len = u16::from_be_bytes([ext_data[2], ext_data[3]]) as usize;
                format!(
                    "key_share(len={}, group=0x{group:04x}, key_len={key_len})",
                    ext_data.len()
                )
            } else {
                format!("key_share(len={})", ext_data.len())
            }
        }
        other => format!("0x{other:04x}(len={})", ext_data.len()),
    }
}

// ── Handshake message parser ──────────────────────────────────────────────────

/// Split decrypted handshake payload into individual messages.
///
/// Each returned element is `(hs_type, raw_msg)` where `raw_msg` is the full
/// 4-byte-prefixed handshake message (type + 3-byte length + body).
pub(super) fn split_handshake_messages(data: &[u8]) -> Vec<(u8, &[u8])> {
    let mut msgs = Vec::new();
    let mut pos = 0;
    while pos + 4 <= data.len() {
        let hs_type = data[pos];
        let hs_len = u32::from_be_bytes([0, data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        let msg_end = pos + 4 + hs_len;
        if msg_end > data.len() {
            break;
        }
        msgs.push((hs_type, &data[pos..msg_end]));
        pos = msg_end;
    }
    msgs
}

// ── Main handshake function ───────────────────────────────────────────────────

/// Complete the TLS 1.3 handshake after the REALITY-authenticated ClientHello.
///
/// Parameters:
/// - `tcp`: the raw TCP stream (ClientHello already sent).
/// - `client_hello_hs_body`: the ClientHello handshake message bytes (WITHOUT
///   the 5-byte TLS record header). Used as the starting point of the transcript.
/// - `client_secret`: the ephemeral x25519 private key whose public half was
///   placed in the `key_share` extension of the ClientHello.
///
/// On success returns a [`Tls13Stream`] ready for application-data I/O.
pub(crate) async fn complete_tls13_handshake(
    tcp: &mut TcpStream,
    client_hello_hs_body: &[u8],
    client_x25519_secret: &StaticSecret,
    client_p256_secret: Option<&P256EphemeralSecret>,
    auth_key: &[u8; 32],
) -> Result<AppKeys, ProxyError> {
    // Running transcript: concatenation of all handshake message bodies.
    let mut transcript: Vec<u8> = client_hello_hs_body.to_vec();

    // ── Read ServerHello ──────────────────────────────────────────────────────
    let (sh_header, sh_body) = read_record(tcp).await?;
    if sh_header[0] != RT_HANDSHAKE {
        return Err(ProxyError::Protocol(format!(
            "expected TLS Handshake (0x16), got 0x{:02x} — REALITY auth may have failed",
            sh_header[0]
        )));
    }

    let (cs, selected_group, server_pub_bytes) = parse_server_hello(&sh_body)?;
    transcript.extend_from_slice(&sh_body);
    debug!(cs = ?cs, selected_group, "TLS 1.3 ServerHello received");

    // ── Derive handshake traffic secrets ──────────────────────────────────────
    let tls_dhe = match selected_group {
        29 => {
            if server_pub_bytes.len() != 32 {
                return Err(ProxyError::Protocol(format!(
                    "ServerHello x25519 key_share length mismatch: {}",
                    server_pub_bytes.len()
                )));
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&server_pub_bytes);
            let server_tls_pub = PublicKey::from(key);
            client_x25519_secret
                .diffie_hellman(&server_tls_pub)
                .as_bytes()
                .to_vec()
        }
        23 => {
            let client_p256_secret = client_p256_secret.ok_or_else(|| {
                ProxyError::Protocol(
                    "ServerHello selected secp256r1 but client has no P-256 key share".into(),
                )
            })?;
            let server_tls_pub =
                P256PublicKey::from_sec1_bytes(&server_pub_bytes).map_err(|e| {
                    ProxyError::Protocol(format!("invalid secp256r1 ServerHello key_share: {e}"))
                })?;
            client_p256_secret
                .diffie_hellman(&server_tls_pub)
                .raw_secret_bytes()
                .to_vec()
        }
        other => {
            return Err(ProxyError::Protocol(format!(
                "unsupported ServerHello key_share group 0x{other:04x}"
            )))
        }
    };

    let transcript_hash_after_sh = cs.hash(&transcript);
    let tls_dhe: [u8; 32] = tls_dhe
        .try_into()
        .map_err(|_| ProxyError::Protocol("TLS key agreement secret length mismatch".into()))?;
    let hs_keys = derive_handshake_keys(cs, &tls_dhe, &transcript_hash_after_sh)?;

    // ── Read and decrypt server handshake messages ────────────────────────────
    // Expected: [ChangeCipherSpec], EncryptedExtensions, Certificate,
    //           CertificateVerify, Finished.
    let mut srv_seq: u64 = 0;
    let mut found_finished = false;

    while !found_finished {
        let (rec_header, rec_body) = read_record(tcp).await?;

        match rec_header[0] {
            RT_CHANGE_CIPHER_SPEC => {
                // Legacy CCS packet — silently ignored.
                continue;
            }
            RT_ALERT => {
                // decode_error / illegal_parameter etc. — auth failed or bad state
                let desc = rec_body.get(1).copied().unwrap_or(0);
                return Err(ProxyError::Protocol(format!(
                    "TLS alert from server during handshake: level={} desc={}",
                    rec_body.first().copied().unwrap_or(0),
                    desc
                )));
            }
            RT_APPLICATION_DATA => {
                let (inner, inner_type) = decrypt_app_record(
                    cs,
                    &hs_keys.server_key,
                    &hs_keys.server_iv,
                    srv_seq,
                    &rec_body,
                    rec_header,
                )?;
                srv_seq += 1;

                if inner_type != RT_HANDSHAKE {
                    // Not a handshake inner type — skip (e.g. early data).
                    continue;
                }

                // Parse one or more handshake messages from the decrypted payload.
                for (hs_type, msg_bytes) in split_handshake_messages(&inner) {
                    match hs_type {
                        HS_CERTIFICATE => {
                            let cert_der = super::cert::parse_certificate_message_der(msg_bytes)?;
                            super::cert::verify_reality_cert_hmac(auth_key, &cert_der)?;
                            debug!("REALITY server certificate HMAC verified");
                            transcript.extend_from_slice(msg_bytes);
                        }
                        HS_ENCRYPTED_EXTENSIONS | HS_CERTIFICATE_VERIFY => {
                            transcript.extend_from_slice(msg_bytes);
                        }
                        HS_FINISHED => {
                            // Verify server Finished before adding it to the transcript.
                            // finished_key = Expand-Label(server_hs_traffic, "finished", "", H)
                            // verify_data = HMAC(finished_key, Hash(transcript_so_far))
                            let transcript_hash = cs.hash(&transcript);
                            let expected =
                                cs.hmac(&hs_keys.server_finished_key, &transcript_hash)?;
                            let body_start = 4; // skip type(1)+len(3)
                            let verify_data = &msg_bytes[body_start..];
                            if verify_data != expected.as_slice() {
                                return Err(ProxyError::Protocol(
                                    "server Finished HMAC mismatch".into(),
                                ));
                            }
                            // Add Finished to transcript AFTER verification.
                            transcript.extend_from_slice(msg_bytes);
                            found_finished = true;
                        }
                        other => {
                            debug!(
                                hs_type = other,
                                "ignoring unexpected handshake message type"
                            );
                        }
                    }
                }
            }
            other => {
                return Err(ProxyError::Protocol(format!(
                    "unexpected TLS record type 0x{other:02x} during handshake"
                )));
            }
        }
    }

    // ── App traffic secrets (derived before sending client Finished) ──────────
    // RFC 8446: app secrets use transcript Hash(CH..server Finished).
    let app_transcript_hash = cs.hash(&transcript);
    let app_keys = derive_app_keys(cs, &hs_keys.master_secret, &app_transcript_hash)?;

    // ── Send legacy ChangeCipherSpec ──────────────────────────────────────────
    tcp.write_all(&[RT_CHANGE_CIPHER_SPEC, 0x03, 0x03, 0x00, 0x01, 0x01])
        .await?;

    // ── Send client Finished ──────────────────────────────────────────────────
    // verify_data = HMAC(client_finished_key, Hash(transcript_so_far))
    let client_finished_data = cs.hmac(&hs_keys.client_finished_key, &app_transcript_hash)?;

    // Build client Finished handshake message: type(1) + len(3) + verify_data
    let vd_len = client_finished_data.len() as u32;
    let mut finished_msg = Vec::with_capacity(4 + client_finished_data.len());
    finished_msg.push(HS_FINISHED);
    finished_msg.push((vd_len >> 16) as u8);
    finished_msg.push((vd_len >> 8) as u8);
    finished_msg.push(vd_len as u8);
    finished_msg.extend_from_slice(&client_finished_data);

    let finished_record = encrypt_app_record(
        cs,
        &hs_keys.client_key,
        &hs_keys.client_iv,
        0,
        &finished_msg,
        RT_HANDSHAKE,
    )?;
    tcp.write_all(&finished_record).await?;

    debug!("TLS 1.3 handshake complete — application traffic keys derived");
    Ok(app_keys)
}

// ── Application-data stream ───────────────────────────────────────────────────

/// Phases of the TLS record read state machine.
const RPHASE_PLAINTEXT: u8 = 0; // serve from decrypted buffer
const RPHASE_HEADER: u8 = 1; // accumulating 5-byte record header
const RPHASE_BODY: u8 = 2; // accumulating record body

pin_project! {
    /// A TLS 1.3 application-data stream.
    ///
    /// Wraps a raw byte stream and transparently AEAD-encrypts/decrypts all I/O
    /// using the application traffic keys derived after the handshake.
    pub struct Tls13Stream {
        #[pin]
        inner: BoxedStream,

        cs: CipherSuite,

        // Encryption: client → server
        client_key: Vec<u8>,
        client_iv: [u8; 12],
        client_seq: u64,

        // Decryption: server → client
        server_key: Vec<u8>,
        server_iv: [u8; 12],
        server_seq: u64,

        // ── Read state machine ──
        plain_buf: Vec<u8>,  // decrypted application data ready to serve
        plain_pos: usize,
        header_buf: [u8; 5], // accumulating the 5-byte TLS record header
        header_pos: usize,
        body_buf: Vec<u8>,   // accumulating the current TLS record body
        body_pos: usize,
        read_phase: u8,      // RPHASE_* constant

        // ── Write state machine ──
        write_buf: Vec<u8>,      // encrypted record waiting to be flushed
        write_pos: usize,        // bytes of write_buf already sent
        write_chunk_len: usize,  // plaintext bytes that produced write_buf
        is_server: bool, // inbound REALITY server endpoint when true
    }
}

impl Tls13Stream {
    /// Application stream for a TLS client (outbound REALITY).
    pub fn new(inner: BoxedStream, keys: AppKeys) -> Self {
        Self::with_role(inner, keys, false)
    }

    /// Application stream for a TLS server (inbound REALITY after handshake).
    pub fn new_server(inner: BoxedStream, keys: AppKeys) -> Self {
        Self::with_role(inner, keys, true)
    }

    fn with_role(inner: BoxedStream, keys: AppKeys, is_server: bool) -> Self {
        Self {
            inner,
            cs: keys.cs,
            client_key: keys.client_key,
            client_iv: keys.client_iv,
            client_seq: 0,
            server_key: keys.server_key,
            server_iv: keys.server_iv,
            server_seq: 0,
            is_server,
            plain_buf: Vec::new(),
            plain_pos: 0,
            header_buf: [0u8; 5],
            header_pos: 0,
            body_buf: Vec::new(),
            body_pos: 0,
            read_phase: RPHASE_HEADER,
            write_buf: Vec::new(),
            write_pos: 0,
            write_chunk_len: 0,
        }
    }
}

impl AsyncRead for Tls13Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut me = self.project();

        loop {
            // ── Phase 0: serve decrypted bytes ────────────────────────────────
            if *me.read_phase == RPHASE_PLAINTEXT {
                if *me.plain_pos < me.plain_buf.len() {
                    let available = &me.plain_buf[*me.plain_pos..];
                    let n = available.len().min(buf.remaining());
                    buf.put_slice(&available[..n]);
                    *me.plain_pos += n;
                    if *me.plain_pos >= me.plain_buf.len() {
                        me.plain_buf.clear();
                        *me.plain_pos = 0;
                    }
                    return Poll::Ready(Ok(()));
                }
                // Buffer exhausted — transition to reading a new record header.
                *me.read_phase = RPHASE_HEADER;
                *me.header_pos = 0;
            }

            // ── Phase 1: read 5-byte TLS record header ────────────────────────
            if *me.read_phase == RPHASE_HEADER {
                while *me.header_pos < 5 {
                    let mut rb = ReadBuf::new(&mut me.header_buf[*me.header_pos..]);
                    ready!(me.inner.as_mut().poll_read(cx, &mut rb))?;
                    let n = rb.filled().len();
                    if n == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "TLS peer closed mid-record-header",
                        )));
                    }
                    *me.header_pos += n;
                }
                let body_len = u16::from_be_bytes([me.header_buf[3], me.header_buf[4]]) as usize;
                me.body_buf.resize(body_len, 0);
                *me.body_pos = 0;
                *me.read_phase = RPHASE_BODY;
            }

            // ── Phase 2: read record body ─────────────────────────────────────
            if *me.read_phase == RPHASE_BODY {
                while *me.body_pos < me.body_buf.len() {
                    let mut rb = ReadBuf::new(&mut me.body_buf[*me.body_pos..]);
                    ready!(me.inner.as_mut().poll_read(cx, &mut rb))?;
                    let n = rb.filled().len();
                    if n == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "TLS peer closed mid-record-body",
                        )));
                    }
                    *me.body_pos += n;
                }

                // Complete record in hand — process it.
                let rec_type = me.header_buf[0];
                match rec_type {
                    RT_APPLICATION_DATA => {
                        let result = if *me.is_server {
                            decrypt_app_record(
                                *me.cs,
                                me.client_key,
                                me.client_iv,
                                *me.client_seq,
                                me.body_buf,
                                *me.header_buf,
                            )
                        } else {
                            decrypt_app_record(
                                *me.cs,
                                me.server_key,
                                me.server_iv,
                                *me.server_seq,
                                me.body_buf,
                                *me.header_buf,
                            )
                        };
                        match result {
                            Err(e) => {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    e.to_string(),
                                )));
                            }
                            Ok((inner, inner_type)) => {
                                if *me.is_server {
                                    *me.client_seq += 1;
                                } else {
                                    *me.server_seq += 1;
                                }
                                match inner_type {
                                    RT_APPLICATION_DATA => {
                                        *me.plain_buf = inner;
                                        *me.plain_pos = 0;
                                        *me.read_phase = RPHASE_PLAINTEXT;
                                        // loop back to phase 0 to serve data
                                    }
                                    RT_ALERT => {
                                        if inner.len() >= 2 && inner[0] == 1 && inner[1] == 0 {
                                            // close_notify → clean EOF
                                            return Poll::Ready(Ok(()));
                                        }
                                        return Poll::Ready(Err(io::Error::new(
                                            io::ErrorKind::ConnectionReset,
                                            "TLS alert from server",
                                        )));
                                    }
                                    _ => {
                                        // Handshake post-auth or other — skip.
                                        *me.read_phase = RPHASE_HEADER;
                                        *me.header_pos = 0;
                                    }
                                }
                            }
                        }
                    }
                    RT_CHANGE_CIPHER_SPEC => {
                        // Legacy packet after the handshake — ignore.
                        *me.read_phase = RPHASE_HEADER;
                        *me.header_pos = 0;
                    }
                    RT_ALERT => {
                        if me.body_buf.len() >= 2 && me.body_buf[0] == 1 && me.body_buf[1] == 0 {
                            return Poll::Ready(Ok(())); // close_notify
                        }
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::ConnectionReset,
                            "TLS alert (unencrypted)",
                        )));
                    }
                    other => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("unexpected TLS record type 0x{other:02x}"),
                        )));
                    }
                }
            }
        }
    }
}

impl AsyncWrite for Tls13Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut me = self.project();

        // ── Flush pending encrypted record from a previous partial write ──────
        if !me.write_buf.is_empty() {
            while *me.write_pos < me.write_buf.len() {
                let n = ready!(me
                    .inner
                    .as_mut()
                    .poll_write(cx, &me.write_buf[*me.write_pos..]))?;
                if n == 0 {
                    return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)));
                }
                *me.write_pos += n;
            }
            me.write_buf.clear();
            *me.write_pos = 0;
            let consumed = *me.write_chunk_len;
            *me.write_chunk_len = 0;
            return Poll::Ready(Ok(consumed));
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // ── Encrypt a new chunk (max TLS record size = 2^14 bytes) ────────────
        let chunk_len = buf.len().min(16384);
        *me.write_chunk_len = chunk_len;

        let record = if *me.is_server {
            encrypt_app_record(
                *me.cs,
                me.server_key,
                me.server_iv,
                *me.server_seq,
                &buf[..chunk_len],
                RT_APPLICATION_DATA,
            )
        } else {
            encrypt_app_record(
                *me.cs,
                me.client_key,
                me.client_iv,
                *me.client_seq,
                &buf[..chunk_len],
                RT_APPLICATION_DATA,
            )
        }
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        if *me.is_server {
            *me.server_seq += 1;
        } else {
            *me.client_seq += 1;
        }
        *me.write_buf = record;
        *me.write_pos = 0;

        // ── Write the record (may be partial) ─────────────────────────────────
        while *me.write_pos < me.write_buf.len() {
            match me
                .inner
                .as_mut()
                .poll_write(cx, &me.write_buf[*me.write_pos..])
            {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)))
                }
                Poll::Ready(Ok(n)) => *me.write_pos += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        me.write_buf.clear();
        *me.write_pos = 0;
        *me.write_chunk_len = 0;
        Poll::Ready(Ok(chunk_len))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
}

#[path = "tls13_server.rs"]
mod tls13_server;
pub use tls13_server::complete_tls13_server_handshake;
