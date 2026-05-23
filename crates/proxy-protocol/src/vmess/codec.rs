//! VMess AEAD header codec — encode and decode VMess request headers.
//!
//! # Header layout (plaintext, before encryption)
//!
//! ```text
//! ┌────────────────────────────────────────────────────────────────────────┐
//! │ Version (1)          = 1                                               │
//! │ IV (16)              — random, used for data channel AES-GCM           │
//! │ Key (16)             — random, used for data channel AES-GCM           │
//! │ V (1)                — random verification byte                        │
//! │ Options (1)          — bitmask of options (ChunkStream=0x01)           │
//! │ Padding+Security (1) — high nibble: padding length; low nibble: sec    │
//! │ Reserved (1)         = 0                                               │
//! │ Command (1)          = 0x01 (TCP)                                      │
//! │ Port (2)             — big-endian destination port                     │
//! │ AddrType (1)         — 0x01 IPv4, 0x02 Host, 0x03 IPv6                │
//! │ Addr (var)           — destination address                             │
//! │ Padding (pad_len)    — random bytes                                    │
//! │ Checksum (4)         — fnv32a over all preceding bytes                 │
//! └────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Encryption
//!
//! The plaintext header is encrypted with AES-128-GCM:
//! - Key: `KDF16(cmd_key, "VMess AEAD Header Key", ...)`
//! - Nonce: `KDF12(cmd_key, "VMess AEAD Header IV", ...)`
//! - AAD: the 16-byte auth ID
//!
//! # Security (encryption algorithm)
//!
//! | Value | Algorithm          |
//! |-------|--------------------|
//! | 0x03  | AES-128-GCM        |
//! | 0x04  | ChaCha20-Poly1305  |
//!
//! # References
//!
//! v2fly/v2ray-core: `proxy/vmess/encoding/`

use aes_gcm::{
    aead::{generic_array::GenericArray, Aead, Payload},
    Aes128Gcm, KeyInit,
};
use bytes::{BufMut, Bytes, BytesMut};
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncReadExt};

use proxy_common::{Address, ProxyError};

use super::kdf::kdf;

// ── Path constants (from v2ray-core) ─────────────────────────────────────────

pub const PATH_HEADER_KEY: &[u8] = b"VMess AEAD Header Key";
pub const PATH_HEADER_IV: &[u8] = b"VMess AEAD Header IV";
pub const PATH_HEADER_KEY_2: &[u8] = b"VMess Header Key";
pub const PATH_HEADER_IV_2: &[u8] = b"VMess Header IV";

// ── Security types ─────────────────────────────────────────────────────────────

/// Security algorithm for the data channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Security {
    /// AES-128-GCM (recommended).
    #[default]
    Aes128Gcm = 0x03,
    /// ChaCha20-Poly1305 (alternative).
    ChaCha20Poly1305 = 0x04,
}

impl TryFrom<u8> for Security {
    type Error = ProxyError;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0x03 => Ok(Self::Aes128Gcm),
            0x04 => Ok(Self::ChaCha20Poly1305),
            other => Err(ProxyError::Protocol(format!(
                "VMess: unknown security byte {other:#x}"
            ))),
        }
    }
}

// ── Address types ─────────────────────────────────────────────────────────────

const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x02;
const ATYP_IPV6: u8 = 0x03;

// ── Request header ────────────────────────────────────────────────────────────

/// Decoded VMess request header (after decryption).
#[derive(Debug)]
pub struct VmessRequest {
    /// 16-byte IV for the data channel cipher.
    pub iv: [u8; 16],

    /// 16-byte key for the data channel cipher.
    pub key: [u8; 16],

    /// Random verification byte (echoed in the response).
    pub v: u8,

    /// Security algorithm for data channel.
    pub security: Security,

    /// Destination address.
    pub dest: Address,
}

// ── Encoder ───────────────────────────────────────────────────────────────────

/// Encode a VMess AEAD request header.
///
/// Returns `(auth_id, encrypted_header)`.
///
/// # Arguments
/// * `cmd_key` — 16-byte key derived from the user's UUID
/// * `auth_id` — the 16-byte auth ID (already computed by `auth::generate_auth_id`)
/// * `dest`    — the destination address to encode
/// * `security`— the data channel cipher to advertise
///
/// # Returns
/// `(iv, key, v, encrypted_header_bytes)` where `iv` and `key` are the
/// generated data-channel parameters and `encrypted_header_bytes` is the wire
/// bytes to send (ciphertext + GCM tag).
pub fn encode_header(
    cmd_key: &[u8; 16],
    auth_id: &[u8; 16],
    dest: &Address,
    security: Security,
) -> ([u8; 16], [u8; 16], u8, Bytes) {
    let mut rng = rand::thread_rng();

    // Generate random IV, Key, V
    let mut iv = [0u8; 16];
    let mut key = [0u8; 16];
    let mut v = [0u8; 1];
    rng.fill_bytes(&mut iv);
    rng.fill_bytes(&mut key);
    rng.fill_bytes(&mut v);
    let v_byte = v[0];

    let pad_len: u8 = (rng.next_u32() % 16) as u8;

    // Build plaintext.
    let plaintext = build_request_plaintext(&iv, &key, v_byte, pad_len, security, dest);

    // Derive AES-128-GCM key and nonce from cmd_key.
    let enc_key: [u8; 16] = kdf(cmd_key, &[PATH_HEADER_KEY, auth_id, PATH_HEADER_KEY_2]);
    let enc_nonce: [u8; 12] = kdf(cmd_key, &[PATH_HEADER_IV, auth_id, PATH_HEADER_IV_2]);

    let cipher = Aes128Gcm::new(GenericArray::from_slice(&enc_key));
    let nonce = GenericArray::from_slice(&enc_nonce);

    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: &plaintext,
                aad: auth_id,
            },
        )
        .unwrap_or_else(|_| panic!("AES-128-GCM encryption must not fail"));

    (iv, key, v_byte, Bytes::from(ciphertext))
}

/// Build the plaintext request header bytes (before encryption).
fn build_request_plaintext(
    iv: &[u8; 16],
    key: &[u8; 16],
    v: u8,
    pad_len: u8,
    security: Security,
    dest: &Address,
) -> Vec<u8> {
    let mut buf = BytesMut::new();

    buf.put_u8(0x01); // version
    buf.put_slice(iv);
    buf.put_slice(key);
    buf.put_u8(v);
    buf.put_u8(0x01); // options: ChunkStream
    buf.put_u8((pad_len << 4) | (security as u8)); // padding nibble + security nibble
    buf.put_u8(0x00); // reserved
    buf.put_u8(0x01); // command: TCP

    // Port + address
    match dest {
        Address::Ipv4(ip, port) => {
            buf.put_u16(*port);
            buf.put_u8(ATYP_IPV4);
            buf.put_slice(&ip.octets());
        }
        Address::Ipv6(ip, port) => {
            buf.put_u16(*port);
            buf.put_u8(ATYP_IPV6);
            buf.put_slice(&ip.octets());
        }
        Address::Domain(name, port) => {
            buf.put_u16(*port);
            buf.put_u8(ATYP_DOMAIN);
            buf.put_u8(name.len() as u8);
            buf.put_slice(name.as_bytes());
        }
    }

    // Random padding
    let mut pad = vec![0u8; pad_len as usize];
    rand::thread_rng().fill_bytes(&mut pad);
    buf.put_slice(&pad);

    // FNV-1a checksum over all preceding bytes
    let checksum = fnv32a(buf.as_ref());
    buf.put_u32(checksum);

    buf.to_vec()
}

// ── Decoder ───────────────────────────────────────────────────────────────────

/// Decrypt and decode a VMess AEAD header from an async stream.
///
/// # Arguments
/// * `reader`   — the byte stream positioned immediately after the auth ID
/// * `cmd_key`  — the 16-byte key for the user who was identified by auth ID
/// * `auth_id`  — the 16-byte auth ID (used as AEAD additional data)
/// * `enc_len`  — the number of ciphertext bytes to read (see note below)
///
/// **Note on `enc_len`:** The plaintext header is variable-length (address
/// varies). In the real VMess AEAD protocol, the header length is encrypted
/// in a separate 2-byte length prefix before the main header. This function
/// reads exactly `enc_len` bytes of ciphertext (including the 16-byte tag).
pub async fn decode_header<R: AsyncRead + Unpin>(
    reader: &mut R,
    cmd_key: &[u8; 16],
    auth_id: &[u8; 16],
    enc_len: usize,
) -> Result<VmessRequest, ProxyError> {
    let mut ciphertext = vec![0u8; enc_len];
    reader.read_exact(&mut ciphertext).await?;

    let enc_key: [u8; 16] = kdf(cmd_key, &[PATH_HEADER_KEY, auth_id, PATH_HEADER_KEY_2]);
    let enc_nonce: [u8; 12] = kdf(cmd_key, &[PATH_HEADER_IV, auth_id, PATH_HEADER_IV_2]);

    let cipher = Aes128Gcm::new(GenericArray::from_slice(&enc_key));
    let nonce = GenericArray::from_slice(&enc_nonce);

    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: &ciphertext,
                aad: auth_id,
            },
        )
        .map_err(|_| ProxyError::Protocol("VMess: AEAD header decryption failed".into()))?;

    decode_plaintext(&plaintext)
}

/// Decode the plaintext header bytes into a `VmessRequest`.
fn decode_plaintext(data: &[u8]) -> Result<VmessRequest, ProxyError> {
    if data.len() < 38 {
        return Err(ProxyError::Protocol("VMess: header too short".into()));
    }

    let ver = data[0];
    if ver != 1 {
        return Err(ProxyError::Protocol(format!(
            "VMess: unexpected version {ver}"
        )));
    }

    let iv: [u8; 16] = data[1..17]
        .try_into()
        .map_err(|_| ProxyError::Protocol("VMess: truncated IV".into()))?;
    let key: [u8; 16] = data[17..33]
        .try_into()
        .map_err(|_| ProxyError::Protocol("VMess: truncated key".into()))?;
    let v = data[33];
    let _options = data[34];
    let pad_sec = data[35];
    let pad_len = (pad_sec >> 4) as usize;
    let security = Security::try_from(pad_sec & 0x0F)?;
    // data[36] = reserved
    let _cmd = data[37];

    let mut pos = 38;

    // Port
    if pos + 2 > data.len() {
        return Err(ProxyError::Protocol(
            "VMess: header truncated at port".into(),
        ));
    }
    let port = u16::from_be_bytes([data[pos], data[pos + 1]]);
    pos += 2;

    // Address type
    if pos >= data.len() {
        return Err(ProxyError::Protocol(
            "VMess: header truncated at atyp".into(),
        ));
    }
    let atyp = data[pos];
    pos += 1;

    let dest = match atyp {
        ATYP_IPV4 => {
            if pos + 4 > data.len() {
                return Err(ProxyError::Protocol("VMess: truncated IPv4".into()));
            }
            let ip =
                std::net::Ipv4Addr::new(data[pos], data[pos + 1], data[pos + 2], data[pos + 3]);
            pos += 4;
            Address::Ipv4(ip, port)
        }
        ATYP_IPV6 => {
            if pos + 16 > data.len() {
                return Err(ProxyError::Protocol("VMess: truncated IPv6".into()));
            }
            let mut ip6 = [0u8; 16];
            ip6.copy_from_slice(&data[pos..pos + 16]);
            pos += 16;
            Address::Ipv6(std::net::Ipv6Addr::from(ip6), port)
        }
        ATYP_DOMAIN => {
            if pos >= data.len() {
                return Err(ProxyError::Protocol(
                    "VMess: truncated domain length".into(),
                ));
            }
            let dlen = data[pos] as usize;
            pos += 1;
            if pos + dlen > data.len() {
                return Err(ProxyError::Protocol("VMess: truncated domain".into()));
            }
            let domain = std::str::from_utf8(&data[pos..pos + dlen])
                .map_err(|_| ProxyError::Protocol("VMess: domain not UTF-8".into()))?
                .to_string();
            pos += dlen;
            Address::Domain(domain, port)
        }
        other => {
            return Err(ProxyError::Protocol(format!(
                "VMess: unknown ATYP {other:#x}"
            )));
        }
    };

    pos += pad_len; // skip padding

    // Checksum
    if pos + 4 > data.len() {
        return Err(ProxyError::Protocol("VMess: truncated checksum".into()));
    }
    let expected = fnv32a(&data[..pos]);
    let received_bytes: [u8; 4] = data[pos..pos + 4]
        .try_into()
        .map_err(|_| ProxyError::Protocol("VMess: truncated checksum bytes".into()))?;
    let received = u32::from_be_bytes(received_bytes);
    if expected != received {
        return Err(ProxyError::Protocol(
            "VMess: header checksum mismatch".into(),
        ));
    }

    Ok(VmessRequest {
        iv,
        key,
        v,
        security,
        dest,
    })
}

// ── FNV-1a ────────────────────────────────────────────────────────────────────

/// FNV-1a 32-bit hash (used for header checksum).
fn fnv32a(data: &[u8]) -> u32 {
    let mut hash: u32 = 0x811c_9dc5;
    for &byte in data {
        hash ^= u32::from(byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use proxy_common::Address;

    fn test_cmd_key() -> [u8; 16] {
        let uuid = *uuid::Uuid::parse_str("a3482e88-686a-4a58-8126-99c9df64b7bf")
            .unwrap()
            .as_bytes();
        super::super::auth::cmd_key(&uuid)
    }

    fn test_auth_id() -> [u8; 16] {
        let key = test_cmd_key();
        let now = super::super::auth::current_timestamp();
        super::super::auth::generate_auth_id_at(&key, now)
    }

    #[test]
    fn fnv32a_known_value() {
        // FNV-1a("") = 2166136261 (the offset basis)
        assert_eq!(fnv32a(b""), 0x811c_9dc5);
    }

    #[test]
    fn build_plaintext_roundtrip_ipv4() {
        let iv = [1u8; 16];
        let key = [2u8; 16];
        let dest = Address::Ipv4("1.2.3.4".parse().unwrap(), 8080);
        let pt = build_request_plaintext(&iv, &key, 0x42, 0, Security::Aes128Gcm, &dest);
        let req = decode_plaintext(&pt).unwrap();
        assert_eq!(req.iv, iv);
        assert_eq!(req.key, key);
        assert_eq!(req.v, 0x42);
        assert_eq!(req.dest, dest);
        assert_eq!(req.security, Security::Aes128Gcm);
    }

    #[test]
    fn build_plaintext_roundtrip_domain() {
        let iv = [3u8; 16];
        let key = [4u8; 16];
        let dest = Address::Domain("example.com".to_string(), 443);
        let pt = build_request_plaintext(&iv, &key, 0x01, 0, Security::ChaCha20Poly1305, &dest);
        let req = decode_plaintext(&pt).unwrap();
        assert_eq!(req.dest, dest);
        assert_eq!(req.security, Security::ChaCha20Poly1305);
    }

    #[test]
    fn encode_decode_header_roundtrip() {
        let cmd_key = test_cmd_key();
        let auth_id = test_auth_id();
        let dest = Address::Domain("test.example.com".to_string(), 443);

        let (iv, key, v, ciphertext) =
            encode_header(&cmd_key, &auth_id, &dest, Security::Aes128Gcm);

        // Simulate read: put ciphertext into a cursor.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut cursor = std::io::Cursor::new(ciphertext.to_vec());
            let req = decode_header(&mut cursor, &cmd_key, &auth_id, ciphertext.len())
                .await
                .unwrap();
            assert_eq!(req.iv, iv);
            assert_eq!(req.key, key);
            assert_eq!(req.v, v);
            assert_eq!(req.dest, dest);
        });
    }
}
