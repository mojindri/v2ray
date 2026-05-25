//! VMess AEAD header codec — encode and decode VMess request/response headers.
//!
//! # Request wire layout (client → server)
//!
//! ```text
//! auth_id(16) | enc_len(18) | connection_nonce(8) | enc_header(N+16)
//! ```
//!
//! Where:
//! - `enc_len`    = AES-128-GCM(length_key, length_nonce, uint16(header_len), aad=auth_id)
//! - `enc_header` = AES-128-GCM(header_key, header_nonce, header_plaintext, aad=auth_id)
//! - Keys/nonces derived via KDF from cmd_key, path constant, auth_id, connection_nonce
//!
//! # Request header plaintext
//!
//! ```text
//! version(1)=1 | iv(16) | key(16) | v(1) | options(1) | pad_sec(1) | reserved(1)=0
//! | command(1)=1 | port(2 BE) | atyp(1) | addr(var) | padding(pad_len) | fnv32a(4)
//! ```
//!
//! # Response wire layout (server → client)
//!
//! ```text
//! enc_resp_len(18) | enc_resp_header(payload+16)
//! ```
//!
//! Using keys derived from `response_body_key = SHA256(request_key)[:16]`.
//!
//! # How it works
//!
//! The client encrypts a request header in two parts: one encrypted length field
//! and one encrypted header payload. The server decrypts both using keys derived
//! from `cmd_key`, `auth_id`, and `connection_nonce`.
//!
//! # Why
//!
//! Splitting length and payload keeps framing confidential and authenticated,
//! while still allowing streaming reads without buffering a full connection.

use aes_gcm::{
    aead::{generic_array::GenericArray, Aead, Payload},
    Aes128Gcm, KeyInit,
};
use bytes::{BufMut, BytesMut};
use rand::{Rng, RngExt};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use blackwire_common::{domain_wire_len, Address, ProxyError};

use super::kdf::kdf;

// ── KDF path constants ────────────────────────────────────────────────────────

/// Request length field encryption key path.
pub const PATH_LEN_KEY: &[u8] = b"VMess Header AEAD Key_Length";
/// Request length field encryption nonce path.
pub const PATH_LEN_IV: &[u8] = b"VMess Header AEAD Nonce_Length";
/// Request header encryption key path.
pub const PATH_HDR_KEY: &[u8] = b"VMess Header AEAD Key";
/// Request header encryption nonce path.
pub const PATH_HDR_IV: &[u8] = b"VMess Header AEAD Nonce";

/// Response header length key path.
pub const PATH_RESP_LEN_KEY: &[u8] = b"AEAD Resp Header Len Key";
/// Response header length nonce path.
pub const PATH_RESP_LEN_IV: &[u8] = b"AEAD Resp Header Len IV";
/// Response header payload key path.
pub const PATH_RESP_HDR_KEY: &[u8] = b"AEAD Resp Header Key";
/// Response header payload nonce path.
pub const PATH_RESP_HDR_IV: &[u8] = b"AEAD Resp Header IV";

// ── Security types ─────────────────────────────────────────────────────────────

/// Security algorithm for the data channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Security {
    #[default]
    /// Use AES-128-GCM for VMess body chunks.
    Aes128Gcm = 0x03,
    /// Use ChaCha20-Poly1305 for VMess body chunks.
    ChaCha20Poly1305 = 0x04,
    /// Disable payload encryption for VMess body chunks.
    None = 0x05,
}

impl TryFrom<u8> for Security {
    type Error = ProxyError;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0x03 => Ok(Self::Aes128Gcm),
            0x04 => Ok(Self::ChaCha20Poly1305),
            0x05 => Ok(Self::None),
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

/// VMess request command: TCP (Xray `RequestCommandTCP`).
const CMD_TCP: u8 = 0x01;
/// VMess request command: UDP (Xray `RequestCommandUDP`).
const CMD_UDP: u8 = 0x02;
/// VMess request command: Mux (Xray `RequestCommandMux`).
const CMD_MUX: u8 = 0x03;
/// Domain used for Mux requests (Xray `MuxCoolAddress`).
const MUX_DOMAIN: &str = "v1.mux.cool";

// ── Request header ────────────────────────────────────────────────────────────

/// Decoded VMess request header.
#[derive(Debug)]
pub struct VmessRequest {
    /// Request body IV used to build inbound body chunk nonces.
    pub iv: [u8; 16],
    /// Request body key used to decrypt inbound body chunks.
    pub key: [u8; 16],
    /// Random verification byte echoed in the response header.
    pub v: u8,
    /// Request option flags (for example chunk masking and padding).
    pub options: u8,
    /// Requested body security algorithm.
    pub security: Security,
    /// Destination parsed from the VMess request header.
    pub dest: Address,
}

/// Tuple returned by `encode_header` with all wire pieces and body secrets.
pub type EncodedHeader = ([u8; 16], [u8; 16], u8, [u8; 8], Vec<u8>, Vec<u8>);

// ── Response key/IV derivation ────────────────────────────────────────────────

/// Derive the response body key from the request body key.
pub fn response_body_key(request_key: &[u8; 16]) -> [u8; 16] {
    let hash = Sha256::digest(request_key);
    let mut out = [0u8; 16];
    out.copy_from_slice(&hash[..16]);
    out
}

/// Derive the response body IV from the request body IV.
pub fn response_body_iv(request_iv: &[u8; 16]) -> [u8; 16] {
    let hash = Sha256::digest(request_iv);
    let mut out = [0u8; 16];
    out.copy_from_slice(&hash[..16]);
    out
}

// ── Encoder ───────────────────────────────────────────────────────────────────

/// Encode a VMess AEAD request header.
///
/// Returns `(iv, key, v, connection_nonce, enc_len_bytes(18), enc_header_bytes)`.
pub fn encode_header(
    cmd_key: &[u8; 16],
    auth_id: &[u8; 16],
    dest: &Address,
    security: Security,
) -> Result<EncodedHeader, ProxyError> {
    let mut rng = rand::rng();

    let mut iv = [0u8; 16];
    let mut key = [0u8; 16];
    let mut v = [0u8; 1];
    let mut connection_nonce = [0u8; 8];
    rng.fill(&mut iv[..]);
    rng.fill(&mut key[..]);
    rng.fill(&mut v[..]);
    rng.fill(&mut connection_nonce[..]);
    let v_byte = v[0];

    let pad_len: u8 = (rng.next_u32() % 16) as u8;
    let plaintext = build_request_plaintext(&iv, &key, v_byte, pad_len, security, dest)?;

    // Encrypt header with connection_nonce in KDF.
    let hdr_key: [u8; 16] = kdf(cmd_key, &[PATH_HDR_KEY, auth_id, &connection_nonce]);
    let hdr_nonce: [u8; 12] = kdf(cmd_key, &[PATH_HDR_IV, auth_id, &connection_nonce]);

    let enc_header = vmess_aead_encrypt(
        &hdr_key,
        &hdr_nonce,
        &plaintext,
        auth_id,
        "VMess: header ciphertext encrypt failed",
    )?;

    let len_key: [u8; 16] = kdf(cmd_key, &[PATH_LEN_KEY, auth_id, &connection_nonce]);
    let len_nonce: [u8; 12] = kdf(cmd_key, &[PATH_LEN_IV, auth_id, &connection_nonce]);

    let enc_len = vmess_aead_encrypt(
        &len_key,
        &len_nonce,
        &(plaintext.len() as u16).to_be_bytes(),
        auth_id,
        "VMess: header length encrypt failed",
    )?;

    Ok((iv, key, v_byte, connection_nonce, enc_len, enc_header))
}

// ── Decoder helpers ───────────────────────────────────────────────────────────

/// Decrypt the 2-byte header length from the 18-byte encrypted field.
///
/// Requires `connection_nonce` (read from wire after enc_len).
pub fn decrypt_length_field(
    cmd_key: &[u8; 16],
    auth_id: &[u8; 16],
    connection_nonce: &[u8; 8],
    enc: &[u8; 18],
) -> Result<usize, ProxyError> {
    let key: [u8; 16] = kdf(cmd_key, &[PATH_LEN_KEY, auth_id, connection_nonce.as_ref()]);
    let nonce: [u8; 12] = kdf(cmd_key, &[PATH_LEN_IV, auth_id, connection_nonce.as_ref()]);

    let plaintext = vmess_aead_decrypt(
        &key,
        &nonce,
        enc,
        auth_id,
        "VMess: length field decryption failed",
    )?;

    if plaintext.len() < 2 {
        return Err(ProxyError::Protocol("VMess: length field too short".into()));
    }
    Ok(u16::from_be_bytes([plaintext[0], plaintext[1]]) as usize)
}

/// Decrypt and decode a VMess AEAD header from an async stream.
pub async fn decode_header<R: AsyncRead + Unpin>(
    reader: &mut R,
    cmd_key: &[u8; 16],
    auth_id: &[u8; 16],
    connection_nonce: &[u8; 8],
    enc_len: usize,
) -> Result<VmessRequest, ProxyError> {
    let mut ciphertext = vec![0u8; enc_len + 16];
    reader.read_exact(&mut ciphertext).await?;

    let key: [u8; 16] = kdf(cmd_key, &[PATH_HDR_KEY, auth_id, connection_nonce.as_ref()]);
    let nonce: [u8; 12] = kdf(cmd_key, &[PATH_HDR_IV, auth_id, connection_nonce.as_ref()]);

    let plaintext = vmess_aead_decrypt(
        &key,
        &nonce,
        &ciphertext,
        auth_id,
        "VMess: AEAD header decryption failed",
    )?;

    decode_plaintext(&plaintext)
}

// ── Response header helpers ───────────────────────────────────────────────────

/// Send the AEAD-encrypted VMess response header to the client.
///
/// Must be called before sending any data chunks.
/// `resp_body_key` = `response_body_key(request.key)`.
pub async fn send_response_header<W: AsyncWrite + Unpin>(
    writer: &mut W,
    v: u8,
    resp_body_key: &[u8; 16],
    resp_body_iv: &[u8; 16],
) -> Result<(), ProxyError> {
    let plaintext = [v, 0u8, 0u8, 0u8];

    let len_key: [u8; 16] = kdf(resp_body_key, &[PATH_RESP_LEN_KEY]);
    let len_nonce: [u8; 12] = kdf(resp_body_iv, &[PATH_RESP_LEN_IV]);

    let enc_len = vmess_aead_encrypt(
        &len_key,
        &len_nonce,
        &(plaintext.len() as u16).to_be_bytes(),
        &[],
        "VMess: resp header len encrypt failed",
    )?;

    let hdr_key: [u8; 16] = kdf(resp_body_key, &[PATH_RESP_HDR_KEY]);
    let hdr_nonce: [u8; 12] = kdf(resp_body_iv, &[PATH_RESP_HDR_IV]);

    let enc_hdr = vmess_aead_encrypt(
        &hdr_key,
        &hdr_nonce,
        &plaintext,
        &[],
        "VMess: resp header encrypt failed",
    )?;

    writer.write_all(&enc_len).await?;
    writer.write_all(&enc_hdr).await?;
    Ok(())
}

/// Read and verify the AEAD-encrypted VMess response header from the server.
///
/// Called by the outbound (client) after sending the request header.
pub async fn read_response_header<R: AsyncRead + Unpin>(
    reader: &mut R,
    expected_v: u8,
    resp_body_key: &[u8; 16],
    resp_body_iv: &[u8; 16],
) -> Result<(), ProxyError> {
    let len_key: [u8; 16] = kdf(resp_body_key, &[PATH_RESP_LEN_KEY]);
    let len_nonce: [u8; 12] = kdf(resp_body_iv, &[PATH_RESP_LEN_IV]);

    let mut enc_len = [0u8; 18];
    reader.read_exact(&mut enc_len).await?;

    let len_pt = vmess_aead_decrypt(
        &len_key,
        &len_nonce,
        enc_len.as_ref(),
        &[],
        "VMess: resp len decrypt failed",
    )?;
    let payload_len = u16::from_be_bytes([len_pt[0], len_pt[1]]) as usize;

    let hdr_key: [u8; 16] = kdf(resp_body_key, &[PATH_RESP_HDR_KEY]);
    let hdr_nonce: [u8; 12] = kdf(resp_body_iv, &[PATH_RESP_HDR_IV]);

    let mut enc_hdr = vec![0u8; payload_len + 16];
    reader.read_exact(&mut enc_hdr).await?;

    let hdr_pt = vmess_aead_decrypt(
        &hdr_key,
        &hdr_nonce,
        enc_hdr.as_ref(),
        &[],
        "VMess: resp header decrypt failed",
    )?;

    let got_v = hdr_pt.first().copied().unwrap_or(0);
    if got_v != expected_v {
        return Err(ProxyError::Protocol(format!(
            "VMess: response V mismatch: got {got_v:#04x}, expected {expected_v:#04x}"
        )));
    }

    Ok(())
}

// ── Internal ──────────────────────────────────────────────────────────────────

fn vmess_aead_encrypt(
    key: &[u8; 16],
    nonce: &[u8; 12],
    msg: &[u8],
    aad: &[u8],
    err: &str,
) -> Result<Vec<u8>, ProxyError> {
    let cipher = Aes128Gcm::new(GenericArray::from_slice(key));
    cipher
        .encrypt(GenericArray::from_slice(nonce), Payload { msg, aad })
        .map_err(|_| ProxyError::Protocol(err.into()))
}

fn vmess_aead_decrypt(
    key: &[u8; 16],
    nonce: &[u8; 12],
    ciphertext: &[u8],
    aad: &[u8],
    err: &str,
) -> Result<Vec<u8>, ProxyError> {
    let cipher = Aes128Gcm::new(GenericArray::from_slice(key));
    cipher
        .decrypt(
            GenericArray::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| ProxyError::Protocol(err.into()))
}

fn build_request_plaintext(
    iv: &[u8; 16],
    key: &[u8; 16],
    v: u8,
    pad_len: u8,
    security: Security,
    dest: &Address,
) -> Result<Vec<u8>, ProxyError> {
    let mut buf = BytesMut::new();
    buf.put_u8(0x01); // version
    buf.put_slice(iv);
    buf.put_slice(key);
    buf.put_u8(v);
    buf.put_u8(0x01); // options: ChunkStream
    buf.put_u8((pad_len << 4) | (security as u8));
    buf.put_u8(0x00); // reserved
    buf.put_u8(0x01); // command: TCP

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
            buf.put_u8(domain_wire_len(name)?);
            buf.put_slice(name.as_bytes());
        }
    }

    let mut pad = vec![0u8; pad_len as usize];
    rand::rng().fill(&mut pad[..]);
    buf.put_slice(&pad);

    let checksum = fnv32a(buf.as_ref());
    buf.put_u32(checksum);

    Ok(buf.to_vec())
}

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
    let options = data[34];
    let pad_sec = data[35];
    let pad_len = (pad_sec >> 4) as usize;
    let security = Security::try_from(pad_sec & 0x0F)?;
    let cmd = data[37];

    let mut pos = 38;

    if pos + 2 > data.len() {
        return Err(ProxyError::Protocol("VMess: truncated at port".into()));
    }
    let port = u16::from_be_bytes([data[pos], data[pos + 1]]);
    pos += 2;

    let dest = match cmd {
        CMD_TCP | CMD_UDP => {
            if pos >= data.len() {
                return Err(ProxyError::Protocol("VMess: truncated at atyp".into()));
            }
            let atyp = data[pos];
            pos += 1;
            read_vmess_address(data, &mut pos, atyp, port)?
        }
        CMD_MUX => {
            if pos >= data.len() {
                return Err(ProxyError::Protocol("VMess: truncated at atyp".into()));
            }
            let atyp = data[pos];
            pos += 1;
            let _ = read_vmess_address(data, &mut pos, atyp, port)?;
            Address::Domain(MUX_DOMAIN.to_string(), port)
        }
        other => {
            return Err(ProxyError::Protocol(format!(
                "VMess: unknown command {other:#x}"
            )));
        }
    };

    pos += pad_len;

    if pos + 4 > data.len() {
        return Err(ProxyError::Protocol("VMess: truncated checksum".into()));
    }
    let expected = fnv32a(&data[..pos]);
    let received = read_u32_be(data, pos)?;
    if expected != received {
        return Err(ProxyError::Protocol(
            "VMess: header checksum mismatch".into(),
        ));
    }

    Ok(VmessRequest {
        iv,
        key,
        v,
        options,
        security,
        dest,
    })
}

fn read_vmess_address(
    data: &[u8],
    pos: &mut usize,
    atyp: u8,
    port: u16,
) -> Result<Address, ProxyError> {
    match atyp {
        ATYP_IPV4 => {
            if *pos + 4 > data.len() {
                return Err(ProxyError::Protocol("VMess: truncated IPv4".into()));
            }
            let ip =
                std::net::Ipv4Addr::new(data[*pos], data[*pos + 1], data[*pos + 2], data[*pos + 3]);
            *pos += 4;
            Ok(Address::Ipv4(ip, port))
        }
        ATYP_IPV6 => {
            if *pos + 16 > data.len() {
                return Err(ProxyError::Protocol("VMess: truncated IPv6".into()));
            }
            let mut ip6 = [0u8; 16];
            ip6.copy_from_slice(&data[*pos..*pos + 16]);
            *pos += 16;
            Ok(Address::Ipv6(std::net::Ipv6Addr::from(ip6), port))
        }
        ATYP_DOMAIN => {
            if *pos >= data.len() {
                return Err(ProxyError::Protocol("VMess: truncated domain len".into()));
            }
            let dlen = data[*pos] as usize;
            *pos += 1;
            if *pos + dlen > data.len() {
                return Err(ProxyError::Protocol("VMess: truncated domain".into()));
            }
            let domain = std::str::from_utf8(&data[*pos..*pos + dlen])
                .map_err(|_| ProxyError::Protocol("VMess: domain not UTF-8".into()))?
                .to_string();
            *pos += dlen;
            Ok(Address::Domain(domain, port))
        }
        other => Err(ProxyError::Protocol(format!(
            "VMess: unknown ATYP {other:#x}"
        ))),
    }
}

fn read_u32_be(data: &[u8], pos: usize) -> Result<u32, ProxyError> {
    if pos + 4 > data.len() {
        return Err(ProxyError::Protocol("VMess: truncated u32 field".into()));
    }
    let bytes: [u8; 4] = data[pos..pos + 4]
        .try_into()
        .map_err(|_| ProxyError::Protocol("VMess: truncated u32 field".into()))?;
    Ok(u32::from_be_bytes(bytes))
}

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
    use blackwire_common::Address;

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
        assert_eq!(fnv32a(b""), 0x811c_9dc5);
    }

    #[test]
    fn encode_decode_header_roundtrip() {
        let cmd_key = test_cmd_key();
        let auth_id = test_auth_id();
        let dest = Address::Domain("test.example.com".to_string(), 443);

        let (_iv, _key, _v, connection_nonce, enc_len, enc_header) =
            encode_header(&cmd_key, &auth_id, &dest, Security::Aes128Gcm).unwrap();

        let enc_len_arr: [u8; 18] = enc_len.try_into().unwrap();
        let header_len =
            decrypt_length_field(&cmd_key, &auth_id, &connection_nonce, &enc_len_arr).unwrap();
        assert_eq!(header_len + 16, enc_header.len());

        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut cursor = std::io::Cursor::new(enc_header.clone());
            let req = decode_header(
                &mut cursor,
                &cmd_key,
                &auth_id,
                &connection_nonce,
                header_len,
            )
            .await
            .unwrap();
            assert_eq!(req.dest, dest);
        });
    }

    #[test]
    fn response_key_differs_from_request_key() {
        let key = [0x42u8; 16];
        let resp_key = response_body_key(&key);
        assert_ne!(resp_key, key);
    }
}
