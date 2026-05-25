use anyhow::Result;
use proxy_common::ProxyError;

/// Parsed fields from a TLS ClientHello.
///
/// REALITY only needs a tiny subset of the full TLS structure. The raw
/// ClientHello bytes remain outside this struct so the server can build the AAD.
pub struct ClientHelloFields {
    /// The 32-byte `random` field. Used as HKDF salt and AES-GCM nonce material.
    pub random: [u8; 32],

    /// The 32-byte `session_id` field containing ciphertext plus GCM tag.
    pub session_id: [u8; 32],

    /// The client's X25519 public key from the `key_share` extension.
    pub x25519_key_share: [u8; 32],

    /// The SNI hostname from the `server_name` extension.
    pub sni: String,
}

/// Byte index of `session_id` length in a ClientHello handshake body (after `random`).
pub(crate) const CLIENT_HELLO_SESSION_ID_LEN_OFFSET: usize = 38;

/// Parse a TLS ClientHello from its handshake body.
///
/// The input starts after the 5-byte TLS record header, so byte 0 is the TLS
/// handshake type. This parser intentionally extracts only fields REALITY uses.
pub fn parse_client_hello(body: &[u8]) -> Result<ClientHelloFields> {
    parse_client_hello_impl(body).map_err(|e| anyhow::anyhow!("{e}"))
}

fn parse_client_hello_impl(body: &[u8]) -> Result<ClientHelloFields, ProxyError> {
    if body.len() < 71 {
        return Err(ProxyError::Protocol(format!(
            "ClientHello body too short: {} bytes",
            body.len()
        )));
    }
    if body[0] != 0x01 {
        return Err(ProxyError::Protocol(format!(
            "expected ClientHello (0x01), got {:#04x}",
            body[0]
        )));
    }

    let mut pos = 6; // handshake_type(1) + length(3) + legacy_version(2)
    let random: [u8; 32] = body[pos..pos + 32]
        .try_into()
        .map_err(|_| ProxyError::Protocol("truncated random field".into()))?;
    pos += 32;

    let sid_len = body[pos] as usize;
    pos += 1;
    if sid_len != 32 {
        return Err(ProxyError::Protocol(format!(
            "session_id_len must be 32, got {sid_len}"
        )));
    }

    let session_id: [u8; 32] = body[pos..pos + 32]
        .try_into()
        .map_err(|_| ProxyError::Protocol("truncated session_id field".into()))?;
    pos += 32;

    pos = skip_cipher_suites(body, pos)?;
    pos = skip_compression_methods(body, pos)?;

    if pos + 2 > body.len() {
        return Err(ProxyError::Protocol("truncated at extensions_len".into()));
    }
    pos += 2;

    let mut x25519_key_share = None;
    let mut sni = String::new();

    while pos + 4 <= body.len() {
        let ext_type = u16::from_be_bytes([body[pos], body[pos + 1]]);
        let ext_len = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
        pos += 4;

        if pos + ext_len > body.len() {
            return Err(ProxyError::Protocol("truncated extension data".into()));
        }
        let ext_data = &body[pos..pos + ext_len];
        pos += ext_len;

        if ext_type == 0x0000 {
            sni = parse_sni(ext_data);
        } else if ext_type == 0x0033 {
            x25519_key_share = first_x25519_key_share(ext_data);
        }
    }

    Ok(ClientHelloFields {
        random,
        session_id,
        x25519_key_share: x25519_key_share.ok_or_else(|| {
            ProxyError::Protocol("no x25519 key share found in ClientHello".into())
        })?,
        sni,
    })
}

/// Session ID bytes from a ClientHello handshake body.
pub(crate) fn client_hello_session_id(body: &[u8]) -> Result<&[u8], ProxyError> {
    if body.len() < CLIENT_HELLO_SESSION_ID_LEN_OFFSET + 1 {
        return Err(ProxyError::Protocol(
            "ClientHello too short for session_id".into(),
        ));
    }
    let sid_len = body[CLIENT_HELLO_SESSION_ID_LEN_OFFSET] as usize;
    let start = CLIENT_HELLO_SESSION_ID_LEN_OFFSET + 1;
    let end = start + sid_len;
    if end > body.len() {
        return Err(ProxyError::Protocol(
            "ClientHello session_id truncated".into(),
        ));
    }
    Ok(&body[start..end])
}

/// Cipher suite list bytes from a ClientHello handshake body.
pub(crate) fn client_hello_cipher_suites(body: &[u8]) -> Result<&[u8], ProxyError> {
    if body.len() < CLIENT_HELLO_SESSION_ID_LEN_OFFSET + 1 {
        return Err(ProxyError::Protocol("ClientHello too short".into()));
    }
    let sid_len = body[CLIENT_HELLO_SESSION_ID_LEN_OFFSET] as usize;
    let mut pos = CLIENT_HELLO_SESSION_ID_LEN_OFFSET + 1 + sid_len;
    if pos + 2 > body.len() {
        return Err(ProxyError::Protocol(
            "ClientHello: cipher_suites_len".into(),
        ));
    }
    let cs_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;
    if pos + cs_len > body.len() {
        return Err(ProxyError::Protocol("ClientHello: cipher_suites".into()));
    }
    Ok(&body[pos..pos + cs_len])
}

fn skip_cipher_suites(body: &[u8], mut pos: usize) -> Result<usize, ProxyError> {
    if pos + 2 > body.len() {
        return Err(ProxyError::Protocol(
            "truncated at cipher_suites_len".into(),
        ));
    }
    let cs_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2 + cs_len;
    if pos > body.len() {
        return Err(ProxyError::Protocol("truncated cipher_suites".into()));
    }
    Ok(pos)
}

fn skip_compression_methods(body: &[u8], mut pos: usize) -> Result<usize, ProxyError> {
    if pos >= body.len() {
        return Err(ProxyError::Protocol(
            "truncated at compression_methods_len".into(),
        ));
    }
    let comp_len = body[pos] as usize;
    pos += 1 + comp_len;
    if pos > body.len() {
        return Err(ProxyError::Protocol("truncated compression_methods".into()));
    }
    Ok(pos)
}

fn parse_sni(ext_data: &[u8]) -> String {
    if ext_data.len() < 5 {
        return String::new();
    }
    let name_len = u16::from_be_bytes([ext_data[3], ext_data[4]]) as usize;
    if ext_data.len() < 5 + name_len {
        return String::new();
    }
    String::from_utf8_lossy(&ext_data[5..5 + name_len]).into_owned()
}

/// TLS named group: X25519 (0x001d = 29).
const GROUP_X25519: u16 = 29;
/// TLS named group: X25519MLKEM768 (draft). Chrome / sing-box may offer this first.
const GROUP_X25519_MLKEM768: u16 = 0x11ec;

/// Public keys used for REALITY auth ECDH, in Xray server preference order.
pub(crate) fn reality_auth_peer_public_keys(body: &[u8]) -> Vec<[u8; 32]> {
    let Some(ext_data) = key_share_extension_data(body) else {
        return Vec::new();
    };
    collect_x25519_auth_keys(ext_data)
}

fn key_share_extension_data(body: &[u8]) -> Option<&[u8]> {
    if body.len() < CLIENT_HELLO_SESSION_ID_LEN_OFFSET + 1 || body[0] != 0x01 {
        return None;
    }
    let sid_len = body[CLIENT_HELLO_SESSION_ID_LEN_OFFSET] as usize;
    let mut pos = CLIENT_HELLO_SESSION_ID_LEN_OFFSET + 1 + sid_len;
    if pos + 2 > body.len() {
        return None;
    }
    let cs_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2 + cs_len;
    if pos >= body.len() {
        return None;
    }
    let comp_len = body[pos] as usize;
    pos += 1 + comp_len;
    if pos + 2 > body.len() {
        return None;
    }
    let ext_total = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;
    let ext_end = (pos + ext_total).min(body.len());
    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([body[pos], body[pos + 1]]);
        let ext_len = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
        pos += 4;
        if pos + ext_len > body.len() {
            break;
        }
        if ext_type == 0x0033 {
            return Some(&body[pos..pos + ext_len]);
        }
        pos += ext_len;
    }
    None
}

fn first_x25519_key_share(ext_data: &[u8]) -> Option<[u8; 32]> {
    collect_x25519_auth_keys(ext_data).into_iter().next()
}

fn collect_x25519_auth_keys(ext_data: &[u8]) -> Vec<[u8; 32]> {
    if ext_data.len() < 2 {
        return Vec::new();
    }

    let mut standalone_x25519 = None;
    let mut mlkem_tail = None;
    let shares_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
    let mut pos = 2;
    while pos + 4 <= 2 + shares_len && pos + 4 <= ext_data.len() {
        let group = u16::from_be_bytes([ext_data[pos], ext_data[pos + 1]]);
        let key_len = u16::from_be_bytes([ext_data[pos + 2], ext_data[pos + 3]]) as usize;
        pos += 4;
        if pos + key_len > ext_data.len() {
            break;
        }
        if group == GROUP_X25519 && key_len == 32 {
            let mut key = [0u8; 32];
            key.copy_from_slice(&ext_data[pos..pos + 32]);
            standalone_x25519 = Some(key);
        } else if group == GROUP_X25519_MLKEM768 && key_len >= 32 {
            let mut key = [0u8; 32];
            key.copy_from_slice(&ext_data[pos + key_len - 32..pos + key_len]);
            mlkem_tail = Some(key);
        }
        pos += key_len;
    }

    let mut out = Vec::new();
    if let Some(k) = standalone_x25519 {
        out.push(k);
    }
    if let Some(k) = mlkem_tail {
        if standalone_x25519 != Some(k) {
            out.push(k);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use proxy_tls::ClientHelloBuilder;

    #[test]
    fn parse_builder_output() {
        let random = [0x11u8; 32];
        let session_id = [0x22u8; 32];
        let mut rng = rand::thread_rng();

        let hello = ClientHelloBuilder::chrome_131().build(
            "www.example.com",
            &random,
            &session_id,
            None,
            &mut rng,
        );
        let fields = parse_client_hello(&hello[5..]).expect("parse_client_hello failed");

        assert_eq!(fields.random, random);
        assert_eq!(fields.session_id, session_id);
        assert_eq!(fields.sni, "www.example.com");
    }

    #[test]
    fn parse_truncated_input_returns_error() {
        assert!(parse_client_hello(&[]).is_err());
        assert!(parse_client_hello(&[0x01, 0x00, 0x00, 0x10]).is_err());
    }

    #[test]
    fn parse_wrong_handshake_type_returns_error() {
        let mut body = vec![0x02u8];
        body.extend(vec![0u8; 80]);
        assert!(parse_client_hello(&body).is_err());
    }
}
