use anyhow::Result;

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

/// Parse a TLS ClientHello from its handshake body.
///
/// The input starts after the 5-byte TLS record header, so byte 0 is the TLS
/// handshake type. This parser intentionally extracts only fields REALITY uses.
pub fn parse_client_hello(body: &[u8]) -> Result<ClientHelloFields> {
    anyhow::ensure!(
        body.len() >= 71,
        "ClientHello body too short: {} bytes",
        body.len()
    );
    anyhow::ensure!(
        body[0] == 0x01,
        "expected ClientHello (0x01), got {:#04x}",
        body[0]
    );

    let mut pos = 6; // handshake_type(1) + length(3) + legacy_version(2)
    let random: [u8; 32] = body[pos..pos + 32]
        .try_into()
        .map_err(|_| anyhow::anyhow!("truncated random field"))?;
    pos += 32;

    let sid_len = body[pos] as usize;
    pos += 1;
    anyhow::ensure!(sid_len == 32, "session_id_len must be 32, got {sid_len}");

    let session_id: [u8; 32] = body[pos..pos + 32]
        .try_into()
        .map_err(|_| anyhow::anyhow!("truncated session_id field"))?;
    pos += 32;

    pos = skip_cipher_suites(body, pos)?;
    pos = skip_compression_methods(body, pos)?;

    anyhow::ensure!(pos + 2 <= body.len(), "truncated at extensions_len");
    pos += 2;

    let mut x25519_key_share = None;
    let mut sni = String::new();

    while pos + 4 <= body.len() {
        let ext_type = u16::from_be_bytes([body[pos], body[pos + 1]]);
        let ext_len = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
        pos += 4;

        anyhow::ensure!(pos + ext_len <= body.len(), "truncated extension data");
        let ext_data = &body[pos..pos + ext_len];
        pos += ext_len;

        match ext_type {
            0x0000 => sni = parse_sni(ext_data),
            0x0033 => x25519_key_share = parse_x25519_key_share(ext_data),
            _ => {}
        }
    }

    Ok(ClientHelloFields {
        random,
        session_id,
        x25519_key_share: x25519_key_share
            .ok_or_else(|| anyhow::anyhow!("no x25519 key share found in ClientHello"))?,
        sni,
    })
}

fn skip_cipher_suites(body: &[u8], mut pos: usize) -> Result<usize> {
    anyhow::ensure!(pos + 2 <= body.len(), "truncated at cipher_suites_len");
    let cs_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2 + cs_len;
    anyhow::ensure!(pos <= body.len(), "truncated cipher_suites");
    Ok(pos)
}

fn skip_compression_methods(body: &[u8], mut pos: usize) -> Result<usize> {
    anyhow::ensure!(pos < body.len(), "truncated at compression_methods_len");
    let comp_len = body[pos] as usize;
    pos += 1 + comp_len;
    anyhow::ensure!(pos <= body.len(), "truncated compression_methods");
    Ok(pos)
}

fn parse_sni(ext_data: &[u8]) -> String {
    // server_name body: list_len(2) + name_type(1) + name_len(2) + name_bytes.
    if ext_data.len() < 5 {
        return String::new();
    }
    let name_len = u16::from_be_bytes([ext_data[3], ext_data[4]]) as usize;
    if ext_data.len() < 5 + name_len {
        return String::new();
    }
    String::from_utf8_lossy(&ext_data[5..5 + name_len]).into_owned()
}

fn parse_x25519_key_share(ext_data: &[u8]) -> Option<[u8; 32]> {
    // key_share body: client_shares_len(2) + [group(2) + key_len(2) + key_bytes]*.
    if ext_data.len() < 2 {
        return None;
    }

    let shares_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
    let mut pos = 2;
    while pos + 4 <= 2 + shares_len && pos + 4 <= ext_data.len() {
        let group = u16::from_be_bytes([ext_data[pos], ext_data[pos + 1]]);
        let key_len = u16::from_be_bytes([ext_data[pos + 2], ext_data[pos + 3]]) as usize;
        pos += 4;

        if pos + key_len > ext_data.len() {
            break;
        }
        if group == 29 && key_len == 32 {
            let mut key = [0u8; 32];
            key.copy_from_slice(&ext_data[pos..pos + 32]);
            return Some(key);
        }
        pos += key_len;
    }

    None
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
