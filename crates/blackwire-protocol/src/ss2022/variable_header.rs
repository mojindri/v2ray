//! SIP022 request variable header: SOCKS5-style address + padding length.

use blackwire_common::{decode_socks5_address, write_socks5_address, Address, ProxyError};

/// Build the SIP022 request variable header plaintext.
///
/// ```text
/// atyp(1) | addr | port(2 BE) | padding_len(2 BE)=0 | initial_payload(empty)
/// ```
pub fn build_request_variable_header(dest: &Address) -> Result<Vec<u8>, ProxyError> {
    let mut buf = Vec::with_capacity(32);
    write_socks5_address(&mut buf, dest)?;
    buf.extend_from_slice(&0u16.to_be_bytes());
    Ok(buf)
}

/// Parse variable header plaintext after decryption.
///
/// Returns destination address and any initial payload bytes after padding.
pub fn parse_variable_header(data: &[u8]) -> Result<(Address, Vec<u8>), ProxyError> {
    if data.is_empty() {
        return Err(ProxyError::Protocol(
            "SS-2022: empty variable header".into(),
        ));
    }
    let atyp = data[0];
    let (dest, consumed) = decode_socks5_address(&data[1..], atyp, "SS-2022")?;
    let pos = 1 + consumed;
    if pos + 2 > data.len() {
        return Err(ProxyError::Protocol(
            "SS-2022: truncated padding length".into(),
        ));
    }
    let pad_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    let pos = pos + 2;
    if pos + pad_len > data.len() {
        return Err(ProxyError::Protocol("SS-2022: truncated padding".into()));
    }
    let pos = pos + pad_len;
    Ok((dest, data[pos..].to_vec()))
}
