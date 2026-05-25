use proxy_common::ProxyError;

use super::marker::markers_equal;

const APPLICATION_DATA_TYPE: u8 = 23;
const TLS_HEADER_LEN: usize = 5;
const MARKER_LEN: usize = 8;

/// Validate the first TLS Application Data record and return bytes after the marker.
///
/// This is a fuzz-only helper so libFuzzer can hammer the marker parser
/// without needing live sockets or a real backend TLS handshake.
pub fn validate_first_application_record(
    expected_marker: &[u8; 8],
    first_record: &[u8],
) -> Result<Vec<u8>, ProxyError> {
    if first_record.len() < TLS_HEADER_LEN {
        return Err(ProxyError::Protocol(
            "ShadowTLS: truncated Application Data header".into(),
        ));
    }

    if first_record[0] != APPLICATION_DATA_TYPE {
        return Err(ProxyError::Protocol(format!(
            "ShadowTLS: expected Application Data (23), got {}",
            first_record[0]
        )));
    }

    let payload_len = u16::from_be_bytes([first_record[3], first_record[4]]) as usize;
    let total_len = TLS_HEADER_LEN + payload_len;
    if first_record.len() < total_len {
        return Err(ProxyError::Protocol(
            "ShadowTLS: truncated Application Data payload".into(),
        ));
    }
    if payload_len < MARKER_LEN {
        return Err(ProxyError::Protocol(
            "ShadowTLS: first Application Data too short to contain marker".into(),
        ));
    }

    let payload = &first_record[TLS_HEADER_LEN..total_len];
    let mut candidate = [0u8; MARKER_LEN];
    candidate.copy_from_slice(&payload[..MARKER_LEN]);

    if !markers_equal(expected_marker, &candidate) {
        return Err(ProxyError::AuthFailed);
    }

    Ok(payload[MARKER_LEN..].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_record_returns_remaining_payload() {
        let marker = [0x42u8; MARKER_LEN];
        let payload = b"hello";
        let payload_len = MARKER_LEN + payload.len();
        let mut record = vec![APPLICATION_DATA_TYPE, 0x03, 0x03];
        record.extend_from_slice(&(payload_len as u16).to_be_bytes());
        record.extend_from_slice(&marker);
        record.extend_from_slice(payload);

        let rest = validate_first_application_record(&marker, &record).unwrap();
        assert_eq!(rest, payload);
    }
}
