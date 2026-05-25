//! ShadowTLS v3 server-side acceptor.
//!
//! The acceptor:
//! 1. Accepts a TCP connection from a client.
//! 2. Relays the TLS handshake transparently to a real backend (e.g. `www.apple.com:443`).
//! 3. While relaying, extracts `server_random` from the ServerHello.
//! 4. Computes the expected HMAC marker = HMAC-SHA256(psk, server_random)[0..8].
//! 5. After the handshake, scans the client→server stream for the 8-byte marker
//!    at the start of the first Application Data record payload.
//! 6. Once detected, returns the stream positioned after the marker so the real
//!    proxy protocol (e.g. VLESS) can take over.

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use blackwire_common::{BoxedStream, ProxyError};

use super::fuzzing::validate_first_application_record;
use super::handshake::relay_v3_handshake;
use super::marker::compute_marker;
use super::pseudo_server_random;
use super::v3::V3Stream;

/// Accept a ShadowTLS v3 connection.
///
/// # Arguments
/// * `stream`   — the inbound TCP stream from the client
/// * `psk`      — the pre-shared key bytes (password)
/// * `backend`  — the real TLS backend address, e.g. `"www.apple.com:443"`
///
/// # Returns
///
/// On success, returns a `BoxedStream` positioned just after the HMAC marker.
/// The caller should hand this stream to the real proxy protocol handler.
pub async fn shadowtls_accept(
    mut stream: BoxedStream,
    psk: &[u8],
    backend: &str,
) -> Result<BoxedStream, ProxyError> {
    let (server_random, first_client_record) =
        relay_v3_handshake(&mut stream, psk, backend).await?;
    V3Stream::server_after_first_client_record(stream, psk, &server_random, &first_client_record)
}

/// Accept the repo's current ShadowTLS marker transport.
///
/// This validates and strips the first marker record without relaying a real
/// TLS handshake. It is intentionally separate from `shadowtls_accept` so the
/// eventual full v3 implementation has a clean upgrade path.
pub async fn shadowtls_marker_accept(
    mut stream: BoxedStream,
    psk: &[u8],
    dest: &str,
) -> Result<BoxedStream, ProxyError> {
    let server_random = pseudo_server_random(dest);
    let expected_marker = compute_marker(psk, &server_random);

    let mut header = [0u8; 5];
    stream
        .read_exact(&mut header)
        .await
        .map_err(|e| ProxyError::Transport(format!("ShadowTLS marker: read header: {e}")))?;

    let payload_len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let mut record = header.to_vec();
    record.resize(5 + payload_len, 0);
    stream
        .read_exact(&mut record[5..])
        .await
        .map_err(|e| ProxyError::Transport(format!("ShadowTLS marker: read payload: {e}")))?;

    let prefix = validate_first_application_record(&expected_marker, &record)?;
    if prefix.is_empty() {
        Ok(stream)
    } else {
        Ok(Box::new(blackwire_common::PrependedStream::new(
            stream, prefix,
        )))
    }
}

/// Write the 8-byte marker as the first bytes of a new Application Data record.
///
/// Used by the client side after the TLS handshake to inject the marker.
pub async fn write_marker_record(
    stream: &mut BoxedStream,
    marker: &[u8; 8],
) -> Result<(), ProxyError> {
    // TLS Application Data record header: type=23, version=0x0303, len=8
    let header = [0x17u8, 0x03, 0x03, 0x00, 0x08];
    stream
        .write_all(&header)
        .await
        .map_err(|e| ProxyError::Transport(format!("ShadowTLS: write marker header: {e}")))?;
    stream
        .write_all(marker)
        .await
        .map_err(|e| ProxyError::Transport(format!("ShadowTLS: write marker: {e}")))?;
    stream
        .flush()
        .await
        .map_err(|e| ProxyError::Transport(format!("ShadowTLS: flush marker: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shadowtls::marker::compute_marker;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    /// Test that `write_marker_record` produces a valid TLS Application Data record.
    #[tokio::test]
    async fn write_marker_produces_correct_record() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let psk = b"test-psk";
        let server_random = [0x42u8; 32];
        let marker = compute_marker(psk, &server_random);

        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut header = [0u8; 5];
            sock.read_exact(&mut header).await.unwrap();
            assert_eq!(header[0], 23); // Application Data
            let len = u16::from_be_bytes([header[3], header[4]]) as usize;
            assert_eq!(len, 8);
            let mut payload = vec![0u8; len];
            sock.read_exact(&mut payload).await.unwrap();
            // Send back what we read for verification
            sock.write_all(&payload).await.unwrap();
        });

        let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let mut stream: BoxedStream = Box::new(tcp);
        write_marker_record(&mut stream, &marker).await.unwrap();

        let mut recv = [0u8; 8];
        stream.read_exact(&mut recv).await.unwrap();
        assert_eq!(recv, marker);
    }
}
