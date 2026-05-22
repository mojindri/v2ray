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

use proxy_common::{BoxedStream, ProxyError};

use super::handshake::relay_handshake;
use super::marker::compute_marker;

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
    // Phase 1: Relay the TLS handshake and capture server_random.
    let (server_random, _) = relay_handshake(&mut stream, backend).await?;

    // Phase 2: Compute the expected HMAC marker.
    let expected_marker = compute_marker(psk, &server_random);

    // Phase 3: Read and verify the marker from the next client bytes.
    // The client sends the marker as the first 8 bytes of its first
    // Application Data record payload (after the 5-byte TLS record header).
    //
    // We read a 5-byte TLS header first, then verify the first 8 bytes of payload.
    let mut header = [0u8; 5];
    stream
        .read_exact(&mut header)
        .await
        .map_err(|e| ProxyError::Transport(format!("ShadowTLS server: read app header: {e}")))?;

    let record_type = header[0];
    if record_type != 23 {
        return Err(ProxyError::Protocol(format!(
            "ShadowTLS: expected Application Data (23), got {record_type}"
        )));
    }

    let payload_len = u16::from_be_bytes([header[3], header[4]]) as usize;
    if payload_len < 8 {
        return Err(ProxyError::Protocol(
            "ShadowTLS: first Application Data too short to contain marker".into(),
        ));
    }

    // Read the marker bytes.
    let mut marker_buf = [0u8; 8];
    stream
        .read_exact(&mut marker_buf)
        .await
        .map_err(|e| ProxyError::Transport(format!("ShadowTLS server: read marker: {e}")))?;

    if marker_buf != expected_marker {
        return Err(ProxyError::AuthFailed);
    }

    // Read the rest of the first application data payload (if any).
    let remaining = payload_len - 8;
    let prefix = if remaining > 0 {
        let mut rest = vec![0u8; remaining];
        stream.read_exact(&mut rest).await.map_err(|e| {
            ProxyError::Transport(format!("ShadowTLS server: read payload rest: {e}"))
        })?;
        rest
    } else {
        vec![]
    };

    // Prepend the remaining bytes so the protocol handler sees the full payload.
    if prefix.is_empty() {
        Ok(stream)
    } else {
        Ok(Box::new(proxy_common::PrependedStream::new(stream, prefix)))
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
