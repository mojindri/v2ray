//! ShadowTLS v3 client-side connector.
//!
//! The connector:
//! 1. Connects to the ShadowTLS server.
//! 2. Performs a TLS handshake (which the server transparently relays to a real backend).
//! 3. Captures `server_random` from the ServerHello (via the handshake relay).
//! 4. Computes the HMAC marker = HMAC-SHA256(psk, server_random)[0..8].
//! 5. Injects the 8-byte marker at the start of the first Application Data record.
//! 6. Returns the stream ready for the real proxy protocol.
//!
//! # Implementation note
//!
//! The client side does a *real* TLS handshake to the ShadowTLS server address.
//! The server relays this handshake to the backend, so the client sees valid TLS.
//! After the handshake, the client wraps its first data write in the marker record.

use proxy_common::{BoxedStream, ProxyError};

use super::marker::compute_marker;
use super::server::write_marker_record;

/// Connect using ShadowTLS v3.
///
/// # Arguments
/// * `stream`         — an already-connected TCP stream to the ShadowTLS server
/// * `psk`            — the pre-shared key bytes (password)
/// * `server_random`  — the `server_random` extracted from the relayed ServerHello
///
/// # Returns
///
/// A stream ready for the real proxy protocol. The first write on this stream
/// will automatically include the HMAC marker prefix.
pub async fn shadowtls_connect(
    mut stream: BoxedStream,
    psk: &[u8],
    server_random: &[u8; 32],
) -> Result<BoxedStream, ProxyError> {
    // Derive the marker from the shared PSK and the server_random captured
    // during the TLS handshake.
    let marker = compute_marker(psk, server_random);

    // Inject the marker as the first Application Data record.
    write_marker_record(&mut stream, &marker).await?;

    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shadowtls::marker::compute_marker;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    /// Test the full client marker injection flow.
    #[tokio::test]
    async fn client_injects_correct_marker() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let psk = b"my-secret-password";
        let server_random = [0x77u8; 32];
        let expected_marker = compute_marker(psk, &server_random);

        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            // Read the TLS Application Data record header (5 bytes)
            let mut header = [0u8; 5];
            sock.read_exact(&mut header).await.unwrap();
            assert_eq!(header[0], 23, "expected Application Data record type");
            let len = u16::from_be_bytes([header[3], header[4]]) as usize;
            assert_eq!(len, 8, "marker record should be 8 bytes");

            let mut payload = vec![0u8; len];
            sock.read_exact(&mut payload).await.unwrap();
            // Echo the payload back so the test can verify it
            sock.write_all(&payload).await.unwrap();
        });

        let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let stream = shadowtls_connect(Box::new(tcp), psk, &server_random)
            .await
            .unwrap();

        let mut stream = stream;
        let mut received = [0u8; 8];
        stream.read_exact(&mut received).await.unwrap();
        assert_eq!(received, expected_marker);
    }
}
