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
use proxy_tls::ClientHelloBuilder;
use rand::RngExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::marker::compute_marker;
use super::pseudo_server_random;
use super::server::write_marker_record;
use super::v3::{
    server_random_from_server_hello_record, sign_client_hello_session_id, V3FrameDecoder,
    V3FrameKind, V3Stream,
};

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

/// Connect using the repo's current ShadowTLS marker transport.
///
/// This is not full upstream ShadowTLS v3 interop. It uses a deterministic
/// pseudo server_random derived from `dest` so both local peers can compute the
/// same marker without a relayed TLS handshake. Keep it behind local e2e tests
/// until the real handshake relay is completed.
pub async fn shadowtls_marker_connect(
    stream: BoxedStream,
    psk: &[u8],
    dest: &str,
) -> Result<BoxedStream, ProxyError> {
    let server_random = pseudo_server_random(dest);
    shadowtls_connect(stream, psk, &server_random).await
}

/// Connect using upstream-style ShadowTLS v3 framing.
///
/// This sends a signed Chrome-like ClientHello, waits until the server proves
/// knowledge of the PSK by tainting a backend TLS ApplicationData record, then
/// switches the stream to ShadowTLS v3 rolling-HMAC data frames.
pub async fn shadowtls_v3_connect(
    mut stream: BoxedStream,
    psk: &[u8],
    dest: &str,
) -> Result<BoxedStream, ProxyError> {
    let sni = shadowtls_sni_from_dest(dest)?;
    let client_hello = {
        let mut rng = rand::rng();
        let mut random = [0u8; 32];
        let session_id = [0u8; 32];
        rng.fill(&mut random[..]);

        let mut client_hello = ClientHelloBuilder::chrome_131()
            .build(sni, &random, &session_id, None, &mut rng)
            .to_vec();
        sign_client_hello_session_id(&mut client_hello, psk, &mut rng)?;
        client_hello
    };

    stream
        .write_all(&client_hello)
        .await
        .map_err(|e| ProxyError::Transport(format!("ShadowTLS v3: write ClientHello: {e}")))?;
    stream
        .flush()
        .await
        .map_err(|e| ProxyError::Transport(format!("ShadowTLS v3: flush ClientHello: {e}")))?;

    let mut server_random = None;
    let mut decoder = None;
    loop {
        let record = read_tls_record(&mut stream).await?;
        if server_random.is_none() {
            server_random = server_random_from_server_hello_record(&record);
            if let Some(sr) = server_random {
                decoder = Some(V3FrameDecoder::server_to_client(psk, &sr));
            }
            continue;
        }

        if record.first() != Some(&0x17) {
            continue;
        }

        let Some(sr) = server_random else {
            return Err(ProxyError::Protocol(
                "ShadowTLS v3 missing server_random before ApplicationData".into(),
            ));
        };
        let Some(decoder) = decoder.as_mut() else {
            return Err(ProxyError::Protocol(
                "ShadowTLS v3 decoder not initialized".into(),
            ));
        };
        match decoder.decode_application_data(&record) {
            Ok((V3FrameKind::ResidualHandshake, _)) => {
                let decoder = decoder.clone();
                return Ok(Box::new(V3Stream::client_after_residual(
                    stream, psk, &sr, decoder,
                )));
            }
            Ok((V3FrameKind::Data, data)) => {
                let decoder = decoder.clone();
                let framed = V3Stream::client_after_residual(stream, psk, &sr, decoder);
                if data.is_empty() {
                    return Ok(Box::new(framed));
                }
                return Ok(Box::new(proxy_common::PrependedStream::new(framed, data)));
            }
            Err(e) => return Err(e),
        }
    }
}

async fn read_tls_record(stream: &mut BoxedStream) -> Result<Vec<u8>, ProxyError> {
    let mut header = [0u8; 5];
    stream
        .read_exact(&mut header)
        .await
        .map_err(|e| ProxyError::Transport(format!("ShadowTLS v3: read record header: {e}")))?;
    let len = u16::from_be_bytes([header[3], header[4]]) as usize;
    if len > 16_384 + 2048 {
        return Err(ProxyError::Protocol(format!(
            "ShadowTLS v3 TLS record too large: {len}"
        )));
    }
    let mut record = header.to_vec();
    record.resize(5 + len, 0);
    stream
        .read_exact(&mut record[5..])
        .await
        .map_err(|e| ProxyError::Transport(format!("ShadowTLS v3: read record payload: {e}")))?;
    Ok(record)
}

fn shadowtls_sni_from_dest(dest: &str) -> Result<&str, ProxyError> {
    let host = dest
        .rsplit_once('@')
        .map(|(_, host)| host)
        .unwrap_or(dest)
        .trim();
    let host = host
        .strip_prefix('[')
        .and_then(|s| s.split_once(']').map(|(inside, _)| inside))
        .or_else(|| host.rsplit_once(':').map(|(name, _)| name))
        .unwrap_or(host)
        .trim();
    if host.is_empty() {
        return Err(ProxyError::Protocol(
            "ShadowTLS v3 dest must include a handshake server name".into(),
        ));
    }
    Ok(host)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shadowtls::marker::compute_marker;
    use crate::shadowtls::server::shadowtls_accept;
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

    #[tokio::test]
    async fn v3_client_and_server_switch_after_tainted_backend_handshake() {
        let psk = b"shadowtls-v3-password";
        let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap();
        let backend_task = tokio::spawn(async move {
            let (mut sock, _) = backend.accept().await.unwrap();
            let mut header = [0u8; 5];
            sock.read_exact(&mut header).await.unwrap();
            assert_eq!(header[0], 0x16);
            let len = u16::from_be_bytes([header[3], header[4]]) as usize;
            let mut payload = vec![0u8; len];
            sock.read_exact(&mut payload).await.unwrap();
            assert_eq!(payload.first(), Some(&0x01));

            let mut server_hello = vec![0x02, 0x00, 0x00, 0x22, 0x03, 0x03];
            server_hello.extend_from_slice(&[0x77; 32]);
            write_tls_record_for_test(&mut sock, 0x16, &server_hello)
                .await
                .unwrap();
            write_tls_record_for_test(&mut sock, 0x17, b"encrypted-backend-finished")
                .await
                .unwrap();
            let mut drain = [0u8; 1024];
            let _ = sock.read(&mut drain).await;
        });

        let shadow = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let shadow_addr = shadow.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let (tcp, source) = shadow.accept().await.unwrap();
            let mut stream = shadowtls_accept(Box::new(tcp), psk, &backend_addr.to_string())
                .await
                .unwrap();
            assert_eq!(source.ip().to_string(), "127.0.0.1");
            let mut request = [0u8; 5];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"hello");
            stream.write_all(b"world").await.unwrap();
            stream.flush().await.unwrap();
        });

        let tcp = TcpStream::connect(shadow_addr).await.unwrap();
        let mut stream = shadowtls_v3_connect(Box::new(tcp), psk, "example.com:443")
            .await
            .unwrap();
        stream.write_all(b"hello").await.unwrap();
        stream.flush().await.unwrap();
        let mut response = [0u8; 5];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"world");

        server_task.await.unwrap();
        backend_task.await.unwrap();
    }

    async fn write_tls_record_for_test(
        sock: &mut TcpStream,
        record_type: u8,
        payload: &[u8],
    ) -> std::io::Result<()> {
        let len = payload.len() as u16;
        sock.write_all(&[record_type, 0x03, 0x03, (len >> 8) as u8, len as u8])
            .await?;
        sock.write_all(payload).await?;
        sock.flush().await
    }
}
