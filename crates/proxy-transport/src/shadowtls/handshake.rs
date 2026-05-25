//! ShadowTLS v3 handshake relay.
//!
//! The ShadowTLS server transparently relays the TLS handshake between the
//! client and a real TLS backend (e.g. `www.apple.com:443`). While relaying,
//! it sniffs the `server_random` field from the ServerHello message so both
//! sides can derive the HMAC marker.
//!
//! # TLS record layout
//!
//! Each TLS record has a 5-byte header:
//! ```text
//! +------+----------+------+
//! | type | version  |  len |
//! | 1 B  |   2 B    |  2 B |
//! +------+----------+------+
//! ```
//! Content types: 20=ChangeCipherSpec, 21=Alert, 22=Handshake, 23=Application.
//!
//! # ServerHello layout (inside a Handshake record)
//!
//! ```text
//! HandshakeType  (1 byte)  = 0x02 (ServerHello)
//! Length         (3 bytes)
//! ProtocolVersion (2 bytes)
//! server_random  (32 bytes)  <-- this is what we extract
//! ...
//! ```

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use proxy_common::{tcp_connect_to, BoxedStream, ProxyError};

/// Maximum time to complete the TLS handshake relay (sing-box `C.TCPTimeoutShort`).
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(4);

use super::v3::{
    residual_handshake_mac, taint_backend_application_data, verify_client_hello_session_id,
    V3FrameDecoder,
};

/// TLS record content type for Handshake messages.
const TLS_RECORD_HANDSHAKE: u8 = 22;
/// TLS record content type for Application Data.
const TLS_RECORD_APPLICATION_DATA: u8 = 23;
/// TLS handshake type for ServerHello.
const TLS_HANDSHAKE_SERVER_HELLO: u8 = 0x02;

/// Relay the TLS handshake from client to backend, extracting `server_random`.
///
/// This function:
/// 1. Connects to `backend_addr`.
/// 2. Relays all TLS handshake records bidirectionally until the handshake ends.
/// 3. Extracts `server_random` from the ServerHello record.
/// 4. Returns both halves and the extracted `server_random`.
///
/// The "handshake end" heuristic: once we have seen a `ChangeCipherSpec` record
/// from the server side (or the first Application Data record), we stop.
pub async fn relay_handshake(
    client: &mut BoxedStream,
    backend_addr: &str,
) -> Result<([u8; 32], bool), ProxyError> {
    let mut backend = tcp_connect_to(backend_addr).await.map_err(|e| {
        ProxyError::Transport(format!(
            "ShadowTLS: cannot connect to backend {backend_addr}: {e}"
        ))
    })?;

    let server_random = tokio::time::timeout(HANDSHAKE_TIMEOUT, do_relay(client, &mut backend))
        .await
        .map_err(|_| ProxyError::Timeout)??;
    Ok((server_random, true))
}

/// Relay a ShadowTLS v3 handshake until the authenticated client data switch.
///
/// Unlike [`relay_handshake`], this function validates the v3 ClientHello
/// SessionID, taints backend TLS ApplicationData frames, and stops before the
/// first authenticated client proxy-data frame is forwarded to the decoy
/// backend.
pub async fn relay_v3_handshake(
    client: &mut BoxedStream,
    psk: &[u8],
    backend_addr: &str,
) -> Result<([u8; 32], Vec<u8>), ProxyError> {
    let mut backend = tcp_connect_to(backend_addr).await.map_err(|e| {
        ProxyError::Transport(format!(
            "ShadowTLS: cannot connect to backend {backend_addr}: {e}"
        ))
    })?;

    let (record_type, version, payload) = read_tls_record(client).await?;
    if record_type != TLS_RECORD_HANDSHAKE || payload.first() != Some(&0x01) {
        return Err(ProxyError::Protocol(
            "ShadowTLS v3 expected ClientHello as first record".into(),
        ));
    }
    let client_hello = encode_tls_record(record_type, version, &payload);
    verify_client_hello_session_id(&client_hello, psk)?;
    write_tls_record(&mut backend, record_type, version, &payload).await?;

    tokio::time::timeout(HANDSHAKE_TIMEOUT, do_v3_relay(client, &mut backend, psk))
        .await
        .map_err(|_| ProxyError::Timeout)?
}

/// Inner relay: pump records between client and backend, sniffing server_random.
async fn do_relay<C, B>(client: &mut C, backend: &mut B) -> Result<[u8; 32], ProxyError>
where
    C: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let mut server_random = [0u8; 32];
    let mut found_server_random = false;
    // Track whether we've seen server's ChangeCipherSpec — after that
    // the handshake is done and the next server record is Application Data.
    let mut server_ccs_seen = false;

    loop {
        // Use tokio::select! to process whichever side is ready first.
        tokio::select! {
            // Client → Backend
            result = read_tls_record(client) => {
                let (record_type, version, payload) = result?;
                write_tls_record(backend, record_type, version, &payload).await?;
                // If client sends Application Data, handshake is done on client side.
                if record_type == TLS_RECORD_APPLICATION_DATA {
                    // Return; the caller will continue reading from here.
                    if !found_server_random {
                        return Err(ProxyError::Protocol(
                            "ShadowTLS: Application Data before ServerHello".into(),
                        ));
                    }
                    return Ok(server_random);
                }
            }
            // Backend → Client
            result = read_tls_record(backend) => {
                let (record_type, version, payload) = result?;

                // Sniff server_random from the first ServerHello.
                if !found_server_random
                    && record_type == TLS_RECORD_HANDSHAKE
                    && payload.first() == Some(&TLS_HANDSHAKE_SERVER_HELLO)
                {
                    if let Some(sr) = extract_server_random(&payload) {
                        server_random.copy_from_slice(sr);
                        found_server_random = true;
                    }
                }

                if record_type == 20 {
                    // ChangeCipherSpec from server
                    server_ccs_seen = true;
                }

                write_tls_record(client, record_type, version, &payload).await?;

                // After server CCS, the very next server record will be
                // Finished (still handshake but encrypted). We keep going.
                // After seeing that plus client CCS, we'll see Application Data.
                let _ = server_ccs_seen;
            }
        }
    }
}

async fn do_v3_relay<C, B>(
    client: &mut C,
    backend: &mut B,
    psk: &[u8],
) -> Result<([u8; 32], Vec<u8>), ProxyError>
where
    C: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let mut server_random = [0u8; 32];
    let mut found_server_random = false;
    let mut residual_mac = None;
    let mut client_switch_decoder = None;

    loop {
        tokio::select! {
            result = read_tls_record(client) => {
                let (record_type, version, payload) = result?;
                let record = encode_tls_record(record_type, version, &payload);

                if record_type == TLS_RECORD_APPLICATION_DATA {
                    if !found_server_random {
                        return Err(ProxyError::Protocol(
                            "ShadowTLS v3 client ApplicationData before ServerHello".into(),
                        ));
                    }

                    let decoder = client_switch_decoder.get_or_insert_with(|| {
                        V3FrameDecoder::client_to_server(psk, &server_random)
                    });
                    if decoder.decode_application_data(&record).is_ok() {
                        return Ok((server_random, record));
                    }
                }

                write_tls_record(backend, record_type, version, &payload).await?;
            }
            result = read_tls_record(backend) => {
                let (record_type, version, payload) = result?;
                let mut record = encode_tls_record(record_type, version, &payload);

                if !found_server_random
                    && record_type == TLS_RECORD_HANDSHAKE
                    && payload.first() == Some(&TLS_HANDSHAKE_SERVER_HELLO)
                {
                    if let Some(sr) = extract_server_random(&payload) {
                        server_random.copy_from_slice(sr);
                        residual_mac = Some(residual_handshake_mac(psk, &server_random));
                        found_server_random = true;
                    }
                }

                if found_server_random && record_type == TLS_RECORD_APPLICATION_DATA {
                    let mac = residual_mac.as_mut().ok_or_else(|| {
                        ProxyError::Protocol("ShadowTLS v3 residual HMAC not initialized".into())
                    })?;
                    record = taint_backend_application_data(mac, psk, &server_random, &record)?;
                }

                client.write_all(&record).await.map_err(|e| {
                    ProxyError::Transport(format!("ShadowTLS: write client record: {e}"))
                })?;
                client.flush().await.map_err(|e| {
                    ProxyError::Transport(format!("ShadowTLS: flush client record: {e}"))
                })?;
            }
        }
    }
}

/// Read one complete TLS record from the stream.
///
/// Returns `(content_type, version_bytes, payload)`.
async fn read_tls_record<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> Result<(u8, [u8; 2], Vec<u8>), ProxyError> {
    // Read the 5-byte header.
    let mut header = [0u8; 5];
    stream
        .read_exact(&mut header)
        .await
        .map_err(|e| ProxyError::Transport(format!("ShadowTLS: read record header: {e}")))?;

    let record_type = header[0];
    let version = [header[1], header[2]];
    let length = u16::from_be_bytes([header[3], header[4]]) as usize;

    if length > 16_384 + 2048 {
        return Err(ProxyError::Protocol(format!(
            "ShadowTLS: TLS record too large: {length}"
        )));
    }

    let mut payload = vec![0u8; length];
    stream
        .read_exact(&mut payload)
        .await
        .map_err(|e| ProxyError::Transport(format!("ShadowTLS: read record payload: {e}")))?;

    Ok((record_type, version, payload))
}

/// Write one TLS record to the stream.
async fn write_tls_record<S: AsyncWrite + Unpin>(
    stream: &mut S,
    record_type: u8,
    version: [u8; 2],
    payload: &[u8],
) -> Result<(), ProxyError> {
    let len = payload.len() as u16;
    let header = [
        record_type,
        version[0],
        version[1],
        (len >> 8) as u8,
        len as u8,
    ];
    stream
        .write_all(&header)
        .await
        .map_err(|e| ProxyError::Transport(format!("ShadowTLS: write record header: {e}")))?;
    stream
        .write_all(payload)
        .await
        .map_err(|e| ProxyError::Transport(format!("ShadowTLS: write record payload: {e}")))?;
    stream
        .flush()
        .await
        .map_err(|e| ProxyError::Transport(format!("ShadowTLS: flush: {e}")))?;
    Ok(())
}

/// Extract the 32-byte `server_random` from a ServerHello handshake payload.
///
/// ServerHello layout (inside a Handshake record payload):
/// ```text
/// [0]      HandshakeType = 0x02
/// [1..4]   Length (3 bytes, big-endian)
/// [4..6]   ProtocolVersion (2 bytes)
/// [6..38]  server_random (32 bytes)
/// ```
fn extract_server_random(payload: &[u8]) -> Option<&[u8]> {
    // Need at least type(1) + length(3) + version(2) + random(32) = 38 bytes
    if payload.len() < 38 {
        return None;
    }
    if payload[0] != TLS_HANDSHAKE_SERVER_HELLO {
        return None;
    }
    Some(&payload[6..38])
}

fn encode_tls_record(record_type: u8, version: [u8; 2], payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u16;
    let mut record = Vec::with_capacity(5 + payload.len());
    record.extend_from_slice(&[
        record_type,
        version[0],
        version[1],
        (len >> 8) as u8,
        len as u8,
    ]);
    record.extend_from_slice(payload);
    record
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_server_random_happy() {
        let mut payload = vec![0u8; 38];
        payload[0] = TLS_HANDSHAKE_SERVER_HELLO; // type
                                                 // length bytes [1..4] = 0
                                                 // version bytes [4..6] = 0x03 0x03
        payload[4] = 0x03;
        payload[5] = 0x03;
        // server_random [6..38]
        for i in 0..32 {
            payload[6 + i] = i as u8;
        }

        let sr = extract_server_random(&payload).unwrap();
        assert_eq!(sr.len(), 32);
        for (i, byte) in sr.iter().copied().enumerate().take(32) {
            assert_eq!(byte, i as u8);
        }
    }

    #[test]
    fn extract_server_random_too_short() {
        let payload = vec![TLS_HANDSHAKE_SERVER_HELLO; 10];
        assert!(extract_server_random(&payload).is_none());
    }

    #[test]
    fn extract_server_random_wrong_type() {
        let mut payload = vec![0u8; 38];
        payload[0] = 0x01; // ClientHello, not ServerHello
        assert!(extract_server_random(&payload).is_none());
    }
}
