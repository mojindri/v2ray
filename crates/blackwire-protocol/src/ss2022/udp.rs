//! SIP022 UDP relay — Shadowsocks-2022 UDP packet encode/decode.
//!
//! Wire format (client → server):
//! ```text
//! session_id(8) | packet_id(8 LE) | AEAD { type(1)=0x00 | timestamp(8 BE) |
//!   padding_len(2 BE) | padding(N) | atyp(1) | addr | port(2 BE) | payload }
//! ```
//!
//! Wire format (server → client):
//! ```text
//! session_id(8) | packet_id(8 LE) | AEAD { type(1)=0x01 | timestamp(8 BE) |
//!   client_packet_id(8 BE) | padding_len(2 BE) | padding(N) | atyp(1) |
//!   addr | port(2 BE) | payload }
//! ```
//!
//! Session key = `blake3::derive_key("shadowsocks 2022 session subkey", psk(32) || session_id(8))`.
//! AEAD nonce = `packet_id (8 bytes LE) || 0x00_0x00_0x00_0x00` (12 bytes).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aes_gcm::{
    aead::{generic_array::GenericArray, Aead},
    Aes256Gcm, KeyInit,
};
use tokio::net::UdpSocket;
use tracing::{debug, warn};

use blackwire_common::{
    decode_socks5_address, write_socks5_address, Address, ProxyError,
};

const TYPE_CLIENT: u8 = 0x00;
const TYPE_SERVER: u8 = 0x01;
const MAX_TIME_DIFF: u64 = 30;
const UDP_RECV_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_SESSIONS: usize = 4096;

/// Derive a 32-byte session key from the PSK and an 8-byte UDP session_id.
fn derive_session_key(psk: &[u8; 32], session_id: &[u8; 8]) -> [u8; 32] {
    let mut material = [0u8; 40];
    material[..32].copy_from_slice(psk);
    material[32..].copy_from_slice(session_id);
    blake3::derive_key("shadowsocks 2022 session subkey", &material)
}

/// Build a 12-byte AEAD nonce from an 8-byte LE packet_id.
fn make_nonce(packet_id: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..8].copy_from_slice(&packet_id.to_le_bytes());
    n
}

/// Decode one SS2022 UDP client packet.
///
/// Returns (session_id, client_packet_id, dest, payload).
pub fn decode_client_packet(
    buf: &[u8],
    psk: &[u8; 32],
) -> Result<([u8; 8], u64, Address, Vec<u8>), ProxyError> {
    if buf.len() < 16 {
        return Err(ProxyError::Protocol("SS2022 UDP packet too short".into()));
    }
    let mut session_id = [0u8; 8];
    session_id.copy_from_slice(&buf[..8]);
    let packet_id = u64::from_le_bytes(buf[8..16].try_into().unwrap());
    let ciphertext = &buf[16..];

    let session_key = derive_session_key(psk, &session_id);
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&session_key));
    let nonce = make_nonce(packet_id);
    let plaintext = cipher
        .decrypt(GenericArray::from_slice(&nonce), ciphertext)
        .map_err(|_| ProxyError::Protocol("SS2022 UDP decrypt failed".into()))?;

    if plaintext.len() < 11 {
        return Err(ProxyError::Protocol("SS2022 UDP plaintext too short".into()));
    }
    if plaintext[0] != TYPE_CLIENT {
        return Err(ProxyError::Protocol(format!(
            "SS2022 UDP unexpected type {:#x}",
            plaintext[0]
        )));
    }
    let ts = u64::from_be_bytes(plaintext[1..9].try_into().unwrap());
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if ts.abs_diff(now) > MAX_TIME_DIFF {
        return Err(ProxyError::AuthFailed);
    }
    let pad_len = u16::from_be_bytes([plaintext[9], plaintext[10]]) as usize;
    let mut pos = 11 + pad_len;
    if pos >= plaintext.len() {
        return Err(ProxyError::Protocol("SS2022 UDP truncated after padding".into()));
    }
    let atyp = plaintext[pos];
    pos += 1;
    let (dest, consumed) = decode_socks5_address(&plaintext[pos..], atyp, "SS2022 UDP")?;
    pos += consumed;
    let payload = plaintext[pos..].to_vec();
    Ok((session_id, packet_id, dest, payload))
}

/// Encode one SS2022 UDP server reply packet.
///
/// `session_id` — the client's session_id (used as key material).
/// `server_packet_id` — the server's monotonic counter for this session.
/// `client_packet_id` — echoed in the reply plaintext.
pub fn encode_server_packet(
    psk: &[u8; 32],
    session_id: &[u8; 8],
    server_packet_id: u64,
    client_packet_id: u64,
    dest: &Address,
    payload: &[u8],
) -> Result<Vec<u8>, ProxyError> {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut plain = Vec::with_capacity(128 + payload.len());
    plain.push(TYPE_SERVER);
    plain.extend_from_slice(&ts.to_be_bytes());
    plain.extend_from_slice(&client_packet_id.to_be_bytes()); // echo client's pkt_id (BE)
    plain.extend_from_slice(&0u16.to_be_bytes()); // padding_len = 0
    // address
    let mut addr_buf = bytes::BytesMut::new();
    write_socks5_address(&mut addr_buf, dest)?;
    plain.extend_from_slice(&addr_buf);
    plain.extend_from_slice(payload);

    let session_key = derive_session_key(psk, session_id);
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&session_key));
    let nonce = make_nonce(server_packet_id);
    let ciphertext = cipher
        .encrypt(GenericArray::from_slice(&nonce), plain.as_slice())
        .map_err(|_| ProxyError::Protocol("SS2022 UDP server encrypt failed".into()))?;

    let mut pkt = Vec::with_capacity(16 + ciphertext.len());
    pkt.extend_from_slice(session_id);
    pkt.extend_from_slice(&server_packet_id.to_le_bytes());
    pkt.extend_from_slice(&ciphertext);
    Ok(pkt)
}

/// Relay SS2022 UDP sessions on the given bound UDP socket.
///
/// This is the server-side loop: accepts encrypted client datagrams, decrypts
/// them, forwards to the real destination UDP, and returns the encrypted reply.
pub async fn relay_ss2022_udp(socket: Arc<UdpSocket>, psk: [u8; 32]) {
    // session_id → server packet counter for this session
    let mut session_counters: HashMap<[u8; 8], u64> = HashMap::new();
    let mut buf = vec![0u8; 65535];

    loop {
        let (n, client_addr) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "SS2022 UDP recv error");
                continue;
            }
        };

        let pkt = buf[..n].to_vec();
        let (session_id, client_packet_id, dest, payload) =
            match decode_client_packet(&pkt, &psk) {
                Ok(v) => v,
                Err(e) => {
                    debug!(source = %client_addr, error = %e, "SS2022 UDP decode failed");
                    continue;
                }
            };

        debug!(
            source = %client_addr,
            dest = %dest,
            session = %hex::encode(session_id),
            "SS2022 UDP relay"
        );

        if payload.is_empty() {
            continue;
        }

        // Prune session table to avoid unbounded growth.
        if session_counters.len() >= MAX_SESSIONS {
            session_counters.clear();
        }
        let server_pkt_id = {
            let ctr = session_counters.entry(session_id).or_insert(0);
            let id = *ctr;
            *ctr += 1;
            id
        };

        let upstream = match resolve_udp_dest(&dest).await {
            Ok(a) => a,
            Err(e) => {
                warn!(dest = %dest, error = %e, "SS2022 UDP DNS failed");
                continue;
            }
        };

        let up_sock = match UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => Arc::new(s),
            Err(e) => {
                warn!(error = %e, "SS2022 UDP upstream bind failed");
                continue;
            }
        };
        if let Err(e) = up_sock.send_to(&payload, upstream).await {
            warn!(error = %e, "SS2022 UDP upstream send failed");
            continue;
        }

        let socket2 = Arc::clone(&socket);
        let psk2 = psk;
        let dest2 = dest.clone();
        tokio::spawn(async move {
            let mut rbuf = vec![0u8; 65535];
            match tokio::time::timeout(UDP_RECV_TIMEOUT, up_sock.recv(&mut rbuf)).await {
                Ok(Ok(rn)) if rn > 0 => {
                    match encode_server_packet(
                        &psk2,
                        &session_id,
                        server_pkt_id,
                        client_packet_id,
                        &dest2,
                        &rbuf[..rn],
                    ) {
                        Ok(reply) => {
                            let _ = socket2.send_to(&reply, client_addr).await;
                        }
                        Err(e) => {
                            warn!(error = %e, "SS2022 UDP encode reply failed");
                        }
                    }
                }
                _ => {}
            }
        });
    }
}

async fn resolve_udp_dest(dest: &Address) -> Result<SocketAddr, ProxyError> {
    match dest {
        Address::Ipv4(ip, port) => Ok(SocketAddr::new((*ip).into(), *port)),
        Address::Ipv6(ip, port) => Ok(SocketAddr::new((*ip).into(), *port)),
        Address::Domain(name, port) => {
            let mut addrs = tokio::net::lookup_host((name.as_str(), *port))
                .await
                .map_err(|e| ProxyError::DnsResolutionFailed(format!("{name}: {e}")))?;
            addrs
                .next()
                .ok_or_else(|| ProxyError::DnsResolutionFailed(name.clone()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn test_psk() -> [u8; 32] {
        *blake3::hash(b"test-password").as_bytes()
    }

    #[test]
    fn decode_encode_roundtrip() {
        use rand::RngExt;
        let psk = test_psk();
        let dest = Address::Ipv4(Ipv4Addr::new(8, 8, 8, 8), 53);
        let payload = b"hello-ss2022-udp";
        let mut session_id = [0u8; 8];
        rand::rng().fill(&mut session_id[..]);
        let client_packet_id = 42u64;

        // Build a client packet manually
        let session_key = derive_session_key(&psk, &session_id);
        let cipher = Aes256Gcm::new(GenericArray::from_slice(&session_key));
        let nonce = make_nonce(client_packet_id);
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut plain = Vec::new();
        plain.push(TYPE_CLIENT);
        plain.extend_from_slice(&ts.to_be_bytes());
        plain.extend_from_slice(&0u16.to_be_bytes()); // padding_len=0

        let mut addr_buf = bytes::BytesMut::new();
        write_socks5_address(&mut addr_buf, &dest).unwrap();
        plain.extend_from_slice(&addr_buf);
        plain.extend_from_slice(payload);

        let ct = cipher.encrypt(GenericArray::from_slice(&nonce), plain.as_slice()).unwrap();
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&session_id);
        pkt.extend_from_slice(&client_packet_id.to_le_bytes());
        pkt.extend_from_slice(&ct);

        let (sid, pid, d, p) = decode_client_packet(&pkt, &psk).unwrap();
        assert_eq!(sid, session_id);
        assert_eq!(pid, client_packet_id);
        assert_eq!(d, dest);
        assert_eq!(p, payload);
    }

    #[test]
    fn server_packet_decodes() {
        let psk = test_psk();
        let dest = Address::Ipv4(Ipv4Addr::new(1, 1, 1, 1), 53);
        let payload = b"pong";
        let session_id = [0xabu8; 8];
        let server_pkt_id = 0u64;
        let client_pkt_id = 7u64;

        let pkt =
            encode_server_packet(&psk, &session_id, server_pkt_id, client_pkt_id, &dest, payload)
                .unwrap();

        // Verify structure: session_id(8) + packet_id(8 LE) + AEAD ciphertext
        assert_eq!(&pkt[..8], &session_id);
        let pid = u64::from_le_bytes(pkt[8..16].try_into().unwrap());
        assert_eq!(pid, server_pkt_id);
        assert!(pkt.len() > 16 + 16); // at least AEAD tag
    }
}
