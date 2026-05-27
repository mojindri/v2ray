//! SIP022 UDP relay — Shadowsocks-2022 UDP (`2022-blake3-aes-256-gcm`).
//!
//! Wire layout matches [sing-shadowsocks `shadowaead_2022`](https://github.com/SagerNet/sing-shadowsocks):
//! ```text
//! AES-ECB(PSK, session_id_u64be || packet_id_u64be) | AEAD-256-GCM(body)
//! ```
//! Session AEAD key = `blake3::derive_key("shadowsocks 2022 session subkey", psk || session_id[0..8])`.
//! AEAD nonce = decrypted separate header bytes `[4..16]`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aes::Aes256;
use aes_gcm::{
    aead::{generic_array::GenericArray, Aead, Payload},
    Aes256Gcm, KeyInit,
};
use cipher::{BlockDecrypt, BlockEncrypt};
use parking_lot::Mutex;
use rand::RngExt;
use tokio::net::UdpSocket;
use tracing::{debug, warn};

use blackwire_common::{decode_socks5_address, write_socks5_address, Address, ProxyError};

const TYPE_CLIENT: u8 = 0x00;
const TYPE_SERVER: u8 = 0x01;
const MAX_TIME_DIFF: u64 = 30;
/// Idle lifetime for a per-session upstream socket before it is torn down.
const UDP_SESSION_IDLE: Duration = Duration::from_secs(30);
const MAX_SESSIONS: usize = 4096;
const AEAD_TAG_LEN: usize = 16;
const SEPARATE_HEADER_LEN: usize = 16;

/// Derive a 32-byte session AEAD key (8-byte session id salt — SIP022 UDP).
fn derive_session_key(psk: &[u8; 32], session_id: &[u8; 8]) -> [u8; 32] {
    let mut material = [0u8; 40];
    material[..32].copy_from_slice(psk);
    material[32..].copy_from_slice(session_id);
    blake3::derive_key("shadowsocks 2022 session subkey", &material)
}

fn block_cipher(psk: &[u8; 32]) -> Aes256 {
    Aes256::new(GenericArray::from_slice(psk))
}

fn decrypt_separate_header(
    psk: &[u8; 32],
    wire: &[u8],
) -> Result<[u8; SEPARATE_HEADER_LEN], ProxyError> {
    if wire.len() < SEPARATE_HEADER_LEN {
        return Err(ProxyError::Protocol("SS2022 UDP packet too short".into()));
    }
    let mut block = GenericArray::clone_from_slice(&wire[..SEPARATE_HEADER_LEN]);
    block_cipher(psk).decrypt_block(&mut block);
    Ok(block.into())
}

fn encrypt_separate_header(
    psk: &[u8; 32],
    plain: &[u8; SEPARATE_HEADER_LEN],
) -> [u8; SEPARATE_HEADER_LEN] {
    let mut block = GenericArray::clone_from_slice(plain);
    block_cipher(psk).encrypt_block(&mut block);
    block.into()
}

fn aead_nonce(header: &[u8; SEPARATE_HEADER_LEN]) -> [u8; 12] {
    let mut n = [0u8; 12];
    n.copy_from_slice(&header[4..16]);
    n
}

fn session_cipher(key: &[u8; 32]) -> Aes256Gcm {
    Aes256Gcm::new(GenericArray::from_slice(key))
}

struct ServerUdpSession {
    server_session_id: u64,
    client_session_id: u64,
    session_key: [u8; 32],
}

impl ServerUdpSession {
    fn new(psk: &[u8; 32], client_session_id: u64) -> Self {
        let mut rng = rand::rng();
        let server_session_id: u64 = rng.random();
        let mut sid_bytes = [0u8; 8];
        sid_bytes.copy_from_slice(&server_session_id.to_be_bytes());
        let session_key = derive_session_key(psk, &sid_bytes);
        Self {
            server_session_id,
            client_session_id,
            session_key,
        }
    }

    fn cipher(&self) -> Aes256Gcm {
        session_cipher(&self.session_key)
    }
}

/// Per-session state held in the relay's session table.
///
/// One `SessionEntry` is created the first time a packet from a given
/// `client_session_id` arrives. A single upstream `UdpSocket` is bound once
/// and reused for all subsequent packets in the same session, eliminating the
/// previous pattern of creating a new socket per packet.
struct SessionEntry {
    /// Persistent upstream socket — reused for every packet in this session.
    upstream_sock: Arc<UdpSocket>,
    /// Current client address, updated on every received packet (handles roaming).
    client_addr: Arc<Mutex<SocketAddr>>,
}

/// Decode one SS2022 UDP client packet (SIP022 / sing-box compatible).
pub fn decode_client_packet(
    buf: &[u8],
    psk: &[u8; 32],
) -> Result<(u64, u64, Address, Vec<u8>), ProxyError> {
    let header = decrypt_separate_header(psk, buf)?;
    let client_session_id = u64::from_be_bytes(header[..8].try_into().unwrap());
    let packet_id = u64::from_be_bytes(header[8..16].try_into().unwrap());
    if buf.len() < SEPARATE_HEADER_LEN + AEAD_TAG_LEN + 1 {
        return Err(ProxyError::Protocol(
            "SS2022 UDP ciphertext too short".into(),
        ));
    }
    let ciphertext = &buf[SEPARATE_HEADER_LEN..];

    let session_key = derive_session_key(psk, header[..8].try_into().unwrap());
    let cipher = session_cipher(&session_key);
    let plaintext = cipher
        .decrypt(GenericArray::from_slice(&aead_nonce(&header)), ciphertext)
        .map_err(|_| ProxyError::Protocol("SS2022 UDP decrypt failed".into()))?;

    if plaintext.is_empty() || plaintext[0] != TYPE_CLIENT {
        return Err(ProxyError::Protocol(format!(
            "SS2022 UDP unexpected type {:#x}",
            plaintext.first().copied().unwrap_or(0xff)
        )));
    }
    if plaintext.len() < 11 {
        return Err(ProxyError::Protocol(
            "SS2022 UDP plaintext too short".into(),
        ));
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
        return Err(ProxyError::Protocol(
            "SS2022 UDP truncated after padding".into(),
        ));
    }
    let atyp = plaintext[pos];
    pos += 1;
    let (dest, consumed) = decode_socks5_address(&plaintext[pos..], atyp, "SS2022 UDP")?;
    pos += consumed;
    let payload = plaintext[pos..].to_vec();
    Ok((client_session_id, packet_id, dest, payload))
}

/// Encode a SIP022 server → client UDP packet.
fn encode_server_packet(
    psk: &[u8; 32],
    session: &ServerUdpSession,
    server_packet_id: u64,
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
    plain.extend_from_slice(&session.client_session_id.to_be_bytes());
    plain.extend_from_slice(&0u16.to_be_bytes());
    let mut addr_buf = bytes::BytesMut::new();
    write_socks5_address(&mut addr_buf, dest)?;
    plain.extend_from_slice(&addr_buf);
    plain.extend_from_slice(payload);

    let mut sep_plain = [0u8; SEPARATE_HEADER_LEN];
    sep_plain[..8].copy_from_slice(&session.server_session_id.to_be_bytes());
    sep_plain[8..].copy_from_slice(&server_packet_id.to_be_bytes());

    let ciphertext = session
        .cipher()
        .encrypt(
            GenericArray::from_slice(&aead_nonce(&sep_plain)),
            Payload {
                msg: &plain,
                aad: &[],
            },
        )
        .map_err(|_| ProxyError::Protocol("SS2022 UDP server encrypt failed".into()))?;

    let mut pkt = Vec::with_capacity(SEPARATE_HEADER_LEN + ciphertext.len());
    pkt.extend_from_slice(&encrypt_separate_header(psk, &sep_plain));
    pkt.extend_from_slice(&ciphertext);
    Ok(pkt)
}

/// Decode a server → client UDP packet body (returns AEAD plaintext).
pub fn decode_server_packet(buf: &[u8], psk: &[u8; 32]) -> Result<Vec<u8>, ProxyError> {
    let header = decrypt_separate_header(psk, buf)?;
    if buf.len() < SEPARATE_HEADER_LEN + AEAD_TAG_LEN {
        return Err(ProxyError::Protocol(
            "SS2022 UDP server packet too short".into(),
        ));
    }
    let server_session_id = &header[..8];
    let session_key = derive_session_key(psk, server_session_id.try_into().unwrap());
    let cipher = session_cipher(&session_key);
    cipher
        .decrypt(
            GenericArray::from_slice(&aead_nonce(&header)),
            &buf[SEPARATE_HEADER_LEN..],
        )
        .map_err(|_| ProxyError::Protocol("SS2022 UDP server decrypt failed".into()))
}

/// Build a client → server packet (used by in-process e2e).
pub fn encode_client_packet(
    psk: &[u8; 32],
    client_session_id: u64,
    packet_id: u64,
    dest: &Address,
    payload: &[u8],
) -> Result<Vec<u8>, ProxyError> {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut plain = Vec::with_capacity(64 + payload.len());
    plain.push(TYPE_CLIENT);
    plain.extend_from_slice(&ts.to_be_bytes());
    plain.extend_from_slice(&0u16.to_be_bytes());
    let mut addr_buf = bytes::BytesMut::new();
    write_socks5_address(&mut addr_buf, dest)?;
    plain.extend_from_slice(&addr_buf);
    plain.extend_from_slice(payload);

    let mut sep_plain = [0u8; SEPARATE_HEADER_LEN];
    sep_plain[..8].copy_from_slice(&client_session_id.to_be_bytes());
    sep_plain[8..].copy_from_slice(&packet_id.to_be_bytes());

    let session_key = derive_session_key(psk, sep_plain[..8].try_into().unwrap());
    let cipher = session_cipher(&session_key);
    let ciphertext = cipher
        .encrypt(
            GenericArray::from_slice(&aead_nonce(&sep_plain)),
            Payload {
                msg: &plain,
                aad: &[],
            },
        )
        .map_err(|_| ProxyError::Protocol("SS2022 UDP client encrypt failed".into()))?;

    let mut pkt = Vec::with_capacity(SEPARATE_HEADER_LEN + ciphertext.len());
    pkt.extend_from_slice(&encrypt_separate_header(psk, &sep_plain));
    pkt.extend_from_slice(&ciphertext);
    Ok(pkt)
}

/// Relay SS2022 UDP sessions on the given bound UDP socket.
///
/// Each unique `client_session_id` gets a single persistent upstream
/// `UdpSocket` (created once, not per packet). A long-running reply task
/// per session loops over `recv_from` on that socket and routes replies back
/// to the client, eliminating the previous one-socket-per-packet pattern.
pub async fn relay_ss2022_udp(socket: Arc<UdpSocket>, psk: [u8; 32]) {
    let mut sessions: HashMap<u64, SessionEntry> = HashMap::new();
    let mut buf = vec![0u8; 65535];

    loop {
        let (n, client_addr) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "SS2022 UDP recv error");
                continue;
            }
        };

        let (client_session_id, _packet_id, dest, payload) =
            match decode_client_packet(&buf[..n], &psk) {
                Ok(v) => v,
                Err(e) => {
                    debug!(source = %client_addr, error = %e, "SS2022 UDP decode failed");
                    continue;
                }
            };

        debug!(
            source = %client_addr,
            dest = %dest,
            session = %client_session_id,
            "SS2022 UDP relay"
        );

        if payload.is_empty() {
            continue;
        }

        if sessions.len() >= MAX_SESSIONS {
            sessions.clear();
        }

        // Create a new session entry on first packet; update client_addr on subsequent ones.
        let entry = if let Some(e) = sessions.get_mut(&client_session_id) {
            *e.client_addr.lock() = client_addr;
            e
        } else {
            let upstream_sock = match UdpSocket::bind("0.0.0.0:0").await {
                Ok(s) => Arc::new(s),
                Err(e) => {
                    warn!(error = %e, "SS2022 UDP upstream bind failed");
                    continue;
                }
            };
            let client_addr_shared = Arc::new(Mutex::new(client_addr));
            let session = ServerUdpSession::new(&psk, client_session_id);

            // Spawn a long-running reply task for this session.
            spawn_reply_task(
                Arc::clone(&upstream_sock),
                Arc::clone(&socket),
                psk,
                session.server_session_id,
                session.client_session_id,
                session.session_key,
                Arc::clone(&client_addr_shared),
            );

            sessions.insert(
                client_session_id,
                SessionEntry {
                    upstream_sock,
                    client_addr: client_addr_shared,
                },
            );
            sessions.get_mut(&client_session_id).unwrap()
        };

        let upstream = match resolve_udp_dest(&dest).await {
            Ok(a) => a,
            Err(e) => {
                warn!(dest = %dest, error = %e, "SS2022 UDP DNS failed");
                continue;
            }
        };

        if let Err(e) = entry.upstream_sock.send_to(&payload, upstream).await {
            warn!(error = %e, "SS2022 UDP upstream send failed");
        }
    }
}

/// Spawn the per-session upstream reply loop.
///
/// Loops over `recv_from` on the upstream socket. For each reply the source
/// address is used as the SS2022 destination field (the address the client
/// originally targeted). Exits after `UDP_SESSION_IDLE` seconds of silence.
fn spawn_reply_task(
    upstream: Arc<UdpSocket>,
    client_sock: Arc<UdpSocket>,
    psk: [u8; 32],
    server_session_id: u64,
    client_session_id: u64,
    session_key: [u8; 32],
    client_addr: Arc<Mutex<SocketAddr>>,
) {
    tokio::spawn(async move {
        let mut rbuf = vec![0u8; 65535];
        let proxy_session = ServerUdpSession {
            server_session_id,
            client_session_id,
            session_key,
        };
        let mut server_packet_id: u64 = 0;
        loop {
            let (rn, upstream_src) =
                match tokio::time::timeout(UDP_SESSION_IDLE, upstream.recv_from(&mut rbuf)).await {
                    Ok(Ok(v)) => v,
                    _ => break, // idle timeout or error — session expired
                };

            if rn == 0 {
                continue;
            }

            // The source address of the upstream reply IS the destination the
            // client originally targeted; use it in the SS2022 reply header.
            let reply_dest = match upstream_src {
                SocketAddr::V4(a) => Address::Ipv4(*a.ip(), upstream_src.port()),
                SocketAddr::V6(a) => match a.ip().to_ipv4_mapped() {
                    Some(v4) => Address::Ipv4(v4, upstream_src.port()),
                    None => Address::Ipv6(*a.ip(), upstream_src.port()),
                },
            };

            let pkt_id = server_packet_id;
            server_packet_id += 1;
            let addr = *client_addr.lock();
            match encode_server_packet(&psk, &proxy_session, pkt_id, &reply_dest, &rbuf[..rn]) {
                Ok(reply) => {
                    let _ = client_sock.send_to(&reply, addr).await;
                }
                Err(e) => {
                    warn!(error = %e, "SS2022 UDP encode reply failed");
                }
            }
        }
    });
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
    fn client_server_roundtrip() {
        let psk = test_psk();
        let dest = Address::Ipv4(Ipv4Addr::new(8, 8, 8, 8), 53);
        let payload = b"hello-ss2022-udp";
        let client_session_id = 0x0123_4567_89ab_cdef_u64;
        let client_packet_id = 1u64;

        let pkt = encode_client_packet(&psk, client_session_id, client_packet_id, &dest, payload)
            .unwrap();

        let (sid, pid, d, p) = decode_client_packet(&pkt, &psk).unwrap();
        assert_eq!(sid, client_session_id);
        assert_eq!(pid, client_packet_id);
        assert_eq!(d, dest);
        assert_eq!(p, payload);

        let session = ServerUdpSession::new(&psk, client_session_id);
        let reply = encode_server_packet(&psk, &session, 0, &dest, b"pong").unwrap();
        assert!(reply.len() > SEPARATE_HEADER_LEN + AEAD_TAG_LEN);
        let header = decrypt_separate_header(&psk, &reply).unwrap();
        let server_session_id = u64::from_be_bytes(header[..8].try_into().unwrap());
        assert_eq!(server_session_id, session.server_session_id);
        assert_ne!(server_session_id, client_session_id);
    }
}
