//! SS-2022 outbound handler — connects to a Shadowsocks-2022 server.
//!
//! # Wire format (SIP022 compatible)
//!
//! 1. Send salt (32 random bytes, plaintext).
//! 2. Send SIP022 request fixed header (nonce=0):
//!    `type(1)=0x00 | timestamp(8 BE) | variable_header_len(2 BE)`
//! 3. Send SIP022 request variable header (nonce=1):
//!    `atyp | addr | port | padding_len(2 BE) | padding | initial_payload`
//! 4. Data relay uses normal length/payload chunks (nonces continue from 2).
//!
//! # How it works
//!
//! This outbound opens TCP to the SS-2022 server, writes the encrypted request
//! headers for the chosen destination, validates the encrypted response header,
//! and then returns an `Ss2022Stream` for normal relay.
//!
//! # Why
//!
//! The split handshake keeps address metadata encrypted while still letting both
//! sides agree on subkeys and nonce positions before data chunks start.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::{
    aead::{generic_array::GenericArray, Aead},
    Aes256Gcm, KeyInit,
};
use async_trait::async_trait;
use bytes::BytesMut;
use rand::RngCore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::debug;

use proxy_app::context::Context;
use proxy_app::features::OutboundHandler;
use proxy_common::{domain_wire_len, tcp_connect, Address, BoxedStream, ProxyError};

use super::{password_to_psk, stream::Ss2022Stream, subkey::derive_subkey};

/// ATYP constants.
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

/// SS-2022 TCP connection type byte.
const TYPE_TCP: u8 = 0x00;

/// SS-2022 outbound handler.
pub struct Ss2022Outbound {
    tag: String,
    server: SocketAddr,
    psk: [u8; 32],
}

impl Ss2022Outbound {
    /// Build a new SS-2022 outbound handler for one server.
    pub fn new(tag: impl Into<String>, server: SocketAddr, password: &str) -> Arc<Self> {
        Arc::new(Self {
            tag: tag.into(),
            server,
            psk: password_to_psk(password),
        })
    }
}

#[async_trait]
impl OutboundHandler for Ss2022Outbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn connect(&self, _ctx: &Context, dest: &Address) -> Result<BoxedStream, ProxyError> {
        debug!(server = %self.server, dest = %dest, "SS-2022 outbound connecting");
        let tcp = tcp_connect(self.server).await?;
        tcp.set_nodelay(true)?;
        Ok(Box::new(
            open_ss2022_stream(Box::new(tcp), &self.psk, dest).await?,
        ))
    }
}

/// Outbound that returns an `Ss2022Stream`-wrapped connection.
pub struct Ss2022ChunkedOutbound {
    tag: String,
    server: SocketAddr,
    psk: [u8; 32],
}

impl Ss2022ChunkedOutbound {
    /// Create a new SS-2022 chunked outbound.
    pub fn new(tag: impl Into<String>, server: SocketAddr, password: &str) -> Arc<Self> {
        Arc::new(Self {
            tag: tag.into(),
            server,
            psk: password_to_psk(password),
        })
    }
}

#[async_trait]
impl OutboundHandler for Ss2022ChunkedOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn connect(&self, _ctx: &Context, dest: &Address) -> Result<BoxedStream, ProxyError> {
        debug!(server = %self.server, dest = %dest, "SS-2022 chunked outbound connecting");
        let tcp = tcp_connect(self.server).await?;
        tcp.set_nodelay(true)?;
        Ok(Box::new(
            open_ss2022_stream(Box::new(tcp), &self.psk, dest).await?,
        ))
    }
}

const MAX_TIME_DIFF: u64 = 30;
const TYPE_SERVER: u8 = 0x01;

/// Open an SS-2022 session on `raw`: send request headers, read response
/// header (SIP022), and return a bidirectional AEAD stream ready for relay.
///
/// Wire flow:
///   client→server: req_salt(32) | enc_fixed_hdr(27) | enc_var_hdr(N+16) → flush
///   server→client: resp_salt(32) | enc_resp_hdr(59) | enc_initial(len+16)
///   data:  both sides use regular length-prefixed chunks, nonces starting at 2.
pub async fn open_ss2022_stream(
    mut raw: BoxedStream,
    psk: &[u8; 32],
    dest: &Address,
) -> Result<Ss2022Stream, ProxyError> {
    // ── 1. Send request ───────────────────────────────────────────────────────
    let mut req_salt = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut req_salt);
    raw.write_all(&req_salt).await?;

    let req_subkey = derive_subkey(psk, &req_salt);
    let req_cipher = Aes256Gcm::new(GenericArray::from_slice(&req_subkey));
    let variable = build_request_variable_header(dest)?;

    let mut fixed = [0u8; 11];
    fixed[0] = TYPE_TCP;
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    fixed[1..9].copy_from_slice(&ts.to_be_bytes());
    fixed[9..11].copy_from_slice(&(variable.len() as u16).to_be_bytes());

    let fixed_ct = req_cipher
        .encrypt(GenericArray::from_slice(&make_nonce(0)), fixed.as_slice())
        .map_err(|_| ProxyError::Protocol("SS-2022: fixed header encrypt failed".into()))?;
    let variable_ct = req_cipher
        .encrypt(
            GenericArray::from_slice(&make_nonce(1)),
            variable.as_slice(),
        )
        .map_err(|_| ProxyError::Protocol("SS-2022: variable header encrypt failed".into()))?;
    raw.write_all(&fixed_ct).await?;
    raw.write_all(&variable_ct).await?;
    raw.flush().await?;

    // ── 2. Read server response header ────────────────────────────────────────
    // resp_salt (32) | enc_resp_header (43+16=59) | enc_initial_payload (len+16)
    let mut resp_salt = [0u8; 32];
    raw.read_exact(&mut resp_salt).await?;

    let resp_subkey = derive_subkey(psk, &resp_salt);
    let resp_cipher = Aes256Gcm::new(GenericArray::from_slice(&resp_subkey));

    let mut resp_hdr_ct = [0u8; 43 + 16];
    raw.read_exact(&mut resp_hdr_ct).await?;
    let resp_hdr = resp_cipher
        .decrypt(
            GenericArray::from_slice(&make_nonce(0)),
            resp_hdr_ct.as_ref(),
        )
        .map_err(|_| ProxyError::Protocol("SS-2022: response header decrypt failed".into()))?;

    if resp_hdr.len() != 43 || resp_hdr[0] != TYPE_SERVER {
        return Err(ProxyError::Protocol(
            "SS-2022: invalid response header type".into(),
        ));
    }
    let resp_ts = super::u64_from_be8(&resp_hdr[1..9])?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if resp_ts.abs_diff(now) > MAX_TIME_DIFF {
        return Err(ProxyError::AuthFailed);
    }

    // Bytes 41-43: initial payload length (may be 0).
    let initial_len = u16::from_be_bytes([resp_hdr[41], resp_hdr[42]]) as usize;
    let mut initial_ct = vec![0u8; initial_len + 16];
    raw.read_exact(&mut initial_ct).await?;
    let initial_pt = resp_cipher
        .decrypt(
            GenericArray::from_slice(&make_nonce(1)),
            initial_ct.as_slice(),
        )
        .map_err(|_| ProxyError::Protocol("SS-2022: initial payload decrypt failed".into()))?;

    // ── 3. Return bidirectional data stream (nonces start at 2 both sides) ───
    Ok(Ss2022Stream::new_bidir(
        raw,
        &resp_subkey,
        2,
        &req_subkey,
        2,
        BytesMut::from(initial_pt.as_slice()),
        None,
    ))
}

/// Build the SIP022 request variable header plaintext.
///
/// ```text
/// atyp(1) | addr | port(2 BE) | padding_len(2 BE)=0 | initial_payload(empty)
/// ```
fn build_request_variable_header(dest: &Address) -> Result<Vec<u8>, ProxyError> {
    let mut buf = Vec::with_capacity(32);
    match dest {
        Address::Ipv4(ip, port) => {
            buf.push(ATYP_IPV4);
            buf.extend_from_slice(&ip.octets());
            buf.extend_from_slice(&port.to_be_bytes());
        }
        Address::Ipv6(ip, port) => {
            buf.push(ATYP_IPV6);
            buf.extend_from_slice(&ip.octets());
            buf.extend_from_slice(&port.to_be_bytes());
        }
        Address::Domain(name, port) => {
            buf.push(ATYP_DOMAIN);
            buf.push(domain_wire_len(name)?);
            buf.extend_from_slice(name.as_bytes());
            buf.extend_from_slice(&port.to_be_bytes());
        }
    }
    buf.extend_from_slice(&0u16.to_be_bytes()); // padding_len = 0
    Ok(buf)
}

fn make_nonce(counter: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..8].copy_from_slice(&counter.to_le_bytes());
    n
}
