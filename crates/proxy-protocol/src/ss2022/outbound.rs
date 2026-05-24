//! SS-2022 outbound handler — connects to a Shadowsocks-2022 server.
//!
//! # Wire format (SIP022 compatible)
//!
//! 1. Send salt (32 random bytes, plaintext).
//! 2. Send request header as the **first AEAD chunk** (nonce=0 for length, nonce=1 for data):
//!    `type(1)=0x00 | timestamp(8 BE) | pad_len(2 BE)=0 | atyp(1) | addr | port(2 BE)`
//! 3. Data relay uses the same AEAD stream (nonces continue from 2).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use rand::RngCore;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tracing::debug;

use proxy_app::context::Context;
use proxy_app::features::OutboundHandler;
use proxy_common::{Address, BoxedStream, ProxyError};

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
        let tcp = TcpStream::connect(self.server).await?;
        tcp.set_nodelay(true)?;
        Ok(Box::new(open_ss2022_stream(Box::new(tcp), &self.psk, dest).await?))
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
        let tcp = TcpStream::connect(self.server).await?;
        tcp.set_nodelay(true)?;
        Ok(Box::new(open_ss2022_stream(Box::new(tcp), &self.psk, dest).await?))
    }
}

/// Open an SS-2022 session on `raw`: send salt + request header, return the AEAD stream.
///
/// The returned `Ss2022Stream` has nonces already past the header (starts at nonce=2),
/// ready for transparent data relay.
pub async fn open_ss2022_stream(
    mut raw: BoxedStream,
    psk: &[u8; 32],
    dest: &Address,
) -> Result<Ss2022Stream, ProxyError> {
    // 1. Generate and send salt (plaintext).
    let mut salt = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut salt);
    raw.write_all(&salt).await?;

    // 2. Derive subkey and wrap raw stream in AEAD chunk stream.
    let subkey = derive_subkey(psk, &salt);
    let mut aead = Ss2022Stream::new_with_nonce(raw, &subkey, 0);

    // 3. Write request header as first AEAD chunk.
    let header = build_request_header(dest);
    aead.write_all(&header).await?;
    aead.flush().await?;

    // Nonce counter is now at 2 (length used nonce 0, data used nonce 1).
    Ok(aead)
}

/// Build the request header plaintext.
///
/// ```text
/// type(1)=0x00 | timestamp(8 BE) | pad_len(2 BE)=0 | atyp(1) | addr | port(2 BE)
/// ```
fn build_request_header(dest: &Address) -> Vec<u8> {
    let mut buf = Vec::with_capacity(32);
    buf.push(TYPE_TCP);
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    buf.extend_from_slice(&ts.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes()); // pad_len = 0
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
            buf.push(name.len() as u8);
            buf.extend_from_slice(name.as_bytes());
            buf.extend_from_slice(&port.to_be_bytes());
        }
    }
    buf
}
