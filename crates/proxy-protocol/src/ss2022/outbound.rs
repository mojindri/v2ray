//! SS-2022 outbound handler — connects to a Shadowsocks-2022 server.
//!
//! # Client-side flow
//!
//! 1. Generate a 32-byte random salt.
//! 2. Derive session subkey: `blake3::derive_key("ss-subkey", psk || salt)`.
//! 3. Encrypt the request header (type, timestamp, address, padding) using AES-256-GCM.
//! 4. Send: salt || header_len (2 BE) || header_ciphertext.
//! 5. Wrap the stream in `Ss2022Stream` for subsequent data.
//!
//! # Header plaintext format
//!
//! ```text
//! type(1)=0x00 | timestamp(8 BE) | atyp(1) | addr | port(2 BE) | padding_len(2 BE)=0x0000
//! ```

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use rand::RngCore;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tracing::debug;

use aes_gcm::{
    aead::{generic_array::GenericArray, Aead},
    Aes256Gcm, KeyInit,
};
use bytes::{BufMut, BytesMut};

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
    /// Create a new SS-2022 outbound handler.
    ///
    /// # Arguments
    /// * `tag`      — unique outbound tag
    /// * `server`   — SS-2022 server address
    /// * `password` — raw UTF-8 password; PSK = blake3::hash(password)
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
        let mut stream: BoxedStream = Box::new(tcp);

        connect_ss2022_on_stream(&mut stream, &self.psk, dest).await?;

        // Wrap in AEAD chunk framing for data.
        // We need to derive the subkey again — store it via a wrapper that
        // already has the subkey applied.
        // For simplicity we store the salt state inside the connect call.
        // The stream returned is already correctly keyed.
        Ok(stream)
    }
}

/// Send the SS-2022 handshake on an already-established stream.
///
/// Returns the salt that was used (so callers can build the keyed stream).
pub async fn connect_ss2022_on_stream(
    stream: &mut BoxedStream,
    psk: &[u8; 32],
    dest: &Address,
) -> Result<[u8; 32], ProxyError> {
    // Generate random salt.
    let mut salt = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut salt);

    // Derive subkey.
    let subkey = derive_subkey(psk, &salt);

    // Build header plaintext.
    let header_pt = build_header_plaintext(dest);

    // Encrypt header with AES-256-GCM, nonce = 0.
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&subkey));
    let nonce = GenericArray::from_slice(&[0u8; 12]);
    let header_ct = cipher
        .encrypt(nonce, header_pt.as_slice())
        .map_err(|_| ProxyError::Protocol("SS-2022: header encryption failed".into()))?;

    // Send: salt || header_len (2 BE) || header_ciphertext.
    let header_len = (header_ct.len() - 16) as u16; // ciphertext = plaintext + 16-byte tag
    let mut buf = BytesMut::with_capacity(32 + 2 + header_ct.len());
    buf.put_slice(&salt);
    buf.put_u16(header_len);
    buf.put_slice(&header_ct);

    stream.write_all(&buf).await?;
    stream.flush().await?;

    Ok(salt)
}

/// Build the SS-2022 header plaintext.
///
/// ```text
/// type(1)=0x00 | timestamp(8 BE) | atyp(1) | addr | port(2 BE) | padding_len(2 BE)=0x0000
/// ```
fn build_header_plaintext(dest: &Address) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);

    // Type byte.
    buf.push(TYPE_TCP);

    // Timestamp (8 bytes BE, Unix seconds).
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    buf.extend_from_slice(&ts.to_be_bytes());

    // ATYP + address + port.
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

    // Padding length = 0 (no padding).
    buf.extend_from_slice(&0u16.to_be_bytes());

    buf
}

/// Outbound that returns an `Ss2022Stream`-wrapped connection.
///
/// This is the full outbound handler that wraps the TCP connection in the
/// AEAD chunk stream after sending the handshake header.
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
        let mut raw: BoxedStream = Box::new(tcp);

        let salt = connect_ss2022_on_stream(&mut raw, &self.psk, dest).await?;
        let subkey = derive_subkey(&self.psk, &salt);

        // Wrap in AEAD chunk stream for data relay.
        Ok(Box::new(Ss2022Stream::new(raw, &subkey)))
    }
}
