//! SS-2022 inbound handler — accepts Shadowsocks-2022 connections.
//!
//! # Server-side flow
//!
//! 1. Read 32-byte random salt from the stream.
//! 2. Check anti-replay filter; reject if salt was seen before.
//! 3. Derive session subkey: `blake3::derive_key("ss-subkey", psk || salt)`.
//! 4. Decrypt the AEAD header using the subkey.
//! 5. Validate timestamp (within ±30 seconds of now).
//! 6. Read destination address from header.
//! 7. Wrap remaining stream in `Ss2022Stream` and hand to dispatcher.
//!
//! # Header format (after salt, AES-256-GCM encrypted)
//!
//! ```text
//! type(1)=0x00 | timestamp(8 BE) | atyp(1) | addr | port(2 BE) | padding_len(2 BE) | padding(N)
//! ```

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use tokio::io::AsyncReadExt;
use tracing::{debug, warn};

use aes_gcm::{
    aead::{generic_array::GenericArray, Aead},
    Aes256Gcm, KeyInit,
};

use proxy_app::context::Context;
use proxy_app::dispatcher::Dispatcher;
use proxy_app::features::InboundHandler;
use proxy_common::{Address, BoxedStream, Network, ProxyError};

use super::{password_to_psk, replay::SaltReplay, stream::Ss2022Stream, subkey::derive_subkey};

/// Maximum timestamp drift allowed (seconds).
const MAX_TIME_DIFF: u64 = 30;

/// SS-2022 connection type: TCP.
const TYPE_TCP: u8 = 0x00;

/// ATYP constants (SOCKS5 style).
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

/// SS-2022 inbound handler.
pub struct Ss2022Inbound {
    tag: String,
    /// 32-byte pre-shared key derived from the password.
    psk: [u8; 32],
    /// Anti-replay filter.
    replay: SaltReplay,
}

impl Ss2022Inbound {
    /// Create a new SS-2022 inbound handler.
    ///
    /// # Arguments
    /// * `tag`      — unique inbound tag from config
    /// * `password` — raw UTF-8 password; PSK = blake3::hash(password)
    pub fn new(tag: impl Into<String>, password: &str) -> Arc<Self> {
        Arc::new(Self {
            tag: tag.into(),
            psk: password_to_psk(password),
            replay: SaltReplay::new(),
        })
    }
}

#[async_trait]
impl InboundHandler for Ss2022Inbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn networks(&self) -> &[Network] {
        &[Network::Tcp]
    }

    async fn handle(
        &self,
        mut stream: BoxedStream,
        source: SocketAddr,
        dispatcher: Arc<dyn Dispatcher>,
    ) -> Result<(), ProxyError> {
        // Step 1: Read 32-byte salt.
        let mut salt = [0u8; 32];
        stream.read_exact(&mut salt).await?;

        // Step 2: Anti-replay check.
        if !self.replay.check_and_insert(&salt) {
            warn!(source = %source, "SS-2022: replayed salt — dropping connection");
            return Err(ProxyError::AuthFailed);
        }

        // Step 3: Derive session subkey.
        let subkey = derive_subkey(&self.psk, &salt);

        // Step 4: Decrypt the AEAD header.
        // Header is encrypted as a single AEAD blob.
        // Max header size: 1(type) + 8(ts) + 1(atyp) + 1(len)+255(domain) + 2(port) + 2(pad_len) + 255(padding)
        // We read up to 512 bytes to cover all cases.
        let header_ct = read_header_ciphertext(&mut stream).await?;
        let cipher = Aes256Gcm::new(GenericArray::from_slice(&subkey));
        // Nonce 0 for the header.
        let nonce = GenericArray::from_slice(&[0u8; 12]);
        let header_pt = cipher
            .decrypt(nonce, header_ct.as_slice())
            .map_err(|_| ProxyError::AuthFailed)?;

        // Step 5 & 6: Parse header plaintext.
        let (dest, _payload_start) = parse_header(&header_pt, source)?;

        debug!(source = %source, dest = %dest, "SS-2022 inbound authenticated");

        // Step 7: Wrap stream in AEAD chunk framing and dispatch.
        let data_stream: BoxedStream = Box::new(Ss2022Stream::new(stream, &subkey));
        let ctx = Context::new(&self.tag, source);
        dispatcher.dispatch(ctx, dest, data_stream).await
    }
}

/// Read the variable-length encrypted header.
///
/// The header is sent as:
///   header_len (2 bytes BE) + ciphertext (header_len bytes + 16 tag)
async fn read_header_ciphertext(stream: &mut BoxedStream) -> Result<Vec<u8>, ProxyError> {
    let len = stream.read_u16().await? as usize;
    if len == 0 || len > 512 {
        return Err(ProxyError::Protocol("SS-2022: invalid header length".into()));
    }
    let mut ct = vec![0u8; len + 16];
    stream.read_exact(&mut ct).await?;
    Ok(ct)
}

/// Parse the decrypted header bytes and extract the destination address.
///
/// Returns `(dest, bytes_consumed)`.
fn parse_header(data: &[u8], source: SocketAddr) -> Result<(Address, usize), ProxyError> {
    let mut pos = 0;

    // Type byte (must be 0x00 for TCP).
    if data.is_empty() {
        return Err(ProxyError::Protocol("SS-2022: header too short".into()));
    }
    let conn_type = data[pos];
    pos += 1;
    if conn_type != TYPE_TCP {
        return Err(ProxyError::Protocol(format!(
            "SS-2022: unsupported type {conn_type:#x}"
        )));
    }

    // Timestamp (8 bytes, big-endian Unix seconds).
    if data.len() < pos + 8 {
        return Err(ProxyError::Protocol("SS-2022: truncated timestamp".into()));
    }
    let ts = u64::from_be_bytes(data[pos..pos + 8].try_into().unwrap());
    pos += 8;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let diff = ts.abs_diff(now);
    if diff > MAX_TIME_DIFF {
        warn!(source = %source, ts = ts, now = now, "SS-2022: timestamp drift too large");
        return Err(ProxyError::AuthFailed);
    }

    // ATYP + address + port.
    if data.len() <= pos {
        return Err(ProxyError::Protocol("SS-2022: missing atyp".into()));
    }
    let atyp = data[pos];
    pos += 1;

    let dest = match atyp {
        ATYP_IPV4 => {
            if data.len() < pos + 6 {
                return Err(ProxyError::Protocol("SS-2022: truncated IPv4".into()));
            }
            let ip = std::net::Ipv4Addr::from([
                data[pos],
                data[pos + 1],
                data[pos + 2],
                data[pos + 3],
            ]);
            let port = u16::from_be_bytes([data[pos + 4], data[pos + 5]]);
            pos += 6;
            Address::Ipv4(ip, port)
        }
        ATYP_IPV6 => {
            if data.len() < pos + 18 {
                return Err(ProxyError::Protocol("SS-2022: truncated IPv6".into()));
            }
            let mut buf = [0u8; 16];
            buf.copy_from_slice(&data[pos..pos + 16]);
            let ip = std::net::Ipv6Addr::from(buf);
            let port = u16::from_be_bytes([data[pos + 16], data[pos + 17]]);
            pos += 18;
            Address::Ipv6(ip, port)
        }
        ATYP_DOMAIN => {
            if data.len() <= pos {
                return Err(ProxyError::Protocol("SS-2022: missing domain len".into()));
            }
            let dlen = data[pos] as usize;
            pos += 1;
            if data.len() < pos + dlen + 2 {
                return Err(ProxyError::Protocol("SS-2022: truncated domain".into()));
            }
            let domain = String::from_utf8(data[pos..pos + dlen].to_vec())
                .map_err(|_| ProxyError::Protocol("SS-2022: invalid domain UTF-8".into()))?;
            let port = u16::from_be_bytes([data[pos + dlen], data[pos + dlen + 1]]);
            pos += dlen + 2;
            Address::Domain(domain, port)
        }
        other => {
            return Err(ProxyError::Protocol(format!(
                "SS-2022: unknown ATYP {other:#x}"
            )));
        }
    };

    // Skip padding_len (2 bytes) + padding.
    if data.len() >= pos + 2 {
        let pad_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2 + pad_len;
    }

    Ok((dest, pos))
}
