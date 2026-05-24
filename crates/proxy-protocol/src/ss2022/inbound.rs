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

        // Step 3: Derive session subkey and wrap stream in AEAD chunk framing.
        // All bytes after the salt (including the request header) are sent as
        // AEAD-encrypted chunks. The first chunk is the request header.
        let subkey = derive_subkey(&self.psk, &salt);
        let mut aead = Ss2022Stream::new_with_nonce(stream, &subkey, 0);

        // Step 4: Read request header from the AEAD stream.
        // Header format: type(1) | timestamp(8 BE) | pad_len(2 BE) | padding | atyp | addr | port(2 BE)
        let type_byte = aead.read_u8().await?;
        if type_byte != TYPE_TCP {
            return Err(ProxyError::Protocol(format!(
                "SS-2022: unsupported type {type_byte:#x}"
            )));
        }

        let ts = aead.read_u64().await?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if ts.abs_diff(now) > MAX_TIME_DIFF {
            warn!(source = %source, ts = ts, now = now, "SS-2022: timestamp drift too large");
            return Err(ProxyError::AuthFailed);
        }

        // Step 5: Skip padding.
        let pad_len = aead.read_u16().await? as usize;
        if pad_len > 0 {
            let mut discard = vec![0u8; pad_len];
            aead.read_exact(&mut discard).await?;
        }

        // Step 6: Read SOCKS5 address.
        let atyp = aead.read_u8().await?;
        let dest = match atyp {
            ATYP_IPV4 => {
                let mut buf = [0u8; 6]; // 4 ip + 2 port
                aead.read_exact(&mut buf).await?;
                let ip = std::net::Ipv4Addr::from([buf[0], buf[1], buf[2], buf[3]]);
                let port = u16::from_be_bytes([buf[4], buf[5]]);
                Address::Ipv4(ip, port)
            }
            ATYP_IPV6 => {
                let mut buf = [0u8; 18]; // 16 ip + 2 port
                aead.read_exact(&mut buf).await?;
                let mut ip_bytes = [0u8; 16];
                ip_bytes.copy_from_slice(&buf[..16]);
                let ip = std::net::Ipv6Addr::from(ip_bytes);
                let port = u16::from_be_bytes([buf[16], buf[17]]);
                Address::Ipv6(ip, port)
            }
            ATYP_DOMAIN => {
                let dlen = aead.read_u8().await? as usize;
                let mut dbuf = vec![0u8; dlen + 2]; // domain + 2 port
                aead.read_exact(&mut dbuf).await?;
                let name = String::from_utf8(dbuf[..dlen].to_vec())
                    .map_err(|_| ProxyError::Protocol("SS-2022: invalid domain UTF-8".into()))?;
                let port = u16::from_be_bytes([dbuf[dlen], dbuf[dlen + 1]]);
                Address::Domain(name, port)
            }
            other => {
                return Err(ProxyError::Protocol(format!(
                    "SS-2022: unknown ATYP {other:#x} from {source}"
                )));
            }
        };

        debug!(source = %source, dest = %dest, "SS-2022 inbound authenticated");

        // Use the same AEAD stream for data relay (nonce counter already advanced past header).
        let ctx = Context::new(&self.tag, source);
        dispatcher.dispatch(ctx, dest, Box::new(aead)).await
    }
}

