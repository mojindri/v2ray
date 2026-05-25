//! SS-2022 inbound handler (SIP022 TCP server side).
//!
//! Request stream layout:
//! `salt | encrypted fixed header(11+16) | encrypted variable header(N+16) | data chunks...`
//!
//! Response stream layout:
//! `salt | encrypted fixed header(43+16) | encrypted first payload(N+16) | data chunks...`
//!
//! # How it works
//!
//! The server reads the client salt, derives a subkey, decrypts the request
//! headers, and extracts the target address. Then it sends its own response
//! salt and response header so both sides can continue with encrypted chunks.
//!
//! # Why
//!
//! SS-2022 checks salt replay and timestamp drift before accepting traffic.
//! That blocks simple replay attacks and stale handshakes.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::{
    aead::{generic_array::GenericArray, Aead},
    Aes256Gcm, KeyInit,
};
use async_trait::async_trait;
use bytes::BytesMut;
use rand::{Rng, RngExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, warn};

use proxy_app::context::Context;
use proxy_app::dispatcher::Dispatcher;
use proxy_app::features::InboundHandler;
use proxy_common::{BoxedStream, Network, ProxyError};

use super::{
    password_to_psk, replay::SaltReplay, stream::Ss2022Stream, subkey::derive_subkey, u64_from_be8,
    variable_header::parse_variable_header,
};

const MAX_TIME_DIFF: u64 = 30;
const TYPE_TCP: u8 = 0x00;
const TYPE_SERVER: u8 = 0x01;
/// SS-2022 inbound handler that accepts encrypted TCP sessions.
pub struct Ss2022Inbound {
    tag: String,
    psk: [u8; 32],
    replay: SaltReplay,
}

impl Ss2022Inbound {
    /// Build a new SS-2022 inbound handler from tag and password.
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
        let mut req_salt = [0u8; 32];
        stream.read_exact(&mut req_salt).await?;
        if !self.replay.check_and_insert(&req_salt) {
            warn!(source = %source, "SS-2022: replayed salt");
            return Err(ProxyError::AuthFailed);
        }

        let req_subkey = derive_subkey(&self.psk, &req_salt);
        let req_cipher = Aes256Gcm::new(GenericArray::from_slice(&req_subkey));

        // SIP022 request fixed header: type(1) | timestamp(8 BE) | length(2 BE)
        let mut fixed_ct = [0u8; 27];
        stream.read_exact(&mut fixed_ct).await?;
        let fixed = req_cipher
            .decrypt(GenericArray::from_slice(&make_nonce(0)), fixed_ct.as_ref())
            .map_err(|_| ProxyError::Protocol("SS-2022: fixed header decrypt failed".into()))?;
        if fixed.len() != 11 || fixed[0] != TYPE_TCP {
            return Err(ProxyError::Protocol(
                "SS-2022: invalid request fixed header".into(),
            ));
        }
        let ts = u64_from_be8(&fixed[1..9])?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if ts.abs_diff(now) > MAX_TIME_DIFF {
            warn!(source = %source, ts = ts, now = now, "SS-2022: timestamp drift too large");
            return Err(ProxyError::AuthFailed);
        }
        let variable_len = u16::from_be_bytes([fixed[9], fixed[10]]) as usize;

        let mut var_ct = vec![0u8; variable_len + 16];
        stream.read_exact(&mut var_ct).await?;
        let variable = req_cipher
            .decrypt(GenericArray::from_slice(&make_nonce(1)), var_ct.as_ref())
            .map_err(|_| ProxyError::Protocol("SS-2022: variable header decrypt failed".into()))?;

        let (dest, initial_payload) = parse_variable_header(&variable)?;
        debug!(source = %source, dest = %dest, "SS-2022 inbound authenticated");

        let mut resp_salt = [0u8; 32];
        rand::rng().fill(&mut resp_salt[..]);
        stream.write_all(&resp_salt).await?;
        let resp_subkey = derive_subkey(&self.psk, &resp_salt);

        // Send response fixed header eagerly (initial_payload_len=0) so the
        // client can finish its handshake before the echo data arrives.
        // Nonce=0: encrypted 43-byte header; nonce=1: encrypted empty payload.
        let resp_cipher = aes_gcm::Aes256Gcm::new(
            aes_gcm::aead::generic_array::GenericArray::from_slice(&resp_subkey),
        );
        let hdr_ct = {
            use aes_gcm::aead::Aead;
            let hdr = build_response_fixed_header(&req_salt);
            resp_cipher
                .encrypt(
                    aes_gcm::aead::generic_array::GenericArray::from_slice(&make_nonce(0)),
                    hdr.as_slice(),
                )
                .map_err(|_| ProxyError::Protocol("SS-2022: resp header encrypt failed".into()))?
        };
        let empty_ct = {
            use aes_gcm::aead::Aead;
            resp_cipher
                .encrypt(
                    aes_gcm::aead::generic_array::GenericArray::from_slice(&make_nonce(1)),
                    &[][..],
                )
                .map_err(|_| {
                    ProxyError::Protocol("SS-2022: empty initial payload encrypt failed".into())
                })?
        };
        stream.write_all(&hdr_ct).await?;
        stream.write_all(&empty_ct).await?;
        stream.flush().await?;

        // Data relay: write uses resp_subkey starting at nonce=2 (0 and 1 were
        // consumed above), read uses req_subkey starting at nonce=2.
        let vm = Ss2022Stream::new_bidir(
            stream,
            &req_subkey,
            2,
            &resp_subkey,
            2,
            BytesMut::from(initial_payload.as_slice()),
            None,
        );

        let ctx = Context::new(&self.tag, source);
        dispatcher.dispatch(ctx, dest, Box::new(vm)).await
    }
}

fn make_nonce(counter: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..8].copy_from_slice(&counter.to_le_bytes());
    n
}

fn build_response_fixed_header(req_salt: &[u8; 32]) -> [u8; 43] {
    let mut out = [0u8; 43];
    out[0] = TYPE_SERVER;
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    out[1..9].copy_from_slice(&ts.to_be_bytes());
    out[9..41].copy_from_slice(req_salt);
    // bytes 41-43: initial_payload_length = 0 (already zeroed)
    out
}
