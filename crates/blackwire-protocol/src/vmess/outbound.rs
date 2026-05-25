//! VMess AEAD outbound handler — connects to a VMess server.
//!
//! # Client-side flow
//!
//! 1. Dial TCP to the VMess server.
//! 2. Generate auth ID.
//! 3. Encode and encrypt the request header.
//! 4. Send: `auth_id(16) || enc_len(18) || encrypted_header`.
//! 5. Wrap the stream in AEAD chunk framing.
//! 6. Return the wrapped stream for bidirectional relay.

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::AsyncWriteExt;
use tracing::debug;

use blackwire_app::context::Context;
use blackwire_app::features::OutboundHandler;
use blackwire_common::{tcp_connect, Address, BoxedStream, ProxyError};

use super::auth::{cmd_key, generate_auth_id};
use super::codec::{
    encode_header, read_response_header, response_body_iv, response_body_key, Security,
};
use super::stream::VmessStream;

// ── Config ────────────────────────────────────────────────────────────────────

/// Configuration for a VMess outbound.
#[derive(Debug, Clone)]
pub struct VmessOutboundConfig {
    /// VMess server address.
    pub server: SocketAddr,

    /// User UUID (16 bytes).
    pub uuid: [u8; 16],
}

// ── Outbound handler ──────────────────────────────────────────────────────────

/// VMess AEAD outbound handler.
pub struct VmessOutbound {
    tag: String,
    server: SocketAddr,
    uuid: [u8; 16],
    cmd_key: [u8; 16],
}

impl VmessOutbound {
    /// Create a new VMess outbound handler.
    pub fn new(tag: impl Into<String>, config: VmessOutboundConfig) -> Arc<Self> {
        let key = cmd_key(&config.uuid);
        Arc::new(Self {
            tag: tag.into(),
            server: config.server,
            uuid: config.uuid,
            cmd_key: key,
        })
    }
}

#[async_trait]
impl OutboundHandler for VmessOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn connect(&self, _ctx: &Context, dest: &Address) -> Result<BoxedStream, ProxyError> {
        debug!(server = %self.server, dest = %dest, "VMess outbound connecting");

        let tcp = tcp_connect(self.server).await?;
        tcp.set_nodelay(true)?;

        connect_vmess_on_stream(Box::new(tcp), &self.uuid, &self.cmd_key, dest).await
    }
}

/// Send the VMess AEAD handshake over an already-established stream.
///
/// Returns a wrapped stream ready for bidirectional AEAD-encrypted relay.
pub async fn connect_vmess_on_stream(
    mut stream: BoxedStream,
    uuid: &[u8; 16],
    cmd_key_bytes: &[u8; 16],
    dest: &Address,
) -> Result<BoxedStream, ProxyError> {
    let auth_id = generate_auth_id(cmd_key_bytes);

    // Build the encrypted header.
    let (iv, key, v, connection_nonce, encrypted_len, header_ct) =
        encode_header(cmd_key_bytes, &auth_id, dest, Security::Aes128Gcm)?;

    // Wire: auth_id(16) || enc_len(18) || connection_nonce(8) || header_ciphertext
    stream.write_all(&auth_id).await?;
    stream.write_all(&encrypted_len).await?;
    stream.write_all(&connection_nonce).await?;
    stream.write_all(&header_ct).await?;
    stream.flush().await?;

    let resp_key = response_body_key(&key);
    let resp_iv = response_body_iv(&iv);
    read_response_header(&mut stream, v, &resp_key, &resp_iv).await?;

    // Wrap in VMess body framing.
    let wrapped: BoxedStream = Box::new(VmessStream::new_bidir(
        stream,
        &resp_key,
        &resp_iv,
        &key,
        &iv,
        Security::Aes128Gcm,
        0,
    ));

    let _ = uuid; // uuid is only used to derive cmd_key
    Ok(wrapped)
}

#[cfg(test)]
mod tests {
    use super::super::auth::cmd_key;

    fn test_uuid() -> [u8; 16] {
        *uuid::Uuid::parse_str("a3482e88-686a-4a58-8126-99c9df64b7bf")
            .unwrap()
            .as_bytes()
    }

    #[test]
    fn command_key_is_derived_from_uuid() {
        let uuid = test_uuid();
        let key = cmd_key(&uuid);
        assert_ne!(key, uuid);
    }
}
