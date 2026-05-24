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
use tokio::net::TcpStream;
use tracing::debug;

use proxy_app::context::Context;
use proxy_app::features::OutboundHandler;
use proxy_common::{Address, BoxedStream, ProxyError};

use super::auth::{cmd_key, generate_auth_id};
use super::codec::{encode_header, Security};
use super::kdf::kdf;
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

        let tcp = TcpStream::connect(self.server).await?;
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
    let (iv, key, _v, connection_nonce, encrypted_len, header_ct) =
        encode_header(cmd_key_bytes, &auth_id, dest, Security::Aes128Gcm);

    // Wire: auth_id(16) || enc_len(18) || connection_nonce(8) || header_ciphertext
    stream.write_all(&auth_id).await?;
    stream.write_all(&encrypted_len).await?;
    stream.write_all(&connection_nonce).await?;
    stream.write_all(&header_ct).await?;
    stream.flush().await?;

    // Wrap in AEAD chunk framing.
    let wrapped: BoxedStream = Box::new(VmessStream::new(stream, &key, &iv));

    let _ = uuid; // uuid is only used to derive cmd_key
    Ok(wrapped)
}

/// Encrypt the 2-byte header length field.
fn encrypt_length_field(
    cmd_key: &[u8; 16],
    auth_id: &[u8; 16],
    len: u16,
) -> Result<Vec<u8>, ProxyError> {
    use super::codec::{PATH_HDR_IV, PATH_HDR_KEY};
    use aes_gcm::{
        aead::{generic_array::GenericArray, Aead, Payload},
        Aes128Gcm, KeyInit,
    };

    let enc_key: [u8; 16] = kdf(cmd_key, &[PATH_HDR_KEY, auth_id]);
    let enc_nonce: [u8; 12] = kdf(cmd_key, &[PATH_HDR_IV, auth_id]);

    let cipher = Aes128Gcm::new(GenericArray::from_slice(&enc_key));
    let nonce = GenericArray::from_slice(&enc_nonce);

    cipher
        .encrypt(
            nonce,
            Payload {
                msg: &len.to_be_bytes(),
                aad: auth_id,
            },
        )
        .map_err(|_| ProxyError::Protocol("VMess: length field encryption failed".into()))
}

#[cfg(test)]
mod tests {
    use super::super::auth::cmd_key;
    use super::*;

    fn test_uuid() -> [u8; 16] {
        *uuid::Uuid::parse_str("a3482e88-686a-4a58-8126-99c9df64b7bf")
            .unwrap()
            .as_bytes()
    }

    #[test]
    fn encrypt_decrypt_length_field_roundtrip() {
        let uuid = test_uuid();
        let key = cmd_key(&uuid);
        let auth_id = super::super::auth::generate_auth_id(&key);
        let len: u16 = 0x0180;

        let enc = encrypt_length_field(&key, &auth_id, len).unwrap();
        assert_eq!(enc.len(), 18); // 2 + 16 GCM tag

        // Decrypt via inbound helper.
        use super::super::inbound::decrypt_length_field;
        let decrypted =
            decrypt_length_field(&key, &auth_id, enc.as_slice().try_into().unwrap()).unwrap();
        assert_eq!(decrypted, len as usize);
    }
}
