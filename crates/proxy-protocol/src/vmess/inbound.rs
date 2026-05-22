//! VMess AEAD inbound handler — accepts VMess connections.
//!
//! # Server-side flow
//!
//! 1. Read 16-byte auth ID from the stream.
//! 2. Identify the user by trying each registered UUID's `cmd_key` until
//!    `validate_auth_id` returns `true`.
//! 3. Read the AEAD-encrypted header length (2-byte ciphertext, 18 bytes on wire).
//! 4. Read and decrypt the full request header.
//! 5. Set up the AEAD data channel stream.
//! 6. Hand off to the dispatcher.

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use dashmap::DashMap;
use tokio::io::AsyncReadExt;
use tracing::{debug, warn};

use proxy_app::context::Context;
use proxy_app::dispatcher::Dispatcher;
use proxy_app::features::InboundHandler;
use proxy_common::{BoxedStream, Network, ProxyError};

use super::auth::{cmd_key, validate_auth_id, MAX_TIME_DIFF_SECS};
use super::codec::{decode_header, Security};
use super::stream::VmessStream;

// ── User registry ─────────────────────────────────────────────────────────────

/// A registered VMess user.
#[derive(Debug, Clone)]
pub struct VmessUser {
    /// The 16-byte UUID.
    pub uuid: [u8; 16],

    /// Derived cmd_key (precomputed for performance).
    pub cmd_key: [u8; 16],

    /// Optional email for logging.
    pub email: String,
}

/// Thread-safe registry of VMess users.
pub struct VmessUserRegistry {
    /// `cmd_key` → user, for O(1) lookup during auth.
    users: DashMap<[u8; 16], VmessUser>,
}

impl VmessUserRegistry {
    /// Create an empty registry.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            users: DashMap::new(),
        })
    }

    /// Register a user.
    pub fn add_user(&self, uuid: [u8; 16], email: impl Into<String>) {
        let key = cmd_key(&uuid);
        self.users.insert(
            key,
            VmessUser {
                uuid,
                cmd_key: key,
                email: email.into(),
            },
        );
    }

    /// Find the user whose `cmd_key` validates the given auth ID.
    pub fn find_by_auth(&self, auth_id: &[u8; 16]) -> Option<VmessUser> {
        for entry in self.users.iter() {
            if validate_auth_id(entry.key(), auth_id, MAX_TIME_DIFF_SECS) {
                return Some(entry.value().clone());
            }
        }
        None
    }
}

impl Default for VmessUserRegistry {
    fn default() -> Self {
        Self {
            users: DashMap::new(),
        }
    }
}

// ── Inbound handler ────────────────────────────────────────────────────────────

/// VMess AEAD inbound handler.
pub struct VmessInbound {
    tag: String,
    registry: Arc<VmessUserRegistry>,
}

impl VmessInbound {
    /// Create a new VMess inbound handler.
    pub fn new(tag: impl Into<String>, registry: Arc<VmessUserRegistry>) -> Arc<Self> {
        Arc::new(Self {
            tag: tag.into(),
            registry,
        })
    }
}

#[async_trait]
impl InboundHandler for VmessInbound {
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
        // Step 1: Read the 16-byte auth ID.
        let mut auth_id = [0u8; 16];
        stream.read_exact(&mut auth_id).await?;

        // Step 2: Identify user.
        let user = match self.registry.find_by_auth(&auth_id) {
            Some(u) => u,
            None => {
                warn!(source = %source, "VMess auth failed — no matching user");
                return Err(ProxyError::AuthFailed);
            }
        };

        debug!(source = %source, user = %user.email, "VMess authenticated");

        // Step 3: Read the encrypted header length.
        // The length field is a 2-byte plaintext encrypted to 18 bytes (2 + 16 tag).
        let mut len_enc = [0u8; 18];
        stream.read_exact(&mut len_enc).await?;

        // Decrypt length field.
        let enc_len = decrypt_length_field(&user.cmd_key, &auth_id, &len_enc)?;

        // Step 4: Read and decrypt the full header.
        let request = decode_header(&mut stream, &user.cmd_key, &auth_id, enc_len).await?;

        debug!(
            source = %source,
            dest = %request.dest,
            "VMess header decoded"
        );

        // Step 5: Wrap the stream in AEAD chunk framing.
        // For AES-128-GCM we use the request's key/iv directly.
        let vmess_stream: BoxedStream = match request.security {
            Security::Aes128Gcm => Box::new(VmessStream::new(stream, &request.key, &request.iv)),
            Security::ChaCha20Poly1305 => {
                // ChaCha20-Poly1305 variant uses the same stream type with a
                // different cipher. For now we fall back to AES-128-GCM since
                // the VmessStream only implements AES.
                // TODO: add ChaCha20-Poly1305 variant.
                Box::new(VmessStream::new(stream, &request.key, &request.iv))
            }
        };

        let ctx = Context::new(&self.tag, source).with_user(user.email);
        dispatcher.dispatch(ctx, request.dest, vmess_stream).await
    }
}

/// Decrypt the 2-byte header length field (18 bytes on wire = 2 plaintext + 16 tag).
pub(super) fn decrypt_length_field(
    cmd_key: &[u8; 16],
    auth_id: &[u8; 16],
    enc: &[u8; 18],
) -> Result<usize, ProxyError> {
    use super::codec::{PATH_HEADER_IV, PATH_HEADER_IV_2, PATH_HEADER_KEY, PATH_HEADER_KEY_2};
    use super::kdf::kdf;
    use aes_gcm::{
        aead::{generic_array::GenericArray, Aead, Payload},
        Aes128Gcm, KeyInit,
    };

    let key: [u8; 16] = kdf(cmd_key, &[PATH_HEADER_KEY, auth_id, PATH_HEADER_KEY_2]);
    let nonce: [u8; 12] = kdf(cmd_key, &[PATH_HEADER_IV, auth_id, PATH_HEADER_IV_2]);

    let cipher = Aes128Gcm::new(GenericArray::from_slice(&key));
    let nonce_ga = GenericArray::from_slice(&nonce);

    let plaintext = cipher
        .decrypt(
            nonce_ga,
            Payload {
                msg: enc,
                aad: auth_id,
            },
        )
        .map_err(|_| ProxyError::Protocol("VMess: length field decryption failed".into()))?;

    if plaintext.len() < 2 {
        return Err(ProxyError::Protocol("VMess: length field too short".into()));
    }

    Ok(u16::from_be_bytes([plaintext[0], plaintext[1]]) as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_registry() -> Arc<VmessUserRegistry> {
        let reg = VmessUserRegistry::new();
        let uuid = *uuid::Uuid::parse_str("a3482e88-686a-4a58-8126-99c9df64b7bf")
            .unwrap()
            .as_bytes();
        reg.add_user(uuid, "test@example.com");
        reg
    }

    #[test]
    fn find_by_valid_auth() {
        let reg = make_registry();
        let uuid = *uuid::Uuid::parse_str("a3482e88-686a-4a58-8126-99c9df64b7bf")
            .unwrap()
            .as_bytes();
        let key = cmd_key(&uuid);
        let now = super::super::auth::current_timestamp();
        let auth = super::super::auth::generate_auth_id_at(&key, now);
        let user = reg.find_by_auth(&auth);
        assert!(user.is_some());
        assert_eq!(user.unwrap().email, "test@example.com");
    }

    #[test]
    fn reject_unknown_auth_id() {
        let reg = make_registry();
        let auth = [0u8; 16];
        assert!(reg.find_by_auth(&auth).is_none());
    }
}
