//! VMess AEAD inbound handler.
//!
//! Wire sequence (client → server):
//! ```text
//! auth_id(16) | enc_len(18) | connection_nonce(8) | enc_header(N+16) | data_chunks
//! ```
//! Server responds:
//! ```text
//! enc_resp_len(18) | enc_resp_header | response_data_chunks
//! ```

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use dashmap::DashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, warn};

use proxy_app::context::Context;
use proxy_app::dispatcher::Dispatcher;
use proxy_app::features::InboundHandler;
use proxy_common::{BoxedStream, Network, ProxyError};

use super::auth::{cmd_key, validate_auth_id, MAX_TIME_DIFF_SECS};
use super::codec::{
    decode_header, decrypt_length_field, response_body_iv, response_body_key, Security,
};
use super::stream::VmessStream;

// ── User registry ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct VmessUser {
    pub uuid: [u8; 16],
    pub cmd_key: [u8; 16],
    pub email: String,
}

pub struct VmessUserRegistry {
    users: DashMap<[u8; 16], VmessUser>,
}

impl VmessUserRegistry {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            users: DashMap::new(),
        })
    }

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

pub struct VmessInbound {
    tag: String,
    registry: Arc<VmessUserRegistry>,
}

impl VmessInbound {
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
        // 1. Read 16-byte auth ID.
        let mut auth_id = [0u8; 16];
        stream.read_exact(&mut auth_id).await?;

        // 2. Identify user.
        let user = match self.registry.find_by_auth(&auth_id) {
            Some(u) => u,
            None => {
                warn!(source = %source, auth_id = %hex::encode(auth_id), "VMess auth failed — no matching user");
                return Err(ProxyError::AuthFailed);
            }
        };

        debug!(source = %source, user = %user.email, "VMess authenticated");

        // 3. Read encrypted length (18 bytes) — buffered before we have the nonce.
        let mut enc_len = [0u8; 18];
        stream.read_exact(&mut enc_len).await?;

        // 4. Read 8-byte connection nonce (appears after enc_len on wire).
        let mut connection_nonce = [0u8; 8];
        stream.read_exact(&mut connection_nonce).await?;

        // 5. Decrypt header length using nonce.
        let header_len = decrypt_length_field(&user.cmd_key, &auth_id, &connection_nonce, &enc_len)?;

        // 6. Decrypt request header.
        let request = match decode_header(&mut stream, &user.cmd_key, &auth_id, &connection_nonce, header_len).await {
            Ok(v) => v,
            Err(e) => {
                warn!(source = %source, error = %e, header_len, "VMess header decode failed");
                return Err(e);
            }
        };

        warn!(source = %source, dest = %request.dest, security = ?request.security, "VMess header decoded");

        // 7. Derive response keys.
        let resp_key = response_body_key(&request.key);
        let resp_iv = response_body_iv(&request.iv);

        // 8. Wrap in bidirectional VMess body stream.
        let mut vmess_stream = match request.security {
            Security::Aes128Gcm | Security::ChaCha20Poly1305 => {
                VmessStream::new_bidir(stream, &request.key, &request.iv, &resp_key, &resp_iv)
            }
        };

        // 9. VMess response header is encrypted as the first body bytes.
        vmess_stream.write_all(&[request.v, 0u8]).await?;
        vmess_stream.flush().await?;

        let vmess_stream: BoxedStream = Box::new(vmess_stream);

        let ctx = Context::new(&self.tag, source).with_user(user.email);
        dispatcher.dispatch(ctx, request.dest, vmess_stream).await
    }
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
        assert!(reg.find_by_auth(&auth).is_some());
    }

    #[test]
    fn reject_unknown_auth_id() {
        let reg = make_registry();
        assert!(reg.find_by_auth(&[0u8; 16]).is_none());
    }
}
