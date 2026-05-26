//! Trojan inbound handler — accepts Trojan connections from clients.
//!
//! The server-side flow:
//!
//! 1. Read the 56-byte auth token from the stream.
//! 2. Compare it (in constant time) against the expected token derived from
//!    each configured password.
//! 3. If valid: read the SOCKS5 address, then relay to the dispatcher.
//! 4. If invalid: silently close or forward to a fallback (active-probe defence).
//!
//! # TLS requirement
//!
//! In production, Trojan must run over TLS — the stream passed to this handler
//! should already have been upgraded by `tls_accept`. In tests we use plain
//! TCP to avoid the overhead of a TLS round-trip.
//!
//! # Active-probe resistance
//!
//! If the auth token is wrong we do not send any error response. We simply
//! drop the connection (or forward to a fallback). An active prober sees the
//! same behaviour as a real HTTPS server — it cannot tell whether we are a
//! proxy or a normal web server.

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use subtle::ConstantTimeEq;
use tracing::{debug, warn};

use blackwire_app::context::Context;
use blackwire_app::dispatcher::Dispatcher;
use blackwire_app::features::InboundHandler;
use blackwire_common::{BoxedStream, Network, ProxyError};

use super::codec::{compute_token, decode_request, CMD_UDP_ASSOCIATE, TOKEN_LEN};
use super::udp::relay_trojan_udp;

/// A Trojan inbound handler.
pub struct TrojanInbound {
    /// The inbound tag from config.
    tag: String,

    /// Pre-computed 56-char auth tokens for each configured password.
    /// We compare against these on every connection.
    tokens: Vec<[u8; TOKEN_LEN]>,
}

impl TrojanInbound {
    /// Create a new Trojan inbound handler.
    ///
    /// # Arguments
    /// * `tag`       — unique inbound tag from config
    /// * `passwords` — list of accepted Trojan passwords
    pub fn new(tag: impl Into<String>, passwords: &[String]) -> Arc<Self> {
        let tokens = passwords
            .iter()
            .map(|p| {
                let hex = compute_token(p);
                let mut arr = [0u8; TOKEN_LEN];
                arr.copy_from_slice(hex.as_bytes());
                arr
            })
            .collect();

        Arc::new(Self {
            tag: tag.into(),
            tokens,
        })
    }

    /// Check whether the given raw token bytes match any configured password.
    ///
    /// Uses constant-time comparison to avoid timing-based side channels.
    fn validate_token(&self, token: &[u8; TOKEN_LEN]) -> bool {
        self.tokens
            .iter()
            .any(|expected| expected.ct_eq(token).into())
    }
}

#[async_trait]
impl InboundHandler for TrojanInbound {
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
        // Decode the Trojan request header (token + CRLF + address + CRLF).
        let request = decode_request(&mut stream).await.map_err(|e| {
            debug!(source = %source, error = %e, "Trojan header parse failed");
            e
        })?;

        // Validate the token in constant time.
        if !self.validate_token(&request.token) {
            warn!(source = %source, "Trojan auth failed — dropping connection");
            return Err(ProxyError::AuthFailed);
        }

        debug!(
            source = %source,
            dest = %request.dest,
            "Trojan authenticated"
        );

        if request.command == CMD_UDP_ASSOCIATE {
            return relay_trojan_udp(stream).await;
        }

        let ctx = Context::new(&self.tag, source);
        dispatcher.dispatch(ctx, request.dest, stream).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Validate that a correct token is accepted and a wrong one is rejected.
    #[test]
    fn token_validation() {
        let handler = TrojanInbound::new("test", &["correct-password".to_string()]);

        let good = compute_token("correct-password");
        let mut good_arr = [0u8; TOKEN_LEN];
        good_arr.copy_from_slice(good.as_bytes());

        let bad = compute_token("wrong-password");
        let mut bad_arr = [0u8; TOKEN_LEN];
        bad_arr.copy_from_slice(bad.as_bytes());

        assert!(handler.validate_token(&good_arr));
        assert!(!handler.validate_token(&bad_arr));
    }

    /// Multiple passwords: any valid one is accepted.
    #[test]
    fn multi_password_validation() {
        let handler = TrojanInbound::new("test", &["pass1".to_string(), "pass2".to_string()]);

        for pw in &["pass1", "pass2"] {
            let token_str = compute_token(pw);
            let mut arr = [0u8; TOKEN_LEN];
            arr.copy_from_slice(token_str.as_bytes());
            assert!(
                handler.validate_token(&arr),
                "password '{pw}' should be valid"
            );
        }

        let bad_str = compute_token("pass3");
        let mut bad_arr = [0u8; TOKEN_LEN];
        bad_arr.copy_from_slice(bad_str.as_bytes());
        assert!(!handler.validate_token(&bad_arr));
    }
}
