//! Trojan outbound handler — connects to a Trojan server.
//!
//! The client-side flow:
//!
//! 1. Connect to the server (TCP, or TCP + TLS).
//! 2. Send the Trojan header: token + CRLF + address + CRLF.
//! 3. Start bidirectional data relay.
//!
//! # TLS
//!
//! In production, Trojan always runs over TLS. The `connect_on_stream`
//! function can be called with a stream that is already TLS-wrapped —
//! the Trojan protocol layer is agnostic to what is underneath.
//!
//! For testing, we also provide a plain TCP path (no TLS).

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tracing::debug;

use proxy_app::context::Context;
use proxy_app::features::OutboundHandler;
use proxy_common::{Address, BoxedStream, ProxyError};

use super::codec::{compute_token, encode_request};

/// Configuration for a Trojan outbound connection.
#[derive(Debug, Clone)]
pub struct TrojanOutboundConfig {
    /// The Trojan server address and port.
    pub server: SocketAddr,

    /// The Trojan password. The SHA224 hex token is derived from this.
    pub password: String,
}

/// The Trojan outbound handler (plain TCP, no TLS).
///
/// For TLS-wrapped connections, use `connect_trojan_on_stream` directly.
pub struct TrojanOutbound {
    /// The unique tag for this outbound.
    tag: String,

    /// The pre-computed 56-char hex token derived from the password.
    token: String,

    /// The Trojan server address.
    server: SocketAddr,
}

impl TrojanOutbound {
    /// Create a new Trojan outbound handler.
    pub fn new(tag: impl Into<String>, config: TrojanOutboundConfig) -> Arc<Self> {
        Arc::new(Self {
            tag: tag.into(),
            token: compute_token(&config.password),
            server: config.server,
        })
    }
}

#[async_trait]
impl OutboundHandler for TrojanOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn connect(&self, _ctx: &Context, dest: &Address) -> Result<BoxedStream, ProxyError> {
        debug!(
            server = %self.server,
            dest = %dest,
            "Trojan outbound connecting"
        );

        let stream = TcpStream::connect(self.server).await?;
        stream.set_nodelay(true)?;

        connect_trojan_on_stream(Box::new(stream), &self.token, dest).await
    }
}

/// Send a Trojan header over an already-established stream.
///
/// This is the key building block for both plain-TCP and TLS-wrapped Trojan.
/// The caller is responsible for setting up the stream (TLS handshake, etc.)
/// before calling this function.
///
/// # Arguments
/// * `stream` — an already-connected stream (TCP or TLS)
/// * `token`  — the 56-char hex token from `compute_token(password)`
/// * `dest`   — the destination address and port
///
/// # Returns
/// The same stream, positioned after the Trojan header, ready for relay.
pub async fn connect_trojan_on_stream(
    mut stream: BoxedStream,
    token: &str,
    dest: &Address,
) -> Result<BoxedStream, ProxyError> {
    let header = encode_request(token, dest)?;
    stream.write_all(&header).await?;
    // No server-to-client handshake in Trojan — payload follows immediately.
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::{TcpListener, TcpStream};

    use crate::trojan::codec as trojan_codec;

    /// Client writes the Trojan header; server decodes it correctly.
    #[tokio::test]
    async fn connect_on_stream_roundtrip() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let password = "roundtrip-test";
        let expected_token = trojan_codec::compute_token(password);
        let dest = Address::Domain("example.com".into(), 443);

        // Server: decode the header and check the destination.
        let expected_dest = dest.clone();
        let expected_tok = expected_token.clone();
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut stream: BoxedStream = Box::new(tcp);
            let req = trojan_codec::decode_request(&mut stream).await.unwrap();
            assert_eq!(req.token, expected_tok.as_bytes());
            assert_eq!(req.dest, expected_dest);
        });

        // Client: connect and send the header.
        let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let _stream = connect_trojan_on_stream(Box::new(tcp), &expected_token, &dest)
            .await
            .unwrap();
    }
}
