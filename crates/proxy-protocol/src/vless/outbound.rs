//! VLESS outbound handler — connects to a VLESS server.
//!
//! This is the client-side half of the VLESS protocol. When the dispatcher
//! needs to forward a connection via VLESS, this handler:
//!
//!   1. Dials a TCP connection to the VLESS server.
//!   2. Sends the VLESS request header (UUID + destination address).
//!   3. Reads and validates the VLESS response header from the server.
//!   4. Returns the stream, now positioned at the start of proxied data,
//!      ready for bidirectional relay.
//!
//! The outbound does not handle TLS — in Phase 1 it connects over plain TCP.
//! In Phase 2, a TLS or REALITY transport layer will wrap the stream before
//! the VLESS header is sent.

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::debug;

use proxy_common::{Address, BoxedStream, ProxyError};
use proxy_app::context::Context;
use proxy_app::features::OutboundHandler;

use super::codec::{encode_request, Command};

/// VLESS outbound configuration.
#[derive(Debug, Clone)]
pub struct VlessOutboundConfig {
    /// The VLESS server's address and port.
    pub server: SocketAddr,

    /// The 16-byte user UUID to send in the VLESS header.
    pub uuid: [u8; 16],

    /// The optional flow string (e.g. "xtls-rprx-vision").
    /// Leave empty for normal VLESS without XTLS.
    pub flow: String,
}

/// The VLESS outbound handler.
pub struct VlessOutbound {
    /// The unique tag for this outbound (from config.json).
    tag: String,

    /// Connection configuration.
    config: VlessOutboundConfig,
}

impl VlessOutbound {
    /// Create a new VLESS outbound handler.
    pub fn new(tag: impl Into<String>, config: VlessOutboundConfig) -> Arc<Self> {
        Arc::new(Self {
            tag: tag.into(),
            config,
        })
    }
}

#[async_trait]
impl OutboundHandler for VlessOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn connect(
        &self,
        _ctx: &Context,
        dest: &Address,
    ) -> Result<BoxedStream, ProxyError> {
        // Step 1: Connect to the VLESS server over TCP.
        // In Phase 2, a TLS/REALITY transport layer will wrap this.
        let mut stream = TcpStream::connect(self.config.server).await?;
        stream.set_nodelay(true)?;

        debug!(
            server = %self.config.server,
            dest = %dest,
            "VLESS outbound connecting"
        );

        // Step 2: Send the VLESS request header.
        // This tells the server which user we are and where we want to connect.
        let header = encode_request(&self.config.uuid, &self.config.flow, Command::Tcp, dest);
        stream.write_all(&header).await?;

        // Step 3: Read the VLESS response header from the server.
        // The response is: VER (1 byte) + ADDONS_LEN (1 byte) + ADDONS (N bytes).
        // We must read this before sending any payload.
        let ver = stream.read_u8().await?;
        if ver != 0x00 {
            return Err(ProxyError::Protocol(format!(
                "VLESS server responded with unexpected version {ver:#x}"
            )));
        }

        let addons_len = stream.read_u8().await? as usize;
        if addons_len > 0 {
            // Read and discard the addons (Phase 2 may use them for flow control).
            let mut addons = vec![0u8; addons_len];
            stream.read_exact(&mut addons).await?;
        }

        debug!(server = %self.config.server, dest = %dest, "VLESS handshake complete");

        // The stream is now ready for raw bidirectional data relay.
        Ok(Box::new(stream))
    }
}
