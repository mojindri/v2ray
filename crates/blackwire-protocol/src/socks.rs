//! SOCKS5 inbound handler.
//!
//! SOCKS5 is the standard local proxy protocol used by browsers, `curl`, and
//! most applications when you configure a system proxy. It runs on a local port
//! (typically 1080) and accepts connections from local applications.
//!
//! # How SOCKS5 works (simplified)
//!
//! The client and server do a brief handshake:
//!
//! ```text
//! Client → Server:  SOCKS version (5) + list of authentication methods
//! Server → Client:  chosen authentication method (0x00 = no auth)
//!
//! Client → Server:  CONNECT command + destination address + port
//! Server → Client:  success/failure reply
//!
//! (Now the proxy relays raw bytes between client and destination)
//! ```
//!
//! # This implementation
//!
//! - SOCKS version 5 only (no SOCKS4)
//! - No authentication (method 0x00)
//! - CONNECT command only (no BIND or UDP ASSOCIATE in Phase 1)
//! - Supports IPv4, IPv6, and domain name destinations
//!
//! # References
//! RFC 1928 — SOCKS Protocol Version 5

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::debug;

use blackwire_app::context::Context;
use blackwire_app::dispatcher::Dispatcher;
use blackwire_app::features::InboundHandler;
use blackwire_common::{read_socks5_address, Address, BoxedStream, Network, ProxyError, ATYP_IPV4};

// ── SOCKS5 protocol constants ─────────────────────────────────────────────────

/// The SOCKS protocol version byte. Any other version is rejected.
const SOCKS_VERSION: u8 = 5;

/// Authentication method: no authentication required.
const METHOD_NO_AUTH: u8 = 0x00;

/// Authentication method: no acceptable methods (sent by server to reject).
const METHOD_NO_ACCEPTABLE: u8 = 0xFF;

/// Command: CONNECT (open a TCP connection to the destination).
const CMD_CONNECT: u8 = 0x01;

/// Reserved byte in the CONNECT request (must be 0x00).
const RSV: u8 = 0x00;

/// Reply code: success.
const REP_SUCCESS: u8 = 0x00;

/// Reply code: command not supported.
const REP_CMD_NOT_SUPPORTED: u8 = 0x07;

/// Reply code: address type not supported.
#[allow(dead_code)]
const REP_ATYP_NOT_SUPPORTED: u8 = 0x08;

// ── SOCKS5 inbound ────────────────────────────────────────────────────────────

/// The SOCKS5 inbound handler.
///
/// Listens for SOCKS5 connections, performs the handshake, extracts the
/// destination address, then hands the connection to the dispatcher.
pub struct Socks5Inbound {
    /// Unique tag for this inbound (from config.json).
    tag: String,
}

impl Socks5Inbound {
    /// Create a new SOCKS5 inbound with the given tag.
    pub fn new(tag: impl Into<String>) -> Arc<Self> {
        Arc::new(Self { tag: tag.into() })
    }
}

#[async_trait]
impl InboundHandler for Socks5Inbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn networks(&self) -> &[Network] {
        // SOCKS5 in Phase 1 only handles TCP. UDP ASSOCIATE is not implemented yet.
        &[Network::Tcp]
    }

    async fn handle(
        &self,
        mut stream: BoxedStream,
        source: SocketAddr,
        dispatcher: Arc<dyn Dispatcher>,
    ) -> Result<(), ProxyError> {
        // Step 1: Read and validate the greeting (version + auth methods).
        let dest = socks5_handshake(&mut stream).await?;

        debug!(source = %source, dest = %dest, "SOCKS5 connection established");

        // Step 2: Hand off to the dispatcher with the destination address.
        let ctx = Context::new(&self.tag, source);
        dispatcher.dispatch(ctx, dest, stream).await
    }
}

// ── SOCKS5 handshake logic ────────────────────────────────────────────────────

/// Perform the full SOCKS5 handshake and return the destination address.
///
/// After this function returns `Ok(dest)`, the stream is positioned at the
/// start of the proxied data — no more SOCKS5 framing, just raw bytes.
async fn socks5_handshake(stream: &mut BoxedStream) -> Result<Address, ProxyError> {
    // ── Phase 1: Greeting ────────────────────────────────────────────────────
    //
    // The client sends:
    //   VER (1)   — version, must be 5
    //   NMETHODS (1) — number of supported authentication methods
    //   METHODS (NMETHODS) — list of method bytes

    let ver = stream.read_u8().await?;
    if ver != SOCKS_VERSION {
        return Err(ProxyError::Protocol(format!(
            "SOCKS version {ver} not supported (expected 5)"
        )));
    }

    let nmethods = stream.read_u8().await? as usize;
    if nmethods == 0 {
        return Err(ProxyError::Protocol("no auth methods offered".into()));
    }

    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await?;

    // We only support "no authentication" (method 0x00).
    // Check if the client offered it.
    if !methods.contains(&METHOD_NO_AUTH) {
        // Tell the client we have no acceptable method and bail.
        stream
            .write_all(&[SOCKS_VERSION, METHOD_NO_ACCEPTABLE])
            .await?;
        return Err(ProxyError::AuthFailed);
    }

    // Tell the client we chose "no authentication".
    stream.write_all(&[SOCKS_VERSION, METHOD_NO_AUTH]).await?;

    // ── Phase 2: Request ─────────────────────────────────────────────────────
    //
    // The client sends:
    //   VER (1)   — version again
    //   CMD (1)   — 0x01 = CONNECT, 0x02 = BIND, 0x03 = UDP ASSOCIATE
    //   RSV (1)   — reserved, must be 0x00
    //   ATYP (1)  — address type: 0x01 IPv4, 0x03 domain, 0x04 IPv6
    //   DST.ADDR  — the destination address (length depends on ATYP)
    //   DST.PORT (2) — destination port in big-endian byte order

    let ver = stream.read_u8().await?;
    if ver != SOCKS_VERSION {
        return Err(ProxyError::Protocol("bad version in request".into()));
    }

    let cmd = stream.read_u8().await?;
    let _rsv = stream.read_u8().await?; // reserved byte, ignored

    if cmd != CMD_CONNECT {
        // We only support CONNECT in Phase 1.
        // Send "command not supported" and return an error.
        send_reply(stream, REP_CMD_NOT_SUPPORTED).await?;
        return Err(ProxyError::Protocol(format!(
            "SOCKS5 CMD {cmd} not supported"
        )));
    }

    let atyp = stream.read_u8().await?;
    let dest = read_socks5_address(stream, atyp, "SOCKS5").await?;

    // ── Phase 3: Reply ───────────────────────────────────────────────────────
    //
    // The server replies:
    //   VER (1)        — 5
    //   REP (1)        — 0x00 = success
    //   RSV (1)        — 0x00 reserved
    //   ATYP (1)       — address type of BND.ADDR
    //   BND.ADDR (var) — the address the server bound to (we send 0.0.0.0)
    //   BND.PORT (2)   — the port the server bound to (we send 0)
    //
    // We always reply with 0.0.0.0:0 because we do not actually bind
    // a local port for the client — we just relay bytes.
    send_reply(stream, REP_SUCCESS).await?;

    Ok(dest)
}

/// Send a SOCKS5 reply with the given reply code.
///
/// The bound address is always 0.0.0.0:0 — we tell the client we succeeded
/// (or failed) but do not bind a real address on its behalf.
async fn send_reply(stream: &mut BoxedStream, rep: u8) -> Result<(), ProxyError> {
    // Reply format:
    //   VER (1)   = 5
    //   REP (1)   = reply code
    //   RSV (1)   = 0
    //   ATYP (1)  = 1 (IPv4)
    //   ADDR (4)  = 0.0.0.0
    //   PORT (2)  = 0
    let reply = [SOCKS_VERSION, rep, RSV, ATYP_IPV4, 0, 0, 0, 0, 0, 0];
    stream.write_all(&reply).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use tokio::io::duplex;

    // Helper: performs a SOCKS5 CONNECT handshake from the "client" side
    // and returns the server's parsed destination address.
    async fn do_handshake(client_send: &[u8]) -> Result<Address, ProxyError> {
        let (mut client, server) = duplex(1024);
        let mut server_stream: BoxedStream = Box::new(server);

        // Send the client bytes in a separate task so we don't deadlock.
        let to_send = client_send.to_vec();
        tokio::spawn(async move {
            client.write_all(&to_send).await.unwrap();
            // Read and discard the server's replies so the server task can proceed.
            let mut buf = [0u8; 64];
            let _ = client.read(&mut buf).await;
            let _ = client.read(&mut buf).await;
        });

        socks5_handshake(&mut server_stream).await
    }

    // Checks that a well-formed CONNECT to an IPv4 address succeeds.
    #[tokio::test]
    async fn connect_ipv4_success() {
        // Greeting: VER=5, NMETHODS=1, METHOD=0x00
        // Request:  VER=5, CMD=CONNECT, RSV=0, ATYP=IPv4, 93.184.216.34, PORT=443
        let client_bytes = [
            5, 1, 0, // greeting
            5, 1, 0, 1, 93, 184, 216, 34, 1, 187, // request (port 443 = 0x01BB)
        ];
        let dest = do_handshake(&client_bytes).await.unwrap();
        assert_eq!(dest, Address::Ipv4(Ipv4Addr::new(93, 184, 216, 34), 443));
    }

    // Checks that a CONNECT to a domain name succeeds.
    #[tokio::test]
    async fn connect_domain_success() {
        // Domain: "example.com" (11 bytes)
        // Port: 443 = 0x01BB
        let domain = b"example.com";
        let mut client_bytes = vec![
            5, 1, 0, // greeting
            5, 1, 0, 3,    // request header
            11u8, // domain length
        ];
        client_bytes.extend_from_slice(domain);
        client_bytes.extend_from_slice(&[0x01, 0xBB]); // port 443

        let dest = do_handshake(&client_bytes).await.unwrap();
        assert_eq!(dest, Address::Domain("example.com".into(), 443));
    }

    // Checks that SOCKS version 4 is rejected.
    #[tokio::test]
    async fn socks4_rejected() {
        let client_bytes = [4, 1, 0]; // SOCKS4 greeting
        let (mut client, server) = duplex(64);
        let mut server_stream: BoxedStream = Box::new(server);
        tokio::spawn(async move {
            client.write_all(&client_bytes).await.unwrap();
        });
        let result = socks5_handshake(&mut server_stream).await;
        assert!(result.is_err());
    }

    // Checks that offering only GSSAPI auth (not no-auth) causes AUTH_FAILED.
    #[tokio::test]
    async fn auth_required_rejected() {
        // Client offers only GSSAPI (method 0x01), not no-auth (0x00).
        let client_bytes = [5, 1, 1]; // VER=5, NMETHODS=1, METHOD=GSSAPI
        let (mut client, server) = duplex(64);
        let mut server_stream: BoxedStream = Box::new(server);
        tokio::spawn(async move {
            client.write_all(&client_bytes).await.unwrap();
            let mut buf = [0u8; 2];
            let _ = client.read(&mut buf).await; // read rejection reply
        });
        let result = socks5_handshake(&mut server_stream).await;
        assert!(matches!(result, Err(ProxyError::AuthFailed)));
    }
}
