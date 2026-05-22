//! TCP proxy over Hysteria2 QUIC streams.
//!
//! After authentication, each new QUIC bidirectional stream represents one
//! TCP proxy connection. This module handles reading the request header
//! (destination address) and writing the response header (OK or error).
//!
//! # Stream lifecycle
//!
//! 1. Client opens a new bidirectional QUIC stream.
//! 2. Client calls `client_write_request()` to send the destination.
//! 3. Server calls `server_read_request()` to decode the destination.
//! 4. Server connects to the destination and calls `server_write_response()`.
//! 5. Client calls `client_read_response()` to confirm the server is ready.
//! 6. Both sides relay data until one side closes the stream.

use proxy_common::{Address, ProxyError};
use tokio::io::{AsyncRead, AsyncWrite};

use super::proto::{
    Destination, TcpRequest, TcpResponse, decode_tcp_request, decode_tcp_response,
    encode_tcp_request, encode_tcp_response,
};

/// Server: read the TCP proxy request from the client.
///
/// Decodes the destination address from the start of the QUIC stream and
/// converts it to a `proxy_common::Address`.
///
/// # Errors
///
/// Returns a `ProxyError` if the frame is malformed or the address is invalid.
pub async fn server_read_request<R: AsyncRead + Unpin>(stream: &mut R) -> Result<Address, ProxyError> {
    let req = decode_tcp_request(stream)
        .await
        .map_err(|e| ProxyError::Protocol(format!("bad TCP request: {e}")))?;

    let addr = dest_to_address(req.dest)?;
    Ok(addr)
}

/// Server: write a TCP response back to the client.
///
/// `ok = true` means the server successfully connected to the destination.
/// `ok = false` means the connection failed; `msg` describes why.
pub async fn server_write_response<W: AsyncWrite + Unpin>(
    stream: &mut W,
    ok: bool,
    msg: &str,
) -> Result<(), ProxyError> {
    let resp = TcpResponse {
        ok,
        message: msg.to_string(),
    };
    encode_tcp_response(stream, &resp)
        .await
        .map_err(ProxyError::Io)
}

/// Client: write the TCP proxy request to the server.
///
/// Encodes the destination address and sends it at the start of the stream.
pub async fn client_write_request<W: AsyncWrite + Unpin>(
    stream: &mut W,
    dest: &Address,
) -> Result<(), ProxyError> {
    let destination = address_to_dest(dest);
    let req = TcpRequest { dest: destination };
    encode_tcp_request(stream, &req)
        .await
        .map_err(ProxyError::Io)
}

/// Client: read the TCP response from the server.
///
/// Returns `Ok(())` if the server confirmed it can reach the destination.
/// Returns a `ProxyError` if the server reported an error or the frame is invalid.
pub async fn client_read_response<R: AsyncRead + Unpin>(
    stream: &mut R,
) -> Result<(), ProxyError> {
    let resp = decode_tcp_response(stream)
        .await
        .map_err(|e| ProxyError::Protocol(format!("bad TCP response: {e}")))?;

    if !resp.ok {
        return Err(ProxyError::Protocol(format!(
            "server refused connection: {}",
            resp.message
        )));
    }

    Ok(())
}

// ── Conversion helpers ────────────────────────────────────────────────────────

/// Convert a proto `Destination` to a `proxy_common::Address`.
fn dest_to_address(dest: Destination) -> Result<Address, ProxyError> {
    match dest {
        Destination::V4(ip, port) => Ok(Address::Ipv4(ip, port)),
        Destination::V6(ip, port) => Ok(Address::Ipv6(ip, port)),
        Destination::Domain(name, port) => Ok(Address::Domain(name, port)),
    }
}

/// Convert a `proxy_common::Address` to a proto `Destination`.
fn address_to_dest(addr: &Address) -> Destination {
    match addr {
        Address::Ipv4(ip, port) => Destination::V4(*ip, *port),
        Address::Ipv6(ip, port) => Destination::V6(*ip, *port),
        Address::Domain(name, port) => Destination::Domain(name.clone(), *port),
    }
}
