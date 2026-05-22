//! Hysteria2 authentication handshake.
//!
//! The first QUIC stream opened by the client is the auth stream.
//! The client sends its password and bandwidth limits; the server validates
//! and responds. All subsequent streams are proxy streams.
//!
//! # Protocol flow
//!
//! 1. Client opens the first bidirectional QUIC stream.
//! 2. Client calls `client_auth()` which encodes and sends an `AuthRequest`.
//! 3. Server calls `server_auth()` which reads the `AuthRequest`, validates
//!    the password, and sends an `AuthResponse`.
//! 4. Client reads the response and returns `Ok(up_mbps, down_mbps)` on success
//!    or `Err(AuthError::WrongPassword)` if the server rejected it.

use tokio::io::{AsyncRead, AsyncWrite};

use super::proto::{
    AuthRequest, AuthResponse, decode_auth_request, decode_auth_response, encode_auth_request,
    encode_auth_response,
};

/// Errors that can occur during Hysteria2 authentication.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// The server rejected the client's password.
    #[error("authentication failed: wrong password")]
    WrongPassword,

    /// The peer sent a malformed or unexpected message.
    #[error("protocol error: {0}")]
    Protocol(String),

    /// An I/O error occurred while reading or writing the auth stream.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<anyhow::Error> for AuthError {
    fn from(e: anyhow::Error) -> Self {
        AuthError::Protocol(e.to_string())
    }
}

/// Server-side authentication handshake.
///
/// Reads the `AuthRequest` from `stream`, validates the password, and sends an
/// `AuthResponse`. Returns `(up_mbps, down_mbps)` from the client's request on
/// success.
///
/// # Errors
///
/// - `AuthError::WrongPassword` — client provided a wrong password.
/// - `AuthError::Protocol` — malformed auth frame.
/// - `AuthError::Io` — network I/O error.
pub async fn server_auth<S>(stream: &mut S, expected_password: &str) -> Result<(u64, u64), AuthError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let req = decode_auth_request(stream).await?;

    if req.auth != expected_password {
        // Send a failure response before closing.
        let resp = AuthResponse {
            ok: false,
            up_mbps: 0,
            down_mbps: 0,
        };
        // Best-effort send; ignore write errors since we're closing anyway.
        let _ = encode_auth_response(stream, &resp).await;
        return Err(AuthError::WrongPassword);
    }

    let resp = AuthResponse {
        ok: true,
        // Echo back the client's requested bandwidth as a simple acknowledgement.
        // A real implementation would cap this at the server's configured limit.
        up_mbps: req.up_mbps,
        down_mbps: req.down_mbps,
    };
    encode_auth_response(stream, &resp)
        .await
        .map_err(AuthError::Io)?;

    Ok((req.up_mbps as u64, req.down_mbps as u64))
}

/// Client-side authentication handshake.
///
/// Sends an `AuthRequest` with `password` and the requested bandwidth, then
/// reads the server's `AuthResponse`. Returns `(up_mbps, down_mbps)` as allowed
/// by the server.
///
/// # Errors
///
/// - `AuthError::WrongPassword` — server rejected the password.
/// - `AuthError::Protocol` — malformed response frame.
/// - `AuthError::Io` — network I/O error.
pub async fn client_auth<S>(
    stream: &mut S,
    password: &str,
    up_mbps: u64,
    down_mbps: u64,
) -> Result<(u64, u64), AuthError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let req = AuthRequest {
        auth: password.to_string(),
        up_mbps: up_mbps as u32,
        down_mbps: down_mbps as u32,
    };
    encode_auth_request(stream, &req)
        .await
        .map_err(AuthError::Io)?;

    let resp = decode_auth_response(stream).await?;

    if !resp.ok {
        return Err(AuthError::WrongPassword);
    }

    Ok((resp.up_mbps as u64, resp.down_mbps as u64))
}
