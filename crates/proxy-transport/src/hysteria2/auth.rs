//! Hysteria2 authentication over HTTP/3.

use http::HeaderMap;
use subtle::ConstantTimeEq;

use super::proto::{auth_request_from_headers, AuthRequest};

/// Errors that can occur during Hysteria2 authentication.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// Password in the request did not match server config.
    #[error("authentication failed: wrong password")]
    WrongPassword,

    /// Request headers were malformed or missing required fields.
    #[error("protocol error: {0}")]
    Protocol(String),
}

/// Validate a Hysteria2 auth request against the configured password.
pub fn verify_auth_request(
    headers: &HeaderMap,
    expected_password: &str,
) -> Result<AuthRequest, AuthError> {
    let req = auth_request_from_headers(headers).map_err(|e| AuthError::Protocol(e.to_string()))?;
    if req
        .auth
        .as_bytes()
        .ct_eq(expected_password.as_bytes())
        .unwrap_u8()
        != 1
    {
        return Err(AuthError::WrongPassword);
    }
    Ok(req)
}
