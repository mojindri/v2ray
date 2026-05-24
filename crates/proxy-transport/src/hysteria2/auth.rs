//! Hysteria2 authentication over HTTP/3.

use http::HeaderMap;

use super::proto::{auth_request_from_headers, AuthRequest};

/// Errors that can occur during Hysteria2 authentication.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("authentication failed: wrong password")]
    WrongPassword,

    #[error("protocol error: {0}")]
    Protocol(String),
}

/// Validate a Hysteria2 auth request against the configured password.
pub fn verify_auth_request(
    headers: &HeaderMap,
    expected_password: &str,
) -> Result<AuthRequest, AuthError> {
    let req = auth_request_from_headers(headers).map_err(|e| AuthError::Protocol(e.to_string()))?;
    if req.auth != expected_password {
        return Err(AuthError::WrongPassword);
    }
    Ok(req)
}
