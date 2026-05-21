//! Error types for the entire proxy platform.
//!
//! All errors that can occur — authentication failure, bad protocol data,
//! network errors, timeouts — are represented here as variants of `ProxyError`.
//!
//! # Design rule
//!
//! Connection-level errors (a client sent bad data, a connection timed out)
//! are logged at `debug` or `info` level and then discarded — they are normal
//! events that should not crash the server or propagate up to `main`.
//!
//! Fatal startup errors (cannot bind to the configured port, config file is
//! missing) use `anyhow::Error` in the binary crate and terminate the process.
//!
//! # Security note
//!
//! `ProxyError::AuthFailed` must NEVER include the reason why authentication
//! failed. If we say "bad UUID" vs "replay attack" in an error message, an
//! attacker can use the different responses to probe the server. All auth
//! failures look identical to the caller.

use std::io;
use thiserror::Error;

/// Every error that can occur in the proxy, across all protocols and transports.
#[derive(Error, Debug)]
pub enum ProxyError {
    /// Authentication failed. The client is not allowed to proceed.
    ///
    /// This variant contains no details intentionally — see the security note
    /// in the module doc comment.
    #[error("authentication failed")]
    AuthFailed,

    /// The data sent by the client did not follow the expected protocol format.
    ///
    /// Examples: the VLESS header had an unexpected version byte, the SOCKS5
    /// handshake had an invalid address type, a TLS record was too long.
    #[error("protocol error: {0}")]
    Protocol(String),

    /// Something went wrong at the transport layer (TCP, TLS, WebSocket).
    ///
    /// Examples: the TCP connection was reset by the peer, the TLS handshake
    /// failed, the WebSocket was closed unexpectedly.
    #[error("transport error: {0}")]
    Transport(String),

    /// A TLS-specific error (certificate invalid, handshake failed, etc.).
    #[error("TLS error: {0}")]
    Tls(String),

    /// An operation did not complete within the allowed time.
    ///
    /// Timeouts are used for security: if a client connects but does not send
    /// the expected authentication data within 300ms, we treat it as a probe
    /// and forward to the fallback backend.
    #[error("timeout")]
    Timeout,

    /// The requested network type (TCP or UDP) is not supported by this handler.
    #[error("unsupported network type")]
    UnsupportedNetwork,

    /// DNS resolution failed for a domain name.
    ///
    /// The domain name is included so the caller can log which name failed.
    #[error("DNS resolution failed for '{0}'")]
    DnsResolutionFailed(String),

    /// The routing engine could not find a matching rule for this connection.
    ///
    /// This usually means the config is missing a catch-all rule, or the
    /// connection's attributes do not match any configured rule.
    #[error("no routing rule matched")]
    RoutingFailed,

    /// The connection must be forwarded to the fallback backend.
    ///
    /// This is not really an "error" — it is the normal path when a client
    /// fails authentication and the server must pretend to be a normal website.
    /// It is represented as an error so that it propagates cleanly through `?`.
    #[error("fallback required")]
    FallbackRequired,

    /// An I/O error from the operating system (read, write, connect, etc.).
    ///
    /// The `#[from]` attribute means `?` on any `io::Error` automatically
    /// converts it into this variant.
    #[error(transparent)]
    Io(#[from] io::Error),
}

impl ProxyError {
    /// Returns `true` if this error is the kind that should be logged at
    /// `debug` level rather than `warn`/`error`.
    ///
    /// Connection resets, EOF, and timeouts are completely normal for a proxy
    /// that handles thousands of concurrent connections — they should not
    /// clutter the logs.
    pub fn is_benign(&self) -> bool {
        match self {
            ProxyError::Timeout => true,
            ProxyError::FallbackRequired => true,
            ProxyError::Io(e) => matches!(
                e.kind(),
                io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::BrokenPipe
                    | io::ErrorKind::UnexpectedEof
            ),
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Checks that benign errors (connection reset, timeout) are classified correctly.
    // These errors are normal in a high-connection-count proxy and should not
    // produce warning log lines.
    #[test]
    fn benign_classification() {
        assert!(ProxyError::Timeout.is_benign());
        assert!(ProxyError::FallbackRequired.is_benign());

        let reset = ProxyError::Io(io::Error::from(io::ErrorKind::ConnectionReset));
        assert!(reset.is_benign());

        // Auth failures are NOT benign — we want to see them in logs.
        assert!(!ProxyError::AuthFailed.is_benign());
        assert!(!ProxyError::Protocol("bad byte".into()).is_benign());
    }

    // Checks that io::Error automatically converts into ProxyError::Io via the `?` operator.
    #[test]
    fn from_io_error() {
        let io_err = io::Error::from(io::ErrorKind::ConnectionRefused);
        let proxy_err = ProxyError::from(io_err);
        assert!(matches!(proxy_err, ProxyError::Io(_)));
    }
}
