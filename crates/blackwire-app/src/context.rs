//! Connection context — metadata carried alongside every proxy connection.
//!
//! When a client connects, we collect information about it (source address,
//! which inbound it arrived on, which user authenticated, etc.) and bundle
//! that into a `Context`. The context travels with the connection through
//! the routing and dispatching pipeline, and is used for:
//!
//!   - Logging (so each log line knows which user/inbound it came from)
//!   - Routing (rules can match on inbound tag, user name, etc.)
//!   - Statistics (per-user byte counts, per-inbound connection counts)

use std::net::SocketAddr;
use std::sync::Arc;

/// Metadata about a single proxy connection.
///
/// This is created when a new connection is accepted and passed through
/// the routing and dispatching pipeline.
#[derive(Debug, Clone, Default)]
pub struct Context {
    /// The IP address and port the client connected from.
    /// Used in logs and for IP-based routing rules.
    pub source: Option<SocketAddr>,

    /// The tag of the inbound that accepted this connection.
    /// Used in routing rules like "only apply rule X to connections from the SOCKS inbound".
    pub inbound_tag: String,

    /// The authenticated user's email/name, if any.
    /// Set after the protocol handler verifies the client's credentials.
    pub user: Option<Arc<str>>,

    /// The detected inner protocol (e.g. "http", "tls"), if sniffing is enabled.
    pub sniffed_protocol: Option<String>,

    /// Sniffed domain (HTTP Host or TLS SNI), if sniffing is enabled.
    pub sniffed_domain: Option<String>,

    /// Client requested VLESS flow `xtls-rprx-vision`.
    pub vision_flow: bool,
}

impl Context {
    /// Create a new context for a connection arriving on `inbound_tag` from `source`.
    pub fn new(inbound_tag: impl Into<String>, source: SocketAddr) -> Self {
        Self {
            source: Some(source),
            inbound_tag: inbound_tag.into(),
            user: None,
            sniffed_protocol: None,
            sniffed_domain: None,
            vision_flow: false,
        }
    }

    /// Mark XTLS Vision flow for relay optimizations.
    pub fn with_vision(mut self, enabled: bool) -> Self {
        self.vision_flow = enabled;
        self
    }

    /// Set the authenticated user on this context.
    pub fn with_user(mut self, user: impl Into<Arc<str>>) -> Self {
        self.user = Some(user.into());
        self
    }

    /// Attach sniffing results from [`crate::sniff::SniffResult`].
    pub fn with_sniff(mut self, protocol: Option<String>, domain: Option<String>) -> Self {
        self.sniffed_protocol = protocol;
        self.sniffed_domain = domain;
        self
    }
}
