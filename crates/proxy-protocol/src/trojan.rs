//! Trojan protocol — inbound and outbound handlers.
//!
//! Trojan disguises proxy traffic as HTTPS by running over TLS and using the
//! same port (443) as a normal web server. It was designed as an answer to the
//! limitations of Shadowsocks-style encryption — instead of trying to look
//! random, Trojan traffic looks exactly like TLS.
//!
//! # How Trojan works
//!
//! 1. The client opens a TLS connection to port 443.
//! 2. It sends a 56-byte authentication token (SHA224 of the password in hex).
//! 3. It follows with a SOCKS5-style address (ATYP + addr + port).
//! 4. Raw payload bytes follow immediately.
//!
//! The server validates the token. If valid, it relays traffic to the
//! destination. If invalid (or if auth fails), it forwards the connection to a
//! fallback HTTPS server — so probes see a real web page.
//!
//! # Modules
//!
//! - `codec`    — wire format (encode/decode token + address)
//! - `inbound`  — server-side handler (validate token, read address, relay)
//! - `outbound` — client-side handler (send token + address)

pub mod codec;
pub mod inbound;
pub mod outbound;

pub use codec::compute_token;
pub use inbound::TrojanInbound;
pub use outbound::{connect_trojan_on_stream, TrojanOutbound, TrojanOutboundConfig};
