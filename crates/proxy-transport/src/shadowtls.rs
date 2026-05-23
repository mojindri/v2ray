//! ShadowTLS v3 transport.
//!
//! ShadowTLS makes a proxy connection look like a real HTTPS connection to an
//! outside observer. It does this by relaying the TLS handshake to a legitimate
//! backend (e.g. `www.apple.com:443`), so any TLS traffic analysis shows a real
//! certificate and handshake from that server.
//!
//! After the handshake, an 8-byte HMAC-SHA256 marker is used to signal that
//! the connection should switch from transparent relay to proxy mode.
//!
//! # Server flow
//!
//! 1. Accept TCP from client.
//! 2. Relay TLS handshake to real backend; extract `server_random`.
//! 3. Watch for the HMAC marker in the first Application Data from client.
//! 4. On valid marker: return the stream for the real protocol handler.
//! 5. On invalid/missing marker: drop the connection (authentication failure).
//!
//! # Client flow
//!
//! 1. Connect TCP to the ShadowTLS server.
//! 2. The server relays our TLS ClientHello to the backend.
//! 3. We complete the TLS handshake (seeing the backend's real certificate).
//! 4. Inject the HMAC marker as the first Application Data record.
//! 5. Continue with the real proxy protocol (e.g. VLESS).

pub mod client;
mod fuzzing;
pub mod handshake;
pub mod marker;
pub mod server;

use sha2::{Digest, Sha256};

pub use client::{shadowtls_connect, shadowtls_marker_connect};
#[cfg(feature = "fuzzing")]
pub use fuzzing::validate_first_application_record;
pub use marker::compute_marker;
pub use server::{shadowtls_accept, shadowtls_marker_accept, write_marker_record};

fn pseudo_server_random(dest: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"proxy-rs-shadowtls-marker-v1");
    hasher.update(dest.as_bytes());
    hasher.finalize().into()
}
