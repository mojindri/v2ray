//! ShadowTLS v3 transport.
//!
//! ShadowTLS makes a proxy connection look like a real HTTPS connection to an
//! outside observer. It does this by relaying the TLS handshake to a legitimate
//! backend (e.g. `www.apple.com:443`), so any TLS traffic analysis shows a real
//! certificate and handshake from that server.
//!
//! Version 3 authenticates the first ClientHello through the 32-byte SessionID
//! field, taints backend TLS 1.3 ApplicationData records with a PSK-derived
//! HMAC, then switches to rolling-HMAC ApplicationData frames for proxy bytes.
//!
//! # Server flow
//!
//! 1. Accept TCP from client.
//! 2. Verify the ClientHello SessionID signature.
//! 3. Relay TLS handshake to a real TLS 1.3 backend; extract `server_random`.
//! 4. Taint backend ApplicationData until the client sends an authenticated
//!    v3 data frame.
//! 5. Return a v3 framed stream to the real protocol handler.
//!
//! # Client flow
//!
//! 1. Connect TCP to the ShadowTLS server.
//! 2. The server relays our TLS ClientHello to the backend.
//! 3. Verify the server by reading a tainted backend ApplicationData frame.
//! 4. Continue with v3 ApplicationData frames carrying the real proxy protocol.

pub mod client;
mod fuzzing;
pub mod handshake;
pub mod marker;
pub mod server;
pub mod v3;

use sha2::{Digest, Sha256};

pub use client::{shadowtls_connect, shadowtls_marker_connect, shadowtls_v3_connect};
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
