//! blackwire-common — shared building blocks for every other crate.
//!
//! This crate sits at the very bottom of the dependency graph, meaning
//! every other crate in the workspace can use it, but it cannot use any
//! of them. That keeps the dependency tree clean and prevents circular
//! imports.
//!
//! What lives here:
//! - [`address`]   — the universal `Address` type (IPv4 / IPv6 / domain name)
//! - [`stream`]    — the `BoxedStream` type: a single trait object that every
//!   protocol and transport speaks to each other through
//! - [`error`]     — the `ProxyError` enum used across the whole project
//! - [`buf`]       — a buffer pool for reusing memory allocations

pub mod address;
pub mod buf;
pub mod connect;
pub mod error;
pub mod relay;
pub mod socks5_address;
pub mod splice;
pub mod stream;

// Re-export the most commonly used items so callers can write
// `use blackwire_common::Address` instead of `use blackwire_common::address::Address`.
pub use address::{Address, Network};
pub use buf::BufferPool;
pub use connect::{tcp_connect, tcp_connect_to, TCP_CONNECT_TIMEOUT};
pub use error::ProxyError;
pub use relay::{
    copy_bidirectional_with_idle, domain_wire_len, with_handshake_timeout, CONNECTION_IDLE_TIMEOUT,
};
pub use socks5_address::{
    decode_socks5_address, read_socks5_address, write_socks5_address, ATYP_DOMAIN, ATYP_IPV4,
    ATYP_IPV6,
};
pub use stream::{
    wrap_vision_stream, AsyncReadWrite, BoxedStream, Link, PooledStream, PrependedStream,
    ReunionStream, VisionStream,
};

// Linux-only relay optimization support.
//
// `try_into_tcp_stream` is not part of normal protocol handling. It exists so
// the Linux dispatcher relay can ask, "is this boxed stream still a plain TCP
// socket that can use splice(2)?" Non-Linux builds do not export it because
// they never compile the splice relay path.
#[cfg(target_os = "linux")]
pub use stream::try_into_tcp_stream;
#[cfg(target_os = "linux")]
pub use stream::try_into_tcp_stream_with_prefix;
#[cfg(target_os = "linux")]
pub use stream::try_into_vision_stream;
