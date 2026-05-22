//! proxy-common — shared building blocks for every other crate.
//!
//! This crate sits at the very bottom of the dependency graph, meaning
//! every other crate in the workspace can use it, but it cannot use any
//! of them. That keeps the dependency tree clean and prevents circular
//! imports.
//!
//! What lives here:
//! - [`address`]   — the universal `Address` type (IPv4 / IPv6 / domain name)
//! - [`stream`]    — the `BoxedStream` type: a single trait object that every
//!                   protocol and transport speaks to each other through
//! - [`error`]     — the `ProxyError` enum used across the whole project
//! - [`buf`]       — a buffer pool for reusing memory allocations

pub mod address;
pub mod buf;
pub mod error;
pub mod stream;
pub mod splice;

// Re-export the most commonly used items so callers can write
// `use proxy_common::Address` instead of `use proxy_common::address::Address`.
pub use address::{Address, Network};
pub use buf::BufferPool;
pub use error::ProxyError;
pub use stream::{AsyncReadWrite, BoxedStream, Link, PrependedStream};
