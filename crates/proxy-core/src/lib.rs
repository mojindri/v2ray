//! proxy-core — instance lifecycle and feature registry.
//!
//! This crate owns the running proxy instance. It is the glue that connects:
//!   - The config (from proxy-config)
//!   - The inbound handlers (from proxy-protocol)
//!   - The outbound handlers (from proxy-protocol)
//!   - The dispatcher (from proxy-app)
//!   - The router (from proxy-app)
//!
//! # Lifecycle
//!
//! 1. Load config → build `Instance`
//! 2. Call `instance.start()` → spawns Tokio tasks for each inbound listener
//! 3. The instance runs until `instance.stop()` is called or a fatal error occurs
//! 4. On SIGHUP → hot-reload config without stopping listeners

pub mod instance;
mod reality;

pub use instance::Instance;
