//! blackwire-core — instance lifecycle and feature registry.
//!
//! This crate owns the running proxy instance. It is the glue that connects:
//!   - The config (from blackwire-config)
//!   - The inbound handlers (from blackwire-protocol)
//!   - The outbound handlers (from blackwire-protocol)
//!   - The dispatcher (from blackwire-app)
//!   - The router (from blackwire-app)
//!
//! # Lifecycle
//!
//! 1. Load config → build `Instance`
//! 2. Call `instance.start()` → spawns Tokio tasks for each inbound listener
//! 3. The instance runs until `instance.stop()` is called or a fatal error occurs
//! 4. On config reload → `ReloadState::apply()` swaps router + VLESS users

mod http;
mod hysteria2;
pub mod instance;
mod outbound_transport;
mod reality;
mod reload;
mod ss2022;
mod trojan;
mod vmess;
mod ws_tls;

pub use instance::Instance;
/// Hot-reload handles: swap routing rules and VLESS users without restarting listeners.
pub use reload::{inbound_listener_changes, requires_instance_restart, ReloadState};
