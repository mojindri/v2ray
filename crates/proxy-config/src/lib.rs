//! proxy-config — configuration schema, parsing, validation, and hot-reload.
//!
//! This crate owns everything related to the config file that the user writes.
//! No other crate should parse JSON directly — they receive typed Rust structs
//! from here.
//!
//! # Config file format
//!
//! The config file is JSON and follows the v2ray config schema. A minimal
//! example:
//!
//! ```json
//! {
//!   "log": { "level": "info" },
//!   "inbounds": [{
//!     "tag": "socks-in",
//!     "protocol": "socks",
//!     "listen": "127.0.0.1",
//!     "port": 1080
//!   }],
//!   "outbounds": [{
//!     "tag": "direct",
//!     "protocol": "freedom"
//!   }]
//! }
//! ```
//!
//! # Hot-reload
//!
//! The `ConfigManager` watches the config file for changes using the OS's
//! file-change notification API. When the file changes, it re-reads and
//! re-validates the config, then atomically swaps the running config via
//! `ArcSwap`. In-flight connections continue using the old config until
//! they complete; new connections see the new config immediately.

pub mod env;
pub mod manager;
pub mod schema;

pub use manager::ConfigManager;
pub use schema::{
    Config, Hysteria2Config, InboundConfig, LogConfig, NetworkType, OutboundConfig, Protocol,
    SecurityType, StreamSettingsConfig,
};
