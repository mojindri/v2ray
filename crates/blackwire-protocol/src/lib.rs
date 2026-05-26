//! blackwire-protocol — proxy protocol implementations.
//!
//! Each sub-module implements one proxy protocol. Every protocol is completely
//! isolated: no protocol module imports from another protocol module.
//!
//! Protocols implemented so far:
//!
//! | Module    | What it does |
//! |-----------|--------------|
//! | `socks`   | SOCKS5 inbound — standard local proxy protocol |
//! | `freedom` | Freedom outbound — direct TCP to destination |
//! | `vless`   | VLESS inbound + outbound |

pub mod freedom;
pub mod http_connect;
pub mod socks;
pub mod socks5_udp;
pub mod ss2022;
pub mod trojan;
pub mod vless;
pub mod vmess;

// Transport-layer protocols (REALITY, Hysteria2, ShadowTLS) live in blackwire-transport.
