//! blackwire-protocol — proxy protocol implementations.
//!
//! Each sub-module implements one proxy protocol. Every protocol is completely
//! isolated: no protocol module imports from another protocol module.
//!
//! Protocols implemented so far:
//!
//! | Module    | Phase | What it does |
//! |-----------|-------|--------------|
//! | `socks`   | 1     | SOCKS5 inbound — standard local proxy protocol |
//! | `freedom` | 1     | Freedom outbound — direct TCP to destination |
//! | `vless`   | 1     | VLESS inbound + outbound |

pub mod freedom;
pub mod http_connect;
pub mod socks;
pub mod ss2022;
pub mod trojan;
pub mod vless;
pub mod vmess;

// Phase 2+
// pub mod reality; (transport — handled in blackwire-transport)

// Phase 3+
// pub mod hysteria2;

// Phase 4+
// pub mod shadowtls;
