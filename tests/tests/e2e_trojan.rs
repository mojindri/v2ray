//! Trojan integration tests: Trojan protocol plus WebSocket/TLS transports.
//!
//! Keep this target file tiny. The actual tests live in smaller files under
//! `tests/e2e_trojan/` so each source file stays easy to scan.

#[path = "e2e_trojan/common.rs"]
mod common;
#[path = "e2e_trojan/trojan.rs"]
mod trojan;
#[path = "e2e_trojan/vless_ws.rs"]
mod vless_ws;
#[path = "e2e_trojan/ws.rs"]
mod ws;
