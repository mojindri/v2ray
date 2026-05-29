//! TUN transport building blocks.
//!
//! This module contains everything needed to run packet-level proxying through
//! an OS TUN device: device creation, packet parsing, UDP NAT, runtime loop,
//! and optional Linux route helpers.

/// Platform support contract for the TUN runtime.
pub mod backend;
/// TUN device creation and configuration.
pub mod device;
/// UDP NAT table used by the runtime.
pub mod nat;
/// Raw IP/TCP/UDP packet parsing and builders.
pub mod packet;
#[cfg(target_os = "linux")]
/// Linux-only route and iptables setup helpers.
pub mod route;
/// Main TUN runtime event loop.
pub mod runtime;
/// Session/flow tracking helpers.
pub mod session;

pub use backend::{current_tun_support, ensure_tun_runtime_supported, TunPlatformSupport};
pub use device::{create_tun, TunConfig, TunDevice};
pub use nat::UdpNatTable;
pub use packet::{
    build_tcp_rst, build_udp_response_packet, parse_ip_packet, IpPacket, TransportProtocol,
};
pub use runtime::TunRuntime;
pub use session::{FlowKey, TunSession, TunSessionTable};
