//! Network address types used throughout the proxy.
//!
//! When a client asks to connect to a destination, it can name that destination
//! in three ways:
//!   - As an IPv4 address (e.g. 93.184.216.34)
//!   - As an IPv6 address (e.g. 2606:2800:220:1:248:1893:25c8:1946)
//!   - As a domain name (e.g. example.com)
//!
//! The `Address` enum captures all three cases in a single type.
//! The port number is always included — you always need both address and port
//! to open a connection.
//!
//! The `Network` enum distinguishes TCP from UDP, because many proxy protocols
//! support both and need to know which kind of socket to use.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// A destination address: either an IP address or a domain name, plus a port.
///
/// # Why not just use `SocketAddr`?
/// Rust's `SocketAddr` only holds IP addresses, not domain names. Proxy
/// protocols often receive domain names from clients (e.g. in SOCKS5 the
/// client sends "example.com:443") and we must forward those names as-is
/// to allow the remote server to do DNS resolution. Converting to an IP
/// address on the proxy would break split-horizon DNS and geo-routing.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Address {
    /// A resolved IPv4 address and port, e.g. 93.184.216.34:443.
    Ipv4(Ipv4Addr, u16),

    /// A resolved IPv6 address and port, e.g. `[2606:2800::1]:443`.
    Ipv6(Ipv6Addr, u16),

    /// An unresolved domain name and port, e.g. example.com:443.
    /// The domain is a UTF-8 string; the port is a u16 (1–65535).
    Domain(String, u16),
}

impl Address {
    /// Returns the port number.
    pub fn port(&self) -> u16 {
        match self {
            Address::Ipv4(_, p) => *p,
            Address::Ipv6(_, p) => *p,
            Address::Domain(_, p) => *p,
        }
    }

    /// Returns `true` if this address is a domain name (not an IP).
    pub fn is_domain(&self) -> bool {
        matches!(self, Address::Domain(..))
    }

    /// Returns the domain name string, if this is a domain address.
    pub fn domain(&self) -> Option<&str> {
        match self {
            Address::Domain(d, _) => Some(d.as_str()),
            _ => None,
        }
    }

    /// Returns the IP address, if this address has already been resolved.
    pub fn ip(&self) -> Option<IpAddr> {
        match self {
            Address::Ipv4(ip, _) => Some(IpAddr::V4(*ip)),
            Address::Ipv6(ip, _) => Some(IpAddr::V6(*ip)),
            Address::Domain(..) => None,
        }
    }

    /// Converts this address into a `SocketAddr` if it holds an IP.
    /// Returns `None` for domain names (they must be resolved first).
    pub fn to_socket_addr(&self) -> Option<SocketAddr> {
        match self {
            Address::Ipv4(ip, port) => Some(SocketAddr::new(IpAddr::V4(*ip), *port)),
            Address::Ipv6(ip, port) => Some(SocketAddr::new(IpAddr::V6(*ip), *port)),
            Address::Domain(..) => None,
        }
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Address::Ipv4(ip, port) => write!(f, "{ip}:{port}"),
            Address::Ipv6(ip, port) => write!(f, "[{ip}]:{port}"),
            Address::Domain(d, port) => write!(f, "{d}:{port}"),
        }
    }
}

impl From<SocketAddr> for Address {
    fn from(s: SocketAddr) -> Self {
        match s.ip() {
            IpAddr::V4(ip) => Address::Ipv4(ip, s.port()),
            IpAddr::V6(ip) => Address::Ipv6(ip, s.port()),
        }
    }
}

/// Whether a connection uses TCP (reliable, ordered stream) or UDP (unreliable datagrams).
///
/// Most proxy protocols use TCP for the control channel and data stream.
/// Protocols like Hysteria2 and mKCP use UDP as their underlying transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Network {
    /// Transmission Control Protocol — reliable, ordered byte stream.
    Tcp,
    /// User Datagram Protocol — unreliable, unordered packets.
    Udp,
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Network::Tcp => write!(f, "tcp"),
            Network::Udp => write!(f, "udp"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    // Checks that port() returns the correct port for all three address variants.
    #[test]
    fn port_extraction() {
        assert_eq!(Address::Ipv4(Ipv4Addr::LOCALHOST, 80).port(), 80);
        assert_eq!(Address::Ipv6(Ipv6Addr::LOCALHOST, 443).port(), 443);
        assert_eq!(Address::Domain("example.com".into(), 8080).port(), 8080);
    }

    // Checks that is_domain() correctly identifies domain vs IP addresses.
    #[test]
    fn is_domain_flag() {
        assert!(Address::Domain("example.com".into(), 443).is_domain());
        assert!(!Address::Ipv4(Ipv4Addr::LOCALHOST, 443).is_domain());
        assert!(!Address::Ipv6(Ipv6Addr::LOCALHOST, 443).is_domain());
    }

    // Checks that to_socket_addr() works for IP addresses and returns None for domains.
    #[test]
    fn to_socket_addr_conversion() {
        let ipv4 = Address::Ipv4(Ipv4Addr::new(1, 2, 3, 4), 443);
        assert!(ipv4.to_socket_addr().is_some());

        let domain = Address::Domain("example.com".into(), 443);
        assert!(domain.to_socket_addr().is_none());
    }

    // Checks the Display format matches what users expect to see in logs.
    #[test]
    fn display_format() {
        assert_eq!(
            Address::Ipv4(Ipv4Addr::new(93, 184, 216, 34), 443).to_string(),
            "93.184.216.34:443"
        );
        assert_eq!(
            Address::Domain("example.com".into(), 443).to_string(),
            "example.com:443"
        );
    }

    // Checks that a SocketAddr converts correctly into an Address.
    #[test]
    fn from_socket_addr() {
        let sa: SocketAddr = "127.0.0.1:1080".parse().unwrap();
        let addr = Address::from(sa);
        assert_eq!(addr, Address::Ipv4(Ipv4Addr::LOCALHOST, 1080));
    }
}
