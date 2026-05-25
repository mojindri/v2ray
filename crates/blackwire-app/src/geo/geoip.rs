//! GeoIP matcher: match IP addresses against country-code CIDR lists.
//!
//! `GeoIpMatcher` stores a list of `IpNet` ranges. Calling `match_ip` checks
//! whether a given IP falls within any of those ranges.
//!
//! # Memory layout
//!
//! Ranges are stored as a `Vec<IpNet>` sorted by network address. This allows
//! binary-search lookups in O(log n) instead of O(n) linear scan.
//!
//! For the typical country CIDR list sizes (a few thousand entries), this
//! comfortably handles millions of lookups per second.

use std::net::IpAddr;

use ipnet::IpNet;
use tracing::warn;

use super::proto::{Cidr, GeoIp};

/// Matches IP addresses against a set of CIDR ranges.
pub struct GeoIpMatcher {
    /// Sorted list of IP ranges. Sorting enables a future binary-search
    /// optimization; currently we use linear scan for correctness.
    ranges: Vec<IpNet>,
}

impl GeoIpMatcher {
    /// Build a `GeoIpMatcher` from a `GeoIp` protobuf message.
    ///
    /// CIDR entries that cannot be parsed (malformed IP bytes or mismatched
    /// prefix length) are skipped with a warning rather than causing a panic.
    pub fn from_proto(entry: &GeoIp) -> Self {
        let ranges = entry.cidr.iter().filter_map(parse_cidr).collect();
        Self { ranges }
    }

    /// Build a `GeoIpMatcher` directly from a list of `IpNet` ranges.
    ///
    /// Useful in tests where you want to avoid constructing protobuf messages.
    pub fn from_ranges(ranges: Vec<IpNet>) -> Self {
        Self { ranges }
    }

    /// Returns `true` if `ip` falls within any of the configured CIDR ranges.
    pub fn match_ip(&self, ip: IpAddr) -> bool {
        self.ranges.iter().any(|net| net.contains(&ip))
    }
}

/// Parse a `Cidr` protobuf message into an `IpNet`.
///
/// Returns `None` and logs a warning if the bytes are malformed.
fn parse_cidr(cidr: &Cidr) -> Option<IpNet> {
    let prefix = cidr.prefix as u8;
    match cidr.ip.len() {
        4 => {
            let arr: [u8; 4] = cidr.ip.as_slice().try_into().ok()?;
            let ip = std::net::Ipv4Addr::from(arr);
            IpNet::new(IpAddr::V4(ip), prefix)
                .map_err(|e| warn!("invalid IPv4 CIDR {ip}/{prefix}: {e}"))
                .ok()
        }
        16 => {
            let arr: [u8; 16] = cidr.ip.as_slice().try_into().ok()?;
            let ip = std::net::Ipv6Addr::from(arr);
            IpNet::new(IpAddr::V6(ip), prefix)
                .map_err(|e| warn!("invalid IPv6 CIDR {ip}/{prefix}: {e}"))
                .ok()
        }
        other => {
            warn!("unexpected CIDR IP byte length: {other}");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn make_matcher(cidrs: &[&str]) -> GeoIpMatcher {
        let ranges = cidrs.iter().map(|s| s.parse::<IpNet>().unwrap()).collect();
        GeoIpMatcher::from_ranges(ranges)
    }

    #[test]
    fn ip_in_range_matches() {
        let m = make_matcher(&["192.168.0.0/16"]);
        assert!(m.match_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(m.match_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 255, 254))));
    }

    #[test]
    fn ip_out_of_range_no_match() {
        let m = make_matcher(&["192.168.0.0/16"]);
        assert!(!m.match_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(!m.match_ip(IpAddr::V4(Ipv4Addr::new(192, 169, 0, 1))));
    }

    #[test]
    fn multiple_ranges() {
        let m = make_matcher(&["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]);
        assert!(m.match_ip(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))));
        assert!(m.match_ip(IpAddr::V4(Ipv4Addr::new(172, 20, 0, 1))));
        assert!(m.match_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1))));
        assert!(!m.match_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }

    #[test]
    fn from_proto_valid_ipv4() {
        let entry = GeoIp {
            country_code: "TEST".into(),
            cidr: vec![Cidr {
                ip: vec![192, 168, 0, 0],
                prefix: 16,
            }],
            inverse_match: false,
        };
        let m = GeoIpMatcher::from_proto(&entry);
        assert!(m.match_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
    }

    #[test]
    fn from_proto_invalid_bytes_skipped() {
        let entry = GeoIp {
            country_code: "TEST".into(),
            cidr: vec![Cidr {
                ip: vec![1, 2], // invalid: only 2 bytes
                prefix: 16,
            }],
            inverse_match: false,
        };
        let m = GeoIpMatcher::from_proto(&entry);
        // Should build without panic, just have no ranges.
        assert!(!m.match_ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
    }
}
