//! GeoIP matcher: match IP addresses against country-code CIDR lists.
//!
//! `GeoIpMatcher` stores a list of `IpNet` ranges. Calling `match_ip` checks
//! whether a given IP falls within any of those ranges.
//!
//! # Memory layout
//!
//! Ranges are stored as a `Vec<IpNet>` sorted by (addr_family, network_address,
//! prefix_len). This enables O(log n) binary-search lookup instead of O(n) linear
//! scan. The typical GeoIP country list has 1 000–8 000 CIDR entries; binary
//! search reduces ~5 000 comparisons to ~13.
//!
//! # Binary-search algorithm
//!
//! For a query IP:
//!   1. Construct a /32 (IPv4) or /128 (IPv6) probe from the query IP.
//!   2. Use `partition_point` to find the first range whose sorted key > probe.
//!   3. Scan backwards up to `MAX_OVERLAP_SCAN` candidates (handles nested CIDRs
//!      such as a /8 that encloses a /24 in the same list).
//!
//! GeoIP lists are non-overlapping, so one backwards step is always enough in
//! practice; the small constant scan guards against edge cases.

use std::net::IpAddr;

use ipnet::IpNet;
use tracing::warn;

use super::proto::{Cidr, GeoIp};

/// How many candidates to check backwards after binary search.
/// 1 is correct for non-overlapping CIDR lists; a small constant handles nesting.
const MAX_OVERLAP_SCAN: usize = 4;

/// Matches IP addresses against a set of CIDR ranges.
#[derive(Clone)]
pub struct GeoIpMatcher {
    /// Sorted list of IP ranges (by network address then prefix length).
    ranges: Vec<IpNet>,
}

impl GeoIpMatcher {
    /// Build a `GeoIpMatcher` from a `GeoIp` protobuf message.
    ///
    /// CIDR entries that cannot be parsed (malformed IP bytes or mismatched
    /// prefix length) are skipped with a warning rather than causing a panic.
    pub fn from_proto(entry: &GeoIp) -> Self {
        let mut ranges: Vec<IpNet> = entry.cidr.iter().filter_map(parse_cidr).collect();
        ranges.sort_unstable();
        Self { ranges }
    }

    /// Build a `GeoIpMatcher` directly from a list of `IpNet` ranges.
    ///
    /// Useful in tests where you want to avoid constructing protobuf messages.
    pub fn from_ranges(ranges: Vec<IpNet>) -> Self {
        let mut sorted = ranges;
        sorted.sort_unstable();
        Self { ranges: sorted }
    }

    /// Returns `true` if `ip` falls within any of the configured CIDR ranges.
    pub fn match_ip(&self, ip: IpAddr) -> bool {
        if self.ranges.is_empty() {
            return false;
        }

        // Build a /32 or /128 probe from the query IP so we can binary-search
        // for it. IpNet::new(ip, full_prefix) produces a network whose base
        // address equals `ip` itself (no bits are masked away).
        let full_prefix = match ip {
            IpAddr::V4(_) => 32u8,
            IpAddr::V6(_) => 128u8,
        };
        let probe = match IpNet::new(ip, full_prefix) {
            Ok(p) => p,
            Err(_) => return self.ranges.iter().any(|net| net.contains(&ip)),
        };

        // partition_point returns the index of the first element > probe.
        // All elements at idx-1 and below have base address ≤ ip.
        let idx = self.ranges.partition_point(|net| *net <= probe);

        // Scan backwards from idx; stop after MAX_OVERLAP_SCAN or when the
        // range's base address is too small to possibly contain ip (handled
        // implicitly — if ranges are sorted, all candidates here have base ≤ ip,
        // so we only need to check `contains`).
        let start = idx.saturating_sub(MAX_OVERLAP_SCAN);
        self.ranges[start..idx]
            .iter()
            .rev()
            .any(|net| net.contains(&ip))
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
    fn binary_search_with_enclosing_supernet() {
        // A /8 enclosing a /16 enclosing a /24 — verify binary search finds
        // the right match even though the enclosing range is far back in the list.
        let m = make_matcher(&["10.0.0.0/8", "10.5.0.0/16", "10.5.6.0/24", "192.168.0.0/16"]);
        assert!(m.match_ip(IpAddr::V4(Ipv4Addr::new(10, 5, 6, 7))));
        assert!(m.match_ip(IpAddr::V4(Ipv4Addr::new(10, 99, 0, 1))));
        assert!(!m.match_ip(IpAddr::V4(Ipv4Addr::new(11, 0, 0, 1))));
    }

    #[test]
    fn ip_between_ranges_no_match() {
        let m = make_matcher(&["10.0.0.0/24", "10.0.2.0/24"]);
        assert!(!m.match_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 5))));
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
